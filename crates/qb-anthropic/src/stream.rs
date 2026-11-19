//! Upstream direction, answer side: Anthropic stream events become canonical C4 content events.
//!
//! [`Translator`] is the stateful mapping of decoded [`Event`]s; [`Reader`] puts the SSE parser
//! in front of it so the caller feeds raw response bytes. Neither emits `route`, `stop` or
//! `error`: the core owns those, and gets the stop reason or a [`Failure`] back instead.

use std::collections::HashMap;

use qb_proto::{Object, StopReason, StreamEvent, Thinking, ToolCall, Usage};
use serde_json::Value;

use crate::limits::{Failure, FailureKind, RateLimits, classify_stream_error};
use crate::request::thinking_to_opaque;
use crate::sse::{self, Frame};
use crate::wire::{ContentBlock, Delta, Event, WireUsage};

/// Bound of the bytes one open block accumulates (tool input JSON, thinking text and signature).
/// About 190 000 characters, beyond the longest output a model writes into one block.
pub const MAX_BLOCK_BYTES: usize = 768 << 10;

/// Where a stream is after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// More events are expected.
    Continue,
    /// `message_stop` arrived; the stream is complete.
    Finished(StopReason),
}

/// The canonical stop reason of a vendor `stop_reason`; unknown reasons end normally.
pub fn stop_reason(s: &str) -> StopReason {
    match s {
        "tool_use" => StopReason::ToolUse,
        "max_tokens" | "model_context_window_exceeded" => StopReason::MaxTokens,
        "refusal" => StopReason::Refusal,
        _ => StopReason::End,
    }
}

/// The vendor `stop_reason` of a canonical one.
pub fn stop_reason_name(r: StopReason) -> &'static str {
    match r {
        StopReason::End => "end_turn",
        StopReason::ToolUse => "tool_use",
        StopReason::MaxTokens => "max_tokens",
        StopReason::Refusal => "refusal",
    }
}

/// Canonical counts from vendor counts.
pub fn usage(u: &WireUsage) -> Usage {
    Usage {
        input: u.input_tokens.unwrap_or(0),
        output: u.output_tokens.unwrap_or(0),
        cache_read: u.cache_read_input_tokens.unwrap_or(0),
        cache_write: u.cache_creation_input_tokens.unwrap_or(0),
    }
}

#[derive(Debug)]
enum Open {
    Text,
    ToolUse {
        id: String,
        name: String,
        json: String,
    },
    Thinking {
        text: String,
        signature: String,
    },
    Redacted(String),
    Skipped,
}

/// Translates one Anthropic stream into canonical events.
#[derive(Debug)]
pub struct Translator {
    vendor: String,
    limits: RateLimits,
    open: Option<(u32, Open)>,
    usage: WireUsage,
    stop: Option<StopReason>,
    started: bool,
    finished: Option<StopReason>,
    tool_names: HashMap<String, String>,
}

fn malformed(what: &str) -> Failure {
    Failure::new(
        FailureKind::Unavailable,
        format!("malformed vendor stream: {what}"),
    )
}

impl Translator {
    /// A translator for a stream of the vendor named `vendor`, whose response headers carried
    /// `limits` (used to classify an `error` event).
    pub fn new(vendor: &str, limits: RateLimits) -> Self {
        Self {
            vendor: vendor.to_owned(),
            limits,
            open: None,
            usage: WireUsage::default(),
            stop: None,
            started: false,
            finished: None,
            tool_names: HashMap::new(),
        }
    }

    /// The same translator, giving a tool call named by a key of `wire_to_client` the value
    /// instead: the inverse of [`crate::request::wire_tool_names`].
    #[must_use]
    pub fn with_tool_names(mut self, wire_to_client: HashMap<String, String>) -> Self {
        self.tool_names = wire_to_client;
        self
    }

    /// Translates one event, appending canonical events to `out`.
    ///
    /// # Errors
    /// The stream's `error` event, classified, or [`FailureKind::Unavailable`] for events out of
    /// order, tool input that is not a JSON object, a block over [`MAX_BLOCK_BYTES`], or events
    /// after `message_stop`.
    pub fn push(&mut self, event: Event, out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        if self.finished.is_some() {
            return match event {
                Event::Ping | Event::Other => Ok(Progress::Continue),
                _ => Err(malformed("event after message_stop")),
            };
        }
        match event {
            Event::MessageStart { message } => {
                if self.started {
                    return Err(malformed("second message_start"));
                }
                self.started = true;
                self.merge_usage(&message.usage);
                out.push(StreamEvent::Usage {
                    usage: usage(&self.usage),
                });
            }
            Event::ContentBlockStart {
                index,
                content_block,
            } => self.start_block(index, content_block, out)?,
            Event::ContentBlockDelta { index, delta } => self.delta(index, delta, out)?,
            Event::ContentBlockStop { index } => {
                let Some((at, open)) = self.open.take() else {
                    return Err(malformed("stop outside a block"));
                };
                if at != index {
                    return Err(malformed("stop for another block"));
                }
                self.close(open, out)?;
            }
            Event::MessageDelta { delta, usage: u } => {
                self.require_started()?;
                self.merge_usage(&u);
                if let Some(reason) = delta.stop_reason.as_deref() {
                    self.stop = Some(stop_reason(reason));
                }
                out.push(StreamEvent::Usage {
                    usage: usage(&self.usage),
                });
            }
            Event::MessageStop => {
                self.require_started()?;
                if self.open.is_some() {
                    return Err(malformed("message_stop inside a block"));
                }
                let stop = self.stop.unwrap_or(StopReason::End);
                self.finished = Some(stop);
                return Ok(Progress::Finished(stop));
            }
            Event::Error { error } => return Err(classify_stream_error(&error, &self.limits)),
            Event::Ping | Event::Other => {}
        }
        Ok(Progress::Continue)
    }

    /// How the stream ended once the vendor closed it.
    ///
    /// # Errors
    /// [`FailureKind::Unavailable`] when `message_stop` never arrived.
    pub fn finish(&self) -> Result<StopReason, Failure> {
        self.finished
            .ok_or_else(|| malformed("stream ended before message_stop"))
    }

    /// The quota windows of the response headers, for qbd's report.
    pub fn windows(&self) -> &[qb_proto::WindowReport] {
        &self.limits.windows
    }

    fn start_block(
        &mut self,
        index: u32,
        content_block: ContentBlock,
        out: &mut Vec<StreamEvent>,
    ) -> Result<(), Failure> {
        self.require_started()?;
        if self.open.is_some() {
            return Err(malformed("block started before the previous one stopped"));
        }
        let open = match content_block {
            ContentBlock::Text { text, .. } => {
                if !text.is_empty() {
                    out.push(StreamEvent::TextDelta { text });
                }
                Open::Text
            }
            ContentBlock::ToolUse {
                id, name, input, ..
            } => Open::ToolUse {
                id,
                name,
                json: match input {
                    Value::Object(m) if !m.is_empty() => Value::Object(m).to_string(),
                    _ => String::new(),
                },
            },
            ContentBlock::Thinking {
                thinking,
                signature,
            } => Open::Thinking {
                text: thinking,
                signature,
            },
            ContentBlock::RedactedThinking { data } => Open::Redacted(data),
            _ => Open::Skipped,
        };
        self.open = Some((index, open));
        Ok(())
    }

    fn delta(
        &mut self,
        index: u32,
        delta: Delta,
        out: &mut Vec<StreamEvent>,
    ) -> Result<(), Failure> {
        let Some((at, open)) = self.open.as_mut() else {
            return Err(malformed("delta outside a block"));
        };
        if *at != index {
            return Err(malformed("delta for another block"));
        }
        let held = match open {
            Open::ToolUse { json, .. } => json.len(),
            Open::Thinking { text, signature } => text.len() + signature.len(),
            Open::Text | Open::Redacted(_) | Open::Skipped => 0,
        };
        let added = match &delta {
            Delta::InputJsonDelta { partial_json: s }
            | Delta::ThinkingDelta { thinking: s }
            | Delta::SignatureDelta { signature: s } => s.len(),
            Delta::TextDelta { .. } | Delta::Other => 0,
        };
        if held + added > MAX_BLOCK_BYTES {
            return Err(malformed("a content block exceeds the size bound"));
        }
        match (open, delta) {
            (Open::Text, Delta::TextDelta { text }) => {
                if !text.is_empty() {
                    out.push(StreamEvent::TextDelta { text });
                }
            }
            (Open::ToolUse { json, .. }, Delta::InputJsonDelta { partial_json }) => {
                json.push_str(&partial_json);
            }
            (Open::Thinking { text, .. }, Delta::ThinkingDelta { thinking }) => {
                text.push_str(&thinking);
            }
            (Open::Thinking { signature, .. }, Delta::SignatureDelta { signature: s }) => {
                signature.push_str(&s);
            }
            (Open::Skipped, _) | (_, Delta::Other) => {}
            _ => return Err(malformed("delta of the wrong type for its block")),
        }
        Ok(())
    }

    fn require_started(&self) -> Result<(), Failure> {
        if self.started {
            Ok(())
        } else {
            Err(malformed("event before message_start"))
        }
    }

    fn merge_usage(&mut self, u: &WireUsage) {
        let keep = |new: Option<u64>, old: Option<u64>| new.or(old);
        self.usage = WireUsage {
            input_tokens: keep(u.input_tokens, self.usage.input_tokens),
            cache_creation_input_tokens: keep(
                u.cache_creation_input_tokens,
                self.usage.cache_creation_input_tokens,
            ),
            cache_read_input_tokens: keep(
                u.cache_read_input_tokens,
                self.usage.cache_read_input_tokens,
            ),
            output_tokens: keep(u.output_tokens, self.usage.output_tokens),
        };
    }

    fn close(&self, open: Open, out: &mut Vec<StreamEvent>) -> Result<(), Failure> {
        match open {
            Open::Text | Open::Skipped => {}
            Open::ToolUse { id, name, json } => {
                let name = self.tool_names.get(&name).cloned().unwrap_or(name);
                let input = if json.trim().is_empty() {
                    Object::new()
                } else {
                    match serde_json::from_str::<Value>(&json) {
                        Ok(Value::Object(m)) => m,
                        _ => return Err(malformed("tool input is not a JSON object")),
                    }
                };
                out.push(StreamEvent::ToolCall {
                    tool_call: ToolCall { id, name, input },
                });
            }
            Open::Thinking { text, signature } => {
                let block = ContentBlock::Thinking {
                    thinking: text,
                    signature,
                };
                out.push(self.thinking(&block));
            }
            Open::Redacted(data) => {
                out.push(self.thinking(&ContentBlock::RedactedThinking { data }));
            }
        }
        Ok(())
    }

    fn thinking(&self, block: &ContentBlock) -> StreamEvent {
        StreamEvent::Thinking {
            thinking: Thinking {
                vendor: self.vendor.clone(),
                opaque: thinking_to_opaque(block),
            },
        }
    }
}

/// SSE bytes in, canonical events out: [`sse::Parser`] plus [`Translator`].
#[derive(Debug)]
pub struct Reader {
    parser: sse::Parser,
    frames: Vec<Frame>,
    translator: Translator,
}

impl Reader {
    /// A reader for one response of `vendor` with `limits` from its headers.
    pub fn new(vendor: &str, limits: RateLimits) -> Self {
        Self {
            parser: sse::Parser::default(),
            frames: Vec::new(),
            translator: Translator::new(vendor, limits),
        }
    }

    /// The same reader, mapping tool call names back as [`Translator::with_tool_names`].
    #[must_use]
    pub fn with_tool_names(mut self, wire_to_client: HashMap<String, String>) -> Self {
        self.translator = self.translator.with_tool_names(wire_to_client);
        self
    }

    /// Feeds response bytes, appending canonical events to `out`.
    ///
    /// # Errors
    /// As [`Translator::push`], plus [`FailureKind::Unavailable`] for an oversized event or event
    /// data that is not a JSON event object.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        self.parser
            .feed(chunk, &mut self.frames)
            .map_err(|e| malformed(&e.to_string()))?;
        let mut progress = Progress::Continue;
        for frame in self.frames.drain(..) {
            let Some(event) = decode(&frame)? else {
                continue;
            };
            if let Progress::Finished(stop) = self.translator.push(event, out)? {
                progress = Progress::Finished(stop);
            }
        }
        Ok(progress)
    }

    /// How the stream ended once the vendor closed it; see [`Translator::finish`].
    ///
    /// # Errors
    /// [`FailureKind::Unavailable`] when `message_stop` never arrived.
    pub fn finish(&self) -> Result<StopReason, Failure> {
        self.translator.finish()
    }

    /// The quota windows of the response headers.
    pub fn windows(&self) -> &[qb_proto::WindowReport] {
        self.translator.windows()
    }
}

/// Event names of the Messages stream.
const KNOWN: &[&str] = &[
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
    "ping",
    "error",
];

/// Decodes one frame; `Ok(None)` for a frame that is not an Anthropic event (unknown type or no
/// JSON object with a `type`, or non-JSON data of an unknown event).
///
/// # Errors
/// [`FailureKind::Unavailable`] for a known event type whose payload does not decode.
pub fn decode(frame: &Frame) -> Result<Option<Event>, Failure> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&frame.data) else {
        return if KNOWN.contains(&frame.event.as_str()) && frame.event != "ping" {
            Err(malformed("event data is not a JSON object"))
        } else {
            Ok(None)
        };
    };
    if !map.get("type").is_some_and(Value::is_string) {
        return Ok(None);
    }
    match serde_json::from_value::<Event>(Value::Object(map)) {
        Ok(Event::Other) => Ok(None),
        Ok(event) => Ok(Some(event)),
        Err(_) => Err(malformed("event payload does not match its type")),
    }
}
