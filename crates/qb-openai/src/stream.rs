//! Upstream direction, answer side: Responses stream events become canonical C4 content events.
//!
//! [`Translator`] is the stateful mapping of decoded [`ResponseEvent`]s; [`Reader`] puts the SSE
//! parser in front of it so the caller feeds raw response bytes. Neither emits `route`, `stop` or
//! `error`: the core owns those, and gets the stop reason or a [`Failure`] back instead.

use qb_proto::{Object, StopReason, StreamEvent, Thinking, ToolCall, Usage, WindowReport};
use serde_json::Value;

use crate::limits::{Failure, FailureKind, RateLimits, classify_stream_error};
use crate::request::reasoning_to_opaque;
use crate::sse::{self, Frame};
use crate::wire::{Content, Item, ResponseEvent, ResponseObject, ResponsesUsage, event};

/// Bound of the bytes the open items of a stream accumulate (function call arguments). About
/// 190 000 characters, beyond the longest output a model writes into one call.
pub const MAX_BLOCK_BYTES: usize = 768 << 10;

/// Bound of the items open at once.
const MAX_OPEN_ITEMS: usize = 64;

/// Where a stream is after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// More events are expected.
    Continue,
    /// `response.completed` or `response.incomplete` arrived; the stream is complete.
    Finished(StopReason),
}

/// The canonical stop reason of an `incomplete_details.reason`.
pub fn incomplete_reason(reason: &str) -> StopReason {
    match reason {
        "content_filter" => StopReason::Refusal,
        _ => StopReason::MaxTokens,
    }
}

/// Canonical counts from vendor counts: `input` excludes the cached tokens, which the vendor
/// counts inside `input_tokens`.
pub fn usage(u: &ResponsesUsage) -> Usage {
    let cached = u.input_tokens_details.map_or(0, |d| d.cached_tokens);
    Usage {
        input: u.input_tokens.saturating_sub(cached),
        output: u.output_tokens,
        cache_read: cached,
        cache_write: 0,
    }
}

#[derive(Debug)]
enum Open {
    Message {
        streamed: bool,
    },
    Function {
        call_id: String,
        name: String,
        args: String,
    },
    Reasoning,
    Skipped,
}

/// Translates one Responses stream into canonical events.
#[derive(Debug)]
pub struct Translator {
    vendor: String,
    limits: RateLimits,
    open: Vec<(u32, Open)>,
    held: usize,
    started: bool,
    tool_calls: bool,
    refused: bool,
    finished: Option<StopReason>,
}

fn malformed(what: &str) -> Failure {
    Failure::new(
        FailureKind::Unavailable,
        format!("malformed vendor stream: {what}"),
    )
}

/// The event types the translator acts on; others are skipped.
const KNOWN: &[&str] = &[
    event::CREATED,
    event::IN_PROGRESS,
    event::OUTPUT_ITEM_ADDED,
    event::OUTPUT_ITEM_DONE,
    event::OUTPUT_TEXT_DELTA,
    event::REFUSAL_DELTA,
    event::FUNCTION_CALL_ARGUMENTS_DELTA,
    event::FUNCTION_CALL_ARGUMENTS_DONE,
    event::COMPLETED,
    event::INCOMPLETE,
    event::FAILED,
    event::ERROR,
];

impl Translator {
    /// A translator for a stream of the vendor named `vendor`, whose response headers carried
    /// `limits` (used to classify an error event).
    pub fn new(vendor: &str, limits: RateLimits) -> Self {
        Self {
            vendor: vendor.to_owned(),
            limits,
            open: Vec::new(),
            held: 0,
            started: false,
            tool_calls: false,
            refused: false,
            finished: None,
        }
    }

    /// Translates one event, appending canonical events to `out`.
    ///
    /// # Errors
    /// The stream's `error` or `response.failed`, classified, or [`FailureKind::Unavailable`]
    /// for events out of order, arguments that are not a JSON object, open items over
    /// [`MAX_BLOCK_BYTES`], or events after the end.
    pub fn push(
        &mut self,
        ev: ResponseEvent,
        out: &mut Vec<StreamEvent>,
    ) -> Result<Progress, Failure> {
        let kind = ev.kind.as_str();
        if !KNOWN.contains(&kind) {
            return Ok(Progress::Continue);
        }
        if self.finished.is_some() {
            return Err(malformed("event after the response ended"));
        }
        match kind {
            event::CREATED => {
                if self.started {
                    return Err(malformed("second response.created"));
                }
                self.started = true;
            }
            event::IN_PROGRESS => self.started = true,
            event::ERROR => {
                return Err(classify_stream_error(
                    ev.code.as_deref().unwrap_or_default(),
                    ev.message.as_deref().unwrap_or_default(),
                    &self.limits,
                ));
            }
            event::FAILED => {
                let e = ev.response.and_then(|r| r.error).unwrap_or_default();
                return Err(classify_stream_error(
                    e.code.as_deref().unwrap_or_default(),
                    e.message.as_deref().unwrap_or_default(),
                    &self.limits,
                ));
            }
            _ => {
                self.require_started()?;
                return self.content(ev, out);
            }
        }
        Ok(Progress::Continue)
    }

    fn content(
        &mut self,
        ev: ResponseEvent,
        out: &mut Vec<StreamEvent>,
    ) -> Result<Progress, Failure> {
        match ev.kind.as_str() {
            event::OUTPUT_ITEM_ADDED => {
                let index = index(&ev)?;
                let item = ev
                    .item
                    .ok_or_else(|| malformed("item event without item"))?;
                self.add(index, item)?;
            }
            event::OUTPUT_TEXT_DELTA | event::REFUSAL_DELTA => {
                let refusal = ev.kind == event::REFUSAL_DELTA;
                let at = index(&ev)?;
                match self.find(at) {
                    Some(Open::Message { streamed }) => *streamed = true,
                    _ => return Err(malformed("text delta outside a message")),
                }
                self.refused |= refusal;
                if let Some(text) = ev.delta.filter(|t| !t.is_empty()) {
                    out.push(StreamEvent::TextDelta { text });
                }
            }
            event::FUNCTION_CALL_ARGUMENTS_DELTA | event::FUNCTION_CALL_ARGUMENTS_DONE => {
                let at = index(&ev)?;
                let done = ev.kind == event::FUNCTION_CALL_ARGUMENTS_DONE;
                let piece = if done { ev.arguments } else { ev.delta }.unwrap_or_default();
                let held = self.held;
                let Some(Open::Function { args, .. }) = self.find(at) else {
                    return Err(malformed("arguments outside a function call"));
                };
                let before = args.len();
                let after = if done {
                    piece.len()
                } else {
                    before + piece.len()
                };
                if held - before + after > MAX_BLOCK_BYTES {
                    return Err(malformed("open items exceed the size bound"));
                }
                if done {
                    *args = piece;
                } else {
                    args.push_str(&piece);
                }
                self.held = held - before + after;
            }
            event::OUTPUT_ITEM_DONE => {
                let at = index(&ev)?;
                let item = ev
                    .item
                    .ok_or_else(|| malformed("item event without item"))?;
                self.done(at, item, out)?;
            }
            event::COMPLETED | event::INCOMPLETE => return Ok(self.end(&ev, out)),
            _ => {}
        }
        Ok(Progress::Continue)
    }

    fn add(&mut self, at: u32, item: Item) -> Result<(), Failure> {
        if self.open.iter().any(|(i, _)| *i == at) {
            return Err(malformed("item added twice"));
        }
        if self.open.len() >= MAX_OPEN_ITEMS {
            return Err(malformed("too many open items"));
        }
        let open = match item.kind.as_deref() {
            Some("message") => Open::Message { streamed: false },
            Some("function_call") => {
                let args = item.arguments.unwrap_or_default();
                if self.held + args.len() > MAX_BLOCK_BYTES {
                    return Err(malformed("open items exceed the size bound"));
                }
                self.held += args.len();
                Open::Function {
                    call_id: item.call_id.unwrap_or_default(),
                    name: item.name.unwrap_or_default(),
                    args,
                }
            }
            Some("reasoning") => Open::Reasoning,
            _ => Open::Skipped,
        };
        self.open.push((at, open));
        Ok(())
    }

    fn find(&mut self, at: u32) -> Option<&mut Open> {
        self.open.iter_mut().find(|(i, _)| *i == at).map(|(_, o)| o)
    }

    /// Closes the item at `at`. The done item is authoritative; an item that was never added is
    /// taken from it alone.
    fn done(&mut self, at: u32, item: Item, out: &mut Vec<StreamEvent>) -> Result<(), Failure> {
        let open = match self.open.iter().position(|(i, _)| *i == at) {
            Some(p) => Some(self.open.remove(p).1),
            None => None,
        };
        if let Some(Open::Function { args, .. }) = &open {
            self.held -= args.len();
        }
        match item.kind.as_deref() {
            Some("function_call") => {
                let (call_id, name, args) = match open {
                    Some(Open::Function {
                        call_id,
                        name,
                        args,
                    }) => (call_id, name, args),
                    None => Default::default(),
                    Some(_) => return Err(malformed("item changed its type")),
                };
                let id = item.call_id.filter(|s| !s.is_empty()).unwrap_or(call_id);
                let name = item.name.filter(|s| !s.is_empty()).unwrap_or(name);
                let args = item.arguments.filter(|s| !s.is_empty()).unwrap_or(args);
                if id.is_empty() || name.is_empty() {
                    return Err(malformed("function call without call_id or name"));
                }
                let input = if args.trim().is_empty() {
                    Object::new()
                } else {
                    match serde_json::from_str::<Value>(&args) {
                        Ok(Value::Object(m)) => m,
                        _ => return Err(malformed("function arguments are not a JSON object")),
                    }
                };
                self.tool_calls = true;
                out.push(StreamEvent::ToolCall {
                    tool_call: ToolCall { id, name, input },
                });
            }
            Some("reasoning") => {
                if let Some(opaque) = reasoning_to_opaque(&item) {
                    out.push(StreamEvent::Thinking {
                        thinking: Thinking {
                            vendor: self.vendor.clone(),
                            opaque,
                        },
                    });
                }
            }
            Some("message") => {
                let streamed = matches!(open, Some(Open::Message { streamed: true }));
                if !streamed {
                    self.unstreamed_text(&item, out);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The text of a message item whose deltas never came.
    fn unstreamed_text(&mut self, item: &Item, out: &mut Vec<StreamEvent>) {
        let Some(Content::Parts(parts)) = &item.content else {
            return;
        };
        for p in parts {
            let text = match p.kind.as_str() {
                "output_text" => p.text.as_deref(),
                "refusal" => {
                    self.refused = true;
                    p.refusal.as_deref()
                }
                _ => None,
            };
            if let Some(text) = text.filter(|t| !t.is_empty()) {
                out.push(StreamEvent::TextDelta { text: text.into() });
            }
        }
    }

    fn end(&mut self, ev: &ResponseEvent, out: &mut Vec<StreamEvent>) -> Progress {
        let response = ev.response.as_deref().cloned().unwrap_or_default();
        if let Some(u) = &response.usage {
            out.push(StreamEvent::Usage { usage: usage(u) });
        }
        let stop = stop_of(
            ev.kind == event::INCOMPLETE,
            &response,
            self.tool_calls,
            self.refused,
        );
        self.open.clear();
        self.held = 0;
        self.finished = Some(stop);
        Progress::Finished(stop)
    }

    /// How the stream ended once the vendor closed it.
    ///
    /// # Errors
    /// [`FailureKind::Unavailable`] when `response.completed` never arrived.
    pub fn finish(&self) -> Result<StopReason, Failure> {
        self.finished
            .ok_or_else(|| malformed("stream ended before response.completed"))
    }

    /// The quota windows of the response headers, for qbd's report.
    pub fn windows(&self) -> &[WindowReport] {
        &self.limits.windows
    }

    fn require_started(&self) -> Result<(), Failure> {
        if self.started {
            Ok(())
        } else {
            Err(malformed("event before response.created"))
        }
    }
}

fn index(ev: &ResponseEvent) -> Result<u32, Failure> {
    ev.output_index
        .ok_or_else(|| malformed("event without output_index"))
}

fn stop_of(incomplete: bool, r: &ResponseObject, tool_calls: bool, refused: bool) -> StopReason {
    if incomplete || r.status == "incomplete" {
        let reason = r
            .incomplete_details
            .as_ref()
            .map_or("", |d| d.reason.as_str());
        return incomplete_reason(reason);
    }
    if tool_calls {
        StopReason::ToolUse
    } else if refused {
        StopReason::Refusal
    } else {
        StopReason::End
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

    /// Feeds response bytes, appending canonical events to `out`.
    ///
    /// # Errors
    /// As [`Translator::push`], plus [`FailureKind::Unavailable`] for an oversized event or event
    /// data of a known type that does not decode.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        self.parser
            .feed(chunk, &mut self.frames)
            .map_err(|e| malformed(&e.to_string()))?;
        let mut progress = Progress::Continue;
        for frame in self.frames.drain(..) {
            let Some(ev) = decode(&frame)? else {
                continue;
            };
            if let Progress::Finished(stop) = self.translator.push(ev, out)? {
                progress = Progress::Finished(stop);
            }
        }
        Ok(progress)
    }

    /// How the stream ended once the vendor closed it; see [`Translator::finish`].
    ///
    /// # Errors
    /// [`FailureKind::Unavailable`] when `response.completed` never arrived.
    pub fn finish(&self) -> Result<StopReason, Failure> {
        self.translator.finish()
    }

    /// The quota windows of the response headers.
    pub fn windows(&self) -> &[WindowReport] {
        self.translator.windows()
    }
}

/// Decodes one frame; `Ok(None)` for a frame that is not a Responses event this crate reads
/// (unknown type, no JSON object with a `type`, `[DONE]`, or non-JSON data of an unknown event).
///
/// # Errors
/// [`FailureKind::Unavailable`] for a known event type whose payload does not decode.
pub fn decode(frame: &Frame) -> Result<Option<ResponseEvent>, Failure> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&frame.data) else {
        return if KNOWN.contains(&frame.event.as_str()) {
            Err(malformed("event data is not a JSON object"))
        } else {
            Ok(None)
        };
    };
    let Some(kind) = map.get("type").and_then(Value::as_str) else {
        return Ok(None);
    };
    if !KNOWN.contains(&kind) {
        return Ok(None);
    }
    match serde_json::from_value::<ResponseEvent>(Value::Object(map)) {
        Ok(ev) => Ok(Some(ev)),
        Err(_) => Err(malformed("event payload does not match its type")),
    }
}
