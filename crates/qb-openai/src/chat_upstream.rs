//! Upstream direction for Chat Completions vendors (OpenRouter and other OpenAI-compatible API
//! keys): a canonical [`TurnRequest`] becomes a [`ChatRequest`] body and a header set, and
//! [`Reader`] turns the SSE answer into canonical content events, the stop reason and the
//! vendor-reported cost. A non-200 answer is [`crate::limits::classify_chat_response`].

use std::borrow::Cow;
use std::fmt;

use qb_proto::{Block, Elsewhere, Role, StopReason, StreamEvent, ToolCall, TurnRequest, Usage};
use serde_json::Value;

use crate::limits::{Failure, FailureKind, classify_chat_stream_error};
use crate::request::{AuthMode, BuildError, data_url, identity};
use crate::sse::{self, Frame};
use crate::stream::{MAX_BLOCK_BYTES, MAX_OPEN_ITEMS, Progress, call_input, counts, malformed};
use crate::wire::{
    ChatChunk, ChatContent, ChatMessage, ChatPart, ChatRequest, ChatTool, ChatToolCall, ChatUsage,
    ChunkChoice, ChunkToolCall, FunctionCall, FunctionDef, ImageUrl, StreamOptions,
};

/// Path of the Chat Completions API below a vendor's base URL.
pub const PATH: &str = "/chat/completions";

/// The header that carries the API key and the prefix of its value; the caller appends the key,
/// so this crate never holds it.
pub fn secret_header() -> (&'static str, &'static str) {
    AuthMode::ApiKey.secret_header()
}

/// A caller-supplied header value that is empty or not printable ASCII.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidHeader(pub &'static str);

impl fmt::Display for InvalidHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` must be non-empty printable ASCII", self.0)
    }
}

impl std::error::Error for InvalidHeader {}

/// Every request header except the secret, lowercase names: those of [`AuthMode::ApiKey`], plus
/// [`identity::REFERER_HEADER`] from `referer` and [`identity::TITLE_HEADER`] from `title` when
/// given.
///
/// # Errors
/// [`InvalidHeader`] naming the header whose value is empty or not printable ASCII.
pub fn headers(
    referer: Option<&str>,
    title: Option<&str>,
) -> Result<Vec<(&'static str, String)>, InvalidHeader> {
    let mut out = AuthMode::ApiKey.headers(None);
    for (name, value) in [
        (identity::REFERER_HEADER, referer),
        (identity::TITLE_HEADER, title),
    ] {
        let Some(v) = value else { continue };
        if v.is_empty() || !v.bytes().all(|b| b == b' ' || b.is_ascii_graphic()) {
            return Err(InvalidHeader(name));
        }
        out.push((name, v.to_owned()));
    }
    Ok(out)
}

/// The upstream body of `req` for `model`, streaming with a final usage chunk.
///
/// A user message becomes one `tool` message per tool result, then one user message of its text
/// and images; an assistant message becomes one assistant message of its text and tool calls.
/// Empty text, every thinking block and images of an assistant message are dropped.
///
/// # Errors
/// [`BuildError::ImagePath`] for an image given by path.
pub fn build(req: &TurnRequest, model: &str) -> Result<ChatRequest, BuildError> {
    let mut messages = Vec::with_capacity(req.messages.len() + 1);
    if let Some(system) = system_prompt(req) {
        messages.push(message("system", Some(ChatContent::Text(system))));
    }
    for m in req.messages.iter().filter(|m| m.role != Role::System) {
        let mut parts: Vec<ChatPart> = Vec::new();
        let mut calls: Vec<ChatToolCall> = Vec::new();
        let mut results: Vec<ChatMessage> = Vec::new();
        for b in &m.content {
            match b {
                Block::Text { text } if text.is_empty() => {}
                Block::Text { text } => parts.push(ChatPart {
                    kind: "text".into(),
                    text: Some(text.clone()),
                    ..ChatPart::default()
                }),
                Block::Image {
                    media_type,
                    base64: Some(b),
                    ..
                } => parts.push(ChatPart {
                    kind: "image_url".into(),
                    image_url: Some(ImageUrl {
                        url: data_url(*media_type, b),
                        detail: None,
                    }),
                    ..ChatPart::default()
                }),
                Block::Image { path, .. } => {
                    return Err(BuildError::ImagePath(path.clone().unwrap_or_default()));
                }
                Block::ToolUse { id, name, input } => calls.push(ChatToolCall {
                    id: tool_id(id).into_owned(),
                    kind: "function".into(),
                    function: FunctionCall {
                        name: name.clone(),
                        arguments: Value::Object(input.clone()).to_string(),
                    },
                }),
                Block::ToolResult { id, content, .. } => results.push(ChatMessage {
                    tool_call_id: Some(tool_id(id).into_owned()),
                    ..message("tool", Some(ChatContent::Text(content.clone())))
                }),
                Block::Thinking { .. } => {}
            }
        }
        match m.role {
            Role::User => {
                messages.append(&mut results);
                if !parts.is_empty() {
                    messages.push(message("user", Some(ChatContent::Parts(parts))));
                }
            }
            Role::System => {}
            Role::Assistant => {
                let text: String = parts.into_iter().filter_map(|p| p.text).collect();
                if !text.is_empty() || !calls.is_empty() {
                    messages.push(ChatMessage {
                        tool_calls: (!calls.is_empty()).then_some(calls),
                        ..message(
                            "assistant",
                            (!text.is_empty()).then_some(ChatContent::Text(text)),
                        )
                    });
                }
                messages.append(&mut results);
            }
        }
    }
    let tools = chat_tools(req)?;
    let has_tools = !tools.is_empty();
    Ok(ChatRequest {
        model: model.into(),
        messages,
        tools: has_tools.then_some(tools),
        tool_choice: has_tools.then(|| Value::String("auto".into())),
        max_tokens: Some(req.max_tokens),
        stream: Some(true),
        stream_options: Some(StreamOptions {
            include_usage: Some(true),
        }),
        ..ChatRequest::default()
    })
}

/// The longest tool call id the OpenAI Chat Completions API takes (a longer one is a 400,
/// "string too long"); compatible vendors take at least as much.
pub const MAX_TOOL_ID: usize = 40;

/// Prefix of a tool id over [`MAX_TOOL_ID`] bytes, shortened by [`tool_id`].
pub const SHORTENED_TOOL_ID_PREFIX: &str = "qbh_";

/// `id` as the vendor accepts it: unchanged up to [`MAX_TOOL_ID`] bytes, else
/// [`SHORTENED_TOOL_ID_PREFIX`] and the 32 lowercase hex digits of its 128-bit FNV-1a hash
/// (36 bytes). The map is deterministic, so a tool call and its tool message still pair on every
/// turn, and two ids of one history merge only by a deliberate collision of the client's own.
/// Ids of another vendor or of a client then reach the vendor instead of a 400; the vendor
/// answers with ids of its own, so a client never sees the shortened form.
pub fn tool_id(id: &str) -> Cow<'_, str> {
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    if id.len() <= MAX_TOOL_ID {
        return Cow::Borrowed(id);
    }
    let hash = id
        .bytes()
        .fold(OFFSET, |h, b| (h ^ u128::from(b)).wrapping_mul(PRIME));
    Cow::Owned(format!("{SHORTENED_TOOL_ID_PREFIX}{hash:032x}"))
}

/// The system prompt and the text of every system message, joined by a blank line: compatible
/// vendors differ on system messages after the first one. `None` when empty.
fn system_prompt(req: &TurnRequest) -> Option<String> {
    let parts: Vec<&str> = req
        .system
        .as_deref()
        .into_iter()
        .chain(
            req.messages
                .iter()
                .filter(|m| m.role == Role::System)
                .flat_map(|m| &m.content)
                .filter_map(|b| match b {
                    Block::Text { text } => Some(text.as_str()),
                    _ => None,
                }),
        )
        .filter(|s| !s.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

/// The function tools of `req`; a tool of another API follows its `elsewhere`.
fn chat_tools(req: &TurnRequest) -> Result<Vec<ChatTool>, BuildError> {
    let mut tools = Vec::with_capacity(req.tools.len());
    for t in &req.tools {
        match t.native.as_ref().map(|n| n.elsewhere) {
            None | Some(Elsewhere::Function) => {}
            Some(Elsewhere::Omit) => continue,
            Some(Elsewhere::Refuse) => return Err(BuildError::Tool(t.name.clone())),
        }
        tools.push(ChatTool {
            kind: "function".into(),
            function: Some(FunctionDef {
                name: t.name.clone(),
                description: Some(t.description.clone()),
                parameters: Some(t.input_schema.clone()),
                strict: None,
            }),
        });
    }
    Ok(tools)
}

fn message(role: &str, content: Option<ChatContent>) -> ChatMessage {
    ChatMessage {
        role: role.into(),
        content,
        ..ChatMessage::default()
    }
}

/// Canonical counts of Chat Completions counts: `input` excludes the cached tokens, which the
/// vendor counts inside `prompt_tokens`.
pub fn usage(u: &ChatUsage) -> Usage {
    let cached = u.prompt_tokens_details.map_or(0, |d| d.cached_tokens);
    counts(u.prompt_tokens, cached, u.completion_tokens)
}

/// The canonical stop reason of a `finish_reason`; `error` has none.
fn stop_reason(reason: &str) -> Option<StopReason> {
    match reason {
        "error" => None,
        "tool_calls" => Some(StopReason::ToolUse),
        "length" => Some(StopReason::MaxTokens),
        "content_filter" => Some(StopReason::Refusal),
        _ => Some(StopReason::End),
    }
}

/// A tool call whose pieces are still arriving; `index` is `None` for a vendor that omits it.
#[derive(Debug)]
struct Pending {
    index: Option<u32>,
    id: String,
    name: String,
    args: String,
}

/// What the chunks of one answer have built so far.
#[derive(Debug, Default)]
struct Turn {
    calls: Vec<Pending>,
    held: usize,
    refused: bool,
    stop: Option<StopReason>,
    usage: Option<Usage>,
    cost: Option<f64>,
}

impl Turn {
    fn chunk(&mut self, data: &str, out: &mut Vec<StreamEvent>) -> Result<(), Failure> {
        let v: Value =
            serde_json::from_str(data).map_err(|_| malformed("chunk data is not JSON"))?;
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            return Err(classify_chat_stream_error(e));
        }
        let chunk: ChatChunk = serde_json::from_value(v)
            .map_err(|_| malformed("chunk is not a chat.completion.chunk"))?;
        for choice in chunk.choices.into_iter().filter(|c| c.index == 0) {
            self.choice(choice, out)?;
        }
        if let Some(u) = chunk.usage {
            self.usage = Some(usage(&u));
            if u.cost.is_some() {
                self.cost = u.cost;
            }
        }
        Ok(())
    }

    fn choice(&mut self, c: ChunkChoice, out: &mut Vec<StreamEvent>) -> Result<(), Failure> {
        let text = c.delta.content.filter(|t| !t.is_empty());
        let refusal = c.delta.refusal.filter(|t| !t.is_empty());
        let pieces = c.delta.tool_calls.unwrap_or_default();
        if self.stop.is_some() && (text.is_some() || refusal.is_some() || !pieces.is_empty()) {
            return Err(malformed("content after the finish reason"));
        }
        if let Some(text) = text {
            out.push(StreamEvent::TextDelta { text });
        }
        if let Some(text) = refusal {
            self.refused = true;
            out.push(StreamEvent::TextDelta { text });
        }
        for piece in pieces {
            self.piece(piece)?;
        }
        match c.finish_reason {
            Some(reason) if self.stop.is_none() => self.end(&reason, out),
            _ => Ok(()),
        }
    }

    /// Adds one tool-call piece: id and name from the first piece of its call that has them,
    /// arguments appended. A piece names its call by `index`; without one, a piece with a new id
    /// starts a call and any other piece continues the last call.
    fn piece(&mut self, piece: ChunkToolCall) -> Result<(), Failure> {
        let function = piece.function.unwrap_or_default();
        let found = match piece.index {
            Some(_) => self.calls.iter().position(|p| p.index == piece.index),
            None => self.calls.len().checked_sub(1).filter(|&last| {
                piece
                    .id
                    .as_ref()
                    .is_none_or(|id| *id == self.calls[last].id)
            }),
        };
        let at = match found {
            Some(at) => at,
            None if self.calls.len() >= MAX_OPEN_ITEMS => {
                return Err(malformed("too many tool calls"));
            }
            None => {
                self.calls.push(Pending {
                    index: piece.index,
                    id: String::new(),
                    name: String::new(),
                    args: String::new(),
                });
                self.calls.len() - 1
            }
        };
        let p = &mut self.calls[at];
        let id = piece.id.filter(|_| p.id.is_empty());
        let name = function.name.filter(|_| p.name.is_empty());
        let args = function.arguments.unwrap_or_default();
        let grow =
            id.as_ref().map_or(0, String::len) + name.as_ref().map_or(0, String::len) + args.len();
        if self.held + grow > MAX_BLOCK_BYTES {
            return Err(malformed("tool calls exceed the size bound"));
        }
        self.held += grow;
        if let Some(id) = id {
            p.id = id;
        }
        if let Some(name) = name {
            p.name = name;
        }
        p.args.push_str(&args);
        Ok(())
    }

    /// Emits the tool calls in `index` order, calls without one last in arrival order, and records
    /// the stop reason; a turn with refusal text stops with `refusal`.
    fn end(&mut self, reason: &str, out: &mut Vec<StreamEvent>) -> Result<(), Failure> {
        let Some(mut stop) = stop_reason(reason) else {
            return Err(Failure::new(
                FailureKind::Unavailable,
                "vendor stream ended with finish_reason `error`",
            ));
        };
        self.calls.sort_by_key(|p| p.index.unwrap_or(u32::MAX));
        let made = !self.calls.is_empty();
        for p in self.calls.drain(..) {
            if p.id.is_empty() || p.name.is_empty() {
                return Err(malformed("tool call without id or name"));
            }
            let input = call_input(&p.args)
                .ok_or_else(|| malformed("tool call arguments are not a JSON object"))?;
            out.push(StreamEvent::ToolCall {
                tool_call: ToolCall {
                    id: p.id,
                    name: p.name,
                    input,
                },
            });
        }
        self.held = 0;
        // Some OpenAI-compatible vendors end a turn with tool calls on `stop`.
        if made && stop == StopReason::End {
            stop = StopReason::ToolUse;
        }
        if self.refused {
            stop = StopReason::Refusal;
        }
        self.stop = Some(stop);
        Ok(())
    }

    /// The stop reason once the stream ended, after the one `usage` event of the last usage
    /// chunk.
    fn close(&mut self, out: &mut Vec<StreamEvent>, missing: &str) -> Result<StopReason, Failure> {
        let stop = self.stop.ok_or_else(|| malformed(missing))?;
        if let Some(usage) = self.usage.take() {
            out.push(StreamEvent::Usage { usage });
        }
        Ok(stop)
    }
}

/// SSE bytes of a Chat Completions answer in, canonical events out. Emits no `route`, `stop` or
/// `error`: the core owns those and gets the stop reason or a [`Failure`] back instead.
#[derive(Debug, Default)]
pub struct Reader {
    parser: sse::Parser,
    frames: Vec<Frame>,
    turn: Turn,
    done: bool,
}

impl Reader {
    /// A reader for one answer, with the event bound [`sse::MAX_EVENT_BYTES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds response bytes, appending canonical events to `out`; `data: [DONE]` finishes and
    /// appends the `usage` event.
    ///
    /// # Errors
    /// The stream's `error` chunk, classified, or [`FailureKind::Unavailable`] for an oversized
    /// event, a chunk that does not decode, content after the finish reason, data after
    /// `[DONE]`, `[DONE]` without a finish reason, a `finish_reason` of `error`, a tool call
    /// without id or name, arguments that are not a JSON object, or tool calls over
    /// [`MAX_BLOCK_BYTES`] or 64 at once.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        self.parser
            .feed(chunk, &mut self.frames)
            .map_err(|e| malformed(&e.to_string()))?;
        let mut progress = Progress::Continue;
        for frame in self.frames.drain(..) {
            if self.done {
                return Err(malformed("data after [DONE]"));
            }
            if frame.data == "[DONE]" {
                self.done = true;
                let stop = self.turn.close(out, "[DONE] before a finish reason")?;
                progress = Progress::Finished(stop);
            } else {
                self.turn.chunk(&frame.data, out)?;
            }
        }
        Ok(progress)
    }

    /// How the stream ended once the vendor closed it, appending the `usage` event to `out`.
    ///
    /// # Errors
    /// [`FailureKind::Unavailable`] when no finish reason arrived.
    pub fn finish(&mut self, out: &mut Vec<StreamEvent>) -> Result<StopReason, Failure> {
        self.turn.close(out, "stream ended before a finish reason")
    }

    /// The cost in USD the usage chunk reported (OpenRouter's `usage.cost`), if any.
    pub fn cost(&self) -> Option<f64> {
        self.turn.cost
    }
}
