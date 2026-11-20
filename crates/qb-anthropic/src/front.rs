//! Client direction, the pure half of the `/v1/messages` front: an Anthropic Messages request
//! from an SDK client becomes a canonical [`TurnRequest`]; canonical events become an Anthropic
//! SSE byte stream ([`SseEncoder`]) or one response body ([`Assembler`]); a canonical error
//! becomes an Anthropic error answer ([`error_response`]).

use qb_proto::{
    Block, CacheMode, Effort, ErrorClass, GatewayError, MediaType, Message, Object, Role,
    StopReason, StreamEvent, Thinking, Tool, TurnRequest, Usage,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::request::thinking_from_opaque;
use crate::sse;
use crate::stream::stop_reason_name;
use crate::wire::{
    Content, ContentBlock, CreateMessage, Delta, ErrorBody, Event, MessageDeltaBody,
    MessageResponse, System, ToolResultContent, WireUsage,
};

/// Prefix of a `redacted_thinking` payload that carries another vendor's thinking block, so a
/// Messages client passes it back like any redacted block.
pub const FOREIGN_THINKING: &str = "qb-thinking:";

/// What the front does with thinking of a vendor other than its native one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ForeignThinking {
    /// Show it as a `redacted_thinking` block the client passes back, so the turn keeps it.
    #[default]
    Keep,
    /// Leave it out, so the client's history stays valid for the native vendor itself.
    Drop,
}

/// Longest `metadata.user_id` taken as the session key.
const MAX_SESSION_KEY: usize = qb_proto::gateway::MAX_SESSION_KEY;

/// A decoded front request.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontRequest {
    /// The canonical turn.
    pub turn: TurnRequest,
    /// The client asked for SSE.
    pub stream: bool,
    /// The `model` the client sent, echoed in the answer.
    pub model: String,
}

#[derive(Serialize, Deserialize)]
struct Foreign {
    vendor: String,
    opaque: String,
}

fn bad(message: impl Into<String>) -> GatewayError {
    GatewayError::new(ErrorClass::BadRequest, false, message)
}

/// Decodes a Messages request body into a canonical turn with `request_id`.
///
/// `route_of` maps the client's `model` to a route alias. Thinking blocks become canonical
/// thinking of `native_vendor`, except redacted blocks this front wrapped for another vendor.
/// Mid-conversation `system` messages stay in place as canonical system messages; tool changes
/// by reference in them are dropped and `tool_reference` blocks become text, since every tool
/// goes upstream loaded.
/// `cache` is `auto` when the request sets `cache_control` on a block, a tool or the request, and
/// `auto_1h` when one of those breakpoints asks for `ttl: 1h`. Sampling parameters,
/// `tool_choice`, `stop_sequences` and thinking budgets are ignored.
///
/// # Errors
/// A `bad_request` error for a body that is not a Messages request, an unknown model, a block
/// the canonical form cannot carry (documents, URL images, images in tool results, inline tool
/// definitions, turn-scoped system messages), or a turn that fails [`TurnRequest::validate`].
pub fn decode_request(
    body: &[u8],
    request_id: &str,
    native_vendor: &str,
    route_of: &dyn Fn(&str) -> Option<String>,
) -> Result<FrontRequest, GatewayError> {
    let raw: Value =
        serde_json::from_slice(body).map_err(|e| bad(format!("body is not JSON: {e}")))?;
    let cache = cache_mode(&raw);
    let req: CreateMessage = serde_json::from_value(raw)
        .map_err(|e| bad(format!("body is not a Messages request: {e}")))?;
    let route = route_of(&req.model).ok_or_else(|| {
        bad(format!(
            "model `{}` is not a route of this gateway",
            req.model
        ))
    })?;

    let system = match req.system {
        None => None,
        Some(System::Text(s)) => Some(s),
        Some(System::Blocks(blocks)) => Some(
            blocks
                .into_iter()
                .map(|b| b.text)
                .collect::<Vec<_>>()
                .join("\n\n"),
        ),
    }
    .filter(|s| !s.is_empty());

    let messages = canonical_messages(req.messages, native_vendor)?;

    let effort = req
        .output_config
        .and_then(|o| o.effort)
        .map(|e| match e.as_str() {
            "low" => Ok(Effort::Low),
            "medium" => Ok(Effort::Medium),
            "high" | "xhigh" => Ok(Effort::High),
            "max" => Ok(Effort::Max),
            other => Err(bad(format!(
                "`output_config.effort` `{other}` is not supported"
            ))),
        })
        .transpose()?;

    let turn = TurnRequest {
        route,
        system,
        messages,
        tools: req
            .tools
            .into_iter()
            .map(|t| Tool {
                name: t.name,
                description: t.description.unwrap_or_default(),
                input_schema: t.input_schema,
                native: None,
            })
            .collect(),
        max_tokens: req.max_tokens,
        effort,
        session_key: req
            .metadata
            .and_then(|m| m.user_id)
            .filter(|k| !k.is_empty())
            .map(session_key),
        cache,
        request_id: request_id.to_owned(),
    };
    turn.validate().map_err(|e| bad(e.0))?;
    Ok(FrontRequest {
        turn,
        stream: req.stream.unwrap_or(false),
        model: req.model,
    })
}

/// The canonical messages of a request's `messages`: `user`, `assistant` and text-only `system`
/// messages; a system message without content, which only sets `output_config` for later
/// turns, is dropped, since the request's own `output_config` is the one that counts.
fn canonical_messages(
    input: Vec<crate::wire::MessageParam>,
    native_vendor: &str,
) -> Result<Vec<Message>, GatewayError> {
    let mut messages = Vec::with_capacity(input.len());
    for (i, m) in input.into_iter().enumerate() {
        let role = match m.role.as_str() {
            "user" => Role::User,
            "assistant" => Role::Assistant,
            "system" => Role::System,
            other => {
                return Err(bad(format!(
                    "`messages[{i}].role` `{other}` is not supported"
                )));
            }
        };
        if let Some(c) = m.clear_at.as_deref().filter(|c| *c != "never") {
            return Err(bad(format!(
                "`messages[{i}].clear_at` `{c}` is not supported by this gateway"
            )));
        }
        let mut blocks: Vec<Block> = Vec::new();
        match m.content {
            Content::Text(text) => blocks.push(Block::Text { text }),
            Content::Blocks(input) => {
                for (j, b) in input.into_iter().enumerate() {
                    let at = format!("messages[{i}].content[{j}]");
                    match (role, b) {
                        (Role::System, b @ ContentBlock::Text { .. }) => {
                            blocks.push(canonical_block(b, native_vendor, &at)?);
                        }
                        // Every tool goes upstream loaded, so a change that only names a
                        // declared tool changes nothing.
                        (Role::System, ContentBlock::ToolAddition { tool })
                            if tool.get("type").and_then(Value::as_str)
                                == Some("tool_reference") => {}
                        (Role::System, _) => {
                            return Err(bad(format!(
                                "`{at}`: a system message may hold text blocks and tool \
                                 changes by reference only here"
                            )));
                        }
                        (_, b) => blocks.push(canonical_block(b, native_vendor, &at)?),
                    }
                }
            }
        }
        if role == Role::System && blocks.is_empty() {
            continue;
        }
        messages.push(Message {
            role,
            content: blocks,
        });
    }

    Ok(messages)
}

/// The cache policy of the request's `cache_control` breakpoints, read where the vendor reads
/// them: at the top level, on a `system` block, a tool, a message content block or a block inside
/// a tool result. Keys of the same name inside schemas or tool inputs are data, not breakpoints.
/// `auto_1h` when any breakpoint asks for `ttl: 1h`, `auto` for other breakpoints, none without.
fn cache_mode(v: &Value) -> Option<CacheMode> {
    fn blocks(v: Option<&Value>) -> &[Value] {
        v.and_then(Value::as_array).map_or(&[], Vec::as_slice)
    }
    let mut marks = Vec::new();
    let mut mark = |v: &Value| {
        if let Some(c) = v.get("cache_control").filter(|c| !c.is_null()) {
            marks.push(c.clone());
        }
    };
    mark(v);
    blocks(v.get("system")).iter().for_each(&mut mark);
    blocks(v.get("tools")).iter().for_each(&mut mark);
    for m in blocks(v.get("messages")) {
        for b in blocks(m.get("content")) {
            mark(b);
            blocks(b.get("content")).iter().for_each(&mut mark);
        }
    }
    if marks.is_empty() {
        None
    } else if marks
        .iter()
        .any(|c| c.get("ttl").and_then(Value::as_str) == Some("1h"))
    {
        Some(CacheMode::Auto1h)
    } else {
        Some(CacheMode::Auto)
    }
}

/// `metadata.user_id` as a session key: itself when it fits, else `qb-sk:` and 32 hex digits
/// derived from all of it, so long SDK ids still keep a session on one login.
fn session_key(user_id: String) -> String {
    if user_id.len() <= MAX_SESSION_KEY {
        return user_id;
    }
    // Two FNV-1a passes with different offsets; stickiness needs determinism, not secrecy.
    let fnv = |offset: u64| {
        user_id.bytes().fold(offset, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    format!(
        "qb-sk:{:016x}{:016x}",
        fnv(0xcbf2_9ce4_8422_2325),
        fnv(0x6c62_272e_07bb_0142)
    )
}

fn media_type(s: &str) -> Option<MediaType> {
    Some(match s {
        "image/png" => MediaType::Png,
        "image/jpeg" => MediaType::Jpeg,
        "image/gif" => MediaType::Gif,
        "image/webp" => MediaType::Webp,
        _ => return None,
    })
}

fn canonical_block(b: ContentBlock, native_vendor: &str, at: &str) -> Result<Block, GatewayError> {
    Ok(match b {
        ContentBlock::Text { text, .. } => Block::Text { text },
        ContentBlock::Image { source, .. } => match source {
            crate::wire::ImageSource::Base64 {
                media_type: m,
                data,
            } => Block::Image {
                media_type: media_type(&m)
                    .ok_or_else(|| bad(format!("`{at}` has unsupported media type `{m}`")))?,
                path: None,
                base64: Some(data),
            },
            crate::wire::ImageSource::Other => {
                return Err(bad(format!("`{at}` needs a base64 image source")));
            }
        },
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Block::ToolUse {
            id,
            name,
            input: match input {
                Value::Object(m) => m,
                _ => return Err(bad(format!("`{at}.input` is not an object"))),
            },
        },
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => Block::ToolResult {
            id: tool_use_id,
            content: match content {
                None => String::new(),
                Some(ToolResultContent::Text(s)) => s,
                Some(ToolResultContent::Blocks(blocks)) => {
                    let mut texts = Vec::with_capacity(blocks.len());
                    for b in blocks {
                        match b {
                            ContentBlock::Text { text, .. } => texts.push(text),
                            ContentBlock::ToolReference { tool_name, name } => {
                                texts.push(loaded(tool_name.or(name).as_deref()));
                            }
                            _ => {
                                return Err(bad(format!(
                                    "`{at}.content` may hold text blocks only"
                                )));
                            }
                        }
                    }
                    texts.join("\n")
                }
            },
            is_error,
        },
        ContentBlock::RedactedThinking { data } if data.starts_with(FOREIGN_THINKING) => {
            let f: Foreign = serde_json::from_str(&data[FOREIGN_THINKING.len()..])
                .map_err(|_| bad(format!("`{at}` is a damaged thinking block")))?;
            Block::Thinking {
                vendor: f.vendor,
                opaque: f.opaque,
            }
        }
        b @ (ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. }) => {
            Block::Thinking {
                vendor: native_vendor.to_owned(),
                opaque: crate::request::thinking_to_opaque(&b),
            }
        }
        ContentBlock::ToolReference { tool_name, name } => Block::Text {
            text: loaded(tool_name.or(name).as_deref()),
        },
        ContentBlock::ToolAddition { .. } => {
            return Err(bad(format!(
                "`{at}` is a tool change outside a system message"
            )));
        }
        ContentBlock::Other => return Err(bad(format!("`{at}` has an unsupported block type"))),
    })
}

/// The text a `tool_reference` becomes: every tool goes upstream loaded, so a tool search's
/// result only tells the model the tool is there.
fn loaded(name: Option<&str>) -> String {
    format!("Tool `{}` is loaded.", name.unwrap_or_default())
}

/// The Anthropic block a canonical thinking event is shown as: the vendor's own block when it
/// comes from `native_vendor`, else a `redacted_thinking` block wrapping vendor and payload.
pub fn thinking_block(t: &Thinking, native_vendor: &str) -> ContentBlock {
    if t.vendor == native_vendor {
        if let Some(block) = thinking_from_opaque(&t.opaque) {
            return block;
        }
    }
    let wrapped = serde_json::to_string(&Foreign {
        vendor: t.vendor.clone(),
        opaque: t.opaque.clone(),
    })
    .unwrap_or_default();
    ContentBlock::RedactedThinking {
        data: format!("{FOREIGN_THINKING}{wrapped}"),
    }
}

/// The block a thinking event is shown as under `policy`; `None` when it is dropped.
fn shown_thinking(
    t: &Thinking,
    native_vendor: &str,
    policy: ForeignThinking,
) -> Option<ContentBlock> {
    match thinking_block(t, native_vendor) {
        ContentBlock::RedactedThinking { data }
            if policy == ForeignThinking::Drop && data.starts_with(FOREIGN_THINKING) =>
        {
            None
        }
        block => Some(block),
    }
}

fn wire_usage(u: Usage) -> WireUsage {
    WireUsage {
        input_tokens: Some(u.input),
        cache_creation_input_tokens: Some(u.cache_write),
        cache_read_input_tokens: Some(u.cache_read),
        output_tokens: Some(u.output),
    }
}

fn empty_message(id: &str, model: &str, usage: Usage) -> MessageResponse {
    MessageResponse {
        id: id.to_owned(),
        kind: "message".into(),
        role: "assistant".into(),
        model: model.to_owned(),
        content: Vec::new(),
        stop_reason: None,
        stop_sequence: None,
        usage: wire_usage(usage),
    }
}

fn event_bytes(event: &Event) -> Vec<u8> {
    let name = match event {
        Event::MessageStart { .. } => "message_start",
        Event::ContentBlockStart { .. } => "content_block_start",
        Event::ContentBlockDelta { .. } => "content_block_delta",
        Event::ContentBlockStop { .. } => "content_block_stop",
        Event::MessageDelta { .. } => "message_delta",
        Event::MessageStop => "message_stop",
        Event::Ping => "ping",
        Event::Error { .. } => "error",
        Event::Other => return Vec::new(),
    };
    sse::encode(name, &serde_json::to_string(event).unwrap_or_default())
}

/// Writes canonical events as an Anthropic Messages SSE stream, with block indices from 0 and
/// cumulative usage in `message_delta`.
///
/// `message_start` is deferred to the first event after `route`, so it carries the input usage
/// when the first event is `usage`.
#[derive(Debug)]
pub struct SseEncoder {
    id: String,
    model: String,
    native_vendor: String,
    foreign: ForeignThinking,
    started: bool,
    text_open: Option<u32>,
    next_index: u32,
    usage: Usage,
    done: bool,
}

impl SseEncoder {
    /// An encoder of message `id` answering `model` (as the client named it).
    pub fn new(id: &str, model: &str, native_vendor: &str) -> Self {
        Self {
            id: id.to_owned(),
            model: model.to_owned(),
            native_vendor: native_vendor.to_owned(),
            foreign: ForeignThinking::Keep,
            started: false,
            text_open: None,
            next_index: 0,
            usage: Usage::default(),
            done: false,
        }
    }

    /// The encoder with `policy` for thinking of other vendors.
    #[must_use]
    pub fn foreign_thinking(mut self, policy: ForeignThinking) -> Self {
        self.foreign = policy;
        self
    }

    /// Whether any byte went out; before that an error is better answered as an HTTP error.
    pub fn started(&self) -> bool {
        self.started
    }

    /// A keep-alive `ping` event.
    pub fn ping() -> Vec<u8> {
        event_bytes(&Event::Ping)
    }

    /// The bytes for one canonical event; empty when it produces none (`route`, events after the
    /// end).
    pub fn push(&mut self, event: &StreamEvent) -> Vec<u8> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        match event {
            StreamEvent::Route { .. } => {}
            StreamEvent::Usage { usage } => {
                self.usage = *usage;
                self.start(&mut out);
            }
            StreamEvent::TextDelta { text } => {
                self.start(&mut out);
                let index = if let Some(i) = self.text_open {
                    i
                } else {
                    let i = self.open_block(
                        ContentBlock::Text {
                            text: String::new(),
                            cache_control: None,
                        },
                        &mut out,
                    );
                    self.text_open = Some(i);
                    i
                };
                out.extend(event_bytes(&Event::ContentBlockDelta {
                    index,
                    delta: Delta::TextDelta { text: text.clone() },
                }));
            }
            StreamEvent::Thinking { thinking } => self.thinking(thinking, &mut out),
            StreamEvent::ToolCall { tool_call } => self.tool_call(tool_call, &mut out),
            StreamEvent::Stop { reason } => {
                self.start(&mut out);
                self.close_text(&mut out);
                out.extend(event_bytes(&Event::MessageDelta {
                    delta: MessageDeltaBody {
                        stop_reason: Some(stop_reason_name(*reason).into()),
                        stop_sequence: None,
                    },
                    usage: wire_usage(self.usage),
                }));
                out.extend(event_bytes(&Event::MessageStop));
                self.done = true;
            }
            StreamEvent::Error { error } => {
                self.started = true;
                out.extend(event_bytes(&Event::Error {
                    error: error_body(error).error,
                }));
                self.done = true;
            }
        }
        out
    }

    fn thinking(&mut self, thinking: &Thinking, out: &mut Vec<u8>) {
        self.start(out);
        let Some(block) = shown_thinking(thinking, &self.native_vendor, self.foreign) else {
            return;
        };
        self.close_text(out);
        match block {
            ContentBlock::Thinking {
                thinking,
                signature,
            } => {
                let index = self.open_block(
                    ContentBlock::Thinking {
                        thinking: String::new(),
                        signature: String::new(),
                    },
                    out,
                );
                if !thinking.is_empty() {
                    out.extend(event_bytes(&Event::ContentBlockDelta {
                        index,
                        delta: Delta::ThinkingDelta { thinking },
                    }));
                }
                out.extend(event_bytes(&Event::ContentBlockDelta {
                    index,
                    delta: Delta::SignatureDelta { signature },
                }));
                out.extend(event_bytes(&Event::ContentBlockStop { index }));
            }
            block => {
                let index = self.open_block(block, out);
                out.extend(event_bytes(&Event::ContentBlockStop { index }));
            }
        }
    }

    fn tool_call(&mut self, tool_call: &qb_proto::ToolCall, out: &mut Vec<u8>) {
        self.start(out);
        self.close_text(out);
        let index = self.open_block(
            ContentBlock::ToolUse {
                id: tool_call.id.clone(),
                name: tool_call.name.clone(),
                input: Value::Object(Object::new()),
                cache_control: None,
            },
            out,
        );
        out.extend(event_bytes(&Event::ContentBlockDelta {
            index,
            delta: Delta::InputJsonDelta {
                partial_json: Value::Object(tool_call.input.clone()).to_string(),
            },
        }));
        out.extend(event_bytes(&Event::ContentBlockStop { index }));
    }

    fn start(&mut self, out: &mut Vec<u8>) {
        if !self.started {
            self.started = true;
            out.extend(event_bytes(&Event::MessageStart {
                message: empty_message(&self.id, &self.model, self.usage),
            }));
        }
    }

    fn open_block(&mut self, block: ContentBlock, out: &mut Vec<u8>) -> u32 {
        let index = self.next_index;
        self.next_index += 1;
        out.extend(event_bytes(&Event::ContentBlockStart {
            index,
            content_block: block,
        }));
        index
    }

    fn close_text(&mut self, out: &mut Vec<u8>) {
        if let Some(index) = self.text_open.take() {
            out.extend(event_bytes(&Event::ContentBlockStop { index }));
        }
    }
}

/// Builds one non-streaming Messages response from canonical events.
#[derive(Debug)]
pub struct Assembler {
    message: MessageResponse,
    native_vendor: String,
    foreign: ForeignThinking,
    usage: Usage,
    stop: Option<StopReason>,
    error: Option<GatewayError>,
}

impl Assembler {
    /// An assembler of message `id` answering `model` (as the client named it).
    pub fn new(id: &str, model: &str, native_vendor: &str) -> Self {
        Self {
            message: empty_message(id, model, Usage::default()),
            native_vendor: native_vendor.to_owned(),
            foreign: ForeignThinking::Keep,
            usage: Usage::default(),
            stop: None,
            error: None,
        }
    }

    /// The assembler with `policy` for thinking of other vendors.
    #[must_use]
    pub fn foreign_thinking(mut self, policy: ForeignThinking) -> Self {
        self.foreign = policy;
        self
    }

    /// Adds one canonical event.
    pub fn push(&mut self, event: &StreamEvent) {
        if self.stop.is_some() || self.error.is_some() {
            return;
        }
        let content = &mut self.message.content;
        match event {
            StreamEvent::Route { .. } => {}
            StreamEvent::Usage { usage } => self.usage = *usage,
            StreamEvent::TextDelta { text } => match content.last_mut() {
                Some(ContentBlock::Text { text: t, .. }) => t.push_str(text),
                _ => content.push(ContentBlock::Text {
                    text: text.clone(),
                    cache_control: None,
                }),
            },
            StreamEvent::Thinking { thinking } => {
                content.extend(shown_thinking(thinking, &self.native_vendor, self.foreign));
            }
            StreamEvent::ToolCall { tool_call } => content.push(ContentBlock::ToolUse {
                id: tool_call.id.clone(),
                name: tool_call.name.clone(),
                input: Value::Object(tool_call.input.clone()),
                cache_control: None,
            }),
            StreamEvent::Stop { reason } => self.stop = Some(*reason),
            StreamEvent::Error { error } => self.error = Some(error.clone()),
        }
    }

    /// The response once the turn ended.
    ///
    /// # Errors
    /// The turn's error, or an `unavailable` error when it ended without `stop`.
    pub fn finish(self) -> Result<MessageResponse, GatewayError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        let Some(stop) = self.stop else {
            return Err(GatewayError::new(
                ErrorClass::Unavailable,
                true,
                "the turn ended without a stop",
            ));
        };
        let mut message = self.message;
        message.stop_reason = Some(stop_reason_name(stop).into());
        message.usage = wire_usage(self.usage);
        Ok(message)
    }
}

/// An Anthropic error answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    /// HTTP status.
    pub status: u16,
    /// `retry-after` header in seconds, when set.
    pub retry_after: Option<u64>,
    /// `x-should-retry` header, when set; Anthropic SDKs follow it over their own retry rules.
    pub should_retry: Option<bool>,
    /// JSON body.
    pub body: ErrorBody,
}

/// The Anthropic error body of a canonical error.
pub fn error_body(e: &GatewayError) -> ErrorBody {
    let (kind, default) = match e.class {
        ErrorClass::QuotaExhausted => (
            "rate_limit_error",
            "every login of the route is out of quota",
        ),
        ErrorClass::Auth => ("api_error", "the vendor rejected the gateway's credential"),
        ErrorClass::Unavailable => ("api_error", "no vendor of the route answered"),
        ErrorClass::Overloaded => ("overloaded_error", "overloaded"),
        ErrorClass::BadRequest => ("invalid_request_error", "invalid request"),
        ErrorClass::ContextTooLong => ("invalid_request_error", "prompt is too long"),
        ErrorClass::Cancelled => ("api_error", "the turn was cancelled"),
        ErrorClass::NoRoute => ("api_error", "no login of the route can serve this request"),
    };
    let detail = e.message.as_deref().filter(|m| !m.is_empty());
    let message = match (e.class, detail) {
        (ErrorClass::ContextTooLong, Some(m)) if !m.contains("prompt is too long") => {
            format!("prompt is too long: {m}")
        }
        (_, Some(m)) => m.to_owned(),
        (_, None) => default.to_owned(),
    };
    ErrorBody::new(kind, message)
}

/// A quota reset further away than this tells SDK clients not to retry.
pub const NO_RETRY_AFTER_S: u64 = 300;

/// The Anthropic error answer of a canonical error at `now`: 429 with `retry-after` until
/// `resets_at` for `quota_exhausted` (and `x-should-retry: false` beyond [`NO_RETRY_AFTER_S`]),
/// 529 for `overloaded`, 400 for `bad_request` and `context_too_long`, 502 for `unavailable`
/// and for `auth`, which is the vendor rejecting the gateway's credential, not the client's;
/// `cancelled` (409) and `no_route` (503) carry `x-should-retry: false`, since a retry cannot help.
pub fn error_response(e: &GatewayError, now: u64) -> ErrorResponse {
    let status = match e.class {
        ErrorClass::Overloaded => 529,
        ErrorClass::Auth => 502,
        c => c.http_status(),
    };
    let retry_after = match e.class {
        ErrorClass::QuotaExhausted => e
            .resets_at
            .map(|r| r.saturating_sub(now).max(1))
            .or(e.retry_after),
        _ => e.retry_after,
    };
    let should_retry = match e.class {
        ErrorClass::Cancelled | ErrorClass::NoRoute => Some(false),
        ErrorClass::QuotaExhausted => retry_after
            .is_some_and(|s| s > NO_RETRY_AFTER_S)
            .then_some(false),
        _ => None,
    };
    ErrorResponse {
        status,
        retry_after,
        should_retry,
        body: error_body(e),
    }
}
