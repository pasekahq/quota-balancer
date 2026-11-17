//! Client direction, the pure half of the `/v1/chat/completions` front: a Chat Completions
//! request becomes a canonical [`TurnRequest`]; canonical events become Chat Completions SSE
//! ([`SseEncoder`]) or one response body ([`Assembler`]). Errors use [`crate::front`].
//!
//! Chat Completions has no field for reasoning, so canonical thinking is not shown and cannot
//! come back on this front.

use qb_proto::{
    Block, CacheMode, ErrorClass, GatewayError, Message, Role, StopReason, StreamEvent, Tool,
    TurnRequest, Usage,
};
use serde_json::{Value, json};

use crate::front::{
    FrontRequest, bad, chat_usage, effort, error_body, finish_reason, image, join_system,
    push_message, session_key,
};
use crate::sse;
use crate::wire::{
    ChatChunk, ChatContent, ChatMessage, ChatPart, ChatRequest, ChatResponse, ChatTool,
    ChatToolCall, Choice, ChunkChoice, ChunkDelta, ChunkFunction, ChunkToolCall, FunctionCall,
};

/// The schema of a function declared without `parameters`: no arguments.
pub(crate) fn empty_schema() -> qb_proto::Object {
    match json!({"type": "object", "properties": {}}) {
        Value::Object(m) => m,
        _ => qb_proto::Object::new(),
    }
}

/// Decodes a Chat Completions request body into a canonical turn with `request_id`.
///
/// `route_of` maps the client's `model` to a route alias; `default_max_tokens` bounds the output
/// when the request names no bound. `system` and `developer` messages join into the system
/// prompt; each `tool` message becomes a tool result merged with its neighbours into one user
/// message. `cache` is always `auto`, as OpenAI caches prompts without being asked. Sampling
/// parameters, `stop`, `tool_choice` and `parallel_tool_calls` are ignored.
///
/// # Errors
/// A `bad_request` error for a body that is not a Chat Completions request, an unknown model,
/// a feature the canonical form cannot carry (`n` > 1, logprobs, audio, structured output,
/// non-function tools, image URLs that are not base64 `data:` URLs, audio and file parts), a
/// tool message that answers no earlier tool call, or a turn that fails
/// [`TurnRequest::validate`].
pub fn decode_request(
    body: &[u8],
    request_id: &str,
    route_of: &dyn Fn(&str) -> Option<String>,
    default_max_tokens: u32,
) -> Result<FrontRequest, GatewayError> {
    let req: ChatRequest = serde_json::from_slice(body)
        .map_err(|e| bad(format!("body is not a Chat Completions request: {e}")))?;
    reject_unsupported(&req)?;
    let route = route_of(&req.model).ok_or_else(|| {
        bad(format!(
            "model `{}` is not a route of this gateway",
            req.model
        ))
    })?;

    let (system, messages) = conversation(req.messages)?;
    let tools = tools(req.tools.unwrap_or_default())?;

    let turn = TurnRequest {
        route,
        system: join_system(system),
        messages,
        tools,
        max_tokens: req
            .max_completion_tokens
            .or(req.max_tokens)
            .unwrap_or(default_max_tokens),
        effort: req
            .reasoning_effort
            .as_deref()
            .map(|e| effort(e, "reasoning_effort"))
            .transpose()?,
        session_key: req
            .prompt_cache_key
            .as_deref()
            .or(req.user.as_deref())
            .and_then(session_key),
        cache: Some(CacheMode::Auto),
        request_id: request_id.to_owned(),
    };
    turn.validate().map_err(|e| bad(e.0))?;
    Ok(FrontRequest {
        turn,
        stream: req.stream.unwrap_or(false),
        model: req.model,
        include_usage: req
            .stream_options
            .and_then(|o| o.include_usage)
            .unwrap_or(false),
    })
}

/// The system prompt parts and canonical messages of a Chat Completions conversation.
fn conversation(input: Vec<ChatMessage>) -> Result<(Vec<String>, Vec<Message>), GatewayError> {
    let mut system = Vec::new();
    let mut messages: Vec<Message> = Vec::with_capacity(input.len());
    let mut calls: Vec<String> = Vec::new();
    for (i, m) in input.into_iter().enumerate() {
        let at = format!("messages[{i}]");
        match m.role.as_str() {
            "system" | "developer" => system.push(text_of(m.content, &at)?),
            "user" => {
                let blocks = user_blocks(m.content, &at)?;
                push_message(&mut messages, Role::User, blocks);
            }
            "assistant" => {
                let mut blocks = Vec::new();
                let mut text = text_of(m.content, &at)?;
                text.push_str(m.refusal.as_deref().unwrap_or_default());
                if !text.is_empty() {
                    blocks.push(Block::Text { text });
                }
                for (j, c) in m.tool_calls.into_iter().flatten().enumerate() {
                    let at = format!("{at}.tool_calls[{j}]");
                    if c.kind != "function" {
                        return Err(bad(format!("`{at}` is not a function call")));
                    }
                    calls.push(c.id.clone());
                    blocks.push(Block::ToolUse {
                        id: c.id,
                        name: c.function.name,
                        input: arguments(&c.function.arguments, &at)?,
                    });
                }
                push_message(&mut messages, Role::Assistant, blocks);
            }
            "tool" => {
                let id = m
                    .tool_call_id
                    .ok_or_else(|| bad(format!("`{at}.tool_call_id` is missing")))?;
                if !calls.contains(&id) {
                    return Err(bad(format!(
                        "`{at}` answers tool call `{id}`, which no earlier assistant message made"
                    )));
                }
                let content = text_of(m.content, &at)?;
                push_message(
                    &mut messages,
                    Role::User,
                    vec![Block::ToolResult {
                        id,
                        content,
                        is_error: None,
                    }],
                );
            }
            other => return Err(bad(format!("`{at}.role` `{other}` is not supported"))),
        }
    }

    Ok((system, messages))
}

fn tools(input: Vec<ChatTool>) -> Result<Vec<Tool>, GatewayError> {
    let mut tools = Vec::with_capacity(input.len());
    for (i, t) in input.into_iter().enumerate() {
        let ("function", Some(f)) = (t.kind.as_str(), t.function) else {
            return Err(bad(format!("`tools[{i}]` is not a function tool")));
        };
        tools.push(Tool {
            name: f.name,
            description: f.description.unwrap_or_default(),
            input_schema: f.parameters.unwrap_or_else(empty_schema),
        });
    }
    Ok(tools)
}

fn reject_unsupported(req: &ChatRequest) -> Result<(), GatewayError> {
    let unsupported = |what: &str| Err(bad(format!("{what} is not supported by this gateway")));
    if req.n.is_some_and(|n| n != 1) {
        return unsupported("`n` other than 1");
    }
    if req.logprobs == Some(true) || req.top_logprobs.is_some_and(|n| n > 0) {
        return unsupported("`logprobs`");
    }
    if req.audio.as_ref().is_some_and(|a| !a.is_null()) {
        return unsupported("`audio`");
    }
    if req.modalities.iter().flatten().any(|m| m != "text") {
        return unsupported("an output modality other than text");
    }
    let format = req
        .response_format
        .as_ref()
        .filter(|f| !f.is_null())
        .map(|f| f.get("type").and_then(Value::as_str).unwrap_or_default());
    if format.is_some_and(|t| t != "text") {
        return unsupported("`response_format` other than text");
    }
    Ok(())
}

/// The text of content that may hold text and refusal parts only, joined without separator.
fn text_of(content: Option<ChatContent>, at: &str) -> Result<String, GatewayError> {
    match content {
        None => Ok(String::new()),
        Some(ChatContent::Text(s)) => Ok(s),
        Some(ChatContent::Parts(parts)) => {
            let mut out = String::new();
            for (j, p) in parts.into_iter().enumerate() {
                match (p.kind.as_str(), p.text, p.refusal) {
                    ("text", Some(t), _) | ("refusal", _, Some(t)) => out.push_str(&t),
                    _ => {
                        return Err(bad(format!("`{at}.content[{j}]` must be a text part here")));
                    }
                }
            }
            Ok(out)
        }
    }
}

fn user_blocks(content: Option<ChatContent>, at: &str) -> Result<Vec<Block>, GatewayError> {
    match content {
        None => Err(bad(format!("`{at}.content` is missing"))),
        Some(ChatContent::Text(text)) => Ok(vec![Block::Text { text }]),
        Some(ChatContent::Parts(parts)) => parts
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                let at = format!("{at}.content[{j}]");
                match p {
                    ChatPart {
                        kind,
                        text: Some(text),
                        ..
                    } if kind == "text" => Ok(Block::Text { text }),
                    ChatPart {
                        kind,
                        image_url: Some(url),
                        ..
                    } if kind == "image_url" => image(&url.url, &format!("{at}.image_url.url")),
                    ChatPart { kind, .. } => {
                        Err(bad(format!("`{at}` has unsupported part type `{kind}`")))
                    }
                }
            })
            .collect(),
    }
}

/// Tool arguments: a JSON object string; empty means no arguments.
pub(crate) fn arguments(s: &str, at: &str) -> Result<qb_proto::Object, GatewayError> {
    if s.trim().is_empty() {
        return Ok(qb_proto::Object::new());
    }
    match serde_json::from_str::<Value>(s) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(bad(format!("`{at}` arguments are not a JSON object"))),
    }
}

fn chunk(
    id: &str,
    model: &str,
    created: u64,
    delta: ChunkDelta,
    finish: Option<StopReason>,
) -> ChatChunk {
    ChatChunk {
        id: id.to_owned(),
        object: "chat.completion.chunk".into(),
        created,
        model: model.to_owned(),
        choices: vec![ChunkChoice {
            index: 0,
            delta,
            finish_reason: finish.map(|r| finish_reason(r).to_owned()),
        }],
        usage: None,
    }
}

fn chunk_bytes(c: &ChatChunk) -> Vec<u8> {
    sse::encode_data(&serde_json::to_string(c).unwrap_or_default())
}

/// Writes canonical events as a Chat Completions SSE stream: chunks with the same `id`,
/// `created` and `model`, tool calls by index from 0, a last chunk with `finish_reason`, a usage
/// chunk when asked, and `data: [DONE]`.
///
/// The first chunk (role `assistant`) is deferred to the first text or tool call; `usage` and
/// `thinking` write nothing.
#[derive(Debug)]
pub struct SseEncoder {
    id: String,
    model: String,
    created: u64,
    include_usage: bool,
    started: bool,
    tool_index: u32,
    usage: Usage,
    done: bool,
}

impl SseEncoder {
    /// An encoder of completion `id` (sent as `chatcmpl-<id>`) answering `model` (as the client
    /// named it) at `created`, with a usage chunk when `include_usage`.
    pub fn new(id: &str, model: &str, created: u64, include_usage: bool) -> Self {
        Self {
            id: format!("chatcmpl-{id}"),
            model: model.to_owned(),
            created,
            include_usage,
            started: false,
            tool_index: 0,
            usage: Usage::default(),
            done: false,
        }
    }

    /// Whether any byte went out; before that an error is better answered as an HTTP error.
    pub fn started(&self) -> bool {
        self.started
    }

    /// A keep-alive comment.
    pub fn ping() -> Vec<u8> {
        sse::keep_alive()
    }

    fn chunk(&self, delta: ChunkDelta, finish: Option<StopReason>) -> Vec<u8> {
        chunk_bytes(&chunk(&self.id, &self.model, self.created, delta, finish))
    }

    fn start(&mut self, out: &mut Vec<u8>) {
        if !self.started {
            self.started = true;
            out.extend(self.chunk(
                ChunkDelta {
                    role: Some("assistant".into()),
                    content: Some(String::new()),
                    tool_calls: None,
                },
                None,
            ));
        }
    }

    /// The bytes for one canonical event; empty when it produces none.
    pub fn push(&mut self, event: &StreamEvent) -> Vec<u8> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        match event {
            StreamEvent::Route { .. } | StreamEvent::Thinking { .. } => {}
            StreamEvent::Usage { usage } => self.usage = *usage,
            StreamEvent::TextDelta { text } => {
                self.start(&mut out);
                out.extend(self.chunk(
                    ChunkDelta {
                        content: Some(text.clone()),
                        ..ChunkDelta::default()
                    },
                    None,
                ));
            }
            StreamEvent::ToolCall { tool_call } => {
                self.start(&mut out);
                let index = self.tool_index;
                self.tool_index += 1;
                out.extend(self.chunk(
                    ChunkDelta {
                        tool_calls: Some(vec![ChunkToolCall {
                            index,
                            id: Some(tool_call.id.clone()),
                            kind: Some("function".into()),
                            function: Some(ChunkFunction {
                                name: Some(tool_call.name.clone()),
                                arguments: Some(Value::Object(tool_call.input.clone()).to_string()),
                            }),
                        }]),
                        ..ChunkDelta::default()
                    },
                    None,
                ));
            }
            StreamEvent::Stop { reason } => {
                self.start(&mut out);
                out.extend(self.chunk(ChunkDelta::default(), Some(*reason)));
                if self.include_usage {
                    let mut c = chunk(
                        &self.id,
                        &self.model,
                        self.created,
                        ChunkDelta::default(),
                        None,
                    );
                    c.choices.clear();
                    c.usage = Some(chat_usage(self.usage));
                    out.extend(chunk_bytes(&c));
                }
                out.extend(sse::encode_data("[DONE]"));
                self.done = true;
            }
            StreamEvent::Error { error } => {
                self.started = true;
                out.extend(sse::encode_data(
                    &serde_json::to_string(&error_body(error, self.created)).unwrap_or_default(),
                ));
                self.done = true;
            }
        }
        out
    }
}

/// Builds one non-streaming Chat Completions response from canonical events.
#[derive(Debug)]
pub struct Assembler {
    id: String,
    model: String,
    created: u64,
    text: String,
    tool_calls: Vec<ChatToolCall>,
    usage: Usage,
    stop: Option<StopReason>,
    error: Option<GatewayError>,
}

impl Assembler {
    /// An assembler of completion `id` (answered as `chatcmpl-<id>`) for `model` at `created`.
    pub fn new(id: &str, model: &str, created: u64) -> Self {
        Self {
            id: format!("chatcmpl-{id}"),
            model: model.to_owned(),
            created,
            text: String::new(),
            tool_calls: Vec::new(),
            usage: Usage::default(),
            stop: None,
            error: None,
        }
    }

    /// Adds one canonical event.
    pub fn push(&mut self, event: &StreamEvent) {
        if self.stop.is_some() || self.error.is_some() {
            return;
        }
        match event {
            StreamEvent::Route { .. } | StreamEvent::Thinking { .. } => {}
            StreamEvent::Usage { usage } => self.usage = *usage,
            StreamEvent::TextDelta { text } => self.text.push_str(text),
            StreamEvent::ToolCall { tool_call } => self.tool_calls.push(ChatToolCall {
                id: tool_call.id.clone(),
                kind: "function".into(),
                function: FunctionCall {
                    name: tool_call.name.clone(),
                    arguments: Value::Object(tool_call.input.clone()).to_string(),
                },
            }),
            StreamEvent::Stop { reason } => self.stop = Some(*reason),
            StreamEvent::Error { error } => self.error = Some(error.clone()),
        }
    }

    /// The response once the turn ended.
    ///
    /// # Errors
    /// The turn's error, or an `unavailable` error when it ended without `stop`.
    pub fn finish(self) -> Result<ChatResponse, GatewayError> {
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
        let has_calls = !self.tool_calls.is_empty();
        Ok(ChatResponse {
            id: self.id,
            object: "chat.completion".into(),
            created: self.created,
            model: self.model,
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".into(),
                    content: (!self.text.is_empty() || !has_calls)
                        .then_some(ChatContent::Text(self.text)),
                    tool_calls: has_calls.then_some(self.tool_calls),
                    ..ChatMessage::default()
                },
                finish_reason: Some(finish_reason(stop).into()),
                logprobs: None,
            }],
            usage: Some(chat_usage(self.usage)),
        })
    }
}
