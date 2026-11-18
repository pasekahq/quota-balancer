//! Client direction, the pure half of the `/v1/responses` front: a Responses request becomes a
//! canonical [`TurnRequest`]; canonical events become Responses SSE ([`SseEncoder`]) or one
//! response object ([`Assembler`]). Errors use [`crate::front`].
//!
//! The gateway is stateless: `previous_response_id`, `conversation` and item references are
//! refused, and reasoning travels in the client's history as `encrypted_content`.

use qb_proto::{
    Block, CacheMode, Elsewhere, ErrorClass, GatewayError, Message, NativeApi, NativeTool, Object,
    Role, StopReason, StreamEvent, Thinking, Tool, TurnRequest, Usage,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::chat::{arguments, empty_schema};
use crate::front::{
    FOREIGN_THINKING, ForeignThinking, FrontRequest, bad, check_tool_choice, effort, error_kind,
    image, join_system, push_message, responses_usage, session_key,
};
use crate::request::{
    CUSTOM_INPUT, TOOL_SEARCH, custom_input, native_kind, output_text, reasoning_from_opaque,
    reasoning_to_opaque,
};
use crate::sse;
use crate::wire::{
    Content, CreateResponse, IncompleteDetails, Input, Item, Part, ResponseError, ResponseEvent,
    ResponseObject, ResponseTool, event,
};

#[derive(Serialize, Deserialize)]
struct Foreign {
    vendor: String,
    opaque: String,
}

/// Decodes a Responses request body into a canonical turn with `request_id`.
///
/// `route_of` maps the client's `model` to a route alias; `default_max_tokens` bounds the output
/// when the request names no bound. `instructions` and `system`/`developer` messages join into
/// the system prompt; `function_call` items join the assistant message before them and
/// `function_call_output` items the user message after. A reasoning item with encrypted content
/// becomes canonical thinking of `native_vendor`, except one this front wrapped for another
/// vendor; one without is dropped. `cache` is always `auto`. `store`, `include`,
/// `reasoning.summary`, sampling parameters and `parallel_tool_calls` are ignored; a `tool_choice`
/// other than `auto` is refused.
///
/// # Errors
/// A `bad_request` error for a body that is not a Responses request, an unknown model, state the
/// gateway does not keep (`previous_response_id`, `conversation`, `item_reference`,
/// `background`), structured output, a `tool_choice` other than `auto`, non-function tools,
/// items or parts the canonical form cannot carry, a tool output that answers no earlier call,
/// or a turn that fails [`TurnRequest::validate`].
pub fn decode_request(
    body: &[u8],
    request_id: &str,
    native_vendor: &str,
    route_of: &dyn Fn(&str) -> Option<String>,
    default_max_tokens: u32,
) -> Result<FrontRequest, GatewayError> {
    let req: CreateResponse = serde_json::from_slice(body)
        .map_err(|e| bad(format!("body is not a Responses request: {e}")))?;
    reject_unsupported(&req)?;
    let route = route_of(&req.model).ok_or_else(|| {
        bad(format!(
            "model `{}` is not a route of this gateway",
            req.model
        ))
    })?;

    let (system, messages) = conversation(req.instructions, req.input, native_vendor)?;
    let tools = tools(req.tools.unwrap_or_default())?;

    let turn = TurnRequest {
        route,
        system: join_system(system),
        messages,
        tools,
        max_tokens: req.max_output_tokens.unwrap_or(default_max_tokens),
        effort: req
            .reasoning
            .and_then(|r| r.effort)
            .map(|e| effort(&e, "reasoning.effort"))
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
        include_usage: true,
    })
}

/// The system prompt parts and canonical messages of `instructions` and `input`.
fn conversation(
    instructions: Option<String>,
    input: Option<Input>,
    native_vendor: &str,
) -> Result<(Vec<String>, Vec<Message>), GatewayError> {
    let mut system: Vec<String> = instructions.into_iter().collect();
    let mut messages: Vec<Message> = Vec::new();
    let mut calls: Vec<String> = Vec::new();
    let items = match input {
        None => Vec::new(),
        Some(Input::Text(text)) => vec![Item {
            role: Some("user".into()),
            content: Some(Content::Text(text)),
            ..Item::default()
        }],
        Some(Input::Items(items)) => items,
    };
    for (i, item) in items.into_iter().enumerate() {
        let at = format!("input[{i}]");
        match item.kind.as_deref().unwrap_or("message") {
            "message" => {
                let role = item.role.as_deref().unwrap_or_default();
                let content = item
                    .content
                    .ok_or_else(|| bad(format!("`{at}.content` is missing")))?;
                match role {
                    "system" | "developer" if messages.is_empty() => {
                        system.push(text_of(content, &at)?);
                    }
                    "system" | "developer" => {
                        let text = text_of(content, &at)?;
                        if !text.is_empty() {
                            push_message(&mut messages, Role::System, vec![Block::Text { text }]);
                        }
                    }
                    "user" => {
                        let blocks = user_blocks(content, &at)?;
                        push_message(&mut messages, Role::User, blocks);
                    }
                    "assistant" => {
                        let text = text_of(content, &at)?;
                        if !text.is_empty() {
                            push_message(
                                &mut messages,
                                Role::Assistant,
                                vec![Block::Text { text }],
                            );
                        }
                    }
                    other => return Err(bad(format!("`{at}.role` `{other}` is not supported"))),
                }
            }
            // A search the vendor ran itself leaves nothing for the client to answer.
            "tool_search_call" | "tool_search_output"
                if item.execution.as_deref() == Some("server") => {}
            // Calls of tools the vendor runs itself: their results are already in the answer
            // that follows, and the vendor needs no record of them.
            kind if HOSTED_CALLS.contains(&kind) => {}
            kind @ ("function_call" | "custom_tool_call" | "tool_search_call") => {
                let kind = kind.to_owned();
                let block = call_of(&kind, item, &at)?;
                if let Block::ToolUse { id, .. } = &block {
                    calls.push(id.clone());
                }
                push_message(&mut messages, Role::Assistant, vec![block]);
            }
            "function_call_output" | "custom_tool_call_output" | "tool_search_output" => {
                let id = item
                    .call_id
                    .clone()
                    .ok_or_else(|| bad(format!("`{at}.call_id` is missing")))?;
                if !calls.contains(&id) {
                    return Err(bad(format!(
                        "`{at}` answers call `{id}`, which no earlier call item made"
                    )));
                }
                let content = match (item.output, item.tools) {
                    (_, Some(tools)) => Value::Array(tools).to_string(),
                    (None, None) => String::new(),
                    (Some(c), None) => text_of(c, &at)?,
                };
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
            "reasoning" => {
                if let Some(block) = thinking_of(&item, native_vendor, &at)? {
                    push_message(&mut messages, Role::Assistant, vec![block]);
                }
            }
            "item_reference" => {
                return Err(bad(format!(
                    "`{at}` is an item reference; the gateway keeps no items, send the item itself"
                )));
            }
            other => return Err(bad(format!("`{at}` has unsupported item type `{other}`"))),
        }
    }

    Ok((system, messages))
}

/// The `tool_use` of a call item: a `function_call` with its arguments, a `custom_tool_call`
/// with `{input: <text>}`, a client `tool_search_call` of [`TOOL_SEARCH`] with its arguments.
fn call_of(kind: &str, item: Item, at: &str) -> Result<Block, GatewayError> {
    let id = item
        .call_id
        .clone()
        .ok_or_else(|| bad(format!("`{at}.call_id` is missing")))?;
    let name = match kind {
        "tool_search_call" => TOOL_SEARCH.to_owned(),
        _ => item
            .name
            .clone()
            .ok_or_else(|| bad(format!("`{at}` needs call_id and name")))?,
    };
    let input = match (kind, item.arguments) {
        ("custom_tool_call", _) => {
            let mut input = Object::new();
            input.insert(
                CUSTOM_INPUT.into(),
                Value::String(item.input.unwrap_or_default()),
            );
            input
        }
        ("tool_search_call", None | Some(Value::Null)) => Object::new(),
        (_, Some(Value::Object(m))) => m,
        (_, Some(Value::String(s))) => arguments(&s, at)?,
        (_, None) => arguments("", at)?,
        (_, Some(_)) => return Err(bad(format!("`{at}.arguments` is not an object"))),
    };
    Ok(Block::ToolUse { id, name, input })
}

/// Output item types of tools the vendor runs itself, dropped from a client's history.
const HOSTED_CALLS: &[&str] = &[
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "mcp_call",
    "mcp_list_tools",
];

/// Tool types the vendor runs itself, or that only extend the toolset; another vendor leaves
/// them out.
const OMIT_ELSEWHERE: &[&str] = &[
    "web_search",
    "web_search_preview",
    "web_search_2025_08_26",
    "web_search_preview_2025_03_11",
    "file_search",
    "code_interpreter",
    "image_generation",
    "mcp",
    "tool_search",
];

/// Fields of a function tool that the canonical tool carries; a function tool with any other
/// field (`defer_loading`, …) keeps its declaration for a Responses upstream.
const FUNCTION_FIELDS: &[&str] = &["type", "name", "description", "parameters", "strict"];

/// The canonical tools of a request. Function tools become plain tools. Every other type keeps
/// its declaration for a Responses upstream; elsewhere a `custom` tool becomes a function of
/// one string argument `input`, the types in [`OMIT_ELSEWHERE`] are left out, and the rest fail
/// the attempt.
fn tools(input: Vec<Value>) -> Result<Vec<Tool>, GatewayError> {
    let mut tools: Vec<Tool> = Vec::with_capacity(input.len());
    for (i, raw) in input.into_iter().enumerate() {
        let Value::Object(spec) = raw else {
            return Err(bad(format!("`tools[{i}]` is not an object")));
        };
        let kind = spec
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let text = |key: &str| spec.get(key).and_then(Value::as_str).map(str::to_owned);
        let native = |spec: Object, elsewhere| {
            Some(NativeTool {
                api: NativeApi::OpenaiResponses,
                spec,
                elsewhere,
            })
        };
        let tool = match kind.as_str() {
            "function" => {
                let t: ResponseTool = serde_json::from_value(Value::Object(spec.clone()))
                    .map_err(|e| bad(format!("`tools[{i}]` is not a function tool: {e}")))?;
                let Some(name) = t.name else {
                    return Err(bad(format!("`tools[{i}]` needs a name")));
                };
                let plain = spec.keys().all(|k| FUNCTION_FIELDS.contains(&k.as_str()));
                Tool {
                    name,
                    description: t.description.unwrap_or_default(),
                    input_schema: t.parameters.unwrap_or_else(empty_schema),
                    native: if plain {
                        None
                    } else {
                        native(spec, Elsewhere::Function)
                    },
                }
            }
            "custom" => {
                let Some(name) = text("name") else {
                    return Err(bad(format!("`tools[{i}]` needs a name")));
                };
                let mut description = text("description").unwrap_or_default();
                if let Some(format) = spec.get("format").filter(|f| !f.is_null()) {
                    description.push_str("\n\nThe `");
                    description.push_str(CUSTOM_INPUT);
                    description.push_str("` argument is free text in this format: ");
                    description.push_str(&format.to_string());
                }
                Tool {
                    name,
                    description,
                    input_schema: custom_schema(),
                    native: native(spec, Elsewhere::Function),
                }
            }
            "" => return Err(bad(format!("`tools[{i}]` has no type"))),
            other => {
                let elsewhere = if OMIT_ELSEWHERE.contains(&other) {
                    Elsewhere::Omit
                } else {
                    Elsewhere::Refuse
                };
                let base = if other == "tool_search" {
                    TOOL_SEARCH.to_owned()
                } else {
                    text("name")
                        .or_else(|| text("server_label"))
                        .unwrap_or_else(|| other.to_owned())
                };
                let mut name = base.clone();
                let mut n = 2;
                while tools.iter().any(|t| t.name == name) {
                    name = format!("{base}_{n}");
                    n += 1;
                }
                Tool {
                    name,
                    description: text("description").unwrap_or_default(),
                    input_schema: match spec.get("parameters") {
                        Some(Value::Object(p)) => p.clone(),
                        _ => empty_schema(),
                    },
                    native: native(spec, elsewhere),
                }
            }
        };
        tools.push(tool);
    }
    Ok(tools)
}

/// The arguments of a `custom` tool offered as a function: one free-text string.
fn custom_schema() -> Object {
    let mut schema = Object::new();
    schema.insert("type".into(), "object".into());
    schema.insert(
        "properties".into(),
        serde_json::json!({ CUSTOM_INPUT: {"type": "string"} }),
    );
    schema.insert("required".into(), serde_json::json!([CUSTOM_INPUT]));
    schema
}

fn reject_unsupported(req: &CreateResponse) -> Result<(), GatewayError> {
    if req.previous_response_id.is_some() {
        return Err(bad(
            "`previous_response_id` is not supported: the gateway is stateless; send the whole \
             conversation in `input`",
        ));
    }
    if req.conversation.as_ref().is_some_and(|c| !c.is_null()) {
        return Err(bad(
            "`conversation` is not supported: the gateway is stateless; send the whole \
             conversation in `input`",
        ));
    }
    check_tool_choice(
        req.tool_choice.as_ref(),
        req.tools.as_ref().is_some_and(|t| !t.is_empty()),
    )?;
    if req.background == Some(true) {
        return Err(bad("`background` is not supported by this gateway"));
    }
    let format = req
        .text
        .as_ref()
        .and_then(|t| t.get("format"))
        .filter(|f| !f.is_null())
        .map(|f| f.get("type").and_then(Value::as_str).unwrap_or_default());
    if format.is_some_and(|t| t != "text") {
        return Err(bad(
            "`text.format` other than text is not supported by this gateway",
        ));
    }
    Ok(())
}

/// The text of content that may hold text and refusal parts only, joined without separator.
fn text_of(content: Content, at: &str) -> Result<String, GatewayError> {
    match content {
        Content::Text(s) => Ok(s),
        Content::Parts(parts) => {
            let mut out = String::new();
            for (j, p) in parts.into_iter().enumerate() {
                match (p.kind.as_str(), p.text, p.refusal) {
                    ("input_text" | "output_text" | "text", Some(t), _)
                    | ("refusal", _, Some(t)) => {
                        out.push_str(&t);
                    }
                    _ => {
                        return Err(bad(format!("`{at}.content[{j}]` must be a text part here")));
                    }
                }
            }
            Ok(out)
        }
    }
}

fn user_blocks(content: Content, at: &str) -> Result<Vec<Block>, GatewayError> {
    match content {
        Content::Text(text) => Ok(vec![Block::Text { text }]),
        Content::Parts(parts) => parts
            .into_iter()
            .enumerate()
            .map(|(j, p)| {
                let at = format!("{at}.content[{j}]");
                match (p.kind.as_str(), p.text, p.image_url) {
                    ("input_text" | "text", Some(text), _) => Ok(Block::Text { text }),
                    ("input_image", _, Some(url)) => image(&url, &format!("{at}.image_url")),
                    ("input_image", _, None) => Err(bad(format!(
                        "`{at}` needs an image_url; stored files are not supported"
                    ))),
                    (kind, _, _) => Err(bad(format!("`{at}` has unsupported part type `{kind}`"))),
                }
            })
            .collect(),
    }
}

/// The canonical thinking of a reasoning item: another vendor's thinking this front wrapped,
/// else thinking of `native_vendor` with the item's normal form; `None` without encrypted
/// content, which the vendor needs to use it again.
fn thinking_of(item: &Item, native_vendor: &str, at: &str) -> Result<Option<Block>, GatewayError> {
    if let Some(wrapped) = item
        .encrypted_content
        .as_deref()
        .and_then(|e| e.strip_prefix(FOREIGN_THINKING))
    {
        let f: Foreign = serde_json::from_str(wrapped)
            .map_err(|_| bad(format!("`{at}` is a damaged reasoning item")))?;
        return Ok(Some(Block::Thinking {
            vendor: f.vendor,
            opaque: f.opaque,
        }));
    }
    Ok(reasoning_to_opaque(item).map(|opaque| Block::Thinking {
        vendor: native_vendor.to_owned(),
        opaque,
    }))
}

/// The reasoning item (without id) a canonical thinking event is shown as: the vendor's own item
/// when it comes from `native_vendor`, else one whose `encrypted_content` wraps vendor and
/// payload.
pub fn reasoning_item(t: &Thinking, native_vendor: &str) -> Item {
    if t.vendor == native_vendor {
        if let Some(item) = reasoning_from_opaque(&t.opaque) {
            return item;
        }
    }
    let wrapped = serde_json::to_string(&Foreign {
        vendor: t.vendor.clone(),
        opaque: t.opaque.clone(),
    })
    .unwrap_or_default();
    Item {
        kind: Some("reasoning".into()),
        summary: Some(Vec::new()),
        encrypted_content: Some(format!("{FOREIGN_THINKING}{wrapped}")),
        ..Item::default()
    }
}

/// The text item being written.
#[derive(Debug)]
struct OpenText {
    index: u32,
    id: String,
    text: String,
}

/// Writes canonical events as a Responses SSE stream: `response.created` and
/// `response.in_progress`, one output item per text run, thinking block and tool call with its
/// full lifecycle (`output_item.added`, parts and deltas, `output_item.done`), then
/// `response.completed` or `response.incomplete` with every item and the usage. Every event
/// carries the next `sequence_number`.
///
/// The lifecycle start is deferred to the first event after `route`.
#[derive(Debug)]
pub struct SseEncoder {
    id: String,
    model: String,
    created: u64,
    native_vendor: String,
    foreign: ForeignThinking,
    write: bool,
    seq: u64,
    started: bool,
    items: Vec<Item>,
    text: Option<OpenText>,
    usage: Usage,
    done: bool,
    /// Names of the request's `custom` and `tool_search` tools, with that type.
    native: Vec<(String, String)>,
}

impl SseEncoder {
    /// An encoder of response `id` (sent as `resp_<id>`, items as `msg_<id>_<n>`, `rs_…`,
    /// `fc_…`) answering `model` (as the client named it) at `created`.
    pub fn new(id: &str, model: &str, created: u64, native_vendor: &str) -> Self {
        Self {
            id: id.to_owned(),
            model: model.to_owned(),
            created,
            native_vendor: native_vendor.to_owned(),
            foreign: ForeignThinking::Keep,
            write: true,
            seq: 0,
            started: false,
            items: Vec::new(),
            text: None,
            usage: Usage::default(),
            done: false,
            native: Vec::new(),
        }
    }

    /// The encoder for a request of `tools`: calls of a `custom` or `tool_search` tool go out
    /// as that tool's item type, not as `function_call`.
    #[must_use]
    pub fn tools(mut self, tools: &[Tool]) -> Self {
        self.native = tools
            .iter()
            .filter_map(|t| {
                let kind = native_kind(t).filter(|k| matches!(*k, "custom" | "tool_search"))?;
                Some((t.name.clone(), kind.to_owned()))
            })
            .collect();
        self
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

    /// A keep-alive comment.
    pub fn ping() -> Vec<u8> {
        sse::keep_alive()
    }

    /// The bytes for one canonical event; empty when it produces none.
    pub fn push(&mut self, ev: &StreamEvent) -> Vec<u8> {
        let mut out = Vec::new();
        if self.done {
            return out;
        }
        match ev {
            StreamEvent::Route { .. } => {}
            StreamEvent::Usage { usage } => {
                self.usage = *usage;
                self.start(&mut out);
            }
            StreamEvent::TextDelta { text } => self.text_delta(text, &mut out),
            StreamEvent::Thinking { thinking } => self.thinking(thinking, &mut out),
            StreamEvent::ToolCall { tool_call } => self.tool_call(tool_call, &mut out),
            StreamEvent::Stop { reason } => {
                self.start(&mut out);
                self.close_text(&mut out);
                let (kind, r) = self.ended(*reason);
                self.emit(
                    ResponseEvent {
                        response: Some(Box::new(r)),
                        ..ResponseEvent::of(kind)
                    },
                    &mut out,
                );
                self.done = true;
            }
            StreamEvent::Error { error } => {
                self.start(&mut out);
                self.close_text(&mut out);
                let body = crate::front::error_body(error, self.created);
                let (_, code) = error_kind(error, self.created);
                let code = code.unwrap_or(body.error.kind.as_str()).to_owned();
                self.emit(
                    ResponseEvent {
                        code: Some(code.clone()),
                        message: Some(body.error.message.clone()),
                        ..ResponseEvent::of(event::ERROR)
                    },
                    &mut out,
                );
                let mut r = self.response("failed");
                r.error = Some(ResponseError {
                    code: Some(code),
                    message: Some(body.error.message),
                });
                self.emit(
                    ResponseEvent {
                        response: Some(Box::new(r)),
                        ..ResponseEvent::of(event::FAILED)
                    },
                    &mut out,
                );
                self.done = true;
            }
        }
        out
    }

    fn response(&self, status: &str) -> ResponseObject {
        ResponseObject {
            id: format!("resp_{}", self.id),
            object: "response".into(),
            created_at: self.created,
            status: status.into(),
            model: self.model.clone(),
            output: self.items.clone(),
            usage: None,
            incomplete_details: None,
            error: None,
        }
    }

    /// The final event type and response of a turn that stopped for `reason`.
    fn ended(&self, reason: StopReason) -> (&'static str, ResponseObject) {
        let mut r = self.response("completed");
        r.usage = Some(responses_usage(self.usage));
        let incomplete = match reason {
            StopReason::MaxTokens => "max_output_tokens",
            StopReason::Refusal => "content_filter",
            StopReason::End | StopReason::ToolUse => return (event::COMPLETED, r),
        };
        r.status = "incomplete".into();
        r.incomplete_details = Some(IncompleteDetails {
            reason: incomplete.into(),
        });
        (event::INCOMPLETE, r)
    }

    fn emit(&mut self, mut ev: ResponseEvent, out: &mut Vec<u8>) {
        ev.sequence_number = Some(self.seq);
        self.seq += 1;
        if self.write {
            out.extend(sse::encode(
                &ev.kind,
                &serde_json::to_string(&ev).unwrap_or_default(),
            ));
        }
    }

    fn start(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        for kind in [event::CREATED, event::IN_PROGRESS] {
            let r = self.response("in_progress");
            self.emit(
                ResponseEvent {
                    response: Some(Box::new(r)),
                    ..ResponseEvent::of(kind)
                },
                out,
            );
        }
    }

    fn next_index(&self) -> u32 {
        u32::try_from(self.items.len()).unwrap_or(u32::MAX)
    }

    fn item_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}_{}", self.id, self.items.len())
    }

    fn text_delta(&mut self, text: &str, out: &mut Vec<u8>) {
        self.start(out);
        if self.text.is_none() {
            let index = self.next_index();
            let id = self.item_id("msg");
            let item = message_item(&id, "in_progress", Vec::new());
            self.emit(item_event(event::OUTPUT_ITEM_ADDED, index, item), out);
            self.emit(
                ResponseEvent {
                    item_id: Some(id.clone()),
                    output_index: Some(index),
                    content_index: Some(0),
                    part: Some(output_text("")),
                    ..ResponseEvent::of(event::CONTENT_PART_ADDED)
                },
                out,
            );
            self.text = Some(OpenText {
                index,
                id,
                text: String::new(),
            });
        }
        let Some(open) = self.text.as_mut() else {
            return;
        };
        open.text.push_str(text);
        let ev = ResponseEvent {
            item_id: Some(open.id.clone()),
            output_index: Some(open.index),
            content_index: Some(0),
            delta: Some(text.to_owned()),
            logprobs: Some(Vec::new()),
            ..ResponseEvent::of(event::OUTPUT_TEXT_DELTA)
        };
        self.emit(ev, out);
    }

    fn close_text(&mut self, out: &mut Vec<u8>) {
        let Some(OpenText { index, id, text }) = self.text.take() else {
            return;
        };
        let text_ev = |kind: &str| ResponseEvent {
            item_id: Some(id.clone()),
            output_index: Some(index),
            content_index: Some(0),
            ..ResponseEvent::of(kind)
        };
        self.emit(
            ResponseEvent {
                text: Some(text.clone()),
                logprobs: Some(Vec::new()),
                ..text_ev(event::OUTPUT_TEXT_DONE)
            },
            out,
        );
        self.emit(
            ResponseEvent {
                part: Some(output_text(&text)),
                ..text_ev(event::CONTENT_PART_DONE)
            },
            out,
        );
        let item = message_item(&id, "completed", vec![output_text(&text)]);
        self.emit(
            item_event(event::OUTPUT_ITEM_DONE, index, item.clone()),
            out,
        );
        self.items.push(item);
    }

    fn thinking(&mut self, thinking: &Thinking, out: &mut Vec<u8>) {
        self.start(out);
        let mut item = reasoning_item(thinking, &self.native_vendor);
        let foreign = item
            .encrypted_content
            .as_deref()
            .is_some_and(|e| e.starts_with(FOREIGN_THINKING));
        if foreign && self.foreign == ForeignThinking::Drop {
            return;
        }
        self.close_text(out);
        let index = self.next_index();
        let id = self.item_id("rs");
        item.id = Some(id.clone());
        let added = Item {
            kind: item.kind.clone(),
            id: item.id.clone(),
            summary: Some(Vec::new()),
            ..Item::default()
        };
        self.emit(item_event(event::OUTPUT_ITEM_ADDED, index, added), out);
        for (j, s) in item.summary.iter().flatten().enumerate() {
            let j = u32::try_from(j).unwrap_or(u32::MAX);
            let part_ev = |kind: &str, text: &str| ResponseEvent {
                item_id: Some(id.clone()),
                output_index: Some(index),
                summary_index: Some(j),
                part: Some(Part {
                    kind: "summary_text".into(),
                    text: Some(text.into()),
                    ..Part::default()
                }),
                ..ResponseEvent::of(kind)
            };
            self.emit(part_ev(event::REASONING_SUMMARY_PART_ADDED, ""), out);
            let text_ev = |kind: &str| ResponseEvent {
                item_id: Some(id.clone()),
                output_index: Some(index),
                summary_index: Some(j),
                ..ResponseEvent::of(kind)
            };
            self.emit(
                ResponseEvent {
                    delta: Some(s.text.clone()),
                    ..text_ev(event::REASONING_SUMMARY_TEXT_DELTA)
                },
                out,
            );
            self.emit(
                ResponseEvent {
                    text: Some(s.text.clone()),
                    ..text_ev(event::REASONING_SUMMARY_TEXT_DONE)
                },
                out,
            );
            self.emit(part_ev(event::REASONING_SUMMARY_PART_DONE, &s.text), out);
        }
        self.emit(
            item_event(event::OUTPUT_ITEM_DONE, index, item.clone()),
            out,
        );
        self.items.push(item);
    }

    fn tool_call(&mut self, call: &qb_proto::ToolCall, out: &mut Vec<u8>) {
        self.start(out);
        self.close_text(out);
        let kind = self
            .native
            .iter()
            .find(|(n, _)| *n == call.name)
            .map(|(_, k)| k.clone());
        match kind.as_deref() {
            Some("custom") => {
                let id = self.item_id("ctc");
                let item = |status: &str, input: &str| Item {
                    kind: Some("custom_tool_call".into()),
                    id: Some(id.clone()),
                    status: Some(status.into()),
                    call_id: Some(call.id.clone()),
                    name: Some(call.name.clone()),
                    input: Some(input.into()),
                    ..Item::default()
                };
                let (added, done) = (
                    item("in_progress", ""),
                    item("completed", &custom_input(&call.input)),
                );
                return self.whole_item(added, done, out);
            }
            Some("tool_search") => {
                let id = self.item_id("tsc");
                let item = |status: &str, arguments: Object| Item {
                    kind: Some("tool_search_call".into()),
                    id: Some(id.clone()),
                    status: Some(status.into()),
                    call_id: Some(call.id.clone()),
                    execution: Some("client".into()),
                    arguments: Some(Value::Object(arguments)),
                    ..Item::default()
                };
                let (added, done) = (
                    item("in_progress", Object::new()),
                    item("completed", call.input.clone()),
                );
                return self.whole_item(added, done, out);
            }
            _ => {}
        }
        let index = self.next_index();
        let id = self.item_id("fc");
        let args = Value::Object(call.input.clone()).to_string();
        let item = |status: &str, arguments: &str| Item {
            kind: Some("function_call".into()),
            id: Some(id.clone()),
            status: Some(status.into()),
            call_id: Some(call.id.clone()),
            name: Some(call.name.clone()),
            arguments: Some(Value::String(arguments.into())),
            ..Item::default()
        };
        self.emit(
            item_event(event::OUTPUT_ITEM_ADDED, index, item("in_progress", "")),
            out,
        );
        let args_ev = |kind: &str| ResponseEvent {
            item_id: Some(id.clone()),
            output_index: Some(index),
            ..ResponseEvent::of(kind)
        };
        self.emit(
            ResponseEvent {
                delta: Some(args.clone()),
                ..args_ev(event::FUNCTION_CALL_ARGUMENTS_DELTA)
            },
            out,
        );
        self.emit(
            ResponseEvent {
                arguments: Some(args.clone()),
                ..args_ev(event::FUNCTION_CALL_ARGUMENTS_DONE)
            },
            out,
        );
        let done = item("completed", &args);
        self.emit(
            item_event(event::OUTPUT_ITEM_DONE, index, done.clone()),
            out,
        );
        self.items.push(done);
    }
}

impl SseEncoder {
    /// One output item without deltas: `output_item.added`, then `output_item.done`.
    fn whole_item(&mut self, added: Item, done: Item, out: &mut Vec<u8>) {
        let index = self.next_index();
        self.emit(item_event(event::OUTPUT_ITEM_ADDED, index, added), out);
        self.emit(
            item_event(event::OUTPUT_ITEM_DONE, index, done.clone()),
            out,
        );
        self.items.push(done);
    }
}

fn item_event(kind: &str, index: u32, item: Item) -> ResponseEvent {
    ResponseEvent {
        output_index: Some(index),
        item: Some(item),
        ..ResponseEvent::of(kind)
    }
}

fn message_item(id: &str, status: &str, content: Vec<Part>) -> Item {
    Item {
        kind: Some("message".into()),
        id: Some(id.into()),
        status: Some(status.into()),
        role: Some("assistant".into()),
        content: Some(Content::Parts(content)),
        ..Item::default()
    }
}

/// Builds one non-streaming Responses object from canonical events, with the same items and ids
/// as [`SseEncoder`] would stream.
#[derive(Debug)]
pub struct Assembler {
    encoder: SseEncoder,
    stop: Option<StopReason>,
    error: Option<GatewayError>,
}

impl Assembler {
    /// An assembler of response `id` for `model` at `created`; see [`SseEncoder::new`].
    pub fn new(id: &str, model: &str, created: u64, native_vendor: &str) -> Self {
        let mut encoder = SseEncoder::new(id, model, created, native_vendor);
        encoder.write = false;
        Self {
            encoder,
            stop: None,
            error: None,
        }
    }

    /// The assembler with `policy` for thinking of other vendors.
    #[must_use]
    pub fn foreign_thinking(mut self, policy: ForeignThinking) -> Self {
        self.encoder.foreign = policy;
        self
    }

    /// The assembler for a request of `tools`; see [`SseEncoder::tools`].
    #[must_use]
    pub fn tools(mut self, tools: &[Tool]) -> Self {
        self.encoder = self.encoder.tools(tools);
        self
    }

    /// Adds one canonical event.
    pub fn push(&mut self, ev: &StreamEvent) {
        if self.stop.is_some() || self.error.is_some() {
            return;
        }
        match ev {
            StreamEvent::Stop { reason } => {
                self.encoder.close_text(&mut Vec::new());
                self.stop = Some(*reason);
            }
            StreamEvent::Error { error } => self.error = Some(error.clone()),
            other => {
                self.encoder.push(other);
            }
        }
    }

    /// The response object once the turn ended: `completed`, or `incomplete` with
    /// `incomplete_details` for `max_tokens` and `refusal`.
    ///
    /// # Errors
    /// The turn's error, or an `unavailable` error when it ended without `stop`.
    pub fn finish(self) -> Result<ResponseObject, GatewayError> {
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
        let (_, r) = self.encoder.ended(stop);
        Ok(r)
    }
}
