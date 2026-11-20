//! Wire types of the model gateway (`qb gateway`): `POST /v1/model/turn` and its NDJSON stream,
//! `GET /v1/model/routes` and `POST /v1/model/cancel`. The contract is in `docs/api.md`.
//!
//! Variants are internally tagged by `type`, so a block or an event is one flat JSON object:
//! `{"type": "text", "text": "..."}`, `{"type": "stop", "reason": "end"}`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A JSON object, such as tool arguments or a tool's input schema.
pub type Object = Map<String, Value>;

/// Longest route alias, `request_id` and tool name.
pub const MAX_NAME: usize = 64;
/// Longest `session_key`.
pub const MAX_SESSION_KEY: usize = 128;

/// `POST /v1/model/turn` request: one model turn on a route alias.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnRequest {
    /// Route alias from the gateway config, e.g. `chat`.
    pub route: String,
    /// System prompt of the client, without any vendor prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    /// Conversation, oldest first; at least one message.
    pub messages: Vec<Message>,
    /// Tools the model may call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,
    /// Upper bound of output tokens, at least 1.
    pub max_tokens: u32,
    /// Reasoning effort, mapped to the picked model's setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
    /// Opaque session id; the gateway keeps a session on one login where it can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
    /// Prompt cache policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheMode>,
    /// Client-chosen id of the turn, unique among the client's running turns.
    pub request_id: String,
}

/// Reasoning effort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effort {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// The model's maximum.
    Max,
}

/// Prompt cache policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// The gateway places cache breakpoints for the picked vendor.
    Auto,
}

/// Author of a message; tool results travel in `user` messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The client.
    User,
    /// The model.
    Assistant,
    /// An instruction of the client from this point of the conversation on, text blocks only
    /// (Anthropic's mid-conversation system message, OpenAI's `developer` message). An upstream
    /// that cannot place it there adds its text to the system prompt.
    System,
}

/// One conversation message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Author.
    pub role: Role,
    /// Blocks in order; at least one.
    pub content: Vec<Block>,
}

/// One message block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", try_from = "WireBlock")]
pub enum Block {
    /// Text.
    Text {
        /// The text.
        text: String,
    },
    /// An image, from exactly one of `path` and `base64`.
    Image {
        /// Media type.
        media_type: MediaType,
        /// Absolute path of a local file; part of the contract's shape, refused by `qb gateway`,
        /// which reads no file a client names.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// Standard base64 of the image bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base64: Option<String>,
    },
    /// A tool call of the model, echoed back from a `tool_call` event.
    ToolUse {
        /// Tool-call id.
        id: String,
        /// Tool name.
        name: String,
        /// Tool arguments.
        input: Object,
    },
    /// The output of a tool call.
    ToolResult {
        /// Id of the `tool_use` it answers.
        id: String,
        /// Tool output as text.
        content: String,
        /// The tool failed; absent means false.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
    /// A thinking block, echoed back unchanged from a `thinking` event.
    Thinking {
        /// Vendor that produced it; blocks of another vendor than the picked one are dropped.
        vendor: String,
        /// Vendor payload.
        opaque: String,
    },
}

/// The kind of a [`Block`] on the wire.
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BlockKind {
    Text,
    Image,
    ToolUse,
    ToolResult,
    Thinking,
}

/// A [`Block`] as one flat object. Decoding through it, rather than through serde's buffered
/// internally tagged enums, keeps the gateway binary small; the wire shape is the same.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBlock {
    #[serde(rename = "type")]
    kind: BlockKind,
    text: Option<String>,
    media_type: Option<MediaType>,
    path: Option<String>,
    base64: Option<String>,
    id: Option<String>,
    name: Option<String>,
    input: Option<Object>,
    content: Option<String>,
    is_error: Option<bool>,
    vendor: Option<String>,
    opaque: Option<String>,
}

impl TryFrom<WireBlock> for Block {
    type Error = String;

    fn try_from(w: WireBlock) -> Result<Self, String> {
        let kind = match w.kind {
            BlockKind::Text => "text",
            BlockKind::Image => "image",
            BlockKind::ToolUse => "tool_use",
            BlockKind::ToolResult => "tool_result",
            BlockKind::Thinking => "thinking",
        };
        let set = [
            ("text", w.text.is_some()),
            ("media_type", w.media_type.is_some()),
            ("path", w.path.is_some()),
            ("base64", w.base64.is_some()),
            ("id", w.id.is_some()),
            ("name", w.name.is_some()),
            ("input", w.input.is_some()),
            ("content", w.content.is_some()),
            ("is_error", w.is_error.is_some()),
            ("vendor", w.vendor.is_some()),
            ("opaque", w.opaque.is_some()),
        ];
        let own: &[&str] = match w.kind {
            BlockKind::Text => &["text"],
            BlockKind::Image => &["media_type", "path", "base64"],
            BlockKind::ToolUse => &["id", "name", "input"],
            BlockKind::ToolResult => &["id", "content", "is_error"],
            BlockKind::Thinking => &["vendor", "opaque"],
        };
        if let Some((field, _)) = set.iter().find(|(f, on)| *on && !own.contains(f)) {
            return Err(format!("unknown field `{field}` in a `{kind}` block"));
        }
        let need = |v: Option<String>, field: &str| {
            v.ok_or_else(|| format!("missing field `{field}` in a `{kind}` block"))
        };
        Ok(match w.kind {
            BlockKind::Text => Self::Text {
                text: need(w.text, "text")?,
            },
            BlockKind::Image => Self::Image {
                media_type: w
                    .media_type
                    .ok_or("missing field `media_type` in a `image` block")?,
                path: w.path,
                base64: w.base64,
            },
            BlockKind::ToolUse => Self::ToolUse {
                id: need(w.id, "id")?,
                name: need(w.name, "name")?,
                input: w
                    .input
                    .ok_or("missing field `input` in a `tool_use` block")?,
            },
            BlockKind::ToolResult => Self::ToolResult {
                id: need(w.id, "id")?,
                content: need(w.content, "content")?,
                is_error: w.is_error,
            },
            BlockKind::Thinking => Self::Thinking {
                vendor: need(w.vendor, "vendor")?,
                opaque: need(w.opaque, "opaque")?,
            },
        })
    }
}

/// Media type of an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    /// PNG.
    #[serde(rename = "image/png")]
    Png,
    /// JPEG.
    #[serde(rename = "image/jpeg")]
    Jpeg,
    /// GIF.
    #[serde(rename = "image/gif")]
    Gif,
    /// WebP.
    #[serde(rename = "image/webp")]
    Webp,
}

/// A tool the model may call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// Tool name, unique within the request.
    pub name: String,
    /// What the tool does, for the model.
    pub description: String,
    /// JSON Schema of the arguments.
    pub input_schema: Object,
    /// The tool as the client declared it in a vendor API, when it is not a plain function
    /// tool there; an upstream of that API sends the declaration as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeTool>,
}

/// A tool declaration in a vendor API's own form.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTool {
    /// The API of the declaration.
    pub api: NativeApi,
    /// The declaration as the client sent it.
    pub spec: Object,
    /// What an upstream of another API does with the tool.
    pub elsewhere: Elsewhere,
}

/// A vendor API whose tool declarations a [`NativeTool`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeApi {
    /// The OpenAI Responses API.
    OpenaiResponses,
}

/// What an upstream of another API does with a [`NativeTool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Elsewhere {
    /// Offer it as a function tool of `name`, `description` and `input_schema`.
    Function,
    /// Leave it out: the vendor runs the tool itself or it only extends the toolset, so the
    /// model works without it.
    Omit,
    /// Fail the attempt with `bad_request`: the client expects calls only that API makes.
    Refuse,
}

/// Why a [`TurnRequest`] is malformed beyond what JSON decoding catches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRequestError(pub String);

/// Whether `s` is a valid route alias: `^[a-z][a-z0-9_-]{0,63}$`.
pub fn is_alias(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && s.len() <= MAX_NAME
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl TurnRequest {
    /// Checks the invariants that the type system does not express.
    ///
    /// # Errors
    /// The first violated invariant, as a message naming the field.
    pub fn validate(&self) -> Result<(), TurnRequestError> {
        let fail = |m: String| Err(TurnRequestError(m));
        if !is_alias(&self.route) {
            return fail("`route` must match ^[a-z][a-z0-9_-]{0,63}$".into());
        }
        if !is_name(&self.request_id) {
            return fail("`request_id` must match ^[A-Za-z0-9_-]{1,64}$".into());
        }
        if self.max_tokens == 0 {
            return fail("`max_tokens` must be at least 1".into());
        }
        if self
            .session_key
            .as_ref()
            .is_some_and(|k| k.is_empty() || k.len() > MAX_SESSION_KEY)
        {
            return fail("`session_key` must have 1 to 128 bytes".into());
        }
        if self.messages.is_empty() {
            return fail("`messages` is empty".into());
        }
        if self.messages.iter().all(|m| m.role == Role::System) {
            return fail("`messages` has no user or assistant message".into());
        }
        for (i, m) in self.messages.iter().enumerate() {
            if m.content.is_empty() {
                return fail(format!("`messages[{i}].content` is empty"));
            }
            if m.role == Role::System && m.content.iter().any(|b| !matches!(b, Block::Text { .. }))
            {
                return fail(format!(
                    "`messages[{i}]` is a system message with a non-text block"
                ));
            }
            for (j, b) in m.content.iter().enumerate() {
                let at = format!("messages[{i}].content[{j}]");
                match b {
                    Block::Image { path, base64, .. } => match (path, base64) {
                        (Some(p), None) if p.starts_with('/') => {}
                        (Some(_), None) => return fail(format!("`{at}.path` must be absolute")),
                        (None, Some(b)) if !b.is_empty() => {}
                        _ => return fail(format!("`{at}` needs exactly one of path and base64")),
                    },
                    Block::ToolUse { id, name, .. } if id.is_empty() || name.is_empty() => {
                        return fail(format!("`{at}` needs a non-empty id and name"));
                    }
                    Block::ToolResult { id, .. } if id.is_empty() => {
                        return fail(format!("`{at}.id` is empty"));
                    }
                    Block::Thinking { vendor, .. } if vendor.is_empty() => {
                        return fail(format!("`{at}.vendor` is empty"));
                    }
                    _ => {}
                }
            }
        }
        for (i, t) in self.tools.iter().enumerate() {
            if !is_name(&t.name) {
                return fail(format!(
                    "`tools[{i}].name` must match ^[A-Za-z0-9_-]{{1,64}}$"
                ));
            }
            if self.tools[..i].iter().any(|o| o.name == t.name) {
                return fail(format!("tool `{}` is declared twice", t.name));
            }
        }
        Ok(())
    }
}

/// One NDJSON line of the turn stream. A stream carries `route`, then any number of
/// `text_delta`, `thinking`, `tool_call` and `usage`, and ends with exactly one `stop` or
/// `error`; a turn that fails before any vendor answered is one `error` without `route`. A
/// stream without a final event was cut by a transport failure. A response type: fields a later
/// version adds are ignored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    /// Where the turn runs; sent before the first other event.
    Route {
        /// Vendor, model, login and lease.
        route: RouteInfo,
    },
    /// Next piece of the answer text.
    TextDelta {
        /// The text.
        text: String,
    },
    /// A complete thinking block.
    Thinking {
        /// The block.
        thinking: Thinking,
    },
    /// A complete tool call.
    ToolCall {
        /// The call.
        tool_call: ToolCall,
    },
    /// Token counts so far; a later `usage` replaces an earlier one.
    Usage {
        /// The counts.
        usage: Usage,
    },
    /// The turn ended.
    Stop {
        /// Why.
        reason: StopReason,
    },
    /// The turn failed.
    Error {
        /// How.
        error: GatewayError,
    },
}

/// Where the gateway runs a turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInfo {
    /// Vendor name from the config.
    pub vendor: String,
    /// Model id.
    pub model: String,
    /// Login name; never a credential.
    pub login_label: String,
    /// qbd lease id of the turn.
    pub lease: String,
}

/// A complete thinking block; the client echoes it back as a `thinking` block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thinking {
    /// Vendor name of the picked route.
    pub vendor: String,
    /// Vendor payload, passed back unchanged.
    pub opaque: String,
}

/// A complete tool call; the client echoes it back as a `tool_use` block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool-call id.
    pub id: String,
    /// Tool name from the request.
    pub name: String,
    /// Tool arguments.
    pub input: Object,
}

/// Token counts of a turn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// Input tokens not read from cache.
    pub input: u64,
    /// Output tokens.
    pub output: u64,
    /// Input tokens read from the prompt cache.
    pub cache_read: u64,
    /// Input tokens written to the prompt cache.
    pub cache_write: u64,
}

/// Why a turn ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Finished.
    End,
    /// Waits for tool results.
    ToolUse,
    /// Hit `max_tokens`.
    MaxTokens,
    /// Declined by the model.
    Refusal,
}

impl StopReason {
    /// The wire name, e.g. `tool_use`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::End => "end",
            Self::ToolUse => "tool_use",
            Self::MaxTokens => "max_tokens",
            Self::Refusal => "refusal",
        }
    }
}

/// Failure class of a turn or a rejected request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Every candidate of the route waits for a reset or back-off; `resets_at` says until when.
    QuotaExhausted,
    /// A login, or the caller, was rejected.
    Auth,
    /// No vendor of the route answered.
    Unavailable,
    /// Asked to back off.
    Overloaded,
    /// The request is invalid.
    BadRequest,
    /// The conversation does not fit the model.
    ContextTooLong,
    /// The turn was cancelled by `POST /v1/model/cancel`.
    Cancelled,
    /// qbd has no candidate the route can ever run on (`dead`).
    NoRoute,
}

impl ErrorClass {
    /// The wire name, e.g. `quota_exhausted`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuotaExhausted => "quota_exhausted",
            Self::Auth => "auth",
            Self::Unavailable => "unavailable",
            Self::Overloaded => "overloaded",
            Self::BadRequest => "bad_request",
            Self::ContextTooLong => "context_too_long",
            Self::Cancelled => "cancelled",
            Self::NoRoute => "no_route",
        }
    }

    /// HTTP status of a gateway answer that rejects a request with this class.
    pub fn http_status(self) -> u16 {
        match self {
            Self::BadRequest | Self::ContextTooLong => 400,
            Self::Auth => 401,
            Self::Cancelled => 409,
            Self::QuotaExhausted | Self::Overloaded => 429,
            Self::Unavailable => 502,
            Self::NoRoute => 503,
        }
    }
}

/// A failed turn: the payload of an `error` event and the body of every non-200 gateway answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayError {
    /// Failure class; authoritative over the HTTP status.
    pub class: ErrorClass,
    /// A retry after `retry_after` (or soon) may succeed.
    pub retryable: bool,
    /// Seconds to wait before a retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// Unix time of the nearest reset that makes the route usable again (`quota_exhausted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
    /// Attempts of this turn, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tried: Vec<Attempt>,
    /// Human-readable detail, without credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl GatewayError {
    /// An error of `class` with a message and nothing else.
    pub fn new(class: ErrorClass, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            class,
            retryable,
            retry_after: None,
            resets_at: None,
            tried: Vec::new(),
            message: Some(message.into()),
        }
    }
}

/// One login a turn tried, and how it failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// Vendor.
    pub vendor: String,
    /// Model id.
    pub model: String,
    /// Login name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_label: Option<String>,
    /// How it failed.
    pub class: ErrorClass,
}

/// State of a route alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteState {
    /// Its requested ladder step or pin has a login now.
    Ready,
    /// Only a neighbouring ladder step has a login now.
    Degraded,
    /// Every candidate waits for a reset.
    Exhausted,
    /// No candidate can run.
    Unavailable,
}

/// One route alias and where a turn would run now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteStatus {
    /// Route alias.
    pub alias: String,
    /// State.
    pub state: RouteState,
    /// Vendor a turn would use now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Model a turn would use now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Nearest reset (`exhausted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
}

/// `GET /v1/model/routes` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutesAnswer {
    /// Route aliases, sorted by alias.
    pub routes: Vec<RouteStatus>,
}

/// The vendor API family the gateway's logins of a vendor speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiFamily {
    /// The Anthropic Messages API.
    Anthropic,
    /// The OpenAI APIs.
    Openai,
    /// The Chat Completions API of an OpenAI-compatible vendor.
    ChatCompletions,
}

/// A candidate of a ladder step and the state of the gateway's logins of its vendor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderCandidateState {
    /// Vendor.
    pub vendor: String,
    /// API family of the gateway's first login of the vendor; absent when it holds none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiFamily>,
    /// Model.
    pub model: String,
    /// Reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Tier; lower tiers are preferred.
    pub tier: u8,
    /// `ready`, `exhausted` or `unavailable`, by the rule of `GET /v1/model/routes`.
    pub state: RouteState,
    /// Nearest reset (`exhausted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
}

/// A ladder step and the route aliases of the caller that run on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderStepState {
    /// Difficulty the step serves.
    pub difficulty: u8,
    /// Ladder route aliases the caller may use that name the step, sorted.
    pub routes: Vec<String>,
    /// Candidates in ladder order.
    pub candidates: Vec<LadderCandidateState>,
}

/// `GET /v1/model/ladder` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderAnswer {
    /// The `qbd` role.
    pub role: String,
    /// Steps by difficulty.
    pub steps: Vec<LadderStepState>,
}

/// `POST /v1/model/cancel` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelRequest {
    /// `request_id` of the caller's running turn.
    pub request_id: String,
}

/// `POST /v1/model/cancel` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelAnswer {
    /// A running turn of the caller with this id was stopped; false when none was running.
    pub cancelled: bool,
}

/// `POST /v1/model/reload` response: the config now serving later turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadAnswer {
    /// Route aliases of the new config.
    pub routes: usize,
    /// Logins of the new config.
    pub logins: usize,
}

/// The spend of one login with a `spend_cap` in the current UTC calendar month.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginSpend {
    /// Login name.
    pub login: String,
    /// USD counted this month.
    pub spent_usd: f64,
    /// The login's `spend_cap` in USD; at or above it the login is not called.
    pub cap_usd: f64,
    /// Unix time the month ends and the count starts again from zero.
    pub period_end: u64,
}

/// `GET /v1/model/spend` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendAnswer {
    /// Every login of the config with a `spend_cap`, in config order.
    pub logins: Vec<LoginSpend>,
}

/// `POST /v1/model/spend/reset` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpendReset {
    /// The login whose count goes back to zero.
    pub login: String,
}

/// `POST /v1/model/clients/{name}/rotate` response. It never holds the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRotateAnswer {
    /// Name of the `[[fronts.clients]]` entry whose token was rotated.
    pub client: String,
    /// The first 12 hex characters of the new token's SHA-256.
    pub token_sha256_prefix: String,
    /// Unix time until which the previous token stays accepted.
    pub grace_until: u64,
}

/// `POST /v1/model/logins/{name}/key` request: the new key of an `api_key` login. It has no
/// `Debug`, so no format of it shows the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginKey {
    /// The key: 1 to [`MAX_LOGIN_KEY`] bytes of visible ASCII.
    pub key: String,
}

/// Longest key of a [`LoginKey`] in bytes.
pub const MAX_LOGIN_KEY: usize = 4096;

impl LoginKey {
    /// Checks the key is 1 to [`MAX_LOGIN_KEY`] bytes of visible ASCII, so it fits in a header.
    ///
    /// # Errors
    /// The rule it breaks, never the key.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.key.is_empty() {
            return Err("`key` is empty");
        }
        if self.key.len() > MAX_LOGIN_KEY {
            return Err("`key` is longer than 4096 bytes");
        }
        if !self.key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("`key` holds whitespace, a control character or non-ASCII");
        }
        Ok(())
    }
}

/// `POST /v1/model/logins/{name}/key` response. It never holds the key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginKeyAnswer {
    /// Name of the `[[logins]]` entry whose key was replaced.
    pub login: String,
    /// Path of the copy of the credential file it replaced; `None` when there was no file.
    pub backup: Option<String>,
    /// The first 12 hex characters of the new key's SHA-256.
    pub key_sha256_prefix: String,
}

/// What the operator pastes back after signing in at the URL of a [`LoginOauthStarted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OauthPaste {
    /// An `oauth_anthropic` login: the `code#state` the vendor's page shows.
    CodeState,
    /// A `chatgpt_oauth` login: the full address of the localhost page the browser then fails to
    /// load.
    RedirectUrl,
}

/// `POST /v1/model/logins/{name}/oauth/start` response: a PKCE sign-in waiting for the paste.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginOauthStarted {
    /// Name of the `[[logins]]` entry signing in.
    pub login: String,
    /// The vendor's authorize URL with the S256 challenge and the state.
    pub url: String,
    /// What to send back as `pasted` of a [`LoginOauthCode`].
    pub paste: OauthPaste,
    /// Unix time after which the sign-in takes no code.
    pub expires_at: u64,
}

/// `POST /v1/model/logins/{name}/oauth/code` request: what the operator pasted back. It has no
/// `Debug`, so no format of it shows the code.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginOauthCode {
    /// The `code#state` or the redirect URL, as [`LoginOauthStarted::paste`] says.
    pub pasted: String,
}

/// `POST /v1/model/logins/{name}/oauth/code` response. It never holds a code or a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginOauthSigned {
    /// Name of the `[[logins]]` entry signed in.
    pub login: String,
    /// Path of the copy of the credential file it replaced; `None` when there was no file.
    pub backup: Option<String>,
}

/// One step of a chain route as `/v1/model/config/routes` carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigStep {
    /// Pinned vendor.
    pub vendor: String,
    /// Pinned model.
    pub model: String,
    /// Reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

/// One `[[routes]]` item of the gateway config file, key for key. Integers take any TOML
/// integer: the gateway's config parser judges every value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRoute {
    /// Alias clients name in `route`.
    pub alias: String,
    /// qbd role of the pick.
    pub role: String,
    /// Ladder step of the role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<i64>,
    /// Pinned vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Pinned model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Reasoning effort of the pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Pins a turn tries in order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<ConfigStep>>,
    /// Expected minutes of a turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_minutes: Option<i64>,
    /// Whose reasoning effort a turn sends: `use` (the client's, else the pick's) or `ignore`
    /// (the pick's only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_effort: Option<String>,
}

/// `GET /v1/model/config/routes` response: the `[[routes]]` items and the `api_key` logins'
/// `spend_cap`s of the config file on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigRoutes {
    /// Hex SHA-256 of the config file; also the answer's `ETag`.
    pub sha256: String,
    /// The items in file order.
    pub routes: Vec<ConfigRoute>,
    /// USD `spend_cap` of each `api_key` login by name; `None` for one without a cap.
    #[serde(default)]
    pub spend_caps: BTreeMap<String, Option<f64>>,
}

/// `PUT /v1/model/config/routes` request: the items that replace the file's `[[routes]]`, the
/// `spend_cap`s to set or remove, or both; the gateway refuses a body with neither.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRoutesPut {
    /// The new items in file order; `None` keeps the file's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<Vec<ConfigRoute>>,
    /// USD `spend_cap` of `api_key` logins by name, `None` to remove it; logins not named keep
    /// theirs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_caps: Option<BTreeMap<String, Option<f64>>>,
}

/// `PUT /v1/model/config/routes` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRoutesWritten {
    /// Hex SHA-256 of the config file written and now serving, or of the file left as it was.
    pub sha256: String,
    /// Path of the copy of the file it replaced; absent when the edit changed no byte and
    /// nothing was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
}

/// An admin action of the gateway, as its audit line names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// `POST /v1/model/reload` or a SIGHUP: the config file read again.
    Reload,
    /// `POST /v1/model/spend/reset`: a login's spend count set to zero.
    SpendReset,
    /// `POST /v1/model/clients/{name}/rotate`: a fresh token written to a named loopback
    /// client's `token_file`.
    ClientRotate,
    /// `PUT /v1/model/config/routes` with `routes`: the config file's `[[routes]]` replaced,
    /// with any `spend_caps` set, and reloaded.
    ConfigRoutes,
    /// `PUT /v1/model/config/routes` with `spend_caps` only: logins' `spend_cap`s set or removed
    /// in the config file and reloaded.
    ConfigSpendCaps,
    /// `POST /v1/model/logins/{name}/key`: a new key written to an `api_key` login's credential
    /// file.
    LoginKey,
    /// `POST /v1/model/logins/{name}/oauth/start`: a PKCE sign-in of an OAuth login started.
    LoginOauthStart,
    /// `POST /v1/model/logins/{name}/oauth/code`: the code of a sign-in exchanged and the new
    /// tokens written to the login's credential file.
    LoginOauthCode,
    /// `PUT /v1/admin/roles` forwarded to `qbd`: its `roles_file` replaced and reloaded.
    AdminRoles,
    /// `POST /v1/admin/reload` forwarded to `qbd`: its config files read again.
    AdminReload,
}

/// Whether an admin action went through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// It answered 200.
    Ok,
    /// It was refused or failed; `reason` says why.
    Refused,
}

/// One line of the gateway's `audit_file`: an admin action and its result. No field holds a
/// token, key or credential content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unix time of the action.
    pub at: u64,
    /// `uid:<n>` for a unix socket caller, `signal` for a SIGHUP reload.
    pub actor: String,
    /// What was done.
    pub action: AuditAction,
    /// The login of a spend reset, a key replacement or a sign-in, the config file of a reload or
    /// a config edit, the client of a rotation, `qbd`'s socket of a forwarded admin request;
    /// absent when a refused request named none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Whether it went through.
    pub result: AuditResult,
    /// Why it was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// A reload or a config edit: hex SHA-256 of the config file before the action; a forwarded
    /// roles edit that went through: of `qbd`'s roles file before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_sha256_before: Option<String>,
    /// A reload or a config edit: hex SHA-256 of the config file after it; the same as before
    /// when it was refused, unless a refused edit had replaced the file. A forwarded roles edit
    /// that went through: of `qbd`'s roles file after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_sha256_after: Option<String>,
    /// Path of the copy an action kept of what it replaced: the config file of a config edit,
    /// the credential file of a key replacement or a sign-in, `qbd`'s roles file of a forwarded
    /// roles edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
    /// A rotation that went through: the first 12 hex characters of the new token's SHA-256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_sha256_prefix: Option<String>,
    /// A key replacement that went through: the first 12 hex characters of the new key's
    /// SHA-256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sha256_prefix: Option<String>,
}

/// `GET /v1/model/audit` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnswer {
    /// The first `limit` entries at or after `since`, oldest first.
    pub entries: Vec<AuditEntry>,
    /// Lines of the file that do not parse as an entry or are too long; they are left out.
    pub skipped: u64,
}

/// Where a usage line's `usd` comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsdSource {
    /// The cost the vendor reported for the attempt.
    Vendor,
    /// The attempt's usage at the model's entry of the config's `[prices]`.
    Prices,
}

/// Most tool names a usage line lists.
pub const MAX_USAGE_TOOLS: usize = 64;

/// One line of the gateway's usage ledger: one attempt of a turn that reached a vendor adapter.
/// No field holds prompt or answer text, thinking, tool arguments or results, headers or
/// credentials.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageLine {
    /// Unix time the attempt ended.
    pub at: u64,
    /// Milliseconds from the credential load to the attempt's end.
    pub duration_ms: u64,
    /// The turn's `request_id`.
    pub request_id: String,
    /// The turn's caller name.
    pub client: String,
    /// The turn's route alias.
    pub route: String,
    /// Index of the chain step the attempt ran on; 0 on a route without a chain.
    pub step: u32,
    /// Login the attempt ran on.
    pub login: String,
    /// Model id the attempt ran.
    pub model: String,
    /// Outcome the gateway reported to qbd for the attempt.
    pub outcome: crate::Outcome,
    /// Why the vendor finished; absent when the attempt failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<StopReason>,
    /// Failure class of an attempt that failed or was cancelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorClass>,
    /// The attempt's last `usage`; zeros when the vendor reported none.
    #[serde(flatten)]
    pub usage: Usage,
    /// USD of the attempt; absent when the vendor reported no cost and the model has no price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<f64>,
    /// Where `usd` comes from; present with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_source: Option<UsdSource>,
    /// Sorted unique names of the attempt's tool calls, each at most [`MAX_NAME`] bytes, at most
    /// [`MAX_USAGE_TOOLS`].
    pub tools: Vec<String>,
}

/// What the rows of a usage aggregate are grouped by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageGroupBy {
    /// The turn's caller.
    Client,
    /// The login the attempt ran on.
    Login,
    /// The model the attempt ran.
    Model,
    /// The turn's route alias.
    Route,
    /// Each tool name of the attempt; an attempt counts once under each and not at all without
    /// tools, so the rows' sums overlap.
    Tool,
}

impl UsageGroupBy {
    /// Every grouping, in wire order.
    pub const ALL: [Self; 5] = [
        Self::Client,
        Self::Login,
        Self::Model,
        Self::Route,
        Self::Tool,
    ];

    /// The wire name, e.g. `login`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Login => "login",
            Self::Model => "model",
            Self::Route => "route",
            Self::Tool => "tool",
        }
    }
}

/// The UTC period a usage aggregate's rows are bucketed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageBucket {
    /// A UTC hour.
    Hour,
    /// A UTC day.
    Day,
    /// A UTC calendar month.
    Month,
}

impl UsageBucket {
    /// Every bucket, in wire order.
    pub const ALL: [Self; 3] = [Self::Hour, Self::Day, Self::Month];

    /// The wire name, e.g. `day`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// The query parameters of `GET /v1/model/usage`, carried in its query string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageQuery {
    /// Unix time; lines with an earlier `at` are left out.
    pub from: u64,
    /// Unix time after `from`, at most [`MAX_USAGE_WINDOW_S`] later; lines at or after it are
    /// left out. Absent means the time of the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<u64>,
    /// What the rows are grouped by; absent means one group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by: Option<UsageGroupBy>,
    /// The UTC period of the rows; absent means the whole window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<UsageBucket>,
}

/// Longest window of a usage query: 400 days.
pub const MAX_USAGE_WINDOW_S: u64 = 400 * 86_400;

/// Most rows of a usage answer; a query that would make more is refused.
pub const MAX_USAGE_ROWS: usize = 10_000;

/// The sums of the usage lines of one bucket and group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageRow {
    /// Start of the row's UTC bucket, which may lie before `from`; `from` without a bucket.
    pub start: u64,
    /// The row's client, login, model, route or tool; absent without `group_by`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Attempts counted.
    pub attempts: u64,
    /// Attempts whose `outcome` is not `ok`.
    pub failed: u64,
    /// Input tokens not read from cache.
    pub input: u64,
    /// Output tokens.
    pub output: u64,
    /// Input tokens read from the prompt cache.
    pub cache_read: u64,
    /// Input tokens written to the prompt cache.
    pub cache_write: u64,
    /// USD of the attempts that have one.
    pub usd: f64,
    /// Attempts without `usd`.
    pub unpriced: u64,
    /// Sum of the attempts' `duration_ms`.
    pub duration_ms: u64,
}

/// `GET /v1/model/usage` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageAnswer {
    /// Start of the window.
    pub from: u64,
    /// End of the window, exclusive.
    pub to: u64,
    /// What the rows are grouped by; absent for one group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_by: Option<UsageGroupBy>,
    /// The UTC period of the rows; absent for the whole window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<UsageBucket>,
    /// One row per bucket and group with an attempt, ordered by `start`, then `group`.
    pub rows: Vec<UsageRow>,
    /// Lines of the files read that do not parse as a usage line or are too long; they are
    /// left out.
    pub skipped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_and_names() {
        for ok in ["chat", "a", "c-1_x"] {
            assert!(is_alias(ok), "{ok}");
        }
        for bad in ["", "Chat", "1chat", "ch at", &"a".repeat(65)] {
            assert!(!is_alias(bad), "{bad}");
        }
        assert!(is_name("Turn_0-1"));
        assert!(!is_name("turn/1"));
        assert!(!is_name(""));
    }

    #[test]
    fn blocks_take_only_their_own_fields() {
        let ok: Block =
            serde_json::from_str(r#"{"type":"tool_result","id":"c","content":"x"}"#).unwrap();
        assert_eq!(
            ok,
            Block::ToolResult {
                id: "c".into(),
                content: "x".into(),
                is_error: None
            }
        );
        for (raw, want) in [
            (
                r#"{"type":"text","text":"a","id":"c"}"#,
                "unknown field `id` in a `text` block",
            ),
            (r#"{"type":"text"}"#, "missing field `text`"),
            (r#"{"type":"text","text":"a","x":1}"#, "unknown field `x`"),
            (r#"{"type":"video","text":"a"}"#, "unknown variant `video`"),
            (
                r#"{"type":"image","base64":"AA=="}"#,
                "missing field `media_type`",
            ),
        ] {
            let e = serde_json::from_str::<Block>(raw).unwrap_err().to_string();
            assert!(e.contains(want), "{raw}: {e}");
        }
    }

    #[test]
    fn error_classes_map_to_http() {
        assert_eq!(ErrorClass::QuotaExhausted.http_status(), 429);
        assert_eq!(ErrorClass::BadRequest.http_status(), 400);
    }
}
