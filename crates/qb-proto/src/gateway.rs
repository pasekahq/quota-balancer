//! Wire types of the model gateway (`qb gateway`): `POST /v1/model/turn` and its NDJSON stream,
//! `GET /v1/model/routes` and `POST /v1/model/cancel`. The contract is in `docs/api.md`.
//!
//! Variants are internally tagged by `type`, so a block or an event is one flat JSON object:
//! `{"type": "text", "text": "..."}`, `{"type": "stop", "reason": "end"}`.

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
