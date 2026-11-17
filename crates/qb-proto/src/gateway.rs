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
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
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
        /// Absolute path of a file beneath one of the gateway's `media_dirs`.
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
}

/// Why a [`TurnRequest`] is malformed beyond what JSON decoding catches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRequestError(pub String);

fn is_alias(s: &str) -> bool {
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
        for (i, m) in self.messages.iter().enumerate() {
            if m.content.is_empty() {
                return fail(format!("`messages[{i}].content` is empty"));
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
/// `error`; a stream without either was cut by a cancel or a transport failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
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

/// Failure class of a turn or a rejected request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Every login of the route is out of quota.
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
}

impl ErrorClass {
    /// HTTP status of a gateway answer that rejects a request with this class.
    pub fn http_status(self) -> u16 {
        match self {
            Self::BadRequest | Self::ContextTooLong => 400,
            Self::Auth => 401,
            Self::QuotaExhausted => 429,
            Self::Unavailable => 502,
            Self::Overloaded => 503,
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
    fn error_classes_map_to_http() {
        assert_eq!(ErrorClass::QuotaExhausted.http_status(), 429);
        assert_eq!(ErrorClass::BadRequest.http_status(), 400);
    }
}
