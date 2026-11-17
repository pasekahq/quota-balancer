//! Client direction, what both OpenAI fronts share: the decoded request, the error answer of a
//! canonical error, and the small mappings (effort, images, session key, usage, stop reason).
//! The fronts themselves are [`crate::chat`] (`/v1/chat/completions`) and [`crate::responses`]
//! (`/v1/responses`).

use qb_proto::{
    Block, Effort, ErrorClass, GatewayError, MediaType, Message, Role, StopReason, TurnRequest,
    Usage,
};

use crate::wire::{
    ChatUsage, CompletionTokensDetails, ErrorBody, PromptTokensDetails, ResponsesUsage,
};

/// A decoded front request.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontRequest {
    /// The canonical turn.
    pub turn: TurnRequest,
    /// The client asked for SSE.
    pub stream: bool,
    /// The `model` the client sent, echoed in the answer.
    pub model: String,
    /// Chat Completions: the client asked for a final usage chunk (`stream_options`).
    pub include_usage: bool,
}

/// What a front does with thinking of a vendor other than its native one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ForeignThinking {
    /// Show it in a form the client passes back, so the turn keeps it.
    #[default]
    Keep,
    /// Leave it out, so the client's history stays valid for the native vendor itself.
    Drop,
}

/// Prefix of an `encrypted_content` that carries another vendor's thinking, so a Responses
/// client passes it back like any reasoning item.
pub const FOREIGN_THINKING: &str = "qb-thinking:";

/// A `bad_request` error with `message`.
pub(crate) fn bad(message: impl Into<String>) -> GatewayError {
    GatewayError::new(ErrorClass::BadRequest, false, message)
}

/// A client id or cache key as a session key: itself when it fits, else `qb-sk:` and 32 hex
/// digits derived from all of it, so long ids still keep a session on one login.
pub fn session_key(id: &str) -> Option<String> {
    if id.is_empty() {
        return None;
    }
    if id.len() <= qb_proto::gateway::MAX_SESSION_KEY {
        return Some(id.to_owned());
    }
    // Two FNV-1a passes with different offsets; stickiness needs determinism, not secrecy.
    let fnv = |offset: u64| {
        id.bytes().fold(offset, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
        })
    };
    Some(format!(
        "qb-sk:{:016x}{:016x}",
        fnv(0xcbf2_9ce4_8422_2325),
        fnv(0x6c62_272e_07bb_0142)
    ))
}

/// The canonical effort of an OpenAI effort: `none` and `minimal` read as `low`, `xhigh` as
/// `max`.
///
/// # Errors
/// A `bad_request` error naming `field` for any other value.
pub fn effort(value: &str, field: &str) -> Result<Effort, GatewayError> {
    Ok(match value {
        "none" | "minimal" | "low" => Effort::Low,
        "medium" => Effort::Medium,
        "high" => Effort::High,
        "xhigh" => Effort::Max,
        other => return Err(bad(format!("`{field}` `{other}` is not supported"))),
    })
}

fn media_type(s: &str) -> Option<MediaType> {
    Some(match s {
        "image/png" => MediaType::Png,
        "image/jpeg" | "image/jpg" => MediaType::Jpeg,
        "image/gif" => MediaType::Gif,
        "image/webp" => MediaType::Webp,
        _ => return None,
    })
}

/// The canonical image of a `data:<media type>;base64,<data>` URL.
///
/// # Errors
/// A `bad_request` error naming `at` for any other URL (the gateway fetches nothing), an
/// unsupported media type, or empty data.
pub fn image(url: &str, at: &str) -> Result<Block, GatewayError> {
    let Some(rest) = url.strip_prefix("data:") else {
        return Err(bad(format!(
            "`{at}` must be a base64 data: URL; the gateway fetches no image"
        )));
    };
    let (head, data) = rest
        .split_once(',')
        .ok_or_else(|| bad(format!("`{at}` is not a data: URL")))?;
    let mt = head
        .strip_suffix(";base64")
        .ok_or_else(|| bad(format!("`{at}` must be base64")))?;
    let media_type =
        media_type(mt).ok_or_else(|| bad(format!("`{at}` has unsupported media type `{mt}`")))?;
    if data.is_empty() {
        return Err(bad(format!("`{at}` has no data")));
    }
    Ok(Block::Image {
        media_type,
        path: None,
        base64: Some(data.to_owned()),
    })
}

/// Appends `blocks` as a message of `role`, merged into the previous message when it has the
/// same role: OpenAI sends each tool result as its own message, the canonical form keeps the
/// results of one assistant turn together.
pub(crate) fn push_message(messages: &mut Vec<Message>, role: Role, blocks: Vec<Block>) {
    if blocks.is_empty() {
        return;
    }
    match messages.last_mut() {
        Some(last) if last.role == role => last.content.extend(blocks),
        _ => messages.push(Message {
            role,
            content: blocks,
        }),
    }
}

/// The joined system prompt; `None` when empty.
pub(crate) fn join_system(parts: Vec<String>) -> Option<String> {
    let parts: Vec<String> = parts.into_iter().filter(|s| !s.is_empty()).collect();
    (!parts.is_empty()).then(|| parts.join("\n\n"))
}

/// Chat Completions `finish_reason` of a canonical stop reason.
pub fn finish_reason(r: StopReason) -> &'static str {
    match r {
        StopReason::End => "stop",
        StopReason::ToolUse => "tool_calls",
        StopReason::MaxTokens => "length",
        StopReason::Refusal => "content_filter",
    }
}

/// Chat Completions counts of canonical counts: `prompt_tokens` includes cached and cache-written
/// tokens, `cached_tokens` is `cache_read`; the canonical counts have no reasoning count, so
/// `reasoning_tokens` is 0.
pub fn chat_usage(u: Usage) -> ChatUsage {
    let prompt = u
        .input
        .saturating_add(u.cache_read)
        .saturating_add(u.cache_write);
    ChatUsage {
        prompt_tokens: prompt,
        completion_tokens: u.output,
        total_tokens: prompt.saturating_add(u.output),
        prompt_tokens_details: Some(PromptTokensDetails {
            cached_tokens: u.cache_read,
        }),
        completion_tokens_details: Some(CompletionTokensDetails::default()),
    }
}

/// Responses counts of canonical counts, as [`chat_usage`].
pub fn responses_usage(u: Usage) -> ResponsesUsage {
    let input = u
        .input
        .saturating_add(u.cache_read)
        .saturating_add(u.cache_write);
    ResponsesUsage {
        input_tokens: input,
        input_tokens_details: Some(PromptTokensDetails {
            cached_tokens: u.cache_read,
        }),
        output_tokens: u.output,
        output_tokens_details: Some(CompletionTokensDetails::default()),
        total_tokens: input.saturating_add(u.output),
    }
}

/// An OpenAI error answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorResponse {
    /// HTTP status.
    pub status: u16,
    /// `retry-after` header in seconds, when set.
    pub retry_after: Option<u64>,
    /// `x-should-retry` header, when set; OpenAI SDKs follow it over their own retry rules.
    pub should_retry: Option<bool>,
    /// JSON body.
    pub body: ErrorBody,
}

impl ErrorResponse {
    /// The headers of the answer besides `content-type`.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(s) = self.retry_after {
            out.push(("retry-after", s.to_string()));
        }
        if let Some(r) = self.should_retry {
            out.push(("x-should-retry", r.to_string()));
        }
        out
    }
}

/// The OpenAI `type` and `code` of a canonical error class.
pub fn error_kind(class: ErrorClass) -> (&'static str, Option<&'static str>) {
    match class {
        ErrorClass::QuotaExhausted => ("insufficient_quota", Some("insufficient_quota")),
        ErrorClass::Overloaded => ("server_error", Some("server_is_overloaded")),
        ErrorClass::Unavailable => ("server_error", Some("upstream_unavailable")),
        ErrorClass::Auth => ("server_error", Some("upstream_auth_failed")),
        ErrorClass::BadRequest => ("invalid_request_error", None),
        ErrorClass::ContextTooLong => ("invalid_request_error", Some("context_length_exceeded")),
        ErrorClass::Cancelled => ("server_error", Some("cancelled")),
        ErrorClass::NoRoute => ("server_error", Some("no_route")),
    }
}

/// The OpenAI error body of a canonical error.
pub fn error_body(e: &GatewayError) -> ErrorBody {
    let (kind, code) = error_kind(e.class);
    let default = match e.class {
        ErrorClass::QuotaExhausted => "every login of the route is out of quota",
        ErrorClass::Overloaded => "the vendor asked to back off",
        ErrorClass::Unavailable => "no vendor of the route answered",
        ErrorClass::Auth => "the vendor rejected the gateway's credential",
        ErrorClass::BadRequest => "invalid request",
        ErrorClass::ContextTooLong => "the conversation does not fit the model's context length",
        ErrorClass::Cancelled => "the turn was cancelled",
        ErrorClass::NoRoute => "the route has no candidate that can run",
    };
    let message = e
        .message
        .as_deref()
        .filter(|m| !m.is_empty())
        .unwrap_or(default);
    ErrorBody::new(kind, code, message)
}

/// A quota reset further away than this tells SDK clients not to retry.
pub const NO_RETRY_AFTER_S: u64 = 300;

/// The `retry-after` of a `quota_exhausted` error that names neither a reset nor a delay.
pub const QUOTA_RETRY_AFTER_S: u64 = 60;

/// The OpenAI error answer of a canonical error at `now`:
///
/// - `quota_exhausted`: 429 `insufficient_quota` with `retry-after` until `resets_at`, else
///   `retry_after`, else [`QUOTA_RETRY_AFTER_S`], and `x-should-retry: false` beyond
///   [`NO_RETRY_AFTER_S`];
/// - `overloaded`, `unavailable` and `no_route`: 503; `auth`, which is the vendor rejecting the
///   gateway's credential and not the client's, 502;
/// - `bad_request`, `context_too_long` (`context_length_exceeded`): 400; `cancelled`: 409;
/// - `auth`, `cancelled` and `no_route` also carry `x-should-retry: false`.
pub fn error_response(e: &GatewayError, now: u64) -> ErrorResponse {
    let status = match e.class {
        ErrorClass::QuotaExhausted => 429,
        ErrorClass::Overloaded | ErrorClass::Unavailable | ErrorClass::NoRoute => 503,
        ErrorClass::Auth => 502,
        ErrorClass::BadRequest | ErrorClass::ContextTooLong => 400,
        ErrorClass::Cancelled => 409,
    };
    let retry_after = match e.class {
        ErrorClass::QuotaExhausted => e
            .resets_at
            .map(|r| r.saturating_sub(now).max(1))
            .or(e.retry_after)
            .or(Some(QUOTA_RETRY_AFTER_S)),
        _ => e.retry_after,
    };
    let should_retry = match e.class {
        ErrorClass::QuotaExhausted => retry_after.is_some_and(|s| s > NO_RETRY_AFTER_S),
        // A retry hits the same rejected credentials, cancelled turn or empty route.
        ErrorClass::Auth | ErrorClass::Cancelled | ErrorClass::NoRoute => true,
        _ => false,
    }
    .then_some(false);
    ErrorResponse {
        status,
        retry_after,
        should_retry,
        body: error_body(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_ids_become_fixed_keys() {
        assert_eq!(session_key(""), None);
        assert_eq!(session_key("conv-1").as_deref(), Some("conv-1"));
        let long = "x".repeat(200);
        let k = session_key(&long).expect("key");
        assert_eq!(k.len(), 38);
        assert!(k.starts_with("qb-sk:"));
        assert_eq!(session_key(&long), Some(k.clone()));
        assert_ne!(session_key(&"y".repeat(200)), Some(k));
    }

    #[test]
    fn data_urls() {
        assert_eq!(
            image("data:image/png;base64,iVBORw0KGgo=", "x"),
            Ok(Block::Image {
                media_type: MediaType::Png,
                path: None,
                base64: Some("iVBORw0KGgo=".into())
            })
        );
        for bad_url in [
            "https://example.invalid/a.png",
            "data:image/png,raw",
            "data:image/tiff;base64,AA==",
            "data:image/png;base64,",
            "data:",
        ] {
            assert!(image(bad_url, "x").is_err(), "{bad_url}");
        }
    }
}
