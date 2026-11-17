//! Upstream direction, failure side: the vendor's rate-limit headers become quota windows for
//! qbd, and an HTTP status, error body and headers become a vendor-neutral [`Failure`].

use qb_proto::{ErrorClass, Outcome, WindowReport};

use crate::wire::{ErrorBody, ErrorDetail};

/// Prefix of the unified rate-limit headers of subscription logins.
pub const UNIFIED: &str = "anthropic-ratelimit-unified-";

/// Absolute times at or above this are milliseconds.
const MS_THRESHOLD: u64 = 100_000_000_000;

/// Longest vendor message carried into a [`Failure`].
const MAX_MESSAGE: usize = 300;

/// The unified rate-limit state a response carried.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateLimits {
    /// `…-unified-status`: `allowed`, `allowed_warning`, `rejected` or another value.
    pub status: Option<String>,
    /// `…-unified-reset`: when the binding limit resets, Unix seconds.
    pub resets_at: Option<u64>,
    /// `…-unified-representative-claim`, as a window name (`five_hour`, `seven_day`, …).
    pub representative_claim: Option<String>,
    /// One window per `…-unified-<claim>-utilization` header that parses, sorted by name.
    pub windows: Vec<WindowReport>,
    /// `retry-after` in whole seconds.
    pub retry_after: Option<u64>,
}

impl RateLimits {
    /// Whether the vendor rejected the request for quota.
    pub fn rejected(&self) -> bool {
        self.status.as_deref() == Some("rejected")
    }

    /// When the binding limit lifts: the unified reset, else the representative window's reset,
    /// else the latest reset of an exhausted window.
    pub fn limit_resets_at(&self) -> Option<u64> {
        self.resets_at
            .or_else(|| {
                let claim = self.representative_claim.as_deref()?;
                self.windows.iter().find(|w| w.name == claim)?.resets_at
            })
            .or_else(|| {
                self.windows
                    .iter()
                    .filter(|w| w.utilization >= 1.0)
                    .filter_map(|w| w.resets_at)
                    .max()
            })
    }
}

fn header<'a>(headers: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

/// Window name and length of a unified claim: `5h` or `five_hour`, `7d` or `seven_day`, and
/// `7d_<model>` or `seven_day_<model>`; other claims (such as overage) are not windows.
pub fn window_of_claim(claim: &str) -> Option<(String, u32)> {
    const FIVE_HOURS: u32 = 5 * 3600;
    const SEVEN_DAYS: u32 = 7 * 86_400;
    let claim = claim.to_ascii_lowercase();
    if claim == "5h" || claim == "five_hour" {
        return Some(("five_hour".into(), FIVE_HOURS));
    }
    if claim == "7d" || claim == "seven_day" {
        return Some(("seven_day".into(), SEVEN_DAYS));
    }
    let model = claim
        .strip_prefix("7d_")
        .or_else(|| claim.strip_prefix("seven_day_"))?;
    let ok = !model.is_empty()
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then(|| (format!("seven_day_{model}"), SEVEN_DAYS))
}

/// A Unix time in seconds, or milliseconds when at or above 10^11; fractions round down.
fn unix_time(value: &str) -> Option<u64> {
    let n = if let Ok(n) = value.parse::<u64>() {
        n
    } else {
        let f = value.parse::<f64>().ok()?;
        if !(0.0..1.8e19).contains(&f) {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "range checked above; truncation rounds down"
        )]
        let n = f as u64;
        n
    };
    if n < MS_THRESHOLD {
        Some(n)
    } else {
        Some(n / 1000).filter(|s| *s < MS_THRESHOLD)
    }
}

/// Reads the unified rate-limit headers and `retry-after`. Names match case-insensitively; an
/// unreadable value is absent and drops only its own window.
///
/// A window whose `…-<claim>-status` is `rejected` counts as fully used.
pub fn rate_limits(headers: &[(&str, &str)]) -> RateLimits {
    let unified = |suffix: &str| header(headers, &format!("{UNIFIED}{suffix}"));
    let mut windows: Vec<WindowReport> = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        let Some(claim) = lower
            .strip_prefix(UNIFIED)
            .and_then(|r| r.strip_suffix("-utilization"))
        else {
            continue;
        };
        let Some((window, length_s)) = window_of_claim(claim) else {
            continue;
        };
        let Some(mut used) = value
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|u| u.is_finite() && *u >= 0.0)
        else {
            continue;
        };
        if unified(&format!("{claim}-status")) == Some("rejected") {
            used = 1.0;
        }
        let resets_at = match unified(&format!("{claim}-reset")) {
            None => None,
            Some(v) => match unix_time(v) {
                Some(t) => Some(t),
                None => continue,
            },
        };
        if windows.iter().any(|w| w.name == window) {
            continue;
        }
        windows.push(WindowReport {
            name: window,
            utilization: used.min(1.0),
            resets_at,
            length_s: Some(length_s),
        });
    }
    windows.sort_by(|a, b| a.name.cmp(&b.name));
    RateLimits {
        status: unified("status").map(str::to_owned),
        resets_at: unified("reset").and_then(unix_time),
        representative_claim: unified("representative-claim")
            .and_then(window_of_claim)
            .map(|(name, _)| name),
        windows,
        retry_after: header(headers, "retry-after").and_then(|v| v.parse().ok()),
    }
}

/// How a vendor call failed, vendor-neutral. Mirrors the gateway seam's `FailureKind` (same
/// variants and names, minus `Cancelled`, which only the adapter sees): this crate stays pure and
/// the binary that owns the seam depends on it, not the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The login's usage limit is reached.
    UsageLimit {
        /// When the limit lifts, if the vendor said so.
        resets_at: Option<u64>,
    },
    /// The credential was rejected (401, 403).
    Auth,
    /// Short rate limit without exhaustion (429).
    RateLimited {
        /// Seconds the vendor asked to wait.
        retry_after: Option<u64>,
    },
    /// The model is unknown or unavailable to the login (404).
    ModelUnavailable,
    /// The vendor as a whole is overloaded (529).
    Overloaded {
        /// Seconds the vendor asked to wait.
        retry_after: Option<u64>,
    },
    /// The vendor failed (5xx, broken or malformed stream).
    Unavailable,
    /// The vendor rejected the request as invalid (400, 413).
    BadRequest,
    /// The conversation does not fit the model.
    ContextTooLong,
}

impl FailureKind {
    /// The seam's name of this kind, e.g. `usage_limit`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UsageLimit { .. } => "usage_limit",
            Self::Auth => "auth",
            Self::RateLimited { .. } => "rate_limited",
            Self::ModelUnavailable => "model_unavailable",
            Self::Overloaded { .. } => "overloaded",
            Self::Unavailable => "unavailable",
            Self::BadRequest => "bad_request",
            Self::ContextTooLong => "context_too_long",
        }
    }

    /// The canonical error class a client sees when this failure ends a turn.
    pub fn error_class(self) -> ErrorClass {
        match self {
            Self::UsageLimit { .. } => ErrorClass::QuotaExhausted,
            Self::Auth => ErrorClass::Auth,
            Self::RateLimited { .. } | Self::Overloaded { .. } => ErrorClass::Overloaded,
            Self::ModelUnavailable | Self::Unavailable => ErrorClass::Unavailable,
            Self::BadRequest => ErrorClass::BadRequest,
            Self::ContextTooLong => ErrorClass::ContextTooLong,
        }
    }

    /// The qbd report outcome of an attempt that failed this way.
    pub fn outcome(self) -> Outcome {
        match self {
            Self::UsageLimit { .. } => Outcome::UsageLimit,
            Self::Auth => Outcome::Http401,
            Self::RateLimited { .. } => Outcome::Http429,
            Self::ModelUnavailable => Outcome::ModelUnavailable,
            Self::Overloaded { .. }
            | Self::Unavailable
            | Self::BadRequest
            | Self::ContextTooLong => Outcome::Error,
        }
    }
}

/// A failed vendor call.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// What went wrong.
    pub kind: FailureKind,
    /// Quota windows the failure carried, for qbd's report.
    pub windows: Vec<WindowReport>,
    /// The vendor's message, shortened; never a header value.
    pub message: String,
}

impl Failure {
    /// A failure of `kind` without windows.
    pub fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            windows: Vec::new(),
            message: message.into(),
        }
    }
}

/// The first [`MAX_MESSAGE`] characters of a vendor message, with control characters (line ends
/// included) as spaces: the message ends up in log lines and client errors.
fn shorten(s: &str) -> String {
    let mut out: String = s
        .chars()
        .take(MAX_MESSAGE)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if s.chars().nth(MAX_MESSAGE).is_some() {
        out.push('…');
    }
    out
}

fn says_usage_limit(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "usage limit",
        "hit your limit",
        "limit reached",
        "rate_limit_rejected",
    ]
    .iter()
    .any(|p| m.contains(p))
}

/// An API key's prepaid credit ran out; Anthropic answers this as a 400, not a 402.
fn says_out_of_credit(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    ["credit balance", "billing"].iter().any(|p| m.contains(p))
}

fn says_context_too_long(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    [
        "prompt is too long",
        "context length",
        "context window",
        "exceed context limit",
        "too many tokens",
    ]
    .iter()
    .any(|p| m.contains(p))
}

fn by_detail(status: Option<u16>, detail: &ErrorDetail, limits: &RateLimits) -> FailureKind {
    let usage_limit = || FailureKind::UsageLimit {
        resets_at: limits.limit_resets_at(),
    };
    match (status, detail.kind.as_str()) {
        (Some(401 | 403), _) | (_, "authentication_error" | "permission_error") => {
            FailureKind::Auth
        }
        (Some(429), _) | (_, "rate_limit_error") => {
            if limits.rejected() || says_usage_limit(&detail.message) {
                usage_limit()
            } else {
                FailureKind::RateLimited {
                    retry_after: limits.retry_after,
                }
            }
        }
        (Some(402), _) | (_, "billing_error") => FailureKind::UsageLimit { resets_at: None },
        (Some(529), _) | (_, "overloaded_error") => FailureKind::Overloaded {
            retry_after: limits.retry_after,
        },
        (Some(404), _) | (_, "not_found_error") => FailureKind::ModelUnavailable,
        (Some(400 | 413), _) | (_, "invalid_request_error" | "request_too_large") => {
            if says_context_too_long(&detail.message) {
                FailureKind::ContextTooLong
            } else if says_usage_limit(&detail.message) {
                usage_limit()
            } else if says_out_of_credit(&detail.message) {
                FailureKind::UsageLimit { resets_at: None }
            } else {
                FailureKind::BadRequest
            }
        }
        _ => FailureKind::Unavailable,
    }
}

/// Classifies a non-200 answer from its status, headers and body. Any body is accepted; one
/// that is not an Anthropic error body classifies by status alone.
pub fn classify_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Failure {
    let limits = rate_limits(headers);
    let detail = serde_json::from_slice::<ErrorBody>(body).map_or_else(
        |_| ErrorDetail {
            kind: String::new(),
            message: String::from_utf8_lossy(body).into_owned(),
        },
        |b| b.error,
    );
    let kind = by_detail(Some(status), &detail, &limits);
    let message = if detail.message.is_empty() {
        format!("vendor answered HTTP {status}")
    } else {
        format!(
            "vendor answered HTTP {status}: {}",
            shorten(&detail.message)
        )
    };
    Failure {
        kind,
        windows: limits.windows,
        message,
    }
}

/// Classifies an `error` event of a stream that started with `limits` in its response headers.
pub fn classify_stream_error(detail: &ErrorDetail, limits: &RateLimits) -> Failure {
    Failure {
        kind: by_detail(None, detail, limits),
        windows: limits.windows.clone(),
        message: format!(
            "vendor stream error {}: {}",
            detail.kind,
            shorten(&detail.message)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_map_to_windows() {
        assert_eq!(window_of_claim("5h"), Some(("five_hour".into(), 18_000)));
        assert_eq!(
            window_of_claim("7d_opus"),
            Some(("seven_day_opus".into(), 604_800))
        );
        assert_eq!(window_of_claim("overage"), None);
        assert_eq!(window_of_claim("7d_"), None);
    }

    #[test]
    fn times_in_ms_and_fractions() {
        assert_eq!(unix_time("1800000000"), Some(1_800_000_000));
        assert_eq!(unix_time("1800000000000"), Some(1_800_000_000));
        assert_eq!(unix_time("1800000000.9"), Some(1_800_000_000));
        assert_eq!(unix_time("-1"), None);
        assert_eq!(unix_time("soon"), None);
    }

    #[test]
    fn control_characters_become_spaces() {
        let f = classify_response(502, &[], b"<html>\r\nPRIORITY<3>forged\n\x1b[31m\t</html>");
        assert_eq!(
            f.message,
            "vendor answered HTTP 502: <html>  PRIORITY<3>forged  [31m </html>"
        );
        assert!(!f.message.chars().any(char::is_control));
    }

    #[test]
    fn long_messages_are_shortened_on_a_char_boundary() {
        let s = "é".repeat(400);
        assert_eq!(shorten(&s).chars().count(), MAX_MESSAGE + 1);
    }
}
