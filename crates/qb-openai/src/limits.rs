//! Upstream direction, failure side: the vendor's rate-limit headers become quota windows for
//! qbd, and an HTTP status, error body and headers become a vendor-neutral [`Failure`].
//!
//! Two header families exist. A ChatGPT subscription login answers with `x-codex-primary-*` and
//! `x-codex-secondary-*` (used percent, window length, reset), the same windows the Codex CLI
//! writes into its rollouts; an API key answers with `x-ratelimit-*` (requests and tokens per
//! period).

use qb_proto::{ErrorClass, Outcome, WindowReport};
use serde_json::Value;

/// Prefix of the subscription window headers.
pub const CODEX: &str = "x-codex-";

/// The subscription windows, in header order.
const CODEX_WINDOWS: [&str; 2] = ["primary", "secondary"];

/// Window names of the API key headers; they are short rate limits, never a usage limit.
pub const API_KEY_WINDOWS: [&str; 2] = ["requests", "tokens"];

/// Absolute times at or above this are milliseconds.
const MS_THRESHOLD: u64 = 100_000_000_000;

/// Longest vendor message carried into a [`Failure`].
const MAX_MESSAGE: usize = 300;

/// The rate-limit state a response carried.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateLimits {
    /// One window per readable subscription window (`five_hour`, `seven_day`, `window_<m>m`) and
    /// per readable API key limit (`requests`, `tokens`), sorted by name.
    pub windows: Vec<WindowReport>,
    /// `retry-after` in whole seconds, else `retry-after-ms` rounded up.
    pub retry_after: Option<u64>,
}

impl RateLimits {
    /// Whether a subscription window is used up.
    pub fn exhausted(&self) -> bool {
        self.subscription().any(|w| w.utilization >= 1.0)
    }

    /// When the binding limit lifts: the latest reset of a used-up subscription window.
    pub fn limit_resets_at(&self) -> Option<u64> {
        self.subscription()
            .filter(|w| w.utilization >= 1.0)
            .filter_map(|w| w.resets_at)
            .max()
    }

    fn subscription(&self) -> impl Iterator<Item = &WindowReport> {
        self.windows
            .iter()
            .filter(|w| !API_KEY_WINDOWS.contains(&w.name.as_str()))
    }
}

fn header<'a>(headers: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

/// Window name and length of a subscription window of `minutes`: `five_hour`, `seven_day`, or
/// `window_<m>m`, as `qb-vendors` names the Codex rollout windows.
pub fn codex_window(minutes: u64) -> Option<(String, u32)> {
    if minutes == 0 {
        return None;
    }
    let length_s = u32::try_from(minutes.checked_mul(60)?).ok()?;
    let name = match minutes {
        300 => "five_hour".to_owned(),
        10_080 => "seven_day".to_owned(),
        m => format!("window_{m}m"),
    };
    Some((name, length_s))
}

/// A non-negative finite number.
fn number(value: &str) -> Option<f64> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|f| f.is_finite() && *f >= 0.0)
}

/// A whole number of seconds, fractions rounded up.
fn ceil_secs(f: f64) -> Option<u64> {
    if !(0.0..1.8e19).contains(&f) {
        return None;
    }
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range checked above"
    )]
    let n = f.ceil() as u64;
    Some(n)
}

/// A Unix time in seconds, or milliseconds when at or above 10^11; fractions round down.
fn unix_time(value: &str) -> Option<u64> {
    let f = number(value)?;
    let n = ceil_secs(f.floor())?;
    if n < MS_THRESHOLD {
        Some(n)
    } else {
        Some(n / 1000).filter(|s| *s < MS_THRESHOLD)
    }
}

/// A duration as the vendor writes it (`1s`, `6m0s`, `1h2m3.5s`, `20ms`, or bare seconds),
/// rounded up to whole seconds.
pub fn duration_secs(value: &str) -> Option<u64> {
    let s = value.trim();
    if let Some(f) = number(s) {
        return ceil_secs(f);
    }
    let mut total = 0.0;
    let mut rest = s;
    if rest.is_empty() {
        return None;
    }
    while !rest.is_empty() {
        let n = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let amount = number(&rest[..n])?;
        rest = &rest[n..];
        let u = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..u] {
            "h" => 3600.0,
            "m" => 60.0,
            "s" => 1.0,
            "ms" => 1e-3,
            "us" | "µs" => 1e-6,
            "ns" => 1e-9,
            _ => return None,
        };
        rest = &rest[u..];
        total += amount * scale;
    }
    ceil_secs(total)
}

/// Seconds a vendor message asks to wait: the duration after `try again in`, if any.
pub fn retry_in(message: &str) -> Option<u64> {
    const AT: &str = "try again in ";
    let lower = message.to_ascii_lowercase();
    let start = lower.find(AT)? + AT.len();
    let tail = &lower[start..];
    let mut words = tail
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == ')')
        .map(|w| w.trim_end_matches('.'));
    let first = words.next()?;
    if !first.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return duration_secs(first);
    }
    // A bare number names its unit in the next word: `5 minutes`, `1 second`.
    let scale = match words.next().unwrap_or_default() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hour" | "hours" => 3600.0,
        "ms" | "millisecond" | "milliseconds" => 1e-3,
        _ => return None,
    };
    ceil_secs(number(first)? * scale)
}

/// Reads the subscription and API key rate-limit headers and `retry-after` of an answer at `now`.
/// Names match case-insensitively; an unreadable value drops only its own window.
pub fn rate_limits(headers: &[(&str, &str)], now: u64) -> RateLimits {
    let mut windows: Vec<WindowReport> = Vec::new();
    for slot in CODEX_WINDOWS {
        let field = |suffix: &str| header(headers, &format!("{CODEX}{slot}-{suffix}"));
        let Some(used) = field("used-percent").and_then(number) else {
            continue;
        };
        let Some((name, length_s)) = field("window-minutes")
            .and_then(|m| m.parse::<u64>().ok())
            .and_then(codex_window)
        else {
            continue;
        };
        let resets_at = match (field("reset-at"), field("reset-after-seconds")) {
            (Some(at), _) => match unix_time(at) {
                Some(t) => Some(t),
                None => continue,
            },
            (None, Some(after)) => match number(after)
                .and_then(ceil_secs)
                .and_then(|s| now.checked_add(s))
            {
                Some(t) => Some(t),
                None => continue,
            },
            (None, None) => None,
        };
        if windows.iter().any(|w| w.name == name) {
            continue;
        }
        windows.push(WindowReport {
            name,
            utilization: (used / 100.0).min(1.0),
            resets_at,
            length_s: Some(length_s),
        });
    }
    for name in API_KEY_WINDOWS {
        let field = |kind: &str| header(headers, &format!("x-ratelimit-{kind}-{name}"));
        let (Some(limit), Some(remaining)) = (
            field("limit").and_then(number),
            field("remaining").and_then(number),
        ) else {
            continue;
        };
        if limit <= 0.0 {
            continue;
        }
        let resets_at = match field("reset") {
            None => None,
            Some(v) => match duration_secs(v).and_then(|s| now.checked_add(s)) {
                Some(t) => Some(t),
                None => continue,
            },
        };
        windows.push(WindowReport {
            name: name.to_owned(),
            utilization: ((limit - remaining) / limit).clamp(0.0, 1.0),
            resets_at,
            length_s: None,
        });
    }
    windows.sort_by(|a, b| a.name.cmp(&b.name));
    RateLimits {
        windows,
        retry_after: retry_after(headers),
    }
}

/// `retry-after` in whole seconds, else `retry-after-ms` rounded up.
fn retry_after(headers: &[(&str, &str)]) -> Option<u64> {
    header(headers, "retry-after")
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            header(headers, "retry-after-ms")
                .and_then(number)
                .and_then(|ms| ceil_secs(ms / 1000.0))
        })
}

/// How a vendor call failed, vendor-neutral; mirrors the gateway core's failure kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The login's usage limit is reached, or an API key's quota is spent.
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
    /// The model is unknown or not included in the login's plan.
    ModelUnavailable,
    /// The vendor as a whole is overloaded (503, `server_is_overloaded`, `slow_down`).
    Overloaded {
        /// Seconds the vendor asked to wait.
        retry_after: Option<u64>,
    },
    /// The vendor failed (5xx, broken or malformed stream).
    Unavailable,
    /// The vendor rejected the request as invalid (400, 413, 422).
    BadRequest,
    /// The conversation does not fit the model.
    ContextTooLong,
}

impl FailureKind {
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
    /// The vendor's message, shortened, without control characters; never a header value.
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
pub(crate) fn shorten(s: &str) -> String {
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

fn says(message: &str, phrases: &[&str]) -> bool {
    let m = message.to_ascii_lowercase();
    phrases.iter().any(|p| m.contains(p))
}

const USAGE_LIMIT_PHRASES: &[&str] = &[
    "usage limit",
    "hit your limit",
    "exceeded your current quota",
    "credit balance",
];

const CONTEXT_PHRASES: &[&str] = &[
    "context length",
    "context window",
    "maximum context",
    "too many tokens",
    "prompt is too long",
    "input is too long",
];

const MODEL_PHRASES: &[&str] = &[
    "model is not supported",
    "does not exist",
    "model not found",
    "must be verified",
];

/// A request over a per-minute token limit: no login with the same limit can ever serve it.
const TOO_LARGE_PHRASES: &[&str] = &["request too large", "must be reduced"];

/// The error object of an answer body, read leniently.
#[derive(Debug, Default)]
struct Detail {
    json: bool,
    kind: String,
    code: String,
    message: String,
    resets_at: Option<u64>,
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Reads `{"error": {...}}`, a top-level error object, or `{"detail": "..."}`; any other body is
/// its own message.
fn detail_of(body: &[u8], now: u64) -> Detail {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Detail {
            message: String::from_utf8_lossy(body).into_owned(),
            ..Detail::default()
        };
    };
    let obj = error_object(&v);
    let resets_at = obj
        .get("resets_at")
        .and_then(|r| unix_time(&text(Some(r))))
        .or_else(|| {
            let after = number(&text(obj.get("resets_in_seconds")))?;
            now.checked_add(ceil_secs(after)?)
        });
    Detail {
        resets_at,
        ..detail_of_value(&v)
    }
}

fn error_object(v: &Value) -> &Value {
    match v.get("error") {
        Some(e @ Value::Object(_)) => e,
        _ => v,
    }
}

/// [`detail_of`] of a decoded body, without a reset.
fn detail_of_value(v: &Value) -> Detail {
    let obj = error_object(v);
    let mut message = text(obj.get("message"));
    if message.is_empty() {
        message = match (v.get("error"), v.get("detail")) {
            (Some(Value::String(s)), _) => s.clone(),
            (_, Some(d)) => match d {
                Value::String(s) => s.clone(),
                other => text(other.get("message")),
            },
            _ => String::new(),
        };
    }
    Detail {
        json: true,
        kind: text(obj.get("type")),
        code: text(obj.get("code")),
        message,
        resets_at: None,
    }
}

fn by_detail(status: Option<u16>, d: &Detail, limits: &RateLimits) -> FailureKind {
    let has = |names: &[&str]| names.contains(&d.code.as_str()) || names.contains(&d.kind.as_str());
    let usage_limit = || FailureKind::UsageLimit {
        resets_at: d.resets_at.or_else(|| limits.limit_resets_at()),
    };
    let retry_after = limits.retry_after.or_else(|| retry_in(&d.message));
    if has(&[
        "usage_limit_reached",
        "insufficient_quota",
        "billing_hard_limit_reached",
        "billing_not_active",
    ]) {
        return usage_limit();
    }
    if has(&["usage_not_included", "model_not_found"]) {
        return FailureKind::ModelUnavailable;
    }
    if has(&["context_length_exceeded"]) || says(&d.message, TOO_LARGE_PHRASES) {
        return FailureKind::ContextTooLong;
    }
    let auth = has(&[
        "invalid_api_key",
        "authentication_error",
        "permission_error",
        "token_expired",
        "account_deactivated",
    ]);
    let rate = has(&[
        "rate_limit_exceeded",
        "rate_limit_error",
        "requests",
        "tokens",
    ]);
    let overloaded = has(&["server_is_overloaded", "slow_down", "overloaded_error"]);
    let invalid = has(&["invalid_request_error", "invalid_prompt"]);
    match status {
        // A 403 that is not an API error is a proxy or bot wall, not a rejected credential.
        Some(403) if !d.json => FailureKind::Unavailable,
        Some(401 | 403) => FailureKind::Auth,
        _ if auth => FailureKind::Auth,
        // A stream error has no status; its rate code on an exhausted window is the same limit.
        Some(429) | None if status.is_some() || rate => {
            if limits.exhausted() || says(&d.message, USAGE_LIMIT_PHRASES) {
                usage_limit()
            } else {
                FailureKind::RateLimited { retry_after }
            }
        }
        _ if rate => FailureKind::RateLimited { retry_after },
        Some(402) => FailureKind::UsageLimit { resets_at: None },
        Some(404) => FailureKind::ModelUnavailable,
        Some(503 | 529) => FailureKind::Overloaded { retry_after },
        _ if overloaded => FailureKind::Overloaded { retry_after },
        Some(400 | 413 | 422) | None if invalid || status.is_some() => {
            if says(&d.message, CONTEXT_PHRASES) {
                FailureKind::ContextTooLong
            } else if says(&d.message, MODEL_PHRASES) {
                FailureKind::ModelUnavailable
            } else if says(&d.message, USAGE_LIMIT_PHRASES) {
                usage_limit()
            } else {
                FailureKind::BadRequest
            }
        }
        _ => FailureKind::Unavailable,
    }
}

/// Classifies a non-200 answer at `now` from its status, headers and body. Any body is accepted;
/// one that is not an OpenAI error body classifies by status alone.
pub fn classify_response(status: u16, headers: &[(&str, &str)], body: &[u8], now: u64) -> Failure {
    let limits = rate_limits(headers, now);
    let detail = detail_of(body, now);
    let kind = by_detail(Some(status), &detail, &limits);
    let mut windows = limits.windows;
    mark_limiting(kind, &mut windows);
    Failure {
        kind,
        windows,
        message: answered(status, &detail.message),
    }
}

fn answered(status: u16, message: &str) -> String {
    if message.trim().is_empty() {
        format!("vendor answered HTTP {status}")
    } else {
        format!("vendor answered HTTP {status}: {}", shorten(message))
    }
}

/// A model id the vendor does not know, in an OpenAI-compatible vendor's words.
const CHAT_MODEL_PHRASES: &[&str] = &["not a valid model"];

/// The failure kind of a Chat Completions vendor's `status`; the error object refines a 429
/// whose code or type is `insufficient_quota`, spent credit, into a usage limit without a reset,
/// and a 400, 413 or 422 with a JSON body.
fn chat_kind(status: u16, d: &Detail, retry_after: Option<u64>) -> FailureKind {
    let has = |names: &[&str]| names.contains(&d.code.as_str()) || names.contains(&d.kind.as_str());
    match status {
        401 | 403 => FailureKind::Auth,
        402 => FailureKind::UsageLimit { resets_at: None },
        429 if has(&["insufficient_quota"]) => FailureKind::UsageLimit { resets_at: None },
        429 => FailureKind::RateLimited { retry_after },
        404 => FailureKind::ModelUnavailable,
        400 | 413 | 422 if d.json => {
            if has(&["context_length_exceeded"]) || says(&d.message, CONTEXT_PHRASES) {
                FailureKind::ContextTooLong
            } else if has(&["model_not_found"])
                || says(&d.message, MODEL_PHRASES)
                || says(&d.message, CHAT_MODEL_PHRASES)
            {
                FailureKind::ModelUnavailable
            } else {
                FailureKind::BadRequest
            }
        }
        400 | 413 | 422 => FailureKind::BadRequest,
        503 => FailureKind::Overloaded { retry_after },
        _ => FailureKind::Unavailable,
    }
}

/// Classifies a non-200 answer of a Chat Completions vendor (OpenRouter, an OpenAI-compatible API
/// key) by its status; `retry-after` sets the wait of a 429 or 503. The failure carries no windows.
pub fn classify_chat_response(
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
    now: u64,
) -> Failure {
    let detail = detail_of(body, now);
    Failure::new(
        chat_kind(status, &detail, retry_after(headers)),
        answered(status, &detail.message),
    )
}

/// Classifies the `error` object of a Chat Completions stream chunk: a numeric `code` from 400 to
/// 599 is the status the vendor would have answered and classifies as [`classify_chat_response`];
/// any other error as [`classify_stream_error`] without windows.
pub fn classify_chat_stream_error(error: &Value) -> Failure {
    let status = error
        .get("code")
        .and_then(Value::as_u64)
        .and_then(|c| u16::try_from(c).ok())
        .filter(|c| (400..600).contains(c));
    let detail = detail_of_value(&serde_json::json!({ "error": error }));
    if let Some(status) = status {
        return Failure::new(
            chat_kind(status, &detail, None),
            format!("vendor stream error {status}: {}", shorten(&detail.message)),
        );
    }
    let code = if detail.code.is_empty() {
        &detail.kind
    } else {
        &detail.code
    };
    classify_stream_error(code, &detail.message, &RateLimits::default())
}

/// Puts the limiting window of a usage limit at 1.0 with its reset, since qbd learns the reset
/// only from the windows: a subscription window already at 1.0 is the limiting one; else the
/// subscription window whose reset is nearest to the limit's. Without a subscription window the
/// limit names none.
fn mark_limiting(kind: FailureKind, windows: &mut [WindowReport]) {
    let FailureKind::UsageLimit {
        resets_at: Some(at),
    } = kind
    else {
        return;
    };
    let subscription = |w: &&mut WindowReport| !API_KEY_WINDOWS.contains(&w.name.as_str());
    if windows
        .iter_mut()
        .filter(subscription)
        .any(|w| w.utilization >= 1.0)
    {
        return;
    }
    if let Some(w) = windows
        .iter_mut()
        .filter(subscription)
        .min_by_key(|w| w.resets_at.map_or(u64::MAX, |r| r.abs_diff(at)))
    {
        w.utilization = 1.0;
        w.resets_at = Some(at);
    }
}

/// Classifies an `error` event or the `error` of a `response.failed` event, in a stream that
/// started with `limits` in its response headers.
pub fn classify_stream_error(code: &str, message: &str, limits: &RateLimits) -> Failure {
    let detail = Detail {
        json: true,
        kind: String::new(),
        code: code.to_owned(),
        message: message.to_owned(),
        resets_at: None,
    };
    let kind = by_detail(None, &detail, limits);
    let mut windows = limits.windows.clone();
    mark_limiting(kind, &mut windows);
    Failure {
        kind,
        windows,
        message: format!(
            "vendor stream error {}: {}",
            shorten(code),
            shorten(message)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration_secs("1s"), Some(1));
        assert_eq!(duration_secs("6m0s"), Some(360));
        assert_eq!(duration_secs("1h2m3.5s"), Some(3724));
        assert_eq!(duration_secs("20ms"), Some(1));
        assert_eq!(duration_secs("0s"), Some(0));
        assert_eq!(duration_secs("7.2"), Some(8));
        assert_eq!(duration_secs("soon"), None);
        assert_eq!(duration_secs("1x"), None);
        assert_eq!(duration_secs(""), None);
        assert_eq!(
            retry_in("Rate limit reached. Please try again in 1.898s."),
            Some(2)
        );
        assert_eq!(retry_in("Please try again in 6m0s. Visit …"), Some(360));
        assert_eq!(retry_in("slow down"), None);
        assert_eq!(retry_in("Please try again in 5 minutes."), Some(300));
        assert_eq!(retry_in("try again in 1 second"), Some(1));
        assert_eq!(retry_in("try again in 20 seconds."), Some(20));
        assert_eq!(retry_in("try again in 3 days"), None);
    }

    #[test]
    fn windows_by_minutes() {
        assert_eq!(codex_window(300), Some(("five_hour".into(), 18_000)));
        assert_eq!(codex_window(10_080), Some(("seven_day".into(), 604_800)));
        assert_eq!(codex_window(60), Some(("window_60m".into(), 3600)));
        assert_eq!(codex_window(0), None);
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
        let f = classify_response(
            502,
            &[],
            b"<html>\r\nPRIORITY<3>forged\n\x1b[31m\t</html>",
            0,
        );
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
