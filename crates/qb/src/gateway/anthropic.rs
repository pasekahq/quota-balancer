//! The Anthropic Messages adapter: [`qb_anthropic`] builds the body and headers and reads the
//! stream, ureq with rustls carries the call. Each attempt runs on its own ureq agent, which the
//! turn's cancel hook shuts down, so a blocked connect, write or read returns at once.

use std::io::{self, Read};
use std::time::Duration;

use qb_anthropic::limits;
use qb_anthropic::request::{self, AuthMode, Target};
use qb_anthropic::stream::{Progress, Reader};
use qb_proto::{StreamEvent, TurnRequest};
use zeroize::Zeroizing;

use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Flow, Picked, Sink, Upstream,
};

/// Base URL of a login without `base_url`: the vendor's public endpoint.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Path of the Messages API below the base URL.
const MESSAGES_PATH: &str = "/v1/messages";

/// Bound of the TCP connect of an attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound of one attempt, from connect to the end of the stream.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(600);

/// Largest error body read for its message.
const MAX_ERROR_BODY: u64 = 64 << 10;

/// Size of one read of the stream.
const READ_BYTES: usize = 16 << 10;

/// The adapter for logins of the `anthropic` API family; OAuth or key mode by the credential.
pub struct Anthropic {
    config: ureq::config::Config,
}

impl Anthropic {
    /// An adapter with [`CONNECT_TIMEOUT`] and [`ATTEMPT_TIMEOUT`], no proxy and no redirects.
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(ATTEMPT_TIMEOUT))
            .build();
        Self { config }
    }
}

impl Default for Anthropic {
    fn default() -> Self {
        Self::new()
    }
}

fn cancelled() -> Failure {
    Failure::new(FailureKind::Cancelled, "cancelled")
}

/// A transport failure, or the cancel that caused it.
fn broken(cancel: &CancelToken, what: &str, e: &dyn std::fmt::Display) -> Failure {
    if cancel.is_cancelled() {
        cancelled()
    } else {
        Failure::new(FailureKind::Unavailable, format!("{what}: {e}"))
    }
}

/// The seam's failure of a classified vendor failure.
fn failure(f: limits::Failure) -> Failure {
    use limits::FailureKind as K;
    let kind = match f.kind {
        K::UsageLimit { resets_at } => FailureKind::UsageLimit { resets_at },
        K::Auth => FailureKind::Auth,
        K::RateLimited { retry_after } => FailureKind::RateLimited { retry_after },
        K::ModelUnavailable => FailureKind::ModelUnavailable,
        K::Overloaded { retry_after } => FailureKind::Overloaded { retry_after },
        K::Unavailable => FailureKind::Unavailable,
        K::BadRequest => FailureKind::BadRequest,
        K::ContextTooLong => FailureKind::ContextTooLong,
    };
    let mut windows = f.windows;
    // qbd learns a usage limit's reset only from a window at 1.0 (see `FailureKind::UsageLimit`).
    if let FailureKind::UsageLimit {
        resets_at: Some(at),
    } = kind
    {
        if !windows.iter().any(|w| w.utilization >= 1.0) {
            for w in windows.iter_mut().filter(|w| w.resets_at == Some(at)) {
                w.utilization = 1.0;
            }
        }
    }
    Failure {
        kind,
        windows,
        message: f.message,
    }
}

/// Hands `events` to `sink`; [`FailureKind::Cancelled`] once it says stop.
fn deliver(events: &mut Vec<StreamEvent>, sink: &mut Sink<'_>) -> Result<(), Failure> {
    for event in events.drain(..) {
        if sink(event) == Flow::Stop {
            return Err(cancelled());
        }
    }
    Ok(())
}

impl Upstream for Anthropic {
    fn turn(
        &self,
        at: &Picked<'_>,
        credential: &Credential,
        req: &TurnRequest,
        sink: &mut Sink<'_>,
        cancel: &CancelToken,
    ) -> Result<Finished, Failure> {
        let auth = match credential {
            Credential::OauthAnthropic { .. } => AuthMode::Oauth,
            Credential::ApiKey { .. } => AuthMode::ApiKey,
        };
        let target = Target {
            vendor: at.vendor,
            model: at.model,
            effort: at.effort,
            auth,
            adaptive_thinking: true,
        };
        // The core admits images inline only, so there is never a path to load.
        let body = request::build(req, &target, &mut |_| None)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let body = serde_json::to_vec(&body)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let url = format!("{}{MESSAGES_PATH}", at.base_url.unwrap_or(DEFAULT_BASE_URL));

        let agent = ureq::Agent::new_with_config(self.config.clone());
        let stop = agent.clone();
        cancel.on_cancel(Box::new(move || stop.shutdown()));
        let (name, prefix) = auth.secret_header();
        let secret = credential.secret();
        let mut value = Zeroizing::new(String::with_capacity(prefix.len() + secret.len()));
        value.push_str(prefix);
        value.push_str(secret);
        let mut call = agent.post(url.as_str());
        for (header, v) in auth.headers() {
            call = call.header(header, v);
        }
        let sent = call.header(name, value.as_str()).send(&body[..]);
        drop(value);
        drop(body);
        let mut response = sent.map_err(|e| broken(cancel, "vendor request failed", &e))?;

        let status = response.status().as_u16();
        let owned: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let headers: Vec<(&str, &str)> = owned
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        if status != 200 {
            let body = response
                .body_mut()
                .with_config()
                .limit(MAX_ERROR_BODY)
                .read_to_vec();
            if cancel.is_cancelled() {
                return Err(cancelled());
            }
            // An unreadable error body still classifies by status and headers.
            let body = body.unwrap_or_default();
            return Err(failure(limits::classify_response(status, &headers, &body)));
        }

        let mut reader = Reader::new(at.vendor, limits::rate_limits(&headers));
        let mut stream = response.into_body().into_reader();
        let mut buf = vec![0u8; READ_BYTES];
        let mut events = Vec::new();
        loop {
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(broken(cancel, "vendor stream broke", &e)),
            };
            let progress = if n == 0 {
                reader.finish().map(Progress::Finished)
            } else {
                reader.feed(&buf[..n], &mut events)
            };
            deliver(&mut events, sink)?;
            if let Progress::Finished(stop) = progress.map_err(failure)? {
                return Ok(Finished {
                    stop,
                    windows: reader.windows().to_vec(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_usage_limit_fills_the_window_that_resets_with_it() {
        let headers = [
            ("anthropic-ratelimit-unified-status", "rejected"),
            ("anthropic-ratelimit-unified-reset", "1800018000"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.97"),
            ("anthropic-ratelimit-unified-5h-reset", "1800018000"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.5"),
            ("anthropic-ratelimit-unified-7d-reset", "1800500000"),
        ];
        let f = failure(limits::classify_response(429, &headers, b""));
        assert_eq!(
            f.kind,
            FailureKind::UsageLimit {
                resets_at: Some(1_800_018_000)
            }
        );
        let used: Vec<(&str, f64)> = f
            .windows
            .iter()
            .map(|w| (w.name.as_str(), w.utilization))
            .collect();
        assert_eq!(used, [("five_hour", 1.0), ("seven_day", 0.5)]);
    }
}
