//! The Anthropic Messages adapter: [`qb_anthropic`] builds the body and headers and reads the
//! stream, [`super::vendor`] carries the call.

use qb_anthropic::limits;
use qb_anthropic::request::{self, AuthMode, Target};
use qb_anthropic::stream::{Progress, Reader};
use qb_proto::TurnRequest;

use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Picked, Sink, Upstream,
};
use super::vendor::{self, Request};

/// Base URL of a login without `base_url`: the vendor's public endpoint.
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Path of the Messages API below the base URL.
const MESSAGES_PATH: &str = "/v1/messages";

/// The adapter for logins of the `anthropic` API family; OAuth or key mode by the credential.
pub struct Anthropic {
    config: ureq::config::Config,
}

impl Anthropic {
    /// An adapter with [`vendor::attempt_config`].
    pub fn new() -> Self {
        Self {
            config: vendor::attempt_config(),
        }
    }
}

impl Default for Anthropic {
    fn default() -> Self {
        Self::new()
    }
}

/// The seam's failure of a classified vendor failure.
pub(super) fn failure(f: limits::Failure) -> Failure {
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
        cost: None,
    }
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
            Credential::ChatgptOauth { .. } => {
                let message = "a `chatgpt_oauth` credential cannot call the Anthropic API";
                return Err(Failure::new(FailureKind::Auth, message));
            }
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
        let headers = auth.headers();
        let request = Request {
            url: &url,
            headers: headers.iter().map(|(n, v)| (*n, v.as_str())).collect(),
            secret_header: auth.secret_header(),
            body,
        };
        let mut answer = vendor::send(&self.config, request, credential.secret(), cancel)?;
        if answer.status != 200 {
            let body = answer.short_body(cancel)?;
            let headers = answer.headers();
            return Err(failure(limits::classify_response(
                answer.status,
                &headers,
                &body,
            )));
        }
        let wire_to_client = request::wire_tool_names(req, auth)
            .into_iter()
            .map(|(client, wire)| (wire, client))
            .collect();
        let mut reader = Reader::new(at.vendor, limits::rate_limits(&answer.headers()))
            .with_tool_names(wire_to_client);
        let stop = answer.stream(cancel, sink, |chunk, events| {
            let progress = if chunk.is_empty() {
                reader.finish().map(Progress::Finished)
            } else {
                reader.feed(chunk, events)
            };
            match progress.map_err(failure)? {
                Progress::Finished(stop) => Ok(Some(stop)),
                Progress::Continue => Ok(None),
            }
        })?;
        Ok(Finished {
            stop,
            windows: reader.windows().to_vec(),
            cost: None,
        })
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
