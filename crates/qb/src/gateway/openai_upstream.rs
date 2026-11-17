//! The OpenAI Responses adapter: [`qb_openai`] builds the body and headers and reads the stream,
//! [`super::vendor`] carries the call. An API key and a ChatGPT subscription login differ in
//! endpoint, headers and `max_output_tokens`, all chosen by the credential's kind.

use qb_openai::limits;
use qb_openai::request::{self, AuthMode, Target};
use qb_openai::stream::{self, Progress, Reader};
use qb_proto::TurnRequest;

use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Picked, Sink, Upstream,
};
use super::vendor::{self, Request};
use crate::server::unix_now;

/// Path of the Responses API below a login's `base_url`.
const RESPONSES_PATH: &str = "/responses";

/// The adapter for logins of the `openai` API family; ChatGPT or key mode by the credential.
pub struct Openai {
    config: ureq::config::Config,
}

impl Openai {
    /// An adapter with [`vendor::attempt_config`].
    pub fn new() -> Self {
        Self {
            config: vendor::attempt_config(),
        }
    }
}

impl Default for Openai {
    fn default() -> Self {
        Self::new()
    }
}

/// The seam's failure of a classified vendor failure; the limiting window of a usage limit is
/// already at 1.0.
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
    Failure {
        kind,
        windows: f.windows,
        message: f.message,
        cost: None,
    }
}

impl Upstream for Openai {
    fn turn(
        &self,
        at: &Picked<'_>,
        credential: &Credential,
        req: &TurnRequest,
        sink: &mut Sink<'_>,
        cancel: &CancelToken,
    ) -> Result<Finished, Failure> {
        let auth = match credential {
            Credential::ApiKey { .. } => AuthMode::ApiKey,
            Credential::ChatgptOauth { .. } => AuthMode::ChatgptOauth,
            Credential::OauthAnthropic { .. } => {
                let message = "an `oauth_anthropic` credential cannot call the OpenAI API";
                return Err(Failure::new(FailureKind::Auth, message));
            }
        };
        let target = Target {
            vendor: at.vendor,
            model: at.model,
            effort: at.effort,
            auth,
            reasoning: at.reasoning,
        };
        let body = request::build(req, &target)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let body = serde_json::to_vec(&body)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let max_event = stream::event_bound(body.len());
        let url = match at.base_url {
            Some(base) => format!("{base}{RESPONSES_PATH}"),
            None => auth.url().to_owned(),
        };
        let mut headers = auth.headers(req.session_key.as_deref());
        if let (Some(name), Some(account)) = (auth.account_header(), credential.account_id()) {
            headers.push((name, account.to_owned()));
        }
        let request = Request {
            url: &url,
            headers: headers.iter().map(|(n, v)| (*n, v.as_str())).collect(),
            secret_header: auth.secret_header(),
            body,
        };
        let mut answer = vendor::send(&self.config, request, credential.secret(), cancel)?;
        if answer.status != 200 {
            let body = answer.error_body(cancel)?;
            let headers = answer.headers();
            let classified = limits::classify_response(answer.status, &headers, &body, unix_now());
            return Err(failure(classified));
        }
        let limits = limits::rate_limits(&answer.headers(), unix_now());
        let mut reader = Reader::with_event_bound(at.vendor, limits, max_event);
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
