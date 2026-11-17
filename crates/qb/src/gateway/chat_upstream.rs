//! The Chat Completions adapter for API keys of OpenRouter and other OpenAI-compatible vendors:
//! [`qb_openai::chat_upstream`] builds the body and headers and reads the stream,
//! [`super::vendor`] carries the call to the login's `base_url`.

use qb_openai::chat_upstream::{self, Reader};
use qb_openai::limits;
use qb_openai::stream::Progress;
use qb_proto::TurnRequest;

use super::openai_upstream::failure;
use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Picked, Sink, Upstream,
};
use super::vendor::{self, Request};
use crate::server::unix_now;

/// The adapter for logins of the `chat_completions` API family.
pub struct ChatCompletions {
    config: ureq::config::Config,
}

impl ChatCompletions {
    /// An adapter with [`vendor::attempt_config`].
    pub fn new() -> Self {
        Self {
            config: vendor::attempt_config(),
        }
    }
}

impl Default for ChatCompletions {
    fn default() -> Self {
        Self::new()
    }
}

impl Upstream for ChatCompletions {
    fn turn(
        &self,
        at: &Picked<'_>,
        credential: &Credential,
        req: &TurnRequest,
        sink: &mut Sink<'_>,
        cancel: &CancelToken,
    ) -> Result<Finished, Failure> {
        let Credential::ApiKey { .. } = credential else {
            let message = format!(
                "an `{}` credential cannot call a Chat Completions API",
                credential.kind()
            );
            return Err(Failure::new(FailureKind::Auth, message));
        };
        let Some(base) = at.base_url else {
            let message = "a `chat_completions` login has no `base_url`";
            return Err(Failure::new(FailureKind::Unavailable, message));
        };
        let headers = chat_upstream::headers(at.referer, at.title)
            .map_err(|e| Failure::new(FailureKind::Unavailable, e.to_string()))?;
        let body = chat_upstream::build(req, at.model)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let body = serde_json::to_vec(&body)
            .map_err(|e| Failure::new(FailureKind::BadRequest, e.to_string()))?;
        let url = format!("{base}{}", chat_upstream::PATH);
        let request = Request {
            url: &url,
            headers: headers.iter().map(|(n, v)| (*n, v.as_str())).collect(),
            secret_header: chat_upstream::secret_header(),
            body,
        };
        let mut answer = vendor::send(&self.config, request, credential.secret(), cancel)?;
        if answer.status != 200 {
            let body = answer.error_body(cancel)?;
            let headers = answer.headers();
            let classified =
                limits::classify_chat_response(answer.status, &headers, &body, unix_now());
            return Err(failure(classified));
        }
        let mut reader = Reader::new();
        let stop = answer.stream(cancel, sink, |chunk, events| {
            let progress = if chunk.is_empty() {
                reader.finish(events).map(Progress::Finished)
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
            windows: Vec::new(),
        })
    }
}
