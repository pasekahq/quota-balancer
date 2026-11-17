//! The seam between the gateway core and a vendor adapter: the core picks a login, loads its
//! credential and calls [`Upstream::turn`] once per attempt; the adapter speaks the vendor's
//! protocol and maps its answer into C4 events and a vendor-neutral [`Failure`].
//!
//! The core owns everything around a call: the `route` event, the terminal `stop` or `error`
//! event, reports to qbd, rotation to the next login, and whether an event already reached the
//! client. An adapter only emits content events (`text_delta`, `thinking`, `tool_call`,
//! `usage`) through the sink and returns how the call ended.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use qb_proto::{StopReason, StreamEvent, TurnRequest, WindowReport};
use zeroize::Zeroizing;

/// The login an attempt runs on, as qbd picked it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Picked<'a> {
    /// Vendor name from the config; the `vendor` of every `thinking` event of this attempt.
    pub vendor: &'a str,
    /// Model id to request.
    pub model: &'a str,
    /// Reasoning effort of the ladder candidate, if any; the request's `effort` wins when set.
    pub effort: Option<&'a str>,
    /// Whether the model reasons, from the config's `openai_models`; the OpenAI adapter sends no
    /// reasoning, effort or `include` without it.
    pub reasoning: bool,
    /// Login name; for logs and errors, never a credential.
    pub login: &'a str,
    /// Base URL of the vendor API from the login's config; `None` for the adapter's public
    /// endpoint.
    pub base_url: Option<&'a str>,
    /// `http-referer` of a `chat_completions` login.
    pub referer: Option<&'a str>,
    /// `x-title` of a `chat_completions` login.
    pub title: Option<&'a str>,
}

/// What the adapter authenticates with, read from the login's credential file for one attempt
/// and zeroized when dropped. `Debug` never shows the secret.
pub enum Credential {
    /// An OAuth access token of an Anthropic subscription login.
    OauthAnthropic {
        /// Bearer access token.
        access_token: Zeroizing<String>,
    },
    /// A vendor API key.
    ApiKey {
        /// The key.
        key: Zeroizing<String>,
    },
    /// An OAuth access token of a ChatGPT subscription login and the account it acts for.
    ChatgptOauth {
        /// Bearer access token.
        access_token: Zeroizing<String>,
        /// ChatGPT account id, sent in its own header.
        account_id: Zeroizing<String>,
    },
}

impl Credential {
    /// The secret to send: the access token or the key.
    pub fn secret(&self) -> &str {
        match self {
            Self::OauthAnthropic { access_token } | Self::ChatgptOauth { access_token, .. } => {
                access_token
            }
            Self::ApiKey { key } => key,
        }
    }

    /// The account id of a ChatGPT login; `None` for the other kinds.
    pub fn account_id(&self) -> Option<&str> {
        match self {
            Self::ChatgptOauth { account_id, .. } => Some(account_id),
            Self::OauthAnthropic { .. } | Self::ApiKey { .. } => None,
        }
    }

    /// The credential type as named in the credential file.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::OauthAnthropic { .. } => "oauth_anthropic",
            Self::ApiKey { .. } => "api_key",
            Self::ChatgptOauth { .. } => "chatgpt_oauth",
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Credential({}, redacted)", self.kind())
    }
}

/// Whether the adapter should go on after handing an event to the sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep streaming.
    Continue,
    /// The client is gone or cancelled: stop reading the vendor and return [`FailureKind::Cancelled`].
    Stop,
}

/// Set by `POST /v1/model/cancel` or a dropped client. An adapter polls it between reads and
/// registers [`CancelToken::on_cancel`] to unblock a read in progress, for example by shutting
/// down a clone of its vendor TCP stream.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<CancelState>);

#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CancelToken({})", self.is_cancelled())
    }
}

impl CancelToken {
    /// A token that is not cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels every clone of this token and runs the registered hook, once.
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::SeqCst);
        let hook = self.hook().take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Whether the turn was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Runs `hook` on cancel, replacing an earlier hook; at once if already cancelled. An
    /// adapter registers one per attempt and calls [`CancelToken::clear`] when it ends.
    pub fn on_cancel(&self, hook: Box<dyn FnOnce() + Send>) {
        let mut slot = self.hook();
        if self.is_cancelled() {
            drop(slot);
            hook();
        } else {
            *slot = Some(hook);
        }
    }

    /// Drops the registered hook.
    pub fn clear(&self) {
        self.hook().take();
    }

    fn hook(&self) -> MutexGuard<'_, Option<Box<dyn FnOnce() + Send>>> {
        self.0.hook.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A call that ended normally.
#[derive(Debug, Clone, PartialEq)]
pub struct Finished {
    /// Why the model stopped.
    pub stop: StopReason,
    /// Quota windows the vendor reported (for example in response headers), for qbd's `report`.
    pub windows: Vec<WindowReport>,
}

/// How a call failed, vendor-neutral. The core maps it to a qbd outcome and decides whether to
/// try another login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// The login's usage limit is reached; `resets_at` when the vendor said so. qbd learns the
    /// reset only from [`Failure::windows`], by the window names its vendor declares, so the
    /// adapter also puts the limiting window there with `utilization` 1.0 and this `resets_at`.
    UsageLimit {
        /// Unix time the limit lifts; the client's `error.resets_at` after content.
        resets_at: Option<u64>,
    },
    /// The credential was rejected (HTTP 401 or equivalent).
    Auth,
    /// The login is rate limited for a short time (HTTP 429 without exhaustion).
    RateLimited {
        /// Seconds the vendor asked to wait.
        retry_after: Option<u64>,
    },
    /// The model is not available on this login.
    ModelUnavailable,
    /// The vendor as a whole asked to back off (overloaded).
    Overloaded {
        /// Seconds the vendor asked to wait.
        retry_after: Option<u64>,
    },
    /// The vendor could not be reached or failed (transport error, 5xx, broken stream).
    Unavailable,
    /// The vendor refused the request as invalid.
    BadRequest,
    /// The conversation does not fit the model.
    ContextTooLong,
    /// The sink returned [`Flow::Stop`] or the [`CancelToken`] was set.
    Cancelled,
}

/// A failed call.
#[derive(Debug, Clone, PartialEq)]
pub struct Failure {
    /// What went wrong.
    pub kind: FailureKind,
    /// Quota windows the vendor reported with the failure, for qbd's `report`.
    pub windows: Vec<WindowReport>,
    /// Detail for the log and the client's `error.message`; never a credential or a header
    /// value. The core still replaces the attempt's credential by `[redacted]` if it appears.
    pub message: String,
}

impl FailureKind {
    /// A short name for logs, e.g. `usage_limit`.
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
            Self::Cancelled => "cancelled",
        }
    }
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

/// Receives the content events of one call; the return value tells the adapter whether to go on.
pub type Sink<'a> = dyn FnMut(StreamEvent) -> Flow + 'a;

/// A vendor adapter. Calls are synchronous; the core runs each turn on its own thread, so one
/// adapter value serves concurrent turns.
pub trait Upstream: Send + Sync {
    /// Runs `req` once on `at` with `credential`, handing content events to `sink` in order.
    /// `req` has no `thinking` blocks of another vendor than `at.vendor`.
    ///
    /// # Errors
    /// The call failed; events already handed to the sink stay delivered.
    fn turn(
        &self,
        at: &Picked<'_>,
        credential: &Credential,
        req: &TurnRequest,
        sink: &mut Sink<'_>,
        cancel: &CancelToken,
    ) -> Result<Finished, Failure>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_secret() {
        let c = Credential::ApiKey {
            key: Zeroizing::new("test-token-1".into()),
        };
        let shown = format!("{c:?}");
        assert!(!shown.contains("test-token-1"), "{shown}");
        assert_eq!(c.secret(), "test-token-1");
        assert_eq!(c.kind(), "api_key");
    }

    #[test]
    fn cancel_reaches_every_clone() {
        let a = CancelToken::new();
        let b = a.clone();
        assert!(!b.is_cancelled());
        let hits = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&hits);
        b.on_cancel(Box::new(move || seen.store(true, Ordering::SeqCst)));
        a.cancel();
        assert!(b.is_cancelled());
        assert!(hits.load(Ordering::SeqCst), "the hook ran");
        let late = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&late);
        a.on_cancel(Box::new(move || seen.store(true, Ordering::SeqCst)));
        assert!(
            late.load(Ordering::SeqCst),
            "a hook after the cancel runs at once"
        );
    }
}
