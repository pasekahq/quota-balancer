//! `qb gateway`: the model gateway. It runs as the owner of vendor credentials, serves the C4
//! contract (`/v1/model/*`, see `docs/api.md`) and the HTTP fronts, the Anthropic Messages API
//! (`/v1/messages`, see `docs/anthropic.md`) and the OpenAI Chat Completions and Responses APIs
//! (`/v1/chat/completions`, `/v1/responses`, see `docs/openai.md`), on its own unix socket, the
//! HTTP fronts also on an optional loopback port, asks qbd where to run each turn and reports back
//! what happened. qbd itself stays without secrets and network.
//!
//! - [`config`]: the gateway's TOML config;
//! - [`config_edit`]: the `[[routes]]` of the config file rendered and spliced and the logins'
//!   `spend_cap`s set for an edit;
//! - [`creds`]: credential files, OAuth refresh behind a trait, atomic write-back;
//! - [`import`]: `qb login import`, a credential of another client copied into a login's file;
//! - [`signin`]: `qb login`, an OAuth login signed in from scratch with PKCE;
//! - [`upstream`]: the seam vendor adapters implement;
//! - [`vendor`]: the transport the adapters share;
//! - [`anthropic`]: the adapter of the `anthropic` API family;
//! - [`openai_upstream`]: the adapter of the `openai` API family;
//! - [`chat_upstream`]: the adapter of the `chat_completions` API family;
//! - [`oauth`]: the token endpoint client of `oauth_anthropic` and `chatgpt_oauth` logins, for
//!   refreshes and sign-ins;
//! - [`core`]: pick, credential, adapter, report and rotation, shared by every front;
//! - [`spend`]: the monthly spend count of capped logins;
//! - [`audit`]: the admin audit file, appended to and read back;
//! - [`admin`]: `qbd`'s `/v1/admin/*` forwarded for the gateway's own uid;
//! - [`usage`]: the usage ledger, one line per adapter attempt, rotated and pruned;
//! - [`tokens`]: the tokens of the named loopback clients with a `token_file`, their rotation and
//!   grace;
//! - [`front`]: the listeners and the C4 front;
//! - [`answer`]: how the HTTP fronts answer a turn, SSE or one body;
//! - [`messages`]: the Messages front;
//! - [`openai`]: the Chat Completions and Responses fronts.

use qb_proto::ErrorClass;

mod admin;
pub mod answer;
pub mod anthropic;
pub mod audit;
mod base64url;
pub mod chat_upstream;
pub mod config;
pub mod config_edit;
pub mod core;
pub mod creds;
pub mod front;
pub mod import;
pub mod messages;
pub mod oauth;
pub mod openai;
pub mod openai_upstream;
pub mod signin;
pub mod spend;
pub mod tokens;
pub mod upstream;
pub mod usage;
pub mod vendor;

/// Why an admin action was refused: the answer's status and class, and a message without a
/// secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// HTTP status of the answer.
    pub status: u16,
    /// Class of the answer's error.
    pub class: ErrorClass,
    /// What went wrong.
    pub message: String,
}

impl Refusal {
    pub(crate) fn new(status: u16, class: ErrorClass, message: String) -> Self {
        Self {
            status,
            class,
            message,
        }
    }
}
