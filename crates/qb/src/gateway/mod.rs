//! `qb gateway`: the model gateway. It runs as the owner of vendor credentials, serves the C4
//! contract (`/v1/model/*`, see `docs/api.md`) and the HTTP fronts, the Anthropic Messages API
//! (`/v1/messages`, see `docs/anthropic.md`) and the OpenAI Chat Completions and Responses APIs
//! (`/v1/chat/completions`, `/v1/responses`, see `docs/openai.md`), on its own unix socket, the
//! HTTP fronts also on an optional loopback port, asks qbd where to run each turn and reports back
//! what happened. qbd itself stays without secrets and network.
//!
//! - [`config`]: the gateway's TOML config;
//! - [`creds`]: credential files, OAuth refresh behind a trait, atomic write-back;
//! - [`upstream`]: the seam vendor adapters implement;
//! - [`vendor`]: the transport the adapters share;
//! - [`anthropic`]: the adapter of the `anthropic` API family;
//! - [`openai_upstream`]: the adapter of the `openai` API family;
//! - [`oauth`]: the token refresher of `oauth_anthropic` logins;
//! - [`core`]: pick, credential, adapter, report and rotation, shared by every front;
//! - [`front`]: the listeners and the C4 front;
//! - [`answer`]: how the HTTP fronts answer a turn, SSE or one body;
//! - [`messages`]: the Messages front;
//! - [`openai`]: the Chat Completions and Responses fronts.

pub mod answer;
pub mod anthropic;
pub mod config;
pub mod core;
pub mod creds;
pub mod front;
pub mod messages;
pub mod oauth;
pub mod openai;
pub mod openai_upstream;
pub mod upstream;
pub mod vendor;
