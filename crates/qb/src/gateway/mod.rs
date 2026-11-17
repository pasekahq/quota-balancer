//! `qb gateway`: the model gateway. It runs as the owner of vendor credentials, serves the C4
//! contract (`/v1/model/*`, see `docs/api.md`) and the Anthropic Messages API (`/v1/messages`,
//! see `docs/anthropic.md`) on its own unix socket, the Messages API also on an optional loopback
//! port, asks qbd where to run each turn and reports back what happened. qbd itself stays without
//! secrets and network.
//!
//! - [`config`]: the gateway's TOML config;
//! - [`creds`]: credential files, OAuth refresh behind a trait, atomic write-back;
//! - [`upstream`]: the seam vendor adapters implement;
//! - [`anthropic`]: the adapter of the `anthropic` API family;
//! - [`oauth`]: the token refresher of `oauth_anthropic` logins;
//! - [`core`]: pick, credential, adapter, report and rotation, shared by every front;
//! - [`front`]: the listeners and the C4 front;
//! - [`messages`]: the Messages front.

pub mod anthropic;
pub mod config;
pub mod core;
pub mod creds;
pub mod front;
pub mod messages;
pub mod oauth;
pub mod upstream;
