//! quota-balancer: one binary, three roles.
//!
//! - `qbd` (or `qb daemon`): the policy daemon. Holds state in RAM, serves `/v1/*` as JSON over
//!   HTTP/1.1 on a unix socket, identifies callers by bearer token or `SO_PEERCRED`. Holds no
//!   vendor secrets and needs no network.
//! - `qb agent`: runs as the owner of vendor CLI credentials and answers the daemon's probe jobs.
//! - `qb <command>`: CLI client (`health`, `state`, `why`, `pick`, `report`) and the offline
//!   `simulate`.

#![deny(unsafe_code)]

pub mod agent;
pub mod api;
pub mod auth;
pub mod client;
pub mod config;
pub mod hooks;
pub mod http;
pub mod journal;
pub mod listen;
pub mod log;
pub mod sandbox;
pub mod server;
mod sha256;
pub mod stream;

/// Socket path used when neither `--socket` nor `QB_SOCKET` is given.
pub const DEFAULT_SOCKET: &str = "/run/qb/qb.sock";

/// Daemon config path used when neither `--config` nor `QB_CONFIG` is given.
pub const DEFAULT_CONFIG: &str = "/etc/qb/qbd.toml";
