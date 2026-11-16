//! `qb agent`: runs as the owner of vendor credentials, connects to the daemon itself and answers
//! its probe requests with window numbers only.
//!
//! Status: skeleton. It checks that the daemon is reachable and exits; vendor adapters, the
//! lazy probe, landlock and memory hygiene for tokens are a later milestone (`docs/roadmap.md`).

use std::path::Path;

use qb_proto::paths;

use crate::{client, log};

/// Runs the agent role.
///
/// # Errors
/// The daemon is unreachable or unhealthy.
pub fn run(socket: &Path) -> Result<(), String> {
    let (status, _) = client::call(socket, "GET", paths::HEALTH, None)
        .map_err(|e| format!("cannot reach qbd at {}: {e}", socket.display()))?;
    if status != 200 {
        return Err(format!("qbd health returned HTTP {status}"));
    }
    log::info("qb agent: qbd is reachable; no vendor adapters are built in yet, exiting");
    Ok(())
}
