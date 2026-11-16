//! Self-restriction of `qb agent` before its first connection to the daemon: the process becomes
//! non-dumpable, and landlock limits it to reading the credential directories and the resolver
//! files and to TCP connections to port 443.

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};

use crate::config::AgentConfig;

/// Files the musl resolver reads for each lookup.
pub const RESOLVER_FILES: [&str; 2] = ["/etc/resolv.conf", "/etc/hosts"];

/// The only TCP port the agent may connect to.
pub const HTTPS_PORT: u16 = 443;

/// The landlock ABI whose rights the ruleset handles; 4 is the first with TCP port rules.
const TARGET_ABI: ABI = ABI::V4;

/// Makes the process non-dumpable, then restricts the calling thread and the threads it starts
/// with landlock: read-only beneath each login's credential directory and
/// [`RESOLVER_FILES`], and TCP connect to [`HTTPS_PORT`] only.
/// Returns what differs from that ruleset, empty when it is enforced as described.
///
/// # Errors
/// The dumpable flag cannot be cleared.
pub fn harden(config: &AgentConfig) -> Result<Vec<String>, String> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    let mut gaps = Vec::new();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for login in &config.logins {
        match credential_dir(&login.credentials) {
            Ok(dir) if !dirs.contains(&dir) => dirs.push(dir),
            Ok(_) => {}
            Err(e) => gaps.push(format!(
                "{} stays unreadable: {e}",
                login.credentials.display()
            )),
        }
    }
    let read_dir = AccessFs::from_read(TARGET_ABI);
    let read_file = read_dir & AccessFs::from_file(TARGET_ABI);
    let readable = dirs
        .iter()
        .map(|d| (d.as_path(), read_dir))
        .chain(RESOLVER_FILES.map(|f| (Path::new(f), read_file)));
    let mut rules = Vec::new();
    for (path, access) in readable {
        match PathFd::new(path) {
            Ok(fd) => rules.push(PathBeneath::new(fd, access)),
            Err(e) => gaps.push(format!("{} stays unreadable: {e}", path.display())),
        }
    }
    match restrict(rules) {
        Ok((RulesetStatus::FullyEnforced, _)) => {}
        Ok((RulesetStatus::PartiallyEnforced, LandlockStatus::Available { effective_abi, .. })) => {
            gaps.push(format!(
                "landlock {effective_abi:?} on this kernel: rights of later ABIs, \
                 including the TCP port rule of V4, are not enforced"
            ));
        }
        Ok((_, status)) => gaps.push(format!(
            "landlock {status:?}: file and network access are not restricted"
        )),
        Err(e) => gaps.push(format!(
            "landlock failed ({e}): file and network access are not restricted"
        )),
    }
    Ok(gaps)
}

/// The absolute directory of the credential file `file`, resolved against the working directory.
///
/// The directory, not the file, is readable because vendor CLIs replace the file by rename when
/// they refresh the token, and a rule on the file would keep pointing at the old inode.
fn credential_dir(file: &Path) -> std::io::Result<PathBuf> {
    let file = std::path::absolute(file)?;
    file.parent().map(Path::to_path_buf).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "has no parent directory")
    })
}

fn restrict(
    rules: Vec<PathBeneath<PathFd>>,
) -> Result<(RulesetStatus, LandlockStatus), landlock::RulesetError> {
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))?
        .handle_access(AccessNet::from_all(TARGET_ABI))?
        .create()?
        .add_rules(rules.into_iter().map(Ok::<_, landlock::RulesetError>))?
        .add_rule(NetPort::new(HTTPS_PORT, AccessNet::ConnectTcp))?
        .restrict_self()?;
    Ok((status.ruleset, status.landlock))
}
