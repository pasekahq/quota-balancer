//! Self-restriction of `qb agent`, `qb gateway`, `qb login import` and `qb login` before they
//! touch a secret: the process becomes non-dumpable, and landlock limits it to the credential
//! directories (read-only for the agent; for the others also writing, creating and removing
//! regular files, as a credential file is written by rename, and the same in the directory of the
//! gateway's spend file). The agent, the gateway and `qb login` may also read the resolver files
//! and connect over TCP to port 443; the import has no network. The gateway and `qb login` may
//! read the files of their config's directory, the gateway for a reload, and the import those of
//! its config's and its source's directories. The only TCP bind allowed is the gateway's on the
//! port of its loopback Messages listener.

use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, LandlockStatus, NetPort, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use rustix::process::{DumpableBehavior, set_dumpable_behavior};

use crate::config::AgentConfig;
use crate::gateway::config::GatewayConfig;

/// Files the musl resolver reads for each lookup.
pub const RESOLVER_FILES: [&str; 2] = ["/etc/resolv.conf", "/etc/hosts"];

/// The only TCP port the agent may connect to.
pub const HTTPS_PORT: u16 = 443;

/// The landlock ABI whose rights the ruleset handles; 4 is the first with TCP port rules.
const TARGET_ABI: ABI = ABI::V4;

/// What [`confine`] applied.
#[derive(Debug)]
pub struct Confined {
    /// What differs from the ruleset described; empty when it is enforced as described.
    pub gaps: Vec<String>,
    /// One line on what is enforced, for the startup log.
    pub summary: String,
    /// The directories of the owned files that the process may use: those landlock opened, or
    /// all of them when landlock restricts nothing.
    pub opened: Vec<PathBuf>,
}

/// Makes the process non-dumpable, then restricts the calling thread and the threads it starts
/// with landlock: read-only beneath each login's credential directory and
/// [`RESOLVER_FILES`], and TCP connect to [`HTTPS_PORT`] only.
/// Returns what differs from that ruleset, empty when it is enforced as described.
///
/// # Errors
/// The dumpable flag cannot be cleared.
pub fn harden(config: &AgentConfig) -> Result<Vec<String>, String> {
    let files: Vec<&Path> = config
        .logins
        .iter()
        .map(|l| l.credentials.as_path())
        .collect();
    confine(&files, false, &[], None, true).map(|c| c.gaps)
}

/// [`harden`] for `qb gateway`: beneath each login's credential directory also write and
/// truncate files, create regular files and remove files, so a refreshed token can be written
/// back by a rename inside the directory; no `REFER`, so nothing moves across directories. The
/// same beneath the directories of `spend_file` and `audit_file`. Read files beneath the
/// directory of `config.file`, so a reload sees the file an editor replaced.
/// TCP bind only on the port of `fronts.listen`, whose listener must exist before. Call it
/// before starting any thread.
///
/// # Errors
/// The dumpable flag cannot be cleared.
pub fn harden_gateway(config: &GatewayConfig) -> Result<Confined, String> {
    let files: Vec<&Path> = config
        .logins
        .iter()
        .map(|l| l.credentials.as_path())
        .chain(config.spend_file.as_deref())
        .chain(config.audit_file.as_deref())
        .collect();
    let bind = config
        .fronts
        .as_ref()
        .and_then(|f| f.listen)
        .map(|a| a.port());
    confine(&files, true, &[&config.file], bind, true)
}

/// [`harden`] for `qb login import`: read files beneath the directories of `config_file` and
/// `source`; beneath the directory of `target`, the login's credential file, also write and
/// truncate files, create regular files and remove files, so the file is written by rename. No
/// resolver files and no TCP at all. Call it before the source is opened.
///
/// # Errors
/// The dumpable flag cannot be cleared.
pub fn harden_import(
    config_file: &Path,
    source: &Path,
    target: &Path,
) -> Result<Vec<String>, String> {
    confine(&[target], true, &[config_file, source], None, false).map(|c| c.gaps)
}

/// [`harden`] for `qb login`: read files beneath the directory of `config_file`; beneath the
/// directory of `target`, the login's credential file, also write and truncate files, create
/// regular files and remove files, so the file is written by rename; the resolver files and TCP
/// connect to [`HTTPS_PORT`] for the token endpoint. Call it before reading the pasted code.
///
/// # Errors
/// The dumpable flag cannot be cleared.
pub fn harden_login(config_file: &Path, target: &Path) -> Result<Vec<String>, String> {
    confine(&[target], true, &[config_file], None, true).map(|c| c.gaps)
}

/// Makes the process non-dumpable: no core dump, no same-uid ptrace or `/proc/<pid>/mem` read.
///
/// # Errors
/// The flag cannot be cleared.
pub fn non_dumpable() -> Result<(), String> {
    set_dumpable_behavior(DumpableBehavior::NotDumpable)
        .map_err(|e| format!("PR_SET_DUMPABLE: {e}"))
}

/// [`non_dumpable`], then landlock: `owned_files`' directories readable (and writable when
/// `writable`), the files of `read_files`' directories readable, TCP bind on `bind`, and with
/// `https` the resolver files and TCP connect to [`HTTPS_PORT`].
fn confine(
    owned_files: &[&Path],
    writable: bool,
    read_files: &[&Path],
    bind: Option<u16>,
    https: bool,
) -> Result<Confined, String> {
    non_dumpable()?;
    let mut gaps = Vec::new();
    let dirs = dirs_of(owned_files, &mut gaps);
    let read_dir = AccessFs::from_read(TARGET_ABI);
    let read_file = read_dir & AccessFs::from_file(TARGET_ABI);
    let credential_access = if writable {
        read_dir
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::MakeReg
            | AccessFs::RemoveFile
    } else {
        read_dir
    };
    let read_dirs = dirs_of(read_files, &mut gaps);
    let resolver: &[&str] = if https { &RESOLVER_FILES } else { &[] };
    let readable = dirs
        .iter()
        .map(|d| (d.as_path(), credential_access))
        .chain(read_dirs.iter().map(|d| (d.as_path(), read_file)))
        .chain(resolver.iter().map(|f| (Path::new(*f), read_file)));
    let mut rules = Vec::new();
    let mut opened = Vec::new();
    for (path, access) in readable {
        match PathFd::new(path) {
            Ok(fd) => {
                if dirs.iter().any(|d| d == path) {
                    opened.push(path.to_path_buf());
                }
                rules.push(PathBeneath::new(fd, access));
            }
            Err(e) => gaps.push(format!("{} stays unreadable: {e}", path.display())),
        }
    }
    let summary = summary(rules.len(), bind, https);
    match restrict(rules, bind, https) {
        Ok((RulesetStatus::FullyEnforced, _)) => {}
        Ok((RulesetStatus::PartiallyEnforced, LandlockStatus::Available { effective_abi, .. })) => {
            gaps.push(format!(
                "landlock {effective_abi:?} on this kernel: rights of later ABIs, \
                 including the TCP port rule of V4, are not enforced"
            ));
        }
        Ok((_, status)) => {
            gaps.push(format!(
                "landlock {status:?}: file and network access are not restricted"
            ));
            opened.clone_from(&dirs);
        }
        Err(e) => {
            gaps.push(format!(
                "landlock failed ({e}): file and network access are not restricted"
            ));
            opened.clone_from(&dirs);
        }
    }
    Ok(Confined {
        gaps,
        summary,
        opened,
    })
}

/// The directory of the config file `file` when the sandbox opening it to reads would open much
/// more: the root, or `home` or a directory above it.
pub fn broad_config_dir(file: &Path, home: Option<&Path>) -> Option<PathBuf> {
    let dir = file_dir(file).ok()?;
    let broad = dir.parent().is_none() || home.is_some_and(|h| h.starts_with(&dir));
    broad.then_some(dir)
}

/// The startup line of a ruleset of `paths` path rules, TCP bind on `bind` and with `https` TCP
/// connect to [`HTTPS_PORT`].
fn summary(paths: usize, bind: Option<u16>, https: bool) -> String {
    let mut net = Vec::new();
    if https {
        net.push(format!("connect {HTTPS_PORT}"));
    }
    if let Some(port) = bind {
        net.push(format!("bind {port}"));
    }
    let net = if net.is_empty() {
        "none".to_owned()
    } else {
        net.join(", ")
    };
    format!(
        "non-dumpable; landlock {TARGET_ABI:?}: files beneath {paths} paths only, TCP {net} only"
    )
}

/// The distinct directories of `files`; a file without one is added to `gaps`.
fn dirs_of(files: &[&Path], gaps: &mut Vec<String>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for file in files {
        match file_dir(file) {
            Ok(dir) if !dirs.contains(&dir) => dirs.push(dir),
            Ok(_) => {}
            Err(e) => gaps.push(format!("{} stays unreadable: {e}", file.display())),
        }
    }
    dirs
}

/// The absolute directory of the credential or config file `file`, resolved against the working
/// directory; the sandbox opens that directory to the file.
///
/// The directory, not the file, is readable because vendor CLIs and editors replace a file by
/// rename, and a rule on the file would keep pointing at the old inode.
///
/// # Errors
/// The working directory is unknown, or `file` has no parent.
pub fn file_dir(file: &Path) -> std::io::Result<PathBuf> {
    let file = std::path::absolute(file)?;
    file.parent().map(Path::to_path_buf).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "has no parent directory")
    })
}

fn restrict(
    rules: Vec<PathBeneath<PathFd>>,
    bind: Option<u16>,
    https: bool,
) -> Result<(RulesetStatus, LandlockStatus), landlock::RulesetError> {
    let ports = bind
        .map(|port| NetPort::new(port, AccessNet::BindTcp))
        .into_iter()
        .chain(https.then(|| NetPort::new(HTTPS_PORT, AccessNet::ConnectTcp)))
        .map(Ok::<_, landlock::RulesetError>);
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))?
        .handle_access(AccessNet::from_all(TARGET_ABI))?
        .create()?
        .add_rules(rules.into_iter().map(Ok::<_, landlock::RulesetError>))?
        .add_rules(ports)?
        .restrict_self()?;
    Ok((status.ruleset, status.landlock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_in_home_or_above_it_opens_a_broad_directory() {
        let home = Some(Path::new("/home/user-1"));
        let cases = [
            ("/home/user-1/.config/qb/gateway.toml", None),
            ("/etc/qb/gateway.toml", None),
            ("/home/user-1/gateway.toml", Some("/home/user-1")),
            ("/home/gateway.toml", Some("/home")),
            ("/gateway.toml", Some("/")),
            ("/home/user-10/gateway.toml", None),
        ];
        for (file, broad) in cases {
            let got = broad_config_dir(Path::new(file), home);
            assert_eq!(got, broad.map(PathBuf::from), "{file}");
        }
        assert_eq!(
            broad_config_dir(Path::new("/gateway.toml"), None),
            Some(PathBuf::from("/"))
        );
        assert_eq!(
            broad_config_dir(Path::new("/srv/qb/gateway.toml"), None),
            None
        );
    }
}
