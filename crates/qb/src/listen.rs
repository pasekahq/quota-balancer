//! Where the daemon's listening socket comes from: systemd socket activation or a path.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// First fd passed by systemd (`SD_LISTEN_FDS_START`).
const SD_LISTEN_FDS_START: i32 = 3;

static TAKEN: AtomicBool = AtomicBool::new(false);

/// Takes the socket passed by systemd (`LISTEN_PID`/`LISTEN_FDS`, see `sd_listen_fds(3)`).
///
/// Returns `Ok(None)` when the process was not socket-activated.
///
/// # Errors
/// More than one fd was passed, the fd is not a stream socket, or this was already called.
#[allow(unsafe_code)]
pub fn from_systemd() -> io::Result<Option<UnixListener>> {
    let ours = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        == Some(std::process::id());
    if !ours {
        return Ok(None);
    }
    let count: u32 = std::env::var("LISTEN_FDS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    match count {
        0 => return Ok(None),
        1 => {}
        n => {
            return Err(io::Error::other(format!(
                "expected 1 socket from systemd, got {n}"
            )));
        }
    }
    if TAKEN.swap(true, Ordering::SeqCst) {
        return Err(io::Error::other("systemd socket already taken"));
    }
    // SAFETY: per sd_listen_fds(3), when LISTEN_PID equals our pid, fd SD_LISTEN_FDS_START is open
    // and belongs to this process. The TAKEN guard makes sure ownership is taken exactly once.
    let fd = unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) };
    rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)?;
    if rustix::net::sockopt::socket_type(&fd)? != rustix::net::SocketType::STREAM
        || rustix::net::sockopt::socket_domain(&fd)? != rustix::net::AddressFamily::UNIX
    {
        return Err(io::Error::other(
            "systemd socket is not an AF_UNIX stream socket",
        ));
    }
    Ok(Some(UnixListener::from(fd)))
}

/// Binds a socket at `path` with mode 0660. A stale socket file nobody listens on is replaced;
/// a live one is an error (another daemon is running).
///
/// # Errors
/// Bind/permission errors, or a live daemon on the path.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} is served by a running daemon", path.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(path)?;
            }
            Err(e) => return Err(e),
        }
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}
