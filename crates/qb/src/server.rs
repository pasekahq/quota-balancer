//! The daemon loop: sleep in `poll()` until a connection or the policy's next deadline, then
//! accept, identify the peer, read one request, answer, close.
//!
//! Single thread, one connection at a time with short timeouts. The policy core is owned by
//! this loop, so leases are consistent without locks.

use std::convert::Infallible;
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_core::Core;
use qb_proto::ErrorCode;
use rustix::event::{PollFd, PollFlags, Timespec};

use crate::api::{self, Caller, Env};
use crate::http::{self, MAX_HEAD, ReadError};
use crate::journal::Journal;
use crate::log;

/// Per-connection read/write timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Identity of the peer from `SO_PEERCRED`.
pub fn caller_of(stream: &UnixStream) -> Caller {
    match rustix::net::sockopt::socket_peercred(stream) {
        Ok(cred) => Caller {
            client: format!("uid:{}", cred.uid.as_raw()),
        },
        Err(_) => Caller {
            client: "unknown".to_owned(),
        },
    }
}

/// How long the loop may sleep at `now`: until the core's next deadline, after applying the
/// deadlines already due; `None` (no timeout) when nothing is pending.
pub fn poll_timeout(core: &mut Core, now: u64) -> Option<Duration> {
    loop {
        let at = core.next_deadline()?;
        if at > now {
            return Some(Duration::from_secs(at - now));
        }
        core.tick(now);
    }
}

/// Serves connections until the listener fails; state changes go to `journal`.
///
/// # Errors
/// The listener cannot be made non-blocking or polled.
pub fn serve(
    listener: &UnixListener,
    core: &mut Core,
    journal: &mut Journal,
) -> io::Result<Infallible> {
    listener.set_nonblocking(true)?;
    let started = Instant::now();
    let mut buf = Vec::with_capacity(MAX_HEAD);
    loop {
        // A deadline too far away for a timespec is as good as none.
        let timeout = poll_timeout(core, unix_now()).and_then(|d| Timespec::try_from(d).ok());
        let mut fds = [PollFd::new(listener, PollFlags::IN)];
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if stream.set_nonblocking(false).is_ok() {
                        handle(&mut stream, core, journal, &mut buf, started);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn(&format!("accept failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    break;
                }
            }
        }
    }
}

fn handle(
    stream: &mut UnixStream,
    core: &mut Core,
    journal: &mut Journal,
    buf: &mut Vec<u8>,
    started: Instant,
) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let caller = caller_of(stream);
    let reply = match http::read_request(stream, buf) {
        Ok(req) => {
            let env = Env {
                now: unix_now(),
                uptime_s: started.elapsed().as_secs(),
            };
            api::handle(core, journal, &req, &caller, env)
        }
        Err(ReadError::Closed | ReadError::Io(_)) => return,
        Err(ReadError::Malformed) => api::error(ErrorCode::BadRequest, "malformed HTTP request"),
        Err(ReadError::HeadTooLarge) => api::error(ErrorCode::PayloadTooLarge, "request too large"),
        Err(ReadError::BodyTooLarge { unread }) => {
            discard(stream, unread);
            api::error(ErrorCode::PayloadTooLarge, "request too large")
        }
        Err(ReadError::LengthRequired) => {
            api::error(ErrorCode::LengthRequired, "Content-Length required")
        }
    };
    if reply.status >= 400 {
        drain_pending(stream);
    }
    if let Err(e) = http::write_response(stream, reply.status, &reply.body) {
        log::warn(&format!("write to {} failed: {e}", caller.client));
    }
}

/// Most bytes read and dropped from a rejected request.
const DRAIN_CAP: usize = 1024 * 1024;

/// Reads and drops up to `len` declared body bytes within one I/O timeout, so a client still
/// writing an oversized body finishes its write and reads the 413 instead of `EPIPE`.
fn discard(stream: &mut UnixStream, len: usize) {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut left = len.min(DRAIN_CAP);
    let mut scratch = [0u8; 4096];
    while left > 0 {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() || stream.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        let take = left.min(scratch.len());
        match stream.read(&mut scratch[..take]) {
            Ok(0) | Err(_) => break,
            Ok(n) => left -= n,
        }
    }
}

/// Reads whatever the peer already sent and we did not consume, without blocking.
///
/// Closing a unix stream socket with unread input makes the peer's next read fail with
/// `ECONNRESET`, so a client that sent an oversized or rejected body would lose our error reply.
fn drain_pending(stream: &mut UnixStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut scratch = [0u8; 4096];
    let mut total = 0;
    while total < DRAIN_CAP {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    let _ = stream.set_nonblocking(false);
}

#[cfg(test)]
mod tests {
    use qb_core::{
        LoginSpec, LoginStatus, OutcomeClass, ReportInput, ReportSubject, Spec, VendorSpec,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn core() -> Core {
        let login = |name: &str| LoginSpec {
            name: name.into(),
            vendor: "vendor-a".into(),
        };
        Core::new(Spec {
            vendors: vec![VendorSpec {
                name: "vendor-a".into(),
                windows: Vec::new(),
            }],
            logins: vec![login("login-1"), login("login-2")],
            rate_limit_backoff_s: 60,
            ..Spec::default()
        })
        .expect("valid spec")
    }

    fn rate_limit(core: &mut Core, login: &str, now: u64) {
        let input = ReportInput {
            subject: ReportSubject::Login(login.into()),
            outcome: OutcomeClass::Http429,
            model: None,
            release: false,
            windows: Vec::new(),
        };
        core.report(&input, now).expect("known login");
    }

    fn statuses(core: &Core) -> Vec<LoginStatus> {
        core.snapshot(NOW).logins.iter().map(|l| l.status).collect()
    }

    #[test]
    fn no_deadline_waits_without_timeout() {
        assert_eq!(poll_timeout(&mut core(), NOW), None);
    }

    #[test]
    fn future_deadline_gives_the_remaining_time() {
        let mut core = core();
        rate_limit(&mut core, "login-1", NOW);
        assert_eq!(poll_timeout(&mut core, NOW), Some(Duration::from_secs(60)));
        assert_eq!(
            poll_timeout(&mut core, NOW + 59),
            Some(Duration::from_secs(1))
        );
        assert_eq!(statuses(&core)[0], LoginStatus::RateLimited);
    }

    #[test]
    fn due_deadline_ticks_before_waiting() {
        let mut core = core();
        rate_limit(&mut core, "login-1", NOW);
        rate_limit(&mut core, "login-2", NOW + 30);
        assert_eq!(
            poll_timeout(&mut core, NOW + 60),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            statuses(&core),
            [LoginStatus::Unknown, LoginStatus::RateLimited]
        );
        assert_eq!(poll_timeout(&mut core, NOW + 95), None);
        assert_eq!(
            statuses(&core),
            [LoginStatus::Unknown, LoginStatus::Unknown]
        );
    }
}
