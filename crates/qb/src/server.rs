//! The daemon loop: accept, identify the peer, read one request, answer, close.
//!
//! Single thread, blocking, one connection at a time with short timeouts. The policy core is
//! owned by this loop, so leases are consistent without locks.

use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_core::Core;
use qb_proto::ErrorCode;

use crate::api::{self, Caller, Env};
use crate::http::{self, MAX_HEAD, ReadError};
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

/// Serves connections forever.
pub fn serve(listener: &UnixListener, core: &mut Core) {
    let started = Instant::now();
    let mut buf = Vec::with_capacity(MAX_HEAD);
    for conn in listener.incoming() {
        match conn {
            Ok(mut stream) => handle(&mut stream, core, &mut buf, started),
            Err(e) => {
                log::warn(&format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn handle(stream: &mut UnixStream, core: &mut Core, buf: &mut Vec<u8>, started: Instant) {
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
            api::handle(core, &req, &caller, env)
        }
        Err(ReadError::Closed | ReadError::Io(_)) => return,
        Err(ReadError::Malformed) => api::error(ErrorCode::BadRequest, "malformed HTTP request"),
        Err(ReadError::HeadTooLarge | ReadError::BodyTooLarge) => {
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

/// Reads whatever the peer already sent and we did not consume, without blocking.
///
/// Closing a unix stream socket with unread input makes the peer's next read fail with
/// `ECONNRESET`, so a client that sent an oversized or rejected body would lose our error reply.
fn drain_pending(stream: &mut UnixStream) {
    const CAP: usize = 1024 * 1024;
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let mut scratch = [0u8; 4096];
    let mut total = 0;
    while total < CAP {
        match stream.read(&mut scratch) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
    let _ = stream.set_nonblocking(false);
}
