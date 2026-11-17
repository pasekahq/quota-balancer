//! The C4 front: `/v1/model/turn`, `/v1/model/routes`, `/v1/model/cancel` and `/v1/health` over
//! the gateway's unix socket. One thread per connection, at most `max_turns` +
//! [`EXTRA_CONNECTIONS`] at once; every rejection is a non-200 [`GatewayError`], every admitted
//! turn a `200` with a chunked NDJSON stream whose head goes out with its first event. The main
//! thread accepts and cancels a turn whose client hangs up.

use std::cell::Cell;
use std::convert::Infallible;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    API_VERSION, CancelAnswer, CancelRequest, ErrorClass, GatewayError, HealthResponse,
    HealthStatus, StreamEvent, TurnRequest, paths,
};
use rustix::event::{EventfdFlags, PollFd, PollFlags};
use rustix::io::Errno;
use serde::Serialize;

use super::core::{Cancel, Gateway};
use super::upstream::{CancelToken, Flow};
use crate::http::{self, Method, ReadError};
use crate::log;
use crate::server::{IO_TIMEOUT, discard, drain_pending};

/// Connections beyond `max_turns` served at once, so routes, cancel and health get through
/// while turns are at the cap.
pub const EXTRA_CONNECTIONS: usize = 2;

/// Stack of a connection thread.
pub const STACK_BYTES: usize = 512 * 1024;

/// How long writing one event to a slow client may take before the turn is cut.
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long reading one request, head and body, may take.
pub const READ_DEADLINE: Duration = Duration::from_secs(10);

/// Content type of the turn stream.
pub const NDJSON: &str = "application/x-ndjson";

/// A client connection of a running turn and the turn's cancel token.
#[derive(Clone)]
struct Watched {
    id: u64,
    stream: Arc<UnixStream>,
    cancel: CancelToken,
}

/// The client connections of running turns, which the main thread polls for a hang-up so a turn
/// blocked on a silent vendor ends with its client.
struct Watch {
    turns: Mutex<Vec<Watched>>,
    /// An eventfd that wakes the main thread when the set changes.
    wake: OwnedFd,
    next: AtomicU64,
}

/// Removes its turn from the [`Watch`] when dropped.
struct Watching<'w> {
    watch: &'w Watch,
    id: u64,
}

impl Drop for Watching<'_> {
    fn drop(&mut self) {
        self.watch.remove(self.id);
    }
}

impl Watch {
    fn new() -> io::Result<Self> {
        let wake = rustix::event::eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        Ok(Self {
            turns: Mutex::new(Vec::new()),
            wake,
            next: AtomicU64::new(0),
        })
    }

    fn turns(&self) -> std::sync::MutexGuard<'_, Vec<Watched>> {
        self.turns.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Watches `stream` until the guard drops; a hang-up cancels `cancel`.
    fn add(&self, stream: &UnixStream, cancel: CancelToken) -> io::Result<Watching<'_>> {
        let stream = Arc::new(stream.try_clone()?);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.turns().push(Watched { id, stream, cancel });
        self.ring();
        Ok(Watching { watch: self, id })
    }

    fn remove(&self, id: u64) {
        self.turns().retain(|w| w.id != id);
        self.ring();
    }

    fn ring(&self) {
        // A full counter already wakes the main thread.
        let _ = rustix::io::write(&self.wake, &1u64.to_ne_bytes());
    }

    /// Sleeps until `listener` has a connection, cancelling the turns whose clients hang up
    /// meanwhile.
    fn wait(&self, listener: &UnixListener) {
        loop {
            let watched = self.turns().clone();
            let mut fds = Vec::with_capacity(2 + watched.len());
            fds.push(PollFd::new(listener, PollFlags::IN));
            fds.push(PollFd::new(&self.wake, PollFlags::IN));
            fds.extend(
                watched
                    .iter()
                    .map(|w| PollFd::new(&*w.stream, PollFlags::empty())),
            );
            match rustix::event::poll(&mut fds, None) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(e) => {
                    log::warn(&format!("gateway: poll failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            }
            if fds[1].revents().contains(PollFlags::IN) {
                let _ = rustix::io::read(&self.wake, &mut [0u8; 8]);
            }
            for (w, fd) in watched.iter().zip(&fds[2..]) {
                if fd.revents().intersects(PollFlags::HUP | PollFlags::ERR) {
                    self.remove(w.id);
                    w.cancel.cancel();
                }
            }
            if fds[0].revents().contains(PollFlags::IN) {
                return;
            }
        }
    }
}

/// Serves `gateway` on `listener` to peers of uid `own_uid`, the gateway's own, and the
/// configured clients. The main thread accepts and watches the clients of running turns; each
/// connection runs on its own thread.
///
/// # Errors
/// The eventfd of the watch cannot be created.
pub fn serve(
    listener: &UnixListener,
    gateway: &Arc<Gateway>,
    own_uid: u32,
) -> io::Result<Infallible> {
    let cap = gateway.config().max_turns as usize + EXTRA_CONNECTIONS;
    let started = Instant::now();
    let live = Arc::new(AtomicUsize::new(0));
    let watch = Arc::new(Watch::new()?);
    loop {
        watch.wait(listener);
        let mut stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                log::warn(&format!("gateway: accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        if live.load(Ordering::SeqCst) >= cap {
            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            reject(
                &mut stream,
                429,
                ErrorClass::Overloaded,
                "too many connections",
            );
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (gateway, done, watch) = (Arc::clone(gateway), Arc::clone(&live), Arc::clone(&watch));
        let spawned = std::thread::Builder::new()
            .name("qb-gateway".into())
            .stack_size(STACK_BYTES)
            .spawn(move || {
                handle(stream, &gateway, &watch, own_uid, started);
                done.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            live.fetch_sub(1, Ordering::SeqCst);
            log::warn(&format!("gateway: cannot start a connection thread: {e}"));
        }
    }
}

/// Writes `body` as a JSON answer with `status`, first reading what the peer still sends.
fn reply<T: Serialize>(stream: &mut UnixStream, status: u16, body: &T) {
    if status >= 400 {
        drain_pending(stream);
    }
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    if let Err(e) = http::write_response(stream, status, &bytes) {
        log::warn(&format!("gateway: write of a {status} reply failed: {e}"));
    }
}

fn reject(stream: &mut UnixStream, status: u16, class: ErrorClass, message: &str) {
    let retryable = class == ErrorClass::Overloaded;
    let mut e = GatewayError::new(class, retryable, message);
    if retryable {
        e.retry_after = Some(1);
    }
    reply(stream, status, &e);
}

/// The caller's name: the gateway's own uid, or a configured client's.
fn caller(gateway: &Gateway, uid: Option<u32>, own_uid: u32) -> Option<String> {
    let uid = uid?;
    if uid == own_uid {
        return Some(format!("uid:{uid}"));
    }
    let clients = &gateway.config().clients;
    clients
        .iter()
        .find(|c| c.uid == uid)
        .map(|c| c.name.clone())
}

/// Reads `stream` until `until`, each read bounded by [`IO_TIMEOUT`] and the time left.
struct Deadline<'a> {
    stream: &'a UnixStream,
    until: Instant,
}

impl io::Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left.min(IO_TIMEOUT)))?;
        (&mut &*self.stream).read(buf)
    }
}

fn handle(
    mut stream: UnixStream,
    gateway: &Gateway,
    watch: &Watch,
    own_uid: u32,
    started: Instant,
) {
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() {
        return;
    }
    let uid = rustix::net::sockopt::socket_peercred(&stream)
        .ok()
        .map(|c| c.uid.as_raw());
    // Checked before reading, so a foreign peer cannot make the gateway buffer a body.
    let Some(caller) = caller(gateway, uid, own_uid) else {
        return reject(
            &mut stream,
            401,
            ErrorClass::Auth,
            "caller is not an allowed client",
        );
    };
    let Some(req) = read(&mut stream, gateway.config().max_request_bytes as usize) else {
        return;
    };
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::MODEL_TURN) => turn(stream, gateway, watch, &caller, req.body),
        (Method::Get, paths::MODEL_ROUTES) => reply(&mut stream, 200, &gateway.routes()),
        (Method::Post, paths::MODEL_CANCEL) => {
            let c = match serde_json::from_slice::<CancelRequest>(&req.body) {
                Ok(c) => c,
                Err(e) => return reject(&mut stream, 400, ErrorClass::BadRequest, &e.to_string()),
            };
            match gateway.cancel(&caller, &c.request_id) {
                Cancel::Cancelled => reply(&mut stream, 200, &CancelAnswer { cancelled: true }),
                Cancel::Unknown => {
                    reject(
                        &mut stream,
                        404,
                        ErrorClass::BadRequest,
                        "no such running turn",
                    );
                }
                Cancel::Forbidden => reject(
                    &mut stream,
                    403,
                    ErrorClass::BadRequest,
                    "the turn belongs to another caller",
                ),
            }
        }
        (Method::Get, paths::HEALTH) => {
            let health = HealthResponse {
                status: HealthStatus::Ok,
                api_version: API_VERSION.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                uptime_s: started.elapsed().as_secs(),
            };
            reply(&mut stream, 200, &health);
        }
        (_, paths::MODEL_TURN | paths::MODEL_ROUTES | paths::MODEL_CANCEL | paths::HEALTH) => {
            reject(
                &mut stream,
                405,
                ErrorClass::BadRequest,
                "method not allowed",
            );
        }
        _ => reject(&mut stream, 404, ErrorClass::BadRequest, "no such endpoint"),
    }
}

/// Reads one request under [`READ_DEADLINE`]: a turn body of at most `max_turn` bytes, any
/// other of at most [`http::MAX_BODY`]. A request that cannot be read is answered here.
fn read(stream: &mut UnixStream, max_turn: usize) -> Option<http::Request> {
    let limit = Cell::new(http::MAX_BODY);
    let max_body = |method, path: &str| {
        if method == Method::Post && path == paths::MODEL_TURN {
            limit.set(max_turn);
        }
        limit.get()
    };
    let mut buf = Vec::new();
    let mut reader = Deadline {
        stream,
        until: Instant::now() + READ_DEADLINE,
    };
    let (status, message) = match http::read_request_limited(&mut reader, &mut buf, &max_body) {
        Ok(r) => return Some(r),
        Err(ReadError::Closed | ReadError::Io(_)) => return None,
        Err(ReadError::Malformed) => (400, "malformed HTTP request".into()),
        Err(ReadError::HeadTooLarge) => (413, "request head too large".into()),
        Err(ReadError::BodyTooLarge { unread }) => {
            discard(stream, unread);
            (413, format!("request body over {} bytes", limit.get()))
        }
        Err(ReadError::LengthRequired) => (411, "Content-Length required".into()),
    };
    reject(stream, status, ErrorClass::BadRequest, &message);
    None
}

fn turn(mut stream: UnixStream, gateway: &Gateway, watch: &Watch, caller: &str, body: Vec<u8>) {
    let req: TurnRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    drop(body);
    let admitted = match gateway.admit(caller, &req) {
        Ok(a) => a,
        Err(e) => return reply(&mut stream, e.class.http_status(), &e),
    };
    let _watching = match watch.add(&stream, admitted.cancel_token().clone()) {
        Ok(w) => w,
        Err(e) => {
            let message = format!("cannot watch the connection: {e}");
            let e = GatewayError::new(ErrorClass::Unavailable, true, message);
            return reply(&mut stream, e.class.http_status(), &e);
        }
    };
    if stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .is_err()
    {
        return;
    }
    let mut started = false;
    let mut emit = |event: StreamEvent| {
        let Ok(mut line) = serde_json::to_vec(&event) else {
            return Flow::Stop;
        };
        line.push(b'\n');
        let head = if started {
            Ok(())
        } else {
            started = true;
            http::write_stream_head(&mut stream, NDJSON)
        };
        match head.and_then(|()| http::write_chunk(&mut stream, &line)) {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Stop,
        }
    };
    gateway.run(&admitted, &req, &mut emit);
    if started {
        let _ = http::write_stream_end(&mut stream);
    }
}
