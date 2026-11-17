//! The gateway's listeners. The unix socket serves the C4 front, `/v1/model/turn`,
//! `/v1/model/routes`, `/v1/model/cancel`, `/v1/model/reload`, `/v1/model/spend`,
//! `/v1/model/spend/reset` and `/v1/health`, and the HTTP fronts: `/v1/messages` ([`super::messages`]), `/v1/chat/completions` and `/v1/responses`
//! ([`super::openai`]); the optional loopback TCP listener serves only the HTTP fronts, to
//! clients with the client token.
//! One thread per connection, at most `max_turns` + [`EXTRA_CONNECTIONS`] at once. On the C4
//! front every rejection is a non-200 [`GatewayError`], every admitted turn a `200` with a chunked
//! NDJSON stream whose head goes out with its first event; an HTTP front answers its errors in
//! its own format. The main thread accepts, cancels a turn whose client hangs up, pings silent
//! SSE answers and reloads the config on SIGHUP.

use std::cell::Cell;
use std::convert::Infallible;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    API_VERSION, CancelAnswer, CancelRequest, ErrorClass, GatewayError, HealthResponse,
    HealthStatus, SpendReset, StreamEvent, TurnRequest, paths,
};
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use serde::Serialize;

use super::answer::Keepalive;
use super::core::{Cancel, Gateway};
use super::upstream::{CancelToken, Flow};
use super::{messages, openai};
use crate::auth::token_matches;
use crate::hangup::Hangup;
use crate::http::{self, Head, Method, ReadError};
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

/// Caller name of the requests on the loopback listener, which carry the client token, not a uid.
const TOKEN_CALLER: &str = "client-token";

/// A client connection: a peer of the unix socket or of the loopback TCP listener.
pub(super) enum Conn {
    /// A unix socket peer, known by its uid.
    Unix(UnixStream),
    /// A loopback TCP peer, known by its client token.
    Tcp(TcpStream),
}

impl Conn {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(match self {
            Self::Unix(s) => Self::Unix(s.try_clone()?),
            Self::Tcp(s) => Self::Tcp(s.try_clone()?),
        })
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.set_read_timeout(timeout),
            Self::Tcp(s) => s.set_read_timeout(timeout),
        }
    }

    pub(super) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.set_write_timeout(timeout),
            Self::Tcp(s) => s.set_write_timeout(timeout),
        }
    }

    /// The poll events that tell a hung-up client: a TCP peer's close only shuts our read side.
    fn hangup_events(&self) -> PollFlags {
        match self {
            Self::Unix(_) => PollFlags::empty(),
            Self::Tcp(_) => PollFlags::RDHUP,
        }
    }
}

impl AsFd for Conn {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Unix(s) => s.as_fd(),
            Self::Tcp(s) => s.as_fd(),
        }
    }
}

impl io::Read for &Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Unix(s) => (&mut &*s).read(buf),
            Conn::Tcp(s) => (&mut &*s).read(buf),
        }
    }
}

impl io::Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Unix(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}

/// A client connection of a running turn, the turn's cancel token and, for an HTTP front, its
/// keepalive.
#[derive(Clone)]
struct Watched {
    id: u64,
    stream: Arc<Conn>,
    cancel: CancelToken,
    keepalive: Option<Arc<Keepalive>>,
}

/// The client connections of running turns, which the main thread polls for a hang-up so a turn
/// blocked on a silent vendor ends with its client, and pings when an SSE answer is silent.
pub(super) struct Watch {
    turns: Mutex<Vec<Watched>>,
    /// An eventfd that wakes the main thread when the set changes.
    wake: OwnedFd,
    next: AtomicU64,
}

/// Removes its turn from the [`Watch`] when dropped.
pub(super) struct Watching<'w> {
    watch: &'w Watch,
    id: u64,
}

impl Drop for Watching<'_> {
    fn drop(&mut self) {
        self.watch.remove(self.id);
    }
}

/// Which listeners have a connection waiting, and whether SIGHUP asked for a reload.
struct Ready {
    unix: bool,
    tcp: bool,
    reload: bool,
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

    /// Watches `stream` until the guard drops; a hang-up cancels `cancel`, and `keepalive` gets
    /// its pings.
    pub(super) fn add(
        &self,
        stream: &Conn,
        cancel: CancelToken,
        keepalive: Option<Arc<Keepalive>>,
    ) -> io::Result<Watching<'_>> {
        let stream = Arc::new(stream.try_clone()?);
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.turns().push(Watched {
            id,
            stream,
            cancel,
            keepalive,
        });
        self.ring();
        Ok(Watching { watch: self, id })
    }

    fn remove(&self, id: u64) {
        self.turns().retain(|w| w.id != id);
        self.ring();
    }

    /// Wakes the main thread to poll the set again.
    pub(super) fn ring(&self) {
        // A full counter already wakes the main thread.
        let _ = rustix::io::write(&self.wake, &1u64.to_ne_bytes());
    }

    /// Sleeps until `listener` or `loopback` has a connection or `sighup` a signal, cancelling
    /// the turns whose clients hang up and pinging the silent SSE answers meanwhile. Without a
    /// stream to ping it sleeps without a timeout.
    fn wait(
        &self,
        listener: &UnixListener,
        loopback: Option<&TcpListener>,
        sighup: Option<&Hangup>,
    ) -> Ready {
        loop {
            let watched = self.turns().clone();
            let mut fds = Vec::with_capacity(4 + watched.len());
            fds.push(PollFd::new(&self.wake, PollFlags::IN));
            fds.push(PollFd::new(listener, PollFlags::IN));
            if let Some(l) = loopback {
                fds.push(PollFd::new(l, PollFlags::IN));
            }
            if let Some(h) = sighup {
                fds.push(PollFd::new(h, PollFlags::IN));
            }
            let first = fds.len();
            fds.extend(
                watched
                    .iter()
                    .map(|w| PollFd::new(&*w.stream, w.stream.hangup_events())),
            );
            let due = watched
                .iter()
                .filter_map(|w| w.keepalive.as_ref()?.due())
                .min();
            let timeout = due
                .and_then(|d| Timespec::try_from(d.saturating_duration_since(Instant::now())).ok());
            match rustix::event::poll(&mut fds, timeout.as_ref()) {
                Ok(_) | Err(Errno::INTR) => {}
                Err(e) => {
                    log::warn(&format!("gateway: poll failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            }
            if fds[0].revents().contains(PollFlags::IN) {
                let _ = rustix::io::read(&self.wake, &mut [0u8; 8]);
            }
            let hangup = PollFlags::HUP | PollFlags::ERR | PollFlags::RDHUP;
            for (w, fd) in watched.iter().zip(&fds[first..]) {
                if fd.revents().intersects(hangup) {
                    self.remove(w.id);
                    w.cancel.cancel();
                }
            }
            let now = Instant::now();
            for w in &watched {
                if let Some(keepalive) = &w.keepalive {
                    keepalive.tick(&w.stream, now);
                }
            }
            let signalled = usize::from(loopback.is_some()) + 2;
            let ready = Ready {
                unix: fds[1].revents().contains(PollFlags::IN),
                tcp: loopback.is_some() && fds[2].revents().contains(PollFlags::IN),
                reload: sighup
                    .is_some_and(|h| fds[signalled].revents().contains(PollFlags::IN) && h.take()),
            };
            if ready.unix || ready.tcp || ready.reload {
                return ready;
            }
        }
    }
}

/// Serves `gateway` on `listener` to peers of uid `own_uid`, the gateway's own, and the
/// configured clients, and its HTTP fronts on `loopback` to peers with the client token of
/// `[fronts]`. The main thread accepts, watches the clients of running turns and reloads the
/// config when `hangup` reads a signal; each connection runs on its own thread.
///
/// # Errors
/// The eventfd of the watch cannot be created.
pub fn serve(
    listener: &UnixListener,
    loopback: Option<&TcpListener>,
    hangup: Option<&Hangup>,
    gateway: &Arc<Gateway>,
    own_uid: u32,
) -> io::Result<Infallible> {
    let started = Instant::now();
    let live = Arc::new(AtomicUsize::new(0));
    let watch = Arc::new(Watch::new()?);
    loop {
        let ready = watch.wait(listener, loopback, hangup);
        if ready.reload {
            // The outcome is logged; nobody waits for an answer.
            let _ = gateway.reload();
        }
        let mut accepted = Vec::with_capacity(2);
        if ready.unix {
            accepted.push(listener.accept().map(|(s, _)| Conn::Unix(s)));
        }
        if let (true, Some(l)) = (ready.tcp, loopback) {
            accepted.push(l.accept().map(|(s, _)| Conn::Tcp(s)));
        }
        for conn in accepted {
            let mut conn = match conn {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::warn(&format!("gateway: accept failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
            };
            let cap = gateway.config().max_turns as usize + EXTRA_CONNECTIONS;
            if live.load(Ordering::SeqCst) >= cap {
                let _ = conn.set_write_timeout(Some(IO_TIMEOUT));
                let mut e = GatewayError::new(ErrorClass::Overloaded, true, "too many connections");
                e.retry_after = Some(1);
                match conn {
                    Conn::Unix(_) => reply(&mut conn, 429, &e),
                    Conn::Tcp(_) => messages::reject(&mut conn, Some(429), &e),
                }
                continue;
            }
            live.fetch_add(1, Ordering::SeqCst);
            let (gateway, done, watch) =
                (Arc::clone(gateway), Arc::clone(&live), Arc::clone(&watch));
            let spawned = std::thread::Builder::new()
                .name("qb-gateway".into())
                .stack_size(STACK_BYTES)
                .spawn(move || {
                    handle(conn, &gateway, &watch, own_uid, started);
                    done.fetch_sub(1, Ordering::SeqCst);
                });
            if let Err(e) = spawned {
                live.fetch_sub(1, Ordering::SeqCst);
                log::warn(&format!("gateway: cannot start a connection thread: {e}"));
            }
        }
    }
}

/// Writes `body` as a JSON answer with `status`, first reading what the peer still sends.
fn reply<T: Serialize>(stream: &mut Conn, status: u16, body: &T) {
    if status >= 400 {
        drain_pending(&*stream);
    }
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    if let Err(e) = http::write_response(stream, status, &bytes) {
        log::warn(&format!("gateway: write of a {status} reply failed: {e}"));
    }
}

fn reject(stream: &mut Conn, status: u16, class: ErrorClass, message: &str) {
    reply(stream, status, &GatewayError::new(class, false, message));
}

/// The caller's name: the gateway's own uid, or a configured client's.
fn caller(gateway: &Gateway, uid: Option<u32>, own_uid: u32) -> Option<String> {
    let uid = uid?;
    if uid == own_uid {
        return Some(format!("uid:{uid}"));
    }
    let config = gateway.config();
    config
        .clients
        .iter()
        .find(|c| c.uid == uid)
        .map(|c| c.name.clone())
}

/// Reads `stream` until `until`, each read bounded by [`IO_TIMEOUT`] and the time left.
struct Deadline<'a> {
    stream: &'a Conn,
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

fn handle(mut stream: Conn, gateway: &Gateway, watch: &Watch, own_uid: u32, started: Instant) {
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() {
        return;
    }
    let uid = match &stream {
        Conn::Unix(s) => rustix::net::sockopt::socket_peercred(s)
            .ok()
            .map(|c| c.uid.as_raw()),
        Conn::Tcp(_) => return loopback(stream, gateway, watch),
    };
    // Checked before reading, so a foreign peer cannot make the gateway buffer a body.
    let Some(caller) = caller(gateway, uid, own_uid) else {
        return reject(
            &mut stream,
            401,
            ErrorClass::Auth,
            "caller is not an allowed client",
        );
    };
    let max_turn = gateway.config().max_request_bytes as usize;
    let limit = Cell::new(http::MAX_BODY);
    let dialect = Cell::new(Dialect::C4);
    let max_body = |head: &Head<'_>| {
        dialect.set(Dialect::of(head.path));
        if head.method == Method::Post
            && (head.path == paths::MODEL_TURN || HTTP_FRONTS.contains(&head.path))
        {
            limit.set(max_turn);
        }
        Some(limit.get())
    };
    let req = match read(&stream, &max_body) {
        Ok(r) => r,
        Err(e) => return unreadable(&mut stream, &e, limit.get(), dialect.get()),
    };
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::MODEL_TURN) => turn(stream, gateway, watch, &caller, req.body),
        (Method::Post, path) if HTTP_FRONTS.contains(&path) => {
            front_turn(stream, gateway, watch, &caller, req);
        }
        (_, path) if HTTP_FRONTS.contains(&path) => {
            let e = GatewayError::new(ErrorClass::BadRequest, false, "method not allowed");
            Dialect::of(path).reject(&mut stream, 405, &e);
        }
        (Method::Get, paths::MODEL_ROUTES) => reply(&mut stream, 200, &gateway.routes()),
        (Method::Post, paths::MODEL_RELOAD) => reload(&mut stream, gateway, uid == Some(own_uid)),
        (Method::Get, paths::MODEL_SPEND) | (Method::Post, paths::MODEL_SPEND_RESET) => {
            spend(&mut stream, gateway, &req, uid == Some(own_uid));
        }
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
        (
            _,
            paths::MODEL_TURN
            | paths::MODEL_ROUTES
            | paths::MODEL_CANCEL
            | paths::MODEL_RELOAD
            | paths::MODEL_SPEND
            | paths::MODEL_SPEND_RESET
            | paths::HEALTH,
        ) => {
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

/// Answers `POST /v1/model/reload`, which only the gateway's `own` uid may send.
fn reload(stream: &mut Conn, gateway: &Gateway, own: bool) {
    if !own {
        let message = "only the gateway's own uid may reload it";
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    match gateway.reload() {
        Ok(answer) => reply(stream, 200, &answer),
        Err(e) => {
            let message = format!("reload refused: {e}");
            reject(stream, 400, ErrorClass::BadRequest, &message);
        }
    }
}

/// Answers `GET /v1/model/spend` and `POST /v1/model/spend/reset`, which only the gateway's
/// `own` uid may send.
fn spend(stream: &mut Conn, gateway: &Gateway, req: &http::Request, own: bool) {
    if !own {
        let message = "only the gateway's own uid may read or reset the spend";
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    if req.method == Method::Get {
        return reply(stream, 200, &gateway.spend());
    }
    let r = match serde_json::from_slice::<SpendReset>(&req.body) {
        Ok(r) => r,
        Err(e) => return reject(stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    match gateway.reset_spend(&r.login) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(e) if e.class == ErrorClass::BadRequest => reply(stream, 400, &e),
        Err(e) => reply(stream, 500, &e),
    }
}

/// The endpoints of the HTTP fronts, `POST` only.
const HTTP_FRONTS: [&str; 3] = [paths::MESSAGES, paths::CHAT_COMPLETIONS, paths::RESPONSES];

/// Runs the HTTP front `req.path` names, one of [`HTTP_FRONTS`].
fn front_turn(stream: Conn, gateway: &Gateway, watch: &Watch, caller: &str, req: http::Request) {
    match req.path.as_str() {
        paths::CHAT_COMPLETIONS => openai::chat_turn(stream, gateway, watch, caller, req.body),
        paths::RESPONSES => openai::responses_turn(stream, gateway, watch, caller, req.body),
        _ => messages::turn(stream, gateway, watch, caller, req.body),
    }
}

/// The error format of an endpoint.
#[derive(Clone, Copy)]
enum Dialect {
    /// [`GatewayError`] of the C4 front and the other gateway endpoints.
    C4,
    /// The Messages error format.
    Messages,
    /// The OpenAI error format.
    Openai,
}

impl Dialect {
    fn of(path: &str) -> Self {
        match path {
            paths::MESSAGES => Self::Messages,
            paths::CHAT_COMPLETIONS | paths::RESPONSES => Self::Openai,
            _ => Self::C4,
        }
    }

    /// Answers `e` in this format with `status`.
    fn reject(self, stream: &mut Conn, status: u16, e: &GatewayError) {
        match self {
            Self::C4 => reply(stream, status, e),
            Self::Messages => messages::reject(stream, Some(status), e),
            Self::Openai => openai::reject(stream, Some(status), e),
        }
    }
}

/// Why the loopback listener refused a request head.
#[derive(Clone, Copy)]
enum Refusal {
    /// No client token, or a wrong one.
    Token,
    /// Not `POST` to one of [`HTTP_FRONTS`].
    Path,
}

/// Serves one connection of the loopback listener: `POST` to one of [`HTTP_FRONTS`] with the
/// client token in `x-api-key` or `Authorization: Bearer`, checked before the body is read. Every
/// answer is in the OpenAI format for the OpenAI endpoints, else in the Messages format.
fn loopback(mut stream: Conn, gateway: &Gateway, watch: &Watch) {
    let config = gateway.config();
    let token = config.fronts.as_ref().and_then(|f| f.token_sha256);
    let max_turn = config.max_request_bytes as usize;
    let refusal = Cell::new(None);
    let dialect = Cell::new(Dialect::Messages);
    let check = |head: &Head<'_>| {
        if let Dialect::Openai = Dialect::of(head.path) {
            dialect.set(Dialect::Openai);
        }
        let mut presented = [head.api_key, head.bearer].into_iter().flatten();
        if !token.is_some_and(|hash| presented.any(|t| token_matches(t, &hash))) {
            refusal.set(Some(Refusal::Token));
            return None;
        }
        if head.method != Method::Post || !HTTP_FRONTS.contains(&head.path) {
            refusal.set(Some(Refusal::Path));
            return None;
        }
        Some(max_turn)
    };
    let refused = match (read(&stream, &check), refusal.get()) {
        (Ok(req), _) => return front_turn(stream, gateway, watch, TOKEN_CALLER, req),
        (Err(ReadError::Refused { .. }), Some(refusal)) => refusal,
        (Err(e), _) => return unreadable(&mut stream, &e, max_turn, dialect.get()),
    };
    let served = "this listener serves only `POST /v1/messages`, `POST /v1/chat/completions` \
                  and `POST /v1/responses`";
    match (refused, dialect.get()) {
        (Refusal::Token, Dialect::Openai) => openai::refuse(
            &mut stream,
            401,
            "invalid_request_error",
            "invalid_api_key",
            "invalid API key: not this gateway's client token",
        ),
        (Refusal::Token, _) => messages::refuse(
            &mut stream,
            401,
            "authentication_error",
            "invalid x-api-key: not this gateway's client token",
        ),
        (Refusal::Path, Dialect::Openai) => {
            openai::refuse(
                &mut stream,
                404,
                "invalid_request_error",
                "unknown_url",
                served,
            );
        }
        (Refusal::Path, _) => messages::refuse(&mut stream, 404, "not_found_error", served),
    }
}

/// Reads one request under [`READ_DEADLINE`] with a body of at most `max_body(head)` bytes.
fn read(
    stream: &Conn,
    max_body: &dyn Fn(&Head<'_>) -> Option<usize>,
) -> Result<http::Request, ReadError> {
    let mut buf = Vec::new();
    let mut reader = Deadline {
        stream,
        until: Instant::now() + READ_DEADLINE,
    };
    http::read_request_limited(&mut reader, &mut buf, max_body)
}

/// Answers a request that could not be read, its body limit `limit`, in the error format
/// `dialect`; a closed connection or a refused head gets no answer here.
fn unreadable(stream: &mut Conn, e: &ReadError, limit: usize, dialect: Dialect) {
    let (status, message) = match *e {
        ReadError::Closed | ReadError::Io(_) | ReadError::Refused { .. } => return,
        ReadError::Malformed => (400, "malformed HTTP request".into()),
        ReadError::HeadTooLarge => (413, "request head too large".into()),
        ReadError::BodyTooLarge { unread } => {
            discard(&*stream, unread);
            (413, format!("request body over {limit} bytes"))
        }
        ReadError::LengthRequired => (411, "Content-Length required".into()),
    };
    let e = GatewayError::new(ErrorClass::BadRequest, false, message);
    dialect.reject(stream, status, &e);
}

fn turn(mut stream: Conn, gateway: &Gateway, watch: &Watch, caller: &str, body: Vec<u8>) {
    let req: TurnRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    drop(body);
    let admitted = match gateway.admit(caller, &req) {
        Ok(a) => a,
        Err(e) => return reply(&mut stream, e.class.http_status(), &e),
    };
    let _watching = match watch.add(&stream, admitted.cancel_token().clone(), None) {
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
