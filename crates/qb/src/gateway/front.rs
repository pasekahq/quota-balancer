//! The gateway's listeners. The unix socket serves the C4 front, `/v1/model/turn`,
//! `/v1/model/routes`, `/v1/model/ladder`, `/v1/model/cancel`, `/v1/model/reload`, `/v1/model/spend`,
//! `/v1/model/spend/reset`, `/v1/model/audit`, `/v1/model/usage`,
//! `/v1/model/clients/{name}/rotate`, `/v1/model/config/routes`, `/v1/model/logins/{name}/key`,
//! `/v1/model/logins/{name}/oauth/start`, `/v1/model/logins/{name}/oauth/code`, `/v1/health`
//! and `qbd`'s `/v1/admin/roles` and `/v1/admin/reload` ([`super::admin`]), and the HTTP fronts:
//! `/v1/messages` ([`super::messages`]), `/v1/chat/completions` and `/v1/responses`
//! ([`super::openai`]); the optional loopback TCP listener serves only the HTTP fronts, to clients
//! with a client token, and `/v1/model/ladder` to a named one.
//! One thread per connection, at most `max_turns` + [`EXTRA_CONNECTIONS`] at once; a loopback
//! peer takes one of these slots only once its head showed a client token, and before that one
//! of [`LOOPBACK_UNCHECKED`] slots of its own, for at most [`LOOPBACK_HEAD_DEADLINE`]. On the C4
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

use qb_proto::gateway::MAX_USAGE_ROWS;
use qb_proto::{
    API_VERSION, AuditAction, CancelAnswer, CancelRequest, ErrorClass, GatewayError,
    HealthResponse, HealthStatus, SpendReset, StreamEvent, TurnRequest, paths,
};
use rustix::event::{EventfdFlags, PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use serde::Serialize;
use zeroize::Zeroizing;

use super::answer::Keepalive;
use super::config::{Fronts, TOKEN_CALLER};
use super::core::{Cancel, Gateway, LadderQuery, edit_action};
use super::tokens::ClientTokens;
use super::upstream::{CancelToken, Flow};
use super::usage::{self, AggregateError};
use super::{admin, audit, messages, openai};
use crate::auth::token_matches;
use crate::hangup::Hangup;
use crate::http::{self, Head, Method, ReadError};
use crate::log;
use crate::server::{IO_TIMEOUT, discard, drain_pending, unix_now};

/// Connections beyond `max_turns` served at once, so routes, cancel and health get through
/// while turns are at the cap.
pub const EXTRA_CONNECTIONS: usize = 2;

/// Stack of a connection thread.
pub const STACK_BYTES: usize = 512 * 1024;

/// How long writing one event to a slow client may take before the turn is cut.
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long reading one request, head and body, may take.
pub const READ_DEADLINE: Duration = Duration::from_secs(10);

/// Loopback connections whose head has not shown a client token yet, served at once; they never
/// hold the slots of the unix socket's clients.
pub const LOOPBACK_UNCHECKED: usize = 4;

/// How long a loopback peer may take to send the head that shows a client token.
pub const LOOPBACK_HEAD_DEADLINE: Duration = Duration::from_secs(2);

/// Content type of the turn stream.
pub const NDJSON: &str = "application/x-ndjson";

/// Who sends a request: the name its turns run under and the route aliases it may run on.
pub(super) struct Caller {
    pub(super) name: String,
    /// `None` for every route.
    pub(super) routes: Option<Vec<String>>,
}

impl Caller {
    /// Whether it may run a turn on the route `alias`.
    pub(super) fn may_run(&self, alias: &str) -> bool {
        self.routes
            .as_ref()
            .is_none_or(|routes| routes.iter().any(|r| r == alias))
    }
}

/// A client connection: a peer of the unix socket or of the loopback TCP listener.
pub(super) enum Conn {
    /// A unix socket peer, known by its uid.
    Unix(UnixStream),
    /// A loopback TCP peer, known by a client token.
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
/// configured clients, and its HTTP fronts on `loopback` to peers with a client token of
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
    let unchecked = Arc::new(AtomicUsize::new(0));
    let watch = Arc::new(Watch::new()?);
    loop {
        let ready = watch.wait(listener, loopback, hangup);
        if ready.reload {
            // The outcome is logged; nobody waits for an answer.
            let _ = gateway.reload(audit::SIGNAL);
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
            let slot = match conn {
                Conn::Unix(_) => Slot::take(&live, connection_cap(gateway)),
                Conn::Tcp(_) => Slot::take(&unchecked, LOOPBACK_UNCHECKED),
            };
            let Some(slot) = slot else {
                let _ = conn.set_write_timeout(Some(IO_TIMEOUT));
                let e = too_many();
                match conn {
                    Conn::Unix(_) => reply(&mut conn, 429, &e),
                    Conn::Tcp(_) => messages::reject(&mut conn, Some(429), &e),
                }
                continue;
            };
            let (gateway, watch, live) =
                (Arc::clone(gateway), Arc::clone(&watch), Arc::clone(&live));
            let spawned = std::thread::Builder::new()
                .name("qb-gateway".into())
                .stack_size(STACK_BYTES)
                .spawn(move || match conn {
                    Conn::Unix(_) => {
                        handle(conn, &gateway, &watch, own_uid, started);
                        drop(slot);
                    }
                    Conn::Tcp(_) => serve_loopback(conn, &gateway, &watch, slot, &live),
                });
            if let Err(e) = spawned {
                log::warn(&format!("gateway: cannot start a connection thread: {e}"));
            }
        }
    }
}

/// Connections served at once besides the loopback peers not yet checked.
fn connection_cap(gateway: &Gateway) -> usize {
    gateway.config().max_turns as usize + EXTRA_CONNECTIONS
}

/// The answer to a connection beyond its cap.
fn too_many() -> GatewayError {
    let mut e = GatewayError::new(ErrorClass::Overloaded, true, "too many connections");
    e.retry_after = Some(1);
    e
}

/// One taken connection slot of a count; dropping it gives the slot back.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// A slot of `count` when fewer than `cap` are taken.
    fn take(count: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        let mut n = count.load(Ordering::SeqCst);
        loop {
            if n >= cap {
                return None;
            }
            match count.compare_exchange_weak(n, n + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Self(Arc::clone(count))),
                Err(now) => n = now,
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Writes `body` as a JSON answer with `status`, first reading what the peer still sends.
fn reply<T: Serialize>(stream: &mut Conn, status: u16, body: &T) {
    reply_with(stream, status, &[], body);
}

/// [`reply`] with the further headers `headers`.
fn reply_with<T: Serialize>(stream: &mut Conn, status: u16, headers: &[(&str, &str)], body: &T) {
    if status >= 400 {
        drain_pending(&*stream);
    }
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    if let Err(e) = http::write_response_with(stream, status, headers, &bytes) {
        log::warn(&format!("gateway: write of a {status} reply failed: {e}"));
    }
}

fn reject(stream: &mut Conn, status: u16, class: ErrorClass, message: &str) {
    reply(stream, status, &GatewayError::new(class, false, message));
}

/// The caller of a unix socket peer: the gateway's own uid, or a configured client's.
fn caller(gateway: &Gateway, uid: u32, own_uid: u32) -> Option<Caller> {
    let name = if uid == own_uid {
        audit::uid_actor(uid)
    } else {
        let config = gateway.config();
        config.clients.iter().find(|c| c.uid == uid)?.name.clone()
    };
    Some(Caller { name, routes: None })
}

/// The caller of a loopback request that carries `token` at `now`: the unnamed client token's or
/// a named client's as `tokens` accepts it, each hash compared in constant time.
fn token_caller(fronts: &Fronts, tokens: &ClientTokens, token: &str, now: u64) -> Option<Caller> {
    if fronts
        .token_sha256
        .is_some_and(|hash| token_matches(token, &hash))
    {
        let name = TOKEN_CALLER.to_owned();
        return Some(Caller { name, routes: None });
    }
    let client = fronts
        .clients
        .iter()
        .find(|c| tokens.accepts(c, token, now))?;
    Some(Caller {
        name: client.name.clone(),
        routes: client.routes.clone(),
    })
}

/// Reads `stream` until `until`, each read bounded by [`IO_TIMEOUT`] and the time left.
struct Deadline<'a> {
    stream: &'a Conn,
    until: &'a Cell<Instant>,
}

impl io::Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.get().saturating_duration_since(Instant::now());
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
        // `serve` hands loopback peers to `serve_loopback`.
        Conn::Tcp(_) => return,
    };
    // Checked before reading, so a foreign peer cannot make the gateway buffer a body.
    let Some((uid, caller)) = uid.and_then(|uid| Some((uid, caller(gateway, uid, own_uid)?)))
    else {
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
    let login_target = Cell::new(None);
    let max_body = |head: &Head<'_>| {
        dialect.set(Dialect::of(head.path));
        if head.method == Method::Post
            && (head.path == paths::MODEL_TURN || HTTP_FRONTS.contains(&head.path))
        {
            limit.set(max_turn);
        }
        if let Some((name, action)) = login_target_of(head.path) {
            limit.set(MAX_LOGIN_BODY);
            login_target.set(Some((name.to_owned(), action)));
        }
        Some(limit.get())
    };
    let req = match read(&stream, &max_body) {
        Ok(r) => r,
        Err(e) => {
            if let Some((name, action)) = login_target.take() {
                let reason = unread(&e, limit.get())
                    .map_or_else(|| "the request's body was not read".to_owned(), |(_, m)| m);
                gateway.refuse_login(&audit::uid_actor(uid), action, &name, &reason);
            }
            return unreadable(&mut stream, &e, limit.get(), dialect.get());
        }
    };
    if named(&mut stream, gateway, &req, uid, own_uid) {
        return;
    }
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::MODEL_TURN) => turn(stream, gateway, watch, &caller.name, req.body),
        (Method::Post, path) if HTTP_FRONTS.contains(&path) => {
            front_turn(stream, gateway, watch, &caller, req);
        }
        (_, path) if HTTP_FRONTS.contains(&path) => {
            let e = GatewayError::new(ErrorClass::BadRequest, false, "method not allowed");
            Dialect::of(path).reject(&mut stream, 405, &e);
        }
        (Method::Get, paths::MODEL_ROUTES) => reply(&mut stream, 200, &gateway.routes()),
        (Method::Get, paths::MODEL_LADDER) => ladder(&mut stream, gateway, &caller, &req),
        (Method::Post, paths::MODEL_RELOAD) => {
            reload(&mut stream, gateway, &audit::uid_actor(uid), uid == own_uid);
        }
        (Method::Get, paths::MODEL_SPEND) => spend(&mut stream, gateway, uid == own_uid),
        (Method::Post, paths::MODEL_SPEND_RESET) => {
            let actor = audit::uid_actor(uid);
            spend_reset(&mut stream, gateway, &req.body, &actor, uid == own_uid);
        }
        (Method::Get, paths::MODEL_AUDIT) => {
            read_audit(&mut stream, gateway, req.query.as_deref(), uid == own_uid);
        }
        (Method::Get, paths::MODEL_USAGE) => {
            read_usage(&mut stream, gateway, req.query.as_deref(), uid == own_uid);
        }
        (_, paths::MODEL_CONFIG_ROUTES) => config_routes(&mut stream, gateway, &req, uid, own_uid),
        (Method::Post, paths::MODEL_CANCEL) => cancel(&mut stream, gateway, &caller, &req.body),
        (Method::Get, paths::HEALTH) => reply(&mut stream, 200, &health(started)),
        (_, path) if admin::serves(path) => qbd_admin(&mut stream, gateway, &req, uid, own_uid),
        (
            _,
            paths::MODEL_TURN
            | paths::MODEL_ROUTES
            | paths::MODEL_LADDER
            | paths::MODEL_CANCEL
            | paths::MODEL_RELOAD
            | paths::MODEL_SPEND
            | paths::MODEL_SPEND_RESET
            | paths::MODEL_AUDIT
            | paths::MODEL_USAGE
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

/// The answer of `GET /v1/health` of a gateway that started at `started`.
fn health(started: Instant) -> HealthResponse {
    HealthResponse {
        status: HealthStatus::Ok,
        api_version: API_VERSION.to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_s: started.elapsed().as_secs(),
    }
}

/// Answers `req` from the peer of `uid` when its path names a client or a login, an admin
/// endpoint of the gateway's own uid `own_uid`; false for another path.
fn named(
    stream: &mut Conn,
    gateway: &Gateway,
    req: &http::Request,
    uid: u32,
    own_uid: u32,
) -> bool {
    let actor = audit::uid_actor(uid);
    let own = uid == own_uid;
    if let Some((name, action)) = login_target_of(&req.path) {
        login(stream, gateway, name, action, req, &actor, own);
    } else if let Some(name) = rotate_target(&req.path) {
        if req.method == Method::Post {
            rotate(stream, gateway, name, &actor, own);
        } else {
            reject(stream, 405, ErrorClass::BadRequest, "method not allowed");
        }
    } else {
        return false;
    }
    true
}

/// The client name of a `/v1/model/clients/{name}/rotate` path.
fn rotate_target(path: &str) -> Option<&str> {
    let name = path
        .strip_prefix(paths::MODEL_CLIENTS)?
        .strip_prefix('/')?
        .strip_suffix("/rotate")?;
    (!name.is_empty() && !name.contains('/')).then_some(name)
}

/// Answers `POST /v1/model/clients/{name}/rotate` of `actor`, which only the gateway's `own` uid
/// may send.
fn rotate(stream: &mut Conn, gateway: &Gateway, name: &str, actor: &str, own: bool) {
    if !own {
        let message = "only the gateway's own uid may rotate a client token";
        let entry = audit::entry(actor, AuditAction::ClientRotate, Some(name.to_owned()));
        gateway.record(&audit::refused(entry, message));
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    respond(stream, gateway.rotate_client(actor, name));
}

/// Largest body of a `POST` to `/v1/model/logins/{name}/key` or `.../oauth/*`.
const MAX_LOGIN_BODY: usize = 8 * 1024;

/// The login name of a `/v1/model/logins/{name}/key`, `.../oauth/start` or `.../oauth/code`
/// path and the audit action of a request to it.
fn login_target_of(path: &str) -> Option<(&str, AuditAction)> {
    let rest = path.strip_prefix(paths::MODEL_LOGINS)?.strip_prefix('/')?;
    let (name, action) = [
        ("/key", AuditAction::LoginKey),
        ("/oauth/start", AuditAction::LoginOauthStart),
        ("/oauth/code", AuditAction::LoginOauthCode),
    ]
    .into_iter()
    .find_map(|(suffix, action)| Some((rest.strip_suffix(suffix)?, action)))?;
    (!name.is_empty() && !name.contains('/')).then_some((name, action))
}

/// Answers `req` of `actor` to the login `name`'s endpoint of `action`, which only the gateway's
/// `own` uid may `POST`.
fn login(
    stream: &mut Conn,
    gateway: &Gateway,
    name: &str,
    action: AuditAction,
    req: &http::Request,
    actor: &str,
    own: bool,
) {
    let refuse = |stream: &mut Conn, status: u16, class: ErrorClass, message: &str| {
        gateway.refuse_login(actor, action, name, message);
        reject(stream, status, class, message);
    };
    if !own {
        let message = if action == AuditAction::LoginKey {
            "only the gateway's own uid may replace a login's key"
        } else {
            "only the gateway's own uid may sign a login in"
        };
        return refuse(stream, 403, ErrorClass::Auth, message);
    }
    if req.method != Method::Post {
        return refuse(stream, 405, ErrorClass::BadRequest, "method not allowed");
    }
    match action {
        AuditAction::LoginOauthStart if !req.body.is_empty() => {
            refuse(
                stream,
                400,
                ErrorClass::BadRequest,
                "this request takes no body",
            );
        }
        AuditAction::LoginOauthStart => respond(stream, gateway.start_sign_in(actor, name)),
        AuditAction::LoginOauthCode => {
            respond(stream, gateway.finish_sign_in(actor, name, &req.body));
        }
        _ => respond(stream, gateway.replace_login_key(actor, name, &req.body)),
    }
}

/// Answers 200 with the answer of an admin action, or its refusal.
fn respond<T: Serialize>(stream: &mut Conn, result: Result<T, super::Refusal>) {
    match result {
        Ok(answer) => reply(stream, 200, &answer),
        Err(r) => reject(stream, r.status, r.class, &r.message),
    }
}

/// Who may read or edit the config's routes and spend caps.
const CONFIG_OWNER: &str =
    "only the gateway's own uid may read or edit the config's routes and spend caps";

/// Answers `req` to `/v1/model/config/routes` from the peer of `uid`.
fn config_routes(
    stream: &mut Conn,
    gateway: &Gateway,
    req: &http::Request,
    uid: u32,
    own_uid: u32,
) {
    let own = uid == own_uid;
    match req.method {
        Method::Get => read_config_routes(stream, gateway, own),
        Method::Put => put_config_routes(stream, gateway, req, &audit::uid_actor(uid), own),
        _ => reject(stream, 405, ErrorClass::BadRequest, "method not allowed"),
    }
}

/// Answers `GET /v1/model/config/routes`, which only the gateway's `own` uid may send, with the
/// file's hash also as a strong `ETag`.
fn read_config_routes(stream: &mut Conn, gateway: &Gateway, own: bool) {
    if !own {
        return reject(stream, 403, ErrorClass::Auth, CONFIG_OWNER);
    }
    match gateway.config_routes() {
        Ok(answer) => {
            let etag = format!("\"{}\"", answer.sha256);
            reply_with(stream, 200, &[("ETag", &etag)], &answer);
        }
        Err(e) => {
            let message = format!("cannot read the config file: {e}");
            log::error(&format!("gateway: {message}"));
            reject(stream, 500, ErrorClass::Unavailable, &message);
        }
    }
}

/// Answers `PUT /v1/model/config/routes` of `actor` with `req`, which only the gateway's `own`
/// uid may send.
fn put_config_routes(
    stream: &mut Conn,
    gateway: &Gateway,
    req: &http::Request,
    actor: &str,
    own: bool,
) {
    if !own {
        let object = Some(gateway.config().file.display().to_string());
        let put = serde_json::from_slice(&req.body).ok();
        let entry = audit::entry(actor, edit_action(put.as_ref()), object);
        gateway.record(&audit::refused(entry, CONFIG_OWNER));
        return reject(stream, 403, ErrorClass::Auth, CONFIG_OWNER);
    }
    match gateway.put_config(actor, req.if_match.as_deref(), &req.body) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(r) => reject(stream, r.status, r.class, &r.message),
    }
}

/// Answers `req` of the peer of `uid` to one of `qbd`'s admin endpoints with `qbd`'s answer, which
/// only the gateway's own uid `own_uid` may send: its 200 body and `ETag` unchanged, or its refusal.
fn qbd_admin(stream: &mut Conn, gateway: &Gateway, req: &http::Request, uid: u32, own_uid: u32) {
    match admin::forward(gateway, req, &audit::uid_actor(uid), uid == own_uid) {
        Ok(passed) => {
            let etag = passed.etag.as_deref().map(|tag| ("ETag", tag));
            if let Err(e) = http::write_response_with(stream, 200, etag.as_slice(), &passed.body) {
                log::warn(&format!("gateway: write of a 200 reply failed: {e}"));
            }
        }
        Err(r) => reject(stream, r.status, r.class, &r.message),
    }
}

/// Answers `POST /v1/model/cancel` of `caller` with `body`.
fn cancel(stream: &mut Conn, gateway: &Gateway, caller: &Caller, body: &[u8]) {
    let c = match serde_json::from_slice::<CancelRequest>(body) {
        Ok(c) => c,
        Err(e) => return reject(stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    match gateway.cancel(&caller.name, &c.request_id) {
        Cancel::Cancelled => reply(stream, 200, &CancelAnswer { cancelled: true }),
        Cancel::Unknown => reject(stream, 404, ErrorClass::BadRequest, "no such running turn"),
        Cancel::Forbidden => reject(
            stream,
            403,
            ErrorClass::BadRequest,
            "the turn belongs to another caller",
        ),
    }
}

/// Answers `POST /v1/model/reload` of `actor`, which only the gateway's `own` uid may send.
fn reload(stream: &mut Conn, gateway: &Gateway, actor: &str, own: bool) {
    if !own {
        let message = "only the gateway's own uid may reload it";
        gateway.refuse_reload(actor, message);
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    match gateway.reload(actor) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(e) => {
            let message = format!("reload refused: {e}");
            reject(stream, 400, ErrorClass::BadRequest, &message);
        }
    }
}

/// Who may read or reset the spend.
const SPEND_OWNER: &str = "only the gateway's own uid may read or reset the spend";

/// Answers `GET /v1/model/spend`, which only the gateway's `own` uid may send.
fn spend(stream: &mut Conn, gateway: &Gateway, own: bool) {
    if !own {
        return reject(stream, 403, ErrorClass::Auth, SPEND_OWNER);
    }
    reply(stream, 200, &gateway.spend());
}

/// Answers `POST /v1/model/spend/reset` of `actor` with `body`, which only the gateway's `own`
/// uid may send.
fn spend_reset(stream: &mut Conn, gateway: &Gateway, body: &[u8], actor: &str, own: bool) {
    let refuse = |stream: &mut Conn, status: u16, class: ErrorClass, message: &str| {
        let entry = audit::entry(actor, AuditAction::SpendReset, None);
        gateway.record(&audit::refused(entry, message));
        reject(stream, status, class, message);
    };
    if !own {
        return refuse(stream, 403, ErrorClass::Auth, SPEND_OWNER);
    }
    let r = match serde_json::from_slice::<SpendReset>(body) {
        Ok(r) => r,
        Err(e) => return refuse(stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    match gateway.reset_spend(actor, &r.login) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(e) if e.class == ErrorClass::BadRequest => reply(stream, 400, &e),
        Err(e) => reply(stream, 500, &e),
    }
}

/// Answers `GET /v1/model/ladder` of `caller` with the query string of `req`.
fn ladder(stream: &mut Conn, gateway: &Gateway, caller: &Caller, req: &http::Request) {
    let query = match LadderQuery::parse(req.query.as_deref()) {
        Ok(q) => q,
        Err(message) => return reject(stream, 400, ErrorClass::BadRequest, &message),
    };
    match gateway.ladder(&caller.name, caller.routes.as_deref(), &query) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(refusal) => {
            if refusal.status == 403 {
                log::warn(&format!(
                    "gateway: refused client `{}` the ladder: {}",
                    caller.name,
                    log::peer_text(&refusal.message)
                ));
            }
            reject(stream, refusal.status, refusal.class, &refusal.message);
        }
    }
}

/// Answers a loopback request to `/v1/model/ladder`: only `GET` of a named client.
fn loopback_ladder(stream: &mut Conn, gateway: &Gateway, caller: &Caller, req: &http::Request) {
    // The config refuses `TOKEN_CALLER` as the name of a named client.
    if caller.name == TOKEN_CALLER {
        let message = "the unnamed client token may not read the ladder; a `[[fronts.clients]]` \
                       token may";
        log::warn("gateway: loopback refused the unnamed client token the ladder");
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    if req.method != Method::Get {
        return reject(stream, 405, ErrorClass::BadRequest, "method not allowed");
    }
    ladder(stream, gateway, caller, req);
}

/// Answers `GET /v1/model/audit` with the query string `query`, which only the gateway's `own`
/// uid may send.
fn read_audit(stream: &mut Conn, gateway: &Gateway, query: Option<&str>, own: bool) {
    if !own {
        let message = "only the gateway's own uid may read the audit";
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    let config = gateway.config();
    let Some(file) = &config.audit_file else {
        let message = "this gateway keeps no audit: its config sets no `audit_file`";
        return reject(stream, 404, ErrorClass::BadRequest, message);
    };
    let query = match audit::Query::parse(query) {
        Ok(q) => q,
        Err(message) => return reject(stream, 400, ErrorClass::BadRequest, &message),
    };
    match audit::read(file, &query) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(e) => {
            let message = format!("cannot read the audit file {}: {e}", file.display());
            log::error(&format!("gateway: {message}"));
            reject(stream, 500, ErrorClass::Unavailable, &message);
        }
    }
}

/// Answers `GET /v1/model/usage` with the query string `query`, which only the gateway's `own`
/// uid may send.
fn read_usage(stream: &mut Conn, gateway: &Gateway, query: Option<&str>, own: bool) {
    if !own {
        let message = "only the gateway's own uid may read the usage";
        return reject(stream, 403, ErrorClass::Auth, message);
    }
    let config = gateway.config();
    let Some(ledger) = &config.usage else {
        let message = "this gateway keeps no usage ledger: its config has no `[usage]` table";
        return reject(stream, 404, ErrorClass::BadRequest, message);
    };
    let window =
        usage::parse_query(query).and_then(|q| usage::window_end(&q, unix_now()).map(|to| (q, to)));
    let (query, to) = match window {
        Ok(w) => w,
        Err(message) => return reject(stream, 400, ErrorClass::BadRequest, &message),
    };
    match usage::aggregate(&ledger.file, &query, to) {
        Ok(answer) => reply(stream, 200, &answer),
        Err(AggregateError::TooManyRows) => {
            let message = format!(
                "the answer would have more than {MAX_USAGE_ROWS} rows; ask for a narrower \
                 window or a coarser bucket"
            );
            reject(stream, 400, ErrorClass::BadRequest, &message);
        }
        Err(AggregateError::Io(e)) => {
            let message = format!(
                "cannot read the usage ledger {}: {e}",
                ledger.file.display()
            );
            log::error(&format!("gateway: {message}"));
            reject(stream, 500, ErrorClass::Unavailable, &message);
        }
    }
}

/// The endpoints of the HTTP fronts, `POST` only.
const HTTP_FRONTS: [&str; 3] = [paths::MESSAGES, paths::CHAT_COMPLETIONS, paths::RESPONSES];

/// Runs the HTTP front `req.path` names, one of [`HTTP_FRONTS`].
fn front_turn(stream: Conn, gateway: &Gateway, watch: &Watch, caller: &Caller, req: http::Request) {
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
    /// Every connection slot is taken.
    Busy,
}

impl Refusal {
    /// Its name in the log.
    fn class(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Path => "path",
            Self::Busy => "busy",
        }
    }
}

/// Records `why` in `refusal` and logs it with the head's method and path, never a header value.
fn refuse_head(refusal: &Cell<Option<Refusal>>, why: Refusal, head: &Head<'_>) {
    refusal.set(Some(why));
    log::warn(&format!(
        "gateway: loopback refused {} {}: {}",
        head.method.as_str(),
        log::peer_text(head.path),
        why.class()
    ));
}

/// Serves one connection of the loopback listener: `POST` to one of [`HTTP_FRONTS`] or a request
/// to `/v1/model/ladder` without a body, with a client token of `[fronts]` in `x-api-key` or
/// `Authorization: Bearer`, checked before the body is read; the turn runs as that token's caller.
/// Every answer is a [`GatewayError`] for the ladder, in the OpenAI format for the OpenAI
/// endpoints, else in the Messages format.
///
/// The connection holds `unchecked` until its head is read, which must happen within
/// [`LOOPBACK_HEAD_DEADLINE`]; a head with the token then takes a slot of `live`, and the body
/// may take the rest of [`READ_DEADLINE`].
fn serve_loopback(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    unchecked: Slot,
    live: &Arc<AtomicUsize>,
) {
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() {
        return;
    }
    let config = gateway.config();
    let fronts = config.fronts.as_ref();
    let tokens = gateway.client_tokens();
    let now = unix_now();
    let limit = Cell::new(config.max_request_bytes as usize);
    let refusal = Cell::new(None);
    let dialect = Cell::new(Dialect::Messages);
    let started = Instant::now();
    let until = Cell::new(started + LOOPBACK_HEAD_DEADLINE);
    let unchecked = Cell::new(Some(unchecked));
    let slot = Cell::new(None);
    let matched = Cell::new(None);
    let check = |head: &Head<'_>| {
        drop(unchecked.take());
        let ladder = head.path == paths::MODEL_LADDER;
        if ladder || matches!(Dialect::of(head.path), Dialect::Openai) {
            dialect.set(Dialect::of(head.path));
        }
        let mut presented = [head.api_key, head.bearer].into_iter().flatten();
        let caller = fronts.and_then(|f| presented.find_map(|t| token_caller(f, &tokens, t, now)));
        let Some(caller) = caller else {
            refuse_head(&refusal, Refusal::Token, head);
            return None;
        };
        if !ladder && (head.method != Method::Post || !HTTP_FRONTS.contains(&head.path)) {
            refuse_head(&refusal, Refusal::Path, head);
            return None;
        }
        let Some(held) = Slot::take(live, connection_cap(gateway)) else {
            refuse_head(&refusal, Refusal::Busy, head);
            return None;
        };
        slot.set(Some(held));
        matched.set(Some(caller));
        until.set(started + READ_DEADLINE);
        if ladder {
            limit.set(0);
        }
        Some(limit.get())
    };
    let read = read_until(&stream, &until, &check);
    drop(unchecked.take());
    let _slot = slot.take();
    let refused = match (read, refusal.get()) {
        (Ok(req), _) => {
            let caller = matched
                .take()
                .expect("`check` admits a head with its caller");
            if req.path == paths::MODEL_LADDER {
                return loopback_ladder(&mut stream, gateway, &caller, &req);
            }
            return front_turn(stream, gateway, watch, &caller, req);
        }
        (Err(ReadError::Refused { .. }), Some(refusal)) => refusal,
        (Err(e), _) => return unreadable(&mut stream, &e, limit.get(), dialect.get()),
    };
    let served = "this listener serves only `POST /v1/messages`, `POST /v1/chat/completions`, \
                  `POST /v1/responses` and `GET /v1/model/ladder`";
    match (refused, dialect.get()) {
        (Refusal::Token, Dialect::C4) => reject(
            &mut stream,
            401,
            ErrorClass::Auth,
            "not a client token of this gateway",
        ),
        (Refusal::Token, Dialect::Openai) => openai::refuse(
            &mut stream,
            401,
            "invalid_request_error",
            "invalid_api_key",
            "invalid API key: not a client token of this gateway",
        ),
        (Refusal::Token, _) => messages::refuse(
            &mut stream,
            401,
            "authentication_error",
            "invalid x-api-key: not a client token of this gateway",
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
        (Refusal::Busy, dialect) => dialect.reject(&mut stream, 429, &too_many()),
    }
}

/// Reads one request under [`READ_DEADLINE`] with a body of at most `max_body(head)` bytes.
fn read(
    stream: &Conn,
    max_body: &dyn Fn(&Head<'_>) -> Option<usize>,
) -> Result<http::Request, ReadError> {
    read_until(stream, &Cell::new(Instant::now() + READ_DEADLINE), max_body)
}

/// [`read`] by the time `until` holds, which `max_body` may move.
fn read_until(
    stream: &Conn,
    until: &Cell<Instant>,
    max_body: &dyn Fn(&Head<'_>) -> Option<usize>,
) -> Result<http::Request, ReadError> {
    // Sized so it never reallocates: the head's buffer holds the start of a body that may carry
    // a credential.
    let mut buf = Zeroizing::new(Vec::with_capacity(http::MAX_HEAD + http::READ_CHUNK));
    let mut reader = Deadline { stream, until };
    http::read_request_limited(&mut reader, &mut buf, max_body)
}

/// Answers a request that could not be read, its body limit `limit`, in the error format
/// `dialect`; a closed connection or a refused head gets no answer here.
fn unreadable(stream: &mut Conn, e: &ReadError, limit: usize, dialect: Dialect) {
    let Some((status, message)) = unread(e, limit) else {
        return;
    };
    if let ReadError::BodyTooLarge { unread } = *e {
        discard(&*stream, unread);
    }
    let e = GatewayError::new(ErrorClass::BadRequest, false, message);
    dialect.reject(stream, status, &e);
}

/// The status and message of the answer to a request that could not be read, its body limit
/// `limit`; `None` for a closed connection or a refused head, which get no answer.
fn unread(e: &ReadError, limit: usize) -> Option<(u16, String)> {
    Some(match *e {
        ReadError::Closed | ReadError::Io(_) | ReadError::Refused { .. } => return None,
        ReadError::Malformed => (400, "malformed HTTP request".into()),
        ReadError::HeadTooLarge => (413, "request head too large".into()),
        ReadError::BodyTooLarge { .. } => (413, format!("request body over {limit} bytes")),
        ReadError::LengthRequired => (411, "Content-Length required".into()),
    })
}

fn turn(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &str,
    body: Zeroizing<Vec<u8>>,
) {
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
