//! The C4 front: `/v1/model/turn`, `/v1/model/routes` and `/v1/model/cancel` over the gateway's
//! unix socket. One thread per connection, at most `max_turns` + [`EXTRA_CONNECTIONS`] at once;
//! a turn answers `200` with a chunked NDJSON stream, every rejection a non-200 [`GatewayError`].

use std::convert::Infallible;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    CancelAnswer, CancelRequest, ErrorClass, GatewayError, StreamEvent, TurnRequest, paths,
};
use serde::Serialize;

use super::config::GatewayClient;
use super::core::Gateway;
use super::upstream::Flow;
use crate::auth::{Denied, Gate};
use crate::config::{Client, Limits};
use crate::http::{self, Method, ReadError};
use crate::log;
use crate::server::{IO_TIMEOUT, discard, drain_pending};

/// Connections beyond `max_turns` served at once, for cancels and route queries.
pub const EXTRA_CONNECTIONS: usize = 8;

/// How long writing one event to a slow client may take before the turn is cut.
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Content type of the turn stream.
pub const NDJSON: &str = "application/x-ndjson";

/// Serves `gateway` on `listener` until accepting fails for good.
///
/// # Errors
/// Never in practice; the type leaves room for a fatal listener error.
pub fn serve(listener: &UnixListener, gateway: &Arc<Gateway>) -> io::Result<Infallible> {
    let config = gateway.config();
    let clients: Vec<Client> = config
        .clients
        .iter()
        .map(GatewayClient::as_client)
        .collect();
    let limits = Limits {
        rate_per_s: config.rate_per_s,
        burst: config.burst,
    };
    let gate = Arc::new(Mutex::new(Gate::new(&clients, &limits)));
    let cap = config.max_turns as usize + EXTRA_CONNECTIONS;
    let live = Arc::new(AtomicUsize::new(0));
    loop {
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
            let mut e = GatewayError::new(ErrorClass::Overloaded, true, "too many connections");
            e.retry_after = Some(1);
            reply(&mut stream, e.class.http_status(), &e);
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (gateway, gate, done) = (Arc::clone(gateway), Arc::clone(&gate), Arc::clone(&live));
        let spawned = std::thread::Builder::new()
            .name("qb-gateway".into())
            .spawn(move || {
                handle(stream, &gateway, &gate);
                done.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            live.fetch_sub(1, Ordering::SeqCst);
            log::warn(&format!("gateway: cannot start a connection thread: {e}"));
        }
    }
}

/// The peer's uid from `SO_PEERCRED`.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|c| c.uid.as_raw())
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

fn handle(mut stream: UnixStream, gateway: &Gateway, gate: &Mutex<Gate>) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let uid = peer_uid(&stream);
    let max_body = gateway.config().max_body_bytes as usize;
    let mut buf = Vec::new();
    let req = match http::read_request_limited(&mut stream, &mut buf, max_body) {
        Ok(r) => r,
        Err(ReadError::Closed | ReadError::Io(_)) => return,
        Err(ReadError::Malformed) => {
            return reject(
                &mut stream,
                400,
                ErrorClass::BadRequest,
                "malformed HTTP request",
            );
        }
        Err(ReadError::HeadTooLarge) => {
            return reject(
                &mut stream,
                413,
                ErrorClass::BadRequest,
                "request head too large",
            );
        }
        Err(ReadError::BodyTooLarge { unread }) => {
            discard(&mut stream, unread);
            let message = format!("request body over {max_body} bytes");
            return reject(&mut stream, 413, ErrorClass::BadRequest, &message);
        }
        Err(ReadError::LengthRequired) => {
            return reject(
                &mut stream,
                411,
                ErrorClass::BadRequest,
                "Content-Length required",
            );
        }
    };
    drop(buf);
    let admitted = gate.lock().unwrap_or_else(PoisonError::into_inner).admit(
        uid,
        req.bearer.as_deref(),
        Instant::now(),
    );
    let caller = match admitted {
        Ok(c) => c.client,
        Err(Denied::Unauthorized) => {
            return reject(
                &mut stream,
                401,
                ErrorClass::Auth,
                "caller is not an allowed client",
            );
        }
        Err(Denied::TooManyRequests) => {
            return reject(
                &mut stream,
                429,
                ErrorClass::Overloaded,
                "rate limit exceeded",
            );
        }
    };
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::MODEL_TURN) => turn(stream, gateway, &caller, req.body),
        (Method::Get, paths::MODEL_ROUTES) => reply(&mut stream, 200, &gateway.routes()),
        (Method::Post, paths::MODEL_CANCEL) => {
            match serde_json::from_slice::<CancelRequest>(&req.body) {
                Ok(c) => {
                    let cancelled = gateway.cancel(&caller, &c.request_id);
                    reply(&mut stream, 200, &CancelAnswer { cancelled });
                }
                Err(e) => reject(&mut stream, 400, ErrorClass::BadRequest, &e.to_string()),
            }
        }
        (_, paths::MODEL_TURN | paths::MODEL_ROUTES | paths::MODEL_CANCEL) => {
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

fn turn(mut stream: UnixStream, gateway: &Gateway, caller: &str, body: Vec<u8>) {
    let req: TurnRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, 400, ErrorClass::BadRequest, &e.to_string()),
    };
    drop(body);
    let admitted = match gateway.admit(caller, &req) {
        Ok(a) => a,
        Err(e) => return reply(&mut stream, e.class.http_status(), &e),
    };
    if stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .is_err()
        || http::write_stream_head(&mut stream, NDJSON).is_err()
    {
        return;
    }
    let mut emit = |event: StreamEvent| {
        let Ok(mut line) = serde_json::to_vec(&event) else {
            return Flow::Stop;
        };
        line.push(b'\n');
        match http::write_chunk(&mut stream, &line) {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Stop,
        }
    };
    gateway.run(&admitted, &req, &mut emit);
    let _ = http::write_stream_end(&mut stream);
}
