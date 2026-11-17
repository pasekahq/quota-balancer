//! The C4 front: `/v1/model/turn`, `/v1/model/routes`, `/v1/model/cancel` and `/v1/health` over
//! the gateway's unix socket. One thread per connection, at most `max_turns` +
//! [`EXTRA_CONNECTIONS`] at once; every rejection is a non-200 [`GatewayError`], every admitted
//! turn a `200` with a chunked NDJSON stream whose head goes out with its first event.

use std::convert::Infallible;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use qb_proto::{
    API_VERSION, CancelAnswer, CancelRequest, ErrorClass, GatewayError, HealthResponse,
    HealthStatus, StreamEvent, TurnRequest, paths,
};
use serde::Serialize;

use super::core::{Cancel, Gateway};
use super::upstream::Flow;
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

/// Content type of the turn stream.
pub const NDJSON: &str = "application/x-ndjson";

/// Serves `gateway` on `listener`. The main thread only accepts; each connection runs on its
/// own thread.
///
/// # Errors
/// Never in practice; the type leaves room for a fatal listener error.
pub fn serve(listener: &UnixListener, gateway: &Arc<Gateway>) -> io::Result<Infallible> {
    let cap = gateway.config().max_turns as usize + EXTRA_CONNECTIONS;
    let own_uid = rustix::process::geteuid().as_raw();
    let started = Instant::now();
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
            reject(
                &mut stream,
                429,
                ErrorClass::Overloaded,
                "too many connections",
            );
            continue;
        }
        live.fetch_add(1, Ordering::SeqCst);
        let (gateway, done) = (Arc::clone(gateway), Arc::clone(&live));
        let spawned = std::thread::Builder::new()
            .name("qb-gateway".into())
            .stack_size(STACK_BYTES)
            .spawn(move || {
                handle(stream, &gateway, own_uid, started);
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

fn handle(mut stream: UnixStream, gateway: &Gateway, own_uid: u32, started: Instant) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let uid = rustix::net::sockopt::socket_peercred(&stream)
        .ok()
        .map(|c| c.uid.as_raw());
    let max_body = gateway.config().max_request_bytes as usize;
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
    let Some(caller) = caller(gateway, uid, own_uid) else {
        return reject(
            &mut stream,
            401,
            ErrorClass::Auth,
            "caller is not an allowed client",
        );
    };
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::MODEL_TURN) => turn(stream, gateway, &caller, req.body),
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
