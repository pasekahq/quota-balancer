//! The Messages front: `POST /v1/messages` on the gateway's unix socket and its optional loopback
//! listener. A request decodes with `qb_anthropic::front` and runs through the core like a C4
//! turn; the answer is Messages SSE for `stream: true`, else one Messages body. An error before
//! the first event is an HTTP error in the Messages format; closing the connection cancels the
//! turn. A started stream silent for `ping_interval_s` gets an SSE `ping` from the main thread.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use qb_anthropic::front::{Assembler, FrontRequest, SseEncoder, decode_request, error_response};
use qb_anthropic::wire::ErrorBody;
use qb_proto::{ErrorClass, GatewayError, StreamEvent};
use rustix::net::SendFlags;

use super::core::{Admitted, Gateway};
use super::front::{Conn, STREAM_WRITE_TIMEOUT, Watch};
use super::upstream::Flow;
use crate::http;
use crate::log;
use crate::server::{drain_pending, unix_now};

/// Content type of a streamed answer.
pub const SSE: &str = "text/event-stream";

/// Numbers the front's turns, so ids stay unique within a second.
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Answers `error` in the Messages error format with its `retry-after` and `x-should-retry`;
/// `status` replaces the status of the error's class.
pub(super) fn reject(stream: &mut Conn, status: Option<u16>, error: &GatewayError) {
    let mut answer = error_response(error, unix_now());
    if let Some(status) = status {
        answer.status = status;
    }
    let retry_after = answer.retry_after.map(|s| s.to_string());
    let mut headers = Vec::with_capacity(2);
    if let Some(seconds) = &retry_after {
        headers.push(("retry-after", seconds.as_str()));
    }
    if let Some(retry) = answer.should_retry {
        headers.push(("x-should-retry", if retry { "true" } else { "false" }));
    }
    write_error(stream, answer.status, &headers, &answer.body);
}

/// Answers `status` with a Messages error of type `kind`, for a refusal no error class names.
pub(super) fn refuse(stream: &mut Conn, status: u16, kind: &str, message: &str) {
    write_error(stream, status, &[], &ErrorBody::new(kind, message));
}

fn write_error(stream: &mut Conn, status: u16, headers: &[(&str, &str)], body: &ErrorBody) {
    drain_pending(&*stream);
    let body = serde_json::to_vec(body).unwrap_or_default();
    if let Err(e) = http::write_response_with(stream, status, headers, &body) {
        log::warn(&format!(
            "gateway: write of a {status} Messages reply failed: {e}"
        ));
    }
}

/// `last` before the stream's first write.
const NOT_STARTED: u64 = u64::MAX;

/// The writes of one Messages stream: the connection thread writes its events through it, and
/// the main thread writes a `ping` once the started stream was silent for `interval`.
pub(super) struct Keepalive {
    interval: Duration,
    epoch: Instant,
    /// Milliseconds after `epoch` of the last write or ping attempt, [`NOT_STARTED`] before the
    /// first write.
    last: AtomicU64,
    out: Mutex<Out>,
}

/// What the writers of one stream share.
#[derive(Default)]
struct Out {
    /// The body ended; nothing may follow.
    ended: bool,
    /// Bytes of a ping the socket did not take at once; they go out before anything else.
    owed: Vec<u8>,
}

impl Keepalive {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            interval,
            epoch: Instant::now(),
            last: AtomicU64::new(NOT_STARTED),
            out: Mutex::default(),
        }
    }

    fn mark(&self, at: Instant) {
        let ms = at.saturating_duration_since(self.epoch).as_millis();
        self.last
            .store(u64::try_from(ms).unwrap_or(u64::MAX - 1), Ordering::Relaxed);
    }

    /// When the next ping is due; `None` before the first write.
    pub(super) fn due(&self) -> Option<Instant> {
        let last = self.last.load(Ordering::Relaxed);
        (last != NOT_STARTED).then(|| self.epoch + Duration::from_millis(last) + self.interval)
    }

    fn lock(&self) -> MutexGuard<'_, Out> {
        self.out.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `write` on `stream` after any owed ping bytes, and starts or restarts the silence.
    fn write(
        &self,
        stream: &mut Conn,
        write: impl FnOnce(&mut Conn) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut out = self.lock();
        if !out.owed.is_empty() {
            stream.write_all(&out.owed)?;
            out.owed.clear();
        }
        write(stream)?;
        self.mark(Instant::now());
        Ok(())
    }

    /// Ends the chunked body; no ping follows.
    fn end(&self, stream: &mut Conn) -> io::Result<()> {
        let mut out = self.lock();
        out.ended = true;
        stream.write_all(&out.owed)?;
        http::write_stream_end(stream)
    }

    /// Sends a ping to `stream` without blocking when one is due at `now` and the connection
    /// thread is not writing; what the socket does not take is owed.
    pub(super) fn tick(&self, stream: &Conn, now: Instant) {
        if self.due().is_none_or(|due| due > now) {
            return;
        }
        // Marked first, so a busy writer or a full socket waits for the next interval.
        self.mark(now);
        let mut out = match self.out.try_lock() {
            Ok(out) => out,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        if out.ended {
            return;
        }
        if out.owed.is_empty() {
            let _ = http::write_chunk(&mut out.owed, &SseEncoder::ping());
        }
        let flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if let Ok(sent) = rustix::net::send(stream, &out.owed, flags) {
            out.owed.drain(..sent);
        }
    }
}

/// Serves one `POST /v1/messages` of `caller` with the request body `body`.
pub(super) fn turn(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &str,
    body: Vec<u8>,
) {
    let config = gateway.config();
    let Some(front) = &config.messages else {
        let message = "this gateway serves no `/v1/messages`: its config has no `[messages]`";
        let e = GatewayError::new(ErrorClass::BadRequest, false, message);
        return reject(&mut stream, Some(404), &e);
    };
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let id = format!("msg_{:x}_{n}", unix_now());
    let route_of = |model: &str| config.route_of_model(model).map(|r| r.alias.clone());
    let req = match decode_request(&body, &id, &front.vendor, &route_of) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, None, &e),
    };
    drop(body);
    let admitted = match gateway.admit(caller, &req.turn) {
        Ok(a) => a,
        Err(e) => return reject(&mut stream, None, &e),
    };
    let keepalive = req.stream.then(|| {
        let interval = Duration::from_secs(front.ping_interval_s.into());
        Arc::new(Keepalive::new(interval))
    });
    let _watching = match watch.add(&stream, admitted.cancel_token().clone(), keepalive.clone()) {
        Ok(w) => w,
        Err(e) => {
            let message = format!("cannot watch the connection: {e}");
            let e = GatewayError::new(ErrorClass::Unavailable, true, message);
            return reject(&mut stream, None, &e);
        }
    };
    if stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .is_err()
    {
        return;
    }
    match &keepalive {
        Some(k) => stream_answer(
            &mut stream,
            gateway,
            &admitted,
            &req,
            &front.vendor,
            watch,
            k,
        ),
        None => body_answer(&mut stream, gateway, &admitted, &req, &front.vendor),
    }
}

/// Writes the turn as Messages SSE through `keepalive`, one chunk per canonical event; an error
/// before the first byte is an HTTP error answer instead. The first write wakes `watch`, whose
/// main thread schedules the pings from then on.
fn stream_answer(
    stream: &mut Conn,
    gateway: &Gateway,
    admitted: &Admitted,
    req: &FrontRequest,
    vendor: &str,
    watch: &Watch,
    keepalive: &Keepalive,
) {
    let mut encoder = SseEncoder::new(&req.turn.request_id, &req.model, vendor);
    let mut early = None;
    let mut emit = |event: StreamEvent| {
        let first = !encoder.started();
        if let (true, StreamEvent::Error { error }) = (first, &event) {
            early = Some(error.clone());
            return Flow::Stop;
        }
        let bytes = encoder.push(&event);
        if bytes.is_empty() {
            return Flow::Continue;
        }
        let sent = keepalive.write(stream, |s| {
            if first {
                http::write_stream_head(s, SSE)?;
            }
            http::write_chunk(s, &bytes)
        });
        if first && sent.is_ok() {
            watch.ring();
        }
        match sent {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Stop,
        }
    };
    gateway.run(admitted, &req.turn, &mut emit);
    if let Some(error) = early {
        reject(stream, None, &error);
    } else if encoder.started() {
        let _ = keepalive.end(stream);
    }
}

/// Assembles the turn into one Messages body; a failed turn is an HTTP error answer.
fn body_answer(
    stream: &mut Conn,
    gateway: &Gateway,
    admitted: &Admitted,
    req: &FrontRequest,
    vendor: &str,
) {
    let mut assembler = Assembler::new(&req.turn.request_id, &req.model, vendor);
    gateway.run(admitted, &req.turn, &mut |event| {
        assembler.push(&event);
        Flow::Continue
    });
    match assembler.finish() {
        Ok(message) => {
            let body = serde_json::to_vec(&message).unwrap_or_default();
            if let Err(e) = http::write_response(stream, 200, &body) {
                log::warn(&format!("gateway: write of a Messages answer failed: {e}"));
            }
        }
        Err(e) => reject(stream, None, &e),
    }
}
