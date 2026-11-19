//! How the HTTP fronts (`/v1/messages`, `/v1/chat/completions`, `/v1/responses`) answer an
//! admitted turn: SSE through a [`Keepalive`] for `stream: true`, else one JSON body. An error
//! before the first event is an HTTP error in the front's format; closing the connection cancels
//! the turn. A started stream silent for `fronts.ping_interval_s` gets the format's keep-alive
//! from the main thread.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use qb_proto::{ErrorClass, GatewayError, StreamEvent, TurnRequest};
use rustix::net::SendFlags;
use serde::Serialize;

use super::core::{Admitted, Gateway};
use super::front::{Caller, Conn, STREAM_WRITE_TIMEOUT, Watch};
use super::upstream::Flow;
use crate::http;
use crate::log;

/// Content type of a streamed answer.
pub const SSE: &str = "text/event-stream";

/// Numbers the fronts' turns, so ids stay unique within a second.
static NEXT: AtomicU64 = AtomicU64::new(0);

/// An id unique to this gateway process at `now`: hex seconds and a counter.
pub(super) fn next_id(now: u64) -> String {
    format!("{now:x}_{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Writes a canonical error as an HTTP error answer in a front's format; `Some` status replaces
/// the status of the error's class.
pub(super) type Reject = fn(&mut Conn, Option<u16>, &GatewayError);

/// Writes a 403 answer with `message` in a front's format.
pub(super) type Forbid = fn(&mut Conn, &str);

/// A front's SSE encoder of canonical events.
pub(super) trait Encoder {
    /// Whether any byte went out.
    fn started(&self) -> bool;
    /// The bytes of one event; empty when it writes none.
    fn push(&mut self, event: &StreamEvent) -> Vec<u8>;
}

/// A front's assembler of canonical events into one answer body.
pub(super) trait Assembler {
    /// The answer body.
    type Body: Serialize;
    /// Adds one event.
    fn push(&mut self, event: &StreamEvent);
    /// The body once the turn ended, or the error the turn ended with.
    fn finish(self) -> Result<Self::Body, GatewayError>;
}

macro_rules! encoders {
    ($($t:ty),*) => {$(
        impl Encoder for $t {
            fn started(&self) -> bool {
                <$t>::started(self)
            }
            fn push(&mut self, event: &StreamEvent) -> Vec<u8> {
                <$t>::push(self, event)
            }
        }
    )*};
}

macro_rules! assemblers {
    ($($t:ty => $body:ty),*) => {$(
        impl Assembler for $t {
            type Body = $body;
            fn push(&mut self, event: &StreamEvent) {
                <$t>::push(self, event);
            }
            fn finish(self) -> Result<$body, GatewayError> {
                <$t>::finish(self)
            }
        }
    )*};
}

encoders!(
    qb_anthropic::front::SseEncoder,
    qb_openai::chat::SseEncoder,
    qb_openai::responses::SseEncoder
);
assemblers!(
    qb_anthropic::front::Assembler => qb_anthropic::wire::MessageResponse,
    qb_openai::chat::Assembler => qb_openai::wire::ChatResponse,
    qb_openai::responses::Assembler => qb_openai::wire::ResponseObject
);

/// How a front answers a turn: as SSE with this encoder, or as one body of this assembler.
pub(super) enum Answer<E, A> {
    Stream(E),
    Body(A),
}

/// What a front's answers look like besides the encoder and assembler.
pub(super) struct Format {
    /// Its error answer.
    pub reject: Reject,
    /// Its answer to a caller outside its routes.
    pub forbid: Forbid,
    /// Its SSE keep-alive.
    pub ping: Vec<u8>,
    /// Silence in a started stream before a keep-alive.
    pub ping_interval: Duration,
}

/// Runs `turn` of `caller` through `gateway` and answers it on `stream` as `answer` says;
/// `watch` cancels the turn when the client hangs up and pings its silent stream. A route the
/// caller may not run is refused before admission.
pub(super) fn serve<E: Encoder, A: Assembler>(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &Caller,
    turn: &TurnRequest,
    answer: Answer<E, A>,
    format: Format,
) {
    if !caller.may_run(&turn.route) {
        let message = format!(
            "client `{}` may not use route `{}`",
            caller.name, turn.route
        );
        return (format.forbid)(&mut stream, &message);
    }
    let admitted = match gateway.admit(&caller.name, turn) {
        Ok(a) => a,
        Err(e) => return (format.reject)(&mut stream, None, &e),
    };
    // A body answer never writes through it, so it never pings.
    let keepalive = Arc::new(Keepalive::new(format.ping_interval, format.ping));
    let cancel = admitted.cancel_token().clone();
    let _watching = match watch.add(&stream, cancel, Some(Arc::clone(&keepalive))) {
        Ok(w) => w,
        Err(e) => {
            let message = format!("cannot watch the connection: {e}");
            let e = GatewayError::new(ErrorClass::Unavailable, true, message);
            return (format.reject)(&mut stream, None, &e);
        }
    };
    if stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .is_err()
    {
        return;
    }
    let run = Run {
        gateway,
        admitted: &admitted,
        turn,
    };
    match answer {
        Answer::Stream(encoder) => {
            stream_answer(&mut stream, &run, encoder, format.reject, watch, &keepalive);
        }
        Answer::Body(assembler) => body_answer(&mut stream, &run, assembler, format.reject),
    }
}

/// An admitted turn ready to run.
struct Run<'a> {
    gateway: &'a Gateway,
    admitted: &'a Admitted,
    turn: &'a TurnRequest,
}

impl Run<'_> {
    fn run(&self, emit: &mut dyn FnMut(StreamEvent) -> Flow) {
        self.gateway.run(self.admitted, self.turn, emit);
    }
}

/// Writes the turn as SSE through `keepalive`, one chunk per canonical event; an error before the
/// first byte is an HTTP error answer instead. The first write wakes `watch`, whose main thread
/// schedules the pings from then on.
fn stream_answer(
    stream: &mut Conn,
    run: &Run<'_>,
    mut encoder: impl Encoder,
    reject: Reject,
    watch: &Watch,
    keepalive: &Keepalive,
) {
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
    run.run(&mut emit);
    if let Some(error) = early {
        reject(stream, None, &error);
    } else if encoder.started() {
        let _ = keepalive.end(stream);
    }
}

/// Assembles the turn into one body; a failed turn is an HTTP error answer.
fn body_answer(stream: &mut Conn, run: &Run<'_>, mut assembler: impl Assembler, reject: Reject) {
    run.run(&mut |event| {
        assembler.push(&event);
        Flow::Continue
    });
    match assembler.finish() {
        Ok(answer) => {
            let body = serde_json::to_vec(&answer).unwrap_or_default();
            if let Err(e) = http::write_response(stream, 200, &body) {
                log::warn(&format!("gateway: write of a front's answer failed: {e}"));
            }
        }
        Err(e) => reject(stream, None, &e),
    }
}

/// `last` before the stream's first write.
const NOT_STARTED: u64 = u64::MAX;

/// The writes of one SSE answer: the connection thread writes its events through it, and the
/// main thread writes a keep-alive once the started stream was silent for `interval`.
pub(super) struct Keepalive {
    interval: Duration,
    ping: Vec<u8>,
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
    /// Pings with the SSE bytes `ping` after `interval` of silence.
    pub(super) fn new(interval: Duration, ping: Vec<u8>) -> Self {
        Self {
            interval,
            ping,
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
            let _ = http::write_chunk(&mut out.owed, &self.ping);
        }
        let flags = SendFlags::DONTWAIT | SendFlags::NOSIGNAL;
        if let Ok(sent) = rustix::net::send(stream, &out.owed, flags) {
            out.owed.drain(..sent);
        }
    }
}
