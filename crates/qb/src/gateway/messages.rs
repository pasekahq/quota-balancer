//! The Messages front: `POST /v1/messages` on the gateway's unix socket. A request decodes with
//! `qb_anthropic::front` and runs through the core like a C4 turn; the answer is Messages SSE for
//! `stream: true`, else one Messages body. An error before the first event is an HTTP error in
//! the Messages format; closing the connection cancels the turn.

use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};

use qb_anthropic::front::{Assembler, FrontRequest, SseEncoder, decode_request, error_response};
use qb_proto::{ErrorClass, GatewayError, StreamEvent};

use super::core::{Admitted, Gateway};
use super::front::{STREAM_WRITE_TIMEOUT, Watch};
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
pub(super) fn reject(stream: &mut UnixStream, status: Option<u16>, error: &GatewayError) {
    drain_pending(stream);
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
    let body = serde_json::to_vec(&answer.body).unwrap_or_default();
    if let Err(e) = http::write_response_with(stream, answer.status, &headers, &body) {
        log::warn(&format!(
            "gateway: write of a {} Messages reply failed: {e}",
            answer.status
        ));
    }
}

/// Serves one `POST /v1/messages` of `caller` with the request body `body`.
pub(super) fn turn(
    mut stream: UnixStream,
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
    let _watching = match watch.add(&stream, admitted.cancel_token().clone()) {
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
    if req.stream {
        stream_answer(&mut stream, gateway, &admitted, &req, &front.vendor);
    } else {
        body_answer(&mut stream, gateway, &admitted, &req, &front.vendor);
    }
}

/// Writes the turn as Messages SSE, one chunk per canonical event; an error before the first
/// byte is an HTTP error answer instead.
fn stream_answer(
    stream: &mut UnixStream,
    gateway: &Gateway,
    admitted: &Admitted,
    req: &FrontRequest,
    vendor: &str,
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
        let head = if first {
            http::write_stream_head(stream, SSE)
        } else {
            Ok(())
        };
        match head.and_then(|()| http::write_chunk(stream, &bytes)) {
            Ok(()) => Flow::Continue,
            Err(_) => Flow::Stop,
        }
    };
    gateway.run(admitted, &req.turn, &mut emit);
    if let Some(error) = early {
        reject(stream, None, &error);
    } else if encoder.started() {
        let _ = http::write_stream_end(stream);
    }
}

/// Assembles the turn into one Messages body; a failed turn is an HTTP error answer.
fn body_answer(
    stream: &mut UnixStream,
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
