//! The Messages front: `POST /v1/messages` on the gateway's unix socket and its optional loopback
//! listener. A request decodes with `qb_anthropic::front` and runs through the core like a C4
//! turn, answered by [`super::answer`] as Messages SSE or one Messages body; errors are in the
//! Messages format.

use std::time::Duration;

use qb_anthropic::front::{Assembler, SseEncoder, decode_request, error_response};
use qb_anthropic::wire::ErrorBody;
use qb_proto::{ErrorClass, GatewayError};

use super::answer::{self, Answer, Format};
use super::core::Gateway;
use super::front::{Conn, Watch};
use crate::http;
use crate::log;
use crate::server::{drain_pending, unix_now};

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

/// Serves one `POST /v1/messages` of `caller` with the request body `body`.
pub(super) fn turn(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &str,
    body: Vec<u8>,
) {
    let config = gateway.config();
    let Some((fronts, front)) = config
        .fronts
        .as_ref()
        .and_then(|f| Some((f, f.messages.as_ref()?)))
    else {
        let message =
            "this gateway serves no `/v1/messages`: its config has no `[fronts.messages]`";
        let e = GatewayError::new(ErrorClass::BadRequest, false, message);
        return reject(&mut stream, Some(404), &e);
    };
    let id = format!("msg_{}", answer::next_id(unix_now()));
    let route_of = |model: &str| config.route_of_model(model).map(|r| r.alias.clone());
    let req = match decode_request(&body, &id, &front.vendor, &route_of) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, None, &e),
    };
    drop(body);
    let answer = if req.stream {
        Answer::Stream(SseEncoder::new(&id, &req.model, &front.vendor))
    } else {
        Answer::Body(Assembler::new(&id, &req.model, &front.vendor))
    };
    let format = Format {
        reject,
        ping: SseEncoder::ping(),
        ping_interval: Duration::from_secs(fronts.ping_interval_s.into()),
    };
    answer::serve(stream, gateway, watch, caller, &req.turn, answer, format);
}
