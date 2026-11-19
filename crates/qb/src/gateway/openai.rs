//! The OpenAI fronts: `POST /v1/chat/completions` and `POST /v1/responses` on the gateway's unix
//! socket and its optional loopback listener. A request decodes with `qb_openai::chat` or
//! `qb_openai::responses` and runs through the core like a C4 turn, answered by
//! [`super::answer`] as SSE of that API or one body; errors are in the OpenAI format.

use std::time::Duration;

use qb_openai::front::error_response;
use qb_openai::wire::ErrorBody;
use qb_openai::{chat, responses};
use qb_proto::{ErrorClass, GatewayError};

use super::answer::{self, Answer, Format};
use super::config::{Fronts, OpenaiFront};
use super::core::Gateway;
use super::front::{Caller, Conn, Watch};
use crate::http;
use crate::log;
use crate::server::{drain_pending, unix_now};

/// Answers `error` in the OpenAI error format with its `retry-after` and `x-should-retry`;
/// `status` replaces the status of the error's class.
pub(super) fn reject(stream: &mut Conn, status: Option<u16>, error: &GatewayError) {
    let mut answer = error_response(error, unix_now());
    if let Some(status) = status {
        answer.status = status;
    }
    let headers = answer.headers();
    let headers: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
    write_error(stream, answer.status, &headers, &answer.body);
}

/// Answers `status` with an OpenAI error of `kind` and `code`, for a refusal no error class names.
pub(super) fn refuse(stream: &mut Conn, status: u16, kind: &str, code: &str, message: &str) {
    write_error(
        stream,
        status,
        &[],
        &ErrorBody::new(kind, Some(code), message),
    );
}

/// Answers 403 with an OpenAI `permission_error` of code `route_not_allowed` saying `message`.
fn forbid(stream: &mut Conn, message: &str) {
    refuse(
        stream,
        403,
        "permission_error",
        "route_not_allowed",
        message,
    );
}

fn write_error(stream: &mut Conn, status: u16, headers: &[(&str, &str)], body: &ErrorBody) {
    drain_pending(&*stream);
    let body = serde_json::to_vec(body).unwrap_or_default();
    if let Err(e) = http::write_response_with(stream, status, headers, &body) {
        log::warn(&format!(
            "gateway: write of a {status} OpenAI reply failed: {e}"
        ));
    }
}

/// The fronts' settings and those of the OpenAI fronts; a 404 answer when the config has none.
fn settings<'c>(
    stream: &mut Conn,
    fronts: Option<&'c Fronts>,
    path: &str,
) -> Option<(&'c Fronts, &'c OpenaiFront)> {
    let found = fronts.and_then(|f| Some((f, f.openai.as_ref()?)));
    if found.is_none() {
        let message =
            format!("this gateway serves no `{path}`: its config has no `[fronts.openai]`");
        let e = GatewayError::new(ErrorClass::BadRequest, false, message);
        reject(stream, Some(404), &e);
    }
    found
}

fn format(fronts: &Fronts) -> Format {
    Format {
        reject,
        forbid,
        ping: chat::SseEncoder::ping(),
        ping_interval: Duration::from_secs(fronts.ping_interval_s.into()),
    }
}

/// Serves one `POST /v1/chat/completions` of `caller` with the request body `body`.
pub(super) fn chat_turn(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &Caller,
    body: Vec<u8>,
) {
    let config = gateway.config();
    let path = qb_proto::paths::CHAT_COMPLETIONS;
    let Some((fronts, front)) = settings(&mut stream, config.fronts.as_ref(), path) else {
        return;
    };
    let now = unix_now();
    let id = answer::next_id(now);
    let route_of = |model: &str| config.route_of_model(model).map(|r| r.alias.clone());
    let request_id = format!("chatcmpl-{id}");
    let req = match chat::decode_request(&body, &request_id, &route_of, front.max_tokens) {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, None, &e),
    };
    drop(body);
    let answer = if req.stream {
        Answer::Stream(chat::SseEncoder::new(
            &id,
            &req.model,
            now,
            req.include_usage,
        ))
    } else {
        Answer::Body(chat::Assembler::new(&id, &req.model, now))
    };
    answer::serve(
        stream,
        gateway,
        watch,
        caller,
        &req.turn,
        answer,
        format(fronts),
    );
}

/// Serves one `POST /v1/responses` of `caller` with the request body `body`.
pub(super) fn responses_turn(
    mut stream: Conn,
    gateway: &Gateway,
    watch: &Watch,
    caller: &Caller,
    body: Vec<u8>,
) {
    let config = gateway.config();
    let path = qb_proto::paths::RESPONSES;
    let Some((fronts, front)) = settings(&mut stream, config.fronts.as_ref(), path) else {
        return;
    };
    let now = unix_now();
    let id = answer::next_id(now);
    let route_of = |model: &str| config.route_of_model(model).map(|r| r.alias.clone());
    let request_id = format!("resp_{id}");
    let decoded = responses::decode_request(
        &body,
        &request_id,
        &front.vendor,
        &route_of,
        front.max_tokens,
    );
    let req = match decoded {
        Ok(r) => r,
        Err(e) => return reject(&mut stream, None, &e),
    };
    drop(body);
    let vendor = &front.vendor;
    let answer = if req.stream {
        Answer::Stream(
            responses::SseEncoder::new(&id, &req.model, now, vendor).tools(&req.turn.tools),
        )
    } else {
        Answer::Body(responses::Assembler::new(&id, &req.model, now, vendor).tools(&req.turn.tools))
    };
    answer::serve(
        stream,
        gateway,
        watch,
        caller,
        &req.turn,
        answer,
        format(fronts),
    );
}
