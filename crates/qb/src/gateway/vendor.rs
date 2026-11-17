//! What the vendor adapters share: one ureq agent with rustls per attempt, which the turn's
//! cancel hook shuts down so a blocked connect, write or read returns at once; the secret header
//! built in a zeroizing string; the bounded error body; the read loop that feeds a stream parser
//! and hands its events to the sink.

use std::io::{self, Read};
use std::time::Duration;

use qb_proto::{StopReason, StreamEvent};
use zeroize::Zeroizing;

use super::upstream::{CancelToken, Failure, FailureKind, Flow, Sink};

/// Bound of the TCP connect of an attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound of one attempt, from connect to the end of the stream.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(600);

/// Largest error body read for its message.
const MAX_ERROR_BODY: u64 = 64 << 10;

/// Size of one read of the stream.
const READ_BYTES: usize = 16 << 10;

/// The ureq config of an attempt: [`CONNECT_TIMEOUT`], [`ATTEMPT_TIMEOUT`], no proxy, no
/// redirects, and every status as an answer.
pub fn attempt_config() -> ureq::config::Config {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_global(Some(ATTEMPT_TIMEOUT))
        .build()
}

fn cancelled() -> Failure {
    Failure::new(FailureKind::Cancelled, "cancelled")
}

/// A transport failure, or the cancel that caused it.
fn broken(cancel: &CancelToken, what: &str, e: &dyn std::fmt::Display) -> Failure {
    if cancel.is_cancelled() {
        cancelled()
    } else {
        Failure::new(FailureKind::Unavailable, format!("{what}: {e}"))
    }
}

/// One upstream request: the URL, every header but the secret, and the body.
pub(super) struct Request<'a> {
    pub(super) url: &'a str,
    pub(super) headers: Vec<(&'a str, &'a str)>,
    /// Name of the secret's header and the prefix of its value.
    pub(super) secret_header: (&'static str, &'static str),
    pub(super) body: Vec<u8>,
}

/// The vendor's answer once its head arrived.
pub(super) struct Answer {
    pub(super) status: u16,
    headers: Vec<(String, String)>,
    response: ureq::http::Response<ureq::Body>,
}

/// Sends `req` with `secret` on a fresh agent of `config` that `cancel` shuts down. The secret
/// header value and the body are dropped once the request is sent.
pub(super) fn send(
    config: &ureq::config::Config,
    req: Request<'_>,
    secret: &str,
    cancel: &CancelToken,
) -> Result<Answer, Failure> {
    let agent = ureq::Agent::new_with_config(config.clone());
    let stop = agent.clone();
    cancel.on_cancel(Box::new(move || stop.shutdown()));
    let (name, prefix) = req.secret_header;
    let mut value = Zeroizing::new(String::with_capacity(prefix.len() + secret.len()));
    value.push_str(prefix);
    value.push_str(secret);
    let mut call = agent.post(req.url);
    for (header, v) in &req.headers {
        call = call.header(*header, *v);
    }
    let sent = call.header(name, value.as_str()).send(&req.body[..]);
    drop(value);
    drop(req.body);
    let response = sent.map_err(|e| broken(cancel, "vendor request failed", &e))?;
    let headers = response
        .headers()
        .iter()
        .filter_map(|(n, v)| Some((n.as_str().to_owned(), v.to_str().ok()?.to_owned())))
        .collect();
    Ok(Answer {
        status: response.status().as_u16(),
        headers,
        response,
    })
}

impl Answer {
    /// The response headers whose values are text, names in lowercase.
    pub(super) fn headers(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect()
    }

    /// The first 64 KiB of an error answer's body; empty when it cannot be read.
    ///
    /// # Errors
    /// The turn was cancelled while reading.
    pub(super) fn error_body(&mut self, cancel: &CancelToken) -> Result<Vec<u8>, Failure> {
        let body = self
            .response
            .body_mut()
            .with_config()
            .limit(MAX_ERROR_BODY)
            .read_to_vec();
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        Ok(body.unwrap_or_default())
    }

    /// Reads the body into `feed` until it reports the stream's stop reason, handing the events
    /// it makes to `sink` after each read, also when `feed` fails. `feed` gets an empty chunk at
    /// the end of the body.
    ///
    /// # Errors
    /// A broken read, a `feed` failure, or [`FailureKind::Cancelled`] once the sink says stop.
    pub(super) fn stream(
        self,
        cancel: &CancelToken,
        sink: &mut Sink<'_>,
        mut feed: impl FnMut(&[u8], &mut Vec<StreamEvent>) -> Result<Option<StopReason>, Failure>,
    ) -> Result<StopReason, Failure> {
        let mut stream = self.response.into_body().into_reader();
        let mut buf = vec![0u8; READ_BYTES];
        let mut events = Vec::new();
        loop {
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(broken(cancel, "vendor stream broke", &e)),
            };
            let progress = feed(&buf[..n], &mut events);
            for event in events.drain(..) {
                if sink(event) == Flow::Stop {
                    return Err(cancelled());
                }
            }
            if let Some(stop) = progress? {
                return Ok(stop);
            }
        }
    }
}
