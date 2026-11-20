//! Blocking `/v1` client over a unix socket, used by the CLI, the agent and the gateway.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Upper bound on a response we are willing to buffer.
const MAX_RESPONSE: u64 = 1024 * 1024;

/// How long [`call`] waits for each read or write.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends one request, with `Authorization: Bearer` when `bearer` is given, and returns
/// `(status, body)`.
///
/// # Errors
/// A bearer with a control character, connection, timeout or framing errors.
pub fn call(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
) -> io::Result<(u16, Vec<u8>)> {
    let answer = exchange(socket, method, path, body, bearer, None, Some(CALL_TIMEOUT))?;
    Ok((answer.status, answer.body))
}

/// A response: its status, its `ETag` and its body.
#[derive(Debug)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// Value of `ETag`, if any.
    pub etag: Option<String>,
    /// Body.
    pub body: Vec<u8>,
}

/// [`call`] that also sends `If-Match: if_match` when given and answers the `ETag` too.
///
/// # Errors
/// As [`call`], and an `If-Match` with a control character.
pub fn call_tagged(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    if_match: Option<&str>,
) -> io::Result<Answer> {
    exchange(
        socket,
        method,
        path,
        body,
        bearer,
        if_match,
        Some(CALL_TIMEOUT),
    )
}

/// [`call`] for a request the daemon parks: waits for the response without a read timeout.
///
/// # Errors
/// As [`call`]; the daemon closing the connection is a framing error.
pub fn call_parked(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
) -> io::Result<(u16, Vec<u8>)> {
    let answer = exchange(socket, method, path, body, bearer, None, None)?;
    Ok((answer.status, answer.body))
}

fn exchange(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    if_match: Option<&str>,
    read_timeout: Option<Duration>,
) -> io::Result<Answer> {
    for (value, what) in [(bearer, "bearer token"), (if_match, "`If-Match`")] {
        if value.is_some_and(|v| v.chars().any(char::is_control)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{what} contains a control character"),
            ));
        }
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(Some(CALL_TIMEOUT))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: qb\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        let _ = write!(req, "Authorization: Bearer {token}\r\n");
    }
    if let Some(tag) = if_match {
        let _ = write!(req, "If-Match: {tag}\r\n");
    }
    if let Some(b) = body {
        let _ = write!(
            req,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            b.len()
        );
    }
    req.push_str("\r\n");
    let mut out = req.into_bytes();
    out.extend_from_slice(body.unwrap_or_default());
    stream.write_all(&out)?;
    let mut raw = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut raw)?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(&raw) {
        Ok(httparse::Status::Complete(head)) => {
            let etag = resp
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("etag"))
                .map(|h| String::from_utf8_lossy(h.value).into_owned());
            Ok(Answer {
                status: resp.code.unwrap_or(0),
                etag,
                body: raw[head..].to_vec(),
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed HTTP response",
        )),
    }
}
