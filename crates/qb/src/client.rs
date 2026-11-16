//! Blocking `/v1` client over a unix socket, used by the CLI and the agent.

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
    exchange(socket, method, path, body, bearer, Some(CALL_TIMEOUT))
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
    exchange(socket, method, path, body, bearer, None)
}

fn exchange(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    read_timeout: Option<Duration>,
) -> io::Result<(u16, Vec<u8>)> {
    if bearer.is_some_and(|b| b.chars().any(char::is_control)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bearer token contains a control character",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(read_timeout)?;
    stream.set_write_timeout(Some(CALL_TIMEOUT))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: qb\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        let _ = write!(req, "Authorization: Bearer {token}\r\n");
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
            let code = resp.code.unwrap_or(0);
            Ok((code, raw[head..].to_vec()))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed HTTP response",
        )),
    }
}
