//! Blocking `/v1` client over a unix socket, used by the CLI and the agent.

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Upper bound on a response we are willing to buffer.
const MAX_RESPONSE: u64 = 1024 * 1024;

/// Sends one request and returns `(status, body)`.
///
/// # Errors
/// Connection, timeout or framing errors.
pub fn call(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> io::Result<(u16, Vec<u8>)> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: qb\r\nConnection: close\r\n");
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
