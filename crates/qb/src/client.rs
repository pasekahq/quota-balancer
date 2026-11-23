//! Blocking `/v1` client over a unix socket, used by the CLI, the agent and the gateway.

use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::http::MAX_HEAD;

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

/// How a [`call_streamed`] ended once its head arrived.
#[derive(Debug)]
pub enum Streamed {
    /// A 2xx answer whose body was copied through its last chunk.
    Complete,
    /// A 2xx answer whose copy stopped before the last chunk; what arrived before is copied.
    Cut(io::Error),
    /// Any other answer: its status and its body, bounded as for [`call`].
    Refused(u16, Vec<u8>),
}

/// [`call_parked`] whose 2xx answer has a chunked body, copied to `out` chunk by chunk as it
/// arrives, with no bound on its size.
///
/// # Errors
/// As [`call_parked`] until the head arrived, and a 2xx answer that is not chunked.
pub fn call_streamed(
    socket: &Path,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    out: &mut impl Write,
) -> io::Result<Streamed> {
    let stream = send(socket, method, path, None, bearer, None, None)?;
    let mut r = BufReader::new(stream);
    let mut head = Vec::new();
    loop {
        let start = head.len();
        let n = (&mut r)
            .take((MAX_HEAD - start) as u64)
            .read_until(b'\n', &mut head)?;
        if n == 0 {
            return Err(malformed());
        }
        if head[start..] == *b"\r\n" {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let Ok(httparse::Status::Complete(_)) = resp.parse(&head) else {
        return Err(malformed());
    };
    let status = resp.code.unwrap_or(0);
    if !(200..300).contains(&status) {
        let mut body = Vec::new();
        r.take(MAX_RESPONSE).read_to_end(&mut body)?;
        return Ok(Streamed::Refused(status, body));
    }
    let chunked = resp.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding") && h.value.eq_ignore_ascii_case(b"chunked")
    });
    if !chunked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a 2xx answer without a chunked body",
        ));
    }
    Ok(match copy_chunked(&mut r, out) {
        Ok(()) => Streamed::Complete,
        Err(e) => Streamed::Cut(e),
    })
}

/// Copies the data of the chunked body `r` to `out`, flushing after each chunk.
///
/// # Errors
/// A body that ends before its last chunk, bad framing, and read or write errors.
fn copy_chunked(r: &mut impl BufRead, out: &mut impl Write) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        read_line(r, &mut line)?;
        let digits = line.split(|b| *b == b';').next().unwrap_or_default();
        let size = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| u64::from_str_radix(d.trim(), 16).ok())
            .ok_or_else(|| framing("a chunk size that is not hexadecimal"))?;
        if size == 0 {
            loop {
                read_line(r, &mut line)?;
                if line.is_empty() {
                    return Ok(());
                }
            }
        }
        let mut left = size;
        while left > 0 {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                return Err(cut());
            }
            let n = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            out.write_all(&buf[..n])?;
            r.consume(n);
            left -= n as u64;
        }
        out.flush()?;
        read_line(r, &mut line)?;
        if !line.is_empty() {
            return Err(framing("a chunk longer than its size"));
        }
    }
}

/// Reads one CRLF-terminated line of chunked framing into `line`, without the CRLF.
fn read_line(r: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<()> {
    line.clear();
    r.take(MAX_HEAD as u64).read_until(b'\n', line)?;
    match line.pop() {
        Some(b'\n') => {}
        _ if line.len() + 1 < MAX_HEAD => return Err(cut()),
        _ => return Err(framing("a framing line over 8 KiB")),
    }
    if line.pop() != Some(b'\r') {
        return Err(framing("a framing line without CRLF"));
    }
    Ok(())
}

fn cut() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "the body ended before its last chunk",
    )
}

fn framing(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("chunked body: {what}"))
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response")
}

/// Connects to `socket` and sends the request; the stream is left to read the answer from.
fn send(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bearer: Option<&str>,
    if_match: Option<&str>,
    read_timeout: Option<Duration>,
) -> io::Result<UnixStream> {
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
    Ok(stream)
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
    let stream = send(socket, method, path, body, bearer, if_match, read_timeout)?;
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
        _ => Err(malformed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copied(raw: &[u8]) -> (Vec<u8>, io::Result<()>) {
        let mut out = Vec::new();
        let result = copy_chunked(&mut BufReader::with_capacity(3, raw), &mut out);
        (out, result)
    }

    #[test]
    fn a_complete_body_is_copied_through_extensions_and_trailers() {
        let (out, result) =
            copied(b"4;ext=1\r\nab\nc\r\n1A\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\nX-T: 1\r\n\r\n");
        result.unwrap();
        assert_eq!(out, b"ab\ncabcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn a_body_cut_anywhere_before_its_last_chunk_keeps_what_arrived() {
        let full = b"3\r\nab\n\r\n3\r\ncd\n\r\n0\r\n\r\n";
        for end in 0..full.len() {
            let (out, result) = copied(&full[..end]);
            let e = result.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "cut at {end}: {e}");
            assert!(b"ab\ncd\n".starts_with(&out), "cut at {end}");
        }
    }

    #[test]
    fn bad_framing_is_an_error() {
        for raw in [
            &b"zz\r\nab\r\n0\r\n\r\n"[..],
            b"2\r\nabc\r\n0\r\n\r\n",
            b"2\nab\r\n0\r\n\r\n",
        ] {
            let e = copied(raw).1.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "{e}");
        }
    }
}
