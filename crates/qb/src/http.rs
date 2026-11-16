//! Minimal HTTP/1.1 framing over a byte stream: one request per connection, bounded sizes.
//!
//! The balancer serves a handful of small JSON calls per second. A blocking reader with hard
//! limits is all it needs; keep-alive and pipelining can come later without changing callers.

use std::io::{self, Read, Write};

/// Maximum size of the request line plus headers.
pub const MAX_HEAD: usize = 8 * 1024;
/// Maximum request body size.
pub const MAX_BODY: usize = 64 * 1024;
const MAX_HEADERS: usize = 32;

/// Request method. Only `GET` and `POST` are routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// Anything else.
    Other,
}

/// A parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Path without the query string.
    pub path: String,
    /// Bearer token from `Authorization`, if any.
    pub bearer: Option<String>,
    /// Body (`Content-Length` bytes).
    pub body: Vec<u8>,
}

/// Why a request could not be read.
#[derive(Debug)]
pub enum ReadError {
    /// Socket error or timeout.
    Io(io::Error),
    /// Peer closed before sending anything.
    Closed,
    /// Not valid HTTP/1.x, or unsupported framing (e.g. chunked bodies).
    Malformed,
    /// Head over [`MAX_HEAD`] or too many headers.
    HeadTooLarge,
    /// Body over [`MAX_BODY`].
    BodyTooLarge,
    /// `POST` without `Content-Length`.
    LengthRequired,
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Reads one request. `buf` is a scratch buffer reused across connections.
///
/// # Errors
/// See [`ReadError`].
pub fn read_request<R: Read>(r: &mut R, buf: &mut Vec<u8>) -> Result<Request, ReadError> {
    buf.clear();
    let mut chunk = [0u8; 2048];
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf) {
            Ok(httparse::Status::Complete(head_len)) => {
                let method = match req.method {
                    Some("GET") => Method::Get,
                    Some("POST") => Method::Post,
                    _ => Method::Other,
                };
                let raw_path = req.path.unwrap_or("/");
                let path = raw_path.split('?').next().unwrap_or("/").to_owned();
                let mut content_length = None;
                let mut bearer = None;
                for h in req.headers.iter() {
                    if h.name.eq_ignore_ascii_case("content-length") {
                        let v = std::str::from_utf8(h.value).map_err(|_| ReadError::Malformed)?;
                        let n: usize = v.trim().parse().map_err(|_| ReadError::Malformed)?;
                        if content_length.is_some_and(|prev| prev != n) {
                            return Err(ReadError::Malformed);
                        }
                        content_length = Some(n);
                    } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
                        return Err(ReadError::Malformed);
                    } else if h.name.eq_ignore_ascii_case("authorization") {
                        let v = std::str::from_utf8(h.value).map_err(|_| ReadError::Malformed)?;
                        if let Some(token) = v.strip_prefix("Bearer ") {
                            bearer = Some(token.trim().to_owned());
                        }
                    }
                }
                if method == Method::Post && content_length.is_none() {
                    return Err(ReadError::LengthRequired);
                }
                let want = content_length.unwrap_or(0);
                if want > MAX_BODY {
                    return Err(ReadError::BodyTooLarge);
                }
                let mut body = Vec::with_capacity(want);
                let already = &buf[head_len..];
                body.extend_from_slice(&already[..already.len().min(want)]);
                while body.len() < want {
                    let n = r.read(&mut chunk)?;
                    if n == 0 {
                        return Err(ReadError::Malformed);
                    }
                    let take = n.min(want - body.len());
                    body.extend_from_slice(&chunk[..take]);
                }
                return Ok(Request {
                    method,
                    path,
                    bearer,
                    body,
                });
            }
            Ok(httparse::Status::Partial) => {
                if buf.len() >= MAX_HEAD {
                    return Err(ReadError::HeadTooLarge);
                }
                let n = r.read(&mut chunk)?;
                if n == 0 {
                    return Err(if buf.is_empty() {
                        ReadError::Closed
                    } else {
                        ReadError::Malformed
                    });
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(httparse::Error::TooManyHeaders) => return Err(ReadError::HeadTooLarge),
            Err(_) => return Err(ReadError::Malformed),
        }
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Writes a complete JSON response and asks the peer to close.
///
/// # Errors
/// Socket errors.
pub fn write_response<W: Write>(w: &mut W, status: u16, body: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(128 + body.len());
    write!(
        out,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    )?;
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &[u8]) -> Result<Request, ReadError> {
        let mut buf = Vec::new();
        read_request(&mut &raw[..], &mut buf)
    }

    #[test]
    fn parses_get_and_strips_query() {
        let r = parse(b"GET /v1/state?x=1 HTTP/1.1\r\nHost: qb\r\n\r\n").expect("valid");
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.path, "/v1/state");
        assert_eq!(r.body, b"");
    }

    #[test]
    fn parses_post_body_and_bearer() {
        let r = parse(
            b"POST /v1/pick HTTP/1.1\r\nAuthorization: Bearer abc\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("valid");
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.bearer.as_deref(), Some("abc"));
        assert_eq!(r.body, b"{}");
    }

    #[test]
    fn rejects_bad_framing() {
        assert!(matches!(
            parse(b"POST /v1/pick HTTP/1.1\r\n\r\n"),
            Err(ReadError::LengthRequired)
        ));
        assert!(matches!(
            parse(b"POST /v1/pick HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Err(ReadError::Malformed)
        ));
        assert!(matches!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n{}"),
            Err(ReadError::Malformed)
        ));
        assert!(matches!(parse(b""), Err(ReadError::Closed)));
        assert!(matches!(
            parse(b"POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n{}"),
            Err(ReadError::Malformed)
        ));
    }

    #[test]
    fn enforces_limits() {
        let big = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(matches!(
            parse(big.as_bytes()),
            Err(ReadError::BodyTooLarge)
        ));
        let mut head = b"GET / HTTP/1.1\r\nX: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        assert!(matches!(parse(&head), Err(ReadError::HeadTooLarge)));
    }

    #[test]
    fn writes_response() {
        let mut out = Vec::new();
        write_response(&mut out, 404, b"{}").expect("write");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }
}
