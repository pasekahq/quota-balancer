//! Raw HTTP/1.1 exchanges over a unix socket and the hashes tests compare answers with.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Sends one request and leaves the connection open for its answer.
pub fn send(sock: &Path, method: &str, path: &str, body: &str) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: qb\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    s
}

/// The chunked body `raw` without its framing.
pub fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|w| w == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).unwrap(), 16).unwrap();
        raw = &raw[line_end + 2..];
        if size == 0 {
            assert_eq!(raw, b"\r\n", "stream ends with the last chunk");
            return out;
        }
        out.extend_from_slice(&raw[..size]);
        assert_eq!(&raw[size..size + 2], b"\r\n");
        raw = &raw[size + 2..];
    }
}

/// Status, head and (dechunked) body of a complete answer.
pub fn finish(mut s: impl Read, already: Vec<u8>) -> (u16, String, Vec<u8>) {
    let mut raw = already;
    s.read_to_end(&mut raw).unwrap();
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..at].to_vec()).unwrap();
    let body = &raw[at + 4..];
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let body = if head.contains("Transfer-Encoding: chunked") {
        dechunk(body)
    } else {
        body.to_vec()
    };
    (status, head, body)
}

/// The value of the `ETag` header in `head`.
pub fn etag(head: &str) -> Option<&str> {
    head.lines().find_map(|l| l.strip_prefix("ETag: "))
}

/// Hex SHA-256 of `text`, by `sha256sum`.
pub fn sha256_hex(text: &str) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_owned()
}
