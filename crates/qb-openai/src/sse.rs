//! An incremental server-sent events parser: byte chunks in, complete events out. Lines may end
//! in `\n`, `\r\n` or `\r` and may be split anywhere across chunks; comments, `id` and `retry`
//! fields are ignored. The size of one event is bounded.

use std::fmt;

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The `event` field; empty when absent.
    pub event: String,
    /// The `data` fields joined by `\n`.
    pub data: String,
}

/// Default bound of one event: line buffer plus data, the per-turn allowance of the gateway's
/// memory budget. A Responses stream repeats the request in its lifecycle events, so its reader
/// adds the request size (`stream::event_bound`).
pub const MAX_EVENT_BYTES: usize = 1 << 20;

/// An event grew beyond the parser's bound; the stream cannot be trusted further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Oversized;

impl fmt::Display for Oversized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a server-sent event exceeds the size bound")
    }
}

impl std::error::Error for Oversized {}

/// The parser state between chunks.
#[derive(Debug)]
pub struct Parser {
    line: Vec<u8>,
    event: String,
    data: String,
    has_data: bool,
    after_cr: bool,
    max: usize,
    failed: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(MAX_EVENT_BYTES)
    }
}

impl Parser {
    /// A parser that fails once one event needs more than `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            line: Vec::new(),
            event: String::new(),
            data: String::new(),
            has_data: false,
            after_cr: false,
            max,
            failed: false,
        }
    }

    /// Feeds `chunk` and appends every event it completes to `out`.
    ///
    /// # Errors
    /// [`Oversized`] once an event exceeds the bound; every later call fails the same way.
    pub fn feed(&mut self, chunk: &[u8], out: &mut Vec<Frame>) -> Result<(), Oversized> {
        if self.failed {
            return Err(Oversized);
        }
        let mut rest = chunk;
        while !rest.is_empty() {
            if self.after_cr {
                self.after_cr = false;
                if rest[0] == b'\n' {
                    rest = &rest[1..];
                    continue;
                }
            }
            if let Some(i) = rest.iter().position(|&b| b == b'\n' || b == b'\r') {
                self.line.extend_from_slice(&rest[..i]);
                self.after_cr = rest[i] == b'\r';
                rest = &rest[i + 1..];
                self.end_line(out);
            } else {
                self.line.extend_from_slice(rest);
                rest = &[];
            }
            if self.line.len() + self.data.len() + self.event.len() > self.max {
                self.failed = true;
                return Err(Oversized);
            }
        }
        Ok(())
    }

    fn end_line(&mut self, out: &mut Vec<Frame>) {
        let line = std::mem::take(&mut self.line);
        if line.is_empty() {
            if self.has_data {
                out.push(Frame {
                    event: std::mem::take(&mut self.event),
                    data: std::mem::take(&mut self.data),
                });
            } else {
                self.event.clear();
            }
            self.has_data = false;
            return;
        }
        if line[0] == b':' {
            return;
        }
        let (name, value) = match line.iter().position(|&b| b == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (&line[..], &[][..]),
        };
        let value = String::from_utf8_lossy(value);
        match name {
            b"event" => self.event = value.into_owned(),
            b"data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(&value);
                self.has_data = true;
            }
            _ => {}
        }
    }
}

/// One event as the bytes of a stream: `event: <name>\ndata: <data>\n\n`. `data` must be one line.
pub fn encode(event: &str, data: &str) -> Vec<u8> {
    format!("event: {event}\ndata: {data}\n\n").into_bytes()
}

/// One unnamed event as the bytes of a stream: `data: <data>\n\n`. `data` must be one line.
pub fn encode_data(data: &str) -> Vec<u8> {
    format!("data: {data}\n\n").into_bytes()
}

/// A comment that keeps an idle stream open; parsers ignore it.
pub fn keep_alive() -> Vec<u8> {
    b": keep-alive\n\n".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(input: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        Parser::default().feed(input, &mut out).expect("bounded");
        out
    }

    #[test]
    fn line_endings_comments_and_multiline_data() {
        let got = all(b": hi\r\nevent: a\r\ndata: 1\rdata:2\n\nid: 7\ndata: x\n\n\n");
        assert_eq!(
            got,
            vec![
                Frame {
                    event: "a".into(),
                    data: "1\n2".into()
                },
                Frame {
                    event: String::new(),
                    data: "x".into()
                }
            ]
        );
    }

    #[test]
    fn cr_lf_split_across_chunks_is_one_line_end() {
        let mut p = Parser::default();
        let mut out = Vec::new();
        p.feed(b"data: 1\r", &mut out).expect("bounded");
        p.feed(b"\n\r", &mut out).expect("bounded");
        p.feed(b"\n", &mut out).expect("bounded");
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn oversized_event_fails_for_good() {
        let mut p = Parser::new(8);
        let mut out = Vec::new();
        assert_eq!(p.feed(b"data: 0123456789", &mut out), Err(Oversized));
        assert_eq!(p.feed(b"\n\n", &mut out), Err(Oversized));
    }
}
