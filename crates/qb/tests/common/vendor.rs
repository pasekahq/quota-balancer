//! A scripted vendor endpoint on a loopback TCP port, for the gateway's adapters.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

/// What the scripted vendor answers to one request.
pub enum Answer {
    /// A complete answer: status, headers and body.
    Full(u16, Vec<(String, String)>, Vec<u8>),
    /// A 200 stream that sends these bytes and then stays silent until the gateway closes it.
    Hold(Vec<u8>),
    /// The answer, after a pause.
    After(Duration, Box<Answer>),
    /// The answer this function gives to the request body.
    Judge(fn(&Value) -> Answer),
}

/// One request the scripted vendor received.
pub struct Received {
    pub path: String,
    /// Header names in lowercase.
    pub headers: Vec<(String, String)>,
    /// A JSON body, or a form body as a string.
    pub body: Value,
    /// When the vendor had read the whole request.
    pub at: Instant,
}

impl Received {
    pub fn header(&self, name: &str) -> Option<&str> {
        let found = self.headers.iter().find(|(n, _)| n == name);
        found.map(|(_, v)| v.as_str())
    }
}

/// A vendor endpoint on a loopback TCP port that replays [`Answer`]s in order. Dropping it
/// closes the port.
pub struct Vendor {
    pub base_url: String,
    answers: Arc<Mutex<Vec<Answer>>>,
    received: Arc<Mutex<Vec<Received>>>,
    /// Receives the time the gateway closed a held stream.
    pub closed: Receiver<Instant>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Vendor {
    /// A vendor on a free loopback port.
    pub fn start() -> Self {
        Self::start_on("127.0.0.1:0".parse().unwrap())
    }

    /// A vendor listening on `addr`.
    pub fn start_on(addr: SocketAddr) -> Self {
        let listener = TcpListener::bind(addr).unwrap_or_else(|e| panic!("bind {addr}: {e}"));
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let answers = Arc::new(Mutex::new(Vec::<Answer>::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, closed) = channel();
        let (queue, log, halt) = (
            Arc::clone(&answers),
            Arc::clone(&received),
            Arc::clone(&stop),
        );
        let accept = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if halt.load(Ordering::SeqCst) {
                    return;
                }
                let (queue, log, tx) = (Arc::clone(&queue), Arc::clone(&log), tx.clone());
                std::thread::spawn(move || {
                    let mut conn = conn.unwrap();
                    let req = read_http(&mut conn);
                    let mut answer = queue.lock().unwrap().remove(0);
                    if let Answer::Judge(judge) = answer {
                        answer = judge(&req.body);
                    }
                    log.lock().unwrap().push(req);
                    answer_with(&mut conn, answer, &tx);
                });
            }
        });
        Self {
            base_url,
            answers,
            received,
            closed,
            addr,
            stop,
            accept: Some(accept),
        }
    }

    pub fn answer(&self, answer: Answer) {
        self.answers.lock().unwrap().push(answer);
    }

    pub fn received(&self) -> MutexGuard<'_, Vec<Received>> {
        self.received.lock().unwrap()
    }

    /// Login keys besides `name` and `credentials` that send the login here.
    pub fn login(&self, kind: &str) -> String {
        format!("{kind}\nbase_url = \"{}\"", self.base_url)
    }
}

impl Drop for Vendor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let woke = TcpStream::connect(self.addr).is_ok();
        if let (true, Some(accept)) = (woke, self.accept.take()) {
            let _ = accept.join();
        }
    }
}

fn read_http(conn: &mut TcpStream) -> Received {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        assert_eq!(conn.read(&mut byte).unwrap(), 1, "request head cut");
        raw.push(byte[0]);
    }
    let head = String::from_utf8(raw).unwrap();
    let mut lines = head.lines();
    let path = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .map(|(_, v)| v.parse().unwrap())
        .unwrap();
    let mut body = vec![0u8; length];
    conn.read_exact(&mut body).unwrap();
    let at = Instant::now();
    let form = headers
        .iter()
        .any(|(n, v)| n == "content-type" && v == "application/x-www-form-urlencoded");
    let body = if form {
        Value::String(String::from_utf8(body).unwrap())
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    Received {
        path,
        headers,
        body,
        at,
    }
}

fn answer_with(conn: &mut TcpStream, answer: Answer, closed: &Sender<Instant>) {
    match answer {
        Answer::Full(status, headers, body) => {
            let mut out = format!("HTTP/1.1 {status} X\r\n");
            for (n, v) in headers {
                write!(out, "{n}: {v}\r\n").unwrap();
            }
            write!(
                out,
                "content-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(&body);
            // The gateway may stop reading once the stream finished.
            let _ = conn.write_all(&bytes);
        }
        Answer::Hold(prefix) => {
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n";
            let chunk = format!("{:x}\r\n", prefix.len());
            conn.write_all(head.as_bytes()).unwrap();
            conn.write_all(chunk.as_bytes()).unwrap();
            conn.write_all(&prefix).unwrap();
            conn.write_all(b"\r\n").unwrap();
            let mut rest = Vec::new();
            let _ = conn.read_to_end(&mut rest);
            let _ = closed.send(Instant::now());
        }
        Answer::After(pause, answer) => {
            std::thread::sleep(pause);
            answer_with(conn, *answer, closed);
        }
        Answer::Judge(_) => unreachable!("judged on receipt"),
    }
}

/// A file of `crates/<krate>/tests/fixtures`.
pub fn fixture_of(krate: &str, name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(krate)
        .join("tests/fixtures");
    std::fs::read(dir.join(name)).unwrap()
}
