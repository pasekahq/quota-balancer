//! Helpers shared by the test targets that drive the daemon over its socket.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use qb::client::call;
use qb_proto::{LoginStatus, PickResponse, ReportResponse, StateResponse, paths};

pub mod cleanup;
pub mod credentials;
pub mod http;
pub mod pkce;
pub mod vendor;

/// Room for the directory and file names a test adds under the base.
const NAME_ROOM: usize = 40;

/// `sun_path` holds 108 bytes including the terminating NUL.
const SUN_PATH: usize = 108;

/// A fresh directory for one test under a base short enough for unix socket paths, removed when
/// the test ends ([`cleanup`]).
pub fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let tmp = std::env::temp_dir();
    let base = if tmp.as_os_str().len() + NAME_ROOM < SUN_PATH {
        tmp
    } else {
        PathBuf::from("/tmp")
    };
    let dir = base.join(format!(
        "qb-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::remove_at_test_end(&dir);
    dir
}

pub struct Daemon(pub Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(path).is_err() {
        assert!(Instant::now() < deadline, "daemon did not come up");
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn pick_worker(sock: &Path) -> PickResponse {
    let (status, resp) = call(
        sock,
        "POST",
        paths::PICK,
        Some(br#"{"role":"worker","difficulty":1}"#),
        None,
    )
    .unwrap();
    assert_eq!(status, 200);
    serde_json::from_slice(&resp).unwrap()
}

pub fn post<T: serde::de::DeserializeOwned>(sock: &Path, path: &str, body: &str) -> T {
    let (status, resp) = call(sock, "POST", path, Some(body.as_bytes()), None).unwrap();
    assert_eq!(status, 200, "{body}: {}", String::from_utf8_lossy(&resp));
    serde_json::from_slice(&resp).unwrap()
}

pub fn state(sock: &Path) -> StateResponse {
    let (status, body) = call(sock, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 200);
    serde_json::from_slice(&body).unwrap()
}

/// The uid this test process runs as: the owner of a directory it created.
pub fn own_uid() -> u32 {
    std::fs::metadata(temp_dir("uid")).unwrap().uid()
}

/// Opens `POST /v1/agent/next` for `logins` and leaves the connection waiting.
pub fn park(sock: &Path, bearer: Option<&str>, logins: &[&str]) -> UnixStream {
    let body = serde_json::json!({ "logins": logins }).to_string();
    let auth = bearer.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let mut s = UnixStream::connect(sock).unwrap();
    write!(
        s,
        "POST {} HTTP/1.1\r\nHost: qb\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        paths::AGENT_NEXT,
        body.len()
    )
    .unwrap();
    s
}

/// The response on a parked connection within `wait`, `None` while it is still parked.
pub fn answer(s: &mut UnixStream, wait: Duration) -> Option<(u16, Vec<u8>)> {
    s.set_read_timeout(Some(wait)).unwrap();
    let mut raw = Vec::new();
    match s.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            assert!(raw.is_empty(), "partial answer");
            return None;
        }
        Err(e) => panic!("{e}"),
    }
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Some((status, body.as_bytes().to_vec()))
}

/// Writes `body` to `hook.sh` next to `config` and appends a `[hooks]` section running it on both
/// events. `/bin/sh` reads the script rather than the kernel exec'ing it, so a fork in a
/// concurrent test that still holds the file open for writing cannot fail the exec.
pub fn hook_config(config: PathBuf, body: &str) -> PathBuf {
    let script = config.with_file_name("hook.sh");
    std::fs::write(&script, body).unwrap();
    let command = format!(r#"["/bin/sh", "{}"]"#, script.display());
    let mut text = std::fs::read_to_string(&config).unwrap();
    write!(
        text,
        "\n[hooks]\non_dead = {command}\non_recover = {command}\n"
    )
    .unwrap();
    std::fs::write(&config, text).unwrap();
    config
}

/// Hook script line appending `$QB_EVENT $QB_LOGIN $QB_VENDOR` to `dir/events`.
pub fn record_event(dir: &Path) -> String {
    format!(
        "echo \"$QB_EVENT $QB_LOGIN $QB_VENDOR\" >> '{}'\n",
        dir.join("events").display()
    )
}

/// The lines of `dir/events` once there are at least `n`, polled for at most 10 s.
pub fn events(dir: &Path, n: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(dir.join("events")).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= n {
            return lines;
        }
        assert!(
            Instant::now() < deadline,
            "want {n} hook events, got {lines:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

pub fn report_login(sock: &Path, login: &str, outcome: &str) -> LoginStatus {
    let body = format!(r#"{{"login":"{login}","outcome":"{outcome}","model":"model-small"}}"#);
    let r: ReportResponse = post(sock, paths::REPORT, &body);
    r.login_status
}

pub fn kill_auth(sock: &Path, login: &str) {
    assert_eq!(
        report_login(sock, login, "http_401"),
        LoginStatus::AuthStale
    );
    assert_eq!(report_login(sock, login, "http_401"), LoginStatus::AuthDead);
}

/// Lines the child writes to stderr, as they come.
pub fn stderr_lines(child: &mut Child) -> Receiver<String> {
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stderr)) {
            let Ok(line) = line else { return };
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// The next line of `lines` within `wait` that contains `needle`.
pub fn line_with(lines: &Receiver<String>, needle: &str, wait: Duration) -> Option<String> {
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match lines.recv_timeout(left) {
            Ok(line) if line.contains(needle) => return Some(line),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// Runs `exe` as the daemon on `sock` with `config` and waits until it accepts connections.
pub fn start_daemon(exe: &Path, config: &Path, sock: &Path, stderr: Stdio) -> Daemon {
    let d = Daemon(
        Command::new(exe)
            .arg("--socket")
            .arg(sock)
            .args(["daemon", "--config"])
            .arg(config)
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    wait_for(sock);
    d
}
