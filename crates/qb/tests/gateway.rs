//! Contract tests of the model gateway: `/v1/model/*` over a real unix socket, with a real qbd
//! in-process and a scripted fake vendor adapter.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qb::auth::Gate;
use qb::gateway::core::Gateway;
use qb::gateway::creds::{RefreshError, Refreshed, Refresher};
use qb::gateway::front;
use qb::gateway::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Flow, Picked, Sink, Upstream,
};
use qb::hooks::Runner;
use qb::journal::Journal;
use qb::server::unix_now;
use qb_core::Core;
use qb_proto::{
    Block, CancelAnswer, ErrorClass, GatewayError, LoginStatus, RouteState, RoutesAnswer,
    StateResponse, StopReason, StreamEvent, Thinking, ToolCall, TurnRequest, Usage, WindowReport,
    paths,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

mod common;

use common::{Daemon, line_with, own_uid, start_daemon, stderr_lines, temp_dir, wait_for};

const QBD: &str = r#"
[journal]
mode = "off"

[[vendors]]
name = "vendor-a"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[vendors]]
name = "vendor-b"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[logins]]
name = "login-1"
vendor = "vendor-a"

[[logins]]
name = "login-2"
vendor = "vendor-a"

[[roles]]
name = "gateway"

[[roles.ladder]]
difficulty = 1
candidates = [{ vendor = "vendor-a", model = "model-large", tier = 1 }]

[limits]
rate_per_s = 1000.0
burst = 1000
"#;

/// What the fake adapter does on one call.
enum Script {
    /// Emit the events, then finish with the stop reason and windows.
    Finish(Vec<StreamEvent>, StopReason, Vec<WindowReport>),
    /// Emit the events, then fail.
    Fail(Vec<StreamEvent>, FailureKind, Vec<WindowReport>),
    /// Emit the events, then wait for the cancel.
    Hang(Vec<StreamEvent>),
}

/// A scripted adapter: one queue of scripts per login, and a record of every call.
#[derive(Default)]
struct Fake {
    scripts: Mutex<HashMap<String, Vec<Script>>>,
    /// `(login, secret, request)` of every call.
    calls: Mutex<Vec<(String, String, TurnRequest)>>,
}

impl Fake {
    fn script(&self, login: &str, script: Script) {
        let mut s = self.scripts.lock().unwrap();
        s.entry(login.to_owned()).or_default().push(script);
    }

    fn calls(&self) -> Vec<(String, String, TurnRequest)> {
        self.calls.lock().unwrap().clone()
    }
}

struct Shared(Arc<Fake>);

impl Upstream for Shared {
    fn turn(
        &self,
        at: &Picked<'_>,
        credential: &Credential,
        req: &TurnRequest,
        sink: &mut Sink<'_>,
        cancel: &CancelToken,
    ) -> Result<Finished, Failure> {
        let login = at.login.to_owned();
        self.0.calls.lock().unwrap().push((
            login.clone(),
            credential.secret().to_owned(),
            req.clone(),
        ));
        let script = {
            let mut s = self.0.scripts.lock().unwrap();
            let queue = s.entry(login).or_default();
            if queue.is_empty() {
                Script::Finish(vec![text("hi")], StopReason::End, Vec::new())
            } else {
                queue.remove(0)
            }
        };
        let emit = |events: Vec<StreamEvent>, sink: &mut Sink<'_>| {
            for e in events {
                if sink(e) == Flow::Stop {
                    return Err(Failure::new(FailureKind::Cancelled, "stopped"));
                }
            }
            Ok(())
        };
        match script {
            Script::Finish(events, stop, windows) => {
                emit(events, sink)?;
                Ok(Finished { stop, windows })
            }
            Script::Fail(events, kind, windows) => {
                emit(events, sink)?;
                Err(Failure {
                    kind,
                    windows,
                    message: format!("scripted {kind:?}"),
                })
            }
            Script::Hang(events) => {
                emit(events, sink)?;
                let deadline = Instant::now() + Duration::from_secs(10);
                while !cancel.is_cancelled() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(Failure::new(FailureKind::Cancelled, "cancelled"))
            }
        }
    }
}

/// Hands out `access-N` and counts its calls.
struct Counting(Arc<AtomicUsize>);

impl Refresher for Counting {
    fn refresh(&self, _: &str, _: &str) -> Result<Refreshed, RefreshError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Refreshed {
            access_token: Zeroizing::new(format!("access-{n}")),
            refresh_token: None,
            expires_at: unix_now() + 3600,
        })
    }
}

fn text(t: &str) -> StreamEvent {
    StreamEvent::TextDelta { text: t.into() }
}

fn window(utilization: f64, resets_at: u64) -> Vec<WindowReport> {
    vec![WindowReport {
        name: "five_hour".into(),
        utilization,
        resets_at: Some(resets_at),
        length_s: None,
    }]
}

fn api_key(secret: &str) -> String {
    format!(r#"{{"type":"api_key","key":"{secret}"}}"#)
}

/// A qbd and a gateway on fresh sockets, both in-process.
struct Rig {
    dir: PathBuf,
    qbd: PathBuf,
    gw: PathBuf,
    fake: Arc<Fake>,
    refreshes: Arc<AtomicUsize>,
}

fn start_qbd(dir: &Path) -> PathBuf {
    let sock = dir.join("qb.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let config = qb::config::parse(Path::new("qbd.toml"), QBD).unwrap();
    std::thread::spawn(move || {
        let mut core = Core::new(config.core_spec()).unwrap();
        let mut gate = Gate::new(&[], &config.limits);
        qb::server::serve(
            &listener,
            &mut core,
            &mut Journal::off(),
            &mut Runner::default(),
            &mut gate,
            &[],
        )
    });
    sock
}

/// The gateway config for `dir`, with `extra` appended.
fn gateway_toml(dir: &Path, qbd: &Path, max_turns: u32, extra: &str) -> String {
    format!(
        r#"socket = "{dir}/gw.sock"
qbd_socket = "{qbd}"
media_dirs = ["{dir}/media"]
max_turns = {max_turns}
max_body_bytes = 65536

[[logins]]
name = "login-1"
credentials = "{dir}/creds/login-1.json"

[[logins]]
name = "login-2"
credentials = "{dir}/creds/login-2.json"

[[routes]]
alias = "chat"
role = "gateway"
difficulty = 1

[[routes]]
alias = "spare"
role = "gateway"
vendor = "vendor-b"
model = "model-b"
{extra}"#,
        dir = dir.display(),
        qbd = qbd.display()
    )
}

/// Writes the credential files `(login, contents, mode)` into `dir/creds`.
fn credentials(dir: &Path, files: &[(&str, String, u32)]) {
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::create_dir_all(dir.join("media")).unwrap();
    for (login, contents, mode) in files {
        let f = creds.join(format!("{login}.json"));
        std::fs::write(&f, contents).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
}

fn rig_with(max_turns: u32, extra: &str, files: &[(&str, String, u32)]) -> Rig {
    let dir = temp_dir("gw");
    credentials(&dir, files);
    let qbd = start_qbd(&dir);
    let text = gateway_toml(&dir, &qbd, max_turns, extra);
    let config = qb::gateway::config::parse(Path::new("gateway.toml"), &text).unwrap();
    let gw = config.socket.clone();
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        config,
        vec![("vendor-a".into(), Box::new(Shared(Arc::clone(&fake))))],
        Box::new(Counting(Arc::clone(&refreshes))),
        None,
    );
    let listener = UnixListener::bind(&gw).unwrap();
    std::thread::spawn(move || front::serve(&listener, &Arc::new(gateway)));
    Rig {
        dir,
        qbd,
        gw,
        fake,
        refreshes,
    }
}

fn rig() -> Rig {
    rig_with(
        4,
        "",
        &[
            ("login-1", api_key("test-token-1"), 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    )
}

/// Sends one request and leaves the connection open for its answer.
fn send(sock: &Path, method: &str, path: &str, body: &str) -> UnixStream {
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
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
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
fn finish(mut s: UnixStream, already: Vec<u8>) -> (u16, String, Vec<u8>) {
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

fn call(sock: &Path, method: &str, path: &str, body: &str) -> (u16, Vec<u8>) {
    let (status, _, body) = finish(send(sock, method, path, body), Vec::new());
    (status, body)
}

fn events(body: &[u8]) -> Vec<StreamEvent> {
    std::str::from_utf8(body)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn turn_body(request_id: &str) -> Value {
    json!({
        "route": "chat",
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Hi"}]}],
        "max_tokens": 64,
        "request_id": request_id,
    })
}

/// Runs one turn to its end: status, head and events.
fn turn(sock: &Path, body: &Value) -> (u16, String, Vec<StreamEvent>) {
    let (status, head, body) = finish(
        send(sock, "POST", paths::MODEL_TURN, &body.to_string()),
        Vec::new(),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    (status, head, events(&body))
}

fn rejection(sock: &Path, method: &str, path: &str, body: &str) -> (u16, GatewayError) {
    let (status, body) = call(sock, method, path, body);
    let e = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&body)));
    (status, e)
}

fn state(qbd: &Path) -> StateResponse {
    let (status, body) = qb::client::call(qbd, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 200);
    serde_json::from_slice(&body).unwrap()
}

fn status_of(s: &StateResponse, login: &str) -> LoginStatus {
    s.logins.iter().find(|l| l.login == login).unwrap().status
}

fn used(s: &StateResponse, login: &str) -> f64 {
    s.logins.iter().find(|l| l.login == login).unwrap().windows[0].used
}

/// `(type, login)` of a route event, else the event's type.
fn kinds(events: &[StreamEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            StreamEvent::Route { route } => format!("route {}", route.login_label),
            StreamEvent::TextDelta { .. } => "text_delta".into(),
            StreamEvent::Thinking { .. } => "thinking".into(),
            StreamEvent::ToolCall { .. } => "tool_call".into(),
            StreamEvent::Usage { .. } => "usage".into(),
            StreamEvent::Stop { reason } => format!("stop {reason:?}"),
            StreamEvent::Error { error } => format!("error {:?}", error.class),
        })
        .collect()
}

fn last_error(events: &[StreamEvent]) -> &GatewayError {
    match events.last() {
        Some(StreamEvent::Error { error }) => error,
        other => panic!("not an error: {other:?}"),
    }
}

#[test]
fn a_turn_streams_route_content_and_stop_in_order() {
    let r = rig();
    let resets = unix_now() + 7200;
    let usage = Usage {
        input: 12,
        output: 3,
        cache_read: 0,
        cache_write: 0,
    };
    r.fake.script(
        "login-1",
        Script::Finish(
            vec![
                StreamEvent::Thinking {
                    thinking: Thinking {
                        vendor: "whatever".into(),
                        opaque: "c3ludGhldGlj".into(),
                    },
                },
                text("Hel"),
                text("lo"),
                StreamEvent::ToolCall {
                    tool_call: ToolCall {
                        id: "call_1".into(),
                        name: "read".into(),
                        input: serde_json::Map::new(),
                    },
                },
                StreamEvent::Usage { usage },
                StreamEvent::Stop {
                    reason: StopReason::End,
                },
            ],
            StopReason::ToolUse,
            window(0.25, resets),
        ),
    );
    let mut body = turn_body("turn-1");
    body["messages"] = json!([
        {"role": "assistant", "content": [
            {"type": "thinking", "vendor": "vendor-z", "opaque": "foreign"},
            {"type": "thinking", "vendor": "vendor-a", "opaque": "own"},
            {"type": "text", "text": "earlier"}]},
        {"role": "assistant", "content": [{"type": "thinking", "vendor": "vendor-z", "opaque": "x"}]},
        {"role": "user", "content": [{"type": "text", "text": "Hi"}]}
    ]);
    let (_, head, events) = turn(&r.gw, &body);
    assert!(
        head.contains("Content-Type: application/x-ndjson"),
        "{head}"
    );
    assert_eq!(
        kinds(&events),
        [
            "route login-1",
            "thinking",
            "text_delta",
            "text_delta",
            "tool_call",
            "usage",
            "stop ToolUse"
        ],
        "the adapter's own stop is dropped; the core ends the stream"
    );
    let StreamEvent::Route { route } = &events[0] else {
        unreachable!()
    };
    assert_eq!(
        (route.vendor.as_str(), route.model.as_str()),
        ("vendor-a", "model-large")
    );
    assert_ne!(route.lease, "");
    let StreamEvent::Thinking { thinking } = &events[1] else {
        unreachable!()
    };
    assert_eq!(
        thinking.vendor, "vendor-a",
        "thinking carries the picked vendor"
    );

    let calls = r.fake.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, "test-token-1");
    let sent: Vec<&Block> = calls[0]
        .2
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .collect();
    assert_eq!(
        sent.len(),
        3,
        "foreign thinking and emptied messages are dropped: {sent:?}"
    );
    assert!(matches!(sent[0], Block::Thinking { vendor, .. } if vendor == "vendor-a"));

    let s = state(&r.qbd);
    assert_eq!(s.leases, Vec::new(), "the lease is released");
    assert!(
        (used(&s, "login-1") - 0.25).abs() < 1e-9,
        "windows are reported"
    );
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Ok);
}

#[test]
fn a_usage_limit_before_the_first_event_moves_to_the_next_login() {
    let r = rig();
    let resets = unix_now() + 3600;
    r.fake.script(
        "login-1",
        Script::Fail(
            Vec::new(),
            FailureKind::UsageLimit {
                resets_at: Some(resets),
            },
            window(1.0, resets),
        ),
    );
    r.fake.script(
        "login-2",
        Script::Finish(vec![text("from 2")], StopReason::End, window(0.5, resets)),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    let logins: Vec<String> = r.fake.calls().into_iter().map(|c| c.0).collect();
    assert_eq!(logins, ["login-1", "login-2"]);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(status_of(&s, "login-2"), LoginStatus::Ok);
    assert!((used(&s, "login-2") - 0.5).abs() < 1e-9);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_failure_after_the_first_event_is_an_error_event() {
    let r = rig();
    let resets = unix_now() + 3600;
    r.fake.script(
        "login-1",
        Script::Fail(
            vec![text("partial")],
            FailureKind::UsageLimit {
                resets_at: Some(resets),
            },
            window(1.0, resets),
        ),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(
        kinds(&events),
        ["route login-1", "text_delta", "error QuotaExhausted"]
    );
    let e = last_error(&events);
    assert_eq!(e.resets_at, Some(resets));
    assert_eq!(e.tried.len(), 1);
    assert_eq!(e.tried[0].login_label.as_deref(), Some("login-1"));
    assert_eq!(r.fake.calls().len(), 1, "no second login after content");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn an_exhausted_chain_answers_quota_exhausted_with_the_nearest_reset() {
    let r = rig();
    let now = unix_now();
    let (late, early) = (now + 7200, now + 3600);
    for (login, resets) in [("login-1", late), ("login-2", early)] {
        r.fake.script(
            login,
            Script::Fail(
                Vec::new(),
                FailureKind::UsageLimit {
                    resets_at: Some(resets),
                },
                window(1.0, resets),
            ),
        );
    }
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["error QuotaExhausted"]);
    let e = last_error(&events);
    assert_eq!(e.resets_at, Some(early));
    assert!(!e.retryable);
    let tried: Vec<_> = e
        .tried
        .iter()
        .map(|a| (a.login_label.clone().unwrap(), a.class))
        .collect();
    assert_eq!(
        tried,
        [
            ("login-1".to_owned(), ErrorClass::QuotaExhausted),
            ("login-2".to_owned(), ErrorClass::QuotaExhausted)
        ]
    );
    let (status, body) = call(&r.gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 200);
    let routes: RoutesAnswer = serde_json::from_slice(&body).unwrap();
    assert_eq!(routes.routes[0].state, RouteState::Exhausted);
    assert_eq!(routes.routes[0].resets_at, Some(early));
    let next = turn(&r.gw, &turn_body("turn-2")).2;
    assert_eq!(
        last_error(&next).resets_at,
        Some(early),
        "no attempt is needed now"
    );
    assert_eq!(r.fake.calls().len(), 2);
}

#[test]
fn routes_show_where_a_turn_would_run_and_take_no_lease() {
    let r = rig();
    let (status, body) = call(&r.gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 200);
    let routes: RoutesAnswer = serde_json::from_slice(&body).unwrap();
    let shown: Vec<_> = routes
        .routes
        .iter()
        .map(|r| {
            (
                r.alias.as_str(),
                r.state,
                r.vendor.as_deref(),
                r.model.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            (
                "chat",
                RouteState::Ready,
                Some("vendor-a"),
                Some("model-large")
            ),
            ("spare", RouteState::Unavailable, None, None)
        ]
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
    assert_eq!(r.fake.calls(), Vec::new());
}

#[test]
fn cancel_stops_an_in_flight_turn_and_frees_its_slot() {
    let r = rig_with(
        1,
        "",
        &[
            ("login-1", api_key("test-token-1"), 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    r.fake
        .script("login-1", Script::Hang(vec![text("thinking...")]));
    let mut s = send(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-1").to_string(),
    );
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("text_delta") {
        let n = s.read(&mut chunk).unwrap();
        assert!(n > 0, "stream ended early");
        seen.extend_from_slice(&chunk[..n]);
    }
    let (status, busy) = rejection(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-2").to_string(),
    );
    assert_eq!(
        (status, busy.class, busy.retry_after),
        (503, ErrorClass::Overloaded, Some(1))
    );
    let (status, dup) = rejection(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-1").to_string(),
    );
    assert_eq!(
        (status, dup.class),
        (400, ErrorClass::BadRequest),
        "{dup:?}"
    );

    let (status, body) = call(
        &r.gw,
        "POST",
        paths::MODEL_CANCEL,
        r#"{"request_id":"turn-1"}"#,
    );
    assert_eq!(status, 200);
    let answer: CancelAnswer = serde_json::from_slice(&body).unwrap();
    assert!(answer.cancelled);
    let (status, _, rest) = finish(s, seen);
    assert_eq!(status, 200);
    assert_eq!(
        kinds(&events(&rest)),
        ["route login-1", "text_delta"],
        "a cut stream has no stop or error"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new(), "the lease is released");
    let (_, body) = call(
        &r.gw,
        "POST",
        paths::MODEL_CANCEL,
        r#"{"request_id":"turn-1"}"#,
    );
    let answer: CancelAnswer = serde_json::from_slice(&body).unwrap();
    assert!(!answer.cancelled, "nothing runs any more");
    let (_, _, events) = turn(&r.gw, &turn_body("turn-3"));
    assert_eq!(
        kinds(&events).last().unwrap(),
        "stop End",
        "the slot is free again"
    );
}

#[test]
fn malformed_and_oversized_requests_are_rejected_before_any_work() {
    let r = rig();
    let big = json!({"route": "chat", "messages": [{"role": "user", "content": [
        {"type": "text", "text": "x".repeat(70_000)}]}], "max_tokens": 1, "request_id": "t"});
    let mut unknown = turn_body("t");
    unknown["route"] = json!("nope");
    let mut extra = turn_body("t");
    extra["model"] = json!("model-large");
    let mut outside = turn_body("t");
    outside["messages"][0]["content"] = json!([
        {"type": "image", "media_type": "image/png", "path": format!("{}/creds/login-1.json", r.dir.display())}
    ]);
    let cases = [
        (
            "POST",
            paths::MODEL_TURN,
            big.to_string(),
            413,
            "over 65536 bytes",
        ),
        (
            "POST",
            paths::MODEL_TURN,
            unknown.to_string(),
            400,
            "unknown route alias `nope`",
        ),
        (
            "POST",
            paths::MODEL_TURN,
            extra.to_string(),
            400,
            "unknown field `model`",
        ),
        ("POST", paths::MODEL_TURN, "{".into(), 400, "EOF"),
        (
            "POST",
            paths::MODEL_TURN,
            outside.to_string(),
            400,
            "outside the gateway's media_dirs",
        ),
        ("GET", paths::MODEL_TURN, String::new(), 405, "method"),
        (
            "GET",
            "/v1/model/nope",
            String::new(),
            404,
            "no such endpoint",
        ),
        ("POST", paths::MODEL_CANCEL, "{}".into(), 400, "request_id"),
    ];
    for (method, path, body, want_status, want) in cases {
        let (status, e) = rejection(&r.gw, method, path, &body);
        assert_eq!(
            (status, e.class),
            (want_status, ErrorClass::BadRequest),
            "{path} {want}"
        );
        assert!(e.message.as_deref().unwrap().contains(want), "{e:?}");
    }
    assert_eq!(r.fake.calls(), Vec::new());
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn a_peer_that_is_not_an_allowed_client_is_refused() {
    let foreign = own_uid().wrapping_add(1);
    let r = rig_with(
        4,
        &format!("\n[[clients]]\nname = \"client-a\"\nuid = {foreign}\n"),
        &[("login-1", api_key("test-token-1"), 0o600)],
    );
    let (status, e) = rejection(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("t").to_string(),
    );
    assert_eq!((status, e.class), (401, ErrorClass::Auth));
    let (status, _) = rejection(&r.gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 401);
    assert_eq!(r.fake.calls(), Vec::new());
}

#[test]
fn a_rejected_token_is_refreshed_and_the_turn_retried() {
    let oauth = |access: &str| {
        format!(
            r#"{{"type":"oauth_anthropic","access_token":"{access}","refresh_token":"refresh-0","expires_at":{}}}"#,
            unix_now() + 3600
        )
    };
    let r = rig_with(4, "", &[("login-1", oauth("access-0"), 0o600)]);
    r.fake.script(
        "login-1",
        Script::Fail(Vec::new(), FailureKind::Auth, Vec::new()),
    );
    r.fake.script(
        "login-1",
        Script::Finish(
            vec![text("ok")],
            StopReason::End,
            window(0.1, unix_now() + 3600),
        ),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
    let secrets: Vec<String> = r.fake.calls().into_iter().map(|c| c.1).collect();
    assert_eq!(secrets, ["access-0", "access-1"]);
    assert_eq!(r.refreshes.load(Ordering::SeqCst), 1);
    let stored = std::fs::read_to_string(r.dir.join("creds/login-1.json")).unwrap();
    assert!(stored.contains("access-1"));
    assert_eq!(status_of(&state(&r.qbd), "login-1"), LoginStatus::Ok);
}

#[test]
fn an_unusable_credential_file_marks_its_login_and_the_turn_moves_on() {
    let r = rig_with(
        4,
        "",
        &[
            ("login-1", api_key("test-token-1"), 0o644),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    let logins: Vec<String> = r.fake.calls().into_iter().map(|c| c.0).collect();
    assert_eq!(logins, ["login-2"], "the open file is never used");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn the_binary_serves_the_gateway_and_never_logs_a_secret() {
    const MARK: &str = "test-token-9c1e";
    let exe = env!("CARGO_BIN_EXE_qb");
    let dir = temp_dir("gwbin");
    credentials(
        &dir,
        &[
            ("login-1", api_key(MARK), 0o644),
            (
                "login-2",
                format!(r#"{{"type":"api_key","key":"{MARK}","x":1}}"#),
                0o600,
            ),
        ],
    );
    let qbd_config = dir.join("qbd.toml");
    std::fs::write(&qbd_config, QBD).unwrap();
    let qbd = dir.join("qb.sock");
    let _qbd = start_daemon(Path::new(exe), &qbd_config, &qbd, Stdio::null());
    let config = dir.join("gateway.toml");
    std::fs::write(&config, gateway_toml(&dir, &qbd, 2, "")).unwrap();
    let mut child = Command::new(exe)
        .args(["gateway", "--config"])
        .arg(&config)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = stderr_lines(&mut child);
    let _gateway = Daemon(child);
    let gw = dir.join("gw.sock");
    wait_for(&gw);

    let (status, _, body) = finish(
        send(
            &gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body("turn-1").to_string(),
        ),
        Vec::new(),
    );
    assert_eq!(status, 200);
    let events = events(&body);
    let e = last_error(&events);
    assert_eq!(e.class, ErrorClass::Auth, "{e:?}");
    assert_eq!(
        e.tried.len(),
        4,
        "two 401 reports per login make it auth_dead: {e:?}"
    );
    assert!(!String::from_utf8_lossy(&body).contains(MARK));
    let mut logged = Vec::new();
    while let Some(line) = line_with(&lines, "", Duration::from_millis(500)) {
        logged.push(line);
    }
    assert!(logged.iter().any(|l| l.contains("too open")), "{logged:?}");
    assert!(
        logged.iter().any(|l| l.contains("missing or invalid")),
        "{logged:?}"
    );
    assert!(logged.iter().all(|l| !l.contains(MARK)), "{logged:?}");
    let s: StateResponse = {
        let (status, body) = qb::client::call(&qbd, "GET", paths::STATE, None, None).unwrap();
        assert_eq!(status, 200);
        serde_json::from_slice(&body).unwrap()
    };
    assert_eq!(s.leases, Vec::new());
    assert_eq!(status_of(&s, "login-2"), LoginStatus::AuthDead);
}
