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
use std::time::Duration;

use qb::auth::Gate;
use qb::gateway::config::CredentialKind;
use qb::gateway::core::{Cancel, Gateway};
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

use common::{Daemon, line_with, start_daemon, stderr_lines, temp_dir, wait_for};

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
                // Blocks like a vendor read until the cancel hook unblocks it.
                let (tx, rx) = std::sync::mpsc::channel::<()>();
                cancel.on_cancel(Box::new(move || {
                    let _ = tx.send(());
                }));
                let woke = rx.recv_timeout(Duration::from_secs(10)).is_ok();
                assert!(woke, "the cancel hook did not run");
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

/// The gateway config for `dir` with credential kinds `kinds` of login-1 and login-2, and
/// `extra` appended.
fn gateway_toml(dir: &Path, qbd: &Path, max_turns: u32, kinds: [&str; 2], extra: &str) -> String {
    format!(
        r#"socket = "{dir}/gw.sock"
qbd_socket = "{qbd}"
max_turns = {max_turns}
max_request_bytes = 131072

[[logins]]
name = "login-1"
kind = "{k1}"
credentials = "{dir}/creds/login-1.json"

[[logins]]
name = "login-2"
kind = "{k2}"
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
        qbd = qbd.display(),
        k1 = kinds[0],
        k2 = kinds[1],
    )
}

/// Writes the credential files `(login, contents, mode)` into `dir/creds`.
fn credentials(dir: &Path, files: &[(&str, String, u32)]) {
    let creds = dir.join("creds");
    std::fs::create_dir_all(&creds).unwrap();
    for (login, contents, mode) in files {
        let f = creds.join(format!("{login}.json"));
        std::fs::write(&f, contents).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
}

/// The kind a credential file's contents declare.
fn kind_of(contents: &str) -> &'static str {
    if contents.contains("oauth_anthropic") {
        "oauth_anthropic"
    } else {
        "api_key"
    }
}

fn rig_with(max_turns: u32, files: &[(&str, String, u32)]) -> Rig {
    rig_as(max_turns, files, "", own_uid())
}

fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A rig whose gateway config ends with `extra` and whose gateway runs as `gateway_uid`.
fn rig_as(max_turns: u32, files: &[(&str, String, u32)], extra: &str, gateway_uid: u32) -> Rig {
    let dir = temp_dir("gw");
    credentials(&dir, files);
    let qbd = start_qbd(&dir);
    let kind = |i: usize| files.get(i).map_or("api_key", |f| kind_of(&f.1));
    let text = gateway_toml(&dir, &qbd, max_turns, [kind(0), kind(1)], extra);
    let config = qb::gateway::config::parse(Path::new("gateway.toml"), &text).unwrap();
    let gw = config.socket.clone();
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        config,
        vec![
            (CredentialKind::ApiKey, Box::new(Shared(Arc::clone(&fake)))),
            (
                CredentialKind::OauthAnthropic,
                Box::new(Shared(Arc::clone(&fake))),
            ),
        ],
        Box::new(Counting(Arc::clone(&refreshes))),
        None,
    );
    let listener = UnixListener::bind(&gw).unwrap();
    std::thread::spawn(move || front::serve(&listener, &Arc::new(gateway), gateway_uid));
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
    assert!(
        e.retryable,
        "a wait ends; quota_exhausted is retryable at resets_at"
    );
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
fn routes_show_the_state_of_their_logins_and_take_no_lease() {
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
            ("chat", RouteState::Ready, None, None),
            (
                "spare",
                RouteState::Unavailable,
                Some("vendor-b"),
                Some("model-b")
            )
        ]
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
    assert_eq!(r.fake.calls(), Vec::new());
}

#[test]
fn cancel_stops_an_in_flight_turn_and_frees_its_slot() {
    let r = rig_with(
        1,
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
        (429, ErrorClass::Overloaded, Some(1))
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
    let events = events(&rest);
    assert_eq!(
        kinds(&events),
        ["route login-1", "text_delta", "error Cancelled"]
    );
    assert!(!last_error(&events).retryable);
    let s = state(&r.qbd);
    assert_eq!(s.leases, Vec::new(), "the lease is released");
    assert_eq!(
        status_of(&s, "login-1"),
        LoginStatus::Unknown,
        "a cancelled stream does not mark the login"
    );
    let (status, gone) = rejection(
        &r.gw,
        "POST",
        paths::MODEL_CANCEL,
        r#"{"request_id":"turn-1"}"#,
    );
    assert_eq!((status, gone.class), (404, ErrorClass::BadRequest));
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
        {"type": "text", "text": "x".repeat(140_000)}]}], "max_tokens": 1, "request_id": "t"});
    let mut unknown = turn_body("t");
    unknown["route"] = json!("nope");
    let mut extra = turn_body("t");
    extra["model"] = json!("model-large");
    let mut by_path = turn_body("t");
    by_path["messages"][0]["content"] = json!([
        {"type": "image", "media_type": "image/png", "path": format!("{}/creds/login-1.json", r.dir.display())}
    ]);
    let cases = [
        (
            "POST",
            paths::MODEL_TURN,
            big.to_string(),
            413,
            "over 131072 bytes",
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
            by_path.to_string(),
            400,
            "images must be sent inline",
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
fn only_the_turn_path_takes_a_body_over_64_kib() {
    let r = rig();
    let pad = "x".repeat(70_000);
    let cancel = format!(r#"{{"request_id":"{pad}"}}"#);
    let (status, e) = rejection(&r.gw, "POST", paths::MODEL_CANCEL, &cancel);
    assert_eq!((status, e.class), (413, ErrorClass::BadRequest));
    assert!(
        e.message.as_deref().unwrap().contains("over 65536 bytes"),
        "{e:?}"
    );
    let mut big = turn_body("turn-1");
    big["messages"][0]["content"][0]["text"] = json!(pad);
    let (_, _, events) = turn(&r.gw, &big);
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
}

#[test]
fn a_foreign_peer_is_refused_before_its_body_is_read() {
    let files = [("login-1", api_key("test-token-1"), 0o600)];
    let r = rig_as(4, &files, "", own_uid() + 1);
    // A head that announces a body it never sends: the answer must not wait for it.
    let mut s = UnixStream::connect(&r.gw).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    write!(
        s,
        "POST {} HTTP/1.1\r\nHost: qb\r\nContent-Length: 60000\r\n\r\n",
        paths::MODEL_TURN
    )
    .unwrap();
    let mut answer = Vec::new();
    let _ = s.read_to_end(&mut answer);
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer:?}");
    assert!(answer.contains(r#""class":"auth""#), "{answer}");
    let (status, e) = rejection(&r.gw, "GET", paths::HEALTH, "");
    assert_eq!((status, e.class), (401, ErrorClass::Auth));
    assert_eq!(r.fake.calls(), Vec::new());
}

#[test]
fn a_configured_client_uid_is_served() {
    let files = [("login-1", api_key("test-token-1"), 0o600)];
    let extra = format!("\n[[clients]]\nname = \"client-a\"\nuid = {}\n", own_uid());
    let r = rig_as(4, &files, &extra, own_uid() + 1);
    let (status, _) = call(&r.gw, "GET", paths::HEALTH, "");
    assert_eq!(status, 200);
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
}

#[test]
fn a_request_must_arrive_within_the_read_deadline() {
    let r = rig();
    let mut s = UnixStream::connect(&r.gw).unwrap();
    let body = turn_body("turn-1").to_string();
    write!(
        s,
        "POST {} HTTP/1.1\r\nHost: qb\r\nContent-Length: {}\r\n\r\n",
        paths::MODEL_TURN,
        body.len()
    )
    .unwrap();
    // One byte at a time, each well within the per-read timeout.
    let started = std::time::Instant::now();
    let mut cut = false;
    for b in body.bytes().take(40) {
        if s.write_all(&[b]).is_err() {
            cut = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let took = started.elapsed();
    assert!(cut, "the gateway kept reading for {took:?}");
    assert!(
        took >= front::READ_DEADLINE && took < front::READ_DEADLINE + Duration::from_secs(3),
        "{took:?}"
    );
    assert_eq!(r.fake.calls(), Vec::new());
}

#[test]
fn health_answers_and_only_the_starting_caller_may_cancel() {
    let r = rig();
    let (status, body) = call(&r.gw, "GET", paths::HEALTH, "");
    assert_eq!(status, 200);
    let health: qb_proto::HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(health.api_version, "v1");

    let config = qb::gateway::config::parse(
        Path::new("gateway.toml"),
        &gateway_toml(&r.dir, &r.qbd, 4, ["api_key", "api_key"], ""),
    )
    .unwrap();
    let gateway = Gateway::new(config, Vec::new(), Box::new(Counting(Arc::default())), None);
    let req: TurnRequest = serde_json::from_value(turn_body("turn-9")).unwrap();
    let admitted = gateway.admit("client-a", &req).unwrap();
    assert_eq!(gateway.cancel("client-b", "turn-9"), Cancel::Forbidden);
    assert!(!admitted.cancel_token().is_cancelled());
    assert_eq!(gateway.cancel("client-a", "turn-8"), Cancel::Unknown);
    let waiter = std::thread::spawn(move || {
        while !admitted.cancel_token().is_cancelled() {
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(admitted);
    });
    assert_eq!(gateway.cancel("client-a", "turn-9"), Cancel::Cancelled);
    waiter.join().unwrap();
}

#[test]
fn a_turn_that_sent_its_last_event_can_no_longer_be_cancelled() {
    let r = rig();
    let config = qb::gateway::config::parse(
        Path::new("gateway.toml"),
        &gateway_toml(&r.dir, &r.qbd, 1, ["api_key", "api_key"], ""),
    )
    .unwrap();
    let fake = Arc::new(Fake::default());
    let upstream: Box<dyn Upstream> = Box::new(Shared(Arc::clone(&fake)));
    let gateway = Gateway::new(
        config,
        vec![(CredentialKind::ApiKey, upstream)],
        Box::new(Counting(Arc::default())),
        None,
    );
    let req: TurnRequest = serde_json::from_value(turn_body("turn-1")).unwrap();
    let admitted = gateway.admit("client-a", &req).unwrap();
    let (mut cancel, mut slot_free) = (None, None);
    gateway.run(&admitted, &req, &mut |event| {
        if matches!(event, StreamEvent::Stop { .. }) {
            // The client is still being written to; the turn itself is over.
            cancel = Some(gateway.cancel("client-a", "turn-1"));
            let next: TurnRequest = serde_json::from_value(turn_body("turn-2")).unwrap();
            slot_free = Some(gateway.admit("client-a", &next).is_ok());
        }
        Flow::Continue
    });
    assert_eq!(cancel, Some(Cancel::Unknown));
    assert_eq!(slot_free, Some(true), "max_turns is 1 and the slot is free");
    assert!(!admitted.cancel_token().is_cancelled());
}

#[test]
fn a_rejected_token_is_refreshed_and_the_turn_retried() {
    let oauth = |access: &str| {
        format!(
            r#"{{"type":"oauth_anthropic","access_token":"{access}","refresh_token":"refresh-0","expires_at":{}}}"#,
            unix_now() + 3600
        )
    };
    let r = rig_with(4, &[("login-1", oauth("access-0"), 0o600)]);
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
    assert_eq!(state(&r.qbd).leases, Vec::new(), "one lease, released");
    let secrets: Vec<String> = r.fake.calls().into_iter().map(|c| c.1).collect();
    assert_eq!(secrets, ["access-0", "access-1"]);
    assert_eq!(r.refreshes.load(Ordering::SeqCst), 1);
    let stored = std::fs::read_to_string(r.dir.join("creds/login-1.json")).unwrap();
    assert!(stored.contains("access-1"));
    assert_eq!(status_of(&state(&r.qbd), "login-1"), LoginStatus::Ok);
}

#[test]
fn an_unusable_credential_file_is_never_used_and_the_turn_moves_on() {
    let r = rig_with(
        4,
        &[
            ("login-1", api_key("test-token-1"), 0o644),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let (_, _, first) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&first), ["route login-2", "text_delta", "stop End"]);
    let logins: Vec<String> = r.fake.calls().into_iter().map(|c| c.0).collect();
    assert_eq!(logins, ["login-2"], "the open file is never used");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
    let (_, _, second) = turn(&r.gw, &turn_body("turn-2"));
    assert_eq!(kinds(&second), ["route login-2", "text_delta", "stop End"]);
}

#[test]
fn a_401_after_the_refresh_moves_to_the_next_login_in_the_same_turn() {
    let oauth = format!(
        r#"{{"type":"oauth_anthropic","access_token":"access-0","refresh_token":"refresh-0","expires_at":{}}}"#,
        unix_now() + 3600
    );
    let r = rig_with(
        4,
        &[
            ("login-1", oauth, 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    for _ in 0..2 {
        r.fake.script(
            "login-1",
            Script::Fail(Vec::new(), FailureKind::Auth, Vec::new()),
        );
    }
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    let calls: Vec<(String, String)> = r.fake.calls().into_iter().map(|c| (c.0, c.1)).collect();
    let calls: Vec<(&str, &str)> = calls
        .iter()
        .map(|(l, s)| (l.as_str(), s.as_str()))
        .collect();
    assert_eq!(
        calls,
        [
            ("login-1", "access-0"),
            ("login-1", "access-1"),
            ("login-2", "test-token-2")
        ]
    );
    assert_eq!(r.refreshes.load(Ordering::SeqCst), 1);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_vendor_failure_before_the_first_event_repicks_avoiding_the_vendor() {
    let r = rig();
    r.fake.script(
        "login-1",
        Script::Fail(
            Vec::new(),
            FailureKind::Overloaded {
                retry_after: Some(30),
            },
            Vec::new(),
        ),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["error Overloaded"]);
    let e = last_error(&events);
    assert!(e.retryable);
    assert_eq!(e.tried.len(), 1, "no other vendor serves the route: {e:?}");
    assert_eq!(r.fake.calls().len(), 1, "login-2 is of the same vendor");
    let s = state(&r.qbd);
    assert_eq!(
        status_of(&s, "login-1"),
        LoginStatus::Unknown,
        "error marks nothing"
    );
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
    let kinds = ["api_key", "api_key"];
    std::fs::write(&config, gateway_toml(&dir, &qbd, 2, kinds, "")).unwrap();
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
    let mode = std::fs::metadata(&gw).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the socket is the owner's only by default");

    // This build links no vendor adapter: a turn picks, finds none for the login's kind,
    // releases the lease and ends with `unavailable`, before any credential is read.
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
    assert_eq!(e.class, ErrorClass::Unavailable, "{e:?}");
    assert!(
        e.message.as_deref().unwrap().contains("no adapter"),
        "{e:?}"
    );
    assert!(!String::from_utf8_lossy(&body).contains(MARK));
    let (status, body) = call(&gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let mut logged = Vec::new();
    while let Some(line) = line_with(&lines, "", Duration::from_millis(500)) {
        logged.push(line);
    }
    assert!(
        logged.iter().any(|l| l.contains("listening on")),
        "{logged:?}"
    );
    assert!(
        logged.iter().any(|l| l.contains("no adapter")),
        "{logged:?}"
    );
    assert!(logged.iter().all(|l| !l.contains(MARK)), "{logged:?}");
    let s: StateResponse = {
        let (status, body) = qb::client::call(&qbd, "GET", paths::STATE, None, None).unwrap();
        assert_eq!(status, 200);
        serde_json::from_slice(&body).unwrap()
    };
    assert_eq!(s.leases, Vec::new());
}
