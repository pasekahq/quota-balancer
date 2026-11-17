//! Contract tests of the model gateway: `/v1/model/*` over a real unix socket, with a real qbd
//! in-process and a scripted fake vendor adapter, or the Anthropic adapter against a scripted
//! vendor endpoint on loopback TCP.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qb::auth::Gate;
use qb::gateway::anthropic::Anthropic;
use qb::gateway::config::Api;
use qb::gateway::core::{Cancel, Gateway, Upstreams};
use qb::gateway::creds::{RefreshError, Refreshed, Refresher};
use qb::gateway::front;
use qb::gateway::oauth::AnthropicOauth;
use qb::gateway::openai_upstream::Openai;
use qb::gateway::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Flow, Picked, Sink, Upstream,
};
use qb::hooks::Runner;
use qb::journal::Journal;
use qb::server::unix_now;
use qb_anthropic::request::identity;
use qb_core::Core;
use qb_openai::request::identity as openai_identity;
use qb_proto::{
    Block, CancelAnswer, ErrorClass, GatewayError, LoginStatus, RouteState, RoutesAnswer,
    StateResponse, StopReason, StreamEvent, Thinking, ToolCall, TurnRequest, Usage, WindowReport,
    paths,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

mod common;

use common::vendor::{Answer, Received, Vendor, fixture_of};
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
    /// Emit a text event every 20 ms until the sink stops it; at most 10 s.
    Drip,
    /// Fail as a refused request with a message that quotes the credential.
    Leak,
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
            Script::Leak => Err(Failure::new(
                FailureKind::BadRequest,
                format!("vendor refused key {}", credential.secret()),
            )),
            Script::Drip => {
                for _ in 0..500 {
                    if sink(text("drop")) == Flow::Stop {
                        return Err(Failure::new(FailureKind::Cancelled, "stopped"));
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                panic!("the sink never stopped the stream");
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

/// Hands out `access-N` and counts its calls. The refresh token `refresh-down` fails as an
/// unreachable endpoint, `refresh-revoked` as a refused token.
struct Counting(Arc<AtomicUsize>);

impl Refresher for Counting {
    fn refresh(&self, _: &str, refresh_token: &str) -> Result<Refreshed, RefreshError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some(rejected) = match refresh_token {
            "refresh-down" => Some(false),
            "refresh-revoked" => Some(true),
            _ => None,
        } {
            return Err(RefreshError {
                rejected,
                message: "scripted refresh failure".into(),
            });
        }
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

/// A qbd of config `text` on a fresh socket in `dir`.
fn start_qbd(dir: &Path, text: &str) -> PathBuf {
    let sock = dir.join("qb.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let config = qb::config::parse(Path::new("qbd.toml"), text).unwrap();
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

/// The keys of an `api_key` login of the `anthropic` API family.
const ANTHROPIC_KEY: &str = "kind = \"api_key\"\napi = \"anthropic\"";

/// The gateway config for `dir` with the keys `logins` of login-1 and login-2 besides `name` and
/// `credentials`, and `extra` appended.
fn gateway_toml(dir: &Path, qbd: &Path, max_turns: u32, logins: [&str; 2], extra: &str) -> String {
    format!(
        r#"socket = "{dir}/gw.sock"
qbd_socket = "{qbd}"
max_turns = {max_turns}
max_request_bytes = 131072

[[logins]]
name = "login-1"
{k1}
credentials = "{dir}/creds/login-1.json"

[[logins]]
name = "login-2"
{k2}
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
        k1 = logins[0],
        k2 = logins[1],
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

/// The login keys of the kind a credential file's contents declare, of the `anthropic` family.
fn keys_of(contents: &str) -> &'static str {
    if contents.contains("oauth_anthropic") {
        "kind = \"oauth_anthropic\""
    } else {
        ANTHROPIC_KEY
    }
}

fn rig_with(max_turns: u32, files: &[(&str, String, u32)]) -> Rig {
    rig_as(max_turns, files, "", own_uid())
}

fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// A rig whose gateway runs as `gateway_uid`, with `extra` in its config: appended when it is
/// a table, else put first as top-level keys.
fn rig_as(max_turns: u32, files: &[(&str, String, u32)], extra: &str, gateway_uid: u32) -> Rig {
    rig_on(max_turns, files, extra, gateway_uid, None)
}

/// [`rig_as`] with the Messages front also on `loopback`.
fn rig_on(
    max_turns: u32,
    files: &[(&str, String, u32)],
    extra: &str,
    gateway_uid: u32,
    loopback: Option<TcpListener>,
) -> Rig {
    let dir = temp_dir("gw");
    credentials(&dir, files);
    let qbd = start_qbd(&dir, QBD);
    let keys = |i: usize| files.get(i).map_or(ANTHROPIC_KEY, |f| keys_of(&f.1));
    let text = if extra.trim_start().starts_with('[') {
        gateway_toml(&dir, &qbd, max_turns, [keys(0), keys(1)], extra)
    } else {
        let toml = gateway_toml(&dir, &qbd, max_turns, [keys(0), keys(1)], "");
        format!("{extra}\n{toml}")
    };
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gw = serve_gateway(
        &text,
        vec![(Api::Anthropic, Box::new(Shared(Arc::clone(&fake))))],
        Box::new(Counting(Arc::clone(&refreshes))),
        gateway_uid,
        loopback,
    );
    Rig {
        dir,
        qbd,
        gw,
        fake,
        refreshes,
    }
}

/// Serves a gateway of config `text` with `upstreams` as `gateway_uid`, and its Messages front
/// on `loopback` when set; its socket.
fn serve_gateway(
    text: &str,
    upstreams: Upstreams,
    refresher: Box<dyn Refresher>,
    gateway_uid: u32,
    loopback: Option<TcpListener>,
) -> PathBuf {
    let config = qb::gateway::config::parse(Path::new("gateway.toml"), text).unwrap();
    let gw = config.socket.clone();
    let gateway = Gateway::new(config, upstreams, refresher, None);
    let listener = UnixListener::bind(&gw).unwrap();
    std::thread::spawn(move || {
        front::serve(
            &listener,
            loopback.as_ref(),
            &Arc::new(gateway),
            gateway_uid,
        )
    });
    gw
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

/// Status and plain body of the complete answer `raw`.
fn finish_raw(raw: &[u8]) -> (u16, Vec<u8>) {
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..at].to_vec()).unwrap();
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        raw[at + 4..].to_vec(),
    )
}

/// Status, head and (dechunked) body of a complete answer.
fn finish(mut s: impl Read, already: Vec<u8>) -> (u16, String, Vec<u8>) {
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
    let answer = refused(
        &r.gw,
        &format!(
            "POST {} HTTP/1.1\r\nHost: qb\r\nContent-Length: 60000\r\n\r\n",
            paths::MODEL_TURN
        ),
    );
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer:?}");
    assert!(answer.contains(r#""class":"auth""#), "{answer}");
    let answer = refused(
        &r.gw,
        &format!(
            "GET {} HTTP/1.1\r\nHost: qb\r\nContent-Length: 0\r\n\r\n",
            paths::HEALTH
        ),
    );
    let (status, body) = finish_raw(answer.as_bytes());
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (401, ErrorClass::Auth));
    assert_eq!(r.fake.calls(), Vec::new());
}

/// The whole answer to `head` from a gateway that refuses the peer at accept. The gateway may
/// answer and close before the head is fully written, so a failed write (EPIPE) is expected.
fn refused(sock: &Path, head: &str) -> String {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let _ = s.write_all(head.as_bytes());
    let mut answer = Vec::new();
    let _ = s.read_to_end(&mut answer);
    String::from_utf8_lossy(&answer).into_owned()
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
        &gateway_toml(&r.dir, &r.qbd, 4, [ANTHROPIC_KEY; 2], ""),
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
        &gateway_toml(&r.dir, &r.qbd, 1, [ANTHROPIC_KEY; 2], ""),
    )
    .unwrap();
    let fake = Arc::new(Fake::default());
    let upstream: Box<dyn Upstream> = Box::new(Shared(Arc::clone(&fake)));
    let gateway = Gateway::new(
        config,
        vec![(Api::Anthropic, upstream)],
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
fn connections_beyond_the_cap_get_429_from_the_main_thread() {
    let r = rig_with(
        1,
        &[
            ("login-1", api_key("test-token-1"), 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    // max_turns 1 plus the two extra connections; these send nothing and hold their threads.
    let cap = 1 + front::EXTRA_CONNECTIONS;
    let idle: Vec<UnixStream> = (0..cap)
        .map(|_| UnixStream::connect(&r.gw).unwrap())
        .collect();
    // The main thread answers without waiting for the request, so a write or, rarely, the
    // read may fail; such a try is repeated.
    let health = || {
        for _ in 0..50 {
            let mut s = UnixStream::connect(&r.gw).unwrap();
            let _ = s.write_all(b"GET /v1/health HTTP/1.1\r\nHost: qb\r\n\r\n");
            let mut raw = Vec::new();
            if s.read_to_end(&mut raw).is_ok() && !raw.is_empty() {
                return finish_raw(&raw);
            }
        }
        panic!("no answer");
    };
    let (status, body) = health();
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        (status, e.class, e.retryable),
        (429, ErrorClass::Overloaded, true)
    );
    assert_eq!(e.message.as_deref(), Some("too many connections"));
    drop(idle);
    let mut status = 0;
    for _ in 0..100 {
        status = health().0;
        if status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(status, 200, "closed connections free their slots");
}

#[test]
fn a_turn_ends_after_max_attempts_picks() {
    let files = [
        ("login-1", api_key("test-token-1"), 0o600),
        ("login-2", api_key("test-token-2"), 0o600),
    ];
    let r = rig_as(4, &files, "max_attempts = 1", own_uid());
    r.fake.script(
        "login-1",
        Script::Fail(
            Vec::new(),
            FailureKind::RateLimited { retry_after: None },
            Vec::new(),
        ),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["error Overloaded"]);
    let e = last_error(&events);
    assert!(e.retryable);
    assert!(
        e.message
            .as_deref()
            .unwrap()
            .contains("gave up after 1 attempts"),
        "{e:?}"
    );
    assert_eq!(e.tried.len(), 1);
    assert_eq!(r.fake.calls().len(), 1, "login-2 is not tried");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::RateLimited);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_client_that_closes_its_connection_cancels_its_turn() {
    let r = rig();
    r.fake.script("login-1", Script::Drip);
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
    assert!(state(&r.qbd).leases.len() == 1, "the turn holds its lease");
    drop(s);
    let mut leases = 1;
    for _ in 0..250 {
        leases = state(&r.qbd).leases.len();
        if leases == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(leases, 0, "the lease is released");
    assert_eq!(
        status_of(&state(&r.qbd), "login-1"),
        LoginStatus::Unknown,
        "a stream that started marks nothing on its login"
    );
    let (_, _, next) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(
        kinds(&next).last().unwrap(),
        "stop End",
        "the request_id is free"
    );
}

/// An OAuth credential file whose token expires now, with `refresh` as its refresh token.
fn expiring_oauth(refresh: &str) -> String {
    format!(
        r#"{{"type":"oauth_anthropic","access_token":"access-0","refresh_token":"{refresh}","expires_at":{}}}"#,
        unix_now()
    )
}

#[test]
fn a_refresh_that_cannot_reach_the_vendor_ends_the_turn_retryable() {
    let r = rig_with(
        4,
        &[
            ("login-1", expiring_oauth("refresh-down"), 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["error Unavailable"]);
    assert!(last_error(&events).retryable);
    assert_eq!(r.fake.calls(), Vec::new(), "the expired token is not sent");
    let s = state(&r.qbd);
    assert_eq!(
        status_of(&s, "login-1"),
        LoginStatus::Unknown,
        "reported as error"
    );
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_refused_refresh_token_kills_the_login_and_the_turn_moves_on() {
    let r = rig_with(
        4,
        &[
            ("login-1", expiring_oauth("refresh-revoked"), 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
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

/// Runs `f` with this process's stderr in a file and returns what was written there.
fn stderr_of(f: impl FnOnce()) -> String {
    stderr_until("", f)
}

/// [`stderr_of`] that keeps stderr in the file until it holds `needle`, for at most 5 s after
/// `f` returned.
fn stderr_until(needle: &str, f: impl FnOnce()) -> String {
    use std::os::fd::AsFd;
    static ONE: Mutex<()> = Mutex::new(());
    let _one = ONE.lock().unwrap();
    let path = temp_dir("stderr").join("stderr.log");
    let file = std::fs::File::create(&path).unwrap();
    let saved = rustix::io::dup(std::io::stderr().as_fd()).unwrap();
    rustix::stdio::dup2_stderr(&file).unwrap();
    f();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !std::fs::read_to_string(&path).unwrap().contains(needle)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    rustix::stdio::dup2_stderr(&saved).unwrap();
    std::fs::read_to_string(&path).unwrap()
}

#[test]
fn a_credential_an_adapter_quotes_reaches_neither_the_log_nor_the_client() {
    const MARK: &str = "test-token-5b2d";
    let r = rig_with(4, &[("login-1", api_key(MARK), 0o600)]);
    r.fake.script("login-1", Script::Leak);
    let mut events = Vec::new();
    let logged = stderr_of(|| events = turn(&r.gw, &turn_body("turn-1")).2);
    assert_eq!(kinds(&events), ["error BadRequest"]);
    let message = last_error(&events).message.clone().unwrap();
    assert!(message.contains("vendor refused key"), "{message}");
    assert!(!message.contains(MARK), "{message}");
    assert!(logged.contains("vendor refused key"), "{logged}");
    assert!(!logged.contains(MARK), "{logged}");
    assert_eq!(r.fake.calls()[0].1, MARK, "the adapter got the credential");
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
            ("login-2", api_key(MARK), 0o600),
        ],
    );
    let qbd_config = dir.join("qbd.toml");
    std::fs::write(&qbd_config, QBD).unwrap();
    let qbd = dir.join("qb.sock");
    let _qbd = start_daemon(Path::new(exe), &qbd_config, &qbd, Stdio::null());
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let keys = format!("{ANTHROPIC_KEY}\nbase_url = \"http://{closed}\"");
    // A free port the gateway binds itself, before its sandbox.
    let listen = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let front = fronts(&format!(
        "listen = \"{listen}\"\ntoken_sha256 = \"{CLIENT_TOKEN_SHA256}\""
    ));
    let config = dir.join("gateway.toml");
    std::fs::write(&config, gateway_toml(&dir, &qbd, 2, [&keys, &keys], &front)).unwrap();
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

    // login-1's open file is never used; login-2's key goes to the linked Anthropic adapter,
    // whose connect to a closed port (or one the sandbox refuses) ends the turn `unavailable`.
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
    let tried: Vec<(Option<&str>, ErrorClass)> = e
        .tried
        .iter()
        .map(|a| (a.login_label.as_deref(), a.class))
        .collect();
    assert_eq!(
        tried,
        [
            (Some("login-1"), ErrorClass::Auth),
            (Some("login-2"), ErrorClass::Unavailable)
        ]
    );
    assert!(!String::from_utf8_lossy(&body).contains(MARK));
    let (status, body) = call(&gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));

    loopback_admits_the_client_token_only(listen);
    let mut logged = Vec::new();
    while let Some(line) = line_with(&lines, "", Duration::from_millis(500)) {
        logged.push(line);
    }
    assert!(
        logged.iter().any(|l| l.contains("listening on")),
        "{logged:?}"
    );
    let serving = format!("serving the HTTP fronts on {listen}");
    assert!(logged.iter().any(|l| l.contains(&serving)), "{logged:?}");
    assert!(
        logged
            .iter()
            .any(|l| l.contains("login-2: unavailable: vendor request failed")),
        "{logged:?}"
    );
    assert!(logged.iter().all(|l| !l.contains(MARK)), "{logged:?}");
    let s: StateResponse = {
        let (status, body) = qb::client::call(&qbd, "GET", paths::STATE, None, None).unwrap();
        assert_eq!(status, 200);
        serde_json::from_slice(&body).unwrap()
    };
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

/// Over the binary's loopback listener `listen`: no token is 401, the token reaches a turn,
/// which fails `unavailable` as the vendor port is closed.
fn loopback_admits_the_client_token_only(listen: SocketAddr) {
    let body = sdk_body("chat", false).to_string();
    let (status, _, _) = finish(
        tcp_send(listen, "POST", paths::MESSAGES, "", &body),
        Vec::new(),
    );
    assert_eq!(status, 401);
    let token = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    let s = tcp_send(listen, "POST", paths::MESSAGES, &token, &body);
    assert_eq!(error_type(s), (502, "api_error".into()));
}

/// A file of `crates/qb-anthropic/tests/fixtures`.
fn vendor_fixture(name: &str) -> Vec<u8> {
    fixture_of("qb-anthropic", name)
}

/// The recorded Anthropic answer `answer_<name>.json`; `sse`, a stream fixture, as the body of
/// a 200.
fn recorded(name: &str, sse: Option<&str>) -> Answer {
    recorded_of("qb-anthropic", name, sse)
}

/// [`recorded`] of the OpenAI fixtures.
fn openai_recorded(name: &str, sse: Option<&str>) -> Answer {
    recorded_of("qb-openai", name, sse)
}

fn recorded_of(krate: &str, name: &str, sse: Option<&str>) -> Answer {
    let v: Value =
        serde_json::from_slice(&fixture_of(krate, &format!("answer_{name}.json"))).unwrap();
    let status = u16::try_from(v["status"].as_u64().unwrap()).unwrap();
    let headers = v["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let pair = |i: usize| h[i].as_str().unwrap().to_owned();
            (pair(0), pair(1))
        })
        .collect();
    let body = match sse {
        Some(file) => fixture_of(krate, file),
        None => serde_json::to_vec(&v["body"]).unwrap(),
    };
    Answer::Full(status, headers, body)
}

/// The `[fronts]` table of the front tests with `keys` added: client model `model-2025-01-01`
/// runs on route `chat`, the Messages front's vendor is `vendor-a`, the OpenAI fronts' `vendor-o`
/// with a default output bound of 4096.
fn fronts(keys: &str) -> String {
    format!(
        "[fronts]\nmodels = {{ \"model-2025-01-01\" = \"chat\" }}\n{keys}\n\
         [fronts.messages]\nvendor = \"vendor-a\"\n\
         [fronts.openai]\nvendor = \"vendor-o\"\nmax_tokens = 4096\n"
    )
}

/// A rig whose gateway runs the Anthropic adapter against a scripted vendor and serves the
/// Messages front; `logins` as in [`gateway_toml`], the credential files `files`.
fn vendor_rig(
    files: &[(&str, String, u32)],
    logins: impl Fn(&Vendor) -> [String; 2],
) -> (Rig, Vendor) {
    vendor_rig_on(files, logins, &fronts(""), None)
}

/// [`vendor_rig`] with the `[fronts]` table `front` and the HTTP fronts also on `loopback`.
fn vendor_rig_on(
    files: &[(&str, String, u32)],
    logins: impl Fn(&Vendor) -> [String; 2],
    front: &str,
    loopback: Option<TcpListener>,
) -> (Rig, Vendor) {
    let upstreams: Upstreams = vec![(Api::Anthropic, Box::new(Anthropic::new()))];
    vendor_rig_with(QBD, upstreams, files, logins, front, loopback)
}

/// [`vendor_rig_on`] with the qbd config `qbd` and the adapters `upstreams`.
fn vendor_rig_with(
    qbd: &str,
    upstreams: Upstreams,
    files: &[(&str, String, u32)],
    logins: impl Fn(&Vendor) -> [String; 2],
    front: &str,
    loopback: Option<TcpListener>,
) -> (Rig, Vendor) {
    let vendor = Vendor::start();
    let dir = temp_dir("gwv");
    credentials(&dir, files);
    let qbd = start_qbd(&dir, qbd);
    let keys = logins(&vendor);
    let text = gateway_toml(&dir, &qbd, 4, [&keys[0], &keys[1]], front);
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gw = serve_gateway(
        &text,
        upstreams,
        Box::new(Counting(Arc::clone(&refreshes))),
        own_uid(),
        loopback,
    );
    let rig = Rig {
        dir,
        qbd,
        gw,
        fake: Arc::default(),
        refreshes,
    };
    (rig, vendor)
}

fn two_keys(v: &Vendor) -> [String; 2] {
    [v.login(ANTHROPIC_KEY), v.login(ANTHROPIC_KEY)]
}

fn key_files() -> [(&'static str, String, u32); 2] {
    [
        ("login-1", api_key("test-token-1"), 0o600),
        ("login-2", api_key("test-token-2"), 0o600),
    ]
}

/// The text of the `text_delta` events, joined.
fn text_of(events: &[StreamEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn the_anthropic_adapter_streams_signed_thinking_text_and_tool_calls_to_stop() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_thinking.sse")));
    vendor.answer(recorded("200_allowed", Some("upstream_tool_use.sse")));

    let (_, _, first) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(
        kinds(&first),
        [
            "route login-1",
            "usage",
            "thinking",
            "thinking",
            "text_delta",
            "usage",
            "stop End"
        ]
    );
    let StreamEvent::Thinking { thinking } = &first[2] else {
        panic!("{first:?}");
    };
    assert_eq!(thinking.vendor, "vendor-a");
    let block: Value = serde_json::from_str(&thinking.opaque).unwrap();
    assert_eq!(
        block,
        json!({"type": "thinking", "thinking": "The user wants a greeting.", "signature": "c2lnbmF0dXJlLXRlc3QtMQ=="})
    );

    let (_, _, second) = turn(&r.gw, &turn_body("turn-2"));
    assert_eq!(
        kinds(&second)[1..],
        [
            "usage",
            "text_delta",
            "tool_call",
            "tool_call",
            "usage",
            "stop ToolUse"
        ]
    );
    let StreamEvent::ToolCall { tool_call } = &second[3] else {
        panic!("{second:?}");
    };
    assert_eq!(tool_call.name, "read");
    assert_eq!(
        Value::Object(tool_call.input.clone()),
        json!({"path": "notes.txt", "lines": [1, 2]})
    );
    let StreamEvent::Usage { usage } = &second[5] else {
        panic!("{second:?}");
    };
    assert_eq!(
        *usage,
        Usage {
            input: 25,
            output: 48,
            cache_read: 2000,
            cache_write: 100
        }
    );

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].path, "/v1/messages");
    assert_eq!(sent[0].body["model"], "model-large");
    assert_eq!(sent[0].body["stream"], true);
    assert_eq!(sent[0].body["messages"][0]["content"][0]["text"], "Hi");
}

#[test]
fn rate_limit_headers_of_a_success_reach_qbd_as_a_report() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Ok);
    assert!((used(&s, "login-1") - 0.42).abs() < 1e-9, "{s:?}");
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_usage_limit_moves_the_turn_on_and_each_login_sends_its_own_auth() {
    const OAUTH: &str = "test-oauth-7f3a";
    const KEY: &str = "test-key-2b9d";
    let oauth = format!(
        r#"{{"type":"oauth_anthropic","access_token":"{OAUTH}","refresh_token":"refresh-0","expires_at":{}}}"#,
        unix_now() + 3600
    );
    let files = [("login-1", oauth, 0o600), ("login-2", api_key(KEY), 0o600)];
    let (r, vendor) = vendor_rig(&files, |v| {
        [
            v.login("kind = \"oauth_anthropic\""),
            v.login(ANTHROPIC_KEY),
        ]
    });
    vendor.answer(recorded("429_usage_limit", None));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let mut events = Vec::new();
    let logged = stderr_of(|| events = turn(&r.gw, &turn_body("turn-1")).2);

    assert_eq!(
        kinds(&events),
        [
            "route login-2",
            "usage",
            "text_delta",
            "text_delta",
            "text_delta",
            "usage",
            "stop End"
        ]
    );
    assert_eq!(text_of(&events), "Hello, world — ünïcode!");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    let (oauth, key) = (&sent[0], &sent[1]);
    assert_eq!(
        oauth.header("authorization"),
        Some(format!("Bearer {OAUTH}").as_str())
    );
    assert_eq!(oauth.header("x-api-key"), None);
    assert_eq!(
        oauth.header("anthropic-beta"),
        Some(identity::OAUTH_BETAS.join(",").as_str())
    );
    assert_eq!(oauth.header("user-agent"), Some(identity::OAUTH_USER_AGENT));
    assert_eq!(oauth.header("x-app"), Some(identity::OAUTH_X_APP));
    assert_eq!(
        oauth.body["system"][0]["text"],
        identity::OAUTH_SYSTEM_PREFIX
    );
    assert_eq!(key.header("x-api-key"), Some(KEY));
    assert_eq!(key.header("authorization"), None);
    assert_eq!(key.header("anthropic-beta"), None);
    assert_eq!(key.header("user-agent"), Some(identity::API_KEY_USER_AGENT));
    assert_eq!(key.body.get("system"), None);
    for both in [oauth, key] {
        assert_eq!(
            both.header("anthropic-version"),
            Some(identity::ANTHROPIC_VERSION)
        );
    }
    assert!(logged.contains("login-1: usage_limit"), "{logged}");
    assert!(!logged.contains(OAUTH) && !logged.contains(KEY), "{logged}");
}

#[test]
fn a_401_from_the_vendor_kills_a_key_login_and_the_turn_moves_on() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("401", None));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events)[0], "route login-2");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
    assert_eq!(
        r.refreshes.load(Ordering::SeqCst),
        0,
        "a key is not refreshed"
    );
}

#[test]
fn a_key_login_of_another_api_family_is_never_sent_to_anthropic() {
    let openai = "kind = \"api_key\"\napi = \"openai\"";
    let (r, vendor) = vendor_rig(&key_files(), |v| [v.login(openai), v.login(openai)]);
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    let e = last_error(&events);
    assert_eq!(e.class, ErrorClass::Unavailable);
    assert!(
        e.message
            .as_deref()
            .unwrap()
            .contains("no adapter serves `openai` logins"),
        "{e:?}"
    );
    assert_eq!(vendor.received().len(), 0);
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

/// The first two events of `upstream_text.sse`: `message_start` and a text block's start and
/// first delta, with nothing after.
fn stream_start() -> Vec<u8> {
    through_first(
        &vendor_fixture("upstream_text.sse"),
        "event: content_block_delta",
    )
}

/// `sse` up to the end of its first event that starts with `event`.
fn through_first(sse: &[u8], event: &str) -> Vec<u8> {
    let sse = std::str::from_utf8(sse).unwrap();
    let cut = sse.find(event).unwrap();
    let rest = &sse[cut..];
    let end = cut + rest.find("\n\n").unwrap() + 2;
    sse.as_bytes()[..end].to_vec()
}

/// Reads `s` until its stream holds a `text_delta`; the bytes so far.
fn until_text(s: &mut impl Read) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains("text_delta") {
        let n = s.read(&mut chunk).unwrap();
        assert!(n > 0, "stream ended early");
        seen.extend_from_slice(&chunk[..n]);
    }
    seen
}

#[test]
fn cancel_and_a_closed_client_shut_a_silent_vendor_stream_down_at_once() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(Answer::Hold(stream_start()));
    vendor.answer(Answer::Hold(stream_start()));

    let mut client = send(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-1").to_string(),
    );
    let seen = until_text(&mut client);
    let asked = std::time::Instant::now();
    let (status, body) = call(
        &r.gw,
        "POST",
        paths::MODEL_CANCEL,
        r#"{"request_id":"turn-1"}"#,
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );
    let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(closed.duration_since(asked) < Duration::from_secs(1));
    let (_, _, body) = finish(client, seen);
    let events = events(&body);
    assert_eq!(last_error(&events).class, ErrorClass::Cancelled);
    assert_eq!(text_of(&events), "Hello");

    let mut client = send(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-2").to_string(),
    );
    until_text(&mut client);
    let dropped = std::time::Instant::now();
    drop(client);
    let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(closed.duration_since(dropped) < Duration::from_secs(1));
    let mut leases = 1;
    for _ in 0..50 {
        leases = state(&r.qbd).leases.len();
        if leases == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(leases, 0, "the lease is released");
    assert_eq!(status_of(&state(&r.qbd), "login-1"), LoginStatus::Unknown);
}

/// Synthetic tokens of the OAuth tests; none may reach a log or a client.
const OLD_ACCESS: &str = "test-access-old-41d7";
const OLD_REFRESH: &str = "test-refresh-old-41d7";
const NEW_ACCESS: &str = "test-access-new-41d7";
const NEW_REFRESH: &str = "test-refresh-new-41d7";
const TOKENS: [&str; 4] = [OLD_ACCESS, OLD_REFRESH, NEW_ACCESS, NEW_REFRESH];

/// login-1's OAuth credential file with the old tokens, expiring at `expires_at`.
fn old_oauth(expires_at: u64) -> String {
    format!(
        r#"{{"type":"oauth_anthropic","access_token":"{OLD_ACCESS}","refresh_token":"{OLD_REFRESH}","expires_at":{expires_at}}}"#
    )
}

/// A token answer that grants the new tokens for 8 hours.
fn grant() -> Answer {
    let body = json!({
        "token_type": "Bearer",
        "access_token": NEW_ACCESS,
        "refresh_token": NEW_REFRESH,
        "expires_in": 28800,
        "scope": "user:inference",
    });
    let headers = vec![("content-type".into(), "application/json".into())];
    Answer::Full(200, headers, serde_json::to_vec(&body).unwrap())
}

/// A gateway with the Anthropic adapter and the shipped OAuth refresher: login-1 an OAuth login
/// with `login_1` as its file, login-2 a key login, both on a scripted vendor, login-1 refreshing
/// at a scripted token endpoint; qbd runs `qbd_config`.
fn oauth_rig(login_1: String, qbd_config: &str) -> (Rig, Vendor, Vendor) {
    let vendor = Vendor::start();
    let tokens = Vendor::start();
    let dir = temp_dir("gwo");
    credentials(
        &dir,
        &[
            ("login-1", login_1, 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let qbd = start_qbd(&dir, qbd_config);
    let oauth = format!(
        "{}\ntoken_url = \"{}/v1/oauth/token\"",
        vendor.login("kind = \"oauth_anthropic\""),
        tokens.base_url
    );
    let text = gateway_toml(&dir, &qbd, 4, [&oauth, &vendor.login(ANTHROPIC_KEY)], "");
    let config = qb::gateway::config::parse(Path::new("gateway.toml"), &text).unwrap();
    let gw = serve_gateway(
        &text,
        vec![(Api::Anthropic, Box::new(Anthropic::new()))],
        Box::new(AnthropicOauth::new(&config)),
        own_uid(),
        None,
    );
    let rig = Rig {
        dir,
        qbd,
        gw,
        fake: Arc::default(),
        refreshes: Arc::default(),
    };
    (rig, vendor, tokens)
}

/// Runs `turn` with stderr captured; its events, after checking that neither the log nor the
/// client's answer holds a token.
fn turn_without_leaks(r: &Rig, request_id: &str) -> Vec<StreamEvent> {
    let mut answer = Vec::new();
    let logged = stderr_of(|| {
        let s = send(
            &r.gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body(request_id).to_string(),
        );
        answer = finish(s, Vec::new()).2;
    });
    let answer = String::from_utf8(answer).unwrap();
    for token in TOKENS {
        assert!(!logged.contains(token), "{token} logged: {logged}");
        assert!(!answer.contains(token), "{token} sent: {answer}");
    }
    events(answer.as_bytes())
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// The stored credential file of login-1.
fn stored(r: &Rig) -> (Value, u32) {
    let f = r.dir.join("creds/login-1.json");
    let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
    (
        serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap(),
        mode,
    )
}

#[test]
fn an_expired_token_is_refreshed_before_the_call_and_written_back() {
    let (r, vendor, tokens) = oauth_rig(old_oauth(unix_now()), QBD);
    tokens.answer(grant());
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let before = unix_now();
    let events = turn_without_leaks(&r, "turn-1");
    let after = unix_now();
    assert_eq!(kinds(&events)[0], "route login-1");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");

    let asked = tokens.received();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].path, "/v1/oauth/token");
    assert_eq!(
        asked[0].header("user-agent"),
        Some(identity::OAUTH_TOKEN_USER_AGENT)
    );
    let form = asked[0].body.as_str().unwrap();
    assert!(
        form.starts_with(&format!(
            "grant_type=refresh_token&refresh_token={OLD_REFRESH}&client_id="
        )),
        "{form}"
    );
    let sent = vendor.received();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].header("authorization"),
        Some(bearer(NEW_ACCESS).as_str())
    );

    let (file, mode) = stored(&r);
    assert_eq!(mode, 0o600);
    assert_eq!(file["access_token"], NEW_ACCESS);
    assert_eq!(file["refresh_token"], NEW_REFRESH);
    let expires_at = file["expires_at"].as_u64().unwrap();
    assert!(
        (before + 28800..=after + 28800).contains(&expires_at),
        "{expires_at}"
    );
}

#[test]
fn a_401_on_a_fresh_token_refreshes_once_and_the_same_turn_succeeds() {
    let (r, vendor, tokens) = oauth_rig(old_oauth(unix_now() + 3600), QBD);
    tokens.answer(grant());
    vendor.answer(recorded("401", None));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let events = turn_without_leaks(&r, "turn-1");
    assert_eq!(kinds(&events)[0], "route login-1");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(tokens.received().len(), 1);
    let auth: Vec<Option<String>> = vendor
        .received()
        .iter()
        .map(|s| s.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(auth, [Some(bearer(OLD_ACCESS)), Some(bearer(NEW_ACCESS))]);
    assert_eq!(stored(&r).0["access_token"], NEW_ACCESS);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Ok);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_rejected_refresh_moves_the_turn_to_the_next_login() {
    let (r, vendor, tokens) = oauth_rig(old_oauth(unix_now()), QBD);
    let refusal = json!({
        "error": "invalid_grant",
        "error_description": format!("refresh token {OLD_REFRESH} is revoked"),
    });
    tokens.answer(Answer::Full(
        400,
        vec![("content-type".into(), "application/json".into())],
        serde_json::to_vec(&refusal).unwrap(),
    ));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let events = turn_without_leaks(&r, "turn-1");
    assert_eq!(kinds(&events)[0], "route login-2");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    let sent = vendor.received();
    assert_eq!(sent.len(), 1, "the expired token is never sent");
    assert_eq!(sent[0].header("x-api-key"), Some("test-token-2"));
    assert_eq!(stored(&r).0["access_token"], OLD_ACCESS);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn an_unreachable_token_endpoint_ends_the_turn_retryable_without_a_token_in_sight() {
    let (r, vendor, tokens) = oauth_rig(old_oauth(unix_now()), QBD);
    let echo = format!(r#"{{"error":"server_error","detail":"{OLD_REFRESH}"}}"#);
    tokens.answer(Answer::Full(503, Vec::new(), echo.into_bytes()));
    let events = turn_without_leaks(&r, "turn-1");
    let e = last_error(&events);
    assert_eq!((e.class, e.retryable), (ErrorClass::Unavailable, true));
    assert_eq!(vendor.received().len(), 0);
    assert_eq!(stored(&r).0["access_token"], OLD_ACCESS);
}

#[test]
fn concurrent_turns_on_one_expiring_login_make_one_token_request() {
    let one_login = QBD.replace(
        "[[logins]]\nname = \"login-2\"\nvendor = \"vendor-a\"\n\n",
        "",
    );
    let (r, vendor, tokens) = oauth_rig(old_oauth(unix_now()), &one_login);
    tokens.answer(Answer::After(Duration::from_millis(300), Box::new(grant())));
    for _ in 0..2 {
        vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    }
    let r = Arc::new(r);
    let turns: Vec<_> = (0..2)
        .map(|i| {
            let r = Arc::clone(&r);
            std::thread::spawn(move || turn(&r.gw, &turn_body(&format!("turn-{i}"))).2)
        })
        .collect();
    for t in turns {
        let events = t.join().unwrap();
        assert_eq!(kinds(&events)[0], "route login-1");
        assert_eq!(kinds(&events).last().unwrap(), "stop End");
    }
    assert_eq!(tokens.received().len(), 1);
    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    for s in sent.iter() {
        assert_eq!(s.header("authorization"), Some(bearer(NEW_ACCESS).as_str()));
    }
}

/// The headers the official Anthropic Python SDK sends besides `Host`, `Content-Length` and
/// `anthropic-beta`, with a synthetic key the gateway ignores.
const SDK_HEADERS: &str = "Accept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\
x-stainless-timeout: 600\r\nAccept: application/json\r\nContent-Type: application/json\r\n\
User-Agent: Anthropic/Python 0.87.0\r\nX-Stainless-Lang: python\r\n\
X-Stainless-Package-Version: 0.87.0\r\nX-Stainless-OS: Linux\r\nX-Stainless-Arch: x64\r\n\
X-Stainless-Runtime: CPython\r\nX-Stainless-Runtime-Version: 3.11.16\r\n\
X-Api-Key: test-client-key\r\nX-Stainless-Async: false\r\nanthropic-version: 2023-06-01\r\n\
x-stainless-retry-count: 0\r\nx-stainless-read-timeout: 600\r\n";

/// Sends `body` to `/v1/messages` with the SDK's headers and `anthropic-beta: beta` when set.
fn sdk_send(sock: &Path, body: &Value, beta: Option<&str>) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let beta = beta.map_or(String::new(), |b| format!("anthropic-beta: {b}\r\n"));
    let body = body.to_string();
    write!(
        s,
        "POST {} HTTP/1.1\r\nHost: localhost\r\n{SDK_HEADERS}{beta}Content-Length: {}\r\n\r\n{body}",
        paths::MESSAGES,
        body.len()
    )
    .unwrap();
    s
}

/// Status, head and body of one `/v1/messages` call.
fn sdk_call(sock: &Path, body: &Value, beta: Option<&str>) -> (u16, String, Vec<u8>) {
    finish(sdk_send(sock, body, beta), Vec::new())
}

/// A first request as the SDK's `messages.create` builds it: cached system prompt and user
/// block, a tool, thinking and `metadata.user_id`.
fn sdk_body(model: &str, stream: bool) -> Value {
    json!({
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "Hi", "cache_control": {"type": "ephemeral"}}
        ]}],
        "model": model,
        "metadata": {"user_id": "session-1"},
        "stream": stream,
        "system": [{"type": "text", "text": "Be brief.", "cache_control": {"type": "ephemeral"}}],
        "thinking": {"type": "enabled", "budget_tokens": 512},
        "tools": [{"name": "read", "description": "Read a file.", "input_schema": {
            "type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]
        }}],
    })
}

/// The SSE events of `body`.
fn frames(body: &[u8]) -> Vec<qb_anthropic::sse::Frame> {
    let mut out = Vec::new();
    qb_anthropic::sse::Parser::default()
        .feed(body, &mut out)
        .unwrap();
    out
}

fn names(frames: &[qb_anthropic::sse::Frame]) -> Vec<&str> {
    frames.iter().map(|f| f.event.as_str()).collect()
}

/// The canonical events and stop reason a Messages stream carries, read as the adapter reads
/// the vendor's.
fn content_of(sse: &[u8]) -> (Vec<StreamEvent>, StopReason) {
    let mut reader =
        qb_anthropic::stream::Reader::new("vendor-a", qb_anthropic::limits::RateLimits::default());
    let mut events = Vec::new();
    reader.feed(sse, &mut events).unwrap();
    (events, reader.finish().unwrap())
}

#[test]
fn messages_streams_the_vendor_content_to_an_sdk_client() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    for _ in 0..2 {
        vendor.answer(recorded("200_allowed", Some("upstream_thinking.sse")));
    }
    let beta = "interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14";
    let body = sdk_body("model-2025-01-01", true);
    let (status, head, plain) = sdk_call(&r.gw, &body, None);
    let (status_beta, _, with_beta) = sdk_call(&r.gw, &body, Some(beta));
    assert_eq!((status, status_beta), (200, 200));
    assert!(head.contains("Content-Type: text/event-stream"), "{head}");

    let got = frames(&with_beta);
    assert_eq!(
        names(&got),
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "content_block_start",
            "content_block_stop",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop",
        ]
    );
    let start: Value = serde_json::from_str(&got[0].data).unwrap();
    assert_eq!(start["message"]["model"], "model-2025-01-01");
    assert_eq!(
        content_of(&with_beta),
        content_of(&vendor_fixture("upstream_thinking.sse"))
    );
    let tail = |sse: &[u8]| frames(sse).into_iter().skip(1).collect::<Vec<_>>();
    assert_eq!(
        tail(&plain),
        tail(&with_beta),
        "only the message id differs"
    );

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].body, sent[1].body,
        "anthropic-beta leaves the turn as it is"
    );
    let names_of = |r: &Received| r.headers.iter().map(|h| h.0.clone()).collect::<Vec<_>>();
    assert_eq!(names_of(&sent[0]), names_of(&sent[1]));
    assert_eq!(sent[1].header("anthropic-beta"), None);
    assert_eq!(sent[1].body["model"], "model-large");
    assert_eq!(sent[1].body["system"][0]["text"], "Be brief.");
    assert!(
        sent[1].body.to_string().contains("cache_control"),
        "{}",
        sent[1].body
    );
}

#[test]
fn messages_answers_stream_false_with_one_assembled_body() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_thinking.sse")));
    let (status, head, body) = sdk_call(&r.gw, &sdk_body("model-2025-01-01", false), None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(head.contains("Content-Type: application/json"), "{head}");
    let mut message: Value = serde_json::from_slice(&body).unwrap();
    assert!(message["id"].as_str().unwrap().starts_with("msg_"));
    message["id"] = Value::Null;
    assert_eq!(
        message,
        json!({
            "id": null,
            "type": "message",
            "role": "assistant",
            "model": "model-2025-01-01",
            "content": [
                {"type": "thinking", "thinking": "The user wants a greeting.",
                 "signature": "c2lnbmF0dXJlLXRlc3QtMQ=="},
                {"type": "redacted_thinking", "data": "cmVkYWN0ZWQtdGVzdC0x"},
                {"type": "text", "text": "Hi!"},
            ],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 25, "cache_creation_input_tokens": 100,
                      "cache_read_input_tokens": 2000, "output_tokens": 30},
        })
    );
    assert_eq!(vendor.received()[0].body["stream"], true);
}

#[test]
fn messages_carries_a_tool_round_trip_with_signed_thinking_to_the_vendor() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_tool_use.sse")));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));

    let mut first = sdk_body("model-2025-01-01", false);
    let (status, _, answer) = sdk_call(&r.gw, &first, None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert_eq!(answer["stop_reason"], "tool_use");
    let content = answer["content"].as_array().unwrap();
    assert_eq!(
        content[1],
        json!({"type": "tool_use", "id": "toolu_test_1", "name": "read",
               "input": {"path": "notes.txt", "lines": [1, 2]}})
    );

    let thinking = json!({"type": "thinking", "thinking": "Read it first.",
                          "signature": "c2lnbmF0dXJlLXRlc3QtMQ=="});
    let mut assistant = vec![thinking.clone()];
    assistant.extend(content.iter().cloned());
    let history = first["messages"].as_array_mut().unwrap();
    history.push(json!({"role": "assistant", "content": assistant}));
    history.push(json!({"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_test_1", "content": "line one",
         "cache_control": {"type": "ephemeral"}},
        {"type": "tool_result", "tool_use_id": "toolu_test_2",
         "content": [{"type": "text", "text": "a.txt"}], "is_error": true},
    ]}));
    first["stream"] = json!(true);
    let (status, _, sse) = sdk_call(&r.gw, &first, Some("interleaved-thinking-2025-05-14"));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert_eq!(
        content_of(&sse),
        content_of(&vendor_fixture("upstream_text.sse"))
    );

    let sent = vendor.received();
    let messages = sent[1].body["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(
        messages[1]["content"][0], thinking,
        "signed thinking reaches the vendor"
    );
    assert_eq!(messages[1]["content"][2]["id"], "toolu_test_1");
    assert_eq!(
        messages[1]["content"][2]["input"],
        json!({"path": "notes.txt", "lines": [1, 2]})
    );
    let results = messages[2]["content"].as_array().unwrap();
    assert_eq!(
        (&results[0]["tool_use_id"], &results[0]["content"]),
        (&json!("toolu_test_1"), &json!("line one"))
    );
    assert_eq!(
        (&results[1]["content"], &results[1]["is_error"]),
        (&json!("a.txt"), &json!(true))
    );
    assert!(
        sent[1].body.to_string().contains("cache_control"),
        "{}",
        sent[1].body
    );
}

/// The vendor's thinking rule: with `thinking` set, the last assistant message of a tool loop
/// starts with its thinking block, or the request is invalid.
fn thinking_rule(body: &Value) -> Answer {
    let messages = body["messages"].as_array().unwrap();
    let last = messages.iter().rev().find(|m| m["role"] == "assistant");
    let content = last.map_or(&[][..], |m| m["content"].as_array().unwrap());
    let calls = content.iter().any(|b| b["type"] == "tool_use");
    let starts_thinking = content
        .first()
        .is_some_and(|b| b["type"] == "thinking" || b["type"] == "redacted_thinking");
    if body.get("thinking").is_some() && calls && !starts_thinking {
        recorded("400_invalid", None)
    } else {
        recorded("200_allowed", Some("upstream_text.sse"))
    }
}

#[test]
fn a_tool_loop_without_thinking_in_its_history_streams_a_normal_answer() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(Answer::Judge(thinking_rule));
    let mut body = sdk_body("model-2025-01-01", true);
    let history = body["messages"].as_array_mut().unwrap();
    history.push(json!({"role": "assistant", "content": [
        {"type": "text", "text": "Reading it."},
        {"type": "tool_use", "id": "toolu_test_1", "name": "read", "input": {"path": "notes.txt"}},
    ]}));
    history.push(json!({"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_test_1", "content": "line one"},
    ]}));

    let (status, _, sse) = sdk_call(&r.gw, &body, None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert!(!names(&frames(&sse)).contains(&"error"));
    assert_eq!(
        content_of(&sse),
        content_of(&vendor_fixture("upstream_text.sse"))
    );
    assert_eq!(vendor.received().len(), 1);
}

#[test]
fn a_usage_limit_rotation_is_invisible_to_a_messages_client() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("429_usage_limit", None));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    let (status, _, sse) = sdk_call(&r.gw, &sdk_body("chat", true), None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert_eq!(names(&frames(&sse))[0], "message_start");
    assert!(!names(&frames(&sse)).contains(&"error"));
    assert_eq!(
        content_of(&sse),
        content_of(&vendor_fixture("upstream_text.sse"))
    );
    let sent = vendor.received();
    let keys: Vec<_> = sent.iter().map(|s| s.header("x-api-key")).collect();
    assert_eq!(keys, [Some("test-token-1"), Some("test-token-2")]);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());
}

/// The `retry-after` and `x-should-retry` headers of an answer head.
fn retry_headers(head: &str) -> (Option<u64>, Option<&str>) {
    let value = |name: &str| {
        head.lines()
            .find_map(|l| l.strip_prefix(name))
            .map(str::trim)
    };
    (
        value("retry-after:").map(|v| v.parse().unwrap()),
        value("x-should-retry:"),
    )
}

#[test]
fn an_exhausted_chain_answers_429_with_retry_after_until_the_reset() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    for _ in 0..2 {
        vendor.answer(recorded("429_usage_limit", None));
    }
    for stream in [true, false] {
        let before = unix_now();
        let (status, head, body) = sdk_call(&r.gw, &sdk_body("model-2025-01-01", stream), None);
        assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["type"], "error");
        assert_eq!(body["error"]["type"], "rate_limit_error");
        let (retry_after, should_retry) = retry_headers(&head);
        let retry_after = retry_after.unwrap();
        let reset = 1_800_018_000;
        assert!(
            (reset - unix_now()..=reset - before).contains(&retry_after),
            "{head}"
        );
        assert_eq!(should_retry, Some("false"), "the reset is hours away");
    }
    assert_eq!(
        vendor.received().len(),
        2,
        "the second turn needs no attempt"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn messages_errors_use_the_messages_format_before_and_after_the_first_event() {
    let r = rig_as(4, &key_files(), &fronts(""), own_uid());
    let resets = unix_now() + 3600;
    r.fake.script(
        "login-1",
        Script::Fail(
            vec![text("partial")],
            FailureKind::Overloaded { retry_after: None },
            window(0.5, resets),
        ),
    );
    let (status, _, sse) = sdk_call(&r.gw, &sdk_body("chat", true), None);
    assert_eq!(status, 200);
    let got = frames(&sse);
    assert_eq!(
        names(&got)[..3],
        [
            "message_start",
            "content_block_start",
            "content_block_delta"
        ]
    );
    assert_eq!(names(&got).last(), Some(&"error"));
    let error: Value = serde_json::from_str(&got.last().unwrap().data).unwrap();
    assert_eq!(error["type"], "error");
    assert_eq!(error["error"]["type"], "overloaded_error");

    let (status, _, body) = sdk_call(&r.gw, &sdk_body("model-unknown", true), None);
    assert_eq!(status, 400);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("model-unknown"),
        "{body}"
    );

    let (status, body) = call(&r.gw, "GET", paths::MESSAGES, "");
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, &body["type"]), (405, &json!("error")));
    let oversized = "x".repeat(131_073);
    let (status, body) = call(&r.gw, "POST", paths::MESSAGES, &oversized);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        (status, &body["error"]["type"]),
        (413, &json!("invalid_request_error"))
    );

    let (status, body) = call(
        &rig().gw,
        "POST",
        paths::MESSAGES,
        &sdk_body("chat", true).to_string(),
    );
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"]["type"], "invalid_request_error");
}

#[test]
fn a_messages_client_that_closes_its_connection_shuts_the_vendor_stream_down() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(Answer::Hold(stream_start()));
    let mut client = sdk_send(&r.gw, &sdk_body("model-2025-01-01", true), None);
    until_text(&mut client);
    let dropped = std::time::Instant::now();
    drop(client);
    let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(closed.duration_since(dropped) < Duration::from_secs(1));
    let mut leases = 1;
    for _ in 0..50 {
        leases = state(&r.qbd).leases.len();
        if leases == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(leases, 0, "the lease is released");
}

/// The local client token of the loopback tests, as the recorded SDK request carries it.
const CLIENT_TOKEN: &str = "qb-local-test-token";
/// `printf %s qb-local-test-token | sha256sum`.
const CLIENT_TOKEN_SHA256: &str =
    "d313474a473655cadbfe1cbb9e2314d155d497a6902d4c72a2fa8dee7fb42444";

/// A loopback listener on a free port and the `[fronts]` table that serves it, `keys` added.
fn loopback_front(keys: &str) -> (TcpListener, SocketAddr, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let front = fronts(&format!(
        "listen = \"{addr}\"\ntoken_sha256 = \"{CLIENT_TOKEN_SHA256}\"\n{keys}"
    ));
    (listener, addr, front)
}

/// Sends one request to `addr` with the header lines `auth` and leaves the connection open.
fn tcp_send(addr: SocketAddr, method: &str, path: &str, auth: &str, body: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    s
}

/// Status and Messages error type of a complete answer.
fn error_type(s: impl Read) -> (u16, String) {
    let (status, _, body) = finish(s, Vec::new());
    let body: Value = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&body)));
    assert_eq!(body["type"], "error", "{body}");
    (status, body["error"]["type"].as_str().unwrap().to_owned())
}

#[test]
fn the_loopback_listener_serves_messages_to_the_client_token_only() {
    let (listener, addr, front) = loopback_front("");
    let r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let body = sdk_body("chat", true).to_string();
    for auth in [
        format!("X-Api-Key: {CLIENT_TOKEN}\r\n"),
        format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
    ] {
        let s = tcp_send(addr, "POST", paths::MESSAGES, &auth, &body);
        let (status, head, sse) = finish(s, Vec::new());
        assert_eq!(status, 200, "{auth}{}", String::from_utf8_lossy(&sse));
        assert!(head.contains("Content-Type: text/event-stream"), "{head}");
        let got = frames(&sse);
        assert_eq!(names(&got).first(), Some(&"message_start"));
        assert_eq!(names(&got).last(), Some(&"message_stop"));
    }
    assert_eq!(r.fake.calls().len(), 2);

    // Heads that announce a body they never send: the 401 does not wait for it.
    for auth in [
        String::new(),
        "X-Api-Key: qb-wrong-token\r\n".into(),
        "Authorization: Bearer qb-wrong-token\r\n".into(),
        format!("X-Api-Key: {CLIENT_TOKEN}-2\r\n"),
        format!("Authorization: {CLIENT_TOKEN}\r\n"),
    ] {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        write!(
            s,
            "POST {} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: 60000\r\n\r\n",
            paths::MESSAGES
        )
        .unwrap();
        assert_eq!(
            error_type(s),
            (401, "authentication_error".into()),
            "{auth}"
        );
    }

    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    for (method, path) in [
        ("GET", paths::HEALTH),
        ("GET", paths::MODEL_ROUTES),
        ("POST", paths::MODEL_TURN),
        ("POST", paths::MODEL_CANCEL),
        ("GET", paths::MESSAGES),
        ("POST", "/v1/messages/count_tokens"),
    ] {
        let s = tcp_send(addr, method, path, &auth, "{}");
        assert_eq!(error_type(s), (404, "not_found_error".into()), "{path}");
    }
    assert_eq!(
        r.fake.calls().len(),
        2,
        "a refused request reaches no vendor"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
    let (status, _) = call(&r.gw, "GET", paths::HEALTH, "");
    assert_eq!(status, 200, "the unix socket needs no token");
}

/// A request an official vendor Python SDK sent with the base URL `http://127.0.0.1:8080` and
/// the key [`CLIENT_TOKEN`], recorded byte for byte in the fixture `name` of `krate`.
fn recorded_sdk_request(krate: &str, name: &str) -> Vec<u8> {
    let v: Value = serde_json::from_slice(&fixture_of(krate, name)).unwrap();
    let text = |v: &Value| v.as_str().unwrap().to_owned();
    let mut raw = format!("{} {} HTTP/1.1\r\n", text(&v["method"]), text(&v["path"]));
    for h in v["headers"].as_array().unwrap() {
        write!(raw, "{}: {}\r\n", text(&h[0]), text(&h[1])).unwrap();
    }
    raw.push_str("\r\n");
    raw.push_str(&text(&v["body"]));
    raw.into_bytes()
}

#[test]
fn a_recorded_sdk_request_streams_over_the_loopback_listener() {
    let (listener, addr, front) = loopback_front("");
    let (r, vendor) = vendor_rig_on(&key_files(), two_keys, &front, Some(listener));
    for _ in 0..2 {
        vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
    }
    let raw = recorded_sdk_request("qb-anthropic", "client_sdk_http_request.json");
    let mut tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.write_all(&raw).unwrap();
    let (status, head, sse) = finish(tcp, Vec::new());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert!(head.contains("Content-Type: text/event-stream"), "{head}");
    let got = frames(&sse);
    assert_eq!(
        names(&got),
        [
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_delta",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop",
        ]
    );
    let start: Value = serde_json::from_str(&got[0].data).unwrap();
    assert_eq!(start["message"]["model"], "model-2025-01-01");
    assert_eq!(
        content_of(&sse),
        content_of(&vendor_fixture("upstream_text.sse"))
    );

    let mut unix = UnixStream::connect(&r.gw).unwrap();
    unix.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    unix.write_all(&raw).unwrap();
    let (status, _, over_unix) = finish(unix, Vec::new());
    assert_eq!(status, 200);
    let tail = |sse: &[u8]| frames(sse).into_iter().skip(1).collect::<Vec<_>>();
    assert_eq!(tail(&sse), tail(&over_unix), "both listeners answer alike");

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body, sent[1].body);
    assert_eq!(sent[0].body["model"], "model-large");
    assert_eq!(sent[0].body["tools"][0]["name"], "read");
    assert!(
        sent[0].body.to_string().contains("What is in notes.txt?"),
        "{}",
        sent[0].body
    );
    for s in sent.iter() {
        let key = s.header("x-api-key");
        assert!(
            matches!(key, Some("test-token-1" | "test-token-2")),
            "{key:?}"
        );
        assert!(
            s.headers.iter().all(|(_, v)| !v.contains(CLIENT_TOKEN)),
            "the client token stays local"
        );
    }
}

#[test]
fn a_silent_stream_gets_pings_after_message_start_only() {
    let (listener, addr, front) = loopback_front("ping_interval_s = 1");
    let (r, vendor) = vendor_rig_on(&key_files(), two_keys, &front, Some(listener));
    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    let body = sdk_body("model-2025-01-01", true).to_string();

    let silence = Duration::from_millis(1500);
    let refused = Box::new(recorded("400_invalid", None));
    vendor.answer(Answer::After(silence, refused));
    let asked = std::time::Instant::now();
    let s = tcp_send(addr, "POST", paths::MESSAGES, &auth, &body);
    let (status, head, answer) = finish(s, Vec::new());
    assert!(asked.elapsed() >= silence);
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&answer));
    assert!(head.contains("Content-Type: application/json"), "{head}");
    assert!(!String::from_utf8_lossy(&answer).contains("ping"));

    vendor.answer(Answer::Hold(stream_start()));
    let mut client = tcp_send(addr, "POST", paths::MESSAGES, &auth, &body);
    until_text(&mut client);
    let quiet = std::time::Instant::now();
    let mut pinged = Vec::new();
    let mut chunk = [0u8; 1024];
    while pinged.len() < 2 {
        let n = client.read(&mut chunk).unwrap();
        assert!(n > 0, "stream ended early");
        let text = String::from_utf8_lossy(&chunk[..n]).into_owned();
        assert!(text.contains("event: ping\n"), "{text:?}");
        pinged.push(quiet.elapsed());
    }
    assert!(pinged[0] >= Duration::from_millis(900), "{pinged:?}");
    assert!(
        pinged[1].saturating_sub(pinged[0]) >= Duration::from_millis(900),
        "{pinged:?}"
    );
    assert!(pinged[1] < Duration::from_secs(4), "{pinged:?}");

    let dropped = std::time::Instant::now();
    drop(client);
    let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(closed.duration_since(dropped) < Duration::from_secs(1));
    let mut leases = 1;
    for _ in 0..50 {
        leases = state(&r.qbd).leases.len();
        if leases == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(leases, 0, "the lease is released");
}

/// The headers the official OpenAI Python SDK sends besides `Host` and `Content-Length`, with a
/// synthetic key the unix socket ignores.
const OPENAI_SDK_HEADERS: &str = "Accept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\
Accept: application/json\r\nContent-Type: application/json\r\nUser-Agent: OpenAI/Python 1.109.1\r\n\
X-Stainless-Lang: python\r\nX-Stainless-Package-Version: 1.109.1\r\nX-Stainless-OS: Linux\r\n\
X-Stainless-Arch: x64\r\nX-Stainless-Runtime: CPython\r\nX-Stainless-Runtime-Version: 3.11.16\r\n\
Authorization: Bearer test-client-key\r\nX-Stainless-Async: false\r\n\
x-stainless-retry-count: 0\r\nx-stainless-read-timeout: 600\r\n";

/// Sends `body` to `path` with the OpenAI SDK's headers.
fn openai_send(sock: &Path, path: &str, body: &Value) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let body = body.to_string();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\n{OPENAI_SDK_HEADERS}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    s
}

/// Status, head and body of one OpenAI front call.
fn openai_call(sock: &Path, path: &str, body: &Value) -> (u16, String, Vec<u8>) {
    finish(openai_send(sock, path, body), Vec::new())
}

/// The read tool's JSON schema.
fn read_schema() -> Value {
    json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"],
           "additionalProperties": false})
}

/// A first request as the SDK's `chat.completions.create` builds it: a developer prompt, a user
/// message, a function tool and the client's `user`, without an output bound.
fn chat_body(model: &str, stream: bool) -> Value {
    let mut body = json!({
        "messages": [
            {"role": "developer", "content": "Be brief."},
            {"role": "user", "content": [{"type": "text", "text": "What is in notes.txt?"}]},
        ],
        "model": model,
        "stream": stream,
        "tool_choice": "auto",
        "tools": [{"type": "function", "function": {
            "name": "read", "description": "Read a file.", "parameters": read_schema(),
            "strict": true,
        }}],
        "user": "session-1",
    });
    if stream {
        body["stream_options"] = json!({"include_usage": true});
    }
    body
}

/// A first request as the SDK's `responses.create` builds it for a stateless client:
/// instructions, input items, a function tool, encrypted reasoning asked for, `store: false`.
fn responses_body(model: &str, stream: bool) -> Value {
    json!({
        "input": [{"role": "user", "content": [
            {"type": "input_text", "text": "What is in notes.txt?"}
        ]}],
        "model": model,
        "include": ["reasoning.encrypted_content"],
        "instructions": "Be brief.",
        "prompt_cache_key": "session-1",
        "store": false,
        "stream": stream,
        "tools": [{"type": "function", "name": "read", "description": "Read a file.",
                   "parameters": read_schema(), "strict": true}],
    })
}

/// The SSE events of an OpenAI stream; keep-alive comments are not events.
fn openai_frames(body: &[u8]) -> Vec<qb_openai::sse::Frame> {
    let mut out = Vec::new();
    qb_openai::sse::Parser::default()
        .feed(body, &mut out)
        .unwrap();
    out
}

/// The `data` of each Chat Completions stream event, `[DONE]` as a string.
fn chat_chunks(sse: &[u8]) -> Vec<Value> {
    openai_frames(sse)
        .iter()
        .map(|f| serde_json::from_str(&f.data).unwrap_or_else(|_| Value::from(f.data.clone())))
        .collect()
}

/// The streamed text of Chat Completions chunks.
fn chat_text(chunks: &[Value]) -> String {
    chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
        .collect()
}

/// The text of `upstream_text.sse`.
const FIXTURE_TEXT: &str = "Hello, world \u{2014} \u{fc}n\u{ef}code!";

/// The canonical blocks of the second turn of a tool round trip, as the Anthropic adapter sent
/// them: the assistant's text and two calls, then both results in one user message.
fn assert_round_trip_reached_the_vendor(sent: &Value) {
    let messages = sent["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3, "{sent}");
    let assistant = messages[1]["content"].as_array().unwrap();
    assert_eq!(assistant[0]["text"], "Reading the file first.");
    assert_eq!(
        (
            &assistant[1]["id"],
            &assistant[1]["name"],
            &assistant[1]["input"]
        ),
        (
            &json!("toolu_test_1"),
            &json!("read"),
            &json!({"path": "notes.txt", "lines": [1, 2]})
        )
    );
    assert_eq!(assistant[2]["id"], "toolu_test_2");
    let results = messages[2]["content"].as_array().unwrap();
    assert_eq!(
        (&results[0]["tool_use_id"], &results[0]["content"]),
        (&json!("toolu_test_1"), &json!("line one"))
    );
    assert_eq!(
        (&results[1]["tool_use_id"], &results[1]["content"]),
        (&json!("toolu_test_2"), &json!("a.txt"))
    );
    assert_eq!(sent["system"][0]["text"], "Be brief.");
    assert_eq!(sent["model"], "model-large");
}

/// The JSON object a function call's `arguments` string holds.
fn arguments(call: &Value) -> Value {
    serde_json::from_str(call.as_str().unwrap()).unwrap()
}

#[test]
fn chat_completions_carries_a_tool_round_trip_without_and_with_streaming() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_tool_use.sse")));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));

    let mut body = chat_body("model-2025-01-01", false);
    let (status, head, answer) = openai_call(&r.gw, paths::CHAT_COMPLETIONS, &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    assert!(head.contains("Content-Type: application/json"), "{head}");
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert!(answer["id"].as_str().unwrap().starts_with("chatcmpl-"));
    assert_eq!(
        (&answer["object"], &answer["model"]),
        (&json!("chat.completion"), &json!("model-2025-01-01"))
    );
    let choice = &answer["choices"][0];
    assert_eq!(choice["finish_reason"], "tool_calls");
    let message = choice["message"].clone();
    assert_eq!(message["content"], "Reading the file first.");
    let calls = message["tool_calls"].as_array().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (
            &calls[0]["id"],
            &calls[0]["type"],
            &calls[0]["function"]["name"]
        ),
        (&json!("toolu_test_1"), &json!("function"), &json!("read"))
    );
    assert_eq!(
        arguments(&calls[0]["function"]["arguments"]),
        json!({"path": "notes.txt", "lines": [1, 2]})
    );
    assert_eq!(arguments(&calls[1]["function"]["arguments"]), json!({}));
    assert_eq!(
        answer["usage"],
        json!({"prompt_tokens": 2125, "completion_tokens": 48, "total_tokens": 2173,
               "prompt_tokens_details": {"cached_tokens": 2000},
               "completion_tokens_details": {"reasoning_tokens": 0}})
    );

    let history = body["messages"].as_array_mut().unwrap();
    history.push(message);
    history.push(json!({"role": "tool", "tool_call_id": "toolu_test_1", "content": "line one"}));
    history.push(json!({"role": "tool", "tool_call_id": "toolu_test_2",
                        "content": [{"type": "text", "text": "a.txt"}]}));
    body["stream"] = json!(true);
    body["stream_options"] = json!({"include_usage": true});
    body["max_completion_tokens"] = json!(512);
    let (status, head, sse) = openai_call(&r.gw, paths::CHAT_COMPLETIONS, &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert!(head.contains("Content-Type: text/event-stream"), "{head}");
    let chunks = chat_chunks(&sse);
    assert_eq!(chunks.last(), Some(&json!("[DONE]")));
    let chunks = &chunks[..chunks.len() - 1];
    assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
    assert_eq!(chat_text(chunks), FIXTURE_TEXT);
    let id = &chunks[0]["id"];
    assert!(
        chunks
            .iter()
            .all(|c| &c["id"] == id && c["model"] == "model-2025-01-01")
    );
    let finish = &chunks[chunks.len() - 2];
    assert_eq!(finish["choices"][0]["finish_reason"], "stop");
    let usage = &chunks[chunks.len() - 1];
    assert_eq!(usage["choices"], json!([]));
    assert_eq!(
        (
            &usage["usage"]["prompt_tokens"],
            &usage["usage"]["completion_tokens"]
        ),
        (&json!(2125), &json!(12))
    );

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert_eq!(
        sent[0].body["max_tokens"], 4096,
        "the config's bound when the request names none"
    );
    assert_eq!(sent[1].body["max_tokens"], 512);
    assert_eq!(sent[0].body["tools"][0]["name"], "read");
    assert_round_trip_reached_the_vendor(&sent[1].body);
}

#[test]
fn responses_carries_a_function_call_round_trip_without_and_with_streaming() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    vendor.answer(recorded("200_allowed", Some("upstream_tool_use.sse")));
    vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));

    let mut body = responses_body("model-2025-01-01", false);
    let (status, head, answer) = openai_call(&r.gw, paths::RESPONSES, &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    assert!(head.contains("Content-Type: application/json"), "{head}");
    let answer: Value = serde_json::from_slice(&answer).unwrap();
    assert!(answer["id"].as_str().unwrap().starts_with("resp_"));
    assert_eq!(
        (&answer["object"], &answer["status"], &answer["model"]),
        (
            &json!("response"),
            &json!("completed"),
            &json!("model-2025-01-01")
        )
    );
    let output = answer["output"].as_array().unwrap().clone();
    let kinds: Vec<&str> = output.iter().map(|i| i["type"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["message", "function_call", "function_call"]);
    assert_eq!(output[0]["content"][0]["text"], "Reading the file first.");
    assert_eq!(
        (&output[1]["call_id"], &output[1]["name"]),
        (&json!("toolu_test_1"), &json!("read"))
    );
    assert_eq!(
        arguments(&output[1]["arguments"]),
        json!({"path": "notes.txt", "lines": [1, 2]})
    );
    assert_eq!(output[2]["call_id"], "toolu_test_2");
    assert_eq!(
        (
            &answer["usage"]["input_tokens"],
            &answer["usage"]["output_tokens"]
        ),
        (&json!(2125), &json!(48))
    );

    let input = body["input"].as_array_mut().unwrap();
    input.extend(output);
    input.push(
        json!({"type": "function_call_output", "call_id": "toolu_test_1",
                      "output": "line one"}),
    );
    input.push(
        json!({"type": "function_call_output", "call_id": "toolu_test_2",
                      "output": [{"type": "input_text", "text": "a.txt"}]}),
    );
    body["stream"] = json!(true);
    let (status, head, sse) = openai_call(&r.gw, paths::RESPONSES, &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert!(head.contains("Content-Type: text/event-stream"), "{head}");
    let got = openai_frames(&sse);
    let names: Vec<&str> = got.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(names[..2], ["response.created", "response.in_progress"]);
    assert_eq!(names.last(), Some(&"response.completed"));
    let deltas: String = got
        .iter()
        .filter(|f| f.event == "response.output_text.delta")
        .map(|f| {
            serde_json::from_str::<Value>(&f.data).unwrap()["delta"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(deltas, FIXTURE_TEXT);
    let completed: Value = serde_json::from_str(&got.last().unwrap().data).unwrap();
    assert_eq!(
        completed["response"]["output"][0]["content"][0]["text"],
        FIXTURE_TEXT
    );
    assert_eq!(completed["response"]["usage"]["output_tokens"], 12);

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body["max_tokens"], 4096);
    assert_round_trip_reached_the_vendor(&sent[1].body);
}

#[test]
fn a_usage_limit_rotation_is_invisible_to_openai_clients() {
    for (path, body) in [
        (paths::CHAT_COMPLETIONS, chat_body("model-2025-01-01", true)),
        (paths::RESPONSES, responses_body("chat", false)),
    ] {
        let (r, vendor) = vendor_rig(&key_files(), two_keys);
        vendor.answer(recorded("429_usage_limit", None));
        vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
        let (status, _, answer) = openai_call(&r.gw, path, &body);
        assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&answer));
        if path == paths::CHAT_COMPLETIONS {
            let chunks = chat_chunks(&answer);
            assert!(
                chunks.iter().all(|c| c.get("error").is_none()),
                "{chunks:?}"
            );
            assert_eq!(chat_text(&chunks), FIXTURE_TEXT);
        } else {
            let answer: Value = serde_json::from_slice(&answer).unwrap();
            assert_eq!(answer["status"], "completed");
            assert_eq!(answer["output"][0]["content"][0]["text"], FIXTURE_TEXT);
        }
        let sent = vendor.received();
        let keys: Vec<_> = sent.iter().map(|s| s.header("x-api-key")).collect();
        assert_eq!(keys, [Some("test-token-1"), Some("test-token-2")], "{path}");
        let s = state(&r.qbd);
        assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
        assert_eq!(s.leases, Vec::new());
    }
}

#[test]
fn an_exhausted_chain_answers_openai_clients_429_with_retry_after_until_the_reset() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    for _ in 0..2 {
        vendor.answer(recorded("429_usage_limit", None));
    }
    for (path, body) in [
        (paths::CHAT_COMPLETIONS, chat_body("model-2025-01-01", true)),
        (
            paths::CHAT_COMPLETIONS,
            chat_body("model-2025-01-01", false),
        ),
        (paths::RESPONSES, responses_body("model-2025-01-01", true)),
        (paths::RESPONSES, responses_body("model-2025-01-01", false)),
    ] {
        let before = unix_now();
        let (status, head, answer) = openai_call(&r.gw, path, &body);
        assert_eq!(status, 429, "{path}: {}", String::from_utf8_lossy(&answer));
        assert!(head.contains("Content-Type: application/json"), "{head}");
        let answer: Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(
            (&answer["error"]["type"], &answer["error"]["code"]),
            (&json!("insufficient_quota"), &json!("insufficient_quota")),
            "{path}: {answer}"
        );
        let (retry_after, should_retry) = retry_headers(&head);
        let retry_after = retry_after.unwrap();
        let reset = 1_800_018_000;
        assert!(
            (reset - unix_now()..=reset - before).contains(&retry_after),
            "{head}"
        );
        assert_eq!(should_retry, Some("false"), "the reset is hours away");
    }
    assert_eq!(
        vendor.received().len(),
        2,
        "the later turns need no attempt"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn openai_errors_use_the_openai_format_before_and_after_the_first_event() {
    let r = rig_as(4, &key_files(), &fronts(""), own_uid());
    for login in ["login-1", "login-2"] {
        for _ in 0..2 {
            r.fake.script(
                login,
                Script::Fail(
                    vec![text("partial")],
                    FailureKind::Overloaded { retry_after: None },
                    window(0.5, unix_now() + 3600),
                ),
            );
        }
    }
    let (status, _, sse) = openai_call(&r.gw, paths::CHAT_COMPLETIONS, &chat_body("chat", true));
    assert_eq!(status, 200);
    let chunks = chat_chunks(&sse);
    assert_eq!(chat_text(&chunks), "partial");
    let last = chunks.last().unwrap();
    assert_eq!(last["error"]["code"], "rate_limit_exceeded", "{chunks:?}");
    assert!(!chunks.contains(&json!("[DONE]")));

    let (status, _, sse) = openai_call(&r.gw, paths::RESPONSES, &responses_body("chat", true));
    assert_eq!(status, 200);
    let got = openai_frames(&sse);
    let names: Vec<&str> = got.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(
        names[names.len() - 2..],
        ["error", "response.failed"],
        "{names:?}"
    );
    let failed: Value = serde_json::from_str(&got.last().unwrap().data).unwrap();
    assert_eq!(failed["response"]["status"], "failed");

    let error_of = |status: u16, body: &[u8]| {
        let body: Value = serde_json::from_slice(body)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(body)));
        (
            status,
            body["error"]["type"].as_str().unwrap().to_owned(),
            body,
        )
    };
    for path in [paths::CHAT_COMPLETIONS, paths::RESPONSES] {
        let unknown = match path {
            paths::RESPONSES => responses_body("model-unknown", true),
            _ => chat_body("model-unknown", true),
        };
        let (status, _, body) = openai_call(&r.gw, path, &unknown);
        let (status, kind, body) = error_of(status, &body);
        assert_eq!(
            (status, kind.as_str()),
            (400, "invalid_request_error"),
            "{path}"
        );
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains("model-unknown"), "{body}");

        let (status, body) = call(&r.gw, "GET", path, "");
        assert_eq!(error_of(status, &body).0, 405, "{path}");
        let (status, body) = call(&r.gw, "POST", path, &"x".repeat(131_073));
        let (status, kind, _) = error_of(status, &body);
        assert_eq!(
            (status, kind.as_str()),
            (413, "invalid_request_error"),
            "{path}"
        );

        let body = chat_body("chat", true).to_string();
        let (status, body) = call(&rig().gw, "POST", path, &body);
        let (status, kind, _) = error_of(status, &body);
        assert_eq!(
            (status, kind.as_str()),
            (404, "invalid_request_error"),
            "{path}"
        );
    }
}

/// Reads `s` until its bytes hold `needle`; the bytes so far.
fn until(s: &mut impl Read, needle: &str) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    while !String::from_utf8_lossy(&seen).contains(needle) {
        let n = s.read(&mut chunk).unwrap();
        assert!(n > 0, "stream ended early");
        seen.extend_from_slice(&chunk[..n]);
    }
    seen
}

#[test]
fn the_loopback_listener_serves_openai_clients_with_the_client_token_only() {
    let (listener, addr, front) = loopback_front("");
    let (r, vendor) = vendor_rig_on(&key_files(), two_keys, &front, Some(listener));
    for path in [paths::CHAT_COMPLETIONS, paths::RESPONSES] {
        // Heads that announce a body they never send: the 401 does not wait for it.
        for auth in [
            String::new(),
            "Authorization: Bearer qb-wrong-token\r\n".into(),
        ] {
            let mut s = TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            write!(
                s,
                "POST {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: 60000\r\n\r\n"
            )
            .unwrap();
            let (status, _, answer) = finish(s, Vec::new());
            let answer: Value = serde_json::from_slice(&answer).unwrap();
            assert_eq!(status, 401, "{path} {auth}");
            assert_eq!(
                (&answer["error"]["type"], &answer["error"]["code"]),
                (&json!("invalid_request_error"), &json!("invalid_api_key"))
            );
        }
        let s = tcp_send(
            addr,
            "GET",
            path,
            &format!("Authorization: Bearer {CLIENT_TOKEN}\r\n"),
            "",
        );
        let (status, _, answer) = finish(s, Vec::new());
        let answer: Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(
            (status, &answer["error"]["code"]),
            (404, &json!("unknown_url"))
        );
    }
    assert_eq!(
        vendor.received().len(),
        0,
        "a refused request reaches no vendor"
    );

    for (path, body, needle) in [
        (
            paths::CHAT_COMPLETIONS,
            chat_body("model-2025-01-01", true),
            "[DONE]",
        ),
        (
            paths::RESPONSES,
            responses_body("model-2025-01-01", true),
            "response.completed",
        ),
    ] {
        vendor.answer(recorded("200_allowed", Some("upstream_text.sse")));
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let s = tcp_send(addr, "POST", path, &auth, &body.to_string());
        let (status, head, sse) = finish(s, Vec::new());
        assert_eq!(status, 200, "{path}: {}", String::from_utf8_lossy(&sse));
        assert!(head.contains("Content-Type: text/event-stream"), "{head}");
        assert!(String::from_utf8_lossy(&sse).contains(needle), "{path}");
    }
    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    assert!(
        sent.iter()
            .all(|s| s.headers.iter().all(|(_, v)| !v.contains(CLIENT_TOKEN))),
        "the client token stays local"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn a_silent_openai_stream_gets_keepalives_and_a_hang_up_cancels_it() {
    let (listener, addr, front) = loopback_front("ping_interval_s = 1");
    let (r, vendor) = vendor_rig_on(&key_files(), two_keys, &front, Some(listener));
    let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
    for (path, body, first) in [
        (
            paths::CHAT_COMPLETIONS,
            chat_body("model-2025-01-01", true),
            "Hello",
        ),
        (
            paths::RESPONSES,
            responses_body("model-2025-01-01", true),
            "output_text.delta",
        ),
    ] {
        vendor.answer(Answer::Hold(stream_start()));
        let mut client = tcp_send(addr, "POST", path, &auth, &body.to_string());
        until(&mut client, first);
        let quiet = std::time::Instant::now();
        until(&mut client, ": keep-alive\n\n");
        let pinged = quiet.elapsed();
        assert!(pinged >= Duration::from_millis(900), "{path}: {pinged:?}");
        assert!(pinged < Duration::from_secs(3), "{path}: {pinged:?}");

        let dropped = std::time::Instant::now();
        drop(client);
        let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            closed.duration_since(dropped) < Duration::from_secs(1),
            "{path}"
        );
        let mut leases = 1;
        for _ in 0..50 {
            leases = state(&r.qbd).leases.len();
            if leases == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(leases, 0, "{path}: the lease is released");
    }
}

/// qbd for the OpenAI adapter tests: login-1 of `vendor_1`, login-2 of `vendor-o`, which has the
/// ChatGPT windows; the ladder of role `gateway` runs on `vendor-o` with `model-o`.
fn openai_qbd(vendor_1: &str) -> String {
    format!(
        r#"
[journal]
mode = "off"

[[vendors]]
name = "vendor-a"
windows = [{{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }}]

[[vendors]]
name = "vendor-o"
windows = [
  {{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }},
  {{ name = "seven_day", length_s = 604800, t_burn_s = 43200 }},
]

[[logins]]
name = "login-1"
vendor = "{vendor_1}"

[[logins]]
name = "login-2"
vendor = "vendor-o"

[[roles]]
name = "gateway"

[[roles.ladder]]
difficulty = 1
candidates = [{{ vendor = "vendor-o", model = "model-o", tier = 1 }}]

[limits]
rate_per_s = 1000.0
burst = 1000
"#
    )
}

/// The keys of an `api_key` login of the `openai` API family.
const OPENAI_KEY: &str = "kind = \"api_key\"\napi = \"openai\"";

/// The keys of a ChatGPT subscription login.
const CHATGPT: &str = "kind = \"chatgpt_oauth\"";

/// A ChatGPT credential file with a refresh token the gateway does not use.
fn chatgpt(access_token: &str, account_id: &str) -> String {
    format!(
        r#"{{"type":"chatgpt_oauth","access_token":"{access_token}","account_id":"{account_id}","refresh_token":"refresh-0"}}"#
    )
}

/// A rig whose gateway runs both adapters against one scripted vendor, with qbd of
/// [`openai_qbd`]`(vendor_1)`, the `[fronts]` table `front` and the HTTP fronts also on
/// `loopback`.
fn openai_rig(
    vendor_1: &str,
    files: &[(&str, String, u32)],
    logins: impl Fn(&Vendor) -> [String; 2],
    front: &str,
    loopback: Option<TcpListener>,
) -> (Rig, Vendor) {
    let upstreams: Upstreams = vec![
        (Api::Anthropic, Box::new(Anthropic::new())),
        (Api::Openai, Box::new(Openai::new())),
    ];
    vendor_rig_with(
        &openai_qbd(vendor_1),
        upstreams,
        files,
        logins,
        front,
        loopback,
    )
}

/// The reasoning item of `upstream_reasoning.sse` as the adapter passes it on.
fn fixture_reasoning() -> Value {
    json!({
        "type": "reasoning",
        "summary": [{"type": "summary_text", "text": "**Checking the file**"}],
        "encrypted_content": "Z0FBQUFBQnN5bnRoZXRpYy1lbmNyeXB0ZWQ=",
    })
}

#[test]
fn the_openai_adapter_streams_reasoning_text_and_a_tool_call_on_a_key_login() {
    const KEY: &str = "test-key-4c8e";
    let files = [
        ("login-1", api_key(KEY), 0o600),
        ("login-2", api_key("test-key-2"), 0o600),
    ];
    let (r, vendor) = openai_rig(
        "vendor-o",
        &files,
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &fronts(""),
        None,
    );
    vendor.answer(openai_recorded(
        "200_api_key",
        Some("upstream_reasoning.sse"),
    ));
    vendor.answer(openai_recorded("200_api_key", Some("upstream_text.sse")));

    let mut first = Vec::new();
    let logged = stderr_of(|| first = turn(&r.gw, &turn_body("turn-1")).2);
    assert_eq!(
        kinds(&first),
        [
            "route login-1",
            "thinking",
            "text_delta",
            "tool_call",
            "usage",
            "stop ToolUse"
        ]
    );
    let StreamEvent::Thinking { thinking } = &first[1] else {
        panic!("{first:?}");
    };
    assert_eq!(thinking.vendor, "vendor-o");
    let opaque: Value = serde_json::from_str(&thinking.opaque).unwrap();
    assert_eq!(opaque, fixture_reasoning());
    assert_eq!(text_of(&first), "Reading it now.");
    let StreamEvent::ToolCall { tool_call } = &first[3] else {
        panic!("{first:?}");
    };
    assert_eq!(
        (
            tool_call.id.as_str(),
            tool_call.name.as_str(),
            Value::Object(tool_call.input.clone())
        ),
        ("call_c3", "read_file", json!({"path": "a.txt"}))
    );
    assert_eq!(
        first[4],
        StreamEvent::Usage {
            usage: Usage {
                input: 372,
                output: 200,
                cache_read: 128,
                cache_write: 0
            }
        }
    );

    let sent = vendor.received();
    assert_eq!(sent.len(), 1);
    let req = &sent[0];
    assert_eq!(req.path, "/responses");
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert_eq!(req.header(openai_identity::ACCOUNT_HEADER), None);
    assert_eq!(
        req.header("user-agent"),
        Some(openai_identity::API_KEY_USER_AGENT)
    );
    assert_eq!(req.header("accept"), Some("text/event-stream"));
    assert_eq!(
        (
            &req.body["model"],
            &req.body["stream"],
            &req.body["store"],
            &req.body["max_output_tokens"]
        ),
        (&json!("model-o"), &json!(true), &json!(false), &json!(64))
    );
    assert_eq!(req.body["input"][0]["content"][0]["text"], "Hi");
    assert_eq!(req.body["include"], json!(["reasoning.encrypted_content"]));
    assert_eq!(state(&r.qbd).leases, Vec::new());
    assert!(!logged.contains(KEY), "{logged}");
}

#[test]
fn reasoning_of_an_openai_login_goes_back_to_it_in_the_next_turn() {
    let (r, vendor) = openai_rig(
        "vendor-o",
        &key_files(),
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &fronts(""),
        None,
    );
    vendor.answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
    let mut next = turn_body("turn-2");
    next["messages"] = json!([
        {"role": "user", "content": [{"type": "text", "text": "Hi"}]},
        {"role": "assistant", "content": [
            {"type": "thinking", "vendor": "vendor-o", "opaque": fixture_reasoning().to_string()},
            {"type": "thinking", "vendor": "vendor-a", "opaque": "{\"type\":\"thinking\"}"},
            {"type": "text", "text": "Reading it now."},
            {"type": "tool_use", "id": "call_c3", "name": "read_file", "input": {"path": "a.txt"}},
        ]},
        {"role": "user", "content": [{"type": "tool_result", "id": "call_c3", "content": "line one"}]},
    ]);
    let (_, _, events) = turn(&r.gw, &next);
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(text_of(&events), "Hello, w\u{f6}rld!");

    let sent = vendor.received();
    let input = sent[0].body["input"].as_array().unwrap();
    let types: Vec<&str> = input.iter().map(|i| i["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "message",
            "reasoning",
            "message",
            "function_call",
            "function_call_output"
        ]
    );
    assert_eq!(
        input[1],
        fixture_reasoning(),
        "the reasoning goes back as it came"
    );
    assert_eq!(
        (&input[4]["call_id"], &input[4]["output"]),
        (&json!("call_c3"), &json!("line one"))
    );
}

#[test]
fn messages_on_a_chatgpt_login_sends_its_account_and_never_shows_reasoning_as_thinking() {
    const ACCESS: &str = "test-access-6d1f";
    const ACCOUNT: &str = "test-account-3a9c";
    let files = [
        ("login-1", chatgpt(ACCESS, ACCOUNT), 0o600),
        ("login-2", chatgpt("test-access-2", "test-account-2"), 0o600),
    ];
    let (r, vendor) = openai_rig(
        "vendor-o",
        &files,
        |v| [v.login(CHATGPT), v.login(CHATGPT)],
        &fronts(""),
        None,
    );
    vendor.answer(openai_recorded(
        "200_chatgpt",
        Some("upstream_reasoning.sse"),
    ));

    let mut answer = (0, String::new(), Vec::new());
    let body = sdk_body("model-2025-01-01", false);
    let logged = stderr_of(|| answer = sdk_call(&r.gw, &body, None));
    let (status, _, answer) = answer;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let message: Value = serde_json::from_slice(&answer).unwrap();
    let content = message["content"].as_array().unwrap();
    let types: Vec<&str> = content
        .iter()
        .map(|b| b["type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["redacted_thinking", "text", "tool_use"]);
    let wrapped = content[0]["data"].as_str().unwrap();
    let wrapped: Value =
        serde_json::from_str(wrapped.strip_prefix("qb-thinking:").unwrap()).unwrap();
    assert_eq!(wrapped["vendor"], "vendor-o");
    let opaque: Value = serde_json::from_str(wrapped["opaque"].as_str().unwrap()).unwrap();
    assert_eq!(opaque, fixture_reasoning());
    assert_eq!(content[1]["text"], "Reading it now.");
    assert_eq!(
        (&content[2]["id"], &content[2]["name"], &content[2]["input"]),
        (
            &json!("call_c3"),
            &json!("read_file"),
            &json!({"path": "a.txt"})
        )
    );
    assert_eq!(message["stop_reason"], "tool_use");

    let sent = vendor.received();
    assert_eq!(sent.len(), 1);
    let req = &sent[0];
    assert_eq!(req.path, "/responses");
    assert_eq!(
        req.header("authorization"),
        Some(format!("Bearer {ACCESS}").as_str())
    );
    assert_eq!(req.header(openai_identity::ACCOUNT_HEADER), Some(ACCOUNT));
    assert_eq!(
        req.header("openai-beta"),
        Some(openai_identity::OPENAI_BETA)
    );
    assert_eq!(req.header("originator"), Some(openai_identity::ORIGINATOR));
    assert_eq!(
        req.header("user-agent"),
        Some(openai_identity::CHATGPT_USER_AGENT)
    );
    assert_eq!(
        req.header(openai_identity::SESSION_HEADER),
        Some("session-1")
    );
    assert_eq!(req.body["instructions"], "Be brief.");
    assert_eq!(req.body.get("max_output_tokens"), None);

    let s = state(&r.qbd);
    assert!((used(&s, "login-1") - 0.425).abs() < 1e-9, "{s:?}");
    assert_eq!(s.leases, Vec::new());
    assert!(
        !logged.contains(ACCESS) && !logged.contains(ACCOUNT),
        "{logged}"
    );
}

/// The canonical blocks of an answer's events: consecutive text joined, as one message item.
fn blocks_of(events: &[StreamEvent]) -> Vec<Block> {
    let mut out: Vec<Block> = Vec::new();
    for e in events {
        match e {
            StreamEvent::Thinking { thinking } => out.push(Block::Thinking {
                vendor: thinking.vendor.clone(),
                opaque: thinking.opaque.clone(),
            }),
            StreamEvent::TextDelta { text } => match out.last_mut() {
                Some(Block::Text { text: run }) => run.push_str(text),
                _ => out.push(Block::Text { text: text.clone() }),
            },
            StreamEvent::ToolCall { tool_call } => out.push(Block::ToolUse {
                id: tool_call.id.clone(),
                name: tool_call.name.clone(),
                input: tool_call.input.clone(),
            }),
            _ => {}
        }
    }
    out
}

/// The canonical blocks of a Responses answer's output, read back as the front reads a client's
/// next turn.
fn blocks_of_output(output: &Value) -> Vec<Block> {
    let mut input = vec![json!({"role": "user", "content": "Hi"})];
    input.extend(output.as_array().unwrap().iter().cloned());
    let next = json!({"model": "any", "input": input}).to_string();
    let route_of = |_: &str| Some("chat".to_owned());
    let decoded =
        qb_openai::responses::decode_request(next.as_bytes(), "turn-x", "vendor-o", &route_of, 64)
            .unwrap();
    decoded.turn.messages[1].content.clone()
}

#[test]
fn responses_gives_the_same_canonical_content_on_an_anthropic_and_an_openai_login() {
    let files = [
        ("login-1", api_key("test-key-1"), 0o600),
        ("login-2", api_key("test-key-2"), 0o600),
    ];
    let pins = "[[routes]]\nalias = \"claude\"\nrole = \"gateway\"\nvendor = \"vendor-a\"\nmodel = \"model-large\"\n\n\
                [[routes]]\nalias = \"gpt\"\nrole = \"gateway\"\nvendor = \"vendor-o\"\nmodel = \"model-o\"\n\n";
    let (r, vendor) = openai_rig(
        "vendor-a",
        &files,
        |v| [v.login(ANTHROPIC_KEY), v.login(OPENAI_KEY)],
        &format!("{pins}{}", fronts("")),
        None,
    );
    let cases = [
        (
            "claude",
            "login-1",
            recorded("200_allowed", Some("upstream_thinking.sse")),
            recorded("200_allowed", Some("upstream_thinking.sse")),
        ),
        (
            "gpt",
            "login-2",
            openai_recorded("200_api_key", Some("upstream_reasoning.sse")),
            openai_recorded("200_api_key", Some("upstream_reasoning.sse")),
        ),
    ];
    for (n, (alias, login, c4, front)) in cases.into_iter().enumerate() {
        vendor.answer(c4);
        vendor.answer(front);
        let mut body = turn_body(&format!("turn-{n}"));
        body["route"] = json!(alias);
        let (_, _, events) = turn(&r.gw, &body);
        assert_eq!(kinds(&events)[0], format!("route {login}"));
        let usage = events
            .iter()
            .rev()
            .find_map(|e| match e {
                StreamEvent::Usage { usage } => Some(*usage),
                _ => None,
            })
            .unwrap();

        let (status, _, answer) =
            openai_call(&r.gw, paths::RESPONSES, &responses_body(alias, false));
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
        let answer: Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(answer["status"], "completed", "{alias}");
        let blocks = blocks_of(&events);
        assert!(blocks.len() >= 2, "{alias}: {blocks:?}");
        assert_eq!(blocks_of_output(&answer["output"]), blocks, "{alias}");
        assert_eq!(
            (
                &answer["usage"]["input_tokens"],
                &answer["usage"]["output_tokens"]
            ),
            (
                &json!(usage.input + usage.cache_read + usage.cache_write),
                &json!(usage.output)
            ),
            "{alias}"
        );
    }
    let sent = vendor.received();
    let paths: Vec<&str> = sent.iter().map(|r| r.path.as_str()).collect();
    assert_eq!(
        paths,
        ["/v1/messages", "/v1/messages", "/responses", "/responses"]
    );
}

#[test]
fn a_usage_limit_on_a_chatgpt_login_moves_the_turn_to_the_next_openai_login() {
    const ACCESS: &str = "test-access-8e2b";
    const ACCOUNT: &str = "test-account-5f7a";
    const KEY: &str = "test-key-1d6c";
    let files = [
        ("login-1", chatgpt(ACCESS, ACCOUNT), 0o600),
        ("login-2", api_key(KEY), 0o600),
    ];
    let (r, vendor) = openai_rig(
        "vendor-o",
        &files,
        |v| [v.login(CHATGPT), v.login(OPENAI_KEY)],
        &fronts(""),
        None,
    );
    vendor.answer(openai_recorded("429_usage_limit", None));
    vendor.answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
    let mut events = Vec::new();
    let logged = stderr_of(|| events = turn(&r.gw, &turn_body("turn-1")).2);

    assert_eq!(kinds(&events)[0], "route login-2");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(text_of(&events), "Hello, w\u{f6}rld!");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    let (chatgpt, key) = (&sent[0], &sent[1]);
    assert_eq!(
        chatgpt.header(openai_identity::ACCOUNT_HEADER),
        Some(ACCOUNT)
    );
    assert_eq!(key.header(openai_identity::ACCOUNT_HEADER), None);
    assert_eq!(
        key.header("authorization"),
        Some(format!("Bearer {KEY}").as_str())
    );
    assert!(logged.contains("login-1: usage_limit"), "{logged}");
    for secret in [ACCESS, ACCOUNT, KEY] {
        assert!(!logged.contains(secret), "{secret}: {logged}");
    }
}

/// The canonical events and stop reason an OpenAI vendor stream carries, read as the adapter
/// reads it.
fn openai_content_of(sse: &[u8]) -> (Vec<StreamEvent>, StopReason) {
    let mut reader =
        qb_openai::stream::Reader::new("vendor-o", qb_openai::limits::RateLimits::default());
    let mut events = Vec::new();
    reader.feed(sse, &mut events).unwrap();
    (events, reader.finish().unwrap())
}

/// The canonical blocks of a Chat Completions assistant message, read back as the front reads a
/// client's next turn.
fn blocks_of_chat(message: &Value) -> Vec<Block> {
    let next = json!({"model": "any", "messages": [{"role": "user", "content": "Hi"}, message]});
    let route_of = |_: &str| Some("chat".to_owned());
    let decoded =
        qb_openai::chat::decode_request(next.to_string().as_bytes(), "turn-x", &route_of, 64)
            .unwrap();
    decoded.turn.messages[1].content.clone()
}

/// The assistant message an OpenAI SDK assembles from Chat Completions chunks: the content
/// joined, and the tool call deltas merged by `index`, where the first delta of a call carries
/// its id, type and name and every later one that names them names the same.
fn chat_message_of(chunks: &[Value]) -> Value {
    let mut calls: Vec<Value> = Vec::new();
    let deltas = chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["tool_calls"].as_array())
        .flatten();
    for delta in deltas {
        let i = usize::try_from(delta["index"].as_u64().unwrap()).unwrap();
        assert!(i <= calls.len(), "calls open in index order: {delta}");
        if i == calls.len() {
            assert!(delta["id"].is_string(), "{delta}");
            assert_eq!(delta["type"], "function", "{delta}");
            assert!(delta["function"]["name"].is_string(), "{delta}");
            calls.push(json!({"id": delta["id"], "type": "function",
                              "function": {"name": delta["function"]["name"], "arguments": ""}}));
        }
        let call = &mut calls[i];
        if let Some(id) = delta.get("id") {
            assert_eq!(&call["id"], id, "a stable id");
        }
        if let Some(name) = delta["function"].get("name") {
            assert_eq!(&call["function"]["name"], name, "a stable name");
        }
        let part = delta["function"]["arguments"].as_str().unwrap_or_default();
        let joined = format!("{}{part}", call["function"]["arguments"].as_str().unwrap());
        call["function"]["arguments"] = json!(joined);
    }
    let text = chat_text(chunks);
    let mut message = json!({"role": "assistant", "content": text});
    if text.is_empty() {
        message["content"] = Value::Null;
    }
    if !calls.is_empty() {
        message["tool_calls"] = json!(calls);
    }
    message
}

/// The chunks of a well-formed Chat Completions stream with usage, without `[DONE]`: one id, one
/// `finish_reason`, the usage chunk last.
fn well_formed_chat_stream(sse: &[u8]) -> Vec<Value> {
    let mut chunks = chat_chunks(sse);
    assert_eq!(chunks.pop(), Some(json!("[DONE]")), "{chunks:?}");
    let id = &chunks[0]["id"];
    assert!(id.as_str().unwrap().starts_with("chatcmpl-"), "{id}");
    for c in &chunks {
        assert_eq!(
            (&c["id"], &c["object"], &c["model"]),
            (
                id,
                &json!("chat.completion.chunk"),
                &json!("model-2025-01-01")
            ),
            "{c}"
        );
    }
    let finishes = chunks
        .iter()
        .filter(|c| !c["choices"][0]["finish_reason"].is_null())
        .count();
    assert_eq!(finishes, 1, "{chunks:?}");
    let usage = chunks.last().unwrap();
    assert_eq!(usage["choices"], json!([]), "{usage}");
    assert!(usage["usage"]["total_tokens"].is_u64(), "{usage}");
    chunks
}

/// The frames of a well-formed Responses stream: `response.created` and `.in_progress` first,
/// `response.completed` last, `sequence_number` counting from 0.
fn well_formed_responses_stream(sse: &[u8]) -> Vec<qb_openai::sse::Frame> {
    let got = openai_frames(sse);
    let names: Vec<&str> = got.iter().map(|f| f.event.as_str()).collect();
    assert_eq!(names[..2], ["response.created", "response.in_progress"]);
    assert_eq!(names.last(), Some(&"response.completed"), "{names:?}");
    for (n, f) in got.iter().enumerate() {
        let data: Value = serde_json::from_str(&f.data).unwrap();
        assert_eq!(
            (data["type"].as_str(), data["sequence_number"].as_u64()),
            (Some(f.event.as_str()), Some(n as u64))
        );
    }
    got
}

/// The canonical blocks of the answer to the recorded SDK request `name`, which must be a
/// well-formed OpenAI answer of a model that called a tool.
fn blocks_of_answer(name: &str, answer: &[u8]) -> Vec<Block> {
    match name {
        "chat" => {
            let answer: Value = serde_json::from_slice(answer).unwrap();
            assert_eq!(
                (&answer["object"], &answer["model"]),
                (&json!("chat.completion"), &json!("model-2025-01-01"))
            );
            let choice = &answer["choices"][0];
            assert_eq!(choice["finish_reason"], "tool_calls");
            blocks_of_chat(&choice["message"])
        }
        "chat_stream" => {
            let chunks = well_formed_chat_stream(answer);
            let finish = &chunks[chunks.len() - 2];
            assert_eq!(finish["choices"][0]["finish_reason"], "tool_calls");
            blocks_of_chat(&chat_message_of(&chunks))
        }
        "responses" => {
            let answer: Value = serde_json::from_slice(answer).unwrap();
            assert_eq!(
                (&answer["object"], &answer["status"], &answer["model"]),
                (
                    &json!("response"),
                    &json!("completed"),
                    &json!("model-2025-01-01")
                )
            );
            blocks_of_output(&answer["output"])
        }
        _ => {
            let got = well_formed_responses_stream(answer);
            let completed: Value = serde_json::from_str(&got.last().unwrap().data).unwrap();
            assert_eq!(completed["response"]["status"], "completed");
            blocks_of_output(&completed["response"]["output"])
        }
    }
}

/// Checks that the vendor request `body` of the recorded SDK request `name` carries its prompt,
/// tool, bound, session and the tool round trip of its history.
fn assert_sdk_history_reached_the_vendor(name: &str, body: &Value) {
    assert_eq!(
        (
            &body["model"],
            &body["instructions"],
            &body["max_output_tokens"],
            &body["prompt_cache_key"],
            &body["tools"][0]["name"]
        ),
        (
            &json!("model-o"),
            &json!("Be brief."),
            &json!(512),
            &json!("session-1"),
            &json!("read")
        ),
        "{name}: {body}"
    );
    let input = body["input"].as_array().unwrap();
    assert_eq!(
        input[0]["content"][0]["text"], "What is in notes.txt?",
        "{name}"
    );
    let item = |kind: &str| input.iter().find(|i| i["type"] == kind).unwrap();
    let call = item("function_call");
    assert_eq!(
        (
            &call["call_id"],
            &call["name"],
            arguments(&call["arguments"])
        ),
        (
            &json!("call_a1"),
            &json!("read"),
            json!({"path": "notes.txt"})
        ),
        "{name}"
    );
    let output = item("function_call_output");
    assert_eq!(
        (&output["call_id"], &output["output"]),
        (&json!("call_a1"), &json!("line one")),
        "{name}"
    );
}

#[test]
fn recorded_openai_sdk_requests_run_on_an_openai_login_over_the_loopback_listener() {
    const KEYS: [&str; 2] = ["test-key-7a3e", "test-key-9b1f"];
    let files = [
        ("login-1", api_key(KEYS[0]), 0o600),
        ("login-2", api_key(KEYS[1]), 0o600),
    ];
    let (listener, addr, front) = loopback_front("");
    let (r, vendor) = openai_rig(
        "vendor-o",
        &files,
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &front,
        Some(listener),
    );
    let (events, stop) = openai_content_of(&fixture_of("qb-openai", "upstream_reasoning.sse"));
    assert_eq!(stop, StopReason::ToolUse);
    let blocks = blocks_of(&events);
    let shown: Vec<Block> = blocks
        .iter()
        .filter(|b| !matches!(b, Block::Thinking { .. }))
        .cloned()
        .collect();
    assert_eq!(
        blocks.len(),
        3,
        "thinking, text and a tool call: {blocks:?}"
    );

    for name in ["chat", "chat_stream", "responses", "responses_stream"] {
        vendor.answer(openai_recorded(
            "200_api_key",
            Some("upstream_reasoning.sse"),
        ));
        let raw = recorded_sdk_request("qb-openai", &format!("client_sdk_http_{name}.json"));
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        tcp.write_all(&raw).unwrap();
        let (status, head, answer) = finish(tcp, Vec::new());
        assert_eq!(status, 200, "{name}: {}", String::from_utf8_lossy(&answer));
        let kind = if name.ends_with("_stream") {
            "text/event-stream"
        } else {
            "application/json"
        };
        assert!(
            head.contains(&format!("Content-Type: {kind}")),
            "{name}: {head}"
        );
        let expected = if name.starts_with("chat") {
            &shown
        } else {
            &blocks
        };
        assert_eq!(&blocks_of_answer(name, &answer), expected, "{name}");
    }

    let sent = vendor.received();
    assert_eq!(sent.len(), 4);
    for (name, s) in ["chat", "chat_stream", "responses", "responses_stream"]
        .iter()
        .zip(sent.iter())
    {
        assert_eq!(s.path, "/responses", "{name}");
        let auth = s.header("authorization").unwrap();
        assert!(KEYS.iter().any(|k| auth == format!("Bearer {k}")), "{name}");
        assert!(
            s.headers.iter().all(|(_, v)| !v.contains(CLIENT_TOKEN)),
            "the client token stays local"
        );
        assert_sdk_history_reached_the_vendor(name, &s.body);
    }
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn a_streamed_chat_tool_call_reaches_the_client_with_one_id_name_and_its_arguments() {
    let (r, vendor) = openai_rig(
        "vendor-o",
        &key_files(),
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &fronts(""),
        None,
    );
    vendor.answer(openai_recorded(
        "200_api_key",
        Some("upstream_tool_calls.sse"),
    ));
    let (status, head, sse) = openai_call(
        &r.gw,
        paths::CHAT_COMPLETIONS,
        &chat_body("model-2025-01-01", true),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    assert!(head.contains("Content-Type: text/event-stream"), "{head}");
    let chunks = well_formed_chat_stream(&sse);
    assert_eq!(chunks[0]["choices"][0]["delta"]["role"], "assistant");
    let finish = &chunks[chunks.len() - 2];
    assert_eq!(finish["choices"][0]["finish_reason"], "tool_calls");

    let message = chat_message_of(&chunks);
    assert_eq!(message["content"], Value::Null, "{message}");
    let calls = message["tool_calls"].as_array().unwrap();
    let got: Vec<(&Value, &Value, Value)> = calls
        .iter()
        .map(|c| {
            (
                &c["id"],
                &c["function"]["name"],
                arguments(&c["function"]["arguments"]),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                &json!("call_a1"),
                &json!("read_file"),
                json!({"path": "notes.txt"})
            ),
            (&json!("call_b2"), &json!("list_dir"), json!({"dir": "src"})),
        ]
    );
    assert_eq!(vendor.received()[0].path, "/responses");
}

/// The events of `upstream_text.sse` of the OpenAI fixtures through its first text delta, with
/// nothing after.
fn openai_stream_start() -> Vec<u8> {
    through_first(
        &fixture_of("qb-openai", "upstream_text.sse"),
        "event: response.output_text.delta",
    )
}

#[test]
fn cancel_and_a_closed_client_shut_a_silent_openai_login_stream_down_at_once() {
    let (r, vendor) = openai_rig(
        "vendor-o",
        &key_files(),
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &fronts(""),
        None,
    );
    vendor.answer(Answer::Hold(openai_stream_start()));
    vendor.answer(Answer::Hold(openai_stream_start()));

    let mut client = send(
        &r.gw,
        "POST",
        paths::MODEL_TURN,
        &turn_body("turn-cancel-o").to_string(),
    );
    let seen = until_text(&mut client);
    let asked = std::time::Instant::now();
    let (status, body) = call(
        &r.gw,
        "POST",
        paths::MODEL_CANCEL,
        r#"{"request_id":"turn-cancel-o"}"#,
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: CancelAnswer = serde_json::from_slice(&body).unwrap();
    assert!(answer.cancelled);
    let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(closed.duration_since(asked) < Duration::from_secs(1));
    let (_, _, body) = finish(client, seen);
    let events = events(&body);
    assert_eq!(
        kinds(&events),
        ["route login-1", "text_delta", "error Cancelled"]
    );
    assert_eq!(text_of(&events), "Hello");
    assert!(!last_error(&events).retryable);

    let logged = stderr_until("turn turn-hangup-o of ", || {
        let mut client = send(
            &r.gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body("turn-hangup-o").to_string(),
        );
        until_text(&mut client);
        let dropped = std::time::Instant::now();
        drop(client);
        let closed = vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(closed.duration_since(dropped) < Duration::from_secs(1));
    });
    let ended = logged
        .lines()
        .find(|l| l.contains("turn turn-hangup-o of "))
        .unwrap_or_else(|| panic!("{logged}"));
    assert!(ended.ends_with(": cancelled"), "{ended}");

    let s = state(&r.qbd);
    assert_eq!(s.leases, Vec::new(), "the leases are released");
    assert_eq!(
        status_of(&s, "login-1"),
        LoginStatus::Unknown,
        "a cancelled stream does not mark the login"
    );
    assert_eq!(vendor.received().len(), 2);
}
