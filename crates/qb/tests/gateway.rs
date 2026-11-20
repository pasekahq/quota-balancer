//! Contract tests of the model gateway: `/v1/model/*` and the HTTP fronts over a real unix
//! socket, with a real qbd in-process and a scripted fake vendor adapter, or the Anthropic,
//! OpenAI Responses and Chat Completions adapters against a scripted vendor endpoint and a
//! scripted OAuth token endpoint on loopback TCP.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qb::auth::Gate;
use qb::gateway::anthropic::Anthropic;
use qb::gateway::chat_upstream::ChatCompletions;
use qb::gateway::config::{Api, GatewayLogin};
use qb::gateway::core::{Cancel, Gateway, Upstreams};
use qb::gateway::creds::{RefreshError, Refreshed, Refresher};
use qb::gateway::front;
use qb::gateway::oauth::OauthRefresher;
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
    AuditAction, AuditAnswer, AuditEntry, AuditResult, Block, CancelAnswer, ClientRotateAnswer,
    ConfigRoute, ConfigRoutes, ConfigRoutesPut, ConfigRoutesWritten, ConfigStep, ErrorClass,
    GatewayError, LoginKeyAnswer, LoginOauthSigned, LoginOauthStarted, LoginSpend, LoginStatus,
    OauthPaste, Outcome, ReloadAnswer, RouteState, RouteStatus, RoutesAnswer, SpendAnswer,
    StateResponse, StopReason, StreamEvent, Thinking, ToolCall, TurnRequest, Usage, UsageAnswer,
    UsageLine, UsageRow, UsdSource, WindowReport, paths,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

mod common;

use common::http::{etag, finish, put, send, sha256_hex};
use common::pkce::{param, params, s256};
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
    /// Emit the events, then finish with `end` or fail with that kind, reporting the cost.
    Costed(Vec<StreamEvent>, Option<FailureKind>, Option<f64>),
    /// Emit the events, then wait for the cancel.
    Hang(Vec<StreamEvent>),
    /// Emit the events, then finish with `end` once the sender sends or hangs up.
    Held(Vec<StreamEvent>, std::sync::mpsc::Receiver<()>),
    /// Emit a text event every 20 ms until the sink stops it; at most 10 s.
    Drip,
    /// Fail as a refused request with a message that quotes the secret and the account id.
    Leak,
}

/// A scripted adapter: one queue of scripts per login, and a record of every call.
#[derive(Default)]
struct Fake {
    scripts: Mutex<HashMap<String, Vec<Script>>>,
    /// `(login, secret, request)` of every call.
    calls: Mutex<Vec<(String, String, TurnRequest)>>,
    /// `(vendor, model, effort)` of every call.
    picked: Mutex<Vec<(String, String, Option<String>)>>,
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
        self.0.picked.lock().unwrap().push((
            at.vendor.to_owned(),
            at.model.to_owned(),
            at.effort.map(str::to_owned),
        ));
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
                Ok(Finished {
                    stop,
                    windows,
                    cost: None,
                })
            }
            Script::Fail(events, kind, windows) => {
                emit(events, sink)?;
                Err(Failure {
                    kind,
                    windows,
                    message: format!("scripted {kind:?}"),
                    cost: None,
                })
            }
            Script::Costed(events, end, cost) => {
                emit(events, sink)?;
                match end {
                    None => Ok(Finished {
                        stop: StopReason::End,
                        windows: Vec::new(),
                        cost,
                    }),
                    Some(kind) => Err(Failure {
                        kind,
                        windows: Vec::new(),
                        message: format!("scripted {kind:?}"),
                        cost,
                    }),
                }
            }
            Script::Leak => Err(Failure::new(
                FailureKind::BadRequest,
                format!(
                    "vendor refused key {} of account {}",
                    credential.secret(),
                    credential.account_id().unwrap_or("none")
                ),
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
            Script::Held(events, release) => {
                emit(events, sink)?;
                let _ = release.recv_timeout(Duration::from_secs(10));
                Ok(Finished {
                    stop: StopReason::End,
                    windows: Vec::new(),
                    cost: None,
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

/// Hands out `access-N` and counts its calls. The refresh token `refresh-down` fails as an
/// unreachable endpoint, `refresh-revoked` as a refused token.
struct Counting(Arc<AtomicUsize>);

impl Refresher for Counting {
    fn refresh(&self, _: &GatewayLogin, refresh_token: &str) -> Result<Refreshed, RefreshError> {
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

/// A qbd of config `text` on `dir/qb.sock` that journals to [`qbd_journal`] of `dir`.
fn start_qbd(dir: &Path, text: &str) -> PathBuf {
    let sock = dir.join("qb.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let config = qb::config::parse(Path::new("qbd.toml"), text).unwrap();
    let mut journal = Journal::open(&qbd_journal(dir), u64::MAX, 0).unwrap();
    std::thread::spawn(move || {
        let mut core = Core::new(config.core_spec()).unwrap();
        let mut gate = Gate::new(&[], &config.limits);
        qb::server::serve(
            &listener,
            &mut core,
            &mut journal,
            &mut Runner::default(),
            &mut gate,
            &[],
            None,
        )
    });
    sock
}

fn qbd_journal(dir: &Path) -> PathBuf {
    dir.join("qbd.journal")
}

/// The `on_behalf_of` of every lease line in the journal of the qbd in `dir`, in order.
fn leased_on_behalf_of(dir: &Path) -> Vec<Option<String>> {
    std::fs::read_to_string(qbd_journal(dir))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|l| l.get("lease").is_some())
        .map(|l| l["lease"]["on_behalf_of"].as_str().map(str::to_owned))
        .collect()
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

/// The login keys of the kind a credential file's contents declare, of the `anthropic` family
/// unless it is a ChatGPT login.
fn keys_of(contents: &str) -> &'static str {
    if contents.contains("oauth_anthropic") {
        "kind = \"oauth_anthropic\""
    } else if contents.contains("chatgpt_oauth") {
        CHATGPT
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

/// A rig whose gateway runs as `gateway_uid`, with `extra` in its config: its top-level keys
/// first, its tables appended.
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
    let (top, tables) = split_top(extra);
    let toml = gateway_toml(&dir, &qbd, max_turns, [keys(0), keys(1)], tables);
    let text = if top.is_empty() && !tables.is_empty() {
        toml
    } else {
        format!("{top}\n{toml}")
    };
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gw = serve_gateway(
        &text,
        vec![
            (Api::Anthropic, Box::new(Shared(Arc::clone(&fake)))),
            (Api::Openai, Box::new(Shared(Arc::clone(&fake)))),
        ],
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

/// `extra` cut before its first table header: its top-level keys and its tables.
fn split_top(extra: &str) -> (&str, &str) {
    if extra.trim_start().starts_with('[') {
        return ("", extra);
    }
    extra
        .find("\n[")
        .map_or((extra, ""), |i| extra.split_at(i + 1))
}

/// Serves a gateway of config `text`, written to `gateway.toml` beside its socket, with
/// `upstreams` as `gateway_uid`, and its Messages front on `loopback` when set; its socket.
fn serve_gateway(
    text: &str,
    upstreams: Upstreams,
    refresher: Box<dyn Refresher>,
    gateway_uid: u32,
    loopback: Option<TcpListener>,
) -> PathBuf {
    serve_gateway_with(text, upstreams, refresher, gateway_uid, loopback, |g| g)
}

/// [`serve_gateway`] of the gateway `configure` makes of the one the config gives.
fn serve_gateway_with(
    text: &str,
    upstreams: Upstreams,
    refresher: Box<dyn Refresher>,
    gateway_uid: u32,
    loopback: Option<TcpListener>,
    configure: impl FnOnce(Gateway) -> Gateway,
) -> PathBuf {
    let parsed = qb::gateway::config::parse(Path::new("gateway.toml"), text).unwrap();
    let file = parsed.socket.with_file_name("gateway.toml");
    std::fs::write(&file, text).unwrap();
    let config = qb::gateway::config::load(&file).unwrap();
    let gw = config.socket.clone();
    let gateway = configure(Gateway::new(config, upstreams, refresher, None).unwrap());
    let listener = UnixListener::bind(&gw).unwrap();
    std::thread::spawn(move || {
        front::serve(
            &listener,
            loopback.as_ref(),
            None,
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

/// Status and plain body of the complete answer `raw`.
fn finish_raw(raw: &[u8]) -> (u16, Vec<u8>) {
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..at].to_vec()).unwrap();
    (
        head.split(' ').nth(1).unwrap().parse().unwrap(),
        raw[at + 4..].to_vec(),
    )
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
    let gateway =
        Gateway::new(config, Vec::new(), Box::new(Counting(Arc::default())), None).unwrap();
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
    )
    .unwrap();
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
fn silent_loopback_peers_neither_hold_the_unix_socket_s_slots_nor_stay_long() {
    let (listener, addr, front) = loopback_front("");
    let files = [
        ("login-1", api_key("test-token-1"), 0o600),
        ("login-2", api_key("test-token-2"), 0o600),
    ];
    // max_turns 1: three slots, fewer than the silent loopback peers below.
    let r = rig_on(1, &files, &front, own_uid(), Some(listener));
    let opened = std::time::Instant::now();
    let silent: Vec<TcpStream> = (0..front::LOOPBACK_UNCHECKED)
        .map(|_| TcpStream::connect(addr).unwrap())
        .collect();
    // The main thread refuses one more at once, before any byte of it.
    let mut refused = None;
    for _ in 0..50 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut raw = Vec::new();
        if s.read_to_end(&mut raw).is_ok() && !raw.is_empty() {
            refused = Some(finish_raw(&raw));
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (status, body) = refused.expect("an answer");
    assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
    assert!(opened.elapsed() < front::LOOPBACK_HEAD_DEADLINE);

    let (status, body) = call(&r.gw, "GET", paths::HEALTH, "");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(opened.elapsed() < front::LOOPBACK_HEAD_DEADLINE);

    for mut s in silent {
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut raw = Vec::new();
        let _ = s.read_to_end(&mut raw);
    }
    let held = opened.elapsed();
    assert!(held >= front::LOOPBACK_HEAD_DEADLINE, "{held:?}");
    assert!(held < front::READ_DEADLINE, "{held:?}");
    let s = tcp_send(addr, "GET", paths::HEALTH, "", "");
    assert_eq!(error_type(s), (401, "authentication_error".into()));

    // A peer with the token shares the slots: with all three held it gets 429 after its head.
    let idle: Vec<UnixStream> = (0..3)
        .map(|_| UnixStream::connect(&r.gw).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(100));
    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    let body = sdk_body("model-2025-01-01", true).to_string();
    let s = tcp_send(addr, "POST", paths::MESSAGES, &auth, &body);
    assert_eq!(error_type(s).0, 429);
    drop(idle);
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

const QBD_THREE_VENDORS: &str = r#"
[journal]
mode = "off"

[[vendors]]
name = "vendor-a"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[vendors]]
name = "vendor-b"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[vendors]]
name = "vendor-c"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[logins]]
name = "login-1"
vendor = "vendor-a"

[[logins]]
name = "login-2"
vendor = "vendor-b"

[[logins]]
name = "login-3"
vendor = "vendor-c"

[[roles]]
name = "gateway"

[[roles.ladder]]
difficulty = 1
candidates = [{ vendor = "vendor-a", model = "model-a", tier = 1 }]

[limits]
rate_per_s = 1000.0
burst = 1000
"#;

/// A rig whose route `chat` is the chain vendor-a, vendor-b, vendor-c with one login each.
fn chain_rig() -> Rig {
    chain_rig_with(QBD_THREE_VENDORS, None, "")
}

/// [`chain_rig`] with qbd's config `qbd_text`, the logins' `spend_cap` amounts in USD when
/// given, the spend file `state/spend.json` with them, and `extra`: its top-level keys first,
/// its tables after the routes.
fn chain_rig_with(qbd_text: &str, caps: Option<[f64; 3]>, extra: &str) -> Rig {
    let dir = temp_dir("chain");
    let logins = ["login-1", "login-2", "login-3"];
    let files: Vec<_> = logins
        .iter()
        .map(|l| (*l, api_key(&format!("test-token-{l}")), 0o600))
        .collect();
    credentials(&dir, &files);
    let qbd = start_qbd(&dir, qbd_text);
    let (top, tables) = split_top(extra);
    let mut text = format!(
        "socket = \"{dir}/gw.sock\"\nqbd_socket = \"{qbd}\"\n{top}",
        dir = dir.display(),
        qbd = qbd.display()
    );
    if caps.is_some() {
        std::fs::create_dir_all(dir.join("state")).unwrap();
        writeln!(text, "spend_file = \"{}/state/spend.json\"", dir.display()).unwrap();
    }
    for (i, login) in logins.into_iter().enumerate() {
        let cap = caps.map_or(String::new(), |c| format!("spend_cap = {:?}\n", c[i]));
        write!(
            text,
            "[[logins]]\nname = \"{login}\"\n{ANTHROPIC_KEY}\n{cap}credentials = \"{}/creds/{login}.json\"\n",
            dir.display()
        )
        .unwrap();
    }
    text.push_str(
        r#"[[routes]]
alias = "chat"
role = "gateway"
chain = [
  { vendor = "vendor-a", model = "model-a" },
  { vendor = "vendor-b", model = "model-b", effort = "high" },
  { vendor = "vendor-c", model = "model-c" },
]
"#,
    );
    text.push_str(tables);
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gw = serve_gateway(
        &text,
        vec![(Api::Anthropic, Box::new(Shared(Arc::clone(&fake))))],
        Box::new(Counting(Arc::clone(&refreshes))),
        own_uid(),
        None,
    );
    Rig {
        dir,
        qbd,
        gw,
        fake,
        refreshes,
    }
}

fn usage_limit(resets: u64) -> Script {
    Script::Fail(
        Vec::new(),
        FailureKind::UsageLimit {
            resets_at: Some(resets),
        },
        window(1.0, resets),
    )
}

/// Marks `login` exhausted in qbd until `resets`, without a turn.
fn exhaust(qbd: &Path, login: &str, resets: u64) {
    let body = json!({
        "login": login,
        "outcome": "usage_limit",
        "windows": [{"name": "five_hour", "utilization": 1.0, "resets_at": resets}],
    });
    let body = body.to_string();
    let (status, answer) =
        qb::client::call(qbd, "POST", paths::REPORT, Some(body.as_bytes()), None).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
}

fn logins_called(r: &Rig) -> Vec<String> {
    r.fake.calls().into_iter().map(|c| c.0).collect()
}

/// `(vendor, model)` of the turn's `route` event.
fn route_of(events: &[StreamEvent]) -> (String, String) {
    match events.first() {
        Some(StreamEvent::Route { route }) => (route.vendor.clone(), route.model.clone()),
        other => panic!("not a route event: {other:?}"),
    }
}

fn tried(e: &GatewayError) -> Vec<(String, ErrorClass)> {
    e.tried
        .iter()
        .map(|a| (a.login_label.clone().unwrap(), a.class))
        .collect()
}

fn routes_of(gw: &Path) -> Vec<RouteStatus> {
    let (status, body) = call(gw, "GET", paths::MODEL_ROUTES, "");
    assert_eq!(status, 200);
    serde_json::from_slice::<RoutesAnswer>(&body)
        .unwrap()
        .routes
}

#[test]
fn a_chain_moves_to_the_next_step_after_a_usage_limit() {
    let r = chain_rig();
    let resets = unix_now() + 3600;
    r.fake.script("login-1", usage_limit(resets));
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-b".into(), "model-b".into()));
    assert_eq!(logins_called(&r), ["login-1", "login-2"]);
    assert_eq!(
        r.fake.picked.lock().unwrap().clone(),
        [
            ("vendor-a".into(), "model-a".into(), None),
            ("vendor-b".into(), "model-b".into(), Some("high".into())),
        ],
        "each step runs its own pin"
    );
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_chain_skips_a_step_qbd_makes_wait_without_calling_it() {
    let r = chain_rig();
    exhaust(&r.qbd, "login-1", unix_now() + 3600);
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-b".into(), "model-b".into()));
    assert_eq!(logins_called(&r), ["login-2"]);
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn a_chain_reaches_its_third_step_when_the_first_two_fail() {
    let r = chain_rig();
    r.fake.script(
        "login-1",
        Script::Fail(
            Vec::new(),
            FailureKind::Overloaded { retry_after: None },
            Vec::new(),
        ),
    );
    r.fake.script(
        "login-2",
        Script::Fail(
            Vec::new(),
            FailureKind::RateLimited {
                retry_after: Some(60),
            },
            Vec::new(),
        ),
    );
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-3", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-c".into(), "model-c".into()));
    assert_eq!(logins_called(&r), ["login-1", "login-2", "login-3"]);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-2"), LoginStatus::RateLimited);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_chain_failure_after_the_first_event_ends_the_turn_without_a_fallback() {
    let r = chain_rig();
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
    assert_eq!(
        tried(e),
        [("login-1".to_owned(), ErrorClass::QuotaExhausted)]
    );
    assert_eq!(e.resets_at, Some(resets));
    assert_eq!(logins_called(&r), ["login-1"], "no step after content");
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn a_spent_chain_answers_quota_exhausted_with_the_nearest_reset() {
    let r = chain_rig();
    let now = unix_now();
    let resets = [now + 7200, now + 3600, now + 5400];
    for (login, at) in ["login-1", "login-2", "login-3"].into_iter().zip(resets) {
        r.fake.script(login, usage_limit(at));
    }
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["error QuotaExhausted"]);
    let e = last_error(&events);
    assert_eq!(e.resets_at, Some(now + 3600));
    assert!(e.retryable);
    assert_eq!(
        tried(e),
        [
            ("login-1".to_owned(), ErrorClass::QuotaExhausted),
            ("login-2".to_owned(), ErrorClass::QuotaExhausted),
            ("login-3".to_owned(), ErrorClass::QuotaExhausted),
        ]
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
    let next = turn(&r.gw, &turn_body("turn-2")).2;
    assert_eq!(kinds(&next), ["error QuotaExhausted"]);
    assert_eq!(last_error(&next).resets_at, Some(now + 3600));
    assert_eq!(last_error(&next).tried, Vec::new(), "no step needs a call");
    assert_eq!(r.fake.calls().len(), 3);
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn routes_show_a_chain_on_its_first_ready_step_or_its_nearest_reset() {
    let r = chain_rig();
    let shown = |gw: &Path| {
        let route = routes_of(gw).remove(0);
        (route.state, route.vendor, route.model, route.resets_at)
    };
    let ready = |vendor: &str, model: &str| {
        (
            RouteState::Ready,
            Some(vendor.to_owned()),
            Some(model.to_owned()),
            None,
        )
    };
    assert_eq!(shown(&r.gw), ready("vendor-a", "model-a"));
    let now = unix_now();
    exhaust(&r.qbd, "login-1", now + 7200);
    assert_eq!(shown(&r.gw), ready("vendor-b", "model-b"));
    exhaust(&r.qbd, "login-2", now + 3600);
    exhaust(&r.qbd, "login-3", now + 5400);
    assert_eq!(
        shown(&r.gw),
        (RouteState::Exhausted, None, None, Some(now + 3600))
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
    assert_eq!(r.fake.calls(), Vec::new());
}

/// The config file of the gateway on socket `gw`.
fn config_file(gw: &Path) -> PathBuf {
    gw.with_file_name("gateway.toml")
}

/// Rewrites the config file of the gateway on `gw` with `edit`, which must change it, and asks
/// the gateway to reload: the answer's status and body.
fn reload_with(gw: &Path, edit: impl FnOnce(&str) -> String) -> (u16, Vec<u8>) {
    let file = config_file(gw);
    let text = std::fs::read_to_string(&file).unwrap();
    let edited = edit(&text);
    assert_ne!(edited, text, "the edit changes the file");
    std::fs::write(&file, edited).unwrap();
    call(gw, "POST", paths::MODEL_RELOAD, "")
}

fn aliases(gw: &Path) -> Vec<String> {
    routes_of(gw).into_iter().map(|r| r.alias).collect()
}

#[test]
fn a_turn_in_flight_keeps_its_chain_across_a_reload_and_the_next_takes_the_new_one() {
    let r = chain_rig();
    let (release, held) = std::sync::mpsc::channel();
    r.fake
        .script("login-1", Script::Held(vec![text("old")], held));
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
    let first_step = "  { vendor = \"vendor-a\", model = \"model-a\" },\n";
    let (status, body) = reload_with(&r.gw, |t| t.replace(first_step, ""));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: ReloadAnswer = serde_json::from_slice(&body).unwrap();
    assert_eq!((answer.routes, answer.logins), (1, 3));

    release.send(()).unwrap();
    let (status, _, rest) = finish(s, seen);
    assert_eq!(status, 200);
    let events = events(&rest);
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-a".into(), "model-a".into()));

    let (_, _, events) = turn(&r.gw, &turn_body("turn-2"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-b".into(), "model-b".into()));
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn routes_and_admissions_follow_the_aliases_a_reload_adds_and_removes() {
    let r = rig();
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);
    let mut answer = (0, Vec::new());
    let logged = stderr_until("gateway: reloaded", || {
        answer = reload_with(&r.gw, |t| {
            t.replace("alias = \"chat\"", "alias = \"added\"")
        });
    });
    assert_eq!(answer.0, 200, "{}", String::from_utf8_lossy(&answer.1));
    let reloaded = format!(
        "gateway: reloaded {}: 2 routes, 2 logins",
        config_file(&r.gw).display()
    );
    assert!(logged.contains(&reloaded), "{logged}");
    assert_eq!(aliases(&r.gw), ["added", "spare"]);

    let mut body = turn_body("turn-1");
    body["route"] = json!("added");
    let (_, _, events) = turn(&r.gw, &body);
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
    body["route"] = json!("chat");
    body["request_id"] = json!("turn-2");
    let (status, e) = rejection(&r.gw, "POST", paths::MODEL_TURN, &body.to_string());
    assert_eq!((status, e.class), (400, ErrorClass::BadRequest));
    assert_eq!(
        e.message.as_deref(),
        Some("unknown route alias `chat`"),
        "{e:?}"
    );
}

/// Asks the gateway on `gw` to reload after `edit`, expects a refusal whose message holds
/// `says`, logged in one line, and puts the file back.
fn refused_reload(gw: &Path, edit: impl FnOnce(&str) -> String, says: &str) {
    let file = config_file(gw);
    let before = std::fs::read_to_string(&file).unwrap();
    let mut answer = (0, Vec::new());
    let logged = stderr_until("reload refused", || answer = reload_with(gw, edit));
    std::fs::write(&file, before).unwrap();
    let e: GatewayError = serde_json::from_slice(&answer.1).unwrap();
    assert_eq!((answer.0, e.class), (400, ErrorClass::BadRequest), "{e:?}");
    let message = e.message.unwrap();
    let refusal = format!("reload refused: {}: {says}", file.display());
    assert!(message.starts_with(&refusal), "{message}");
    let lines: Vec<&str> = logged
        .lines()
        .filter(|l| l.contains("reload refused"))
        .collect();
    assert_eq!(lines.len(), 1, "{logged}");
    assert!(
        lines[0].contains(&format!("gateway: {message}")),
        "{logged}"
    );
}

#[test]
fn a_broken_config_is_refused_and_the_running_one_keeps_serving() {
    let r = rig();
    refused_reload(
        &r.gw,
        |t| format!("{t}[[routes]\n"),
        "unclosed array table, expected `]` (line 29)",
    );
    refused_reload(
        &r.gw,
        |t| t.replace("alias = \"spare\"", "alias = \"chat\""),
        "routes[1].alias: duplicate `chat` (line ",
    );
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
}

#[test]
fn a_change_that_needs_a_restart_is_refused_naming_the_field() {
    let r = rig();
    let socket = r.gw.display().to_string();
    refused_reload(
        &r.gw,
        |t| t.replace(&socket, &format!("{socket}.new")),
        "socket: changed; it takes effect only on a restart",
    );
    refused_reload(
        &r.gw,
        |t| format!("socket_mode = 0o660\n{t}"),
        "socket_mode: changed",
    );
    refused_reload(
        &r.gw,
        |t| t.replace("creds/login-2.json", "elsewhere/login-2.json"),
        "logins[1].credentials: lies outside the credential directories the sandbox opened; \
         it takes effect only on a restart",
    );
    let ledger = r.dir.join("usage.jsonl");
    refused_reload(
        &r.gw,
        |t| format!("{t}{}", usage_table(&ledger, 1 << 20)),
        "usage: changed; it takes effect only on a restart",
    );
    let login_3 = format!(
        "\n[[logins]]\nname = \"login-3\"\n{ANTHROPIC_KEY}\ncredentials = \"{}/creds/login-3.json\"\n",
        r.dir.display()
    );
    let (status, body) = reload_with(&r.gw, |t| format!("{t}{login_3}"));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: ReloadAnswer = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        answer.logins, 3,
        "a new file in an opened directory needs no restart"
    );
}

#[test]
fn only_the_gateway_s_own_uid_may_reload_it() {
    let files = [("login-1", api_key("test-token-1"), 0o600)];
    let extra = format!("\n[[clients]]\nname = \"client-a\"\nuid = {}\n", own_uid());
    let r = rig_as(4, &files, &extra, own_uid() + 1);
    let (status, body) = reload_with(&r.gw, |t| {
        t.replace("alias = \"spare\"", "alias = \"added\"")
    });
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (403, ErrorClass::Auth), "{e:?}");
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);
}

/// qbd's config of [`chain_rig`] whose vendors also declare the `spend` window of capped logins.
fn qbd_with_spend() -> String {
    QBD_THREE_VENDORS.replace(
        "windows = [{ name = \"five_hour\", length_s = 18000, t_burn_s = 1800 }]",
        "windows = [\n  { name = \"five_hour\", length_s = 18000, t_burn_s = 1800 },\n  { name = \"spend\", length_s = 2678400, t_burn_s = 0 },\n]",
    )
}

/// Prices of model-a and model-b; model-c has none.
const PRICES: &str = r#"
[prices."model-a"]
input = 1
output = 2
cache_read = 0
cache_write = 0

[prices."model-b"]
input = 3.0
output = 6.0
cache_read = 0
cache_write = 0
"#;

/// A [`chain_rig`] whose logins have the spend caps `caps`, with [`PRICES`].
fn spend_rig(caps: [f64; 3]) -> Rig {
    chain_rig_with(&qbd_with_spend(), Some(caps), PRICES)
}

fn usage(input: u64, output: u64) -> StreamEvent {
    StreamEvent::Usage {
        usage: Usage {
            input,
            output,
            cache_read: 0,
            cache_write: 0,
        },
    }
}

fn spend_of(gw: &Path) -> SpendAnswer {
    let (status, body) = call(gw, "GET", paths::MODEL_SPEND, "");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

/// USD `login` spent this month, by the gateway on `gw`.
fn spent(gw: &Path, login: &str) -> f64 {
    let answer = spend_of(gw);
    answer
        .logins
        .iter()
        .find(|l| l.login == login)
        .unwrap()
        .spent_usd
}

fn assert_usd(got: f64, want: f64) {
    assert!((got - want).abs() < 1e-9, "{got} USD, not {want}");
}

/// The end of the current UTC calendar month.
fn month_end() -> u64 {
    qb::gateway::spend::month(unix_now()).1
}

/// `(used, resets_at)` of `login`'s `spend` window in qbd.
fn spend_window(qbd: &Path, login: &str) -> (f64, Option<u64>) {
    let s = state(qbd);
    let l = s.logins.iter().find(|l| l.login == login).unwrap();
    let w = l.windows.iter().find(|w| w.name == "spend").unwrap();
    (w.used, w.resets_at)
}

/// Makes qbd forget the `spend` window of `login`, as if the gateway never reported it.
fn forget_spend(qbd: &Path, login: &str) {
    let body = json!({
        "login": login,
        "outcome": "error",
        "windows": [{"name": "spend", "utilization": 0.0}],
    })
    .to_string();
    let (status, answer) =
        qb::client::call(qbd, "POST", paths::REPORT, Some(body.as_bytes()), None).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
}

#[test]
fn a_login_at_its_spend_cap_is_not_called_and_the_next_turn_takes_the_next_step() {
    let r = spend_rig([1.0, 100.0, 100.0]);
    r.fake.script(
        "login-1",
        Script::Costed(vec![text("hi"), usage(10, 5)], None, Some(1.5)),
    );
    let first = turn(&r.gw, &turn_body("turn-1")).2;
    assert_eq!(
        kinds(&first),
        ["route login-1", "text_delta", "usage", "stop End"]
    );
    assert_usd(spent(&r.gw, "login-1"), 1.5);
    assert_eq!(spend_window(&r.qbd, "login-1"), (1.0, Some(month_end())));

    let second = turn(&r.gw, &turn_body("turn-2")).2;
    assert_eq!(kinds(&second), ["route login-2", "text_delta", "stop End"]);
    assert_eq!(logins_called(&r), ["login-1", "login-2"]);

    forget_spend(&r.qbd, "login-1");
    let third = turn(&r.gw, &turn_body("turn-3")).2;
    assert_eq!(kinds(&third), ["route login-2", "text_delta", "stop End"]);
    assert_eq!(
        logins_called(&r),
        ["login-1", "login-2", "login-2"],
        "the gateway refuses the capped login qbd picked"
    );
    assert_eq!(spend_window(&r.qbd, "login-1"), (1.0, Some(month_end())));
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn turns_without_a_reported_cost_are_priced_per_model_from_the_table() {
    let r = spend_rig([100.0, 100.0, 100.0]);
    for login in ["login-1", "login-2"] {
        r.fake.script(
            login,
            Script::Costed(vec![text("hi"), usage(1_000_000, 500_000)], None, None),
        );
    }
    let resets = unix_now() + 3600;
    turn(&r.gw, &turn_body("turn-1"));
    exhaust(&r.qbd, "login-1", resets);
    turn(&r.gw, &turn_body("turn-2"));
    exhaust(&r.qbd, "login-2", resets);
    assert_eq!(logins_called(&r), ["login-1", "login-2"]);
    assert_usd(spent(&r.gw, "login-1"), 2.0);
    assert_usd(spent(&r.gw, "login-2"), 6.0);

    for _ in 0..2 {
        r.fake.script(
            "login-3",
            Script::Costed(vec![text("hi"), usage(1_000_000, 0)], None, None),
        );
    }
    let logged = stderr_until("has no price", || {
        turn(&r.gw, &turn_body("turn-3"));
        turn(&r.gw, &turn_body("turn-4"));
    });
    let warned = logged
        .lines()
        .filter(|l| l.contains("gateway: model `model-c` has no price"))
        .count();
    assert_eq!(warned, 1, "{logged}");
    assert_usd(spent(&r.gw, "login-3"), 0.0);
}

#[test]
fn when_every_login_is_at_its_cap_the_turn_and_the_routes_wait_for_the_month_end() {
    let r = spend_rig([0.5, 0.5, 0.5]);
    for login in ["login-1", "login-2", "login-3"] {
        r.fake
            .script(login, Script::Costed(vec![text("hi")], None, Some(1.0)));
    }
    for (i, login) in ["login-1", "login-2", "login-3"].into_iter().enumerate() {
        let events = turn(&r.gw, &turn_body(&format!("turn-{i}"))).2;
        assert_eq!(kinds(&events)[0], format!("route {login}"));
    }
    let events = turn(&r.gw, &turn_body("turn-last")).2;
    assert_eq!(kinds(&events), ["error QuotaExhausted"]);
    let e = last_error(&events);
    assert_eq!(e.resets_at, Some(month_end()));
    assert!(e.retryable);
    assert_eq!(r.fake.calls().len(), 3);
    let route = routes_of(&r.gw).remove(0);
    assert_eq!(
        (route.state, route.resets_at),
        (RouteState::Exhausted, Some(month_end()))
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());
}

#[test]
fn the_spend_count_survives_a_gateway_restart_on_the_same_file() {
    let r = spend_rig([1.0, 100.0, 100.0]);
    r.fake
        .script("login-1", Script::Costed(vec![text("hi")], None, Some(0.6)));
    turn(&r.gw, &turn_body("turn-1"));
    let file = r.dir.join("state/spend.json");
    let mode = std::fs::metadata(&file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let config = std::fs::read_to_string(config_file(&r.gw))
        .unwrap()
        .replace("gw.sock", "gw2.sock");
    let fake = Arc::new(Fake::default());
    let gw2 = serve_gateway(
        &config,
        vec![(Api::Anthropic, Box::new(Shared(Arc::clone(&fake))))],
        Box::new(Counting(Arc::default())),
        own_uid(),
        None,
    );
    assert_usd(spent(&gw2, "login-1"), 0.6);
    fake.script("login-1", Script::Costed(vec![text("hi")], None, Some(0.6)));
    let events = turn(&gw2, &turn_body("turn-2")).2;
    assert_eq!(kinds(&events)[0], "route login-1");
    assert_usd(spent(&gw2, "login-1"), 1.2);
    let events = turn(&gw2, &turn_body("turn-3")).2;
    assert_eq!(
        kinds(&events)[0],
        "route login-2",
        "the restored count reached the cap"
    );
}

/// Runs `qb --socket <gw> spend <args>` and parses its JSON output.
fn qb_spend<T: serde::de::DeserializeOwned>(gw: &Path, args: &[&str]) -> T {
    let out = Command::new(env!("CARGO_BIN_EXE_qb"))
        .arg("--socket")
        .arg(gw)
        .arg("spend")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn a_spend_reset_or_a_raised_cap_makes_the_login_run_again() {
    let r = spend_rig([1.0, 100.0, 100.0]);
    for _ in 0..2 {
        r.fake
            .script("login-1", Script::Costed(vec![text("hi")], None, Some(2.0)));
    }
    let first_login = |id: &str| kinds(&turn(&r.gw, &turn_body(id)).2).remove(0);
    assert_eq!(first_login("turn-1"), "route login-1");
    assert_eq!(first_login("turn-2"), "route login-2");

    let reset: LoginSpend = qb_spend(&r.gw, &["reset", "login-1"]);
    assert_eq!(
        (reset.login.as_str(), reset.spent_usd, reset.period_end),
        ("login-1", 0.0, month_end())
    );
    assert_eq!(first_login("turn-3"), "route login-1");
    assert_eq!(first_login("turn-4"), "route login-2");

    let (status, body) = reload_with(&r.gw, |t| t.replace("spend_cap = 1.0", "spend_cap = 5.0"));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(first_login("turn-5"), "route login-1");
    let answer: SpendAnswer = qb_spend(&r.gw, &[]);
    let shown: Vec<_> = answer
        .logins
        .iter()
        .map(|l| (l.login.as_str(), l.spent_usd, l.cap_usd, l.period_end))
        .collect();
    assert_eq!(
        shown,
        [
            ("login-1", 2.0, 5.0, month_end()),
            ("login-2", 0.0, 100.0, month_end()),
            ("login-3", 0.0, 100.0, month_end()),
        ]
    );

    let body = json!({"login": "login-9"}).to_string();
    let (status, e) = rejection(&r.gw, "POST", paths::MODEL_SPEND_RESET, &body);
    assert_eq!((status, e.class), (400, ErrorClass::BadRequest), "{e:?}");
    assert_eq!(
        e.message.as_deref(),
        Some("login `login-9` has no spend_cap")
    );
}

#[test]
fn only_the_gateway_s_own_uid_may_read_or_reset_the_spend() {
    let files = [("login-1", api_key("test-token-1"), 0o600)];
    let extra = format!("\n[[clients]]\nname = \"client-a\"\nuid = {}\n", own_uid());
    let r = rig_as(4, &files, &extra, own_uid() + 1);
    for (method, path, body) in [
        ("GET", paths::MODEL_SPEND, ""),
        ("POST", paths::MODEL_SPEND_RESET, r#"{"login":"login-1"}"#),
    ] {
        let (status, e) = rejection(&r.gw, method, path, body);
        assert_eq!((status, e.class), (403, ErrorClass::Auth), "{path}: {e:?}");
    }
}

/// A fresh `audit.jsonl` path in a directory of its own, not created yet.
fn audit_path() -> PathBuf {
    temp_dir("audit").join("audit.jsonl")
}

/// The `audit_file` line of `file`.
fn audit_key(file: &Path) -> String {
    format!("audit_file = \"{}\"\n", file.display())
}

/// `GET /v1/model/audit` with `query` on `gw`: the status and the answer body.
fn audit_of(gw: &Path, query: &str) -> (u16, Vec<u8>) {
    call(gw, "GET", &format!("{}{query}", paths::MODEL_AUDIT), "")
}

fn audit_answer(gw: &Path, query: &str) -> AuditAnswer {
    let (status, body) = audit_of(gw, query);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

/// Actor, action, object, result and reason of an audit entry.
type AuditRow<'a> = (
    &'a str,
    AuditAction,
    Option<&'a str>,
    AuditResult,
    Option<&'a str>,
);

/// The [`AuditRow`] of each entry.
fn audit_rows(entries: &[AuditEntry]) -> Vec<AuditRow<'_>> {
    entries
        .iter()
        .map(|e| {
            let (object, reason) = (e.object.as_deref(), e.reason.as_deref());
            (e.actor.as_str(), e.action, object, e.result, reason)
        })
        .collect()
}

fn mode_of(file: &Path) -> u32 {
    std::fs::metadata(file).unwrap().permissions().mode() & 0o777
}

#[test]
fn reloads_and_spend_resets_leave_audit_lines_that_read_back_oldest_first() {
    let audit = audit_path();
    let started = unix_now();
    let r = chain_rig_with(
        &qbd_with_spend(),
        Some([1.0, 100.0, 100.0]),
        &format!("{}{PRICES}", audit_key(&audit)),
    );
    let (status, body) = reload_with(&r.gw, |t| t.replace("spend_cap = 1.0", "spend_cap = 5.0"));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let file = config_file(&r.gw);
    let served = std::fs::read_to_string(&file).unwrap();
    let (status, _) = reload_with(&r.gw, |t| format!("{t}[[routes]\n"));
    assert_eq!(status, 400);
    std::fs::write(&file, served).unwrap();
    for (body, want) in [
        (r#"{"login":"login-1"}"#, 200),
        (r#"{"name":"login-1"}"#, 400),
        (r#"{"login":"login-9"}"#, 400),
    ] {
        let (status, answer) = call(&r.gw, "POST", paths::MODEL_SPEND_RESET, body);
        assert_eq!(status, want, "{body}: {}", String::from_utf8_lossy(&answer));
    }

    let answer = audit_answer(&r.gw, "");
    let actor = format!("uid:{}", own_uid());
    let config = file.display().to_string();
    let mut rows = audit_rows(&answer.entries);
    let broken = rows[1].4.take().unwrap();
    let unclosed = format!("{config}: unclosed array table");
    assert!(broken.starts_with(&unclosed), "{broken}");
    let bad_body = rows[3].4.take().unwrap();
    assert!(bad_body.contains("unknown field `name`"), "{bad_body}");
    let (reload, reset) = (AuditAction::Reload, AuditAction::SpendReset);
    let (ok, refused) = (AuditResult::Ok, AuditResult::Refused);
    let (actor, config) = (actor.as_str(), Some(config.as_str()));
    let no_cap = Some("login `login-9` has no spend_cap");
    assert_eq!(
        rows,
        [
            (actor, reload, config, ok, None),
            (actor, reload, config, refused, None),
            (actor, reset, Some("login-1"), ok, None),
            (actor, reset, None, refused, None),
            (actor, reset, Some("login-9"), refused, no_cap),
        ]
    );
    assert_eq!(answer.skipped, 0);
    let hashes: Vec<_> = answer
        .entries
        .iter()
        .map(|e| {
            (
                e.config_sha256_before.as_deref(),
                e.config_sha256_after.as_deref(),
            )
        })
        .collect();
    let (Some(first), Some(edited)) = hashes[0] else {
        panic!("a reload names both hashes: {hashes:?}");
    };
    assert_ne!(first, edited, "the reload took the edited file");
    assert_eq!(first.len(), 64);
    assert!(first.bytes().all(|b| b.is_ascii_hexdigit()), "{first}");
    assert_eq!(
        hashes[1..],
        [
            (Some(edited), Some(edited)),
            (None, None),
            (None, None),
            (None, None)
        ],
        "a refused reload keeps the served file"
    );
    let now = unix_now();
    assert!(
        answer
            .entries
            .iter()
            .all(|e| (started..=now).contains(&e.at))
    );
    assert!(answer.entries.iter().all(|e| e.backup.is_none()));
    assert_eq!(mode_of(&audit), 0o600);

    let first_two = audit_answer(&r.gw, "?limit=2");
    assert_eq!(first_two.entries, answer.entries[..2]);
    let later = audit_answer(&r.gw, &format!("?since={}&limit=1000", now + 1));
    assert_eq!(later.entries, Vec::new());
    for query in ["?limit=0", "?limit=1001", "?since=soon", "?until=1"] {
        let (status, body) = audit_of(&r.gw, query);
        assert_eq!(status, 400, "{query}: {}", String::from_utf8_lossy(&body));
    }
    let (status, _) = call(&r.gw, "POST", paths::MODEL_AUDIT, "");
    assert_eq!(status, 405);
}

#[test]
fn another_uid_is_refused_the_admin_endpoints_and_its_refusals_are_recorded() {
    let audit = audit_path();
    let files = [("login-1", api_key("test-token-1"), 0o600)];
    let extra = format!(
        "{}[[clients]]\nname = \"client-a\"\nuid = {}\n",
        audit_key(&audit),
        own_uid()
    );
    let r = rig_as(4, &files, &extra, own_uid() + 1);
    for (method, path, body) in [
        ("POST", paths::MODEL_RELOAD, ""),
        ("POST", paths::MODEL_SPEND_RESET, r#"{"login":"login-1"}"#),
        ("GET", paths::MODEL_AUDIT, ""),
    ] {
        let (status, e) = rejection(&r.gw, method, path, body);
        assert_eq!((status, e.class), (403, ErrorClass::Auth), "{path}: {e:?}");
    }
    let entries: Vec<AuditEntry> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actor = format!("uid:{}", own_uid());
    let config = config_file(&r.gw).display().to_string();
    assert_eq!(
        audit_rows(&entries),
        [
            (
                actor.as_str(),
                AuditAction::Reload,
                Some(config.as_str()),
                AuditResult::Refused,
                Some("only the gateway's own uid may reload it"),
            ),
            (
                actor.as_str(),
                AuditAction::SpendReset,
                None,
                AuditResult::Refused,
                Some("only the gateway's own uid may read or reset the spend"),
            ),
        ]
    );
    assert_eq!(
        entries[0].config_sha256_before, entries[0].config_sha256_after,
        "nothing was reloaded"
    );
    assert_eq!(mode_of(&audit), 0o600);
}

#[test]
fn the_loopback_listener_does_not_serve_the_audit_to_a_client_token() {
    let (listener, addr, front) = loopback_front("");
    let extra = format!("{}{front}", audit_key(&audit_path()));
    let r = rig_on(4, &key_files(), &extra, own_uid(), Some(listener));
    assert_eq!(audit_answer(&r.gw, "").entries, Vec::new());
    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    let (status, _, body) = finish(
        tcp_send(addr, "GET", paths::MODEL_AUDIT, &auth, ""),
        Vec::new(),
    );
    assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
    assert!(!String::from_utf8_lossy(&body).contains("entries"));
}

#[test]
fn a_line_that_does_not_parse_is_skipped_and_counted() {
    let audit = audit_path();
    let r = rig_as(4, &key_files(), &audit_key(&audit), own_uid());
    let empty = audit_answer(&r.gw, "");
    assert_eq!((empty.entries, empty.skipped), (Vec::new(), 0));
    let kept = r#"{"at":1800000000,"actor":"uid:1000","action":"spend_reset","object":"login-1","result":"ok"}"#;
    let later = kept.replace("1800000000", "1800000060");
    let lines = [
        kept,
        "{\"at\":1800000030,\"actor\":\"uid:1000\"",
        r#"{"at":1800000040,"actor":"uid:1000","action":"rename","result":"ok"}"#,
        "not json",
        &later,
    ];
    std::fs::write(&audit, format!("{}\n", lines.join("\n"))).unwrap();
    let answer = audit_answer(&r.gw, "");
    let at: Vec<u64> = answer.entries.iter().map(|e| e.at).collect();
    assert_eq!(
        (at, answer.skipped),
        (vec![1_800_000_000, 1_800_000_060], 3)
    );
    let since = audit_answer(&r.gw, "?since=1800000001");
    assert_eq!(since.entries.len(), 1);
    assert_eq!(since.skipped, 3);

    let plain = rig();
    let (status, e) = rejection(&plain.gw, "GET", paths::MODEL_AUDIT, "");
    assert_eq!((status, e.class), (404, ErrorClass::BadRequest), "{e:?}");
    assert_eq!(
        e.message.as_deref(),
        Some("this gateway keeps no audit: its config sets no `audit_file`")
    );
}

#[test]
fn a_failed_audit_append_is_logged_and_leaves_the_answer_alone() {
    let audit = temp_dir("audit").join("missing").join("audit.jsonl");
    let r = rig_as(4, &key_files(), &audit_key(&audit), own_uid());
    let mut answer = (0, Vec::new());
    let needle = format!("gateway: audit line not appended to {}: ", audit.display());
    let logged = stderr_until(&needle, || {
        answer = reload_with(&r.gw, |t| {
            t.replace("alias = \"spare\"", "alias = \"added\"")
        });
    });
    assert_eq!(answer.0, 200, "{}", String::from_utf8_lossy(&answer.1));
    let line = logged.lines().find(|l| l.contains(&needle)).unwrap();
    assert!(
        line.starts_with("error: ") || line.starts_with("<3>"),
        "{logged}"
    );
    assert_eq!(aliases(&r.gw), ["added", "chat"]);
}

/// The `[usage]` table of a ledger at `file` rotated past `rotate_bytes` and kept 30 days.
fn usage_table(file: &Path, rotate_bytes: u64) -> String {
    format!(
        "[usage]\nfile = \"{}\"\nrotate_bytes = {rotate_bytes}\nkeep_days = 30\n",
        file.display()
    )
}

/// The ledger file `file` and its rotated files, oldest first.
fn ledger_files(file: &Path) -> Vec<PathBuf> {
    let rotated = qb::gateway::usage::rotated(file).unwrap();
    let mut files: Vec<PathBuf> = rotated.into_iter().map(|(_, f)| f).collect();
    files.push(file.to_owned());
    files
}

/// The lines of every ledger file of `file`, oldest first.
fn usage_lines(file: &Path) -> Vec<UsageLine> {
    ledger_files(file)
        .iter()
        .flat_map(|f| {
            let text = std::fs::read_to_string(f).unwrap();
            let lines: Vec<UsageLine> = text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            lines
        })
        .collect()
}

fn tool_call(id: &str, name: &str, input: Value) -> StreamEvent {
    let Value::Object(input) = input else {
        panic!("tool input is an object");
    };
    StreamEvent::ToolCall {
        tool_call: ToolCall {
            id: id.into(),
            name: name.into(),
            input,
        },
    }
}

#[test]
fn a_finished_turn_leaves_one_content_free_usage_line_priced_from_the_table() {
    let ledger = temp_dir("usage").join("usage.jsonl");
    let extra = format!(
        "[[clients]]\nname = \"client-a\"\nuid = {}\n{}\
         [prices.\"model-large\"]\ninput = 2\noutput = 10\ncache_read = 0.5\ncache_write = 4\n",
        own_uid(),
        usage_table(&ledger, 1 << 20)
    );
    let r = rig_as(4, &key_files(), &extra, own_uid() + 1);
    let long = "t".repeat(70);
    r.fake.script(
        "login-1",
        Script::Finish(
            vec![
                StreamEvent::Thinking {
                    thinking: Thinking {
                        vendor: "vendor-a".into(),
                        opaque: "marker-thinking-c3".into(),
                    },
                },
                text("marker-answer-91"),
                tool_call("call_1", "search", json!({"q": "marker-arg-4d"})),
                tool_call("call_2", "read_file", json!({"path": "marker-arg-77"})),
                tool_call("call_3", "search", json!({"q": "marker-arg-e0"})),
                tool_call("call_4", &long, json!({})),
                StreamEvent::Usage {
                    usage: Usage {
                        input: 1_000_000,
                        output: 200_000,
                        cache_read: 2_000_000,
                        cache_write: 500_000,
                    },
                },
            ],
            StopReason::ToolUse,
            Vec::new(),
        ),
    );
    let mut body = turn_body("turn-1");
    body["system"] = json!("marker-system-5a");
    body["messages"] = json!([
        {"role": "user", "content": [{"type": "text", "text": "marker-prompt-b2"}]},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "call_0", "name": "search",
             "input": {"q": "marker-history-arg-6f"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "id": "call_0", "content": "marker-result-08"}]}
    ]);
    body["tools"] = json!([{"name": "search", "description": "marker-tool-doc-3e",
                            "input_schema": {"type": "object"}}]);
    let started = unix_now();
    let (_, _, events) = turn(&r.gw, &body);
    assert_eq!(kinds(&events).last().unwrap(), "stop ToolUse");

    let lines = usage_lines(&ledger);
    assert_eq!(lines.len(), 1, "{lines:?}");
    let line = &lines[0];
    assert!((started..=unix_now()).contains(&line.at), "{line:?}");
    assert!(line.duration_ms < 20_000, "{line:?}");
    assert_eq!(
        (
            line.request_id.as_str(),
            line.client.as_str(),
            line.route.as_str(),
            line.step,
            line.login.as_str(),
            line.model.as_str(),
        ),
        ("turn-1", "client-a", "chat", 0, "login-1", "model-large")
    );
    assert_eq!(
        (line.outcome, line.stop, line.error),
        (Outcome::Ok, Some(StopReason::ToolUse), None)
    );
    assert_eq!(
        (
            line.usage.input,
            line.usage.output,
            line.usage.cache_read,
            line.usage.cache_write
        ),
        (1_000_000, 200_000, 2_000_000, 500_000)
    );
    assert_usd(line.usd.unwrap(), 7.0);
    assert_eq!(line.usd_source, Some(UsdSource::Prices));
    assert_eq!(line.tools, ["read_file", "search", &long[..64]]);
    assert_eq!(mode_of(&ledger), 0o600);

    let sent = format!("{:?}", r.fake.calls());
    for marker in [
        "marker-prompt-b2",
        "marker-history-arg-6f",
        "marker-result-08",
    ] {
        assert!(sent.contains(marker), "the adapter got {marker}");
    }
    let raw = std::fs::read_to_string(&ledger).unwrap();
    for marker in ["marker-", "test-token-"] {
        assert!(!raw.contains(marker), "{marker} in {raw}");
    }
}

#[test]
fn a_chain_fallback_leaves_one_usage_line_per_step_with_the_failure_on_the_first() {
    let ledger = temp_dir("usage").join("usage.jsonl");
    let r = chain_rig_with(QBD_THREE_VENDORS, None, &usage_table(&ledger, 1 << 20));
    r.fake.script("login-1", usage_limit(unix_now() + 3600));
    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-2", "text_delta", "stop End"]);
    let client = format!("uid:{}", own_uid());
    let rows: Vec<_> = usage_lines(&ledger)
        .into_iter()
        .map(|l| {
            assert_eq!(
                (l.request_id.as_str(), l.client.as_str()),
                ("turn-1", client.as_str())
            );
            assert_eq!(
                (l.usd, l.usd_source, l.tools.len()),
                (None, None, 0),
                "unpriced"
            );
            (l.step, l.login, l.model, l.outcome, l.stop, l.error)
        })
        .collect();
    assert_eq!(
        rows,
        [
            (
                0,
                "login-1".into(),
                "model-a".into(),
                Outcome::UsageLimit,
                None,
                Some(ErrorClass::QuotaExhausted)
            ),
            (
                1,
                "login-2".into(),
                "model-b".into(),
                Outcome::Ok,
                Some(StopReason::End),
                None
            ),
        ]
    );
}

#[test]
fn the_ledger_rotates_before_rotate_bytes_and_prunes_expired_rotated_files() {
    let dir = temp_dir("usage");
    let ledger = dir.join("usage.jsonl");
    let started = unix_now();
    let stamp = |s: u64| dir.join(format!("usage.jsonl.{s}"));
    let (expired, recent) = (stamp(started - 31 * 86_400), stamp(started - 86_400));
    let other = dir.join("usage.jsonl.old");
    for f in [&expired, &recent, &other] {
        std::fs::write(f, "").unwrap();
    }
    let r = rig_as(4, &key_files(), &usage_table(&ledger, 1024), own_uid());
    let ids: Vec<String> = (0..12).map(|i| format!("turn-{i}")).collect();
    for id in &ids {
        turn(&r.gw, &turn_body(id));
    }

    assert!(!expired.exists(), "older than keep_days");
    assert!(recent.exists() && other.exists());
    let files = ledger_files(&ledger);
    assert_eq!(files[0], recent);
    let rotated = &files[1..files.len() - 1];
    assert!(rotated.len() >= 2, "{files:?}");
    let now = unix_now();
    for f in rotated {
        let s = f.to_str().unwrap().rsplit('.').next().unwrap();
        assert!((started..=now + 12).contains(&s.parse().unwrap()), "{f:?}");
    }
    for f in &files {
        let len = std::fs::metadata(f).unwrap().len();
        assert!(len <= 1024, "{f:?} has {len} bytes");
    }
    let written: Vec<String> = usage_lines(&ledger)
        .into_iter()
        .map(|l| l.request_id)
        .collect();
    assert_eq!(written, ids);
}

#[test]
fn a_failed_usage_append_is_logged_and_leaves_the_turn_alone() {
    let ledger = temp_dir("usage").join("missing").join("usage.jsonl");
    let r = rig_as(4, &key_files(), &usage_table(&ledger, 1 << 20), own_uid());
    let mut events = Vec::new();
    let needle = format!("gateway: usage line not appended to {}: ", ledger.display());
    let logged = stderr_until(&needle, || {
        events = turn(&r.gw, &turn_body("turn-1")).2;
    });
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);
    let line = logged.lines().find(|l| l.contains(&needle)).unwrap();
    assert!(
        line.starts_with("error: ") || line.starts_with("<3>"),
        "{logged}"
    );
}

/// One ledger line at `at` as `edit` leaves it, starting from an unpriced `ok` attempt of
/// `client-a` on `login-1`, `model-a` and route `chat` without usage or tools.
fn ledger_line(at: u64, edit: impl FnOnce(&mut UsageLine)) -> String {
    let mut line = UsageLine {
        at,
        duration_ms: 100,
        request_id: format!("turn-{at}"),
        client: "client-a".into(),
        route: "chat".into(),
        step: 0,
        login: "login-1".into(),
        model: "model-a".into(),
        outcome: Outcome::Ok,
        stop: Some(StopReason::End),
        error: None,
        usage: Usage::default(),
        usd: None,
        usd_source: None,
        tools: Vec::new(),
    };
    edit(&mut line);
    serde_json::to_string(&line).unwrap()
}

/// `GET /v1/model/usage` with `query` on `gw`: the status and the answer body.
fn usage_of(gw: &Path, query: &str) -> (u16, Vec<u8>) {
    call(gw, "GET", &format!("{}{query}", paths::MODEL_USAGE), "")
}

fn usage_answer(gw: &Path, query: &str) -> UsageAnswer {
    let (status, body) = usage_of(gw, query);
    assert_eq!(status, 200, "{query}: {}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

/// Start, group and attempts of each row.
fn usage_rows(answer: &UsageAnswer) -> Vec<(u64, Option<&str>, u64)> {
    answer
        .rows
        .iter()
        .map(|r| (r.start, r.group.as_deref(), r.attempts))
        .collect()
}

/// 2024-02-28T22:00:00Z and 2024-04-01T00:00:00Z.
const USAGE_FROM: u64 = 1_709_157_600;
const USAGE_TO: u64 = 1_711_929_600;

/// A gateway whose ledger holds attempts from 2024-02-28 to 2024-04-01 in a rotated file and the
/// current one, one line before [`USAGE_FROM`] and one at [`USAGE_TO`], beside a rotated file
/// stamped before [`USAGE_FROM`] that holds only lines that do not parse.
fn usage_rig() -> Rig {
    let dir = temp_dir("usage");
    let ledger = dir.join("usage.jsonl");
    let lines = [
        ledger_line(USAGE_FROM - 1, |l| l.usage.input = 1_000_000),
        // 2024-02-28T23:59:59Z
        ledger_line(1_709_164_799, |l| {
            l.usage = Usage {
                input: 100,
                output: 10,
                cache_read: 1000,
                cache_write: 0,
            };
            l.usd = Some(0.5);
            l.usd_source = Some(UsdSource::Prices);
            l.tools = vec!["read_file".into(), "search".into()];
            l.duration_ms = 1000;
        }),
        // 2024-02-29T00:00:00Z
        ledger_line(1_709_164_800, |l| {
            l.client = "client-b".into();
            l.login = "login-2".into();
            l.model = "model-b".into();
            l.route = "code".into();
            l.outcome = Outcome::UsageLimit;
            l.stop = None;
            l.error = Some(ErrorClass::QuotaExhausted);
            l.duration_ms = 200;
        }),
        // 2024-02-29T23:30:00Z
        ledger_line(1_709_249_400, |l| {
            l.model = "model-b".into();
            l.usage.input = 50;
            l.usage.output = 5;
            l.usage.cache_write = 20;
            l.usd = Some(0.25);
            l.usd_source = Some(UsdSource::Vendor);
            l.tools = vec!["search".into()];
            l.duration_ms = 300;
        }),
        // 2024-03-01T00:00:00Z
        ledger_line(1_709_251_200, |l| {
            l.login = "login-2".into();
            l.route = "code".into();
            l.outcome = Outcome::Error;
            l.stop = None;
            l.error = Some(ErrorClass::Unavailable);
            l.usage.input = 10;
            l.usd = Some(0.125);
            l.usd_source = Some(UsdSource::Prices);
            l.tools = vec!["search".into(), "search".into()];
            l.duration_ms = 400;
        }),
        // 2024-03-31T23:59:59Z
        ledger_line(1_711_929_599, |l| {
            l.client = "client-b".into();
            l.model = "model-c".into();
            l.route = "code".into();
            l.usage.input = 1;
            l.duration_ms = 500;
        }),
        ledger_line(USAGE_TO, |l| l.usage.input = 1_000_000),
    ];
    let overlong = ledger_line(USAGE_FROM - 2, |l| l.tools = vec!["t".repeat(70_000)]);
    let stamped = |s: u64| dir.join(format!("usage.jsonl.{s}"));
    std::fs::write(stamped(USAGE_FROM - 1), format!("not json\n{overlong}\n")).unwrap();
    std::fs::write(
        stamped(1_709_164_800),
        format!("{}\n", lines[..3].join("\n")),
    )
    .unwrap();
    std::fs::write(&ledger, format!("{}\n", lines[3..].join("\n"))).unwrap();
    rig_as(4, &key_files(), &usage_table(&ledger, 1 << 20), own_uid())
}

#[test]
fn usage_sums_the_window_s_attempts_of_the_current_and_rotated_ledger_files() {
    let r = usage_rig();
    let window = format!("?from={USAGE_FROM}&to={USAGE_TO}");
    let answer = usage_answer(&r.gw, &window);
    assert_eq!(
        (answer.from, answer.to, answer.group_by, answer.bucket),
        (USAGE_FROM, USAGE_TO, None, None)
    );
    assert_eq!(
        answer.rows,
        [UsageRow {
            start: USAGE_FROM,
            group: None,
            attempts: 5,
            failed: 2,
            input: 161,
            output: 15,
            cache_read: 1000,
            cache_write: 20,
            usd: 0.875,
            unpriced: 2,
            duration_ms: 2400,
        }]
    );
    assert_eq!(
        answer.skipped, 0,
        "the rotated file older than `from` is not read"
    );
    let (_, raw) = usage_of(&r.gw, &window);
    let raw: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(raw["rows"][0].get("group"), None);
    assert_eq!(raw.get("group_by"), None);

    let before_end = usage_answer(&r.gw, &format!("?from={USAGE_FROM}&to={}", USAGE_TO - 1));
    assert_eq!(usage_rows(&before_end), [(USAGE_FROM, None, 4)]);
    let past_end = usage_answer(&r.gw, &format!("?from={USAGE_FROM}&to={}", USAGE_TO + 1));
    assert_eq!(
        usage_rows(&past_end),
        [(USAGE_FROM, None, 6)],
        "`to` is exclusive"
    );
    let earlier = usage_answer(&r.gw, &format!("?to={USAGE_TO}&from={}", USAGE_FROM - 1));
    assert_eq!(usage_rows(&earlier), [(USAGE_FROM - 1, None, 6)]);
    assert_eq!(
        earlier.skipped, 2,
        "a rotated file stamped at `from` is read"
    );
}

#[test]
fn usage_rows_are_grouped_by_client_login_model_route_or_each_tool() {
    let r = usage_rig();
    let by = |group: &str| {
        let query = format!("?from={USAGE_FROM}&to={USAGE_TO}&group_by={group}");
        let answer = usage_answer(&r.gw, &query);
        assert_eq!(answer.group_by.unwrap().as_str(), group);
        assert_eq!(answer.skipped, 0);
        answer
    };
    let rows = |answer: &UsageAnswer| -> Vec<(String, u64)> {
        usage_rows(answer)
            .into_iter()
            .map(|(start, group, attempts)| {
                assert_eq!(start, USAGE_FROM);
                (group.unwrap().to_owned(), attempts)
            })
            .collect()
    };
    let named = |pairs: &[(&str, u64)]| -> Vec<(String, u64)> {
        pairs.iter().map(|(g, n)| ((*g).to_owned(), *n)).collect()
    };
    assert_eq!(
        rows(&by("client")),
        named(&[("client-a", 3), ("client-b", 2)])
    );
    let logins = by("login");
    assert_eq!(rows(&logins), named(&[("login-1", 3), ("login-2", 2)]));
    let sums: Vec<_> = logins
        .rows
        .iter()
        .map(|r| (r.failed, r.input, r.usd, r.unpriced, r.duration_ms))
        .collect();
    assert_eq!(sums, [(0, 151, 0.75, 1, 1800), (2, 10, 0.125, 1, 600)]);
    assert_eq!(
        rows(&by("model")),
        named(&[("model-a", 2), ("model-b", 2), ("model-c", 1)])
    );
    assert_eq!(rows(&by("route")), named(&[("chat", 2), ("code", 3)]));
    let tools = by("tool");
    assert_eq!(rows(&tools), named(&[("read_file", 1), ("search", 3)]));
    let input: Vec<u64> = tools.rows.iter().map(|r| r.input).collect();
    assert_eq!(
        input,
        [100, 160],
        "an attempt counts once under each of its tools"
    );
}

#[test]
fn usage_buckets_are_utc_hours_days_and_months() {
    let r = usage_rig();
    let bucketed = |bucket: &str, group: &str| {
        let query = format!("?from={USAGE_FROM}&to={USAGE_TO}&bucket={bucket}{group}");
        let answer = usage_answer(&r.gw, &query);
        assert_eq!(answer.bucket.unwrap().as_str(), bucket);
        answer
    };
    // 2024-02-28T23:00Z, 2024-02-29T00:00Z, 2024-02-29T23:00Z, 2024-03-01T00:00Z,
    // 2024-03-31T23:00Z.
    let hours = [
        1_709_161_200,
        1_709_164_800,
        1_709_247_600,
        1_709_251_200,
        1_711_926_000,
    ];
    let one_each: Vec<_> = hours.iter().map(|h| (*h, None, 1)).collect();
    assert_eq!(usage_rows(&bucketed("hour", "")), one_each);
    // 2024-02-28, the leap day 2024-02-29, 2024-03-01, 2024-03-31.
    let (eve, leap, march, last) = (1_709_078_400, 1_709_164_800, 1_709_251_200, 1_711_843_200);
    assert_eq!(
        usage_rows(&bucketed("day", "")),
        [
            (eve, None, 1),
            (leap, None, 2),
            (march, None, 1),
            (last, None, 1)
        ]
    );
    // 2024-02-01: the leap February, starting before `from`.
    let february = 1_706_745_600;
    assert_eq!(
        usage_rows(&bucketed("month", "")),
        [(february, None, 3), (march, None, 2)]
    );
    let (a, b) = (Some("client-a"), Some("client-b"));
    assert_eq!(
        usage_rows(&bucketed("day", "&group_by=client")),
        [
            (eve, a, 1),
            (leap, a, 1),
            (leap, b, 1),
            (march, a, 1),
            (last, b, 1)
        ],
        "ordered by start, then group"
    );
}

#[test]
fn bad_and_overlong_lines_are_skipped_and_counted_by_usage_and_audit() {
    let audit = audit_path();
    let ledger = temp_dir("usage").join("usage.jsonl");
    let extra = format!("{}{}", audit_key(&audit), usage_table(&ledger, 1 << 20));
    let r = rig_as(4, &key_files(), &extra, own_uid());
    let at = USAGE_FROM;
    let mut lines: Vec<Vec<u8>> = vec![
        ledger_line(at, |_| {}).into(),
        b"not json".to_vec(),
        ledger_line(at + 1, |l| l.tools = vec!["t".repeat(70_000)]).into(),
        format!("{{\"at\":{at}}}").into(),
        vec![b'{', 0xff, b'}'],
        ledger_line(at + 2, |_| {}).into(),
    ];
    std::fs::write(&ledger, lines.join(&b'\n')).unwrap();
    let answer = usage_answer(&r.gw, &format!("?from={at}&to={}", at + 10));
    assert_eq!(
        (usage_rows(&answer), answer.skipped),
        (vec![(at, None, 2)], 4)
    );

    let entry = |at: u64, object: &str| {
        format!(
            r#"{{"at":{at},"actor":"uid:1000","action":"spend_reset","object":"{object}","result":"ok"}}"#
        )
    };
    lines = vec![
        entry(at, "login-1").into(),
        entry(at + 1, &"o".repeat(70_000)).into(),
        vec![0xff, 0xfe],
        entry(at + 2, "login-2").into(),
    ];
    std::fs::write(&audit, lines.join(&b'\n')).unwrap();
    let answer = audit_answer(&r.gw, "");
    let objects: Vec<_> = answer.entries.iter().map(|e| e.object.as_deref()).collect();
    assert_eq!(
        (objects, answer.skipped),
        (vec![Some("login-1"), Some("login-2")], 2)
    );
}

#[test]
fn only_the_gateway_s_own_uid_reads_the_usage_and_only_on_the_unix_socket() {
    let ledger = temp_dir("usage").join("usage.jsonl");
    let extra = format!(
        "[[clients]]\nname = \"client-a\"\nuid = {}\n{}",
        own_uid(),
        usage_table(&ledger, 1 << 20)
    );
    let other = rig_as(4, &key_files(), &extra, own_uid() + 1);
    let (status, e) = rejection(
        &other.gw,
        "GET",
        &format!("{}?from=0", paths::MODEL_USAGE),
        "",
    );
    assert_eq!((status, e.class), (403, ErrorClass::Auth), "{e:?}");

    let (listener, addr, front) = loopback_front("");
    let extra = format!("{}{front}", usage_table(&ledger, 1 << 20));
    let r = rig_on(4, &key_files(), &extra, own_uid(), Some(listener));
    let from = unix_now() - 3600;
    assert_eq!(
        usage_answer(&r.gw, &format!("?from={from}")).rows,
        Vec::new()
    );
    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
    let path = format!("{}?from={from}", paths::MODEL_USAGE);
    let (status, _, body) = finish(tcp_send(addr, "GET", &path, &auth, ""), Vec::new());
    assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
    assert!(!String::from_utf8_lossy(&body).contains("rows"));

    let plain = rig();
    let (status, e) = rejection(&plain.gw, "GET", &path, "");
    assert_eq!((status, e.class), (404, ErrorClass::BadRequest), "{e:?}");
    assert_eq!(
        e.message.as_deref(),
        Some("this gateway keeps no usage ledger: its config has no `[usage]` table")
    );
}

#[test]
fn a_bad_usage_query_or_too_many_rows_is_400_naming_the_cause() {
    let ledger = temp_dir("usage").join("usage.jsonl");
    let r = rig_as(4, &key_files(), &usage_table(&ledger, 1 << 20), own_uid());
    let now = unix_now();
    let mut lines: Vec<String> = (0..160)
        .map(|i| {
            ledger_line(USAGE_FROM, |l| {
                l.tools = (0..64).map(|j| format!("tool-{i}-{j}")).collect();
            })
        })
        .collect();
    lines.push(ledger_line(now - 60, |_| {}));
    std::fs::write(&ledger, format!("{}\n", lines.join("\n"))).unwrap();

    let recent = usage_answer(&r.gw, &format!("?from={}", now - 3600));
    assert_eq!(usage_rows(&recent), [(now - 3600, None, 1)]);
    assert!(
        (now..=unix_now()).contains(&recent.to),
        "`to` defaults to now"
    );
    let window = format!("?from={USAGE_FROM}&to={}", USAGE_FROM + 1);
    let one = usage_answer(&r.gw, &format!("{window}&group_by=route"));
    assert_eq!(usage_rows(&one), [(USAGE_FROM, Some("chat"), 160)]);

    let later = now + 3600;
    for (query, says) in [
        (
            window.clone() + "&group_by=tool",
            "the answer would have more than 10000 rows; ask for a narrower window or a coarser bucket",
        ),
        (String::new(), "`from` is required"),
        ("?to=5".into(), "`from` is required"),
        ("?from=soon".into(), "`from` must be a whole number"),
        ("?from=-1".into(), "`from` must be a whole number"),
        ("?from=1&from=2".into(), "`from` is given twice"),
        ("?from=1&to=x".into(), "`to` must be a whole number"),
        ("?from=10&to=10".into(), "`to` must be after `from`"),
        (
            format!("?from={later}"),
            "`from` must lie before now, the default `to`",
        ),
        (
            "?from=0&to=34560001".into(),
            "`from` and `to` must lie at most 400 days apart",
        ),
        (
            "?from=1&to=2&group_by=user".into(),
            "`group_by` must be one of client, login, model, route, tool",
        ),
        (
            "?from=1&to=2&bucket=week".into(),
            "`bucket` must be one of hour, day, month",
        ),
        (
            "?from=1&to=2&bucket=day&bucket=day".into(),
            "`bucket` is given twice",
        ),
        (
            "?from=1&to=2&since=1".into(),
            "unknown parameter `since`: the query takes `from`, `to`, `group_by` and `bucket`",
        ),
    ] {
        let path = format!("{}{query}", paths::MODEL_USAGE);
        let (status, e) = rejection(&r.gw, "GET", &path, "");
        assert_eq!(
            (status, e.class),
            (400, ErrorClass::BadRequest),
            "{query}: {e:?}"
        );
        assert_eq!(e.message.as_deref(), Some(says), "{query}");
    }
    assert_eq!(
        usage_rows(&usage_answer(&r.gw, "?from=0&to=34560000")),
        Vec::new(),
        "a window of exactly 400 days"
    );
    let (status, _) = call(&r.gw, "POST", paths::MODEL_USAGE, "");
    assert_eq!(status, 405);
}

#[test]
fn a_turn_that_fails_after_content_still_counts_its_cost() {
    let r = spend_rig([100.0, 100.0, 100.0]);
    let unavailable = Some(FailureKind::Unavailable);
    r.fake.script(
        "login-1",
        Script::Costed(
            vec![text("partial"), usage(1_000_000, 0)],
            unavailable,
            None,
        ),
    );
    r.fake.script(
        "login-1",
        Script::Costed(vec![text("partial")], unavailable, Some(0.25)),
    );
    for id in ["turn-1", "turn-2"] {
        let events = turn(&r.gw, &turn_body(id)).2;
        assert_eq!(kinds(&events).last().unwrap(), "error Unavailable");
        assert_eq!(kinds(&events)[0], "route login-1");
    }
    assert_usd(spent(&r.gw, "login-1"), 1.25);
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
fn a_chatgpt_account_id_an_adapter_quotes_is_redacted_like_the_token() {
    const TOKEN: &str = "test-token-3e7a";
    const ACCOUNT: &str = "test-account-8d1f";
    let r = rig_with(4, &[("login-1", chatgpt(TOKEN, ACCOUNT), 0o600)]);
    r.fake.script("login-1", Script::Leak);
    let mut events = Vec::new();
    let logged = stderr_of(|| events = turn(&r.gw, &turn_body("turn-1")).2);
    assert_eq!(kinds(&events), ["error BadRequest"]);
    let message = last_error(&events).message.clone().unwrap();
    assert!(message.contains("of account [redacted]"), "{message}");
    for mark in [TOKEN, ACCOUNT] {
        assert!(!message.contains(mark), "{message}");
        assert!(!logged.contains(mark), "{logged}");
    }
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
    // Either the applied sandbox or its gaps, never silence.
    let sandboxed = logged.iter().any(|l| {
        l.contains("qb gateway: sandbox: non-dumpable; landlock")
            || l.contains("qb gateway: sandbox incomplete: ")
    });
    assert!(sandboxed, "{logged:?}");
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
    recorded_of("qb-anthropic", &format!("answer_{name}.json"), sse)
}

/// [`recorded`] of the OpenAI fixtures.
fn openai_recorded(name: &str, sse: Option<&str>) -> Answer {
    recorded_of("qb-openai", &format!("answer_{name}.json"), sse)
}

/// The recorded answer fixture `file` of `krate`; `sse`, a stream fixture, as the body of a 200.
fn recorded_of(krate: &str, file: &str, sse: Option<&str>) -> Answer {
    let v: Value = serde_json::from_slice(&fixture_of(krate, file)).unwrap();
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
    let gw = serve_gateway(
        &text,
        vec![(Api::Anthropic, Box::new(Anthropic::new()))],
        Box::new(OauthRefresher::new()),
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
    turn_hiding(r, request_id, &TOKENS)
}

/// Runs `turn` with stderr captured; its events, after checking that neither the log nor the
/// client's answer holds one of `secrets`.
fn turn_hiding(r: &Rig, request_id: &str, secrets: &[&str]) -> Vec<StreamEvent> {
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
    for token in secrets {
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

#[test]
fn a_refused_loopback_request_logs_its_reason_method_and_path_but_no_token() {
    let (listener, addr, front) = loopback_front("");
    let _r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let logged = stderr_until("/v1/models", || {
        let s = tcp_send(
            addr,
            "POST",
            paths::MESSAGES,
            "X-Api-Key: qb-wrong-token\r\n",
            "{}",
        );
        assert_eq!(error_type(s).0, 401);
        let auth = format!("Authorization: Bearer {CLIENT_TOKEN}\r\n");
        let s = tcp_send(addr, "GET", "/v1/models", &auth, "");
        assert_eq!(error_type(s).0, 404);
    });
    assert!(
        logged.contains(&format!(
            "gateway: loopback refused POST {}: token",
            paths::MESSAGES
        )),
        "{logged}"
    );
    assert!(
        logged.contains("gateway: loopback refused GET /v1/models: path"),
        "{logged}"
    );
    assert!(!logged.contains("qb-wrong-token"), "{logged}");
    assert!(!logged.contains(CLIENT_TOKEN), "{logged}");
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

#[test]
fn messages_sends_message_start_with_the_input_usage_before_the_vendor_s_content() {
    let (r, vendor) = vendor_rig(&key_files(), two_keys);
    let start = through_first(&vendor_fixture("upstream_text.sse"), "event: message_start");
    vendor.answer(Answer::Hold(start));
    let body = sdk_body("model-2025-01-01", true);
    let mut client = sdk_send(&r.gw, &body, None);
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 1024];
    let event = loop {
        let text = String::from_utf8_lossy(&seen).into_owned();
        if let Some(at) = text.find("event: message_start") {
            if let Some(end) = text[at..].find("\n\n") {
                break text[at..at + end].to_owned();
            }
        }
        let n = client
            .read(&mut chunk)
            .expect("message_start arrives while the vendor still holds its content");
        assert!(n > 0, "stream ended early");
        seen.extend_from_slice(&chunk[..n]);
    };
    let text = String::from_utf8_lossy(&seen);
    assert!(!text.contains("content_block"), "{text}");
    let data = event.split_once("data: ").unwrap().1;
    let start: Value = serde_json::from_str(data.lines().next().unwrap()).unwrap();
    let usage = &start["message"]["usage"];
    assert_eq!(usage["input_tokens"], 25, "{start}");
    assert_eq!(
        usage["output_tokens"], 1,
        "the vendor's start, not a final count: {start}"
    );
    drop(client);
    vendor.closed.recv_timeout(Duration::from_secs(1)).unwrap();
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

/// Named loopback client tokens and their SHA-256, `printf %s <token> | sha256sum`.
const CLIENT_A: (&str, &str) = (
    "qb-client-a-token",
    "5d35a058cf5118a9e66c11dc7b4b1ccb5b1931d453a64ff4e100a619bf2a824f",
);
const CLIENT_B: (&str, &str) = (
    "qb-client-b-token",
    "1d97fabc1bc79ad582c1a433e58d2aef7295984a71aff4f8b119c4d82c34c342",
);
const CLIENT_C: (&str, &str) = (
    "qb-client-c-token",
    "a5a906a0ceafdaa8f69134b59baaf877ff00268c53eb6a6cb405ebe5c8ef8a6c",
);

/// A `[[fronts.clients]]` entry `name` with the token hash `hash`, `rest` added.
fn front_client(name: &str, hash: &str, rest: &str) -> String {
    format!("[[fronts.clients]]\nname = \"{name}\"\ntoken_sha256 = \"{hash}\"\n{rest}")
}

/// Posts `body` to `path` on the loopback listener `addr` with `token` in `x-api-key`: the
/// status and the answer body.
fn loopback_post(addr: SocketAddr, path: &str, token: &str, body: &Value) -> (u16, Vec<u8>) {
    let auth = format!("X-Api-Key: {token}\r\n");
    let (status, _, answer) = finish(
        tcp_send(addr, "POST", path, &auth, &body.to_string()),
        Vec::new(),
    );
    (status, answer)
}

#[test]
fn named_loopback_clients_run_under_their_names_and_within_their_routes() {
    let clients = [
        front_client("client-a", CLIENT_A.1, "routes = [\"chat\"]\n"),
        front_client("client-b", CLIENT_B.1, "routes = [\"spare\"]\n"),
        front_client("client-c", CLIENT_C.1, ""),
    ];
    let (listener, addr, front) = loopback_front(&clients.concat());
    let r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let messages = sdk_body("model-2025-01-01", false);
    for (token, name) in [
        (CLIENT_TOKEN, "client-token"),
        (CLIENT_A.0, "client-a"),
        (CLIENT_C.0, "client-c"),
    ] {
        let mut answer = (0, Vec::new());
        let needle = format!(" of {name}: ");
        let logged = stderr_until(&needle, || {
            answer = loopback_post(addr, paths::MESSAGES, token, &messages);
        });
        assert_eq!(
            answer.0,
            200,
            "{name}: {}",
            String::from_utf8_lossy(&answer.1)
        );
        assert!(logged.contains(&needle), "{name}: {logged}");
    }
    let served = r.fake.calls().len();
    assert_eq!(served, 3);

    for (token, path, body, kind, message) in [
        (
            CLIENT_B.0,
            paths::MESSAGES,
            sdk_body("model-2025-01-01", false),
            "permission_error",
            "client `client-b` may not use route `chat`",
        ),
        (
            CLIENT_A.0,
            paths::CHAT_COMPLETIONS,
            chat_body("spare", false),
            "permission_error",
            "client `client-a` may not use route `spare`",
        ),
        (
            CLIENT_B.0,
            paths::RESPONSES,
            responses_body("model-2025-01-01", false),
            "permission_error",
            "client `client-b` may not use route `chat`",
        ),
    ] {
        let (status, answer) = loopback_post(addr, path, token, &body);
        let text = String::from_utf8_lossy(&answer).into_owned();
        assert_eq!(status, 403, "{path}: {text}");
        assert!(!text.contains(token), "{text}");
        let answer: Value = serde_json::from_slice(&answer).unwrap();
        assert_eq!(answer["error"]["type"], kind, "{text}");
        assert_eq!(answer["error"]["message"], message, "{text}");
        if path != paths::MESSAGES {
            assert_eq!(answer["error"]["code"], "route_not_allowed", "{text}");
        }
    }
    assert_eq!(
        r.fake.calls().len(),
        served,
        "a refused route reaches no vendor"
    );
    assert_eq!(state(&r.qbd).leases, Vec::new());

    let auth = "X-Api-Key: qb-client-d-token\r\n";
    let s = tcp_send(addr, "POST", paths::MESSAGES, auth, &messages.to_string());
    assert_eq!(error_type(s), (401, "authentication_error".into()));
}

#[test]
fn every_pick_names_the_turn_s_caller_on_behalf_of() {
    let client_a = front_client("client-a", CLIENT_A.1, "");
    let (listener, addr, front) = loopback_front(&client_a);
    let r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let messages = sdk_body("model-2025-01-01", false);
    for token in [CLIENT_A.0, CLIENT_TOKEN] {
        let (status, answer) = loopback_post(addr, paths::MESSAGES, token, &messages);
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    }
    turn(&r.gw, &turn_body("turn-1"));
    let own = format!("uid:{}", own_uid());
    assert_eq!(
        leased_on_behalf_of(&r.dir),
        [Some("client-a"), Some("client-token"), Some(own.as_str())].map(|c| c.map(str::to_owned))
    );
}

#[test]
fn a_route_refusal_logs_the_client_and_the_route_but_no_token() {
    let client = front_client("client-refused", CLIENT_C.1, "routes = [\"spare\"]\n");
    let (listener, addr, front) = loopback_front(&client);
    let _r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let messages = sdk_body("model-2025-01-01", false);
    let mut status = 0;
    let logged = stderr_until("client `client-refused`", || {
        status = loopback_post(addr, paths::MESSAGES, CLIENT_C.0, &messages).0;
    });
    assert_eq!(status, 403);
    let refusals: Vec<&str> = logged
        .lines()
        .filter(|l| l.contains("client `client-refused`"))
        .collect();
    let line = "gateway: loopback refused client `client-refused` route `chat`: route";
    assert!(
        refusals.len() == 1 && refusals[0].ends_with(line),
        "{logged}"
    );
    assert!(!logged.contains(CLIENT_C.0), "{logged}");
}

#[test]
fn a_reload_adds_removes_and_changes_named_loopback_clients_for_the_next_connection() {
    let client_a = front_client("client-a", CLIENT_A.1, "");
    let (listener, addr, front) = loopback_front(&client_a);
    let r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let body = sdk_body("model-2025-01-01", false);
    let status = |token: &str| loopback_post(addr, paths::MESSAGES, token, &body).0;
    assert_eq!((status(CLIENT_A.0), status(CLIENT_B.0)), (200, 401));

    let client_b = front_client("client-b", CLIENT_B.1, "");
    let (reloaded, answer) = reload_with(&r.gw, |t| t.replace(&client_a, &client_b));
    assert_eq!(reloaded, 200, "{}", String::from_utf8_lossy(&answer));
    assert_eq!((status(CLIENT_A.0), status(CLIENT_B.0)), (401, 200));

    let limited = front_client("client-b", CLIENT_B.1, "routes = [\"spare\"]\n");
    let (reloaded, answer) = reload_with(&r.gw, |t| t.replace(&client_b, &limited));
    assert_eq!(reloaded, 200, "{}", String::from_utf8_lossy(&answer));
    assert_eq!(status(CLIENT_B.0), 403);
    assert_eq!(status(CLIENT_TOKEN), 200, "the unnamed token keeps serving");
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

/// A ChatGPT credential file without an expiry: the gateway refreshes it only after a 401.
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
fn a_model_configured_without_reasoning_gets_no_reasoning_effort_or_include() {
    let plain = "[[routes]]\nalias = \"plain\"\nrole = \"gateway\"\nvendor = \"vendor-o\"\n\
                 model = \"model-plain\"\neffort = \"low\"\n\n\
                 [openai_models.\"model-plain\"]\nreasoning = false\n\n";
    let (r, vendor) = openai_rig(
        "vendor-o",
        &key_files(),
        |v| [v.login(OPENAI_KEY), v.login(OPENAI_KEY)],
        &format!("{plain}{}", fronts("")),
        None,
    );
    for (n, alias) in ["plain", "chat"].into_iter().enumerate() {
        vendor.answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
        let mut body = turn_body(&format!("turn-{n}"));
        body["route"] = json!(alias);
        body["effort"] = json!("high");
        let (_, _, events) = turn(&r.gw, &body);
        assert_eq!(kinds(&events).last().unwrap(), "stop End", "{alias}");
    }

    let sent = vendor.received();
    let bodies: Vec<&Value> = sent.iter().map(|r| &r.body).collect();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["model"], "model-plain");
    assert_eq!(bodies[0].get("reasoning"), None, "{}", bodies[0]);
    assert_eq!(bodies[0].get("include"), None, "{}", bodies[0]);
    assert_eq!(bodies[1]["model"], "model-o");
    assert_eq!(bodies[1]["reasoning"]["effort"], "high");
    assert_eq!(bodies[1]["include"], json!(["reasoning.encrypted_content"]));
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
    let mut answer = Vec::new();
    let logged = stderr_of(|| {
        let s = send(
            &r.gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body("turn-1").to_string(),
        );
        answer = finish(s, Vec::new()).2;
    });
    let answer = String::from_utf8(answer).unwrap();
    let events = events(answer.as_bytes());

    assert_eq!(kinds(&events)[0], "route login-2");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(text_of(&events), "Hello, w\u{f6}rld!");
    let s = state(&r.qbd);
    let exhausted = s.logins.iter().find(|l| l.login == "login-1").unwrap();
    assert_eq!(exhausted.status, LoginStatus::Exhausted);
    assert_eq!(exhausted.dead_until, Some(1_800_018_000), "until the reset");
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
        assert!(!logged.contains(secret), "{secret} logged: {logged}");
        assert!(!answer.contains(secret), "{secret} sent: {answer}");
    }
}

const ACCOUNT: &str = "test-account-41d7";
/// A JWT whose payload holds [`ACCOUNT`] and an `exp`, as the ChatGPT token endpoint returns.
const ID_TOKEN: &str = "e30.eyJleHAiOjE5MDAwMDAwMDAsImFjY291bnQiOiJ0ZXN0LWFjY291bnQtNDFkNyJ9.c2ln";
const CHATGPT_SECRETS: [&str; 6] = [
    OLD_ACCESS,
    OLD_REFRESH,
    NEW_ACCESS,
    NEW_REFRESH,
    ACCOUNT,
    ID_TOKEN,
];

/// login-1's ChatGPT credential file with the old tokens, expiring at `expires_at`.
fn old_chatgpt(expires_at: u64) -> String {
    format!(
        r#"{{"type":"chatgpt_oauth","access_token":"{OLD_ACCESS}","account_id":"{ACCOUNT}","refresh_token":"{OLD_REFRESH}","expires_at":{expires_at}}}"#
    )
}

/// A ChatGPT token answer that rotates the refresh token and dates the access token by the
/// `id_token`.
fn codex_grant() -> Answer {
    let body = json!({
        "access_token": NEW_ACCESS,
        "refresh_token": NEW_REFRESH,
        "id_token": ID_TOKEN,
    });
    let headers = vec![("content-type".into(), "application/json".into())];
    Answer::Full(200, headers, serde_json::to_vec(&body).unwrap())
}

/// A gateway with the OpenAI adapter and the shipped OAuth refresher: login-1 a ChatGPT login
/// with `login_1` as its file, refreshing at a scripted token endpoint, login-2 an OpenAI key
/// login, both of `vendor-o` on one scripted vendor.
fn chatgpt_rig(login_1: String) -> (Rig, Vendor, Vendor) {
    let vendor = Vendor::start();
    let tokens = Vendor::start();
    let dir = temp_dir("gwc");
    credentials(
        &dir,
        &[
            ("login-1", login_1, 0o600),
            ("login-2", api_key("test-token-2"), 0o600),
        ],
    );
    let qbd = start_qbd(&dir, &openai_qbd("vendor-o"));
    let chatgpt = format!(
        "{}\ntoken_url = \"{}/oauth/token\"",
        vendor.login(CHATGPT),
        tokens.base_url
    );
    let key = vendor.login(OPENAI_KEY);
    let text = gateway_toml(&dir, &qbd, 4, [&chatgpt, &key], "");
    let gw = serve_gateway(
        &text,
        vec![(Api::Openai, Box::new(Openai::new()))],
        Box::new(OauthRefresher::new()),
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

/// The `authorization` header of every request the vendor received.
fn bearers(vendor: &Vendor) -> Vec<Option<String>> {
    let sent = vendor.received();
    sent.iter()
        .map(|s| s.header("authorization").map(str::to_owned))
        .collect()
}

#[test]
fn an_expired_chatgpt_token_is_refreshed_before_the_call_and_written_back() {
    let (r, vendor, tokens) = chatgpt_rig(old_chatgpt(unix_now()));
    tokens.answer(codex_grant());
    vendor.answer(openai_recorded("200_chatgpt", Some("upstream_text.sse")));
    let events = turn_hiding(&r, "turn-1", &CHATGPT_SECRETS);
    assert_eq!(kinds(&events)[0], "route login-1");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");

    let asked = tokens.received();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].path, "/oauth/token");
    assert_eq!(
        asked[0].body.as_str().unwrap(),
        format!(
            "grant_type=refresh_token&refresh_token={OLD_REFRESH}&client_id={}",
            openai_identity::OAUTH_CLIENT_ID
        )
    );
    let sent = vendor.received();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].header("authorization"),
        Some(bearer(NEW_ACCESS).as_str())
    );
    assert_eq!(
        sent[0].header(openai_identity::ACCOUNT_HEADER),
        Some(ACCOUNT)
    );

    let (file, mode) = stored(&r);
    assert_eq!(mode, 0o600);
    assert_eq!(
        file,
        json!({
            "type": "chatgpt_oauth",
            "access_token": NEW_ACCESS,
            "refresh_token": NEW_REFRESH,
            "account_id": ACCOUNT,
            "expires_at": 1_900_000_000,
        })
    );
}

#[test]
fn a_401_on_a_chatgpt_login_refreshes_once_and_the_same_turn_succeeds() {
    let (r, vendor, tokens) = chatgpt_rig(old_chatgpt(unix_now() + 3600));
    tokens.answer(codex_grant());
    vendor.answer(openai_recorded("401", None));
    vendor.answer(openai_recorded("200_chatgpt", Some("upstream_text.sse")));
    let events = turn_hiding(&r, "turn-1", &CHATGPT_SECRETS);
    assert_eq!(kinds(&events)[0], "route login-1");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(tokens.received().len(), 1);
    assert_eq!(
        bearers(&vendor),
        [Some(bearer(OLD_ACCESS)), Some(bearer(NEW_ACCESS))]
    );
    assert_eq!(stored(&r).0["access_token"], NEW_ACCESS);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Ok);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_second_401_on_a_chatgpt_login_moves_the_turn_to_the_next_login() {
    let (r, vendor, tokens) = chatgpt_rig(old_chatgpt(unix_now() + 3600));
    tokens.answer(codex_grant());
    vendor.answer(openai_recorded("401", None));
    vendor.answer(openai_recorded("401", None));
    vendor.answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
    let events = turn_hiding(&r, "turn-1", &CHATGPT_SECRETS);
    assert_eq!(kinds(&events)[0], "route login-2");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(tokens.received().len(), 1, "one refresh per turn");
    assert_eq!(
        bearers(&vendor),
        [
            Some(bearer(OLD_ACCESS)),
            Some(bearer(NEW_ACCESS)),
            Some(bearer("test-token-2"))
        ]
    );
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn the_codex_windows_of_a_chatgpt_answer_reach_qbd_as_sent() {
    let (r, vendor, _tokens) = chatgpt_rig(old_chatgpt(unix_now() + 3600));
    vendor.answer(openai_recorded("200_chatgpt", Some("upstream_text.sse")));
    let before = unix_now();
    let events = turn_hiding(&r, "turn-1", &CHATGPT_SECRETS);
    let after = unix_now();
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    let s = state(&r.qbd);
    let login = s.logins.iter().find(|l| l.login == "login-1").unwrap();
    assert_eq!(login.status, LoginStatus::Ok);
    let window = |name: &str| {
        let w = login.windows.iter().find(|w| w.name == name).unwrap();
        (w.used, w.resets_at.unwrap())
    };
    let (used, resets_at) = window("five_hour");
    assert!((used - 0.425).abs() < 1e-9, "{login:?}");
    assert_eq!(resets_at, 1_800_010_000);
    let (used, resets_at) = window("seven_day");
    assert!((used - 0.07).abs() < 1e-9, "{login:?}");
    assert!(
        (before + 86_400..=after + 86_400).contains(&resets_at),
        "{login:?}"
    );
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

/// The keys of an `api_key` login of the `chat_completions` API family, without `base_url`.
const CHAT_KEY: &str = "kind = \"api_key\"\napi = \"chat_completions\"";

/// The login keys of a `chat_completions` login on `v` below `path`, with OpenRouter's app
/// attribution.
fn chat_login(v: &Vendor, path: &str) -> String {
    format!(
        "{CHAT_KEY}\nbase_url = \"{}{path}\"\nreferer = \"https://app.example.com\"\ntitle = \"qb test\"",
        v.base_url
    )
}

/// A rig whose gateway runs every adapter against one scripted vendor, with qbd of
/// [`openai_qbd`]`("vendor-o")`, login-1 a `chat_completions` login at the vendor's root and
/// login-2 one below `/api/v1`.
fn chat_rig(files: &[(&str, String, u32)]) -> (Rig, Vendor) {
    let upstreams: Upstreams = vec![
        (Api::Anthropic, Box::new(Anthropic::new())),
        (Api::Openai, Box::new(Openai::new())),
        (Api::ChatCompletions, Box::new(ChatCompletions::new())),
    ];
    vendor_rig_with(
        &openai_qbd("vendor-o"),
        upstreams,
        files,
        |v| [chat_login(v, ""), chat_login(v, "/api/v1")],
        &fronts(""),
        None,
    )
}

/// A 200 Chat Completions stream of `text`, its finish reason and a usage chunk.
fn chat_text_answer(text: &str) -> Answer {
    let chunk = |choices: Value, usage: Value| {
        let c = json!({"id": "chatcmpl-test-9", "object": "chat.completion.chunk",
            "created": 1_800_000_000, "model": "model-o", "choices": choices, "usage": usage});
        format!("data: {c}\n\n")
    };
    let sse = [
        chunk(
            json!([{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]),
            Value::Null,
        ),
        chunk(
            json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]),
            Value::Null,
        ),
        chunk(
            json!([]),
            json!({"prompt_tokens": 50, "completion_tokens": 5, "total_tokens": 55}),
        ),
        "data: [DONE]\n\n".to_owned(),
    ]
    .concat();
    chat_stream(sse.into_bytes())
}

/// A 200 answer with the event stream `sse`.
fn chat_stream(sse: Vec<u8>) -> Answer {
    let headers = vec![("content-type".to_owned(), "text/event-stream".to_owned())];
    Answer::Full(200, headers, sse)
}

/// The recorded Chat Completions vendor answer `chat_answer_<name>.json`.
fn chat_recorded(name: &str) -> Answer {
    recorded_of("qb-openai", &format!("chat_answer_{name}.json"), None)
}

/// The `(id, name, input)` of each `tool_call` event.
fn tool_calls(events: &[StreamEvent]) -> Vec<(String, String, Value)> {
    events
        .iter()
        .filter_map(|e| match e {
            StreamEvent::ToolCall { tool_call } => Some((
                tool_call.id.clone(),
                tool_call.name.clone(),
                Value::Object(tool_call.input.clone()),
            )),
            _ => None,
        })
        .collect()
}

/// The second turn of the Chat Completions tool loop as the vendor got it: the assistant's two
/// calls, then one `tool` message per result with the same call id.
fn assert_tool_results_reached_the_chat_vendor(body: &Value) {
    let messages = body["messages"].as_array().unwrap();
    let roles: Vec<&str> = messages
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, ["user", "assistant", "tool", "tool"]);
    let ids: Vec<&Value> = messages[1]["tool_calls"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| &c["id"])
        .collect();
    assert_eq!(ids, [&json!("call_a1"), &json!("call_b2")]);
    assert_eq!(
        (&messages[2]["tool_call_id"], &messages[2]["content"]),
        (&json!("call_a1"), &json!("line one"))
    );
    assert_eq!(
        (&messages[3]["tool_call_id"], &messages[3]["content"]),
        (&json!("call_b2"), &json!("a.txt"))
    );
}

#[test]
fn a_chat_completions_login_runs_a_tool_loop_with_its_attribution_headers() {
    const KEY: &str = "test-key-3e9a";
    let files = [
        ("login-1", api_key(KEY), 0o600),
        ("login-2", api_key("test-key-2"), 0o600),
    ];
    let (r, vendor) = chat_rig(&files);
    vendor.answer(chat_stream(fixture_of(
        "qb-openai",
        "chat_upstream_openai.sse",
    )));
    vendor.answer(chat_text_answer("Both read."));

    let mut first = Vec::new();
    let logged = stderr_of(|| first = turn(&r.gw, &turn_body("turn-1")).2);
    assert_eq!(
        kinds(&first),
        [
            "route login-1",
            "text_delta",
            "text_delta",
            "tool_call",
            "tool_call",
            "usage",
            "stop ToolUse"
        ]
    );
    assert_eq!(text_of(&first), "Reading both.");
    assert_eq!(
        tool_calls(&first),
        [
            (
                "call_a1".to_owned(),
                "read_file".to_owned(),
                json!({"path": "notes.txt"})
            ),
            (
                "call_b2".to_owned(),
                "list_dir".to_owned(),
                json!({"dir": "src"})
            ),
        ]
    );
    assert_eq!(
        first[5],
        StreamEvent::Usage {
            usage: Usage {
                input: 300,
                output: 40,
                cache_read: 2000,
                cache_write: 0
            }
        }
    );

    let mut next = turn_body("turn-2");
    next["messages"] = json!([
        {"role": "user", "content": [{"type": "text", "text": "Hi"}]},
        {"role": "assistant", "content": [
            {"type": "text", "text": "Reading both."},
            {"type": "tool_use", "id": "call_a1", "name": "read_file", "input": {"path": "notes.txt"}},
            {"type": "tool_use", "id": "call_b2", "name": "list_dir", "input": {"dir": "src"}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "id": "call_a1", "content": "line one"},
            {"type": "tool_result", "id": "call_b2", "content": "a.txt"},
        ]},
    ]);
    let (_, _, second) = turn(&r.gw, &next);
    assert_eq!(
        kinds(&second),
        ["route login-1", "text_delta", "usage", "stop End"]
    );
    assert_eq!(text_of(&second), "Both read.");

    let sent = vendor.received();
    assert_eq!(sent.len(), 2);
    for s in sent.iter() {
        assert_eq!(s.path, "/chat/completions");
        let bearer = format!("Bearer {KEY}");
        assert_eq!(s.header("authorization"), Some(bearer.as_str()));
        assert_eq!(s.header("http-referer"), Some("https://app.example.com"));
        assert_eq!(s.header("x-title"), Some("qb test"));
        assert_eq!(
            (&s.body["model"], &s.body["stream"]),
            (&json!("model-o"), &json!(true))
        );
    }
    assert_tool_results_reached_the_chat_vendor(&sent[1].body);
    assert!(!logged.contains(KEY), "{logged}");
}

#[test]
fn a_402_on_a_chat_completions_login_moves_a_chat_client_to_the_next_login() {
    const KEYS: [&str; 2] = ["test-key-6b1d", "test-key-0c4f"];
    let files = [
        ("login-1", api_key(KEYS[0]), 0o600),
        ("login-2", api_key(KEYS[1]), 0o600),
    ];
    let (r, vendor) = chat_rig(&files);
    vendor.answer(chat_recorded("402_credits"));
    vendor.answer(chat_text_answer("From the next login."));

    let mut answer = Vec::new();
    let logged = stderr_of(|| {
        let (status, _, body) = openai_call(
            &r.gw,
            paths::CHAT_COMPLETIONS,
            &chat_body("model-2025-01-01", true),
        );
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        answer = body;
    });
    let chunks = chat_chunks(&answer);
    assert!(
        chunks.iter().all(|c| c.get("error").is_none()),
        "{chunks:?}"
    );
    assert_eq!(chat_text(&chunks), "From the next login.");

    let sent = vendor.received();
    let seen: Vec<(&str, Option<&str>)> = sent
        .iter()
        .map(|s| (s.path.as_str(), s.header("authorization")))
        .collect();
    let bearers = KEYS.map(|k| format!("Bearer {k}"));
    assert_eq!(
        seen,
        [
            ("/chat/completions", Some(bearers[0].as_str())),
            ("/api/v1/chat/completions", Some(bearers[1].as_str())),
        ]
    );
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());
    assert!(logged.contains("login-1: usage_limit"), "{logged}");
    let answer = String::from_utf8(answer).unwrap();
    for key in KEYS {
        assert!(!logged.contains(key), "{key}: {logged}");
        assert!(!answer.contains(key), "{key}: {answer}");
    }
}

#[test]
fn a_429_with_retry_after_on_a_chat_completions_login_is_rate_limited() {
    const KEYS: [&str; 2] = ["test-key-9d2e", "test-key-5a7b"];
    let files = [
        ("login-1", api_key(KEYS[0]), 0o600),
        ("login-2", api_key(KEYS[1]), 0o600),
    ];
    let (r, vendor) = chat_rig(&files);
    vendor.answer(chat_recorded("429_retry"));
    vendor.answer(chat_recorded("429_retry"));

    let mut answer = Vec::new();
    let logged = stderr_of(|| {
        let s = send(
            &r.gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body("turn-1").to_string(),
        );
        answer = finish(s, Vec::new()).2;
    });
    let events = events(&answer);
    let error = last_error(&events);
    assert!(error.retryable, "{error:?}");
    // qbd's own 60 s back-off is the later reset; the vendor's 12 s still reaches the client.
    let now = unix_now();
    assert_eq!(error.class, ErrorClass::QuotaExhausted, "{error:?}");
    assert!(matches!(error.retry_after, Some(11..=12)), "{error:?}");
    assert!(
        error.resets_at.is_some_and(|at| at >= now + 50),
        "{error:?}"
    );
    let tried: Vec<(Option<&str>, ErrorClass)> = error
        .tried
        .iter()
        .map(|a| (a.login_label.as_deref(), a.class))
        .collect();
    assert_eq!(
        tried,
        [
            (Some("login-1"), ErrorClass::Overloaded),
            (Some("login-2"), ErrorClass::Overloaded)
        ]
    );
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::RateLimited);
    assert_eq!(status_of(&s, "login-2"), LoginStatus::RateLimited);
    assert_eq!(s.leases, Vec::new());
    for login in ["login-1", "login-2"] {
        let line = format!("{login}: rate_limited: vendor answered HTTP 429");
        assert!(logged.contains(&line), "{logged}");
    }
    let answer = String::from_utf8(answer).unwrap();
    for key in KEYS {
        assert!(!logged.contains(key), "{key}: {logged}");
        assert!(!answer.contains(key), "{key}: {answer}");
    }
}

/// `answer` with its `retry-after` header set to `seconds`.
fn retry_after(answer: Answer, seconds: &str) -> Answer {
    let Answer::Full(status, mut headers, body) = answer else {
        panic!("a full answer");
    };
    for (name, value) in &mut headers {
        if name.eq_ignore_ascii_case("retry-after") {
            seconds.clone_into(value);
        }
    }
    Answer::Full(status, headers, body)
}

#[test]
fn a_vendor_wait_longer_than_qbd_s_back_off_moves_the_messages_retry_after() {
    let (r, vendor) = chat_rig(&key_files());
    vendor.answer(retry_after(chat_recorded("429_retry"), "200"));
    vendor.answer(retry_after(chat_recorded("429_retry"), "250"));
    let asked = unix_now();
    let (status, head, body) = sdk_call(&r.gw, &sdk_body("model-2025-01-01", false), None);
    assert_eq!(status, 429, "{}", String::from_utf8_lossy(&body));
    let (wait, should_retry) = retry_headers(&head);
    assert!(
        wait.is_some_and(|s| (195..=200).contains(&s)),
        "the soonest vendor wait, not qbd's 60 s: {head}"
    );
    assert_eq!(should_retry, None, "{head}");
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::RateLimited);
    assert_eq!(status_of(&s, "login-2"), LoginStatus::RateLimited);
    assert!(unix_now() - asked < 5);
}

#[test]
fn the_chat_completions_adapter_refuses_a_credential_of_another_kind_without_quoting_it() {
    const TOKEN: &str = "test-access-2f8c";
    let at = Picked {
        vendor: "vendor-o",
        model: "model-o",
        effort: None,
        reasoning: true,
        login: "login-1",
        base_url: Some("http://127.0.0.1:9"),
        referer: None,
        title: None,
    };
    let credential = Credential::OauthAnthropic {
        access_token: Zeroizing::new(TOKEN.into()),
    };
    let req: TurnRequest = serde_json::from_value(turn_body("turn-1")).unwrap();
    let mut sink = |_: StreamEvent| Flow::Continue;
    let failure = ChatCompletions::new()
        .turn(&at, &credential, &req, &mut sink, &CancelToken::new())
        .unwrap_err();
    assert_eq!(failure.kind, FailureKind::Auth);
    assert!(!failure.message.contains(TOKEN), "{}", failure.message);
}

/// qbd of the cross-vendor tests: vendor-a served by the Anthropic adapter, vendor-o by the
/// OpenAI Responses adapter and vendor-r by the Chat Completions adapter, one login each, with
/// `login_a` the login of vendor-a.
fn cross_qbd(login_a: &str) -> String {
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

[[vendors]]
name = "vendor-r"
windows = [{{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }}]

[[logins]]
name = "{login_a}"
vendor = "vendor-a"

[[logins]]
name = "login-2"
vendor = "vendor-o"

[[logins]]
name = "login-3"
vendor = "vendor-r"

[[roles]]
name = "gateway"

[[roles.ladder]]
difficulty = 1
candidates = [{{ vendor = "vendor-a", model = "model-a", tier = 1 }}]

[limits]
rate_per_s = 1000.0
burst = 1000
"#
    )
}

/// A gateway with the real adapters, each login on its own scripted vendor, and the OAuth
/// token endpoint of login-1.
struct Cross {
    rig: Rig,
    anthropic: Vendor,
    openai: Vendor,
    chat: Vendor,
    tokens: Vendor,
}

fn every_adapter() -> Upstreams {
    vec![
        (Api::Anthropic, Box::new(Anthropic::new())),
        (Api::Openai, Box::new(Openai::new())),
        (Api::ChatCompletions, Box::new(ChatCompletions::new())),
    ]
}

/// [`cross_rig_with`] with every adapter, login-1 an Anthropic key login known to qbd.
fn cross_rig() -> Cross {
    cross_rig_with("login-1", false, every_adapter())
}

/// A rig whose route `chat` is the chain vendor-a (Anthropic), vendor-o (OpenAI Responses),
/// vendor-r (Chat Completions) and whose route `solo` pins vendor-a: login-1 an Anthropic login,
/// OAuth when `oauth`, login-2 an OpenAI key login and login-3 a Chat Completions key login.
/// qbd runs [`cross_qbd`]`(login_a)`; the gateway has the adapters `upstreams` and the shipped
/// OAuth refresher.
fn cross_rig_with(login_a: &str, oauth: bool, upstreams: Upstreams) -> Cross {
    let (anthropic, openai, chat, tokens) = (
        Vendor::start(),
        Vendor::start(),
        Vendor::start(),
        Vendor::start(),
    );
    let dir = temp_dir("cross");
    let login_1 = if oauth {
        old_oauth(unix_now() + 3600)
    } else {
        api_key("test-key-a")
    };
    credentials(
        &dir,
        &[
            ("login-1", login_1, 0o600),
            ("login-2", api_key("test-key-o"), 0o600),
            ("login-3", api_key("test-key-r"), 0o600),
        ],
    );
    let qbd = start_qbd(&dir, &cross_qbd(login_a));
    let keys_1 = if oauth {
        format!(
            "{}\ntoken_url = \"{}/v1/oauth/token\"",
            anthropic.login("kind = \"oauth_anthropic\""),
            tokens.base_url
        )
    } else {
        anthropic.login(ANTHROPIC_KEY)
    };
    let text = format!(
        r#"socket = "{dir}/gw.sock"
qbd_socket = "{qbd}"

[[logins]]
name = "login-1"
{keys_1}
credentials = "{dir}/creds/login-1.json"

[[logins]]
name = "login-2"
{keys_2}
credentials = "{dir}/creds/login-2.json"

[[logins]]
name = "login-3"
{keys_3}
credentials = "{dir}/creds/login-3.json"

[[routes]]
alias = "chat"
role = "gateway"
chain = [
  {{ vendor = "vendor-a", model = "model-a" }},
  {{ vendor = "vendor-o", model = "model-o" }},
  {{ vendor = "vendor-r", model = "model-r" }},
]

[[routes]]
alias = "solo"
role = "gateway"
vendor = "vendor-a"
model = "model-a"

{fronts}"#,
        dir = dir.display(),
        qbd = qbd.display(),
        keys_2 = openai.login(OPENAI_KEY),
        keys_3 = chat_login(&chat, ""),
        fronts = fronts(""),
    );
    let gw = serve_gateway(
        &text,
        upstreams,
        Box::new(OauthRefresher::new()),
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
    Cross {
        rig,
        anthropic,
        openai,
        chat,
        tokens,
    }
}

/// An Anthropic stream of signed thinking, then the two tool calls `toolu_test_1` and
/// `toolu_test_2`: the thinking block of `upstream_thinking.sse` spliced before the tool blocks
/// of `upstream_tool_use.sse`.
fn thinking_then_tools() -> Answer {
    let second_block =
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1";
    let thinking = String::from_utf8(vendor_fixture("upstream_thinking.sse")).unwrap();
    let tools = String::from_utf8(vendor_fixture("upstream_tool_use.sse")).unwrap();
    let head = &thinking[..thinking.find(second_block).unwrap()];
    let tail = &tools[tools.find(second_block).unwrap()..];
    let mut answer = recorded("200_allowed", None);
    if let Answer::Full(_, _, body) = &mut answer {
        *body = format!("{head}{tail}").into_bytes();
    }
    answer
}

/// The `route` event's `(vendor, login)`.
fn answered_by(events: &[StreamEvent]) -> (String, String) {
    match events.first() {
        Some(StreamEvent::Route { route }) => (route.vendor.clone(), route.login_label.clone()),
        other => panic!("not a route event: {other:?}"),
    }
}

/// `body` with the assistant message of `events` and a user message of `results`, each
/// `(tool id, output)`, appended to its history.
fn next_turn(
    body: &Value,
    request_id: &str,
    events: &[StreamEvent],
    results: &[(&str, &str)],
) -> Value {
    let mut next = body.clone();
    next["request_id"] = json!(request_id);
    let results: Vec<Block> = results
        .iter()
        .map(|(id, content)| Block::ToolResult {
            id: (*id).to_owned(),
            content: (*content).to_owned(),
            is_error: None,
        })
        .collect();
    let history = next["messages"].as_array_mut().unwrap();
    history.push(json!({"role": "assistant", "content": blocks_of(events)}));
    history.push(json!({"role": "user", "content": results}));
    next
}

/// The thinking payloads of the turns in the cross-vendor loop; none may reach another vendor.
const ANTHROPIC_THINKING: [&str; 2] = ["c2lnbmF0dXJlLXRlc3QtMQ==", "The user wants a greeting."];
const OPENAI_REASONING: [&str; 2] = ["Z0FBQUFBQnN5bnRoZXRpYy1lbmNyeXB0ZWQ=", "Checking the file"];

fn assert_absent(body: &Value, payloads: &[&str]) {
    let text = body.to_string();
    for p in payloads {
        assert!(!text.contains(p), "{p} sent: {text}");
    }
}

/// `(type, call_id)` of each input item of a Responses request body; `call_id` empty when absent.
fn input_items(body: &Value) -> Vec<(&str, &str)> {
    let input = body["input"].as_array().unwrap();
    input
        .iter()
        .map(|i| {
            let id = i["call_id"].as_str().unwrap_or_default();
            (i["type"].as_str().unwrap(), id)
        })
        .collect()
}

/// `(role, tool ids)` of each message of a Chat Completions request body: an assistant
/// message's `tool_calls[].id`, a tool message's `tool_call_id`.
fn chat_tool_ids(body: &Value) -> Vec<(&str, Vec<&str>)> {
    let messages = body["messages"].as_array().unwrap();
    messages
        .iter()
        .map(|m| {
            let ids = match m["role"].as_str().unwrap() {
                "assistant" => m["tool_calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| c["id"].as_str().unwrap())
                    .collect(),
                "tool" => vec![m["tool_call_id"].as_str().unwrap()],
                _ => Vec::new(),
            };
            (m["role"].as_str().unwrap(), ids)
        })
        .collect()
}

#[test]
#[allow(clippy::too_many_lines)] // the three turns of one tool loop read best in order
fn a_tool_loop_falls_from_anthropic_to_openai_to_chat_completions_keeping_its_tool_ids() {
    let c = cross_rig();
    let r = &c.rig;

    c.anthropic.answer(thinking_then_tools());
    let first_body = turn_body("turn-1");
    let (_, _, first) = turn(&r.gw, &first_body);
    assert_eq!(answered_by(&first), ("vendor-a".into(), "login-1".into()));
    assert_eq!(
        kinds(&first),
        [
            "route login-1",
            "usage",
            "thinking",
            "tool_call",
            "tool_call",
            "usage",
            "stop ToolUse"
        ]
    );
    let first_calls: Vec<String> = tool_calls(&first).into_iter().map(|c| c.0).collect();
    assert_eq!(first_calls, ["toolu_test_1", "toolu_test_2"]);

    c.anthropic.answer(recorded("529", None));
    c.openai.answer(openai_recorded(
        "200_api_key",
        Some("upstream_reasoning.sse"),
    ));
    let second_body = next_turn(
        &first_body,
        "turn-2",
        &first,
        &[("toolu_test_1", "line one"), ("toolu_test_2", "notes.txt")],
    );
    let (_, _, second) = turn(&r.gw, &second_body);
    assert_eq!(answered_by(&second), ("vendor-o".into(), "login-2".into()));
    assert_eq!(
        kinds(&second),
        [
            "route login-2",
            "thinking",
            "text_delta",
            "tool_call",
            "usage",
            "stop ToolUse"
        ]
    );
    assert_eq!(
        tool_calls(&second),
        [(
            "call_c3".to_owned(),
            "read_file".to_owned(),
            json!({"path": "a.txt"})
        )]
    );
    {
        let sent = c.openai.received();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            input_items(&sent[0].body),
            [
                ("message", ""),
                ("function_call", "toolu_test_1"),
                ("function_call", "toolu_test_2"),
                ("function_call_output", "toolu_test_1"),
                ("function_call_output", "toolu_test_2"),
            ]
        );
        assert_absent(&sent[0].body, &ANTHROPIC_THINKING);
    }

    c.anthropic.answer(recorded("529", None));
    c.openai
        .answer(openai_recorded("429_insufficient_quota", None));
    c.chat.answer(chat_text_answer("All read."));
    let third_body = next_turn(
        &second_body,
        "turn-3",
        &second,
        &[("call_c3", "a.txt line")],
    );
    let (_, _, third) = turn(&r.gw, &third_body);
    assert_eq!(answered_by(&third), ("vendor-r".into(), "login-3".into()));
    assert_eq!(
        kinds(&third),
        ["route login-3", "text_delta", "usage", "stop End"]
    );
    assert_eq!(text_of(&third), "All read.");

    let chat = c.chat.received();
    assert_eq!(chat.len(), 1);
    assert_eq!(
        chat_tool_ids(&chat[0].body),
        [
            ("user", vec![]),
            ("assistant", vec!["toolu_test_1", "toolu_test_2"]),
            ("tool", vec!["toolu_test_1"]),
            ("tool", vec!["toolu_test_2"]),
            ("assistant", vec!["call_c3"]),
            ("tool", vec!["call_c3"]),
        ]
    );
    assert_absent(&chat[0].body, &ANTHROPIC_THINKING);
    assert_absent(&chat[0].body, &OPENAI_REASONING);

    let anthropic = c.anthropic.received();
    assert_eq!(anthropic.len(), 3, "one call per turn");
    assert_absent(&anthropic[2].body, &OPENAI_REASONING);
    assert!(
        anthropic[2]
            .body
            .to_string()
            .contains(ANTHROPIC_THINKING[0]),
        "its own signed thinking goes back to Anthropic: {}",
        anthropic[2].body
    );
    assert_eq!(c.openai.received().len(), 2);
    let s = state(&r.qbd);
    assert_eq!(status_of(&s, "login-2"), LoginStatus::Exhausted);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_stream_that_breaks_after_content_ends_the_turn_and_the_next_step_is_never_called() {
    let c = cross_rig();
    c.anthropic.answer(recorded("529", None));
    c.openai
        .answer(openai_recorded("200_api_key", Some("upstream_cut.sse")));
    c.chat.answer(chat_text_answer("never"));
    let (_, _, events) = turn(&c.rig.gw, &turn_body("turn-1"));
    assert_eq!(
        kinds(&events),
        ["route login-2", "text_delta", "error Unavailable"]
    );
    assert_eq!(text_of(&events), "Cut here");
    assert_eq!(
        tried(last_error(&events)),
        [
            ("login-1".to_owned(), ErrorClass::Overloaded),
            ("login-2".to_owned(), ErrorClass::Unavailable),
        ]
    );
    assert_eq!(c.chat.received().len(), 0, "no step after content");
    assert_eq!(state(&c.rig.qbd).leases, Vec::new());
}

/// A turn on route `alias`.
fn turn_on(alias: &str, request_id: &str) -> Value {
    let mut body = turn_body(request_id);
    body["route"] = json!(alias);
    body
}

#[test]
fn a_key_login_that_answers_401_is_called_once_in_the_turn() {
    let c = cross_rig();
    for _ in 0..4 {
        c.anthropic.answer(recorded("401", None));
    }
    let (_, _, pinned) = turn(&c.rig.gw, &turn_on("solo", "turn-1"));
    assert_eq!(kinds(&pinned), ["error Auth"]);
    let e = last_error(&pinned);
    assert!(!e.retryable);
    assert_eq!(tried(e), [("login-1".to_owned(), ErrorClass::Auth)]);
    assert_eq!(c.anthropic.received().len(), 1, "one vendor request");
    assert_eq!(
        status_of(&state(&c.rig.qbd), "login-1"),
        LoginStatus::AuthDead
    );

    let c = cross_rig();
    for _ in 0..4 {
        c.anthropic.answer(recorded("401", None));
    }
    c.openai
        .answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
    let (_, _, chained) = turn(&c.rig.gw, &turn_body("turn-1"));
    assert_eq!(answered_by(&chained), ("vendor-o".into(), "login-2".into()));
    assert_eq!(kinds(&chained).last().unwrap(), "stop End");
    assert_eq!(c.anthropic.received().len(), 1, "one vendor request");
    assert_eq!(c.tokens.received().len(), 0, "a key is not refreshed");
    let s = state(&c.rig.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn an_oauth_login_that_answers_401_is_refreshed_and_retried_once_then_left_in_the_turn() {
    let c = cross_rig_with("login-1", true, every_adapter());
    for _ in 0..4 {
        c.anthropic.answer(recorded("401", None));
    }
    c.tokens.answer(grant());
    c.tokens.answer(grant());
    c.openai
        .answer(openai_recorded("200_api_key", Some("upstream_text.sse")));
    let events = turn_without_leaks(&c.rig, "turn-1");
    assert_eq!(answered_by(&events), ("vendor-o".into(), "login-2".into()));
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    let bearers: Vec<Option<String>> = c
        .anthropic
        .received()
        .iter()
        .map(|s| s.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(
        bearers,
        [Some(bearer(OLD_ACCESS)), Some(bearer(NEW_ACCESS))],
        "one call, one refresh, one retry"
    );
    assert_eq!(c.tokens.received().len(), 1);
    let s = state(&c.rig.qbd);
    assert_eq!(status_of(&s, "login-1"), LoginStatus::AuthDead);
    assert_eq!(s.leases, Vec::new());
}

#[test]
fn a_chain_step_whose_login_has_no_credential_entry_or_adapter_moves_to_the_next_step() {
    let c = cross_rig_with(
        "login-0",
        false,
        vec![
            (Api::Anthropic, Box::new(Anthropic::new())),
            (Api::ChatCompletions, Box::new(ChatCompletions::new())),
        ],
    );
    c.chat.answer(chat_text_answer("Third step."));
    let (_, _, events) = turn(&c.rig.gw, &turn_body("turn-1"));
    assert_eq!(answered_by(&events), ("vendor-r".into(), "login-3".into()));
    assert_eq!(text_of(&events), "Third step.");
    assert_eq!(kinds(&events).last().unwrap(), "stop End");
    assert_eq!(c.anthropic.received().len(), 0);
    assert_eq!(c.openai.received().len(), 0);
    assert_eq!(state(&c.rig.qbd).leases, Vec::new());
}

#[test]
fn a_messages_client_sees_its_tool_ids_kept_across_a_fallback_to_openai() {
    let c = cross_rig();
    c.anthropic.answer(recorded("529", None));
    c.openai.answer(openai_recorded(
        "200_api_key",
        Some("upstream_reasoning.sse"),
    ));
    let mut body = sdk_body("model-2025-01-01", true);
    let history = body["messages"].as_array_mut().unwrap();
    history.push(json!({"role": "assistant", "content": [
        {"type": "thinking", "thinking": ANTHROPIC_THINKING[1], "signature": ANTHROPIC_THINKING[0]},
        {"type": "tool_use", "id": "toolu_test_1", "name": "read", "input": {"path": "notes.txt"}},
    ]}));
    history.push(json!({"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_test_1", "content": "line one"},
    ]}));
    let (status, _, sse) = sdk_call(&c.rig.gw, &body, None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&sse));
    let (events, stop) = content_of(&sse);
    assert_eq!(stop, StopReason::ToolUse);
    assert_eq!(
        tool_calls(&events),
        [(
            "call_c3".to_owned(),
            "read_file".to_owned(),
            json!({"path": "a.txt"})
        )]
    );

    let sent = c.openai.received();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        input_items(&sent[0].body),
        [
            ("message", ""),
            ("function_call", "toolu_test_1"),
            ("function_call_output", "toolu_test_1")
        ]
    );
    assert_absent(&sent[0].body, &ANTHROPIC_THINKING);
    assert_eq!(c.anthropic.received().len(), 1);
}

/// The token the rotation tests start `client-f`'s token file with.
const FILE_TOKEN: &str = "qb-client-f-token";

/// A gateway whose loopback listener serves `client-f`, whose token is in a `token_file` of a
/// directory of its own, and `client-a` with `token_sha256`; audit file and usage ledger set.
struct Rotating {
    r: Rig,
    addr: SocketAddr,
    token_file: PathBuf,
    grace_file: PathBuf,
    audit: PathBuf,
    ledger: PathBuf,
}

/// The `[fronts]` keys and clients of [`Rotating`] with `rotate_grace_s = grace_s`.
fn rotating_keys(token_file: &Path, grace_file: &Path, grace_s: u32) -> String {
    format!(
        "rotate_grace_s = {grace_s}\ngrace_file = \"{}\"\n\
         [[fronts.clients]]\nname = \"client-f\"\ntoken_file = \"{}\"\n{}",
        grace_file.display(),
        token_file.display(),
        front_client("client-a", CLIENT_A.1, ""),
    )
}

/// `client-f`'s 0600 token file holding `contents` and a grace file path, each in a directory of
/// its own.
fn token_files(contents: &str) -> (PathBuf, PathBuf) {
    let token_file = temp_dir("tokens").join("client-f.token");
    std::fs::write(&token_file, contents).unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    (token_file, temp_dir("grace").join("grace.json"))
}

/// A [`Rotating`] gateway whose token file holds `contents`.
fn rotating_rig(grace_s: u32, contents: &str) -> Rotating {
    let (token_file, grace_file) = token_files(contents);
    let (audit, ledger) = (audit_path(), temp_dir("ledger").join("usage.jsonl"));
    let (listener, addr, front) = loopback_front(&rotating_keys(&token_file, &grace_file, grace_s));
    let extra = format!(
        "{}{}{front}",
        audit_key(&audit),
        usage_table(&ledger, 1 << 20)
    );
    let r = rig_on(4, &key_files(), &extra, own_uid(), Some(listener));
    Rotating {
        r,
        addr,
        token_file,
        grace_file,
        audit,
        ledger,
    }
}

/// The status of a Messages turn on `addr` with `token`.
fn turn_status(addr: SocketAddr, token: &str) -> u16 {
    loopback_post(
        addr,
        paths::MESSAGES,
        token,
        &sdk_body("model-2025-01-01", false),
    )
    .0
}

/// `POST /v1/model/clients/<name>/rotate` on `gw`: the status and the answer body.
fn rotate(gw: &Path, name: &str) -> (u16, Vec<u8>) {
    call(
        gw,
        "POST",
        &format!("{}/{name}/rotate", paths::MODEL_CLIENTS),
        "",
    )
}

/// [`rotate`] that must answer 200: the answer and the token the file now holds.
fn rotated(gw: &Path, token_file: &Path) -> (ClientRotateAnswer, String) {
    let (status, body) = rotate(gw, "client-f");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let token = std::fs::read_to_string(token_file).unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains(&token),
        "the answer holds no token"
    );
    (serde_json::from_slice(&body).unwrap(), token)
}

#[test]
fn a_rotation_writes_a_fresh_token_and_keeps_the_previous_one_within_the_grace() {
    let f = rotating_rig(3600, &format!("{FILE_TOKEN}\n"));
    assert_eq!(turn_status(f.addr, FILE_TOKEN), 200, "one newline is cut");
    let mut answer = None;
    let logged = stderr_until("rotated the token", || {
        answer = Some(rotated(&f.r.gw, &f.token_file));
    });
    let (answer, first) = answer.unwrap();
    let now = unix_now();
    assert_eq!(answer.client, "client-f");
    assert!(
        (now..=now + 1).contains(&(answer.grace_until - 3600)),
        "{answer:?}"
    );
    assert_eq!(answer.token_sha256_prefix, sha256_hex(&first)[..12]);
    assert_eq!(first.len(), 43, "32 random bytes in base64url");
    assert_ne!(first, FILE_TOKEN);
    assert_eq!(mode_of(&f.token_file), 0o600);
    assert_eq!(mode_of(&f.grace_file), 0o600);
    assert_eq!(
        (turn_status(f.addr, &first), turn_status(f.addr, FILE_TOKEN)),
        (200, 200),
        "the new token, and the old one within the grace"
    );

    let (_, second) = rotated(&f.r.gw, &f.token_file);
    assert_eq!(
        (
            turn_status(f.addr, &second),
            turn_status(f.addr, &first),
            turn_status(f.addr, FILE_TOKEN)
        ),
        (200, 200, 401),
        "a second rotation replaces the previous hash"
    );
    let (reloaded, body) = reload_with(&f.r.gw, |t| format!("{t}# reloaded\n"));
    assert_eq!(reloaded, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        (turn_status(f.addr, &second), turn_status(f.addr, &first)),
        (200, 200),
        "a reload keeps the grace"
    );
    assert_eq!(
        turn_status(f.addr, CLIENT_A.0),
        200,
        "a hash client serves on"
    );

    let entries = audit_answer(&f.r.gw, "").entries;
    let rotations: Vec<_> = entries
        .iter()
        .filter(|e| e.action == AuditAction::ClientRotate)
        .map(|e| (e.object.as_deref(), e.result, e.token_sha256_prefix.clone()))
        .collect();
    assert_eq!(
        rotations,
        [
            (
                Some("client-f"),
                AuditResult::Ok,
                Some(answer.token_sha256_prefix.clone())
            ),
            (
                Some("client-f"),
                AuditResult::Ok,
                Some(sha256_hex(&second)[..12].to_owned())
            ),
        ]
    );
    let grace = std::fs::read_to_string(&f.grace_file).unwrap();
    assert!(grace.contains(&sha256_hex(&first)), "{grace}");
    let ledger = usage_lines(&f.ledger);
    assert!(ledger.iter().any(|l| l.client == "client-f"), "{ledger:?}");
    let ledger = std::fs::read_to_string(&f.ledger).unwrap();
    let audit = std::fs::read_to_string(&f.audit).unwrap();
    for token in [FILE_TOKEN, &first, &second] {
        for (what, text) in [
            ("stderr", &logged),
            ("audit", &audit),
            ("ledger", &ledger),
            ("grace file", &grace),
        ] {
            assert!(!text.contains(token), "{what} holds a token: {text}");
        }
    }
    assert!(
        logged.contains(&format!("sha256 {}", answer.token_sha256_prefix)),
        "{logged}"
    );
}

#[test]
fn without_a_grace_the_previous_token_is_refused_at_once() {
    let f = rotating_rig(0, FILE_TOKEN);
    let (answer, token) = rotated(&f.r.gw, &f.token_file);
    assert!(answer.grace_until <= unix_now(), "{answer:?}");
    assert_eq!(
        (turn_status(f.addr, &token), turn_status(f.addr, FILE_TOKEN)),
        (200, 401)
    );
}

#[test]
fn a_restart_within_the_grace_still_accepts_the_previous_token() {
    let f = rotating_rig(3600, FILE_TOKEN);
    let (_, token) = rotated(&f.r.gw, &f.token_file);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = std::fs::read_to_string(config_file(&f.r.gw))
        .unwrap()
        .replace("gw.sock", "gw2.sock")
        .replace(&f.addr.to_string(), &addr.to_string());
    let fake = Arc::new(Fake::default());
    serve_gateway(
        &config,
        vec![(Api::Anthropic, Box::new(Shared(fake)))],
        Box::new(Counting(Arc::default())),
        own_uid(),
        Some(listener),
    );
    assert_eq!(
        (turn_status(addr, &token), turn_status(addr, FILE_TOKEN)),
        (200, 200)
    );
}

#[test]
fn a_rotation_is_refused_for_other_uids_unknown_and_hash_clients_and_on_loopback() {
    let f = rotating_rig(3600, FILE_TOKEN);
    let refusal = |name: &str| {
        let (status, body) = rotate(&f.r.gw, name);
        let e: GatewayError = serde_json::from_slice(&body).unwrap();
        (status, e.message.unwrap())
    };
    assert_eq!(
        refusal("client-x"),
        (
            404,
            "no `[[fronts.clients]]` entry is named `client-x`".into()
        )
    );
    assert_eq!(
        refusal("client-a"),
        (
            409,
            "client `client-a` has a `token_sha256`, not a `token_file` the gateway can write"
                .into()
        )
    );
    let path = format!("{}/client-f/rotate", paths::MODEL_CLIENTS);
    let (status, _) = call(&f.r.gw, "GET", &path, "");
    assert_eq!(status, 405);
    let auth = format!("X-Api-Key: {FILE_TOKEN}\r\n");
    let (status, _) = error_type(tcp_send(f.addr, "POST", &path, &auth, ""));
    assert_eq!(status, 404, "the loopback listener does not serve it");
    assert_eq!(std::fs::read_to_string(&f.token_file).unwrap(), FILE_TOKEN);
    let rows: Vec<_> = audit_answer(&f.r.gw, "")
        .entries
        .into_iter()
        .map(|e| (e.object, e.result, e.token_sha256_prefix))
        .collect();
    assert_eq!(
        rows,
        [
            (Some("client-x".into()), AuditResult::Refused, None),
            (Some("client-a".into()), AuditResult::Refused, None),
        ]
    );

    let tokens = temp_dir("tokens");
    let token_file = tokens.join("client-f.token");
    std::fs::write(&token_file, FILE_TOKEN).unwrap();
    let (_, _, front) = loopback_front(&rotating_keys(
        &token_file,
        &temp_dir("grace").join("grace.json"),
        60,
    ));
    let audit = audit_path();
    let extra = format!(
        "{}\n[[clients]]\nname = \"client-u\"\nuid = {}\n{front}",
        audit_key(&audit),
        own_uid()
    );
    let r = rig_as(4, &key_files(), &extra, own_uid() + 1);
    let (status, body) = rotate(&r.gw, "client-f");
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (403, ErrorClass::Auth), "{e:?}");
    assert_eq!(std::fs::read_to_string(&token_file).unwrap(), FILE_TOKEN);
    let line: AuditEntry =
        serde_json::from_str(std::fs::read_to_string(&audit).unwrap().trim_end()).unwrap();
    assert_eq!(
        (line.action, line.object.as_deref(), line.result),
        (
            AuditAction::ClientRotate,
            Some("client-f"),
            AuditResult::Refused
        )
    );
}

#[test]
fn a_failed_token_write_keeps_the_file_and_the_accepted_tokens() {
    let f = rotating_rig(3600, FILE_TOKEN);
    let (_, first) = rotated(&f.r.gw, &f.token_file);
    let grace = std::fs::read_to_string(&f.grace_file).unwrap();
    let dir = f.token_file.parent().unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(dir.join("probe"), "").is_ok() {
        // Running as root: directory modes do not bind, nothing to check.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let (status, body) = rotate(&f.r.gw, "client-f");
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (500, ErrorClass::Unavailable), "{e:?}");
    assert!(e.message.unwrap().contains("cannot write the token file"));
    assert_eq!(std::fs::read_to_string(&f.token_file).unwrap(), first);
    assert_eq!(std::fs::read_to_string(&f.grace_file).unwrap(), grace);
    assert_eq!(
        (turn_status(f.addr, &first), turn_status(f.addr, FILE_TOKEN)),
        (200, 200)
    );
    let last = audit_answer(&f.r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (last.action, last.result, last.token_sha256_prefix),
        (AuditAction::ClientRotate, AuditResult::Refused, None)
    );
}

#[test]
fn an_empty_or_unreadable_token_file_fails_start_and_is_refused_on_reload() {
    let f = rotating_rig(3600, FILE_TOKEN);
    std::fs::write(&f.token_file, "\n").unwrap();
    let (status, body) = call(&f.r.gw, "POST", paths::MODEL_RELOAD, "");
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    let message = e.message.unwrap();
    assert_eq!(status, 400, "{message}");
    let field = format!(
        "fronts.clients[0].token_file: {}: is empty",
        f.token_file.display()
    );
    assert!(message.contains(&field), "{message}");
    assert_eq!(
        turn_status(f.addr, FILE_TOKEN),
        200,
        "the running hash stays"
    );
    let last = audit_answer(&f.r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (last.action, last.result),
        (AuditAction::Reload, AuditResult::Refused)
    );

    let text = std::fs::read_to_string(config_file(&f.r.gw)).unwrap();
    let config = qb::gateway::config::parse(&config_file(&f.r.gw), &text).unwrap();
    let start = |config| {
        let upstreams: Upstreams = Vec::new();
        Gateway::new(config, upstreams, Box::new(Counting(Arc::default())), None)
            .err()
            .unwrap()
    };
    assert!(start(config.clone()).contains(&field), "empty");
    std::fs::write(&f.token_file, "x".repeat(4097)).unwrap();
    let refused = start(config.clone());
    assert!(refused.contains("is larger than 4096 bytes"), "{refused}");
    std::fs::remove_file(&f.token_file).unwrap();
    let refused = start(config);
    let missing = format!("fronts.clients[0].token_file: {}: ", f.token_file.display());
    assert!(refused.contains(&missing), "{refused}");
}

/// `GET /v1/model/config/routes` on `gw` that must answer 200: the answer and its `ETag`.
fn config_routes(gw: &Path) -> (ConfigRoutes, String) {
    let (status, head, body) = finish(send(gw, "GET", paths::MODEL_CONFIG_ROUTES, ""), Vec::new());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let etag = etag(&head).unwrap().to_owned();
    (serde_json::from_slice(&body).unwrap(), etag)
}

/// The body of a `PUT` of `routes`.
fn routes_body(routes: &[ConfigRoute]) -> String {
    serde_json::to_string(&ConfigRoutesPut {
        routes: Some(routes.to_vec()),
        spend_caps: None,
    })
    .unwrap()
}

/// A route of `alias` on ladder step 1 of the role `gateway`.
fn ladder_route(alias: &str) -> ConfigRoute {
    ConfigRoute {
        alias: alias.into(),
        role: "gateway".into(),
        difficulty: Some(1),
        vendor: None,
        model: None,
        effort: None,
        chain: None,
        expected_minutes: None,
    }
}

fn step(vendor: &str, model: &str, effort: Option<&str>) -> ConfigStep {
    ConfigStep {
        vendor: vendor.into(),
        model: model.into(),
        effort: effort.map(str::to_owned),
    }
}

/// The backups `<config>.bak-*` beside the config file of `gw`.
fn backups(gw: &Path) -> Vec<PathBuf> {
    backups_of(&config_file(gw))
}

/// The backups `<file>.bak-*` beside `file`, sorted.
fn backups_of(file: &Path) -> Vec<PathBuf> {
    let prefix = format!("{}.bak-", file.file_name().unwrap().to_str().unwrap());
    let mut found: Vec<PathBuf> = std::fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(&prefix)
        })
        .collect();
    found.sort();
    found
}

#[test]
fn config_routes_answer_the_file_s_routes_and_hash_and_a_put_of_them_round_trips() {
    let r = chain_rig();
    let file = config_file(&r.gw);
    let text = std::fs::read_to_string(&file).unwrap();
    let (got, etag) = config_routes(&r.gw);
    assert_eq!(got.sha256, sha256_hex(&text));
    assert_eq!(etag, format!("\"{}\"", got.sha256));
    let chat = ConfigRoute {
        difficulty: None,
        chain: Some(vec![
            step("vendor-a", "model-a", None),
            step("vendor-b", "model-b", Some("high")),
            step("vendor-c", "model-c", None),
        ]),
        ..ladder_route("chat")
    };
    assert_eq!(got.routes, [chat]);

    let (status, body) = put(
        &r.gw,
        paths::MODEL_CONFIG_ROUTES,
        Some(&etag),
        &routes_body(&got.routes),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (again, _) = config_routes(&r.gw);
    assert_eq!(again.routes, got.routes);

    let r = rig();
    let (got, _) = config_routes(&r.gw);
    let spare = ConfigRoute {
        difficulty: None,
        vendor: Some("vendor-b".into()),
        model: Some("model-b".into()),
        ..ladder_route("spare")
    };
    assert_eq!(got.routes, [ladder_route("chat"), spare]);
}

#[test]
fn a_put_of_a_changed_chain_and_a_new_route_serves_the_next_turn_and_keeps_other_bytes() {
    let audit = audit_path();
    let extra = format!(
        "# top comment\n{}[openai_models.\"model-z\"]\nreasoning = false # kept\n# tail comment\n",
        audit_key(&audit)
    );
    let r = chain_rig_with(QBD_THREE_VENDORS, None, &extra);
    let file = config_file(&r.gw);
    let before = std::fs::read_to_string(&file).unwrap();
    let old = qb::gateway::config::load(&file).unwrap();
    let (got, etag) = config_routes(&r.gw);
    let chat = ConfigRoute {
        difficulty: None,
        chain: Some(vec![
            step("vendor-c", "model-c", None),
            step("vendor-a", "model-a", Some("low")),
        ]),
        ..ladder_route("chat")
    };
    let added = ConfigRoute {
        expected_minutes: Some(7),
        ..ladder_route("added")
    };
    let started = unix_now();
    let (status, body) = put(
        &r.gw,
        paths::MODEL_CONFIG_ROUTES,
        Some(&etag),
        &routes_body(&[chat, added]),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let written: ConfigRoutesWritten = serde_json::from_slice(&body).unwrap();

    let after = std::fs::read_to_string(&file).unwrap();
    assert_eq!(written.sha256, sha256_hex(&after));
    let routes_at = before.find("[[routes]]").unwrap();
    let tail_at = before.find("[openai_models").unwrap();
    assert!(after.starts_with(&before[..routes_at]), "{after}");
    assert!(after.ends_with(&before[tail_at..]), "{after}");
    assert!(before[..routes_at].contains("# top comment\n"), "{before}");
    assert!(before[tail_at..].contains("# tail comment\n"), "{before}");
    assert_eq!(aliases(&r.gw), ["added", "chat"]);

    let (_, _, events) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(kinds(&events), ["route login-3", "text_delta", "stop End"]);
    assert_eq!(route_of(&events), ("vendor-c".into(), "model-c".into()));
    let mut body = turn_body("turn-2");
    body["route"] = json!("added");
    let (_, _, events) = turn(&r.gw, &body);
    assert_eq!(kinds(&events), ["route login-1", "text_delta", "stop End"]);

    let written_backup = written.backup.clone().unwrap();
    let backup = PathBuf::from(&written_backup);
    assert_eq!(backups(&r.gw), std::slice::from_ref(&backup));
    let stamp: u64 = written_backup
        .strip_prefix(&format!("{}.bak-", file.display()))
        .unwrap()
        .parse()
        .unwrap();
    assert!((started..=unix_now()).contains(&stamp), "{stamp}");
    assert_eq!(mode_of(&backup), 0o600);
    let kept = qb::gateway::config::load(&backup).unwrap();
    assert_eq!((kept.sha256, kept.routes), (old.sha256, old.routes));

    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    let file_name = file.display().to_string();
    assert_eq!(
        audit_rows(std::slice::from_ref(&last)),
        [(
            format!("uid:{}", own_uid()).as_str(),
            AuditAction::ConfigRoutes,
            Some(file_name.as_str()),
            AuditResult::Ok,
            None
        )]
    );
    assert_eq!(
        (
            last.config_sha256_before,
            last.config_sha256_after,
            last.backup
        ),
        (Some(got.sha256), Some(written.sha256), written.backup)
    );
}

#[test]
fn a_put_without_or_with_a_stale_if_match_or_an_invalid_candidate_leaves_everything_alone() {
    let audit = audit_path();
    let r = rig_as(4, &key_files(), &audit_key(&audit), own_uid());
    let file = config_file(&r.gw);
    let (got, etag) = config_routes(&r.gw);
    let valid = routes_body(&[ladder_route("other")]);

    let (status, e) = put_error(&r.gw, None, &valid);
    assert_eq!((status, e.class), (428, ErrorClass::BadRequest), "{e:?}");
    let stale = "0".repeat(64);
    let (status, e) = put_error(&r.gw, Some(&stale), &valid);
    assert_eq!((status, e.class), (412, ErrorClass::BadRequest), "{e:?}");
    let message = e.message.unwrap();
    assert!(message.contains(&got.sha256), "{message}");

    let mut bad = ladder_route("Bad\"Alias");
    bad.role = "gateway".into();
    let invalid = routes_body(&[ladder_route("chat"), bad]);
    let (status, e) = put_error(&r.gw, Some(&got.sha256), &invalid);
    assert_eq!((status, e.class), (400, ErrorClass::BadRequest), "{e:?}");
    let refusal = e.message.unwrap();
    let field = format!(
        "routes refused: {}: routes[1].alias: must match ^[a-z][a-z0-9_-]{{0,63}}$ (line ",
        file.display()
    );
    assert!(refusal.starts_with(&field), "{refusal}");
    let mut pinned_and_laddered = ladder_route("chat");
    pinned_and_laddered.vendor = Some("vendor-a".into());
    let (status, e) = put_error(&r.gw, Some(&etag), &routes_body(&[pinned_and_laddered]));
    assert_eq!(status, 400, "{e:?}");
    let message = e.message.unwrap();
    assert!(
        message.contains(": routes[0]: needs `difficulty`"),
        "{message}"
    );
    let unknown = r#"{"routes": [], "spend_cap": 1}"#;
    let (status, e) = put_error(&r.gw, Some(&etag), unknown);
    assert_eq!(status, 400, "{e:?}");
    assert!(e.message.unwrap().contains("unknown field `spend_cap`"));

    let text = std::fs::read_to_string(&file).unwrap();
    assert_eq!(sha256_hex(&text), got.sha256, "the file is untouched");
    assert_eq!(backups(&r.gw), Vec::<PathBuf>::new());
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);

    std::fs::write(&file, format!("{text}# edited by hand\n")).unwrap();
    let (status, e) = put_error(&r.gw, Some(&etag), &valid);
    assert_eq!(status, 412, "an edit by hand changes the hash: {e:?}");
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);

    let entries = audit_answer(&r.gw, "").entries;
    let reasons: Vec<_> = entries
        .iter()
        .map(|e| (e.action, e.result, e.backup.is_some()))
        .collect();
    let refused = (AuditAction::ConfigRoutes, AuditResult::Refused, false);
    assert_eq!(reasons, [refused; 6]);
    let edited = sha256_hex(&format!("{text}# edited by hand\n"));
    let hashes: Vec<_> = entries
        .iter()
        .map(|e| {
            (
                e.config_sha256_before.clone(),
                e.config_sha256_after.clone(),
            )
        })
        .collect();
    let unchanged = (Some(got.sha256.clone()), Some(got.sha256.clone()));
    assert_eq!(hashes[..5], vec![unchanged; 5]);
    assert_eq!(hashes[5], (Some(edited.clone()), Some(edited)));
    assert_eq!(entries[2].reason.as_deref(), Some(refusal.as_str()));
}

/// [`put_routes`] that must be refused: the status and the error.
fn put_error(gw: &Path, if_match: Option<&str>, body: &str) -> (u16, GatewayError) {
    let (status, body) = put(gw, paths::MODEL_CONFIG_ROUTES, if_match, body);
    let e = serde_json::from_slice(&body)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&body)));
    (status, e)
}

#[test]
fn string_values_needing_toml_escapes_round_trip() {
    let r = rig();
    let (_, etag) = config_routes(&r.gw);
    let odd = ConfigRoute {
        role: "role \"q\" \\ back\nslash\t\u{1}é".into(),
        difficulty: None,
        chain: Some(vec![
            step("vendor-a", "model \\\"a\"", Some("high # not a comment")),
            step("vendor-'b'", "model-b", None),
        ]),
        ..ladder_route("odd")
    };
    let routes = [ladder_route("chat"), odd];
    let (status, body) = put(
        &r.gw,
        paths::MODEL_CONFIG_ROUTES,
        Some(&etag),
        &routes_body(&routes),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (got, _) = config_routes(&r.gw);
    assert_eq!(got.routes, routes);
    assert_eq!(aliases(&r.gw), ["chat", "odd"]);
}

#[test]
fn only_the_gateway_s_own_uid_reads_or_replaces_the_routes_and_only_on_the_unix_socket() {
    let audit = audit_path();
    let extra = format!(
        "{}[[clients]]\nname = \"client-a\"\nuid = {}\n",
        audit_key(&audit),
        own_uid()
    );
    let r = rig_as(4, &key_files(), &extra, own_uid() + 1);
    let file = config_file(&r.gw);
    let text = std::fs::read_to_string(&file).unwrap();
    let (status, e) = rejection(&r.gw, "GET", paths::MODEL_CONFIG_ROUTES, "");
    assert_eq!((status, e.class), (403, ErrorClass::Auth), "{e:?}");
    let body = routes_body(&[ladder_route("other")]);
    let (status, e) = put_error(&r.gw, Some(&sha256_hex(&text)), &body);
    assert_eq!((status, e.class), (403, ErrorClass::Auth), "{e:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    let entries: Vec<AuditEntry> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let actor = format!("uid:{}", own_uid());
    let config = file.display().to_string();
    assert_eq!(
        audit_rows(&entries),
        [(
            actor.as_str(),
            AuditAction::ConfigRoutes,
            Some(config.as_str()),
            AuditResult::Refused,
            Some("only the gateway's own uid may read or edit the config's routes and spend caps"),
        )]
    );
    let (status, _) = call(&r.gw, "POST", paths::MODEL_CONFIG_ROUTES, "");
    assert_eq!(status, 405);

    let (listener, addr, front) = loopback_front("");
    let r = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let (_, etag) = config_routes(&r.gw);
    let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\nIf-Match: {etag}\r\n");
    for method in ["GET", "PUT"] {
        let (status, _, answer) = finish(
            tcp_send(addr, method, paths::MODEL_CONFIG_ROUTES, &auth, &body),
            Vec::new(),
        );
        assert_eq!(
            status,
            404,
            "{method}: {}",
            String::from_utf8_lossy(&answer)
        );
    }
    assert_eq!(aliases(&r.gw), ["chat", "spare"]);
}

/// The body of a `PUT` of `spend_caps` only.
fn caps_body(caps: &[(&str, Option<f64>)]) -> String {
    serde_json::to_string(&ConfigRoutesPut {
        routes: None,
        spend_caps: Some(caps.iter().map(|(l, c)| ((*l).to_owned(), *c)).collect()),
    })
    .unwrap()
}

/// `(login, cap_usd)` of each login in the spend view of `gw`.
fn caps_in_spend(gw: &Path) -> Vec<(String, f64)> {
    let answer = spend_of(gw);
    answer
        .logins
        .into_iter()
        .map(|l| (l.login, l.cap_usd))
        .collect()
}

/// The `[[logins]]` table of `login` as [`chain_rig_with`] writes it, `cap` its `spend_cap`
/// line.
fn chain_login(r: &Rig, login: &str, cap: &str) -> String {
    format!(
        "[[logins]]\nname = \"{login}\"\n{ANTHROPIC_KEY}\n{cap}credentials = \"{}/creds/{login}.json\"\n",
        r.dir.display()
    )
}

#[test]
fn spend_caps_are_set_changed_and_removed_in_place_and_the_spend_view_follows() {
    let audit = audit_path();
    let extra = format!("{}{PRICES}", audit_key(&audit));
    let r = chain_rig_with(&qbd_with_spend(), Some([1.0, 100.0, 100.0]), &extra);
    let file = config_file(&r.gw);
    let before = std::fs::read_to_string(&file).unwrap();
    let (got, etag) = config_routes(&r.gw);
    let caps = |c: [Option<f64>; 3]| {
        let names = ["login-1", "login-2", "login-3"].map(str::to_owned);
        names
            .into_iter()
            .zip(c)
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(got.spend_caps, caps([Some(1.0), Some(100.0), Some(100.0)]));

    let body = caps_body(&[("login-1", Some(2.5)), ("login-2", None)]);
    let (status, answer) = put(&r.gw, paths::MODEL_CONFIG_ROUTES, Some(&etag), &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let written: ConfigRoutesWritten = serde_json::from_slice(&answer).unwrap();
    let after = std::fs::read_to_string(&file).unwrap();
    let want = before
        .replace(
            &chain_login(&r, "login-1", "spend_cap = 1.0\n"),
            &chain_login(&r, "login-1", "spend_cap = 2.5\n"),
        )
        .replace(
            &chain_login(&r, "login-2", "spend_cap = 100.0\n"),
            &chain_login(&r, "login-2", ""),
        );
    assert_eq!(after, want);
    assert_eq!(written.sha256, sha256_hex(&after));
    assert_eq!(
        caps_in_spend(&r.gw),
        [("login-1".into(), 2.5), ("login-3".into(), 100.0)]
    );
    let (got, etag) = config_routes(&r.gw);
    assert_eq!(got.spend_caps, caps([Some(2.5), None, Some(100.0)]));

    let (status, answer) = put(
        &r.gw,
        paths::MODEL_CONFIG_ROUTES,
        Some(&etag),
        &caps_body(&[("login-2", Some(0.1))]),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let added = std::fs::read_to_string(&file).unwrap();
    let with_cap = format!("{}spend_cap = 0.1\n", chain_login(&r, "login-2", ""));
    assert_eq!(
        added,
        after.replace(&chain_login(&r, "login-2", ""), &with_cap)
    );
    assert_eq!(
        caps_in_spend(&r.gw),
        [
            ("login-1".into(), 2.5),
            ("login-2".into(), 0.1),
            ("login-3".into(), 100.0)
        ]
    );
    let (got, _) = config_routes(&r.gw);
    assert_eq!(got.spend_caps, caps([Some(2.5), Some(0.1), Some(100.0)]));

    let entries = audit_answer(&r.gw, "").entries;
    let rows: Vec<_> = entries
        .iter()
        .map(|e| (e.action, e.result, e.backup.is_some()))
        .collect();
    let edited = (AuditAction::ConfigSpendCaps, AuditResult::Ok, true);
    assert_eq!(rows, [edited; 2]);
    assert_eq!(backups(&r.gw).len(), 2);
    assert_eq!(std::fs::read_to_string(&backups(&r.gw)[0]).unwrap(), before);
}

#[test]
fn a_put_that_changes_no_byte_answers_the_file_s_hash_and_neither_writes_nor_reloads() {
    let audit = audit_path();
    let extra = format!("{}{PRICES}", audit_key(&audit));
    let r = chain_rig_with(&qbd_with_spend(), Some([1.0, 100.0, 100.0]), &extra);
    let file = config_file(&r.gw);
    let before = std::fs::read_to_string(&file).unwrap();
    let by_hand = before.replace(
        &chain_login(&r, "login-1", "spend_cap = 1.0\n"),
        &chain_login(&r, "login-1", "spend_cap = 3.0\n"),
    );
    assert_ne!(by_hand, before);
    std::fs::write(&file, &by_hand).unwrap();
    let inode = std::fs::metadata(&file).unwrap().ino();
    let (got, etag) = config_routes(&r.gw);

    let (status, answer) = put(
        &r.gw,
        paths::MODEL_CONFIG_ROUTES,
        Some(&etag),
        &caps_body(&[("login-1", Some(3.0))]),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let written: ConfigRoutesWritten = serde_json::from_slice(&answer).unwrap();
    let unchanged = ConfigRoutesWritten {
        sha256: got.sha256.clone(),
        backup: None,
    };
    assert_eq!(written, unchanged);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), by_hand);
    assert_eq!(
        std::fs::metadata(&file).unwrap().ino(),
        inode,
        "not rewritten"
    );
    assert_eq!(backups(&r.gw), Vec::<PathBuf>::new());
    assert_eq!(
        caps_in_spend(&r.gw)[0],
        ("login-1".into(), 1.0),
        "the running config is not reloaded"
    );

    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (last.action, last.result, last.reason, last.backup),
        (AuditAction::ConfigSpendCaps, AuditResult::Ok, None, None)
    );
    assert_eq!(
        (last.config_sha256_before, last.config_sha256_after),
        (Some(got.sha256.clone()), Some(got.sha256))
    );
}

#[test]
fn a_put_of_routes_and_caps_is_one_edit_audited_as_config_routes() {
    let audit = audit_path();
    let extra = format!("{}{PRICES}", audit_key(&audit));
    let r = chain_rig_with(&qbd_with_spend(), Some([1.0, 100.0, 100.0]), &extra);
    let (_, etag) = config_routes(&r.gw);
    let body = json!({
        "routes": [ladder_route("chat"), ladder_route("added")],
        "spend_caps": {"login-3": 50, "login-1": null},
    })
    .to_string();
    let (status, answer) = put(&r.gw, paths::MODEL_CONFIG_ROUTES, Some(&etag), &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let written: ConfigRoutesWritten = serde_json::from_slice(&answer).unwrap();
    assert_eq!(aliases(&r.gw), ["added", "chat"]);
    assert_eq!(
        caps_in_spend(&r.gw),
        [("login-2".into(), 100.0), ("login-3".into(), 50.0)]
    );
    let text = std::fs::read_to_string(config_file(&r.gw)).unwrap();
    assert!(
        text.contains(&chain_login(&r, "login-3", "spend_cap = 50.0\n")),
        "{text}"
    );
    assert_eq!(
        backups(&r.gw),
        [PathBuf::from(written.backup.clone().unwrap())]
    );
    let entries = audit_answer(&r.gw, "").entries;
    let rows: Vec<_> = entries
        .iter()
        .map(|e| (e.action, e.result, e.backup.clone()))
        .collect();
    assert_eq!(
        rows,
        [(AuditAction::ConfigRoutes, AuditResult::Ok, written.backup)]
    );
}

#[test]
fn caps_of_unknown_or_other_kind_logins_or_without_a_spend_file_are_refused_by_name() {
    let audit = audit_path();
    let files = [
        ("login-1", api_key("test-token-1"), 0o600),
        ("login-2", chatgpt("access-0", "account-0"), 0o600),
    ];
    let r = rig_as(4, &files, &audit_key(&audit), own_uid());
    let file = config_file(&r.gw);
    let text = std::fs::read_to_string(&file).unwrap();
    let (got, etag) = config_routes(&r.gw);
    assert_eq!(
        got.spend_caps.into_iter().collect::<Vec<_>>(),
        [("login-1".to_owned(), None)]
    );

    let cases = [
        (caps_body(&[("login-9", Some(1.0))]), "no login `login-9`"),
        (
            caps_body(&[("login-2", Some(1.0))]),
            "login `login-2` is not an `api_key` login",
        ),
        (
            caps_body(&[("login-1", Some(5.0))]),
            "logins[0].spend_cap: needs a top-level `spend_file` to count in",
        ),
        ("{}".to_owned(), "give `routes`, `spend_caps` or both"),
        (
            r#"{"spend_caps": {"login-1": "5"}}"#.to_owned(),
            "invalid type: string \"5\"",
        ),
    ];
    for (body, says) in &cases {
        let (status, e) = put_error(&r.gw, Some(&etag), body);
        let message = e.message.unwrap();
        assert_eq!(
            (status, e.class),
            (400, ErrorClass::BadRequest),
            "{message}"
        );
        assert!(message.contains(says), "{body}: {message}");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    assert_eq!(backups(&r.gw), Vec::<PathBuf>::new());
    let actions: Vec<_> = audit_answer(&r.gw, "")
        .entries
        .iter()
        .map(|e| (e.action, e.result))
        .collect();
    let caps = (AuditAction::ConfigSpendCaps, AuditResult::Refused);
    let routes = (AuditAction::ConfigRoutes, AuditResult::Refused);
    assert_eq!(actions, [caps, caps, caps, routes, routes]);
}

#[test]
fn a_routes_item_split_by_an_unrelated_table_is_refused_and_nothing_changes() {
    let r = rig();
    let file = config_file(&r.gw);
    let split = "[[routes]]\nalias = \"split\"\nrole = \"gateway\"\n\
                 [openai_models.\"model-z\"]\nreasoning = false\n\
                 [[routes.chain]]\nvendor = \"vendor-a\"\nmodel = \"model-a\"\n";
    let text = format!("{}{split}", std::fs::read_to_string(&file).unwrap());
    std::fs::write(&file, &text).unwrap();
    let (got, etag) = config_routes(&r.gw);
    assert_eq!(got.routes.last().unwrap().alias, "split");
    let (status, e) = put_error(&r.gw, Some(&etag), &routes_body(&[ladder_route("chat")]));
    let message = e.message.unwrap();
    assert_eq!(status, 400, "{message}");
    assert!(
        message.contains("routes: a table outside `routes` lies between a `[[routes]]` item"),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    assert_eq!(backups(&r.gw), Vec::<PathBuf>::new());
}

#[test]
fn a_write_that_replaced_the_file_and_then_failed_keeps_the_backup_and_installs_nothing() {
    let audit = audit_path();
    let r = rig_as(4, &key_files(), &audit_key(&audit), own_uid());
    let file = config_file(&r.gw);
    let before = std::fs::read_to_string(&file).unwrap();
    let (_, etag) = config_routes(&r.gw);
    let dir = file.parent().unwrap();
    // Without read permission the rename into the directory works, its sync after it does not.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    if std::fs::read_dir(dir).is_ok() {
        // Running as root: directory modes do not bind, nothing to check.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let (status, e) = put_error(&r.gw, Some(&etag), &routes_body(&[ladder_route("other")]));
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!((status, e.class), (500, ErrorClass::Unavailable), "{e:?}");
    let message = e.message.unwrap();
    let replaced = format!("{} was replaced but not installed: ", file.display());
    assert!(message.starts_with(&replaced), "{message}");
    let kept = backups(&r.gw);
    assert_eq!(kept.len(), 1);
    assert!(
        message.ends_with(&format!("the old file is kept as {}", kept[0].display())),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), before);
    let (on_disk, _) = config_routes(&r.gw);
    assert_eq!(on_disk.routes, [ladder_route("other")]);
    assert_eq!(
        aliases(&r.gw),
        ["chat", "spare"],
        "the running config stays"
    );
    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (last.action, last.result, last.backup),
        (
            AuditAction::ConfigRoutes,
            AuditResult::Refused,
            Some(kept[0].display().to_string())
        )
    );
    let after = std::fs::read_to_string(&file).unwrap();
    assert_eq!(
        (last.config_sha256_before, last.config_sha256_after),
        (Some(sha256_hex(&before)), Some(sha256_hex(&after)))
    );
}

/// The key login-1's credential file starts with in the key replacement tests.
const OLD_KEY: &str = "test-key-old-4e1a";

/// The key the key replacement tests write.
const NEW_KEY: &str = "test-key-new-9b07";

/// A gateway whose login-1 holds [`OLD_KEY`] and login-2 `login_2`, with an audit file and a
/// usage ledger, served as `gateway_uid` with `extra` appended: the rig, the audit file and the
/// ledger.
fn key_rig(login_2: String, extra: &str, gateway_uid: u32) -> (Rig, PathBuf, PathBuf) {
    let (audit, ledger) = (audit_path(), temp_dir("ledger").join("usage.jsonl"));
    let extra = format!(
        "{}{extra}{}",
        audit_key(&audit),
        usage_table(&ledger, 1 << 20)
    );
    let files = [
        ("login-1", api_key(OLD_KEY), 0o600),
        ("login-2", login_2, 0o600),
    ];
    (rig_as(4, &files, &extra, gateway_uid), audit, ledger)
}

/// `POST /v1/model/logins/<login>/key` on `gw` with `body`: the status and the answer body.
fn put_key(gw: &Path, login: &str, body: &str) -> (u16, Vec<u8>) {
    let path = format!("{}/{login}/key", paths::MODEL_LOGINS);
    call(gw, "POST", &path, body)
}

/// The secret every adapter call of login-1 sent, in order.
fn login_1_secrets(r: &Rig) -> Vec<String> {
    r.fake
        .calls()
        .into_iter()
        .filter(|(login, _, _)| login == "login-1")
        .map(|(_, secret, _)| secret)
        .collect()
}

#[test]
fn a_new_key_is_written_beside_a_backup_and_the_next_attempt_sends_it() {
    let (r, audit, ledger) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    let (status, _, _) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(status, 200);
    let mut answers = Vec::new();
    let logged = stderr_until("replaced the key of login `login-1`", || {
        answers.push(put_key(
            &r.gw,
            "login-1",
            &json!({"key": NEW_KEY}).to_string(),
        ));
    });
    let (status, body) = answers[0].clone();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: LoginKeyAnswer = serde_json::from_slice(&body).unwrap();
    let prefix = sha256_hex(NEW_KEY)[..12].to_owned();
    assert_eq!(
        (answer.login.as_str(), answer.key_sha256_prefix.as_str()),
        ("login-1", prefix.as_str())
    );
    let backup = PathBuf::from(answer.backup.clone().unwrap());
    assert_eq!(backups_of(&file), std::slice::from_ref(&backup));
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), api_key(OLD_KEY));
    assert_eq!(mode_of(&backup), 0o600);
    let written: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(written, json!({"type": "api_key", "key": NEW_KEY}));
    assert_eq!(mode_of(&file), 0o600);
    let (status, _, _) = turn(&r.gw, &turn_body("turn-2"));
    assert_eq!(status, 200);
    assert_eq!(
        login_1_secrets(&r),
        [OLD_KEY, NEW_KEY],
        "the attempt after the replacement sends the new key, without a restart"
    );

    let (status, body) = put_key(&r.gw, "login-1", &json!({"key": OLD_KEY}).to_string());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let again: LoginKeyAnswer = serde_json::from_slice(&body).unwrap();
    let second = PathBuf::from(again.backup.clone().unwrap());
    assert_eq!(backups_of(&file).len(), 2, "a backup never replaces one");
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), api_key(OLD_KEY));
    let kept: Value = serde_json::from_slice(&std::fs::read(&second).unwrap()).unwrap();
    assert_eq!(kept["key"], NEW_KEY);
    answers.push((status, body));

    let rows: Vec<_> = audit_answer(&r.gw, "")
        .entries
        .into_iter()
        .map(|e| (e.action, e.object, e.result, e.key_sha256_prefix, e.backup))
        .collect();
    assert_eq!(
        rows,
        [
            (
                AuditAction::LoginKey,
                Some("login-1".into()),
                AuditResult::Ok,
                Some(prefix.clone()),
                answer.backup.clone()
            ),
            (
                AuditAction::LoginKey,
                Some("login-1".into()),
                AuditResult::Ok,
                Some(sha256_hex(OLD_KEY)[..12].to_owned()),
                again.backup.clone()
            ),
        ]
    );
    assert!(logged.contains(&format!("sha256 {prefix}")), "{logged}");
    assert_eq!(
        usage_lines(&ledger).len(),
        2,
        "both turns are in the ledger"
    );
    let texts = [
        ("stderr", logged),
        ("audit", std::fs::read_to_string(&audit).unwrap()),
        ("ledger", std::fs::read_to_string(&ledger).unwrap()),
        (
            "answer",
            String::from_utf8_lossy(&answers[0].1).into_owned(),
        ),
        (
            "answer",
            String::from_utf8_lossy(&answers[1].1).into_owned(),
        ),
    ];
    for key in [OLD_KEY, NEW_KEY] {
        for (what, text) in &texts {
            assert!(!text.contains(key), "{what} holds a key: {text}");
        }
    }
}

#[test]
fn a_login_without_a_credential_file_gets_one_and_no_backup() {
    let (r, _, _) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    std::fs::remove_file(&file).unwrap();
    let (status, body) = put_key(&r.gw, "login-1", &json!({"key": NEW_KEY}).to_string());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let answer: LoginKeyAnswer = serde_json::from_slice(&body).unwrap();
    assert_eq!(answer.backup, None);
    assert_eq!(backups_of(&file), Vec::<PathBuf>::new());
    assert_eq!(mode_of(&file), 0o600);
    let (status, _, _) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(status, 200);
    assert_eq!(login_1_secrets(&r), [NEW_KEY]);
}

/// Bad key requests: the login, the body, the status and the message of the answer.
fn bad_key_requests() -> Vec<(&'static str, String, u16, &'static str)> {
    let key = |key: &str| json!({ "key": key }).to_string();
    let long = format!("{NEW_KEY}{}", "x".repeat(4097 - NEW_KEY.len()));
    let over = format!(r#"{{"key": "{NEW_KEY}", "pad": "{}"}}"#, "x".repeat(8192));
    vec![
        ("login-9", key(NEW_KEY), 404, "no login `login-9`"),
        (
            "login-2",
            key(NEW_KEY),
            409,
            "login `login-2` is `oauth_anthropic`, not `api_key`",
        ),
        (
            "login-1",
            format!(r#"{{"key": "{NEW_KEY}", "{NEW_KEY}": 1}}"#),
            400,
            "the body must be one object with the string `key` only",
        ),
        (
            "login-1",
            format!(r#"{{"{NEW_KEY}": 1}}"#),
            400,
            "the body must be one object with the string `key` only",
        ),
        (
            "login-1",
            format!(r#"{{"key": "{NEW_KEY}""#),
            400,
            "the body is not valid JSON (line 1, column 27)",
        ),
        ("login-1", key(""), 400, "`key` is empty"),
        (
            "login-1",
            key(&long),
            400,
            "`key` is longer than 4096 bytes",
        ),
        (
            "login-1",
            key(&format!("{NEW_KEY} x")),
            400,
            "`key` holds whitespace, a control character or non-ASCII",
        ),
        (
            "login-1",
            key(&format!("{NEW_KEY}\u{1}")),
            400,
            "`key` holds whitespace, a control character or non-ASCII",
        ),
        ("login-1", over, 413, "request body over 8192 bytes"),
    ]
}

#[test]
fn a_bad_key_request_is_refused_and_audited_without_echoing_the_key_or_the_body() {
    let (r, audit, _) = key_rig(expiring_oauth("refresh-0"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    let key = |key: &str| json!({ "key": key }).to_string();
    let cases = bad_key_requests();
    let mut bodies = Vec::new();
    let logged = stderr_of(|| {
        for (login, body, status, message) in &cases {
            let (got, answer) = put_key(&r.gw, login, body);
            let e: GatewayError = serde_json::from_slice(&answer).unwrap();
            assert_eq!(
                (got, e.message.as_deref()),
                (*status, Some(*message)),
                "{body}"
            );
            bodies.push(String::from_utf8(answer).unwrap());
        }
        let path = format!("{}/login-1/key", paths::MODEL_LOGINS);
        let (status, answer) = call(&r.gw, "PUT", &path, &key(NEW_KEY));
        assert_eq!(status, 405);
        bodies.push(String::from_utf8(answer).unwrap());
    });
    assert_eq!(std::fs::read_to_string(&file).unwrap(), api_key(OLD_KEY));
    assert_eq!(backups_of(&file), Vec::<PathBuf>::new());

    let entries = audit_answer(&r.gw, "").entries;
    let rows: Vec<_> = entries
        .iter()
        .map(|e| (e.action, e.object.as_deref(), e.result, e.reason.as_deref()))
        .collect();
    let mut want: Vec<_> = cases
        .iter()
        .map(|(login, _, _, message)| {
            (
                AuditAction::LoginKey,
                Some(*login),
                AuditResult::Refused,
                Some(*message),
            )
        })
        .collect();
    want.push((
        AuditAction::LoginKey,
        Some("login-1"),
        AuditResult::Refused,
        Some("method not allowed"),
    ));
    assert_eq!(rows, want);
    assert!(entries.iter().all(|e| e.key_sha256_prefix.is_none()));
    let audit = std::fs::read_to_string(&audit).unwrap();
    for (what, text) in [("stderr", &logged), ("audit", &audit)]
        .into_iter()
        .chain(bodies.iter().map(|b| ("answer", b)))
    {
        for key in [OLD_KEY, NEW_KEY] {
            assert!(!text.contains(key), "{what} holds a key: {text}");
        }
    }
}

#[test]
fn a_key_of_4096_bytes_is_taken() {
    let (r, _, _) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let longest = "k".repeat(4096);
    let body = json!({ "key": longest }).to_string();
    let (status, answer) = put_key(&r.gw, "login-1", &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let (status, _, _) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(status, 200);
    assert_eq!(login_1_secrets(&r), [longest]);
}

#[test]
fn a_key_replacement_is_refused_for_other_uids_and_on_loopback() {
    let others = format!("\n[[clients]]\nname = \"client-u\"\nuid = {}\n", own_uid());
    let (r, audit, _) = key_rig(api_key("test-key-two-5c3d"), &others, own_uid() + 1);
    let file = r.dir.join("creds/login-1.json");
    let (listener, addr, front) = loopback_front("");
    let served = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    let body = json!({"key": NEW_KEY}).to_string();
    let mut answers = Vec::new();
    let logged = stderr_of(|| {
        answers.push(put_key(&r.gw, "login-1", &body));
        let path = format!("{}/login-1/key", paths::MODEL_LOGINS);
        let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
        let (status, _, answer) = finish(tcp_send(addr, "POST", &path, &auth, &body), Vec::new());
        answers.push((status, answer));
    });
    let e: GatewayError = serde_json::from_slice(&answers[0].1).unwrap();
    assert_eq!((answers[0].0, e.class), (403, ErrorClass::Auth), "{e:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), api_key(OLD_KEY));
    let audited = std::fs::read_to_string(&audit).unwrap();
    let line: AuditEntry = serde_json::from_str(audited.trim_end()).unwrap();
    assert_eq!(
        (line.action, line.object.as_deref(), line.result),
        (AuditAction::LoginKey, Some("login-1"), AuditResult::Refused)
    );
    assert_eq!(answers[1].0, 404, "the loopback listener does not serve it");
    assert_eq!(
        std::fs::read_to_string(served.dir.join("creds/login-1.json")).unwrap(),
        api_key("test-token-1")
    );
    let texts = [
        ("stderr", logged),
        ("audit", audited),
        (
            "403 answer",
            String::from_utf8_lossy(&answers[0].1).into_owned(),
        ),
        (
            "loopback answer",
            String::from_utf8_lossy(&answers[1].1).into_owned(),
        ),
    ];
    for key in [OLD_KEY, NEW_KEY] {
        for (what, text) in &texts {
            assert!(!text.contains(key), "{what} holds a key: {text}");
        }
    }
}

#[test]
fn a_write_that_replaced_the_credential_file_and_then_failed_keeps_the_backup() {
    let (r, audit, _) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    let dir = file.parent().unwrap();
    // Without read permission the rename into the directory works, its sync after it does not.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    if std::fs::read_dir(dir).is_ok() {
        // Running as root: directory modes do not bind, nothing to check.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let mut answer = (0, Vec::new());
    let logged = stderr_until("key replacement of login `login-1` refused", || {
        answer = put_key(&r.gw, "login-1", &json!({"key": NEW_KEY}).to_string());
    });
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let e: GatewayError = serde_json::from_slice(&answer.1).unwrap();
    assert_eq!((answer.0, e.class), (500, ErrorClass::Unavailable), "{e:?}");
    let message = e.message.unwrap();
    let replaced = format!("{} was replaced but the write failed: ", file.display());
    assert!(message.starts_with(&replaced), "{message}");
    let kept = backups_of(&file);
    assert_eq!(kept.len(), 1);
    assert!(
        message.ends_with(&format!("the old file is kept as {}", kept[0].display())),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&kept[0]).unwrap(), api_key(OLD_KEY));
    assert_eq!(mode_of(&kept[0]), 0o600);
    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (
            last.action,
            last.object.as_deref(),
            last.result,
            last.backup
        ),
        (
            AuditAction::LoginKey,
            Some("login-1"),
            AuditResult::Refused,
            Some(kept[0].display().to_string())
        )
    );
    let texts = [
        ("stderr", logged),
        ("audit", std::fs::read_to_string(&audit).unwrap()),
        ("answer", String::from_utf8_lossy(&answer.1).into_owned()),
    ];
    for key in [OLD_KEY, NEW_KEY] {
        for (what, text) in &texts {
            assert!(!text.contains(key), "{what} holds a key: {text}");
        }
    }
}

#[test]
fn a_write_that_created_the_credential_file_and_then_failed_says_there_was_no_old_file() {
    let (r, audit, _) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    std::fs::remove_file(&file).unwrap();
    let dir = file.parent().unwrap();
    // Without read permission the rename into the directory works, its sync after it does not.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o300)).unwrap();
    if std::fs::read_dir(dir).is_ok() {
        // Running as root: directory modes do not bind, nothing to check.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let mut answer = (0, Vec::new());
    stderr_until("key replacement of login `login-1` refused", || {
        answer = put_key(&r.gw, "login-1", &json!({"key": NEW_KEY}).to_string());
    });
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let e: GatewayError = serde_json::from_slice(&answer.1).unwrap();
    assert_eq!((answer.0, e.class), (500, ErrorClass::Unavailable), "{e:?}");
    let message = e.message.unwrap();
    let replaced = format!("{} was replaced but the write failed: ", file.display());
    assert!(message.starts_with(&replaced), "{message}");
    assert!(message.ends_with("; there was no old file"), "{message}");
    assert!(!message.contains(NEW_KEY), "{message}");
    assert_eq!(backups_of(&file), Vec::<PathBuf>::new());
    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (
            last.action,
            last.object.as_deref(),
            last.result,
            last.backup
        ),
        (
            AuditAction::LoginKey,
            Some("login-1"),
            AuditResult::Refused,
            None
        )
    );
    let audited = std::fs::read_to_string(&audit).unwrap();
    assert!(!audited.contains(NEW_KEY), "{audited}");
}

#[test]
fn a_backup_that_cannot_be_written_keeps_the_old_key_in_force() {
    let (r, _, _) = key_rig(api_key("test-key-two-5c3d"), "", own_uid());
    let file = r.dir.join("creds/login-1.json");
    let dir = file.parent().unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::write(dir.join("probe"), "").is_ok() {
        // Running as root: directory modes do not bind, nothing to check.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let (status, body) = put_key(&r.gw, "login-1", &json!({"key": NEW_KEY}).to_string());
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (500, ErrorClass::Unavailable), "{e:?}");
    let message = e.message.unwrap();
    assert!(message.contains("cannot write a backup of"), "{message}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), api_key(OLD_KEY));
    assert_eq!(backups_of(&file), Vec::<PathBuf>::new());
    let (status, _, _) = turn(&r.gw, &turn_body("turn-1"));
    assert_eq!(status, 200);
    assert_eq!(login_1_secrets(&r), [OLD_KEY]);
    let last = audit_answer(&r.gw, "").entries.pop().unwrap();
    assert_eq!(
        (
            last.action,
            last.result,
            last.key_sha256_prefix,
            last.backup
        ),
        (AuditAction::LoginKey, AuditResult::Refused, None, None)
    );
}

/// Part of every synthetic secret of the sign-in tests: codes, tokens and account ids. No
/// answer, log line, audit line or usage line may hold it.
const SIGN_MARK: &str = "mk-5e2c";

/// A gateway whose login-1 is an OAuth login of `kind` that exchanges codes at its own scripted
/// token endpoint and holds an old credential, and whose login-2 is an `api_key` login; with an
/// audit file and a usage ledger, sign-ins expiring after `expiry` s, served as `gateway_uid`.
struct SignRig {
    r: Rig,
    tokens: Vendor,
    audit: PathBuf,
    ledger: PathBuf,
    file: PathBuf,
    /// login-1's credential file as the rig wrote it.
    old: String,
    kind: &'static str,
}

/// The action, object, result, reason and backup of an audit line.
type SignAudit = (
    AuditAction,
    Option<String>,
    AuditResult,
    Option<String>,
    Option<String>,
);

const SIGN_KINDS: [&str; 2] = ["oauth_anthropic", "chatgpt_oauth"];

fn old_credential(kind: &str) -> String {
    let account = if kind == "chatgpt_oauth" {
        format!(r#""account_id":"acct-old-{SIGN_MARK}","#)
    } else {
        String::new()
    };
    format!(
        r#"{{"type":"{kind}","access_token":"access-old-{SIGN_MARK}",{account}"refresh_token":"refresh-old-{SIGN_MARK}","expires_at":{}}}"#,
        unix_now() + 86_400
    )
}

fn sign_rig(kind: &'static str, expiry: u64, extra: &str, gateway_uid: u32) -> SignRig {
    sign_rig_on(kind, expiry, extra, gateway_uid, None)
}

/// [`sign_rig`] with the HTTP fronts also on `loopback`.
fn sign_rig_on(
    kind: &'static str,
    expiry: u64,
    extra: &str,
    gateway_uid: u32,
    loopback: Option<TcpListener>,
) -> SignRig {
    let tokens = Vendor::start();
    let dir = temp_dir("gw");
    let (audit, ledger) = (audit_path(), temp_dir("ledger").join("usage.jsonl"));
    let old = old_credential(kind);
    credentials(
        &dir,
        &[
            ("login-1", old.clone(), 0o600),
            ("login-2", api_key("test-key-two-5c3d"), 0o600),
        ],
    );
    let qbd = start_qbd(&dir, QBD);
    let login_1 = format!(
        "kind = \"{kind}\"\ntoken_url = \"{}/oauth/token\"",
        tokens.base_url
    );
    let extra = format!(
        "{}{extra}{}",
        audit_key(&audit),
        usage_table(&ledger, 1 << 20)
    );
    let (top, tables) = split_top(&extra);
    let toml = gateway_toml(&dir, &qbd, 4, [&login_1, ANTHROPIC_KEY], tables);
    let text = format!("{top}\n{toml}");
    let fake = Arc::new(Fake::default());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let gw = serve_gateway_with(
        &text,
        vec![
            (Api::Anthropic, Box::new(Shared(Arc::clone(&fake)))),
            (Api::Openai, Box::new(Shared(Arc::clone(&fake)))),
        ],
        Box::new(Counting(Arc::clone(&refreshes))),
        gateway_uid,
        loopback,
        |g| g.sign_in_expiry(expiry),
    );
    let file = dir.join("creds/login-1.json");
    let r = Rig {
        dir,
        qbd,
        gw,
        fake,
        refreshes,
    };
    SignRig {
        r,
        tokens,
        audit,
        ledger,
        file,
        old,
        kind,
    }
}

impl SignRig {
    /// `POST /v1/model/logins/<login>/oauth/<step>` with `body`: the status and the answer body.
    fn post(&self, login: &str, step: &str, body: &str) -> (u16, Vec<u8>) {
        let path = format!("{}/{login}/oauth/{step}", paths::MODEL_LOGINS);
        call(&self.r.gw, "POST", &path, body)
    }

    /// Starts a sign-in of login-1: the answer.
    fn start(&self) -> LoginOauthStarted {
        let (status, body) = self.post("login-1", "start", "");
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    /// Sends `pasted` as the code of login-1's sign-in.
    fn code(&self, pasted: &str) -> (u16, Vec<u8>) {
        self.post("login-1", "code", &json!({ "pasted": pasted }).to_string())
    }

    /// What the operator pastes back for `code` and `state`, as the login's kind asks.
    fn paste(&self, code: &str, state: &str) -> String {
        if self.kind == "chatgpt_oauth" {
            format!(
                "http://localhost:1455/auth/callback?code={code}&scope=openid+offline_access&state={state}"
            )
        } else {
            format!("{code}#{state}")
        }
    }

    /// Scripts the token endpoint's 200 answer with fresh tokens for the login's kind.
    fn grant(&self) {
        let mut body = json!({
            "access_token": format!("access-new-{SIGN_MARK}"),
            "refresh_token": format!("refresh-new-{SIGN_MARK}"),
            "expires_in": 3600,
        });
        if self.kind == "chatgpt_oauth" {
            let claims = json!({
                "https://api.openai.com/auth": {"chatgpt_account_id": format!("acct-new-{SIGN_MARK}")}
            });
            body["id_token"] = Value::String(common::credentials::jwt(&claims, SIGN_MARK));
        }
        self.tokens.answer(token_answer(200, &body));
    }

    /// The secrets login-1's adapter calls sent, in order.
    fn sent(&self) -> Vec<String> {
        login_1_secrets(&self.r)
    }

    /// Asserts that the sign-in `signed` kept login-1's old file as its backup and wrote the
    /// tokens of [`Self::grant`].
    fn assert_signed_in(&self, signed: &LoginOauthSigned) {
        assert_eq!(signed.login, "login-1");
        let backup = PathBuf::from(signed.backup.clone().unwrap());
        assert_eq!(backups_of(&self.file), std::slice::from_ref(&backup));
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), self.old);
        assert_eq!(mode_of(&backup), 0o600);
        let written = common::credentials::written(&self.file);
        assert_eq!(written["type"], self.kind);
        assert_eq!(written["access_token"], format!("access-new-{SIGN_MARK}"));
        assert_eq!(written["refresh_token"], format!("refresh-new-{SIGN_MARK}"));
        if self.kind == "chatgpt_oauth" {
            assert_eq!(written["account_id"], format!("acct-new-{SIGN_MARK}"));
        }
    }

    /// The verifier of the one code grant the token endpoint received, after checking that its
    /// S256 challenge is the one of the URL of `started` and its code the marked one.
    fn exchanged(&self, started: &LoginOauthStarted) -> String {
        let received = self.tokens.received();
        assert_eq!(received.len(), 1, "{}: one exchange", self.kind);
        assert_eq!(received[0].path, "/oauth/token");
        let (verifier, code) = granted_code(&received[0]);
        assert_eq!(code, format!("code-{SIGN_MARK}"));
        assert_eq!(param(&started.url, "code_challenge_method"), "S256");
        assert_eq!(
            s256(&verifier),
            param(&started.url, "code_challenge"),
            "{}: the challenge is the verifier's",
            self.kind
        );
        assert!(
            !started.url.contains(&verifier),
            "the URL carries only the challenge"
        );
        verifier
    }

    /// The `(action, object, result, reason, backup)` of every audit line.
    fn audited(&self) -> Vec<SignAudit> {
        audit_answer(&self.r.gw, "")
            .entries
            .into_iter()
            .map(|e| (e.action, e.object, e.result, e.reason, e.backup))
            .collect()
    }

    /// Asserts that none of `answers`, `logged`, the audit file and the files of the ledger's
    /// directory holds a marked value or one of `hidden`.
    fn assert_hidden(&self, answers: &[(u16, Vec<u8>)], logged: &str, hidden: &[&str]) {
        let read = |f: &Path| {
            std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{}: {e}", f.display()))
        };
        let mut texts = vec![("stderr", logged.to_owned()), ("audit", read(&self.audit))];
        let ledger_dir = std::fs::read_dir(self.ledger.parent().unwrap()).unwrap();
        texts.extend(ledger_dir.map(|f| ("ledger", read(&f.unwrap().path()))));
        texts.extend(
            answers
                .iter()
                .map(|(_, a)| ("answer", String::from_utf8_lossy(a).into_owned())),
        );
        for (what, text) in &texts {
            for value in hidden.iter().copied().chain([SIGN_MARK]) {
                assert!(!text.contains(value), "{what} holds `{value}`: {text}");
            }
        }
    }
}

fn token_answer(status: u16, body: &Value) -> Answer {
    Answer::Full(
        status,
        vec![("content-type".into(), "application/json".into())],
        body.to_string().into_bytes(),
    )
}

/// The PKCE verifier and the code of the code grant the token endpoint received.
fn granted_code(req: &Received) -> (String, String) {
    match &req.body {
        Value::String(form) => {
            let fields = params(&format!("?{form}"));
            let field = |k: &str| fields.iter().find(|(n, _)| n == k).unwrap().1.clone();
            (field("code_verifier"), field("code"))
        }
        body => (
            body["code_verifier"].as_str().unwrap().to_owned(),
            body["code"].as_str().unwrap().to_owned(),
        ),
    }
}

#[test]
fn a_sign_in_through_the_socket_writes_the_new_tokens_and_the_next_attempt_sends_them() {
    for kind in SIGN_KINDS {
        let s = sign_rig(kind, 600, "", own_uid());
        let (status, _, _) = turn(&s.r.gw, &turn_body("turn-1"));
        assert_eq!(status, 200);
        let mut answers = Vec::new();
        let mut started = None;
        let before = unix_now();
        let logged = stderr_until("signed in login `login-1`", || {
            let (status, body) = s.post("login-1", "start", "");
            assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
            started = Some(serde_json::from_slice::<LoginOauthStarted>(&body).unwrap());
            let state = param(&started.as_ref().unwrap().url, "state");
            s.grant();
            answers.push(s.code(&format!(
                "  {}\n",
                s.paste(&format!("code-{SIGN_MARK}"), &state)
            )));
        });
        let after = unix_now();
        let started = started.unwrap();
        let paste = if kind == "chatgpt_oauth" {
            OauthPaste::RedirectUrl
        } else {
            OauthPaste::CodeState
        };
        assert_eq!((started.login.as_str(), started.paste), ("login-1", paste));
        assert!((before + 600..=after + 600).contains(&started.expires_at));
        let state = param(&started.url, "state");

        let (status, body) = answers[0].clone();
        assert_eq!(status, 200, "{kind}: {}", String::from_utf8_lossy(&body));
        let signed: LoginOauthSigned = serde_json::from_slice(&body).unwrap();
        s.assert_signed_in(&signed);
        let verifier = s.exchanged(&started);

        let (status, _, _) = turn(&s.r.gw, &turn_body("turn-2"));
        assert_eq!(status, 200);
        assert_eq!(
            s.sent(),
            [
                format!("access-old-{SIGN_MARK}"),
                format!("access-new-{SIGN_MARK}")
            ],
            "{kind}: the attempt after the sign-in sends the new token, without a restart"
        );
        assert_eq!(s.r.refreshes.load(Ordering::SeqCst), 0);

        let (status, again) = s.code(&s.paste(&format!("code-{SIGN_MARK}"), &state));
        let e: GatewayError = serde_json::from_slice(&again).unwrap();
        assert_eq!(
            (status, e.class),
            (409, ErrorClass::BadRequest),
            "the sign-in is used up"
        );
        answers.push((status, again));
        assert_eq!(s.tokens.received().len(), 1);

        let login = Some("login-1".to_owned());
        let audited = s.audited();
        assert_eq!(
            audited[..2],
            [
                (
                    AuditAction::LoginOauthStart,
                    login.clone(),
                    AuditResult::Ok,
                    None,
                    None
                ),
                (
                    AuditAction::LoginOauthCode,
                    login,
                    AuditResult::Ok,
                    None,
                    signed.backup.clone()
                ),
            ]
        );
        assert_eq!(
            usage_lines(&s.ledger).len(),
            2,
            "both turns are in the ledger"
        );
        assert!(
            logged.contains("sign-in of login `login-1` started"),
            "{logged}"
        );
        s.assert_hidden(&answers, &logged, &[&state, &verifier]);
    }
}

#[test]
fn a_wrong_state_or_a_paste_without_a_code_is_400_and_the_sign_in_stays_pending() {
    for kind in SIGN_KINDS {
        let s = sign_rig(kind, 600, "", own_uid());
        let started = s.start();
        let state = param(&started.url, "state");
        let code = format!("code-{SIGN_MARK}");
        let mut cases = vec![
            (
                s.paste(&code, &format!("not-{state}")),
                "the pasted state is not the one this sign-in sent",
            ),
            (
                s.paste(&code, ""),
                "the pasted state is not the one this sign-in sent",
            ),
        ];
        if kind == "chatgpt_oauth" {
            cases.push((
                format!("http://localhost:1455/auth/callback?scope=openid&state={state}"),
                "the pasted URL has no `code`",
            ));
            cases.push((code.clone(), "the pasted line is not a URL with a query"));
        } else {
            cases.push((
                format!("#{state}"),
                "the pasted code is not a non-empty visible ASCII string",
            ));
            cases.push((code.clone(), "the pasted line is not `code#state`"));
        }
        let mut answers = Vec::new();
        let logged = stderr_of(|| {
            for (pasted, message) in &cases {
                let (status, body) = s.code(pasted);
                let e: GatewayError = serde_json::from_slice(&body).unwrap();
                assert_eq!(
                    (status, e.class, e.message.as_deref()),
                    (400, ErrorClass::BadRequest, Some(*message)),
                    "{kind}"
                );
                answers.push((status, body));
            }
        });
        assert!(
            s.tokens.received().is_empty(),
            "{kind}: nothing was exchanged"
        );
        assert_eq!(std::fs::read_to_string(&s.file).unwrap(), s.old);
        assert_eq!(backups_of(&s.file), Vec::<PathBuf>::new());

        s.grant();
        let (status, body) = s.code(&s.paste(&code, &state));
        assert_eq!(
            status,
            200,
            "{kind}: the sign-in stayed pending: {}",
            String::from_utf8_lossy(&body)
        );
        let refused: Vec<_> = s.audited()[1..=cases.len()]
            .iter()
            .map(|(action, _, result, reason, _)| (*action, *result, reason.clone().unwrap()))
            .collect();
        let want: Vec<_> = cases
            .iter()
            .map(|(_, m)| {
                (
                    AuditAction::LoginOauthCode,
                    AuditResult::Refused,
                    (*m).to_owned(),
                )
            })
            .collect();
        assert_eq!(refused, want);
        s.assert_hidden(&answers, &logged, &[&state]);
    }
}

#[test]
fn a_code_without_a_live_sign_in_is_409_and_reaches_no_endpoint() {
    let s = sign_rig("oauth_anthropic", 0, "", own_uid());
    let code = format!("code-{SIGN_MARK}");
    let (status, e) = {
        let (status, body) = s.code(&s.paste(&code, "state-1"));
        (
            status,
            serde_json::from_slice::<GatewayError>(&body).unwrap(),
        )
    };
    assert_eq!((status, e.class), (409, ErrorClass::BadRequest));
    assert_eq!(
        e.message.as_deref(),
        Some(
            "no sign-in of login `login-1` is pending; start one with POST /v1/model/logins/login-1/oauth/start"
        )
    );
    let started = s.start();
    assert!(
        started.expires_at <= unix_now(),
        "a sign-in of expiry 0 has expired at once"
    );
    let state = param(&started.url, "state");
    let mut answers = Vec::new();
    let logged = stderr_of(|| {
        answers.push(s.code(&s.paste(&code, &state)));
        answers.push(s.code(&s.paste(&code, &state)));
    });
    let messages: Vec<_> = answers
        .iter()
        .map(|(status, body)| {
            let e: GatewayError = serde_json::from_slice(body).unwrap();
            (*status, e.message.unwrap())
        })
        .collect();
    assert_eq!(
        messages,
        [
            (
                409,
                format!(
                    "the sign-in of login `login-1` expired at {}; start a new one",
                    started.expires_at
                )
            ),
            (
                409,
                "no sign-in of login `login-1` is pending; start one with POST \
                 /v1/model/logins/login-1/oauth/start"
                    .to_owned()
            ),
        ],
        "an expired sign-in is dropped"
    );
    assert!(s.tokens.received().is_empty());
    let results: Vec<_> = s
        .audited()
        .into_iter()
        .map(|(a, _, r, _, _)| (a, r))
        .collect();
    assert_eq!(
        results,
        [
            (AuditAction::LoginOauthCode, AuditResult::Refused),
            (AuditAction::LoginOauthStart, AuditResult::Ok),
            (AuditAction::LoginOauthCode, AuditResult::Refused),
            (AuditAction::LoginOauthCode, AuditResult::Refused),
        ]
    );
    s.assert_hidden(&answers, &logged, &[&state]);
}

#[test]
fn a_new_start_replaces_the_pending_sign_in_of_the_login() {
    let s = sign_rig("oauth_anthropic", 600, "", own_uid());
    let first = param(&s.start().url, "state");
    let second = s.start();
    let state = param(&second.url, "state");
    assert_ne!(first, state);
    let code = format!("code-{SIGN_MARK}");
    let (status, body) = s.code(&s.paste(&code, &first));
    let e: GatewayError = serde_json::from_slice(&body).unwrap();
    assert_eq!((status, e.class), (400, ErrorClass::BadRequest), "{e:?}");
    s.grant();
    let (status, body) = s.code(&s.paste(&code, &state));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (verifier, _) = granted_code(&s.tokens.received()[0]);
    assert_eq!(s256(&verifier), param(&second.url, "code_challenge"));
}

#[test]
fn a_refused_or_failed_exchange_is_502_names_no_value_and_uses_the_sign_in_up() {
    let refusal = json!({
        "error": "invalid_grant",
        "error_description": format!("code code-{SIGN_MARK} is spent"),
    });
    let no_refresh = json!({"access_token": format!("access-new-{SIGN_MARK}"), "expires_in": 3600});
    let down = json!({"error": format!("down {SIGN_MARK}")});
    let cases = [
        (
            token_answer(400, &refusal),
            ErrorClass::Auth,
            "the token endpoint refused the code: ",
        ),
        (
            token_answer(200, &no_refresh),
            ErrorClass::Unavailable,
            "the token answer has no `refresh_token`",
        ),
        (
            token_answer(503, &down),
            ErrorClass::Unavailable,
            "the token exchange failed: ",
        ),
    ];
    for (answer, class, says) in cases {
        let s = sign_rig("oauth_anthropic", 600, "", own_uid());
        let state = param(&s.start().url, "state");
        let pasted = s.paste(&format!("code-{SIGN_MARK}"), &state);
        s.tokens.answer(answer);
        let mut answers = Vec::new();
        let logged = stderr_of(|| {
            answers.push(s.code(&pasted));
            answers.push(s.code(&pasted));
        });
        let e: GatewayError = serde_json::from_slice(&answers[0].1).unwrap();
        assert_eq!((answers[0].0, e.class), (502, class), "{e:?}");
        let message = e.message.unwrap();
        assert!(message.starts_with(says), "{message}");
        let e: GatewayError = serde_json::from_slice(&answers[1].1).unwrap();
        assert_eq!(
            answers[1].0, 409,
            "the failed exchange used the sign-in up: {e:?}"
        );
        assert_eq!(s.tokens.received().len(), 1);
        assert_eq!(std::fs::read_to_string(&s.file).unwrap(), s.old);
        assert_eq!(backups_of(&s.file), Vec::<PathBuf>::new());
        let (status, _, _) = turn(&s.r.gw, &turn_body("turn-1"));
        assert_eq!(status, 200);
        assert_eq!(s.sent(), [format!("access-old-{SIGN_MARK}")]);
        let audited = s.audited();
        assert_eq!(
            audited[1],
            (
                AuditAction::LoginOauthCode,
                Some("login-1".to_owned()),
                AuditResult::Refused,
                Some(message),
                None
            )
        );
        s.assert_hidden(&answers, &logged, &[&state]);
    }
}

/// A refused sign-in request: method, login, step, body, status and message of the answer.
type SignCase = (
    &'static str,
    &'static str,
    &'static str,
    String,
    u16,
    &'static str,
);

/// A paste that names a state no sign-in sent.
fn some_code() -> String {
    json!({ "pasted": format!("code-{SIGN_MARK}#state-1") }).to_string()
}

/// Sends each of `cases` to `rig` and checks its answer, then that nothing was exchanged or
/// written and that each left its refused audit line and no value anywhere.
fn refused_sign_ins(rig: &SignRig, cases: &[SignCase]) {
    let mut answers = Vec::new();
    let logged = stderr_of(|| {
        for (method, login, step, body, status, message) in cases {
            let path = format!("{}/{login}/oauth/{step}", paths::MODEL_LOGINS);
            let (got, answer) = call(&rig.r.gw, method, &path, body);
            let e: GatewayError = serde_json::from_slice(&answer).unwrap();
            assert_eq!(
                (got, e.message.as_deref()),
                (*status, Some(*message)),
                "{method} {login} {step}"
            );
            let class = if *status == 403 {
                ErrorClass::Auth
            } else {
                ErrorClass::BadRequest
            };
            assert_eq!(e.class, class);
            answers.push((got, answer));
        }
    });
    assert!(rig.tokens.received().is_empty());
    assert_eq!(std::fs::read_to_string(&rig.file).unwrap(), rig.old);
    assert_eq!(backups_of(&rig.file), Vec::<PathBuf>::new());
    let audited: Vec<_> = std::fs::read_to_string(&rig.audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<AuditEntry>(l).unwrap())
        .map(|e| (e.action, e.object, e.result, e.reason))
        .collect();
    let want: Vec<_> = cases
        .iter()
        .map(|(_, login, step, _, _, message)| {
            let action = if *step == "start" {
                AuditAction::LoginOauthStart
            } else {
                AuditAction::LoginOauthCode
            };
            let reason = Some((*message).to_owned());
            (
                action,
                Some((*login).to_owned()),
                AuditResult::Refused,
                reason,
            )
        })
        .collect();
    assert_eq!(audited, want);
    rig.assert_hidden(&answers, &logged, &[]);
}

#[test]
fn a_sign_in_is_refused_to_other_uids_and_on_the_loopback_listener() {
    let others = format!("\n[[clients]]\nname = \"client-u\"\nuid = {}\n", own_uid());
    let foreign = sign_rig("chatgpt_oauth", 600, &others, own_uid() + 1);
    let only = "only the gateway's own uid may sign a login in";
    refused_sign_ins(
        &foreign,
        &[
            ("POST", "login-1", "start", String::new(), 403, only),
            ("POST", "login-1", "code", some_code(), 403, only),
        ],
    );
    let (listener, addr, front) = loopback_front("");
    let served = rig_on(4, &key_files(), &front, own_uid(), Some(listener));
    for step in ["start", "code"] {
        let path = format!("{}/login-1/oauth/{step}", paths::MODEL_LOGINS);
        let auth = format!("X-Api-Key: {CLIENT_TOKEN}\r\n");
        let sent = tcp_send(addr, "POST", &path, &auth, &some_code());
        let (status, _, answer) = finish(sent, Vec::new());
        assert_eq!(status, 404, "the loopback listener does not serve `{step}`");
        let answer = String::from_utf8_lossy(&answer);
        assert!(!answer.contains(SIGN_MARK), "{answer}");
    }
    assert_eq!(
        std::fs::read_to_string(served.dir.join("creds/login-1.json")).unwrap(),
        api_key("test-token-1")
    );
}

#[test]
fn a_bad_sign_in_request_is_refused_and_audited_without_echoing_the_body() {
    let s = sign_rig("oauth_anthropic", 600, "", own_uid());
    let api_key_login = "login `login-2` is `api_key`, not an OAuth login";
    let extra = json!({"pasted": format!("code-{SIGN_MARK}"), "code": SIGN_MARK}).to_string();
    let cut = format!(r#"{{"pasted": "code-{SIGN_MARK}""#);
    let over = json!({ "pasted": format!("code-{SIGN_MARK}#{}", "s".repeat(8192)) }).to_string();
    refused_sign_ins(
        &s,
        &[
            (
                "POST",
                "login-9",
                "start",
                String::new(),
                404,
                "no login `login-9`",
            ),
            (
                "POST",
                "login-9",
                "code",
                some_code(),
                404,
                "no login `login-9`",
            ),
            (
                "POST",
                "login-2",
                "start",
                String::new(),
                409,
                api_key_login,
            ),
            ("POST", "login-2", "code", some_code(), 409, api_key_login),
            (
                "POST",
                "login-1",
                "start",
                "{}".into(),
                400,
                "this request takes no body",
            ),
            (
                "GET",
                "login-1",
                "start",
                String::new(),
                405,
                "method not allowed",
            ),
            (
                "PUT",
                "login-1",
                "code",
                some_code(),
                405,
                "method not allowed",
            ),
            (
                "POST",
                "login-1",
                "code",
                extra,
                400,
                "the body must be one object with the string `pasted` only",
            ),
            (
                "POST",
                "login-1",
                "code",
                cut,
                400,
                "the body is not valid JSON (line 1, column 25)",
            ),
            (
                "POST",
                "login-1",
                "code",
                over,
                413,
                "request body over 8192 bytes",
            ),
        ],
    );
}

/// The answers of every admin read on `gw`: routes, config routes, spend, audit, health, and the
/// usage since `from` by each grouping.
fn admin_reads(gw: &Path, from: u64) -> Vec<(u16, Vec<u8>)> {
    let mut answers: Vec<_> = [
        paths::MODEL_ROUTES,
        paths::MODEL_CONFIG_ROUTES,
        paths::MODEL_SPEND,
        paths::MODEL_AUDIT,
        paths::HEALTH,
    ]
    .into_iter()
    .map(|path| call(gw, "GET", path, ""))
    .collect();
    for group_by in ["client", "login", "model", "route", "tool"] {
        answers.push(usage_of(gw, &format!("?from={from}&group_by={group_by}")));
    }
    answers
}

/// The access token, refresh token and account id of the old `chatgpt_oauth` credential of
/// [`sign_rig`] and of its [`SignRig::grant`], the two access tokens first.
fn oauth_values() -> Vec<String> {
    [
        "access-old",
        "access-new",
        "refresh-old",
        "refresh-new",
        "acct-old",
        "acct-new",
    ]
    .map(|v| format!("{v}-{SIGN_MARK}"))
    .to_vec()
}

#[test]
fn no_secret_the_gateway_handles_reaches_its_log_ledger_audit_or_any_answer() {
    let (token_file, grace_file) = token_files(FILE_TOKEN);
    let (listener, addr, front) = loopback_front(&rotating_keys(&token_file, &grace_file, 3600));
    let s = sign_rig_on("chatgpt_oauth", 600, &front, own_uid(), Some(listener));
    let old_key = common::credentials::written(&s.r.dir.join("creds/login-2.json"))["key"]
        .as_str()
        .unwrap()
        .to_owned();
    let code = format!("code-{SIGN_MARK}");
    let messages = sdk_body("model-2025-01-01", false);
    let front_turn = |token: &str| loopback_post(addr, paths::MESSAGES, token, &messages);
    let unix_turn = |id: &str| {
        call(
            &s.r.gw,
            "POST",
            paths::MODEL_TURN,
            &turn_body(id).to_string(),
        )
    };
    let now = unix_now();
    let mut answers = Vec::new();
    let mut start = (0, Vec::new());
    let mut rotated_token = String::new();
    let logged = stderr_until("on login-1: usage_limit", || {
        answers.push(unix_turn("turn-1"));
        answers.extend([CLIENT_TOKEN, FILE_TOKEN, CLIENT_A.0].map(front_turn));
        answers.push(rotate(&s.r.gw, "client-f"));
        rotated_token = std::fs::read_to_string(&token_file).unwrap();
        answers.extend([rotated_token.as_str(), FILE_TOKEN].map(front_turn));
        answers.push(put_key(
            &s.r.gw,
            "login-2",
            &json!({"key": NEW_KEY}).to_string(),
        ));
        start = s.post("login-1", "start", "");
        let started: LoginOauthStarted = serde_json::from_slice(&start.1).unwrap();
        s.grant();
        answers.push(s.code(&s.paste(&code, &param(&started.url, "state"))));
        s.r.fake.script("login-1", usage_limit(now + 3600));
        answers.push(unix_turn("turn-2"));
        answers.push(front_turn(&rotated_token));
        answers.extend(admin_reads(&s.r.gw, now - 60));
    });
    for (status, body) in answers.iter().chain([&start]) {
        assert_eq!(*status, 200, "{}", String::from_utf8_lossy(body));
    }
    for done in [
        "rotated the token of client `client-f`",
        "replaced the key of login `login-2`",
        "signed in login `login-1`",
    ] {
        assert!(logged.contains(done), "{logged}");
    }

    let calls = s.r.fake.calls();
    let sent: Vec<(&str, &str)> = calls
        .iter()
        .map(|(l, k, _)| (l.as_str(), k.as_str()))
        .collect();
    let oauth = oauth_values();
    assert_eq!(sent[0], ("login-1", oauth[0].as_str()));
    assert_eq!(
        sent[sent.len() - 3..],
        [
            ("login-1", oauth[1].as_str()),
            ("login-2", NEW_KEY),
            ("login-2", NEW_KEY)
        ],
        "the attempts after the replacements send the new credentials"
    );
    let ledger = usage_lines(&s.ledger);
    let clients: Vec<&str> = ledger.iter().map(|l| l.client.as_str()).collect();
    for client in ["client-f", "client-a"] {
        assert!(clients.contains(&client), "{clients:?}");
    }

    let started: LoginOauthStarted = serde_json::from_slice(&start.1).unwrap();
    let verifier = s.exchanged(&started);
    let state = param(&started.url, "state");
    let challenge = param(&started.url, "code_challenge");
    let in_url = [state.as_str(), challenge.as_str()];
    let mut secrets = vec![
        CLIENT_TOKEN.to_owned(),
        CLIENT_A.0.to_owned(),
        FILE_TOKEN.to_owned(),
        rotated_token,
        old_key,
        NEW_KEY.to_owned(),
        code,
        verifier,
    ];
    secrets.extend(oauth);
    for secret in &secrets {
        assert!(!started.url.contains(secret.as_str()), "{}", started.url);
    }
    // The authorize URL is the one place the state and the challenge may appear.
    let start_text = String::from_utf8(start.1).unwrap();
    assert!(start_text.contains(&started.url), "{start_text}");
    answers.push((200, start_text.replace(&started.url, "").into_bytes()));
    let hidden: Vec<&str> = secrets.iter().map(String::as_str).chain(in_url).collect();
    s.assert_hidden(&answers, &logged, &hidden);
}
