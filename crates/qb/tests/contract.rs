//! Contract tests: the `/v1` endpoints over a real unix socket, in-process and via the binary.

#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb::agent::{Fetched, Fetcher};
use qb::auth::Gate;
use qb::client::call;
use qb::config::Kind;
use qb::config::{self, Limits};
use qb::hooks::Runner;
use qb::journal::{self, Journal};
use qb_core::{Core, Record, Spec};
use qb_proto::{
    AdminLoginsResetAnswer, AdminReloadAnswer, AdminRoles, AdminRolesPut, AdminRolesWritten,
    AgentJob, Decision, ErrorBody, ErrorCode, HealthResponse, HealthStatus, LadderCandidate,
    LadderStep, LoginStatus, Outcome, PickResponse, ReportRequest, ReportResponse, RoleConfig,
    RoleReserve, RolesResponse, RolesSource, Source, StateResponse, WhyResponse, WindowReport,
    paths,
};

mod common;

use common::http::{etag, finish, put, send, sha256_hex};
use common::{
    Daemon, answer, events, hook_config, kill_auth, line_with, own_uid, park, pick_worker, post,
    record_event, report_login, start_daemon, state, stderr_lines, temp_dir, wait_for,
};

fn temp_socket(tag: &str) -> PathBuf {
    temp_dir(tag).join("qb.sock")
}

/// Starts an in-process daemon on a fresh socket. The thread lives until the test binary exits.
fn spawn_server() -> PathBuf {
    let path = temp_socket("lib");
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        let mut core = Core::new(Spec::default()).unwrap();
        let mut gate = Gate::new(&[], &Limits::default());
        qb::server::serve(
            &listener,
            &mut core,
            &mut Journal::off(),
            &mut Runner::default(),
            &mut gate,
            &[],
            None,
        )
    });
    path
}

fn error_of(body: &[u8]) -> ErrorCode {
    serde_json::from_slice::<ErrorBody>(body).unwrap().error
}

#[test]
fn health_reports_version() {
    let sock = spawn_server();
    let (status, body) = call(&sock, "GET", paths::HEALTH, None, None).unwrap();
    assert_eq!(status, 200);
    let h: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(h.status, HealthStatus::Ok);
    assert_eq!(h.api_version, "v1");
    assert_eq!(h.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn state_is_empty_without_config() {
    let sock = spawn_server();
    let (status, body) = call(&sock, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 200);
    let s: StateResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(s.logins.len(), 0);
    assert_eq!(s.leases.len(), 0);
    assert!(s.now > 1_700_000_000);
}

#[test]
fn pick_without_logins_is_dead() {
    let sock = spawn_server();
    let body = br#"{"role":"worker","difficulty":1}"#;
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(body), None).unwrap();
    assert_eq!(status, 200);
    let p: PickResponse = serde_json::from_slice(&resp).unwrap();
    assert_eq!(p.decision, Decision::Dead);
    assert_eq!(p.reason, "no_candidates");
    assert!(p.lease_id.is_none());
}

#[test]
fn pick_rejects_invalid_requests() {
    let sock = spawn_server();
    for body in [
        &b"not json"[..],
        br#"{"role":"worker"}"#,
        br#"{"role":"worker","difficulty":1,"pin":{"vendor":"v","model":"m"}}"#,
        br#"{"role":"worker","difficulty":1,"unknown":true}"#,
        br#"{"role":"worker","difficulty":1,"on_behalf_of":""}"#,
        format!(
            r#"{{"role":"worker","difficulty":1,"on_behalf_of":"{}"}}"#,
            "c".repeat(129)
        )
        .as_bytes(),
    ] {
        let (status, resp) = call(&sock, "POST", paths::PICK, Some(body), None).unwrap();
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(body));
        assert_eq!(error_of(&resp), ErrorCode::BadRequest);
    }
}

#[test]
fn report_on_unknown_subjects() {
    let sock = spawn_server();
    let (status, resp) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(br#"{"lease_id":"l-1","outcome":"ok","release":true}"#),
        None,
    )
    .unwrap();
    assert_eq!(status, 404);
    assert_eq!(error_of(&resp), ErrorCode::NotFound);
    let (status, _) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(br#"{"login":"nope","outcome":"usage_limit"}"#),
        None,
    )
    .unwrap();
    assert_eq!(status, 404);
    let (status, _) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(br#"{"outcome":"ok"}"#),
        None,
    )
    .unwrap();
    assert_eq!(status, 400);
}

#[test]
fn routing_errors() {
    let sock = spawn_server();
    let (status, resp) = call(&sock, "GET", "/v1/nope", None, None).unwrap();
    assert_eq!(status, 404);
    assert_eq!(error_of(&resp), ErrorCode::NotFound);
    let (status, resp) = call(&sock, "GET", paths::PICK, None, None).unwrap();
    assert_eq!(status, 405);
    assert_eq!(error_of(&resp), ErrorCode::MethodNotAllowed);
    let (status, _) = call(&sock, "POST", paths::HEALTH, Some(b"{}"), None).unwrap();
    assert_eq!(status, 405);
}

#[test]
fn oversized_and_unframed_requests() {
    let sock = spawn_server();
    let big = vec![b' '; qb::http::MAX_BODY + 1];
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(&big), None).unwrap();
    assert_eq!(status, 413);
    assert_eq!(error_of(&resp), ErrorCode::PayloadTooLarge);

    let mut s = UnixStream::connect(&sock).unwrap();
    s.write_all(b"POST /v1/pick HTTP/1.1\r\nHost: qb\r\n\r\n")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 411 "), "{raw}");
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/examples")
        .join(name)
}

#[test]
fn binary_roles_end_to_end() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let sock = temp_socket("bin");
    let _d = Daemon(
        Command::new(exe)
            .args(["--socket"])
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(example("minimal.toml"))
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&sock);

    let health = Command::new(exe)
        .arg("--socket")
        .arg(&sock)
        .arg("health")
        .output()
        .unwrap();
    assert!(health.status.success());
    let h: HealthResponse = serde_json::from_slice(&health.stdout).unwrap();
    assert_eq!(h.api_version, "v1");

    let pick = Command::new(exe)
        .env("QB_SOCKET", &sock)
        .args(["pick", "--role", "worker", "--difficulty", "0"])
        .output()
        .unwrap();
    assert!(pick.status.success());
    let p: PickResponse = serde_json::from_slice(&pick.stdout).unwrap();
    assert_eq!(p.decision, Decision::Dead);

    let report = Command::new(exe)
        .env("QB_SOCKET", &sock)
        .args(["report", "--lease", "l-9", "--outcome", "http_429"])
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(1), "404 maps to exit 1");

    let second = Command::new(exe)
        .env("QB_SOCKET", &sock)
        .env("QB_CONFIG", example("minimal.toml"))
        .arg("daemon")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(
        second.code(),
        Some(2),
        "a second daemon on a live socket refuses"
    );
}

#[test]
fn daemon_serves_configured_logins() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let sock = temp_socket("cfg");
    let file = journaled_config(sock.parent().unwrap(), 1 << 20);
    let _d = Daemon(
        Command::new(exe)
            .arg("--socket")
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(&file)
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&sock);
    let (status, body) = call(&sock, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 200);
    let state: StateResponse = serde_json::from_slice(&body).unwrap();
    let served: Vec<(String, String)> = state
        .logins
        .into_iter()
        .map(|l| (l.login, l.vendor))
        .collect();
    let configured: Vec<(String, String)> = config::load(&file)
        .unwrap()
        .logins
        .into_iter()
        .map(|l| (l.name, l.vendor))
        .collect();
    assert_ne!(configured, []);
    assert_eq!(served, configured);
}

fn report_windows(sock: &Path, login: &str, windows: &[(&str, f64, u64)]) {
    let req = ReportRequest {
        lease_id: None,
        login: Some(login.into()),
        outcome: Outcome::Ok,
        model: None,
        windows: windows
            .iter()
            .map(|&(name, utilization, resets_at)| WindowReport {
                name: name.into(),
                utilization,
                resets_at: Some(resets_at),
                length_s: None,
            })
            .collect(),
        release: false,
        credential: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let (status, resp) = call(sock, "POST", paths::REPORT, Some(&body), None).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let r: ReportResponse = serde_json::from_slice(&resp).unwrap();
    assert!(r.accepted);
}

#[test]
fn reported_windows_steer_pick_and_show_in_state() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let sock = temp_socket("policy");
    let _d = Daemon(
        Command::new(exe)
            .arg("--socket")
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(journaled_config(sock.parent().unwrap(), 1 << 20))
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&sock);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (hour, day) = (3600, 86_400);
    report_windows(
        &sock,
        "login-1",
        &[
            ("five_hour", 0.1, now + 2 * hour),
            ("seven_day", 0.7, now + 6 * hour),
        ],
    );
    report_windows(
        &sock,
        "login-2",
        &[
            ("five_hour", 0.1, now + 2 * hour),
            ("seven_day", 0.1, now + 6 * day),
        ],
    );

    let p = pick_worker(&sock);
    assert_eq!(p.decision, Decision::Run, "{p:?}");
    assert_eq!(p.reason, "spend_before_reset");
    assert_eq!(
        (p.login.as_deref(), p.vendor.as_deref(), p.model.as_deref()),
        (Some("login-1"), Some("vendor-a"), Some("model-small"))
    );
    assert_eq!(
        (p.effort.as_deref(), p.tier, p.stale),
        (Some("low"), Some(1), false)
    );
    assert!(p.quota_snapshot_at.is_some_and(|t| t >= now));

    report_windows(&sock, "login-1", &[("five_hour", 1.0, now + 2 * hour)]);
    let p = pick_worker(&sock);
    assert_eq!(p.decision, Decision::Run, "{p:?}");
    assert_eq!(p.login.as_deref(), Some("login-2"));

    let (status, body) = call(&sock, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 200);
    let state: StateResponse = serde_json::from_slice(&body).unwrap();
    let login = |name: &str| {
        state
            .logins
            .iter()
            .find(|l| l.login == name)
            .unwrap()
            .windows
            .iter()
            .map(|w| (w.name.as_str(), w.used, w.resets_at, w.source, w.stale))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        login("login-1"),
        [
            (
                "five_hour",
                1.0,
                Some(now + 2 * hour),
                Source::Stream,
                false
            ),
            (
                "seven_day",
                0.7,
                Some(now + 6 * hour),
                Source::Stream,
                false
            ),
        ]
    );
    assert_eq!(
        login("login-3"),
        [("five_hour", 0.0, None, Source::Assumed, true)]
    );
    let l1 = &state.logins[0].windows[0];
    assert!(l1.observed_at >= now && l1.reserved == 0.0, "{l1:?}");
}

#[test]
fn daemon_refuses_a_missing_or_invalid_config() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let sock = temp_socket("badcfg");
    let invalid = sock.with_file_name("invalid.toml");
    let text = std::fs::read_to_string(example("minimal.toml"))
        .unwrap()
        .replace("vendor = \"vendor-a\"", "vendor = \"vendor-z\"");
    std::fs::write(&invalid, text).unwrap();
    let missing = sock.with_file_name("missing.toml");
    for (config, expected) in [
        (&missing, format!("{}: cannot read", missing.display())),
        (
            &invalid,
            format!(
                "{}: logins[0].vendor: undeclared vendor `vendor-z`",
                invalid.display()
            ),
        ),
    ] {
        let out = Command::new(exe)
            .arg("--socket")
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(config)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{stderr}");
        assert!(stderr.contains(&expected), "{stderr}");
        assert!(
            !sock.exists(),
            "the socket is bound only after the config loads"
        );
    }
}

#[test]
fn cli_usage_errors_exit_2() {
    let exe = env!("CARGO_BIN_EXE_qb");
    for args in [
        &["pick", "--role", "worker"][..],
        &["report", "--lease", "l-1"],
        &["report", "--lease", "l-1", "--outcome", "bogus"],
        &[
            "report",
            "--lease",
            "l-1",
            "--outcome",
            "ok",
            "--from-stream-json",
            "-",
        ],
        &["why"],
        &["agent"],
        &["agent", "--config", "/nonexistent/agent.toml"],
        &["simulate"],
        &["simulate", "journal", "--pick", r#"{"role":"worker"}"#],
        &["frobnicate"],
    ] {
        let st = Command::new(exe)
            .env("QB_SOCKET", "/nonexistent/qb.sock")
            .args(args)
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(st.code(), Some(2), "{args:?}");
    }
    let unreachable = Command::new(exe)
        .env("QB_SOCKET", "/nonexistent/qb.sock")
        .arg("health")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(unreachable.code(), Some(2));
}

#[test]
fn leases_reserve_quota_and_reports_steer_the_next_pick() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let sock = temp_socket("leases");
    let _d = Daemon(
        Command::new(exe)
            .arg("--socket")
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(journaled_config(sock.parent().unwrap(), 1 << 20))
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&sock);
    let task = r#"{"role":"worker","difficulty":1,"expected_minutes":30,"run_id":"run-1"}"#;

    let first: PickResponse = post(&sock, paths::PICK, task);
    assert_eq!(first.decision, Decision::Run, "{first:?}");
    assert_eq!(first.login.as_deref(), Some("login-1"));
    let lease = first.lease_id.clone().unwrap();

    let s = state(&sock);
    assert_eq!(s.leases.len(), 1);
    let l = &s.leases[0];
    assert_eq!(
        (l.lease_id.as_str(), l.login.as_str(), l.model.as_str()),
        (lease.as_str(), "login-1", "model-small")
    );
    assert_eq!(l.run_id.as_deref(), Some("run-1"));
    assert!(l.expires_at >= s.now + 30 * 60, "{l:?}");
    let reserved: Vec<f64> = s.logins[0].windows.iter().map(|w| w.reserved).collect();
    assert!(reserved.iter().all(|&r| r > 0.0), "{reserved:?}");

    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{lease}","outcome":"usage_limit"}}"#),
    );
    assert_eq!(r.login_status, LoginStatus::Exhausted);
    let second: PickResponse = post(&sock, paths::PICK, task);
    assert_eq!(second.decision, Decision::Run, "{second:?}");
    assert_eq!(second.login.as_deref(), Some("login-2"));
    assert_ne!(second.lease_id, first.lease_id);

    let release = format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#);
    let _: ReportResponse = post(&sock, paths::REPORT, &release);
    let s = state(&sock);
    let live: Vec<&str> = s.leases.iter().map(|l| l.lease_id.as_str()).collect();
    assert_eq!(live, [second.lease_id.as_deref().unwrap()]);
    assert!(s.logins[0].windows.iter().all(|w| w.reserved == 0.0));
    assert!(s.logins[0].dead_until.is_some());
    let (status, _) = call(&sock, "POST", paths::REPORT, Some(release.as_bytes()), None).unwrap();
    assert_eq!(status, 404, "a released lease is gone");
}

#[test]
fn a_login_list_keeps_picks_on_its_logins() {
    let sock = temp_socket("allow");
    let _d = start(&journaled_config(sock.parent().unwrap(), 1 << 20), &sock);
    let listed = r#"{"role":"worker","difficulty":1,"expected_minutes":30,"logins":["login-2"]}"#;
    for _ in 0..5 {
        let p: PickResponse = post(&sock, paths::PICK, listed);
        assert_eq!(
            (p.decision, p.login.as_deref()),
            (Decision::Run, Some("login-2")),
            "{p:?}"
        );
    }
    let free = pick_worker(&sock);
    assert_eq!(
        free.login.as_deref(),
        Some("login-1"),
        "the unlisted login is preferred"
    );

    let unknown = br#"{"role":"worker","difficulty":1,"logins":["login-2","login-9"]}"#;
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(unknown), None).unwrap();
    assert_eq!(status, 400);
    let e: ErrorBody = serde_json::from_slice(&resp).unwrap();
    assert_eq!(e.error, ErrorCode::BadRequest);
    assert!(e.message.contains("`logins`"), "{}", e.message);
}

#[test]
fn need_is_accepted_and_does_not_change_the_pick() {
    let sock = temp_socket("need");
    let _d = start(&journaled_config(sock.parent().unwrap(), 1 << 20), &sock);
    let shape = |p: PickResponse| (p.decision, p.vendor, p.model, p.effort, p.login, p.tier);
    let needy = r#"{"role":"worker","difficulty":1,"need":["capability-x","capability-y"]}"#;
    let with_need: PickResponse = post(&sock, paths::PICK, needy);
    assert_eq!(with_need.decision, Decision::Run, "{with_need:?}");
    assert_eq!(
        shape(with_need),
        shape(pick_worker(&sock)),
        "no candidate declares capabilities, so `need` filters nothing"
    );
}

/// Token of the bearer client `client-b` in the configs below; `BEARER_SHA256` is its hash.
const BEARER: &str = "token-b";
const BEARER_SHA256: &str = "49e2bb7eab54cf09b409ffafd3fa8a8a955a60eb972faacaefbed3dbd3207132";

/// Uids no test process runs as and `qbd.toml` does not declare.
const FOREIGN_UIDS: [u32; 2] = [4_000_000_001, 4_000_000_002];

fn foreign_uid(slot: usize) -> u32 {
    let uid = FOREIGN_UIDS[slot];
    assert_ne!(uid, own_uid(), "the test process runs as a foreign uid");
    uid
}

/// The lines that declare `client-a` and `agent-1` in the example `qbd.toml`, by bearer as the
/// shipped `qbd.service` needs; the edits below swap the bearer for a uid.
const CLIENT_A: &str = "name = \"client-a\"\nbearer_sha256 = \"0000000000000000000000000000000000000000000000000000000000000003\"";
const AGENT_1: &str = "name = \"agent-1\"\nbearer_sha256 = \"0000000000000000000000000000000000000000000000000000000000000002\"";

/// [`config_copy`] edit giving the example client `client` the uid `uid`. Anchored on the client's
/// name, so edits of different clients never rewrite each other's result.
fn client_uid(client: &str, uid: u32) -> (&'static str, String) {
    let line = match client {
        "client-a" => CLIENT_A,
        "agent-1" => AGENT_1,
        other => panic!("{other} is not a client of qbd.toml"),
    };
    (line, format!("name = \"{client}\"\nuid = {uid}"))
}

/// `qbd.toml` in `dir` with each `(from, to)` replaced, `from` occurring exactly once, and its
/// journal at `dir/journal`.
fn config_copy(dir: &Path, edits: &[(&str, String)]) -> PathBuf {
    let mut text = std::fs::read_to_string(example("qbd.toml")).unwrap();
    let journal = format!("path = \"{}\"", dir.join("journal").display());
    for (from, to) in [("path = \"/var/lib/qb/journal\"", journal)]
        .iter()
        .chain(edits)
    {
        assert_eq!(text.matches(from).count(), 1, "{from} not once in qbd.toml");
        text = text.replacen(from, to, 1);
    }
    let file = dir.join("qbd.toml");
    std::fs::write(&file, text).unwrap();
    file
}

/// `qbd.toml` rotated at `rotate_bytes`, with `client-a` on this process's uid, `agent-1` on a
/// foreign uid, `client-b` on [`BEARER`] and limits no test reaches.
fn journaled_config(dir: &Path, rotate_bytes: u64) -> PathBuf {
    config_copy(
        dir,
        &[
            (
                "rotate_bytes = 1048576",
                format!("rotate_bytes = {rotate_bytes}"),
            ),
            client_uid("client-a", own_uid()),
            client_uid("agent-1", foreign_uid(0)),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                BEARER_SHA256.to_owned(),
            ),
            ("rate_per_s = 5.0", "rate_per_s = 1000.0".to_owned()),
            ("burst = 20", "burst = 1000".to_owned()),
        ],
    )
}

fn start(config: &Path, sock: &Path) -> Daemon {
    start_with(config, sock, Stdio::null())
}

fn start_with(config: &Path, sock: &Path, stderr: Stdio) -> Daemon {
    start_daemon(Path::new(env!("CARGO_BIN_EXE_qb")), config, sock, stderr)
}

const TASK: &str = r#"{"role":"worker","difficulty":1,"expected_minutes":30}"#;

/// Leaves a live lease on login-1, `exhausted` on login-1, `auth_dead` on login-3, and a
/// released lease on login-2 whose id it returns.
fn mark_and_lease(sock: &Path) -> String {
    for _ in 0..2 {
        let r: ReportResponse = post(
            sock,
            paths::REPORT,
            r#"{"login":"login-3","outcome":"http_401"}"#,
        );
        assert!(r.accepted);
    }
    let live: PickResponse = post(sock, paths::PICK, TASK);
    assert_eq!(live.login.as_deref(), Some("login-1"), "{live:?}");
    let r: ReportResponse = post(
        sock,
        paths::REPORT,
        &format!(
            r#"{{"lease_id":"{}","outcome":"usage_limit"}}"#,
            live.lease_id.unwrap()
        ),
    );
    assert_eq!(r.login_status, LoginStatus::Exhausted);
    let gone: PickResponse = post(sock, paths::PICK, TASK);
    assert_eq!(gone.login.as_deref(), Some("login-2"), "{gone:?}");
    let gone = gone.lease_id.unwrap();
    let _: ReportResponse = post(
        sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{gone}","outcome":"ok","release":true}}"#),
    );
    gone
}

/// A login's status, dead-until mark and reserved fractions.
type LoginMarks = (LoginStatus, Option<u64>, Vec<f64>);

/// What a restart must keep: leases, statuses with their dead-until marks, reservations.
fn durable(s: &StateResponse) -> (Vec<String>, Vec<LoginMarks>) {
    let leases = s
        .leases
        .iter()
        .map(|l| format!("{} {} {} {}", l.lease_id, l.login, l.model, l.expires_at))
        .collect();
    let logins = s
        .logins
        .iter()
        .map(|l| {
            let reserved = l.windows.iter().map(|w| w.reserved).collect();
            (l.status, l.dead_until, reserved)
        })
        .collect();
    (leases, logins)
}

fn assert_restored(before: &StateResponse, after: &StateResponse, released: &str) {
    assert_eq!(durable(after), durable(before));
    assert_eq!(after.leases.len(), 1);
    assert_eq!(after.logins[0].status, LoginStatus::Exhausted);
    assert!(after.logins[0].dead_until.is_some());
    assert_eq!(after.logins[2].status, LoginStatus::AuthDead);
    assert!(after.leases.iter().all(|l| l.lease_id != released));
}

#[test]
fn leases_and_marks_survive_a_restart() {
    let dir = temp_dir("restart");
    let config = journaled_config(&dir, 1 << 20);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let released = mark_and_lease(&sock);
    let before = state(&sock);
    drop(d);

    let _d = start(&config, &sock);
    let after = state(&sock);
    assert_restored(&before, &after, &released);
    let release = format!(r#"{{"lease_id":"{released}","outcome":"ok","release":true}}"#);
    let (status, _) = call(&sock, "POST", paths::REPORT, Some(release.as_bytes()), None).unwrap();
    assert_eq!(status, 404, "a released lease stays released");

    let fresh: PickResponse = post(&sock, paths::PICK, TASK);
    let fresh = fresh.lease_id.unwrap();
    assert!(fresh != released && after.leases.iter().all(|l| l.lease_id != fresh));
}

/// [`journaled_config`] with `client-a` an admin.
fn admin_journaled_config(dir: &Path) -> PathBuf {
    let (from, to) = client_uid("client-a", own_uid());
    config_copy(
        dir,
        &[
            (from, format!("{to}\nadmin = true")),
            client_uid("agent-1", foreign_uid(0)),
            (
                "0000000000000000000000000000000000000000000000000000000000000001",
                BEARER_SHA256.to_owned(),
            ),
            ("rate_per_s = 5.0", "rate_per_s = 1000.0".to_owned()),
            ("burst = 20", "burst = 1000".to_owned()),
        ],
    )
}

/// Reports `outcome` on `login` with the credential fingerprint `fp`: the login's status after.
fn report_credential(sock: &Path, login: &str, outcome: &str, fp: &str) -> LoginStatus {
    let body = format!(r#"{{"login":"{login}","outcome":"{outcome}","credential":"{fp}"}}"#);
    let r: ReportResponse = post(sock, paths::REPORT, &body);
    r.login_status
}

fn status_in(s: &StateResponse, login: &str) -> LoginStatus {
    s.logins.iter().find(|l| l.login == login).unwrap().status
}

#[test]
fn a_new_credential_clears_auth_dead_and_the_change_survives_a_restart() {
    let dir = temp_dir("credential");
    let config = journaled_config(&dir, 1 << 20);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    for _ in 0..2 {
        report_credential(&sock, "login-3", "http_401", "aaaaaaaaaaaaaaaa");
    }
    assert_eq!(status_in(&state(&sock), "login-3"), LoginStatus::AuthDead);
    drop(d);

    let d = start(&config, &sock);
    assert_eq!(status_in(&state(&sock), "login-3"), LoginStatus::AuthDead);
    assert_eq!(
        report_credential(&sock, "login-3", "error", "aaaaaaaaaaaaaaaa"),
        LoginStatus::AuthDead,
        "the credential the mark was reported with keeps it after a restart"
    );
    let bad = br#"{"login":"login-3","outcome":"error","credential":"not hex"}"#;
    let (status, body) = call(&sock, "POST", paths::REPORT, Some(bad), None).unwrap();
    assert_eq!((status, error_of(&body)), (400, ErrorCode::BadRequest));
    assert_ne!(
        report_credential(&sock, "login-3", "error", "bbbbbbbbbbbbbbbb"),
        LoginStatus::AuthDead,
        "a new credential clears the mark"
    );
    drop(d);

    let _d = start(&config, &sock);
    assert_ne!(status_in(&state(&sock), "login-3"), LoginStatus::AuthDead);
    let pin =
        r#"{"role":"worker","pin":{"vendor":"vendor-b","model":"model-small","login":"login-3"}}"#;
    let picked: PickResponse = post(&sock, paths::PICK, pin);
    assert_eq!(picked.login.as_deref(), Some("login-3"), "{picked:?}");
    let journal = std::fs::read_to_string(dir.join("journal")).unwrap();
    assert!(
        journal.contains(r#""auth":"dead","credential":"aaaaaaaaaaaaaaaa""#),
        "{journal}"
    );
}

/// `qb login reset` with `args` against `sock` as this process's uid, or with `bearer`: its exit
/// code and stdout.
fn login_reset(sock: &Path, bearer: Option<&Path>, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qb"));
    cmd.arg("--socket").arg(sock);
    if let Some(file) = bearer {
        cmd.arg("--bearer-file").arg(file);
    }
    let out = cmd
        .args(["login", "reset"])
        .args(args)
        .env_remove("QB_BEARER_FILE")
        .stderr(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

#[test]
fn login_reset_clears_auth_marks_for_an_admin_only_and_survives_a_restart() {
    let dir = temp_dir("loginreset");
    let config = admin_journaled_config(&dir);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let released = mark_and_lease(&sock);
    report_credential(&sock, "login-2", "http_401", "aaaaaaaaaaaaaaaa");
    let before = state(&sock);
    assert_eq!(status_in(&before, "login-2"), LoginStatus::AuthStale);

    let bearer = dir.join("bearer");
    std::fs::write(&bearer, BEARER).unwrap();
    let (code, out) = login_reset(&sock, Some(&bearer), &["login-3"]);
    assert_eq!(code, 1, "client-b is no admin");
    assert_eq!(error_of(out.as_bytes()), ErrorCode::Forbidden, "{out}");
    assert_eq!(status_in(&state(&sock), "login-3"), LoginStatus::AuthDead);
    let (code, _) = login_reset(&sock, None, &["login-9"]);
    assert_eq!(code, 1, "an unknown login");
    assert_eq!(status_in(&state(&sock), "login-3"), LoginStatus::AuthDead);

    let (code, out) = login_reset(&sock, None, &["login-3", "login-1"]);
    assert_eq!(code, 0, "{out}");
    let answer: AdminLoginsResetAnswer = serde_json::from_str(&out).unwrap();
    let got: Vec<(&str, bool, LoginStatus)> = answer
        .logins
        .iter()
        .map(|l| (l.login.as_str(), l.cleared, l.status))
        .collect();
    assert_eq!(
        got,
        [
            ("login-3", true, LoginStatus::Unknown),
            ("login-1", false, LoginStatus::Exhausted),
        ]
    );
    let (code, out) = login_reset(&sock, None, &["--all"]);
    assert_eq!(code, 0, "{out}");
    let answer: AdminLoginsResetAnswer = serde_json::from_str(&out).unwrap();
    let cleared: Vec<&str> = answer
        .logins
        .iter()
        .filter(|l| l.cleared)
        .map(|l| l.login.as_str())
        .collect();
    assert_eq!(cleared, ["login-2"]);
    assert_eq!(answer.logins.len(), before.logins.len());
    drop(d);

    let _d = start(&config, &sock);
    let after = state(&sock);
    for l in &after.logins {
        assert!(
            !matches!(l.status, LoginStatus::AuthDead | LoginStatus::AuthStale),
            "{l:?}"
        );
    }
    assert_eq!(status_in(&after, "login-1"), LoginStatus::Exhausted);
    assert!(after.leases.iter().all(|l| l.lease_id != released));
    assert_eq!(after.leases.len(), 1, "the live lease stays");
}

#[test]
fn login_reset_needs_logins_or_all() {
    // Usage errors exit before any connection.
    let sock = Path::new("/nonexistent/qb.sock");
    for args in [&[][..], &["--all", "login-1"][..]] {
        let (code, _) = login_reset(sock, None, args);
        assert_eq!(code, 2, "{args:?}");
    }
}

#[test]
fn rotation_keeps_two_bounded_files_and_the_live_state() {
    const ROTATE: u64 = 1024;
    const LINE: u64 = 400;
    let dir = temp_dir("rotate");
    let config = journaled_config(&dir, ROTATE);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let released = mark_and_lease(&sock);
    for _ in 0..12 {
        let p: PickResponse = post(&sock, paths::PICK, TASK);
        let lease = p.lease_id.unwrap();
        let _: ReportResponse = post(
            &sock,
            paths::REPORT,
            &format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#),
        );
    }
    let before = state(&sock);
    drop(d);

    let mut files: Vec<(String, u64)> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| {
            (
                e.file_name().into_string().unwrap(),
                e.metadata().unwrap().len(),
            )
        })
        .filter(|(name, _)| name.starts_with("journal"))
        .collect();
    files.sort();
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["journal", "journal.1"]);
    for (name, len) in &files {
        assert!(*len < ROTATE + LINE, "{name} has {len} bytes");
    }
    let issued = |name: &str| {
        let text = std::fs::read(dir.join(name)).unwrap();
        let first = text.split(|&b| b == b'\n').next().unwrap();
        match journal::decode(first).unwrap().0 {
            Record::Issued(n) => n,
            other => panic!("{name} starts with {other:?}"),
        }
    };
    assert!(
        issued("journal") > issued("journal.1"),
        "both files start with a rotation header, the current one later"
    );

    let _d = start(&config, &sock);
    assert_restored(&before, &state(&sock), &released);
}

fn lease_line(id: u64, now: u64) -> String {
    format!(
        r#"{{"at":{now},"lease":{{"id":{id},"login":"login-1","model":"model-small","client":"uid:1","cost":[0.06,0.0005],"expires_at":{}}}}}"#,
        now + 3600
    )
}

#[test]
fn a_torn_final_line_is_skipped() {
    let dir = temp_dir("torn");
    let config = journaled_config(&dir, 1 << 20);
    let journal = dir.join("journal");
    let now = qb::server::unix_now();
    let torn = lease_line(513, now);
    let torn = &torn[..torn.len() / 2];
    std::fs::write(&journal, format!("{}\n{torn}", lease_line(257, now))).unwrap();
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let ids: Vec<String> = state(&sock)
        .leases
        .into_iter()
        .map(|l| l.lease_id)
        .collect();
    assert_eq!(ids, ["l-257"]);
    let _: PickResponse = post(&sock, paths::PICK, TASK);
    drop(d);

    let _d = start(&config, &sock);
    assert_eq!(
        state(&sock).leases.len(),
        2,
        "appends after a torn line replay"
    );
}

#[test]
fn a_corrupt_middle_line_stops_start_up() {
    let dir = temp_dir("corrupt");
    let config = journaled_config(&dir, 1 << 20);
    let journal = dir.join("journal");
    let now = qb::server::unix_now();
    let text = format!(
        "{}\nnot json\n{}\n",
        lease_line(257, now),
        lease_line(513, now)
    );
    std::fs::write(&journal, text).unwrap();
    let sock = dir.join("qb.sock");
    let out = Command::new(env!("CARGO_BIN_EXE_qb"))
        .arg("--socket")
        .arg(&sock)
        .args(["daemon", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!("{}: line 2: ", journal.display())),
        "{stderr}"
    );
    assert!(!sock.exists(), "the socket is bound only after replay");
}

#[test]
fn journal_off_writes_nothing() {
    let state_dir = temp_dir("off-state");
    let sock = temp_socket("off");
    let d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_qb"))
            .current_dir(&state_dir)
            .env("TMPDIR", &state_dir)
            .arg("--socket")
            .arg(&sock)
            .args(["daemon", "--config"])
            .arg(example("minimal.toml"))
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(&sock);
    let p: PickResponse = post(&sock, paths::PICK, TASK);
    assert_eq!(p.decision, Decision::Run, "{p:?}");
    let lease = p.lease_id.unwrap();
    let _: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{lease}","outcome":"usage_limit","release":true}}"#),
    );
    let _: ReportResponse = post(
        &sock,
        paths::REPORT,
        r#"{"login":"login-1","outcome":"http_401"}"#,
    );
    drop(d);
    let left: Vec<_> = std::fs::read_dir(&state_dir).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
}

fn lease_clients(sock: &Path) -> Vec<(String, String)> {
    state(sock)
        .leases
        .into_iter()
        .map(|l| (l.lease_id, l.client))
        .collect()
}

#[test]
fn callers_are_identified_by_bearer_then_uid() {
    let dir = temp_dir("ident");
    let sock = dir.join("qb.sock");
    let _d = start(&journaled_config(&dir, 1 << 20), &sock);

    let by_uid: PickResponse = post(&sock, paths::PICK, TASK);
    let (status, body) = call(
        &sock,
        "POST",
        paths::PICK,
        Some(TASK.as_bytes()),
        Some(BEARER),
    )
    .unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let by_bearer: PickResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        lease_clients(&sock),
        [
            (by_uid.lease_id.unwrap(), "client-a".to_owned()),
            (by_bearer.lease_id.unwrap(), "client-b".to_owned()),
        ]
    );

    for (method, path, body) in [
        ("POST", paths::PICK, Some(TASK.as_bytes())),
        ("GET", paths::STATE, None),
    ] {
        let (status, resp) = call(&sock, method, path, body, Some("token-x")).unwrap();
        assert_eq!(
            status, 401,
            "{path}: a wrong bearer does not fall back to the uid"
        );
        assert_eq!(error_of(&resp), ErrorCode::Unauthorized);
    }
    assert_eq!(lease_clients(&sock).len(), 2);
}

#[test]
fn an_undeclared_uid_may_only_ask_for_health() {
    let dir = temp_dir("stranger");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[
            client_uid("client-a", foreign_uid(0)),
            client_uid("agent-1", foreign_uid(1)),
        ],
    );
    let _d = start(&config, &sock);
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(TASK.as_bytes()), None).unwrap();
    assert_eq!(status, 401);
    assert_eq!(error_of(&resp), ErrorCode::Unauthorized);
    let (status, _) = call(&sock, "GET", paths::STATE, None, None).unwrap();
    assert_eq!(status, 401);
    let (status, _) = call(&sock, "GET", paths::HEALTH, None, None).unwrap();
    assert_eq!(status, 200);
}

#[test]
fn without_clients_callers_are_named_by_uid() {
    let sock = temp_socket("open");
    let _d = start(&example("minimal.toml"), &sock);
    let p: PickResponse = post(&sock, paths::PICK, TASK);
    assert_eq!(
        lease_clients(&sock),
        [(p.lease_id.unwrap(), format!("uid:{}", own_uid()))]
    );
}

#[test]
fn only_the_holder_reports_a_lease() {
    let dir = temp_dir("owner");
    let sock = dir.join("qb.sock");
    let _d = start(&journaled_config(&dir, 1 << 20), &sock);
    let lease = post::<PickResponse>(&sock, paths::PICK, TASK)
        .lease_id
        .unwrap();
    let before = state(&sock);
    let release = format!(r#"{{"lease_id":"{lease}","outcome":"usage_limit","release":true}}"#);

    let (status, resp) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(release.as_bytes()),
        Some(BEARER),
    )
    .unwrap();
    assert_eq!(status, 403);
    assert_eq!(error_of(&resp), ErrorCode::Forbidden);
    let after = state(&sock);
    assert_eq!(
        durable(&after),
        durable(&before),
        "the lease and marks are unchanged"
    );

    let r: ReportResponse = post(&sock, paths::REPORT, &release);
    assert_eq!(r.login_status, LoginStatus::Exhausted);
    assert_eq!(lease_clients(&sock), Vec::<(String, String)>::new());

    let by_login = r#"{"login":"login-2","outcome":"ok"}"#;
    let (status, _) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(by_login.as_bytes()),
        Some(BEARER),
    )
    .unwrap();
    assert_eq!(status, 200, "login reports are open to every client");
}

#[test]
fn each_client_has_a_token_bucket() {
    let dir = temp_dir("bucket");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[
            client_uid("client-a", own_uid()),
            client_uid("agent-1", foreign_uid(0)),
            ("rate_per_s = 5.0", "rate_per_s = 0.5".to_owned()),
            ("burst = 20", "burst = 3".to_owned()),
        ],
    );
    let _d = start(&config, &sock);
    for _ in 0..5 {
        let (status, _) = call(&sock, "GET", paths::STATE, None, Some("token-x")).unwrap();
        assert_eq!(status, 401);
    }
    let started = Instant::now();
    for i in 0..3 {
        let (status, _) = call(&sock, "GET", paths::STATE, None, None).unwrap();
        assert_eq!(status, 200, "request {i} fits the burst after the 401s");
    }
    let (status, resp) = call(&sock, "GET", paths::STATE, None, None).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "too slow to test the burst"
    );
    assert_eq!(status, 429);
    assert_eq!(error_of(&resp), ErrorCode::TooManyRequests);
}

/// Runs the `qb` binary on `sock` with `args` and returns its output.
fn qb(sock: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qb"))
        .env_remove("QB_BEARER_FILE")
        .arg("--socket")
        .arg(sock)
        .args(args)
        .output()
        .unwrap()
}

fn why(sock: &Path, lease: &str) -> (u16, Vec<u8>) {
    call(sock, "GET", &format!("{}{lease}", paths::WHY), None, None).unwrap()
}

#[test]
fn why_explains_a_live_lease_across_a_restart() {
    let dir = temp_dir("why");
    let config = journaled_config(&dir, 1 << 20);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let task = r#"{"role":"worker","difficulty":1,"expected_minutes":30,"run_id":"run-1"}"#;
    let p: PickResponse = post(&sock, paths::PICK, task);
    let lease = p.lease_id.clone().unwrap();

    let out = qb(&sock, &["why", &lease]);
    assert!(out.status.success(), "{out:?}");
    let w: WhyResponse = serde_json::from_slice(&out.stdout).unwrap();
    let s = state(&sock);
    let held = &s.leases[0];
    assert_eq!(
        (
            &w.lease_id,
            &w.login,
            &w.model,
            &w.client,
            &w.run_id,
            w.expires_at
        ),
        (
            &held.lease_id,
            &held.login,
            &held.model,
            &held.client,
            &held.run_id,
            held.expires_at
        )
    );
    assert_eq!(w.reason.as_deref(), Some(p.reason.as_str()));
    assert_eq!(&w.login_state, &s.logins[0]);
    let cost: Vec<(&str, f64)> = w.cost.iter().map(|c| (c.name.as_str(), c.cost)).collect();
    let reserved: Vec<(&str, f64)> = s.logins[0]
        .windows
        .iter()
        .map(|w| (w.name.as_str(), w.reserved))
        .collect();
    assert_eq!(cost, reserved);

    let (status, resp) = why(&sock, "l-999999");
    assert_eq!(status, 404);
    assert_eq!(error_of(&resp), ErrorCode::NotFound);
    assert_eq!(qb(&sock, &["why", "l-999999"]).status.code(), Some(1));
    let ended: PickResponse = post(&sock, paths::PICK, task);
    let ended = ended.lease_id.unwrap();
    let _: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{ended}","outcome":"ok","release":true}}"#),
    );
    assert_eq!(why(&sock, &ended).0, 404, "a released lease is gone");
    drop(d);

    let _d = start(&config, &sock);
    let (status, body) = why(&sock, &lease);
    assert_eq!(status, 200);
    let again: WhyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(again.reason, w.reason, "the journal keeps the reason");
}

#[test]
fn a_lease_line_without_reason_replays() {
    let dir = temp_dir("oldline");
    let config = journaled_config(&dir, 1 << 20);
    std::fs::write(
        dir.join("journal"),
        format!("{}\n", lease_line(257, qb::server::unix_now())),
    )
    .unwrap();
    let sock = dir.join("qb.sock");
    let _d = start(&config, &sock);
    let (status, body) = why(&sock, "l-257");
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let w: WhyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!((w.login.as_str(), w.reason), ("login-1", None));
    assert_eq!(state(&sock).leases[0].on_behalf_of, None);
}

#[test]
fn on_behalf_of_stays_on_the_lease_in_state_the_journal_and_a_restart() {
    let dir = temp_dir("behalf");
    let config = journaled_config(&dir, 1 << 20);
    let sock = dir.join("qb.sock");
    let d = start(&config, &sock);
    let task =
        r#"{"role":"worker","difficulty":1,"expected_minutes":30,"on_behalf_of":"client-x"}"#;
    let p: PickResponse = post(&sock, paths::PICK, task);
    assert_eq!(p.decision, Decision::Run, "{p:?}");
    let held = |sock: &Path| {
        let l = state(sock).leases.remove(0);
        (l.lease_id, l.client, l.on_behalf_of)
    };
    let before = held(&sock);
    assert_eq!(
        before,
        (
            p.lease_id.clone().unwrap(),
            "client-a".to_owned(),
            Some("client-x".to_owned())
        )
    );
    let journal = std::fs::read_to_string(dir.join("journal")).unwrap();
    let lease: serde_json::Value = serde_json::from_str(journal.lines().last().unwrap()).unwrap();
    assert_eq!(lease["lease"]["on_behalf_of"], "client-x", "{journal}");
    drop(d);

    let _d = start(&config, &sock);
    assert_eq!(held(&sock), before);
    let (status, body) = why(&sock, &before.0);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let w: WhyResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(w.on_behalf_of.as_deref(), Some("client-x"));
}

fn rate_limit_line(status: &str, five_hour: f64, seven_day: f64, now: u64) -> String {
    format!(
        r#"{{"type":"rate_limit_event","rate_limit_info":{{"status":"{status}","unifiedWindows":{{"five_hour":{{"utilization":{five_hour},"resetsAt":{}}},"seven_day":{{"utilization":{seven_day},"resetsAt":{}}}}}}}}}"#,
        now + 7200,
        now + 6 * 86_400
    )
}

#[test]
fn report_from_stream_json_posts_the_last_rate_limit_event() {
    let dir = temp_dir("stream");
    let sock = dir.join("qb.sock");
    let _d = start(&journaled_config(&dir, 1 << 20), &sock);
    let now = qb::server::unix_now();
    let log = dir.join("run.jsonl");
    std::fs::write(
        &log,
        [
            r#"{"type":"system","subtype":"init"}"#.to_owned(),
            "not json".to_owned(),
            rate_limit_line("allowed", 0.3, 0.2, now),
            r#"{"type":"assistant","message":{}}"#.to_owned(),
            rate_limit_line("rejected", 1.0, 0.5, now),
            r#"{"type":"result","subtype":"success"}"#.to_owned(),
        ]
        .join("\n"),
    )
    .unwrap();

    let log_arg = log.to_str().unwrap();
    let out = qb(
        &sock,
        &[
            "report",
            "--login",
            "login-1",
            "--from-stream-json",
            log_arg,
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let r: ReportResponse = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r.login_status, LoginStatus::Exhausted);
    let s = state(&sock);
    assert_eq!(s.logins[0].status, LoginStatus::Exhausted);
    let windows: Vec<(&str, f64, Option<u64>, Source)> = s.logins[0]
        .windows
        .iter()
        .map(|w| (w.name.as_str(), w.used, w.resets_at, w.source))
        .collect();
    assert_eq!(
        windows,
        [
            ("five_hour", 1.0, Some(now + 7200), Source::Stream),
            ("seven_day", 0.5, Some(now + 6 * 86_400), Source::Stream),
        ]
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_qb"))
        .env_remove("QB_BEARER_FILE")
        .arg("--socket")
        .arg(&sock)
        .args(["report", "--login", "login-2", "--from-stream-json", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"type\":\"system\"}\nnot json\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no rate_limit_event"),
        "{out:?}"
    );
    let login2 = &state(&sock).logins[1];
    assert_eq!(login2.status, LoginStatus::Unknown);
    assert!(
        login2.windows.iter().all(|w| w.observed_at == 0),
        "{login2:?}"
    );
}

/// Every file of `dir` with its bytes, sorted by name.
fn contents(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().into_string().unwrap(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

fn simulate(config: &Path, journal: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qb"))
        .arg("simulate")
        .arg("--config")
        .arg(config)
        .arg(journal)
        .args(extra)
        .output()
        .unwrap()
}

/// The JSON documents of a `simulate` output, one per line.
fn documents(out: &std::process::Output) -> Vec<serde_json::Value> {
    assert!(out.status.success(), "{out:?}");
    out.stdout
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect()
}

#[test]
fn simulate_replays_a_daemon_journal_without_writing() {
    let dir = temp_dir("sim");
    let config = journaled_config(&dir, 1 << 20);
    let sock = temp_socket("simsock");
    let d = start(&config, &sock);
    mark_and_lease(&sock);
    let live = state(&sock);
    drop(d);
    let journal = dir.join("journal");
    let before = contents(&dir);

    let docs = documents(&simulate(&config, &journal, &[]));
    assert_eq!(docs.len(), 1);
    let simulated: StateResponse = serde_json::from_value(docs[0].clone()).unwrap();
    assert_eq!(simulated.leases, live.leases);
    assert_eq!(durable(&simulated), durable(&live));

    let task = ["--pick", r#"{"role":"worker","difficulty":1}"#];
    let docs = documents(&simulate(&config, &journal, &task));
    let recorded: PickResponse = serde_json::from_value(docs[1].clone()).unwrap();
    assert_eq!(
        (recorded.login.as_deref(), recorded.model.as_deref()),
        (Some("login-2"), Some("model-small"))
    );
    let changed = config_copy(
        &temp_dir("simcfg"),
        &[(
            r#"{ vendor = "vendor-a", model = "model-small", effort = "low", tier = 1 }"#,
            r#"{ vendor = "vendor-a", model = "model-tiny", tier = 1 }"#.to_owned(),
        )],
    );
    let docs = documents(&simulate(&changed, &journal, &task));
    let tried: PickResponse = serde_json::from_value(docs[1].clone()).unwrap();
    assert_eq!(tried.decision, Decision::Run, "{tried:?}");
    assert_eq!(
        (tried.login.as_deref(), tried.model.as_deref(), tried.effort),
        (Some("login-2"), Some("model-tiny"), None)
    );
    assert_eq!(contents(&dir), before, "the journal directory is untouched");
}

#[test]
fn simulate_stops_on_a_corrupt_middle_line() {
    let dir = temp_dir("simbad");
    let config = journaled_config(&dir, 1 << 20);
    let journal = dir.join("journal");
    let now = qb::server::unix_now();
    let text = format!(
        "{}\nnot json\n{}\n",
        lease_line(257, now),
        lease_line(513, now)
    );
    std::fs::write(&journal, text).unwrap();
    let out = simulate(&config, &journal, &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!("{}: line 2: ", journal.display())),
        "{stderr}"
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn a_bearer_file_names_the_caller() {
    let dir = temp_dir("bearerfile");
    let sock = dir.join("qb.sock");
    let _d = start(&journaled_config(&dir, 1 << 20), &sock);
    let (good, wrong, empty) = (dir.join("good"), dir.join("wrong"), dir.join("empty"));
    std::fs::write(&good, format!("{BEARER}\n")).unwrap();
    std::fs::write(&wrong, "token-x\n").unwrap();
    std::fs::write(&empty, " \n").unwrap();

    let out = qb(
        &sock,
        &[
            "--bearer-file",
            good.to_str().unwrap(),
            "pick",
            "--role",
            "worker",
            "--difficulty",
            "1",
        ],
    );
    assert!(out.status.success(), "{out:?}");
    let p: PickResponse = serde_json::from_slice(&out.stdout).unwrap();
    let lease = p.lease_id.unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_qb"))
        .env("QB_BEARER_FILE", &good)
        .arg("--socket")
        .arg(&sock)
        .args(["why", &lease])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let w: WhyResponse = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(w.client, "client-b");

    let out = qb(&sock, &["--bearer-file", wrong.to_str().unwrap(), "state"]);
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    assert_eq!(error_of(&out.stdout), ErrorCode::Unauthorized);
    let out = qb(&sock, &["--bearer-file", empty.to_str().unwrap(), "state"]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
}

#[test]
fn an_invalid_agent_config_exits_2_naming_the_field() {
    let dir = temp_dir("agentcfg");
    let file = dir.join("agent.toml");
    std::fs::write(
        &file,
        "[[logins]]\nname = \"login-1\"\nkind = \"vendor-x\"\ncredentials = \"c\"\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_qb"))
        .arg("--socket")
        .arg(dir.join("qb.sock"))
        .args(["agent", "--config"])
        .arg(&file)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(&format!("{}: logins[0].kind", file.display())),
        "{stderr}"
    );
}

/// Bearer tokens of the extra agent clients `bot-1`..`bot-3` and their SHA-256.
const BOTS: [(&str, &str); 3] = [
    (
        "token-1",
        "3f08aace122ee2368432c1ca23a049bc640bafbf00fdf33a52429f38ba12dbf9",
    ),
    (
        "token-2",
        "0f6bffa9661cb5dd2f3f7b2929f33061f58a7ba7fdd689530b1a306f8ed8f3ec",
    ),
    (
        "token-3",
        "a2f2b0b588bcc84fbf4d2ac8cc086b6f84de3e00fa3c1ba11e38ac078eb03192",
    ),
];

/// `qbd.toml` with the agent client `agent-1` on this process's uid, `client-a` on a foreign uid,
/// `client-b` on [`BEARER`], limits no test reaches, and `edits` applied.
fn agent_config(dir: &Path, edits: &[(&str, String)]) -> PathBuf {
    let mut all = vec![
        client_uid("client-a", foreign_uid(0)),
        client_uid("agent-1", own_uid()),
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            BEARER_SHA256.to_owned(),
        ),
        ("rate_per_s = 5.0", "rate_per_s = 1000.0".to_owned()),
        ("burst = 20", "burst = 1000".to_owned()),
    ];
    all.extend(edits.iter().cloned());
    config_copy(dir, &all)
}

const PROBE_ON: (&str, &str) = ("enabled = false", "enabled = true");

fn probe_on() -> (&'static str, String) {
    (PROBE_ON.0, PROBE_ON.1.to_owned())
}

fn next_now(sock: &Path, bearer: Option<&str>, logins: &[&str]) -> (u16, Vec<u8>) {
    let body = serde_json::json!({ "logins": logins }).to_string();
    call(
        sock,
        "POST",
        paths::AGENT_NEXT,
        Some(body.as_bytes()),
        bearer,
    )
    .unwrap()
}

fn result(sock: &Path, bearer: Option<&str>, body: &str) -> (u16, Vec<u8>) {
    call(
        sock,
        "POST",
        paths::AGENT_RESULT,
        Some(body.as_bytes()),
        bearer,
    )
    .unwrap()
}

/// `(name, used, resets_at, source)` of each window of `login`.
fn windows_of(sock: &Path, login: &str) -> Vec<(String, f64, Option<u64>, Source)> {
    state(sock)
        .logins
        .into_iter()
        .find(|l| l.login == login)
        .unwrap()
        .windows
        .into_iter()
        .map(|w| (w.name, w.used, w.resets_at, w.source))
        .collect()
}

/// Claude `oauth/usage` body with resets in 2099 (Unix 4070908800 and 4071513600).
const CLAUDE_USAGE: &str = r#"{"five_hour":{"utilization":6.0,"resets_at":"2099-01-01T00:00:00Z"},"seven_day":{"utilization":35.0,"resets_at":"2099-01-08T00:00:00Z"},"seven_day_opus":{"utilization":50.0,"resets_at":"2099-01-08T00:00:00Z"}}"#;

fn probed_windows() -> Vec<(String, f64, Option<u64>, Source)> {
    vec![
        ("five_hour".into(), 0.06, Some(4_070_908_800), Source::Probe),
        ("seven_day".into(), 0.35, Some(4_071_513_600), Source::Probe),
    ]
}

/// A fetcher that reports each login it is asked for on `calls`, then waits for `release` when
/// given, and answers 200 with [`CLAUDE_USAGE`].
struct TestFetcher {
    calls: Sender<String>,
    release: Option<Arc<Mutex<Receiver<()>>>>,
}

impl Fetcher for TestFetcher {
    fn fetch(&mut self, login: &str, kind: Kind, _: &Path) -> Result<Fetched, String> {
        assert_eq!(kind, Kind::Claude);
        let _ = self.calls.send(login.to_owned());
        if let Some(release) = &self.release {
            let _ = release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10));
        }
        Ok(Fetched {
            status: 200,
            retry_after_s: None,
            body: CLAUDE_USAGE.as_bytes().to_vec(),
        })
    }
}

/// Runs `qb agent` in this process for `login-1` until the test binary exits.
fn spawn_agent(sock: &Path, bearer: Option<&'static str>, fetcher: TestFetcher) {
    let config = qb::config::parse_agent(
        Path::new("agent.toml"),
        "[[logins]]\nname = \"login-1\"\nkind = \"claude\"\ncredentials = \"unused\"\n",
    )
    .unwrap();
    let sock = sock.to_owned();
    let mut fetcher = fetcher;
    std::thread::spawn(move || qb::agent::run(&sock, bearer, &config, &mut fetcher));
}

#[test]
fn with_probes_off_a_parked_agent_gets_no_job_and_others_are_served() {
    let dir = temp_dir("probeoff");
    let sock = dir.join("qb.sock");
    let config = agent_config(
        &dir,
        &[(
            "agents = [\"agent-1\"]",
            "agents = [\"agent-1\", \"client-b\"]".to_owned(),
        )],
    );
    let _d = start(&config, &sock);
    let logins = ["login-1", "login-2", "login-3"];
    let mut parked = park(&sock, None, &logins);
    for _ in 0..3 {
        let p = pick_worker(&sock);
        assert_eq!(p.decision, Decision::Run, "{p:?}");
        assert!(p.stale, "the pick relied on a stale login");
        assert_eq!(state(&sock).logins.len(), 7);
    }
    // A `next` gets a due job before the daemon accepts the next connection, so once `state`
    // has answered, a job for `late` would already be in its socket.
    let mut late = park(&sock, Some(BEARER), &logins);
    assert_eq!(state(&sock).logins.len(), 7);
    assert_eq!(answer(&mut late, Duration::from_millis(10)), None);
    assert_eq!(answer(&mut parked, Duration::from_millis(10)), None);
}

#[test]
fn a_pick_on_a_stale_login_sends_one_probe_whose_windows_show_in_state() {
    let dir = temp_dir("probe");
    let sock = dir.join("qb.sock");
    let config = agent_config(
        &dir,
        &[
            probe_on(),
            (
                "agents = [\"agent-1\"]",
                "agents = [\"agent-1\", \"client-b\"]".to_owned(),
            ),
        ],
    );
    let _d = start(&config, &sock);
    let (calls, called) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Arc::new(Mutex::new(released));
    for bearer in [None, Some(BEARER)] {
        let fetcher = TestFetcher {
            calls: calls.clone(),
            release: Some(Arc::clone(&released)),
        };
        spawn_agent(&sock, bearer, fetcher);
    }

    assert!(pick_worker(&sock).stale);
    let login = called.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(login, "login-1");
    assert!(pick_worker(&sock).stale, "the probe has not answered yet");
    // Singleflight itself is a table test in qb-core; here no second job may have reached the
    // other agent by the time the daemon answers again, without waiting for its absence.
    state(&sock);
    assert_eq!(
        called.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "no second job while one is in flight"
    );

    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while windows_of(&sock, "login-1") != probed_windows() {
        assert!(
            Instant::now() < deadline,
            "{:?}",
            windows_of(&sock, "login-1")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let s = state(&sock);
    assert_eq!(s.logins[0].status, LoginStatus::Ok);
    assert!(s.logins[0].windows.iter().all(|w| !w.stale));
    assert_eq!(
        called.try_recv(),
        Err(mpsc::TryRecvError::Empty),
        "exactly one job"
    );
}

#[test]
fn only_declared_agents_may_wait_for_jobs() {
    let dir = temp_dir("notagent");
    let sock = dir.join("qb.sock");
    let _d = start(&agent_config(&dir, &[probe_on()]), &sock);
    let (status, resp) = next_now(&sock, Some(BEARER), &["login-1"]);
    assert_eq!(status, 403);
    assert_eq!(error_of(&resp), ErrorCode::Forbidden);
    for logins in [&["login-9"][..], &[]] {
        let (status, resp) = next_now(&sock, None, logins);
        assert_eq!(status, 400, "{logins:?}");
        assert_eq!(error_of(&resp), ErrorCode::BadRequest);
    }
}

#[test]
fn stale_and_foreign_probe_results_change_nothing() {
    let dir = temp_dir("probeids");
    let sock = dir.join("qb.sock");
    let _d = start(&agent_config(&dir, &[probe_on()]), &sock);
    pick_worker(&sock);
    let (status, resp) = next_now(&sock, None, &["login-1"]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let job: AgentJob = serde_json::from_slice(&resp).unwrap();
    assert_eq!(job.login, "login-1");

    let ok = |id: &str| {
        format!(
            r#"{{"probe_id":"{id}","outcome":"ok","windows":[{{"name":"five_hour","utilization":0.5}}]}}"#
        )
    };
    let before = state(&sock).logins;
    for (bearer, id, status, code) in [
        (None, "p-999", 404, ErrorCode::NotFound),
        (None, "l-1", 404, ErrorCode::NotFound),
        (
            Some(BEARER),
            job.probe_id.as_str(),
            403,
            ErrorCode::Forbidden,
        ),
    ] {
        let (got, resp) = result(&sock, bearer, &ok(id));
        assert_eq!((got, error_of(&resp)), (status, code), "{id}");
        assert_eq!(state(&sock).logins, before, "{id}");
    }
    let (status, resp) = result(&sock, None, &ok(&job.probe_id));
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let w = &windows_of(&sock, "login-1")[0];
    assert_eq!((w.1, w.3), (0.5, Source::Probe));
    let (status, _) = result(&sock, None, &ok(&job.probe_id));
    assert_eq!(status, 404, "an answered probe is gone");
}

#[test]
fn a_failed_probe_result_is_logged_with_its_login_and_outcome() {
    let dir = temp_dir("probelog");
    let sock = dir.join("qb.sock");
    let mut d = start_with(&agent_config(&dir, &[probe_on()]), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    pick_worker(&sock);
    let (status, resp) = next_now(&sock, None, &["login-1"]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let job: AgentJob = serde_json::from_slice(&resp).unwrap();
    let body = format!(
        r#"{{"probe_id":"{}","outcome":"http_429","retry_after_s":120}}"#,
        job.probe_id
    );
    let (status, resp) = result(&sock, None, &body);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let line = line_with(&lines, "probe of login-1 by ", Duration::from_secs(10));
    let line = line.expect("a warning about the failed probe");
    assert!(line.starts_with("<4>"), "{line}");
    assert!(
        line.ends_with("failed: http_429, retry after 120 s"),
        "{line}"
    );
}

fn status_of(sock: &Path, login: &str) -> LoginStatus {
    state(sock)
        .logins
        .into_iter()
        .find(|l| l.login == login)
        .unwrap()
        .status
}

#[test]
fn auth_recovered_by_a_probe_survives_a_restart() {
    let dir = temp_dir("probeauth");
    let sock = dir.join("qb.sock");
    let config = agent_config(&dir, &[probe_on()]);
    let d = start(&config, &sock);
    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        r#"{"login":"login-1","outcome":"http_401"}"#,
    );
    assert_eq!(r.login_status, LoginStatus::AuthStale);
    pick_worker(&sock);
    let (status, resp) = next_now(&sock, None, &["login-1"]);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let job: AgentJob = serde_json::from_slice(&resp).unwrap();
    let ok = format!(
        r#"{{"probe_id":"{}","outcome":"ok","windows":[{{"name":"five_hour","utilization":0.5}}]}}"#,
        job.probe_id
    );
    let (status, resp) = result(&sock, None, &ok);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    assert_eq!(status_of(&sock, "login-1"), LoginStatus::Ok);

    drop(d);
    let _d = start(&config, &sock);
    // Windows are not journaled, so without an auth mark the replayed login is `unknown`.
    assert_eq!(status_of(&sock, "login-1"), LoginStatus::Unknown);
    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        r#"{"login":"login-1","outcome":"http_401"}"#,
    );
    assert_eq!(
        r.login_status,
        LoginStatus::AuthStale,
        "one 401 after recovery"
    );
}

/// Parks the agent behind `bearer` once the daemon has seen a closed parked connection and
/// freed its place; each refused attempt is answered 429 and retried, for at most 10 s.
fn park_when_free(sock: &Path, bearer: &str, logins: &[&str]) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut s = park(sock, Some(bearer), logins);
        // Connections are accepted and answered in order, so once a later request is answered
        // the park was decided and a refusal is already readable.
        state(sock);
        match answer(&mut s, Duration::from_millis(10)) {
            None => return s,
            Some((status, resp)) => {
                assert_eq!(status, 429, "{}", String::from_utf8_lossy(&resp));
                assert!(
                    Instant::now() < deadline,
                    "the closed connection kept its place"
                );
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn parked_connections_are_bounded_per_agent_and_in_total() {
    let dir = temp_dir("parkcap");
    let sock = dir.join("qb.sock");
    let mut edits = vec![(
        "agents = [\"agent-1\"]",
        "agents = [\"agent-1\", \"client-b\", \"bot-1\", \"bot-2\", \"bot-3\"]".to_owned(),
    )];
    let bots = BOTS
        .iter()
        .enumerate()
        .fold(String::new(), |mut out, (i, (_, hash))| {
            let _ = write!(
                out,
                "\n[[clients]]\nname = \"bot-{}\"\nbearer_sha256 = \"{hash}\"\nrole = \"worker\"\n",
                i + 1
            );
            out
        });
    edits.push((
        "role = \"reviewer\"\n",
        format!("role = \"reviewer\"\n{bots}"),
    ));
    let _d = start(&agent_config(&dir, &edits), &sock);
    let logins = ["login-1"];

    let mut waiting = vec![park(&sock, None, &logins)];
    let (status, resp) = next_now(&sock, None, &logins);
    assert_eq!(status, 429, "one parked connection per agent");
    assert_eq!(error_of(&resp), ErrorCode::TooManyRequests);
    waiting.push(park(&sock, Some(BEARER), &logins));
    waiting.push(park(&sock, Some(BOTS[0].0), &logins));
    waiting.push(park(&sock, Some(BOTS[1].0), &logins));
    let (status, resp) = next_now(&sock, Some(BOTS[2].0), &logins);
    assert_eq!(status, 429, "at most 4 parked in total");
    assert_eq!(error_of(&resp), ErrorCode::TooManyRequests);
    assert_eq!(state(&sock).logins.len(), 7, "others are still served");

    drop(waiting.pop());
    let _last = park_when_free(&sock, BOTS[2].0, &logins);
    for mut w in waiting {
        assert_eq!(answer(&mut w, Duration::from_millis(10)), None);
    }
}

#[test]
fn an_agent_reconnects_after_a_daemon_restart() {
    let dir = temp_dir("agentre");
    let sock = dir.join("qb.sock");
    let config = agent_config(&dir, &[probe_on()]);
    let d = start(&config, &sock);
    let (calls, called) = mpsc::channel();
    spawn_agent(
        &sock,
        None,
        TestFetcher {
            calls,
            release: None,
        },
    );
    pick_worker(&sock);
    assert_eq!(
        called.recv_timeout(Duration::from_secs(10)).unwrap(),
        "login-1"
    );
    drop(d);
    let _d = start(&config, &sock);
    assert!(pick_worker(&sock).stale, "snapshots are not persisted");
    assert_eq!(
        called.recv_timeout(Duration::from_secs(15)).unwrap(),
        "login-1"
    );
}

#[test]
fn hooks_run_once_per_auth_dead_edge_and_never_on_replay() {
    let dir = temp_dir("hooks");
    let sock = dir.join("qb.sock");
    let config = hook_config(journaled_config(&dir, 1 << 20), &record_event(&dir));
    let d = start(&config, &sock);
    kill_auth(&sock, "login-1");
    assert_eq!(events(&dir, 1), ["dead login-1 vendor-a"]);

    assert_eq!(
        report_login(&sock, "login-1", "http_401"),
        LoginStatus::AuthDead
    );
    let changed_while_dead = report_login(&sock, "login-1", "model_unavailable");
    assert_eq!(changed_while_dead, LoginStatus::AuthDead);
    let resets = state(&sock).now + 3600;
    report_windows(&sock, "login-1", &[("five_hour", 0.5, resets)]);
    assert_eq!(status_of(&sock, "login-1"), LoginStatus::Ok);
    assert_eq!(
        events(&dir, 2),
        ["dead login-1 vendor-a", "recover login-1 vendor-a"],
        "a repeated dead state runs nothing"
    );

    kill_auth(&sock, "login-1");
    assert_eq!(events(&dir, 3)[2], "dead login-1 vendor-a");
    drop(d);
    let _d = start(&config, &sock);
    assert_eq!(status_of(&sock, "login-1"), LoginStatus::AuthDead);
    kill_auth(&sock, "login-3");
    assert_eq!(
        events(&dir, 4),
        [
            "dead login-1 vendor-a",
            "recover login-1 vendor-a",
            "dead login-1 vendor-a",
            "dead login-3 vendor-b"
        ],
        "replaying the journal runs nothing"
    );
}

#[test]
fn a_hook_beyond_two_in_flight_is_dropped_with_a_warning() {
    let dir = temp_dir("hookcap");
    let sock = dir.join("qb.sock");
    let fifo = dir.join("gate");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    // Open for reading and writing: hooks open the FIFO at once and read until this closes.
    let gate = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fifo)
        .unwrap();
    let script = format!(
        "exec 3< '{}'\n{}cat <&3 >/dev/null\n",
        fifo.display(),
        record_event(&dir)
    );
    let config = hook_config(journaled_config(&dir, 1 << 20), &script);
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    kill_auth(&sock, "login-1");
    kill_auth(&sock, "login-2");
    let mut running = events(&dir, 2);
    running.sort();
    assert_eq!(running, ["dead login-1 vendor-a", "dead login-2 vendor-a"]);

    kill_auth(&sock, "login-3");
    let warning = line_with(&lines, "hook dead of login-3", Duration::from_secs(10));
    let warning = warning.expect("a warning about the dropped hook");
    assert!(warning.contains("dropped"), "{warning}");
    let (status, _) = call(&sock, "GET", paths::HEALTH, None, None).unwrap();
    assert_eq!(status, 200);
    assert_eq!(events(&dir, 2).len(), 2, "the dropped hook never ran");
    drop(gate);
}

/// Stands in for a token in credential files; it must never reach a log.
const CREDENTIAL_MARK: &str = "synthetic-token-5c1e";

#[test]
fn a_hardened_agent_binary_reports_a_malformed_credential_file_as_a_failed_probe() {
    let dir = temp_dir("agentbin");
    let sock = dir.join("qb.sock");
    let _d = start(&agent_config(&dir, &[probe_on()]), &sock);
    std::fs::create_dir_all(dir.join("creds")).unwrap();
    let credentials = dir.join("creds/.credentials.json");
    std::fs::write(
        &credentials,
        format!(r#"{{"claudeAiOauth":{{"accessToken":"{CREDENTIAL_MARK}"#),
    )
    .unwrap();
    std::fs::write(
        dir.join("agent.toml"),
        "[[logins]]\nname = \"login-1\"\nkind = \"claude\"\n\
         credentials = \"creds/.credentials.json\"\n",
    )
    .unwrap();
    let mut agent = Daemon(
        Command::new(env!("CARGO_BIN_EXE_qb"))
            .arg("--socket")
            .arg(&sock)
            .args(["agent", "--config", "agent.toml"])
            .current_dir(&dir)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let lines = stderr_lines(&mut agent.0);
    let failure = "probe of login-1: creds/.credentials.json: not valid JSON";

    assert!(pick_worker(&sock).stale);
    let first = line_with(&lines, "probe of login-1", Duration::from_secs(10));
    let first = first.expect("the agent took the job");
    assert!(first.contains(failure), "{first}");
    assert!(!first.contains(CREDENTIAL_MARK), "{first}");
    let status = std::fs::metadata(format!("/proc/{}/status", agent.0.id())).unwrap();
    assert_eq!(
        status.uid(),
        0,
        "a non-dumpable process's /proc files belong to root"
    );

    let s = state(&sock);
    assert_eq!(s.logins[0].login, "login-1");
    assert_eq!(s.logins[0].status, LoginStatus::Unknown);
    assert!(
        s.logins[0]
            .windows
            .iter()
            .all(|w| w.stale && w.source != Source::Probe)
    );
}

/// Runs one `clients/python/qb_client.py` call through its contract driver and returns the
/// driver's JSON line. `-I -S` keeps site-packages and the environment off `sys.path`, so a
/// client import outside the stdlib fails every test that goes through here.
fn py_client(
    sock: &Path,
    bearer: Option<&str>,
    timeout: f64,
    op: &str,
    request: Option<&str>,
) -> serde_json::Value {
    let driver =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../clients/python/contract_driver.py");
    let out = Command::new("python3")
        .args(["-I", "-S"])
        .arg(driver)
        .arg(sock)
        .arg(bearer.unwrap_or(""))
        .arg(timeout.to_string())
        .arg(op)
        .args(request)
        .output()
        .unwrap_or_else(|e| {
            panic!("the Python client tests need python3 (3.9+) on PATH, running it failed: {e}")
        });
    assert!(
        out.status.success(),
        "python3 driver {op} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn python_client_picks_reports_and_sends_its_bearer() {
    let dir = temp_dir("py");
    let sock = dir.join("qb.sock");
    let _d = start(&journaled_config(&dir, 1 << 20), &sock);

    let picked = &py_client(&sock, None, 2.0, "pick", Some(TASK))["result"];
    assert_eq!(picked["decision"], "run", "{picked}");
    assert!(picked.get("fallback").is_none(), "{picked}");
    let lease = picked["lease_id"].as_str().unwrap();
    let report = format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#);
    let reported = py_client(&sock, None, 2.0, "report", Some(&report));
    assert_eq!(reported["result"]["accepted"], true, "{reported}");

    let by_bearer = py_client(&sock, Some(BEARER), 2.0, "pick", Some(TASK));
    let lease = by_bearer["result"]["lease_id"].as_str().unwrap();
    let s = py_client(&sock, Some(BEARER), 2.0, "state", None);
    let leases = s["result"]["leases"].as_array().unwrap();
    assert_eq!(leases.len(), 1, "{s}");
    assert_eq!(leases[0]["lease_id"], lease);
    assert_eq!(leases[0]["client"], "client-b");
    let h = py_client(&sock, None, 2.0, "health", None);
    assert_eq!(h["result"]["status"], "ok", "{h}");
}

#[test]
fn python_client_falls_back_when_qbd_is_unreachable() {
    let dir = temp_dir("pyoff");
    let missing = dir.join("missing.sock");
    let refused = dir.join("refused.sock");
    drop(UnixListener::bind(&refused).unwrap());
    let silent = dir.join("silent.sock");
    let listener = UnixListener::bind(&silent).unwrap();
    std::thread::spawn(move || {
        let held: Vec<_> = listener.incoming().collect();
        drop(held);
    });

    let local = serde_json::json!({
        "decision": "run", "login": "local-login", "role": "worker", "fallback": true,
    });
    for sock in [&missing, &refused, &silent] {
        let picked = py_client(sock, None, 0.3, "pick", Some(TASK));
        assert_eq!(picked["result"], local, "{}", sock.display());
        let reported = py_client(
            sock,
            None,
            0.3,
            "report",
            Some(r#"{"login":"login-1","outcome":"ok"}"#),
        );
        assert_eq!(
            reported,
            serde_json::json!({ "result": null }),
            "{}",
            sock.display()
        );
    }
}

#[test]
fn python_client_raises_http_errors_instead_of_falling_back() {
    let dir = temp_dir("pyerr");
    let sock = dir.join("qb.sock");
    let d = start(&journaled_config(&dir, 1 << 20), &sock);
    let unknown = py_client(
        &sock,
        None,
        2.0,
        "report",
        Some(r#"{"login":"login-9","outcome":"ok"}"#),
    );
    assert_eq!(unknown["qb_error"]["status"], 404, "{unknown}");
    assert_eq!(unknown["qb_error"]["error"], "not_found");
    drop(d);

    let dir = temp_dir("pyerr");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[
            client_uid("client-a", foreign_uid(0)),
            client_uid("agent-1", foreign_uid(1)),
        ],
    );
    let _d = start(&config, &sock);
    let stranger = py_client(&sock, None, 2.0, "pick", Some(TASK));
    assert_eq!(stranger["qb_error"]["status"], 401, "{stranger}");
    assert_eq!(stranger["qb_error"]["error"], "unauthorized");
    assert!(stranger.get("result").is_none(), "{stranger}");
}

/// `qbd.toml` in `dir` with its roles in `dir/roles.toml`: `login-1` on vendor-a with a
/// five-hour window, `login-2` on vendor-b, `client-a` on this process's uid, no journal, and
/// `extra` appended.
fn reloadable(dir: &Path, extra: &str) -> PathBuf {
    let text = format!(
        "roles_file = \"{roles}\"\n\
         [journal]\nmode = \"off\"\n\
         [limits]\nrate_per_s = 1000.0\nburst = 1000\n\
         [[vendors]]\nname = \"vendor-a\"\n\
         windows = [{{ name = \"five_hour\", length_s = 18000, t_burn_s = 1800 }}]\n\
         [[vendors]]\nname = \"vendor-b\"\nwindows = []\n\
         [[logins]]\nname = \"login-1\"\nvendor = \"vendor-a\"\n\
         [[logins]]\nname = \"login-2\"\nvendor = \"vendor-b\"\n\
         [[clients]]\nname = \"client-a\"\nuid = {uid}\nrole = \"worker\"\n\
         {extra}\n",
        roles = dir.join("roles.toml").display(),
        uid = own_uid(),
    );
    let file = dir.join("qbd.toml");
    std::fs::write(&file, text).unwrap();
    file
}

/// Writes `dir/roles.toml` with one role per `(name, vendor, model)`, each a single difficulty-1
/// step.
fn write_roles(dir: &Path, roles: &[(&str, &str, &str)]) {
    let text = roles
        .iter()
        .fold(String::new(), |mut t, (name, vendor, model)| {
            let _ = write!(
                t,
                "[[roles]]\nname = \"{name}\"\nladder = [{{ difficulty = 1, candidates = \
             [{{ vendor = \"{vendor}\", model = \"{model}\", tier = 1 }}] }}]\n"
            );
            t
        });
    std::fs::write(dir.join("roles.toml"), text).unwrap();
}

/// Sends SIGHUP to `d` and returns the reload line it logs.
fn hang_up(d: &Daemon, lines: &Receiver<String>) -> String {
    let pid = rustix::process::Pid::from_raw(i32::try_from(d.0.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
    line_with(lines, "qbd: reload", Duration::from_secs(10)).expect("a reload line")
}

fn pick_role(sock: &Path, role: &str) -> PickResponse {
    let body = format!(r#"{{"role":"{role}","difficulty":1,"expected_minutes":30}}"#);
    post(sock, paths::PICK, &body)
}

#[test]
fn sighup_takes_a_new_ladder_and_keeps_live_leases() {
    let dir = temp_dir("reload");
    let sock = dir.join("qb.sock");
    write_roles(
        &dir,
        &[
            ("worker", "vendor-a", "model-small"),
            ("old", "vendor-a", "model-old"),
        ],
    );
    let mut d = start_with(&reloadable(&dir, ""), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let held = pick_role(&sock, "old");
    assert_eq!(held.model.as_deref(), Some("model-old"), "{held:?}");
    let lease = held.lease_id.unwrap();
    let before = state(&sock).logins;
    assert!(before[0].windows[0].reserved > 0.0, "{before:?}");

    write_roles(&dir, &[("worker", "vendor-b", "model-large")]);
    let line = hang_up(&d, &lines);
    assert!(line.ends_with("qbd.toml: 1 roles, 1 clients"), "{line}");

    let next = pick_role(&sock, "worker");
    assert_eq!(
        (next.login.as_deref(), next.model.as_deref()),
        (Some("login-2"), Some("model-large")),
        "{next:?}"
    );
    let after = state(&sock);
    assert!(
        after.leases.iter().any(|l| l.lease_id == lease),
        "{after:?}"
    );
    assert_eq!(after.logins[0], before[0], "login-1 keeps its reservation");
    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#),
    );
    assert!(r.accepted);
    assert!(state(&sock).leases.iter().all(|l| l.lease_id != lease));
}

#[test]
fn a_refused_reload_keeps_the_running_ladder() {
    let dir = temp_dir("refuse");
    let sock = dir.join("qb.sock");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let config = reloadable(&dir, "");
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);

    write_roles(&dir, &[("worker", "vendor-z", "model-large")]);
    let line = hang_up(&d, &lines);
    let roles = dir.join("roles.toml");
    let expected = format!(
        "qbd: reload refused: {}: roles[0].ladder[0].candidates[0].vendor: undeclared vendor \
         `vendor-z` (line 3)",
        roles.display()
    );
    assert!(line.starts_with("<4>"), "{line}");
    assert!(line.ends_with(&expected), "{line}");
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small")
    );

    write_roles(&dir, &[("worker", "vendor-b", "model-large")]);
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, text.replace("burst = 1000", "burst = 999")).unwrap();
    let line = hang_up(&d, &lines);
    let expected = format!(
        "{}: limits: changed; it takes effect only on a restart",
        config.display()
    );
    assert!(line.ends_with(&expected), "{line}");
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small"),
        "a restart-only change refuses the roles file with it"
    );
}

/// `GET /v1/roles` on `sock` as this process's uid: the models of each role's steps, by role.
fn running_models(sock: &Path) -> Vec<(String, Vec<String>)> {
    let (status, body) = call(sock, "GET", paths::ROLES, None, None).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let running: RolesResponse = serde_json::from_slice(&body).unwrap();
    running
        .roles
        .into_iter()
        .map(|r| {
            let models = r.ladder.iter().flat_map(|s| &s.candidates);
            (r.name, models.map(|c| c.model.clone()).collect())
        })
        .collect()
}

#[test]
fn the_running_roles_follow_a_reload_not_the_file_on_disk() {
    let dir = temp_dir("runroles");
    let sock = dir.join("qb.sock");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let mut d = start_with(&reloadable(&dir, ""), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let at_start = vec![("worker".to_owned(), vec!["model-small".to_owned()])];
    assert_eq!(
        running_models(&sock),
        at_start,
        "a non-admin client reads them"
    );

    write_roles(
        &dir,
        &[
            ("worker", "vendor-b", "model-large"),
            ("other", "vendor-a", "model-other"),
        ],
    );
    assert_eq!(
        running_models(&sock),
        at_start,
        "an unreloaded file is not running"
    );
    hang_up(&d, &lines);
    assert_eq!(
        running_models(&sock),
        [
            ("worker".to_owned(), vec!["model-large".to_owned()]),
            ("other".to_owned(), vec!["model-other".to_owned()]),
        ]
    );

    let (status, _) = call(&sock, "GET", paths::ROLES, None, Some(BEARER)).unwrap();
    assert_eq!(status, 401, "an unidentified caller");
    let (status, _) = call(&sock, "POST", paths::ROLES, Some(b""), None).unwrap();
    assert_eq!(status, 405);
}

#[test]
fn sighup_identifies_a_client_added_to_the_config() {
    let dir = temp_dir("addclient");
    let sock = dir.join("qb.sock");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let config = reloadable(&dir, "");
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let task = br#"{"role":"worker","difficulty":1}"#;
    let (status, _) = call(&sock, "POST", paths::PICK, Some(task), Some(BEARER)).unwrap();
    assert_eq!(status, 401);

    let client_b = format!(
        "[[clients]]\nname = \"client-b\"\nbearer_sha256 = \"{BEARER_SHA256}\"\nrole = \"worker\""
    );
    reloadable(&dir, &client_b);
    let line = hang_up(&d, &lines);
    assert!(line.ends_with("1 roles, 2 clients"), "{line}");
    let (status, body) = call(&sock, "POST", paths::PICK, Some(task), Some(BEARER)).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let pick: PickResponse = serde_json::from_slice(&body).unwrap();
    let lease = pick.lease_id.unwrap();
    assert!(
        lease_clients(&sock).contains(&(lease, "client-b".to_owned())),
        "the lease names the new client"
    );
}

/// `GET /v1/admin/roles` on `sock` as this process's uid that must answer 200: the answer, its
/// raw body and its `ETag`.
fn admin_roles_ok(sock: &Path) -> (AdminRoles, String, String) {
    let (status, head, body) = finish(send(sock, "GET", paths::ADMIN_ROLES, ""), Vec::new());
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, 200, "{text}");
    let tag = etag(&head).unwrap().to_owned();
    (serde_json::from_str(&text).unwrap(), text, tag)
}

/// `POST /v1/admin/reload` on `sock` as this process's uid, or with `bearer`.
fn admin_reload(sock: &Path, bearer: Option<&str>) -> (u16, Vec<u8>) {
    call(sock, "POST", paths::ADMIN_RELOAD, Some(b""), bearer).unwrap()
}

/// [`reloadable`] edit making `client-a` an admin.
const ADMIN: &str = "admin = true";

#[test]
fn an_admin_reads_the_roles_of_the_roles_file_on_disk() {
    let dir = temp_dir("adminroles");
    let sock = dir.join("qb.sock");
    let roles = dir.join("roles.toml");
    std::fs::write(
        &roles,
        "[[roles]]\nname = \"worker\"\n\
         [[roles.ladder]]\ndifficulty = 1\ncandidates = [\n\
         { vendor = \"vendor-a\", model = \"model-small\", tier = 1 },\n\
         { vendor = \"vendor-b\", model = \"model-large\", effort = \"high\", tier = 2, \
         cost_per_minute = 0.004 },\n]\n\
         [[roles.reserves]]\ndifficulty = 1\nwindow = \"five_hour\"\nfraction = 0.25\n\
         [[roles]]\nname = \"reviewer\"\n\
         ladder = [{ difficulty = 2, candidates = [{ vendor = \"vendor-b\", model = \"model-b\", \
         tier = 1 }] }]\n",
    )
    .unwrap();
    let mut d = start_with(&reloadable(&dir, ADMIN), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);

    let (got, text, tag) = admin_roles_ok(&sock);
    let audit = line_with(&lines, "qbd: admin", Duration::from_secs(10)).unwrap();
    assert!(
        audit.ends_with("qbd: admin GET /v1/admin/roles by client-a: 200"),
        "{audit}"
    );
    let hash = sha256_hex(&std::fs::read_to_string(&roles).unwrap());
    assert_eq!(
        (got.sha256.as_str(), tag),
        (hash.as_str(), format!("\"{hash}\""))
    );
    assert_eq!(got.source, RolesSource::RolesFile);
    assert_eq!(Path::new(&got.file), roles);
    let names: Vec<_> = got.roles.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["worker", "reviewer"]);
    let candidate = |vendor: &str, model: &str, effort: Option<&str>, tier, cost| LadderCandidate {
        vendor: vendor.into(),
        model: model.into(),
        effort: effort.map(str::to_owned),
        tier,
        cost_per_minute: cost,
    };
    assert_eq!(
        got.roles[0].ladder,
        [LadderStep {
            difficulty: 1,
            candidates: vec![
                candidate("vendor-a", "model-small", None, 1, None),
                candidate("vendor-b", "model-large", Some("high"), 2, Some(0.004)),
            ],
        }]
    );
    assert_eq!(
        got.roles[0].reserves,
        [RoleReserve {
            difficulty: 1,
            window: "five_hour".into(),
            fraction: 0.25,
        }]
    );
    assert_eq!(got.roles[1].reserves, Vec::<RoleReserve>::new());
    assert!(!text.contains("null"), "absent keys are omitted: {text}");

    write_roles(&dir, &[("worker", "vendor-z", "model-small")]);
    let (status, head, body) = finish(send(&sock, "GET", paths::ADMIN_ROLES, ""), Vec::new());
    assert_eq!((status, etag(&head)), (500, None));
    let e: ErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(e.error, ErrorCode::Internal);
    let fault = format!(
        "{}: roles[0].ladder[0].candidates[0].vendor: undeclared vendor",
        roles.display()
    );
    assert!(e.message.contains(&fault), "{}", e.message);
}

#[test]
fn an_admin_reads_the_roles_held_inline_in_the_config() {
    let dir = temp_dir("admininline");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[(
            CLIENT_A,
            format!("name = \"client-a\"\nuid = {}\n{ADMIN}", own_uid()),
        )],
    );
    let _d = start(&config, &sock);
    let (got, _, tag) = admin_roles_ok(&sock);
    let hash = sha256_hex(&std::fs::read_to_string(&config).unwrap());
    assert_eq!(
        (got.sha256.as_str(), tag),
        (hash.as_str(), format!("\"{hash}\""))
    );
    assert_eq!(
        (got.source, Path::new(&got.file)),
        (RolesSource::Config, config.as_path())
    );
    let names: Vec<_> = got.roles.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["worker", "reviewer", "gateway", "hive-heads"]);
    let worker = &got.roles[0];
    let difficulties: Vec<_> = worker.ladder.iter().map(|s| s.difficulty).collect();
    assert_eq!(difficulties, [1, 2]);
    assert_eq!(
        worker.ladder[0].candidates[0].effort.as_deref(),
        Some("low")
    );
    assert_eq!(worker.reserves[0].window, "seven_day");
}

#[test]
fn only_an_admin_client_reaches_the_admin_endpoints() {
    let dir = temp_dir("adminonly");
    let sock = dir.join("qb.sock");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let client_b = format!(
        "[[clients]]\nname = \"client-b\"\nbearer_sha256 = \"{BEARER_SHA256}\"\nrole = \"worker\""
    );
    let config = reloadable(&dir, &client_b);
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);

    write_roles(&dir, &[("worker", "vendor-b", "model-large")]);
    let (status, _) = call(&sock, "GET", paths::ADMIN_ROLES, None, None).unwrap();
    let (status_b, body_b) = call(&sock, "GET", paths::ADMIN_ROLES, None, Some(BEARER)).unwrap();
    let (reload_a, _) = admin_reload(&sock, None);
    let (reload_b, body) = admin_reload(&sock, Some(BEARER));
    assert_eq!((status, status_b, reload_a, reload_b), (403, 403, 403, 403));
    assert_eq!(error_of(&body_b), ErrorCode::Forbidden);
    assert_eq!(error_of(&body), ErrorCode::Forbidden);
    let audit = line_with(
        &lines,
        "POST /v1/admin/reload by client-b",
        Duration::from_secs(10),
    );
    assert!(audit.unwrap().ends_with(": 403"));
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small"),
        "a refused caller reloads nothing"
    );

    let open = temp_socket("adminuid");
    let _o = start(&example("minimal.toml"), &open);
    let (status, _) = call(&open, "GET", paths::ADMIN_ROLES, None, None).unwrap();
    let (reload, _) = admin_reload(&open, None);
    assert_eq!((status, reload), (403, 403), "uid callers are never admins");
}

#[test]
fn an_admin_reload_takes_a_new_ladder_and_keeps_live_leases() {
    let dir = temp_dir("adminreload");
    let sock = dir.join("qb.sock");
    write_roles(
        &dir,
        &[
            ("worker", "vendor-a", "model-small"),
            ("old", "vendor-a", "model-old"),
        ],
    );
    let mut d = start_with(&reloadable(&dir, ADMIN), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let lease = pick_role(&sock, "old").lease_id.unwrap();

    write_roles(&dir, &[("worker", "vendor-b", "model-large")]);
    let (status, body) = admin_reload(&sock, None);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let counts: AdminReloadAnswer = serde_json::from_slice(&body).unwrap();
    assert_eq!((counts.roles, counts.clients), (1, 1));
    let line = line_with(&lines, "qbd: reload", Duration::from_secs(10)).unwrap();
    assert!(line.ends_with("qbd.toml: 1 roles, 1 clients"), "{line}");
    let audit = line_with(&lines, "qbd: admin", Duration::from_secs(10)).unwrap();
    assert!(
        audit.ends_with("qbd: admin POST /v1/admin/reload by client-a: 200"),
        "{audit}"
    );

    let next = pick_role(&sock, "worker");
    assert_eq!(next.model.as_deref(), Some("model-large"), "{next:?}");
    assert!(state(&sock).leases.iter().any(|l| l.lease_id == lease));
    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#),
    );
    assert!(r.accepted);
}

#[test]
fn a_refused_admin_reload_answers_400_and_keeps_the_ladder() {
    let dir = temp_dir("adminrefuse");
    let sock = dir.join("qb.sock");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let _d = start(&reloadable(&dir, ADMIN), &sock);

    write_roles(&dir, &[("worker", "vendor-z", "model-large")]);
    let (status, body) = admin_reload(&sock, None);
    assert_eq!(status, 400);
    let e: ErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!(e.error, ErrorCode::BadRequest);
    let expected = format!(
        "reload refused: {}: roles[0].ladder[0].candidates[0].vendor: undeclared vendor \
         `vendor-z` (line 3)",
        dir.join("roles.toml").display()
    );
    assert_eq!(e.message, expected);
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small")
    );
}

/// A role with one difficulty-1 step on `(vendor, model)` at tier 1.
fn one_step(name: &str, vendor: &str, model: &str) -> RoleConfig {
    RoleConfig {
        name: name.into(),
        ladder: vec![LadderStep {
            difficulty: 1,
            candidates: vec![LadderCandidate {
                vendor: vendor.into(),
                model: model.into(),
                effort: None,
                tier: 1,
                cost_per_minute: None,
            }],
        }],
        reserves: Vec::new(),
    }
}

/// `PUT /v1/admin/roles` of `roles` on `sock` as this process's uid, with `If-Match: if_match`
/// when given.
fn put_roles(sock: &Path, if_match: Option<&str>, roles: &[RoleConfig]) -> (u16, Vec<u8>) {
    let body = serde_json::to_string(&AdminRolesPut {
        roles: roles.to_vec(),
    })
    .unwrap();
    put(sock, paths::ADMIN_ROLES, if_match, &body)
}

/// The backups `<name>.bak-*` beside `file`.
fn backups_of(file: &Path) -> Vec<PathBuf> {
    let prefix = format!("{}.bak-", file.file_name().unwrap().to_string_lossy());
    std::fs::read_dir(file.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&prefix)
        })
        .collect()
}

/// The error of a refused `PUT` that must answer `status` with `code`, and the audit line it logs.
fn refused_put(
    sock: &Path,
    lines: &Receiver<String>,
    if_match: Option<&str>,
    roles: &[RoleConfig],
    (status, code): (u16, ErrorCode),
) -> (String, String) {
    let (got, body) = put_roles(sock, if_match, roles);
    let e: ErrorBody = serde_json::from_slice(&body).unwrap();
    assert_eq!((got, e.error), (status, code), "{}", e.message);
    let audit = line_with(lines, "qbd: admin PUT", Duration::from_secs(10)).unwrap();
    (e.message, audit)
}

#[test]
fn an_admin_put_rewrites_the_roles_file_and_the_next_pick_follows_it() {
    let dir = temp_dir("adminput");
    let sock = dir.join("qb.sock");
    let roles = dir.join("roles.toml");
    write_roles(
        &dir,
        &[
            ("worker", "vendor-a", "model-small"),
            ("old", "vendor-a", "model-old"),
        ],
    );
    let old = std::fs::read_to_string(&roles).unwrap();
    let mut d = start_with(&reloadable(&dir, ADMIN), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let lease = pick_role(&sock, "old").lease_id.unwrap();
    let held = state(&sock).logins[0].clone();
    let (_, _, tag) = admin_roles_ok(&sock);

    let odd = "model-\"large\"\\é\t";
    let mut worker = one_step("worker", "vendor-b", odd);
    worker.ladder[0].candidates[0].effort = Some("high".into());
    worker.ladder[0].candidates[0].cost_per_minute = Some(1.0 / 3.0);
    worker.ladder.push(LadderStep {
        difficulty: 2,
        candidates: vec![LadderCandidate {
            vendor: "vendor-a".into(),
            model: "model-small".into(),
            effort: None,
            tier: 2,
            cost_per_minute: None,
        }],
    });
    worker.reserves.push(RoleReserve {
        difficulty: 2,
        window: "five_hour".into(),
        fraction: 0.1,
    });
    let new_roles = [worker, one_step("reviewer", "vendor-a", "model-small")];
    let (status, body) = put_roles(&sock, Some(&tag), &new_roles);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let written: AdminRolesWritten = serde_json::from_slice(&body).unwrap();

    let text = std::fs::read_to_string(&roles).unwrap();
    assert_eq!(written.sha256, sha256_hex(&text));
    let backup = PathBuf::from(written.backup.unwrap());
    assert_eq!(backups_of(&roles), std::slice::from_ref(&backup));
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), old);
    for f in [&roles, &backup] {
        assert_eq!(std::fs::metadata(f).unwrap().mode() & 0o777, 0o600);
    }
    let reloaded = line_with(&lines, "qbd: reloaded", Duration::from_secs(10)).unwrap();
    assert!(
        reloaded.ends_with("qbd.toml: 2 roles, 1 clients"),
        "{reloaded}"
    );
    let audit = line_with(&lines, "qbd: admin PUT", Duration::from_secs(10)).unwrap();
    let expected = format!(
        "qbd: admin PUT /v1/admin/roles by client-a: 200, roles sha256 {} -> {}, backup {}",
        sha256_hex(&old),
        written.sha256,
        backup.display()
    );
    assert!(audit.ends_with(&expected), "{audit}");

    let next = pick_role(&sock, "worker");
    assert_eq!(
        (next.login.as_deref(), next.model.as_deref()),
        (Some("login-2"), Some(odd)),
        "{next:?}"
    );
    let (got, _, tag) = admin_roles_ok(&sock);
    assert_eq!(
        (got.sha256, got.roles),
        (written.sha256.clone(), new_roles.to_vec())
    );
    assert_eq!(tag, format!("\"{}\"", written.sha256));
    let after = state(&sock);
    assert!(
        after.leases.iter().any(|l| l.lease_id == lease),
        "{after:?}"
    );
    assert_eq!(
        after.logins[0], held,
        "login-1 keeps its lease's reservation"
    );
    let r: ReportResponse = post(
        &sock,
        paths::REPORT,
        &format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#),
    );
    assert!(r.accepted);
    assert!(state(&sock).leases.iter().all(|l| l.lease_id != lease));
}

#[test]
fn a_put_without_or_with_a_stale_if_match_writes_nothing() {
    let dir = temp_dir("adminstale");
    let sock = dir.join("qb.sock");
    let roles = dir.join("roles.toml");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let old = std::fs::read_to_string(&roles).unwrap();
    let mut d = start_with(&reloadable(&dir, ADMIN), &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let hash = sha256_hex(&old);
    let new_roles = [one_step("worker", "vendor-b", "model-large")];

    let (message, audit) = refused_put(
        &sock,
        &lines,
        None,
        &new_roles,
        (428, ErrorCode::PreconditionRequired),
    );
    assert_eq!(
        message,
        "`If-Match` with the roles file's sha256 is required"
    );
    let expected = format!("by client-a: 428, roles sha256 {hash} -> {hash}, nothing written");
    assert!(audit.ends_with(&expected), "{audit}");
    let stale = sha256_hex("an edit by hand");
    let (message, _) = refused_put(
        &sock,
        &lines,
        Some(&stale),
        &new_roles,
        (412, ErrorCode::PreconditionFailed),
    );
    assert_eq!(
        message,
        format!("`If-Match` is not the roles file's sha256 {hash}")
    );

    assert_eq!(std::fs::read_to_string(&roles).unwrap(), old);
    assert_eq!(backups_of(&roles), Vec::<PathBuf>::new());
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small")
    );
}

#[test]
fn a_put_the_startup_parser_refuses_writes_nothing() {
    let dir = temp_dir("adminbad");
    let sock = dir.join("qb.sock");
    let roles = dir.join("roles.toml");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let old = std::fs::read_to_string(&roles).unwrap();
    let config = reloadable(&dir, ADMIN);
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let tag = sha256_hex(&old);
    let bad = (400, ErrorCode::BadRequest);

    let (message, audit) = refused_put(
        &sock,
        &lines,
        Some(&tag),
        &[one_step("reviewer", "vendor-a", "model-small")],
        bad,
    );
    let expected = format!(
        "roles refused: {}: clients[0].role: undeclared role `worker` (line 22)",
        config.display()
    );
    assert_eq!(message, expected);
    assert!(audit.ends_with(", nothing written"), "{audit}");
    let mut reserved = one_step("worker", "vendor-a", "model-small");
    reserved.reserves.push(RoleReserve {
        difficulty: 3,
        window: "five_hour".into(),
        fraction: 0.5,
    });
    let roles_fault = |field: &str, reason: &str| {
        format!("roles refused: {}: {field}: {reason}", roles.display())
    };
    for (put, expected) in [
        (
            vec![one_step("worker", "vendor-z", "model-small")],
            roles_fault(
                "roles[0].ladder[0].candidates[0].vendor",
                "undeclared vendor `vendor-z` (line 7)",
            ),
        ),
        (
            vec![
                one_step("worker", "vendor-a", "model-small"),
                one_step("worker", "vendor-b", "model-large"),
            ],
            roles_fault("roles[1].name", "duplicate name `worker` (line 11)"),
        ),
        (
            vec![reserved],
            roles_fault(
                "roles[0].reserves[0].difficulty",
                "no ladder step with difficulty 3 (line 11)",
            ),
        ),
        (
            Vec::new(),
            format!(
                "roles refused: {}: missing field `roles` (line 1)",
                roles.display()
            ),
        ),
    ] {
        let (message, _) = refused_put(&sock, &lines, Some(&tag), &put, bad);
        assert_eq!(message, expected);
    }

    assert_eq!(std::fs::read_to_string(&roles).unwrap(), old);
    assert_eq!(backups_of(&roles), Vec::<PathBuf>::new());
    assert_eq!(
        pick_role(&sock, "worker").model.as_deref(),
        Some("model-small")
    );
}

#[test]
fn a_put_without_a_roles_file_is_404_and_writes_nothing() {
    let dir = temp_dir("adminnofile");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[(
            CLIENT_A,
            format!("name = \"client-a\"\nuid = {}\n{ADMIN}", own_uid()),
        )],
    );
    let old = std::fs::read_to_string(&config).unwrap();
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let (got, _, tag) = admin_roles_ok(&sock);

    let (message, audit) = refused_put(
        &sock,
        &lines,
        Some(&tag),
        &got.roles,
        (404, ErrorCode::NotFound),
    );
    assert_eq!(
        message,
        format!("no roles_file: the roles are in {}", config.display())
    );
    assert!(
        audit.ends_with("by client-a: 404, nothing written"),
        "{audit}"
    );
    assert_eq!(std::fs::read_to_string(&config).unwrap(), old);
    assert_eq!(backups_of(&config), Vec::<PathBuf>::new());
}

#[test]
fn a_put_equal_to_the_file_writes_and_reloads_nothing() {
    let dir = temp_dir("adminsame");
    let sock = dir.join("qb.sock");
    let roles = dir.join("roles.toml");
    write_roles(&dir, &[("worker", "vendor-a", "model-small")]);
    let config = reloadable(&dir, ADMIN);
    let mut d = start_with(&config, &sock, Stdio::piped());
    let lines = stderr_lines(&mut d.0);
    let (got, _, tag) = admin_roles_ok(&sock);
    let (status, body) = put_roles(&sock, Some(&tag), &got.roles);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let first: AdminRolesWritten = serde_json::from_slice(&body).unwrap();
    let rendered = std::fs::read_to_string(&roles).unwrap();
    let client_b = format!(
        "{ADMIN}\n[[clients]]\nname = \"client-b\"\nbearer_sha256 = \"{BEARER_SHA256}\"\n\
         role = \"worker\""
    );
    reloadable(&dir, &client_b);

    let (status, body) = put_roles(&sock, Some(&first.sha256), &got.roles);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let same: AdminRolesWritten = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        same,
        AdminRolesWritten {
            sha256: first.sha256.clone(),
            backup: None,
        }
    );
    let audit = line_with(&lines, "qbd: admin PUT", Duration::from_secs(10)).unwrap();
    assert!(audit.contains(": 200, roles sha256"), "{audit}");
    let audit = line_with(&lines, "qbd: admin PUT", Duration::from_secs(10)).unwrap();
    let expected = format!(
        ": 200, roles sha256 {0} -> {0}, nothing written",
        first.sha256
    );
    assert!(audit.ends_with(&expected), "{audit}");
    assert_eq!(std::fs::read_to_string(&roles).unwrap(), rendered);
    assert_eq!(
        backups_of(&roles).len(),
        1,
        "only the first PUT made a backup"
    );
    let task = br#"{"role":"worker","difficulty":1}"#;
    let (status, _) = call(&sock, "POST", paths::PICK, Some(task), Some(BEARER)).unwrap();
    assert_eq!(status, 401, "no reload took the client added since");
}

/// `qb --version` and `qb version` print the version and the git revision the binary was built
/// from, so that two builds of one version can be told apart.
#[test]
fn version_names_the_build_revision() {
    let exe = env!("CARGO_BIN_EXE_qb");
    let head = Command::new("git")
        .args([
            "-C",
            env!("CARGO_MANIFEST_DIR"),
            "rev-parse",
            "--short=12",
            "HEAD",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8(o.stdout).unwrap().trim().to_owned());
    for args in [&["--version"][..], &["-V"], &["version"]] {
        let out = Command::new(exe).args(args).output().unwrap();
        assert!(out.status.success(), "{args:?}");
        let line = String::from_utf8(out.stdout).unwrap();
        let rest = line
            .strip_prefix(&format!("qb {} (", env!("CARGO_PKG_VERSION")))
            .unwrap_or_else(|| panic!("{args:?}: {line:?}"));
        let rev = rest
            .strip_suffix(")\n")
            .unwrap_or_else(|| panic!("{line:?}"));
        match (
            std::env::var("QB_BUILD_REVISION")
                .ok()
                .filter(|s| !s.is_empty()),
            &head,
        ) {
            (Some(env), _) => assert_eq!(rev, env.trim()),
            (None, Some(head)) => assert_eq!(rev, head),
            (None, None) => assert_eq!(rev, "unknown"),
        }
    }
}
