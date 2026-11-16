//! Contract tests: the `/v1` endpoints over a real unix socket, in-process and via the binary.

#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb::auth::Gate;
use qb::client::call;
use qb::config::{self, Limits};
use qb::journal::{self, Journal};
use qb_core::{Core, Record, Spec};
use qb_proto::{
    Decision, ErrorBody, ErrorCode, HealthResponse, HealthStatus, LoginStatus, Outcome,
    PickResponse, ReportRequest, ReportResponse, Source, StateResponse, WindowReport, paths,
};

/// Room for the directory and file names a test adds under the base.
const NAME_ROOM: usize = 40;
/// `sun_path` holds 108 bytes including the terminating NUL.
const SUN_PATH: usize = 108;

/// A fresh directory for one test under a base short enough for unix socket paths.
fn temp_dir(tag: &str) -> PathBuf {
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
    dir
}

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
        qb::server::serve(&listener, &mut core, &mut Journal::off(), &mut gate)
    });
    path
}

fn error_of(body: &[u8]) -> ErrorCode {
    serde_json::from_slice::<ErrorBody>(body).unwrap().error
}

#[test]
fn health_reports_version() {
    let sock = spawn_server();
    let (status, body) = call(&sock, "GET", paths::HEALTH, None).unwrap();
    assert_eq!(status, 200);
    let h: HealthResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(h.status, HealthStatus::Ok);
    assert_eq!(h.api_version, "v1");
    assert_eq!(h.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn state_is_empty_without_config() {
    let sock = spawn_server();
    let (status, body) = call(&sock, "GET", paths::STATE, None).unwrap();
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
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(body)).unwrap();
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
    ] {
        let (status, resp) = call(&sock, "POST", paths::PICK, Some(body)).unwrap();
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
    )
    .unwrap();
    assert_eq!(status, 404);
    assert_eq!(error_of(&resp), ErrorCode::NotFound);
    let (status, _) = call(
        &sock,
        "POST",
        paths::REPORT,
        Some(br#"{"login":"nope","outcome":"usage_limit"}"#),
    )
    .unwrap();
    assert_eq!(status, 404);
    let (status, _) = call(&sock, "POST", paths::REPORT, Some(br#"{"outcome":"ok"}"#)).unwrap();
    assert_eq!(status, 400);
}

#[test]
fn routing_errors() {
    let sock = spawn_server();
    let (status, resp) = call(&sock, "GET", "/v1/nope", None).unwrap();
    assert_eq!(status, 404);
    assert_eq!(error_of(&resp), ErrorCode::NotFound);
    let (status, resp) = call(&sock, "GET", paths::PICK, None).unwrap();
    assert_eq!(status, 405);
    assert_eq!(error_of(&resp), ErrorCode::MethodNotAllowed);
    let (status, _) = call(&sock, "POST", paths::HEALTH, Some(b"{}")).unwrap();
    assert_eq!(status, 405);
}

#[test]
fn oversized_and_unframed_requests() {
    let sock = spawn_server();
    let big = vec![b' '; qb::http::MAX_BODY + 1];
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(&big)).unwrap();
    assert_eq!(status, 413);
    assert_eq!(error_of(&resp), ErrorCode::PayloadTooLarge);

    let mut s = UnixStream::connect(&sock).unwrap();
    s.write_all(b"POST /v1/pick HTTP/1.1\r\nHost: qb\r\n\r\n")
        .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    assert!(raw.starts_with("HTTP/1.1 411 "), "{raw}");
}

#[test]
fn a_silent_client_does_not_wedge_the_daemon() {
    let sock = spawn_server();
    let _idle = UnixStream::connect(&sock).unwrap();
    let t = Instant::now();
    let (status, _) = call(&sock, "GET", paths::HEALTH, None).unwrap();
    assert_eq!(status, 200);
    assert!(t.elapsed() < qb::server::IO_TIMEOUT + Duration::from_secs(2));
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while UnixStream::connect(path).is_err() {
        assert!(Instant::now() < deadline, "daemon did not come up");
        std::thread::sleep(Duration::from_millis(20));
    }
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

    let agent = Command::new(exe)
        .env("QB_SOCKET", &sock)
        .arg("agent")
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(agent.success());

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
    let (status, body) = call(&sock, "GET", paths::STATE, None).unwrap();
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
    };
    let body = serde_json::to_vec(&req).unwrap();
    let (status, resp) = call(sock, "POST", paths::REPORT, Some(&body)).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&resp));
    let r: ReportResponse = serde_json::from_slice(&resp).unwrap();
    assert!(r.accepted);
}

fn pick_worker(sock: &Path) -> PickResponse {
    let (status, resp) = call(
        sock,
        "POST",
        paths::PICK,
        Some(br#"{"role":"worker","difficulty":1}"#),
    )
    .unwrap();
    assert_eq!(status, 200);
    serde_json::from_slice(&resp).unwrap()
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

    let (status, body) = call(&sock, "GET", paths::STATE, None).unwrap();
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

fn post<T: serde::de::DeserializeOwned>(sock: &Path, path: &str, body: &str) -> T {
    let (status, resp) = call(sock, "POST", path, Some(body.as_bytes())).unwrap();
    assert_eq!(status, 200, "{body}: {}", String::from_utf8_lossy(&resp));
    serde_json::from_slice(&resp).unwrap()
}

fn state(sock: &Path) -> StateResponse {
    let (status, body) = call(sock, "GET", paths::STATE, None).unwrap();
    assert_eq!(status, 200);
    serde_json::from_slice(&body).unwrap()
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
    let (status, _) = call(&sock, "POST", paths::REPORT, Some(release.as_bytes())).unwrap();
    assert_eq!(status, 404, "a released lease is gone");
}

/// The uid this test process runs as: the owner of a directory it created.
fn own_uid() -> u32 {
    std::fs::metadata(temp_dir("uid")).unwrap().uid()
}

/// Token of the bearer client `client-b` in the configs below; `BEARER_SHA256` is its hash.
const BEARER: &str = "token-b";
const BEARER_SHA256: &str = "49e2bb7eab54cf09b409ffafd3fa8a8a955a60eb972faacaefbed3dbd3207132";

/// `qbd.toml` in `dir` with each `(from, to)` replaced once and its journal at `dir/journal`.
fn config_copy(dir: &Path, edits: &[(&str, String)]) -> PathBuf {
    let mut text = std::fs::read_to_string(example("qbd.toml")).unwrap();
    let journal = format!("path = \"{}\"", dir.join("journal").display());
    for (from, to) in [("path = \"/var/lib/qb/journal\"", journal)]
        .iter()
        .chain(edits)
    {
        assert!(text.contains(from), "{from} not in qbd.toml");
        text = text.replace(from, to);
    }
    let file = dir.join("qbd.toml");
    std::fs::write(&file, text).unwrap();
    file
}

/// `qbd.toml` rotated at `rotate_bytes`, with `client-a` on this process's uid, `client-b` on
/// [`BEARER`] and limits no test reaches.
fn journaled_config(dir: &Path, rotate_bytes: u64) -> PathBuf {
    config_copy(
        dir,
        &[
            (
                "rotate_bytes = 1048576",
                format!("rotate_bytes = {rotate_bytes}"),
            ),
            ("uid = 1001", format!("uid = {}", own_uid())),
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
    let d = Daemon(
        Command::new(env!("CARGO_BIN_EXE_qb"))
            .arg("--socket")
            .arg(sock)
            .args(["daemon", "--config"])
            .arg(config)
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for(sock);
    d
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
    let (status, _) = call(&sock, "POST", paths::REPORT, Some(release.as_bytes())).unwrap();
    assert_eq!(status, 404, "a released lease stays released");

    let fresh: PickResponse = post(&sock, paths::PICK, TASK);
    let fresh = fresh.lease_id.unwrap();
    assert!(fresh != released && after.leases.iter().all(|l| l.lease_id != fresh));
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

/// Sends one request with `Authorization: Bearer <bearer>` and returns `(status, body)`.
fn call_with_bearer(
    sock: &Path,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: &str,
) -> (u16, Vec<u8>) {
    let mut s = UnixStream::connect(sock).unwrap();
    let body = body.unwrap_or_default();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: qb\r\nAuthorization: Bearer {bearer}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let head = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let status = std::str::from_utf8(&raw[9..12]).unwrap().parse().unwrap();
    (status, raw[head + 4..].to_vec())
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
    let (status, body) = call_with_bearer(&sock, "POST", paths::PICK, Some(TASK), BEARER);
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
        ("POST", paths::PICK, Some(TASK)),
        ("GET", paths::STATE, None),
    ] {
        let (status, resp) = call_with_bearer(&sock, method, path, body, "token-x");
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
    let other = own_uid().wrapping_add(1);
    let config = config_copy(&dir, &[("uid = 1001", format!("uid = {other}"))]);
    let _d = start(&config, &sock);
    let (status, resp) = call(&sock, "POST", paths::PICK, Some(TASK.as_bytes())).unwrap();
    assert_eq!(status, 401);
    assert_eq!(error_of(&resp), ErrorCode::Unauthorized);
    let (status, _) = call(&sock, "GET", paths::STATE, None).unwrap();
    assert_eq!(status, 401);
    let (status, _) = call(&sock, "GET", paths::HEALTH, None).unwrap();
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

    let (status, resp) = call_with_bearer(&sock, "POST", paths::REPORT, Some(&release), BEARER);
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
    let (status, _) = call_with_bearer(&sock, "POST", paths::REPORT, Some(by_login), BEARER);
    assert_eq!(status, 200, "login reports are open to every client");
}

#[test]
fn each_client_has_a_token_bucket() {
    let dir = temp_dir("bucket");
    let sock = dir.join("qb.sock");
    let config = config_copy(
        &dir,
        &[
            ("uid = 1001", format!("uid = {}", own_uid())),
            ("rate_per_s = 5.0", "rate_per_s = 0.5".to_owned()),
            ("burst = 20", "burst = 3".to_owned()),
        ],
    );
    let _d = start(&config, &sock);
    for _ in 0..5 {
        let (status, _) = call_with_bearer(&sock, "GET", paths::STATE, None, "token-x");
        assert_eq!(status, 401);
    }
    let started = Instant::now();
    for i in 0..3 {
        let (status, _) = call(&sock, "GET", paths::STATE, None).unwrap();
        assert_eq!(status, 200, "request {i} fits the burst after the 401s");
    }
    let (status, resp) = call(&sock, "GET", paths::STATE, None).unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "too slow to test the burst"
    );
    assert_eq!(status, 429);
    assert_eq!(error_of(&resp), ErrorCode::TooManyRequests);
}
