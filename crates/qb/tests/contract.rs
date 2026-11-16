//! Contract tests: the `/v1` endpoints over a real unix socket, in-process and via the binary.

#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb::client::call;
use qb::config;
use qb_core::{Core, Spec};
use qb_proto::{
    Decision, ErrorBody, ErrorCode, HealthResponse, HealthStatus, Outcome, PickResponse,
    ReportRequest, ReportResponse, Source, StateResponse, WindowReport, paths,
};

fn temp_socket(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "qb-test-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("qb.sock")
}

/// Starts an in-process daemon on a fresh socket. The thread lives until the test binary exits.
fn spawn_server() -> PathBuf {
    let path = temp_socket("lib");
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        let mut core = Core::new(Spec::default()).unwrap();
        qb::server::serve(&listener, &mut core);
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
    let file = example("qbd.toml");
    let sock = temp_socket("cfg");
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
            .arg(example("qbd.toml"))
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
