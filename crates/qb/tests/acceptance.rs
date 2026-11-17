//! Acceptance lane: the policy scenarios, latency, memory, disk and wake-up budgets of the daemon
//! and of `qb gateway`, measured on the binary in `QB_ACCEPTANCE_BIN` (the cargo-built one when
//! unset). Timing-bound, so every test is ignored by default and the `budgets` CI job runs them
//! one at a time. The gateway cases bind the scripted vendor to loopback port 443, the only port
//! the gateway's sandbox connects to, so they need `net.ipv4.ip_unprivileged_port_start` <= 443.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use qb::client::call;
use qb_proto::{Decision, PickResponse, ReportResponse, paths};
use serde_json::json;

mod common;

use common::vendor::{Answer, Vendor, fixture_of};
use common::{
    Daemon, answer, events, hook_config, kill_auth, line_with, own_uid, park, pick_worker, post,
    record_event, start_daemon, state, stderr_lines, temp_dir, wait_for,
};

const PICKS: usize = 10_000;
const MAX_P99: Duration = Duration::from_millis(1);
const MAX_HWM_KB: u64 = 4096;
const IDLE: Duration = Duration::from_secs(10);

const PICK: &str = r#"{"role":"worker","difficulty":1}"#;

/// The binary under test.
fn exe() -> PathBuf {
    let Some(bin) = std::env::var_os("QB_ACCEPTANCE_BIN") else {
        return PathBuf::from(env!("CARGO_BIN_EXE_qb"));
    };
    let bin = PathBuf::from(bin);
    assert!(
        bin.is_absolute(),
        "QB_ACCEPTANCE_BIN must be absolute: {}",
        bin.display()
    );
    bin
}

fn start(config: &Path, sock: &Path) -> Daemon {
    start_daemon(&exe(), config, sock, Stdio::null())
}

/// Daemon config in `dir`: `logins` as `(name, vendor)`, the worker ladder `vendor-a` tier 1 then
/// `vendor-b` tier 2, this process's uid as the agent client `client-1`, a journal in `dir` or
/// none, limits no test reaches, and `extra` appended.
fn config(dir: &Path, journal: bool, logins: &[(&str, &str)], extra: &str) -> PathBuf {
    let mut text = if journal {
        format!(
            "[journal]\nmode = \"path\"\npath = \"{}\"\n",
            dir.join("journal").display()
        )
    } else {
        "[journal]\nmode = \"off\"\n".to_owned()
    };
    write!(
        text,
        r#"
[limits]
rate_per_s = 100000.0
burst = 100000

[probe]
agents = ["client-1"]
{extra}

[[vendors]]
name = "vendor-a"
windows = [{{ name = "seven_day", length_s = 604800, t_burn_s = 43200 }}]

[[vendors]]
name = "vendor-b"
windows = [{{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }}]

[[roles]]
name = "worker"

[[roles.ladder]]
difficulty = 1
candidates = [
  {{ vendor = "vendor-a", model = "model-small", tier = 1 }},
  {{ vendor = "vendor-b", model = "model-small", tier = 2 }},
]

[[clients]]
name = "client-1"
uid = {uid}
role = "worker"
"#,
        uid = own_uid()
    )
    .unwrap();
    for (name, vendor) in logins {
        write!(
            text,
            "\n[[logins]]\nname = \"{name}\"\nvendor = \"{vendor}\"\n"
        )
        .unwrap();
    }
    let file = dir.join("qbd.toml");
    std::fs::write(&file, text).unwrap();
    file
}

const A_AND_B: [(&str, &str); 2] = [("login-1", "vendor-a"), ("login-2", "vendor-b")];

fn release(sock: &Path, lease: &str) {
    let body = format!(r#"{{"lease_id":"{lease}","outcome":"ok","release":true}}"#);
    let r: ReportResponse = post(sock, paths::REPORT, &body);
    assert!(r.accepted);
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn vendor_a_dead_sends_the_pick_to_vendor_b() {
    let dir = temp_dir("acc-dead-a");
    let sock = dir.join("qb.sock");
    let _d = start(&config(&dir, true, &A_AND_B, ""), &sock);
    let before = pick_worker(&sock);
    assert_eq!(before.vendor.as_deref(), Some("vendor-a"), "{before:?}");
    release(&sock, &before.lease_id.unwrap());

    kill_auth(&sock, "login-1");
    let after = pick_worker(&sock);
    assert_eq!(after.decision, Decision::Run, "{after:?}");
    assert_eq!(
        (after.vendor.as_deref(), after.login.as_deref()),
        (Some("vendor-b"), Some("login-2"))
    );
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn thirty_percent_left_resetting_in_six_hours_is_spent_first() {
    let dir = temp_dir("acc-spend");
    let sock = dir.join("qb.sock");
    let logins = [("login-1", "vendor-a"), ("login-2", "vendor-a")];
    let _d = start(&config(&dir, true, &logins, ""), &sock);
    let now = state(&sock).now;
    for (login, used, resets_in) in [("login-1", 0.1, 6 * 86_400), ("login-2", 0.7, 6 * 3600)] {
        let body = format!(
            r#"{{"login":"{login}","outcome":"ok","windows":[{{"name":"seven_day","utilization":{used},"resets_at":{}}}]}}"#,
            now + resets_in
        );
        let r: ReportResponse = post(&sock, paths::REPORT, &body);
        assert!(r.accepted);
    }
    let p = pick_worker(&sock);
    assert_eq!(p.decision, Decision::Run, "{p:?}");
    assert_eq!(
        (p.login.as_deref(), p.reason.as_str()),
        (Some("login-2"), "spend_before_reset")
    );
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn everything_dead_answers_dead() {
    let dir = temp_dir("acc-dead-all");
    let sock = dir.join("qb.sock");
    let _d = start(&config(&dir, true, &A_AND_B, ""), &sock);
    kill_auth(&sock, "login-1");
    kill_auth(&sock, "login-2");
    let p = pick_worker(&sock);
    assert_eq!(p.decision, Decision::Dead, "{p:?}");
    assert!(p.lease_id.is_none());
}

/// Runs [`PICKS`] picks, each released by a report, one connection per request, and returns the
/// sorted latencies of the picks from connect to the full response.
fn pick_and_release(sock: &Path) -> Vec<Duration> {
    let mut latencies = Vec::with_capacity(PICKS);
    for _ in 0..PICKS {
        let t = Instant::now();
        let (status, body) = call(sock, "POST", paths::PICK, Some(PICK.as_bytes()), None).unwrap();
        latencies.push(t.elapsed());
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let p: PickResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(p.decision, Decision::Run, "{p:?}");
        release(sock, &p.lease_id.unwrap());
    }
    latencies.sort();
    latencies
}

/// The nearest-rank `pct`th percentile of sorted `latencies`.
fn percentile(latencies: &[Duration], pct: usize) -> Duration {
    latencies[(latencies.len() * pct).div_ceil(100) - 1]
}

/// The number of the `field` line of the `/proc` status file `path`.
fn status_number(path: &Path, field: &str) -> u64 {
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().find(|l| l.starts_with(field)).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// The value in kB of the `field` line of `/proc/<pid>/status`.
fn status_kb(pid: u32, field: &str) -> u64 {
    status_number(Path::new(&format!("/proc/{pid}/status")), field)
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn ten_thousand_picks_keep_p99_and_peak_rss_within_budget() {
    let dir = temp_dir("acc-load");
    let sock = dir.join("qb.sock");
    let d = start(&config(&dir, true, &A_AND_B, ""), &sock);
    let lat = pick_and_release(&sock);
    let hwm = status_kb(d.0.id(), "VmHWM:");
    let p99 = percentile(&lat, 99);
    eprintln!(
        "acceptance: {PICKS} picks over UDS, journal on: p50 {:?}, p90 {:?}, p99 {p99:?}, max {:?}",
        percentile(&lat, 50),
        percentile(&lat, 90),
        lat[lat.len() - 1]
    );
    eprintln!(
        "acceptance: daemon VmHWM {hwm} kB, VmRSS {} kB",
        status_kb(d.0.id(), "VmRSS:")
    );
    assert!(p99 <= MAX_P99, "pick p99 {p99:?} > {MAX_P99:?}");
    assert!(hwm <= MAX_HWM_KB, "daemon VmHWM {hwm} kB > {MAX_HWM_KB} kB");
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn journal_off_writes_no_bytes_over_ten_thousand_picks() {
    let dir = temp_dir("acc-off");
    let sock = dir.join("qb.sock");
    let d = start(&config(&dir, false, &A_AND_B, ""), &sock);
    pick_and_release(&sock);
    let io = std::fs::read_to_string(format!("/proc/{}/io", d.0.id())).unwrap();
    let written: u64 = io
        .lines()
        .find_map(|l| l.strip_prefix("write_bytes: "))
        .unwrap()
        .parse()
        .unwrap();
    eprintln!("acceptance: {PICKS} picks, journal off: daemon write_bytes {written}");
    assert_eq!(written, 0);
}

/// Voluntary plus involuntary context switches so far of each thread of process `pid`.
fn switches(pid: u32) -> BTreeMap<PathBuf, u64> {
    let tasks = std::fs::read_dir(format!("/proc/{pid}/task")).unwrap();
    tasks
        .map(|t| {
            let status = t.unwrap().path().join("status");
            let n = status_number(&status, "voluntary_ctxt_switches:")
                + status_number(&status, "nonvoluntary_ctxt_switches:");
            (status, n)
        })
        .collect()
}

/// The context switches between two samples of [`switches`] of the same threads.
fn woken(before: &BTreeMap<PathBuf, u64>, after: &BTreeMap<PathBuf, u64>) -> u64 {
    let threads = |s: &BTreeMap<PathBuf, u64>| s.keys().cloned().collect::<Vec<_>>();
    assert_eq!(threads(before), threads(after), "threads started or ended");
    after.iter().map(|(t, n)| n - before[t]).sum()
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn an_idle_daemon_with_a_parked_agent_and_hooks_does_not_wake_up() {
    let dir = temp_dir("acc-idle");
    let sock = dir.join("qb.sock");
    let config = config(&dir, true, &A_AND_B, "enabled = true");
    let d = start(&hook_config(config, &record_event(&dir)), &sock);
    let mut parked = park(&sock, None, &["login-1"]);
    kill_auth(&sock, "login-2");
    assert_eq!(events(&dir, 1), ["dead login-2 vendor-b"]);
    assert_eq!(state(&sock).logins.len(), 2);
    std::thread::sleep(Duration::from_millis(100));
    let before = switches(d.0.id());
    std::thread::sleep(IDLE);
    let woke = woken(&before, &switches(d.0.id()));
    eprintln!("acceptance: idle daemon context switches over {IDLE:?}: {woke}");
    assert_eq!(woke, 0);
    assert_eq!(answer(&mut parked, Duration::from_millis(10)), None);
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn a_failed_probe_backs_the_login_off_until_the_next_job() {
    let dir = temp_dir("acc-backoff");
    let sock = dir.join("qb.sock");
    let probe = "enabled = true\nbackoff_initial_s = 2";
    let _d = start(&config(&dir, true, &A_AND_B, probe), &sock);
    std::fs::create_dir_all(dir.join("creds")).unwrap();
    std::fs::write(dir.join("creds/.credentials.json"), "{").unwrap();
    std::fs::write(
        dir.join("agent.toml"),
        "[[logins]]\nname = \"login-1\"\nkind = \"claude\"\n\
         credentials = \"creds/.credentials.json\"\n",
    )
    .unwrap();
    let mut agent = Daemon(
        Command::new(exe())
            .arg("--socket")
            .arg(&sock)
            .args(["agent", "--config", "agent.toml"])
            .current_dir(&dir)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let lines = stderr_lines(&mut agent.0);
    let probe_line = "probe of login-1";

    assert!(pick_worker(&sock).stale);
    let first = line_with(&lines, probe_line, Duration::from_secs(10));
    assert!(
        first
            .expect("the agent took the job")
            .contains("not valid JSON")
    );
    assert!(pick_worker(&sock).stale);
    assert_eq!(
        line_with(&lines, probe_line, Duration::from_millis(500)),
        None,
        "the failed probe backs the login off"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(pick_worker(&sock).stale);
    let second = line_with(&lines, probe_line, Duration::from_secs(5));
    let second = second.expect("a job after the back-off, well before the probe timeout");
    assert!(second.contains("not valid JSON"), "{second}");
}

const GATEWAY_TURNS: usize = 300;
const GATEWAY_MAX_P99: Duration = Duration::from_millis(5);
/// Turns in a row of [`TURN_TEXT_BYTES`] for the gateway's peak RSS.
const LARGE_TURNS: usize = 20;
const TURN_TEXT_BYTES: usize = 1 << 20;
/// The documented RSS of one turn in flight besides twice its request body.
const TURN_KB: u64 = 1024;

/// `qb gateway` with its default caps and its loopback listener, the qbd it picks from, and the
/// scripted vendor its one login `login-1` sends to.
struct Gateway {
    vendor: Vendor,
    sock: PathBuf,
    config: PathBuf,
    process: Daemon,
    _qbd: Daemon,
}

impl Gateway {
    /// Starts all three in a fresh directory named after `tag`. The vendor listens on loopback
    /// port 443, the only port the gateway's sandbox connects to.
    fn start(tag: &str) -> Self {
        let dir = temp_dir(tag);
        let qbd = dir.join("qb.sock");
        let qbd_process = start(&config(&dir, false, &[("login-1", "vendor-a")], ""), &qbd);
        let vendor = Vendor::start_on("127.0.0.1:443".parse().unwrap());
        let credentials = dir.join("login-1.json");
        std::fs::write(&credentials, r#"{"type":"api_key","key":"test-token-1"}"#).unwrap();
        std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600)).unwrap();
        // A free port the gateway binds itself, before its sandbox.
        let listen = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let sock = dir.join("gw.sock");
        let text = format!(
            r#"socket = "{sock}"
qbd_socket = "{qbd}"

[[logins]]
name = "login-1"
{login}
credentials = "{credentials}"

[[routes]]
alias = "chat"
role = "worker"
difficulty = 1

[fronts]
listen = "{listen}"
token_sha256 = "{hash}"

[fronts.messages]
vendor = "vendor-a"
"#,
            sock = sock.display(),
            qbd = qbd.display(),
            login = vendor.login("kind = \"api_key\"\napi = \"anthropic\""),
            credentials = credentials.display(),
            hash = "0".repeat(64),
        );
        let config = dir.join("gateway.toml");
        std::fs::write(&config, text).unwrap();
        let process = Daemon(
            Command::new(exe())
                .args(["gateway", "--config"])
                .arg(&config)
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&sock);
        Self {
            vendor,
            sock,
            config,
            process,
            _qbd: qbd_process,
        }
    }

    fn pid(&self) -> u32 {
        self.process.0.id()
    }

    /// Runs the C4 turn `body` to its end, the vendor streaming a short text; the time from the
    /// client's connect to the vendor holding the whole upstream request.
    fn turn(&self, body: &str) -> Duration {
        let sse = fixture_of("qb-anthropic", "upstream_text.sse");
        let head = vec![("content-type".to_owned(), "text/event-stream".to_owned())];
        self.vendor.answer(Answer::Full(200, head, sse));
        let t = Instant::now();
        let (status, answer) = call(
            &self.sock,
            "POST",
            paths::MODEL_TURN,
            Some(body.as_bytes()),
            None,
        )
        .unwrap();
        let answer = String::from_utf8_lossy(&answer);
        assert_eq!(status, 200, "{answer}");
        assert!(answer.contains(r#"{"type":"stop""#), "{answer}");
        let received = self.vendor.received().pop().expect("the upstream request");
        received.at - t
    }
}

/// The C4 turn body numbered `n` with the user text `text` on route `chat`.
fn turn_body(n: usize, text: &str) -> String {
    json!({
        "route": "chat",
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
        "max_tokens": 64,
        "request_id": format!("turn-{n}"),
    })
    .to_string()
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn gateway_peak_rss_stays_within_budget_idle_and_per_turn() {
    let gw = Gateway::start("acc-gw-rss");
    std::thread::sleep(Duration::from_millis(100));
    let idle = status_kb(gw.pid(), "VmHWM:");
    eprintln!("acceptance: idle gateway VmHWM {idle} kB");
    assert!(
        idle <= MAX_HWM_KB,
        "idle gateway VmHWM {idle} kB > {MAX_HWM_KB} kB"
    );

    let text = "a".repeat(TURN_TEXT_BYTES);
    let body_kb = (turn_body(0, &text).len() as u64).div_ceil(1024);
    for n in 0..LARGE_TURNS {
        gw.turn(&turn_body(n, &text));
    }
    let hwm = status_kb(gw.pid(), "VmHWM:");
    let bound = MAX_HWM_KB + TURN_KB + 2 * body_kb;
    eprintln!(
        "acceptance: gateway after {LARGE_TURNS} turns of {body_kb} kB, one in flight: \
         VmHWM {hwm} kB, VmRSS {} kB (budget {bound} kB)",
        status_kb(gw.pid(), "VmRSS:")
    );
    assert!(hwm <= bound, "gateway VmHWM {hwm} kB > {bound} kB");
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn an_idle_gateway_with_its_loopback_listener_does_not_wake_up() {
    let gw = Gateway::start("acc-gw-idle");
    gw.turn(&turn_body(0, "Hi"));
    std::thread::sleep(Duration::from_millis(100));
    let before = switches(gw.pid());
    std::thread::sleep(IDLE);
    let woke = woken(&before, &switches(gw.pid()));
    eprintln!("acceptance: idle gateway context switches over {IDLE:?}: {woke}");
    assert_eq!(woke, 0);
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn gateway_turns_reach_the_vendor_within_the_p99_budget() {
    let gw = Gateway::start("acc-gw-p99");
    let mut lat: Vec<Duration> = (0..GATEWAY_TURNS)
        .map(|n| gw.turn(&turn_body(n, "Hi")))
        .collect();
    lat.sort();
    let p99 = percentile(&lat, 99);
    eprintln!(
        "acceptance: {GATEWAY_TURNS} gateway turns, client connect to upstream request: \
         p50 {:?}, p90 {:?}, p99 {p99:?}, max {:?}",
        percentile(&lat, 50),
        percentile(&lat, 90),
        lat[lat.len() - 1]
    );
    assert!(
        p99 <= GATEWAY_MAX_P99,
        "gateway p99 {p99:?} > {GATEWAY_MAX_P99:?}"
    );
}

/// The route aliases the gateway on `sock` serves.
fn aliases(sock: &Path) -> Vec<String> {
    let (status, body) = call(sock, "GET", paths::MODEL_ROUTES, None, None).unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let routes: serde_json::Value = serde_json::from_slice(&body).unwrap();
    routes["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["alias"].as_str().unwrap().to_owned())
        .collect()
}

/// `qb reload` against the gateway on `sock`: its exit status and output.
fn qb_reload(sock: &Path) -> (bool, String) {
    let out = Command::new(exe())
        .arg("--socket")
        .arg(sock)
        .arg("reload")
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
#[ignore = "acceptance lane, run by the budgets CI job"]
fn the_gateway_reloads_its_config_on_sighup_and_on_qb_reload() {
    let gw = Gateway::start("acc-gw-reload");
    let text = std::fs::read_to_string(&gw.config).unwrap();
    let with = |aliases: &[&str]| {
        let mut t = text.clone();
        for alias in aliases {
            write!(
                t,
                "\n[[routes]]\nalias = \"{alias}\"\nrole = \"worker\"\ndifficulty = 1\n"
            )
            .unwrap();
        }
        t
    };

    std::fs::write(&gw.config, with(&["hup"])).unwrap();
    let pid = rustix::process::Pid::from_raw(i32::try_from(gw.pid()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !aliases(&gw.sock).contains(&"hup".to_owned()) {
        assert!(Instant::now() < deadline, "SIGHUP did not add the alias");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut body: serde_json::Value = serde_json::from_str(&turn_body(1, "Hi")).unwrap();
    body["route"] = json!("hup");
    gw.turn(&body.to_string());

    std::fs::write(&gw.config, with(&["hup", "cli"])).unwrap();
    let (ok, answer) = qb_reload(&gw.sock);
    assert!(ok, "{answer}");
    assert!(answer.contains(r#""routes":3"#), "{answer}");
    assert_eq!(aliases(&gw.sock), ["chat", "cli", "hup"]);

    std::fs::write(&gw.config, format!("{}[[routes]\n", with(&["hup", "cli"]))).unwrap();
    let (ok, answer) = qb_reload(&gw.sock);
    assert!(!ok, "{answer}");
    assert!(answer.contains("reload refused"), "{answer}");
    assert_eq!(
        aliases(&gw.sock),
        ["chat", "cli", "hup"],
        "the running config stays"
    );
}
