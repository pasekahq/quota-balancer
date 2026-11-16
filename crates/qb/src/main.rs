//! `qb` multicall entry point. Invoked as `qbd` it runs the daemon.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use qb::journal::{self, Journal};
use qb::{DEFAULT_CONFIG, DEFAULT_SOCKET, agent, client, config, listen, log, server};
use qb_core::Core;
use qb_proto::{Outcome, PickRequest, Pin, ReportRequest, paths};

const HELP: &str = "\
qb - pre-flight quota balancer for coding-agent subscriptions

USAGE:
    qbd [--socket PATH] [--config PATH] run the policy daemon (same as `qb daemon`)
    qb [--socket PATH] <COMMAND> [OPTIONS]

COMMANDS:
    daemon [--config PATH]              run the policy daemon; config default: $QB_CONFIG,
                                        else /etc/qb/qbd.toml
    agent                               run the credential-owner agent
    health                              GET /v1/health
    state                               GET /v1/state
    pick --role R (--difficulty N | --vendor V --model M [--effort E] [--login L])
         [--resume-of RUN] [--avoid-vendor V] [--minutes N] [--run-id ID]
                                        POST /v1/pick
    report (--lease ID | --login L) --outcome O [--model M] [--release]
                                        POST /v1/report
    version                             print the version

OPTIONS:
    -s, --socket PATH   unix socket (default: $QB_SOCKET, else /run/qb/qb.sock)
    -h, --help          print this help
    -V, --version       print the version

Client commands print the JSON response and exit 0 on HTTP 2xx, 1 otherwise, 2 on usage or
connection errors. qb sends no telemetry.
";

enum Cmd {
    Daemon(PathBuf),
    Agent,
    Health,
    State,
    Pick(PickRequest),
    Report(ReportRequest),
    Version,
    Help,
}

fn main() -> ExitCode {
    let argv0 = std::env::args_os().next().unwrap_or_default();
    let as_qbd = Path::new(&argv0).file_name().is_some_and(|n| n == "qbd");
    match parse(as_qbd).map_err(|e| e.to_string()).and_then(run) {
        Ok(code) => code,
        Err(msg) => {
            log::error(&format!("qb: {msg}"));
            ExitCode::from(2)
        }
    }
}

fn default_socket() -> PathBuf {
    std::env::var_os("QB_SOCKET").map_or_else(|| PathBuf::from(DEFAULT_SOCKET), PathBuf::from)
}

fn default_config() -> PathBuf {
    std::env::var_os("QB_CONFIG").map_or_else(|| PathBuf::from(DEFAULT_CONFIG), PathBuf::from)
}

fn string(v: OsString) -> Result<String, lexopt::Error> {
    v.into_string().map_err(lexopt::Error::NonUnicodeValue)
}

#[allow(clippy::too_many_lines)] // one flat table of options reads best
fn parse(as_qbd: bool) -> Result<(PathBuf, Cmd), lexopt::Error> {
    use lexopt::prelude::*;
    let mut p = lexopt::Parser::from_env();
    let mut socket = None;
    let mut config = None;
    let mut name: Option<String> = if as_qbd {
        Some("daemon".to_owned())
    } else {
        None
    };
    let mut pick = PickRequest {
        role: String::new(),
        difficulty: None,
        pin: None,
        resume_of: None,
        avoid_vendor: None,
        need: Vec::new(),
        expected_minutes: None,
        run_id: None,
    };
    let (mut vendor, mut model, mut effort, mut pin_login) = (None, None, None, None);
    let mut report = ReportRequest {
        lease_id: None,
        login: None,
        outcome: Outcome::Ok,
        model: None,
        windows: Vec::new(),
        release: false,
    };
    let mut outcome_set = false;

    while let Some(arg) = p.next()? {
        let sub = name.as_deref();
        match arg {
            Short('s') | Long("socket") => socket = Some(PathBuf::from(p.value()?)),
            Short('h') | Long("help") => return Ok((default_socket(), Cmd::Help)),
            Short('V') | Long("version") => return Ok((default_socket(), Cmd::Version)),
            Value(v) if name.is_none() => name = Some(string(v)?),
            Long("config") if sub == Some("daemon") => config = Some(PathBuf::from(p.value()?)),
            Long("role") if sub == Some("pick") => pick.role = string(p.value()?)?,
            Long("difficulty") if sub == Some("pick") => {
                pick.difficulty = Some(p.value()?.parse()?);
            }
            Long("vendor") if sub == Some("pick") => vendor = Some(string(p.value()?)?),
            Long("model") if sub == Some("pick") => model = Some(string(p.value()?)?),
            Long("effort") if sub == Some("pick") => effort = Some(string(p.value()?)?),
            Long("login") if sub == Some("pick") => pin_login = Some(string(p.value()?)?),
            Long("resume-of") if sub == Some("pick") => {
                pick.resume_of = Some(string(p.value()?)?);
            }
            Long("avoid-vendor") if sub == Some("pick") => {
                pick.avoid_vendor = Some(string(p.value()?)?);
            }
            Long("minutes") if sub == Some("pick") => {
                pick.expected_minutes = Some(p.value()?.parse()?);
            }
            Long("run-id") if sub == Some("pick") => pick.run_id = Some(string(p.value()?)?),
            Long("lease") if sub == Some("report") => report.lease_id = Some(string(p.value()?)?),
            Long("login") if sub == Some("report") => report.login = Some(string(p.value()?)?),
            Long("model") if sub == Some("report") => report.model = Some(string(p.value()?)?),
            Long("release") if sub == Some("report") => report.release = true,
            Long("outcome") if sub == Some("report") => {
                let raw = string(p.value()?)?;
                report.outcome = serde_json::from_value(serde_json::Value::String(raw.clone()))
                    .map_err(|_| lexopt::Error::from(format!("unknown outcome `{raw}`")))?;
                outcome_set = true;
            }
            _ => return Err(arg.unexpected()),
        }
    }

    let socket = socket.unwrap_or_else(default_socket);
    let cmd = match name.as_deref() {
        None => Cmd::Help,
        Some("daemon") => Cmd::Daemon(config.unwrap_or_else(default_config)),
        Some("agent") => Cmd::Agent,
        Some("health") => Cmd::Health,
        Some("state") => Cmd::State,
        Some("version") => Cmd::Version,
        Some("pick") => {
            if vendor.is_some() || model.is_some() {
                let (Some(vendor), Some(model)) = (vendor, model) else {
                    return Err("--vendor and --model go together".into());
                };
                pick.pin = Some(Pin {
                    vendor,
                    model,
                    effort,
                    login: pin_login,
                });
            }
            pick.validate()
                .map_err(|e| lexopt::Error::from(e.message()))?;
            Cmd::Pick(pick)
        }
        Some("report") => {
            if !outcome_set {
                return Err("--outcome is required".into());
            }
            if report.lease_id.is_none() && report.login.is_none() {
                return Err("--lease or --login is required".into());
            }
            Cmd::Report(report)
        }
        Some(other) => return Err(format!("unknown command `{other}`").into()),
    };
    Ok((socket, cmd))
}

fn run((socket, cmd): (PathBuf, Cmd)) -> Result<ExitCode, String> {
    let mut out = std::io::stdout().lock();
    match cmd {
        Cmd::Help => {
            let _ = out.write_all(HELP.as_bytes());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Version => {
            let _ = writeln!(out, "qb {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon(config) => daemon(&socket, &config),
        Cmd::Agent => agent::run(&socket).map(|()| ExitCode::SUCCESS),
        Cmd::Health => request(&socket, "GET", paths::HEALTH, None),
        Cmd::State => request(&socket, "GET", paths::STATE, None),
        Cmd::Pick(req) => {
            let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
            request(&socket, "POST", paths::PICK, Some(&body))
        }
        Cmd::Report(req) => {
            let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
            request(&socket, "POST", paths::REPORT, Some(&body))
        }
    }
}

fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<ExitCode, String> {
    let (status, resp) = client::call(socket, method, path, body)
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&resp);
    let _ = out.write_all(b"\n");
    Ok(if (200..300).contains(&status) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn daemon(socket: &Path, file: &Path) -> Result<ExitCode, String> {
    let config = config::load(file).map_err(|e| e.to_string())?;
    let mut core = Core::new(config.core_spec()).map_err(|e| format!("{}: {e}", file.display()))?;
    let mut journal = match &config.journal {
        config::Journal::Off {} => Journal::off(),
        config::Journal::Path { path, rotate_bytes } => {
            let valid = journal::replay(&mut core, path).map_err(|e| e.to_string())?;
            Journal::open(path, *rotate_bytes, valid)
                .map_err(|e| format!("{}: {e}", path.display()))?
        }
    };
    core.tick(server::unix_now());
    let listener = if let Some(l) = listen::from_systemd().map_err(|e| e.to_string())? {
        log::info("qbd: using the socket passed by systemd");
        l
    } else {
        let l = listen::bind(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
        log::info(&format!("qbd: listening on {}", socket.display()));
        l
    };
    let Err(e) = server::serve(&listener, &mut core, &mut journal);
    Err(format!("listener failed: {e}"))
}
