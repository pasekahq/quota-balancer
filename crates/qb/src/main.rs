//! `qb` multicall entry point. Invoked as `qbd` it runs the daemon.

use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use qb::auth::Gate;
use qb::config::Config;
use qb::gateway::core::Gateway;
use qb::gateway::creds::NoRefresher;
use qb::gateway::front;
use qb::hooks::Runner;
use qb::journal::{self, Journal};
use qb::{
    DEFAULT_CONFIG, DEFAULT_SOCKET, agent, api, client, config, listen, log, sandbox, server,
    stream,
};
use qb_core::Core;
use qb_proto::{Outcome, PickRequest, Pin, ReportRequest, paths};
use qb_vendors::claude::Event;

const HELP: &str = "\
qb - pre-flight quota balancer for coding-agent subscriptions

USAGE:
    qbd [--socket PATH] [--config PATH] run the policy daemon (same as `qb daemon`)
    qb [--socket PATH] <COMMAND> [OPTIONS]

COMMANDS:
    daemon [--config PATH]              run the policy daemon; config default: $QB_CONFIG,
                                        else /etc/qb/qbd.toml
    agent --config PATH                 run the credential-owner agent: wait for the daemon's
                                        probe jobs and answer them
    gateway --config PATH               run the model gateway: serve /v1/model/* on the socket
                                        named in its config, picking and reporting via qbd
    health                              GET /v1/health
    state                               GET /v1/state
    why <LEASE>                         GET /v1/why/<LEASE>: why a live lease was granted
    pick --role R (--difficulty N | --vendor V --model M [--effort E] [--login L])
         [--resume-of RUN] [--avoid-vendor V] [--minutes N] [--run-id ID]
                                        POST /v1/pick
    report (--lease ID | --login L) --outcome O [--model M] [--release]
                                        POST /v1/report
    report (--lease ID | --login L) --from-stream-json FILE [--model M] [--release]
                                        POST /v1/report with the windows of the last
                                        rate_limit_event of a stream-json log (- = stdin);
                                        outcome `rejected` if that event was rejected, else
                                        `ok`; exit 1 without an event; lines over 1 MiB
                                        are skipped
    simulate [--config PATH] <JOURNAL> [--at T] [--pick JSON]
                                        replay JOURNAL.1 and JOURNAL against a config
                                        without a daemon and print the /v1/state JSON at T
                                        (default: the last record's time), then the
                                        PickResponse to the PickRequest JSON; writes nothing
    version                             print the version

OPTIONS:
    -s, --socket PATH       unix socket (default: $QB_SOCKET, else /run/qb/qb.sock)
    --bearer-file PATH      send the token in PATH (trailing whitespace trimmed) as
                            `Authorization: Bearer` (default: $QB_BEARER_FILE)
    -h, --help              print this help
    -V, --version           print the version

Client commands print the JSON response and exit 0 on HTTP 2xx, 1 otherwise, 2 on usage or
connection errors. qb sends no telemetry.
";

enum Cmd {
    Daemon(PathBuf),
    Agent(PathBuf),
    Gateway(PathBuf),
    Simulate(Simulate),
    Call(Call),
    Version,
    Help,
}

/// A request to the daemon.
enum Call {
    Health,
    State,
    Why(String),
    Pick(PickRequest),
    Report(ReportRequest),
    /// A report whose outcome and windows come from a stream-json log; `-` is stdin.
    ReportStream(ReportRequest, PathBuf),
}

struct Simulate {
    config: PathBuf,
    journal: PathBuf,
    at: Option<u64>,
    pick: Option<PickRequest>,
}

/// The client name a simulated pick runs as.
const SIMULATE_CLIENT: &str = "simulate";

struct Args {
    socket: PathBuf,
    bearer_file: Option<PathBuf>,
    cmd: Cmd,
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
fn parse(as_qbd: bool) -> Result<Args, lexopt::Error> {
    use lexopt::prelude::*;
    let mut p = lexopt::Parser::from_env();
    let mut socket = None;
    let mut bearer_file = None;
    let mut config = None;
    let mut operand: Option<OsString> = None;
    let (mut at, mut sim_pick) = (None, None);
    let mut from_stream = None;
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

    let early = |cmd| Args {
        socket: default_socket(),
        bearer_file: None,
        cmd,
    };
    while let Some(arg) = p.next()? {
        let sub = name.as_deref();
        match arg {
            Short('s') | Long("socket") => socket = Some(PathBuf::from(p.value()?)),
            Long("bearer-file") => bearer_file = Some(PathBuf::from(p.value()?)),
            Short('h') | Long("help") => return Ok(early(Cmd::Help)),
            Short('V') | Long("version") => return Ok(early(Cmd::Version)),
            Value(v) if name.is_none() => name = Some(string(v)?),
            Value(v) if matches!(sub, Some("why" | "simulate")) && operand.is_none() => {
                operand = Some(v);
            }
            Long("config") if matches!(sub, Some("daemon" | "simulate" | "agent" | "gateway")) => {
                config = Some(PathBuf::from(p.value()?));
            }
            Long("at") if sub == Some("simulate") => at = Some(p.value()?.parse()?),
            Long("pick") if sub == Some("simulate") => {
                let raw = string(p.value()?)?;
                let req: PickRequest = serde_json::from_str(&raw)
                    .map_err(|e| lexopt::Error::from(format!("--pick: {e}")))?;
                sim_pick = Some(req);
            }
            Long("from-stream-json") if sub == Some("report") => {
                from_stream = Some(PathBuf::from(p.value()?));
            }
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
        Some("agent") => Cmd::Agent(config.ok_or("--config is required")?),
        Some("gateway") => Cmd::Gateway(config.ok_or("--config is required")?),
        Some("health") => Cmd::Call(Call::Health),
        Some("state") => Cmd::Call(Call::State),
        Some("version") => Cmd::Version,
        Some("why") => {
            let lease = operand.ok_or("a lease id is required")?;
            Cmd::Call(Call::Why(string(lease)?))
        }
        Some("simulate") => {
            let journal = operand.ok_or("a journal path is required")?;
            if let Some(req) = &sim_pick {
                req.validate()
                    .map_err(|e| lexopt::Error::from(format!("--pick: {}", e.message())))?;
            }
            Cmd::Simulate(Simulate {
                config: config.unwrap_or_else(default_config),
                journal: PathBuf::from(journal),
                at,
                pick: sim_pick,
            })
        }
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
            Cmd::Call(Call::Pick(pick))
        }
        Some("report") => {
            if report.lease_id.is_none() && report.login.is_none() {
                return Err("--lease or --login is required".into());
            }
            match (from_stream, outcome_set) {
                (Some(_), true) => {
                    return Err("--outcome and --from-stream-json are exclusive".into());
                }
                (Some(file), false) => Cmd::Call(Call::ReportStream(report, file)),
                (None, true) => Cmd::Call(Call::Report(report)),
                (None, false) => return Err("--outcome is required".into()),
            }
        }
        Some(other) => return Err(format!("unknown command `{other}`").into()),
    };
    Ok(Args {
        socket,
        bearer_file,
        cmd,
    })
}

fn run(args: Args) -> Result<ExitCode, String> {
    let mut out = std::io::stdout().lock();
    match args.cmd {
        Cmd::Help => {
            let _ = out.write_all(HELP.as_bytes());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Version => {
            let _ = writeln!(out, "qb {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Daemon(config) => daemon(&args.socket, &config),
        Cmd::Agent(file) => {
            let config = config::load_agent(&file).map_err(|e| e.to_string())?;
            let bearer = bearer(args.bearer_file)?;
            let mut fetcher = agent::Https::new();
            let gaps = sandbox::harden(&config)?;
            if !gaps.is_empty() {
                log::warn(&format!(
                    "qb agent: sandbox incomplete: {}",
                    gaps.join("; ")
                ));
            }
            agent::run(&args.socket, bearer.as_deref(), &config, &mut fetcher)
        }
        Cmd::Gateway(file) => gateway(&file),
        Cmd::Simulate(sim) => simulate(sim),
        Cmd::Call(call) => {
            let bearer = bearer(args.bearer_file)?;
            let send = |method, path: &str, body: Option<&[u8]>| {
                request(&args.socket, bearer.as_deref(), method, path, body)
            };
            match call {
                Call::Health => send("GET", paths::HEALTH, None),
                Call::State => send("GET", paths::STATE, None),
                Call::Why(lease) => send("GET", &format!("{}{lease}", paths::WHY), None),
                Call::Pick(req) => send("POST", paths::PICK, Some(&encode(&req)?)),
                Call::Report(req) => send("POST", paths::REPORT, Some(&encode(&req)?)),
                Call::ReportStream(mut req, file) => {
                    let Some(event) = last_event(&file)? else {
                        log::error(&format!(
                            "qb: {}: no rate_limit_event, nothing reported",
                            file.display()
                        ));
                        return Ok(ExitCode::from(1));
                    };
                    req.outcome = if event.status == "rejected" {
                        Outcome::Rejected
                    } else {
                        Outcome::Ok
                    };
                    req.windows = event.windows;
                    send("POST", paths::REPORT, Some(&encode(&req)?))
                }
            }
        }
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

/// The token of `--bearer-file`, else of `$QB_BEARER_FILE`, without trailing whitespace;
/// `None` without either.
fn bearer(file: Option<PathBuf>) -> Result<Option<String>, String> {
    let Some(file) = file.or_else(|| std::env::var_os("QB_BEARER_FILE").map(PathBuf::from)) else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let token = text.trim_end();
    if token.is_empty() {
        return Err(format!("{}: the bearer file is empty", file.display()));
    }
    Ok(Some(token.to_owned()))
}

/// The last `rate_limit_event` of the stream-json log `file`, `-` for stdin.
fn last_event(file: &Path) -> Result<Option<Event>, String> {
    let name = file.display().to_string();
    let found = if file == Path::new("-") {
        stream::last_rate_limit_event(&mut std::io::stdin().lock(), "stdin")
    } else {
        let f = File::open(file).map_err(|e| format!("{name}: {e}"))?;
        stream::last_rate_limit_event(&mut BufReader::new(f), &name)
    };
    found.map_err(|e| format!("{name}: {e}"))
}

fn request(
    socket: &Path,
    bearer: Option<&str>,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<ExitCode, String> {
    let (status, resp) = client::call(socket, method, path, body, bearer)
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

/// The config in `file` and a core built from it, validated as the daemon does.
fn load(file: &Path) -> Result<(Config, Core), String> {
    let config = config::load(file).map_err(|e| e.to_string())?;
    let core = Core::new(config.core_spec()).map_err(|e| format!("{}: {e}", file.display()))?;
    Ok((config, core))
}

fn simulate(sim: Simulate) -> Result<ExitCode, String> {
    let (_, mut core) = load(&sim.config)?;
    let replayed = journal::replay(&mut core, &sim.journal).map_err(|e| e.to_string())?;
    let at = sim.at.or(replayed.last_at).ok_or_else(|| {
        format!(
            "{}: no record to take the time from; pass --at",
            sim.journal.display()
        )
    })?;
    let mut out = std::io::stdout().lock();
    let state = encode(&api::state(&mut core, at))?;
    let _ = out.write_all(&state);
    let _ = out.write_all(b"\n");
    if let Some(req) = sim.pick {
        let (resp, _) = api::decide(&mut core, req, SIMULATE_CLIENT, at)
            .map_err(|e| format!("--pick: {}", e.message()))?;
        let _ = out.write_all(&encode(&resp)?);
        let _ = out.write_all(b"\n");
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs the model gateway of the config in `file`. Vendor adapters are not part of this build
/// yet, so every turn ends with `unavailable`; the credential and qbd paths run in full.
fn gateway(file: &Path) -> Result<ExitCode, String> {
    let config = qb::gateway::config::load(file).map_err(|e| e.to_string())?;
    let qbd_bearer = bearer(config.qbd_bearer_file.clone())?.map(zeroize::Zeroizing::new);
    let listener = if let Some(l) = listen::from_systemd().map_err(|e| e.to_string())? {
        log::info("qb gateway: using the socket passed by systemd");
        l
    } else {
        let l = listen::bind(&config.socket)
            .map_err(|e| format!("{}: {e}", config.socket.display()))?;
        log::info(&format!(
            "qb gateway: listening on {}",
            config.socket.display()
        ));
        l
    };
    let gaps = sandbox::harden_gateway(&config)?;
    if !gaps.is_empty() {
        log::warn(&format!(
            "qb gateway: sandbox incomplete: {}",
            gaps.join("; ")
        ));
    }
    let gateway = Gateway::new(config, Vec::new(), Box::new(NoRefresher), qbd_bearer);
    let Err(e) = front::serve(&listener, &std::sync::Arc::new(gateway));
    Err(format!("listener failed: {e}"))
}

fn daemon(socket: &Path, file: &Path) -> Result<ExitCode, String> {
    let (config, mut core) = load(file)?;
    let mut journal = match &config.journal {
        config::Journal::Off {} => Journal::off(),
        config::Journal::Path { path, rotate_bytes } => {
            let replayed = journal::replay(&mut core, path).map_err(|e| e.to_string())?;
            Journal::open(path, *rotate_bytes, replayed.valid_len)
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
    let mut gate = Gate::new(&config.clients, &config.limits);
    let mut hooks = Runner::new(&config);
    let Err(e) = server::serve(
        &listener,
        &mut core,
        &mut journal,
        &mut hooks,
        &mut gate,
        &config.probe.agents,
    );
    Err(format!("listener failed: {e}"))
}
