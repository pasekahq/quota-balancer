//! `/v1` routing: HTTP request in, status and JSON body out. No sockets here.

use qb_core::{
    Core, LoginStatus as CoreStatus, LoginView, OutcomeClass, PickInput, ProbeError, ProbeJob,
    ProbeOutcome as CoreProbeOutcome, Record, ReportError, ReportInput, ReportSubject,
    Source as CoreSource, Target, Verdict, WindowObservation,
};
use qb_proto::{
    API_VERSION, AgentJob, AgentNextRequest, AgentResultRequest, Decision, ErrorBody, ErrorCode,
    HealthResponse, HealthStatus, LeaseState, LoginState, LoginStatus, Outcome, PickRequest,
    PickRequestError, PickResponse, ProbeOutcome, ReportRequest, ReportResponse, Source,
    StateResponse, WhyResponse, WindowCost, WindowReport, WindowState, paths,
};
use serde::Serialize;

use crate::http::{Method, Request};
use crate::journal::Journal;
use crate::log;

/// Who is calling, as established by the transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Client name used in leases and the journal.
    pub client: String,
}

/// Daemon facts the API reports but does not own.
#[derive(Debug, Clone, Copy)]
pub struct Env {
    /// Current Unix time.
    pub now: u64,
    /// Seconds since start.
    pub uptime_s: u64,
}

/// A response ready to be framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// JSON body.
    pub body: Vec<u8>,
}

/// What the transport does with a routed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Reply now.
    Reply(Reply),
    /// Keep the agent's connection open until a probe of one of these declared logins is due.
    Park(Vec<String>),
}

impl From<Reply> for Answer {
    fn from(reply: Reply) -> Self {
        Self::Reply(reply)
    }
}

fn json<T: Serialize>(status: u16, value: &T) -> Reply {
    match serde_json::to_vec(value) {
        Ok(body) => Reply { status, body },
        Err(_) => Reply {
            status: 500,
            body: br#"{"error":"internal","message":"encode failed"}"#.to_vec(),
        },
    }
}

/// Error reply with the status implied by `code`.
pub fn error(code: ErrorCode, message: impl Into<String>) -> Reply {
    json(
        code.http_status(),
        &ErrorBody {
            error: code,
            message: message.into(),
        },
    )
}

/// Routes one request; granted leases, changed marks and releases go to `journal`. Only the
/// clients in `agents` may wait for probe jobs.
pub fn handle(
    core: &mut Core,
    journal: &mut Journal,
    req: &Request,
    caller: &Caller,
    agents: &[String],
    env: Env,
) -> Answer {
    let known = [
        paths::PICK,
        paths::REPORT,
        paths::STATE,
        paths::HEALTH,
        paths::AGENT_NEXT,
        paths::AGENT_RESULT,
    ];
    let why_of = req.path.strip_prefix(paths::WHY);
    let now = env.now;
    match (req.method, req.path.as_str(), why_of) {
        (Method::Get, paths::HEALTH, _) => health(env).into(),
        (Method::Get, paths::STATE, _) => json(200, &state(core, now)).into(),
        (Method::Get, _, Some(lease)) => why(core, lease, now).into(),
        (Method::Post, paths::PICK, _) => pick(core, journal, &req.body, caller, now).into(),
        (Method::Post, paths::REPORT, _) => report(core, journal, &req.body, caller, now).into(),
        (Method::Post, paths::AGENT_NEXT, _) => agent_next(core, &req.body, caller, agents),
        (Method::Post, paths::AGENT_RESULT, _) => {
            agent_result(core, journal, &req.body, caller, now).into()
        }
        (_, p, why_of) if known.contains(&p) || why_of.is_some() => {
            error(ErrorCode::MethodNotAllowed, "method not allowed").into()
        }
        _ => error(ErrorCode::NotFound, "no such endpoint").into(),
    }
}

/// The `GET /v1/health` reply, which needs no caller.
pub fn health(env: Env) -> Reply {
    json(
        200,
        &HealthResponse {
            status: HealthStatus::Ok,
            api_version: API_VERSION.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            uptime_s: env.uptime_s,
        },
    )
}

fn record(journal: &mut Journal, core: &Core, record: &Record, now: u64) {
    if let Err(e) = journal.record(core, record, now) {
        log::error(&format!("journal write failed: {e}"));
    }
}

fn pick(core: &mut Core, journal: &mut Journal, body: &[u8], caller: &Caller, now: u64) -> Reply {
    let req: PickRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return error(ErrorCode::BadRequest, format!("invalid pick request: {e}")),
    };
    match decide(core, req, &caller.client, now) {
        Ok((resp, lease)) => {
            if let Some(lease) = lease.and_then(|id| core.lease(id)) {
                record(journal, core, &Record::Lease(lease), now);
            }
            json(200, &resp)
        }
        Err(e) => error(ErrorCode::BadRequest, e.message()),
    }
}

/// Answers `req` for `client` at `now`, with the id of the lease a `run` grants.
///
/// # Errors
/// The request breaks an invariant of [`PickRequest::validate`].
pub fn decide(
    core: &mut Core,
    req: PickRequest,
    client: &str,
    now: u64,
) -> Result<(PickResponse, Option<u64>), PickRequestError> {
    req.validate()?;
    let target = match (req.difficulty, req.pin) {
        (Some(d), _) => Target::Difficulty(d),
        (None, Some(p)) => Target::Pin {
            vendor: p.vendor,
            model: p.model,
            effort: p.effort,
            login: p.login,
        },
        (None, None) => return Err(PickRequestError::NoTarget),
    };
    let input = PickInput {
        role: req.role,
        target,
        resume_of: req.resume_of,
        avoid_vendor: req.avoid_vendor,
        client: client.to_owned(),
        expected_minutes: req.expected_minutes,
        run_id: req.run_id,
    };
    Ok(match core.pick(&input, now) {
        Verdict::Run(grant, reason) => {
            let lease = grant.lease;
            let resp = PickResponse {
                decision: Decision::Run,
                reason: reason.as_str().to_owned(),
                lease_id: Some(lease_id(grant.lease)),
                vendor: Some(grant.vendor),
                model: Some(grant.model),
                effort: grant.effort,
                login: Some(grant.login),
                tier: grant.tier,
                retry_after: None,
                stale: grant.stale,
                quota_snapshot_at: grant.snapshot_at,
            };
            (resp, Some(lease))
        }
        Verdict::Wait {
            retry_after,
            reason,
            stale,
        } => {
            let resp = PickResponse {
                retry_after: Some(retry_after),
                stale,
                ..bare(Decision::Wait, reason.as_str())
            };
            (resp, None)
        }
        Verdict::Dead(reason) => (bare(Decision::Dead, reason.as_str()), None),
    })
}

fn bare(decision: Decision, reason: &str) -> PickResponse {
    PickResponse {
        decision,
        reason: reason.to_owned(),
        lease_id: None,
        vendor: None,
        model: None,
        effort: None,
        login: None,
        tier: None,
        retry_after: None,
        stale: false,
        quota_snapshot_at: None,
    }
}

fn report(core: &mut Core, journal: &mut Journal, body: &[u8], caller: &Caller, now: u64) -> Reply {
    let req: ReportRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return error(ErrorCode::BadRequest, format!("invalid report: {e}")),
    };
    let subject = match (req.lease_id, req.login) {
        (Some(lease), _) => match parse_lease_id(&lease) {
            Some(id) => ReportSubject::Lease(id),
            None => return error(ErrorCode::NotFound, "unknown lease"),
        },
        (None, Some(login)) => ReportSubject::Login(login),
        (None, None) => return error(ErrorCode::BadRequest, "`lease_id` or `login` is required"),
    };
    let input = ReportInput {
        subject,
        outcome: outcome(req.outcome),
        model: req.model,
        release: req.release,
        windows: observations(req.windows),
    };
    core.tick(now);
    let login = match &input.subject {
        ReportSubject::Lease(id) => match core.lease(*id) {
            Some(l) if l.client != caller.client => {
                return error(ErrorCode::Forbidden, "lease held by another client");
            }
            l => l.map(|l| l.login),
        },
        ReportSubject::Login(name) => Some(name.clone()),
    };
    let before = login.as_deref().and_then(|l| core.marks(l));
    match core.report(&input, now) {
        Ok(status) => {
            if let Some(login) = login {
                let after = core.marks(&login);
                if let Some(marks) = after.filter(|m| Some(m) != before.as_ref()) {
                    record(journal, core, &Record::Marks { login, marks }, now);
                }
            }
            if let (true, ReportSubject::Lease(id)) = (input.release, &input.subject) {
                record(journal, core, &Record::Release(*id), now);
            }
            json(
                200,
                &ReportResponse {
                    accepted: true,
                    login_status: login_status(status),
                },
            )
        }
        Err(ReportError::UnknownLease) => error(ErrorCode::NotFound, "unknown lease"),
        Err(ReportError::UnknownLogin) => error(ErrorCode::NotFound, "unknown login"),
        Err(ReportError::InvalidUtilization) => error(
            ErrorCode::BadRequest,
            "window utilization must be within 0.0..=1.0",
        ),
        Err(ReportError::MissingModel) => error(
            ErrorCode::BadRequest,
            "`model_unavailable` on a login needs `model`",
        ),
        Err(ReportError::UnknownModel) => error(ErrorCode::NotFound, "unknown model"),
    }
}

fn agent_next(core: &Core, body: &[u8], caller: &Caller, agents: &[String]) -> Answer {
    if !agents.contains(&caller.client) {
        return error(ErrorCode::Forbidden, "not a probe agent").into();
    }
    let req: AgentNextRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return error(ErrorCode::BadRequest, format!("invalid next request: {e}")).into(),
    };
    if req.logins.is_empty() {
        return error(ErrorCode::BadRequest, "`logins` is empty").into();
    }
    if let Some(unknown) = req.logins.iter().find(|l| core.marks(l).is_none()) {
        return error(ErrorCode::BadRequest, format!("unknown login `{unknown}`")).into();
    }
    Answer::Park(req.logins)
}

/// The `POST /v1/agent/next` reply that hands out `job`.
pub fn job(job: &ProbeJob) -> Reply {
    json(
        200,
        &AgentJob {
            probe_id: format!("{PROBE_PREFIX}{}", job.id),
            login: job.login.clone(),
        },
    )
}

fn agent_result(
    core: &mut Core,
    journal: &mut Journal,
    body: &[u8],
    caller: &Caller,
    now: u64,
) -> Reply {
    let req: AgentResultRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return error(ErrorCode::BadRequest, format!("invalid probe result: {e}")),
    };
    let Some(id) = req
        .probe_id
        .strip_prefix(PROBE_PREFIX)
        .and_then(|n| n.parse().ok())
    else {
        return error(ErrorCode::NotFound, "unknown probe");
    };
    let outcome = match req.outcome {
        ProbeOutcome::Ok => CoreProbeOutcome::Ok(observations(req.windows)),
        ProbeOutcome::Http401 => CoreProbeOutcome::Http401,
        ProbeOutcome::Http429 => CoreProbeOutcome::Http429 {
            retry_after_s: req.retry_after_s,
        },
        ProbeOutcome::Error => CoreProbeOutcome::Error,
    };
    match core.probe_result(id, &caller.client, &outcome, now) {
        Ok((login, status)) => {
            if outcome == CoreProbeOutcome::Http401 {
                if let Some(marks) = core.marks(&login) {
                    record(journal, core, &Record::Marks { login, marks }, now);
                }
            }
            json(
                200,
                &ReportResponse {
                    accepted: true,
                    login_status: login_status(status),
                },
            )
        }
        Err(ProbeError::UnknownProbe) => error(ErrorCode::NotFound, "unknown probe"),
        Err(ProbeError::OtherClient) => {
            error(ErrorCode::Forbidden, "probe handed to another client")
        }
        Err(ProbeError::InvalidUtilization) => error(
            ErrorCode::BadRequest,
            "window utilization must be within 0.0..=1.0",
        ),
    }
}

fn observations(windows: Vec<WindowReport>) -> Vec<WindowObservation> {
    windows
        .into_iter()
        .map(|w| WindowObservation {
            name: w.name,
            used: w.utilization,
            resets_at: w.resets_at,
        })
        .collect()
}

/// The `GET /v1/state` body at `now`, after the deadlines due by then.
pub fn state(core: &mut Core, now: u64) -> StateResponse {
    core.tick(now);
    let snap = core.snapshot(now);
    StateResponse {
        api_version: API_VERSION.to_owned(),
        now,
        logins: snap.logins.into_iter().map(login_state).collect(),
        leases: snap
            .leases
            .into_iter()
            .map(|l| LeaseState {
                lease_id: lease_id(l.id),
                login: l.login,
                model: l.model,
                client: l.client,
                run_id: l.run_id,
                expires_at: l.expires_at,
            })
            .collect(),
    }
}

fn login_state(l: LoginView) -> LoginState {
    LoginState {
        login: l.name,
        vendor: l.vendor,
        status: login_status(l.status),
        dead_until: l.dead_until,
        windows: l
            .windows
            .into_iter()
            .map(|w| WindowState {
                name: w.name,
                used: w.used,
                reserved: w.reserved,
                resets_at: w.resets_at,
                observed_at: w.observed_at,
                source: source(w.source),
                stale: w.stale,
            })
            .collect(),
    }
}

fn why(core: &mut Core, lease: &str, now: u64) -> Reply {
    core.tick(now);
    let Some(lease) = parse_lease_id(lease).and_then(|id| core.lease(id)) else {
        return error(ErrorCode::NotFound, "unknown lease");
    };
    let Some(login) = core
        .snapshot(now)
        .logins
        .into_iter()
        .find(|l| l.name == lease.login)
    else {
        return error(ErrorCode::Internal, "lease on an unknown login");
    };
    let login = login_state(login);
    json(
        200,
        &WhyResponse {
            lease_id: lease_id(lease.id),
            login: lease.login,
            model: lease.model,
            client: lease.client,
            run_id: lease.run_id,
            expires_at: lease.expires_at,
            cost: login
                .windows
                .iter()
                .zip(lease.cost)
                .map(|(w, cost)| WindowCost {
                    name: w.name.clone(),
                    cost,
                })
                .collect(),
            reason: lease.reason.map(|r| r.as_str().to_owned()),
            login_state: login,
        },
    )
}

const LEASE_PREFIX: &str = "l-";
const PROBE_PREFIX: &str = "p-";

fn lease_id(id: u64) -> String {
    format!("{LEASE_PREFIX}{id}")
}

fn parse_lease_id(wire: &str) -> Option<u64> {
    wire.strip_prefix(LEASE_PREFIX)?.parse().ok()
}

fn outcome(o: Outcome) -> OutcomeClass {
    match o {
        Outcome::Ok => OutcomeClass::Ok,
        Outcome::UsageLimit => OutcomeClass::UsageLimit,
        Outcome::Rejected => OutcomeClass::Rejected,
        Outcome::Http401 => OutcomeClass::Http401,
        Outcome::Http429 => OutcomeClass::Http429,
        Outcome::ModelUnavailable => OutcomeClass::ModelUnavailable,
        Outcome::Error => OutcomeClass::Error,
    }
}

fn login_status(s: CoreStatus) -> LoginStatus {
    match s {
        CoreStatus::Ok => LoginStatus::Ok,
        CoreStatus::RateLimited => LoginStatus::RateLimited,
        CoreStatus::Exhausted => LoginStatus::Exhausted,
        CoreStatus::AuthStale => LoginStatus::AuthStale,
        CoreStatus::AuthDead => LoginStatus::AuthDead,
        CoreStatus::Unknown => LoginStatus::Unknown,
    }
}

fn source(s: CoreSource) -> Source {
    match s {
        CoreSource::Stream => Source::Stream,
        CoreSource::Probe => Source::Probe,
        CoreSource::Assumed => Source::Assumed,
    }
}
