//! The daemon loop: sleep in `poll()` until a connection, a parked agent hanging up, SIGHUP or
//! the policy's next deadline, then reap finished hooks, reload the roles and clients on SIGHUP,
//! hand due probe jobs to parked agents, accept, read one request, identify and rate-limit the
//! caller, answer, close.
//!
//! Single thread, one request at a time with short timeouts; an agent's `next` request is parked
//! in the poll set without a timeout until a probe is due. The policy core is owned by this
//! loop, so leases and probes are consistent without locks.

use std::convert::Infallible;
use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use qb_core::{Core, ProbeOutcome};
use qb_proto::{ErrorCode, paths};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::net::RecvFlags;
use rustix::net::sockopt::{Timeout, set_socket_timeout};

use crate::api::{self, Answer, Env, Reply};
use crate::auth::{Denied, Gate};
use crate::config::{self, Config};
use crate::hangup::Hangup;
use crate::hooks::Runner;
use crate::http::{self, MAX_HEAD, Method, ReadError};
use crate::journal::Journal;
use crate::log;

/// Per-connection read/write timeout.
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Most connections parked in `POST /v1/agent/next` at once, over all agents; each agent client
/// parks at most one.
pub const MAX_PARKED: usize = 4;

/// An agent's connection waiting for a probe of one of `logins`.
struct Parked {
    stream: UnixStream,
    client: String,
    logins: Vec<String>,
}

/// Current Unix time in seconds.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The peer's uid from `SO_PEERCRED`, `None` when the kernel does not report one.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|cred| cred.uid.as_raw())
}

/// How long the loop may sleep at `now`: until the core's next deadline, after applying the
/// deadlines already due; `None` (no timeout) when nothing is pending.
pub fn poll_timeout(core: &mut Core, now: u64) -> Option<Duration> {
    loop {
        let at = core.next_deadline()?;
        if at > now {
            return Some(Duration::from_secs(at - now));
        }
        core.tick(now);
    }
}

/// The running config and the file SIGHUP reloads it from.
pub struct Reload {
    /// SIGHUP as a descriptor.
    pub hangup: Hangup,
    /// The config file `qbd` started from.
    pub file: PathBuf,
    /// The config `core` and the gate run.
    pub running: Config,
}

impl Reload {
    /// Reads the config file and its roles file again. A candidate that validates and changes
    /// nothing but `[[roles]]` and `[[clients]]` becomes the running config: `core` takes its
    /// roles, `gate` its clients. Logs one line either way.
    fn run(&mut self, core: &mut Core, gate: &mut Gate) {
        match self.apply(core, gate) {
            Ok(()) => log::info(&format!(
                "qbd: reloaded {}: {} roles, {} clients",
                self.file.display(),
                self.running.roles.len(),
                self.running.clients.len()
            )),
            Err(e) => log::warn(&format!("qbd: reload refused: {e}")),
        }
    }

    fn apply(&mut self, core: &mut Core, gate: &mut Gate) -> Result<(), config::Error> {
        let candidate = config::load(&self.file)?;
        if let Some(key) = self.running.restart_only_change(&candidate) {
            return Err(config::Error {
                file: self.file.clone(),
                field: key.to_owned(),
                reason: "changed; it takes effect only on a restart".to_owned(),
            });
        }
        core.set_roles(candidate.core_spec().roles)
            .map_err(|e| config::Error {
                file: candidate
                    .roles_file
                    .clone()
                    .unwrap_or_else(|| self.file.clone()),
                field: "roles".to_owned(),
                reason: e.to_string(),
            })?;
        *gate = Gate::new(&candidate.clients, &candidate.limits);
        self.running = candidate;
        Ok(())
    }
}

/// Serves connections until the listener fails; `gate` admits callers, the clients in
/// `agents` may wait for probe jobs, state changes go to `journal`, `auth_dead` edges to
/// `hooks`, and SIGHUP on `reload` reloads the roles and clients.
///
/// # Errors
/// The listener cannot be made non-blocking or polled.
pub fn serve(
    listener: &UnixListener,
    core: &mut Core,
    journal: &mut Journal,
    hooks: &mut Runner,
    gate: &mut Gate,
    agents: &[String],
    mut reload: Option<&mut Reload>,
) -> io::Result<Infallible> {
    listener.set_nonblocking(true)?;
    let started = Instant::now();
    let mut buf = Vec::with_capacity(MAX_HEAD);
    let mut parked: Vec<Parked> = Vec::with_capacity(MAX_PARKED);
    let mut hung = Vec::with_capacity(MAX_PARKED);
    loop {
        hooks.reap();
        if let Some(r) = reload.as_deref_mut() {
            if r.hangup.take() {
                r.run(core, gate);
            }
        }
        let now = unix_now();
        dispatch(core, &mut parked, now);
        // A deadline too far away for a timespec is as good as none.
        let timeout = poll_timeout(core, now).and_then(|d| Timespec::try_from(d).ok());
        let mut fds: Vec<PollFd<'_>> = Vec::with_capacity(2 + parked.len());
        fds.push(PollFd::new(listener, PollFlags::IN));
        fds.extend(parked.iter().map(|p| PollFd::new(&p.stream, PollFlags::IN)));
        if let Some(r) = reload.as_deref() {
            fds.push(PollFd::new(&r.hangup, PollFlags::IN));
        }
        match rustix::event::poll(&mut fds, timeout.as_ref()) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
        // A parked agent sends nothing more, so any event means it hung up or broke protocol.
        hung.clear();
        hung.extend(
            fds[1..=parked.len()]
                .iter()
                .map(|f| !f.revents().is_empty()),
        );
        drop(fds);
        let mut i = 0;
        parked.retain(|_| {
            i += 1;
            !hung[i - 1]
        });
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if stream.set_nonblocking(false).is_ok() {
                        let conn = Conn {
                            core: &mut *core,
                            journal: &mut *journal,
                            hooks: &mut *hooks,
                            gate: &mut *gate,
                            agents,
                            parked: &mut parked,
                            started,
                        };
                        conn.handle(stream, &mut buf);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    log::warn(&format!("accept failed: {e}"));
                    std::thread::sleep(Duration::from_millis(50));
                    break;
                }
            }
        }
    }
}

/// Answers every parked agent that has a due probe among its logins, oldest first. A job that
/// cannot be written fails at once, as an `error` result would, instead of waiting out its
/// [`qb_core::PROBE_TIMEOUT_S`].
fn dispatch(core: &mut Core, parked: &mut Vec<Parked>, now: u64) {
    let mut i = 0;
    while i < parked.len() {
        let p = &parked[i];
        let Some(job) = core.probe_next(&p.client, &p.logins, now) else {
            i += 1;
            continue;
        };
        let mut p = parked.remove(i);
        let reply = api::job(&job);
        if let Err(e) = http::write_response(&mut p.stream, reply.status, &reply.body) {
            log::warn(&format!(
                "write of probe job for {} to {} failed: {e}",
                job.login, p.client
            ));
            // The job was just handed to this client, so the core cannot refuse its result.
            let _ = core.probe_result(job.id, &p.client, &ProbeOutcome::Error, now);
        }
    }
}

/// The daemon state one request may touch.
struct Conn<'a> {
    core: &'a mut Core,
    journal: &'a mut Journal,
    hooks: &'a mut Runner,
    gate: &'a mut Gate,
    agents: &'a [String],
    parked: &'a mut Vec<Parked>,
    started: Instant,
}

impl Conn<'_> {
    fn handle(self, mut stream: UnixStream, buf: &mut Vec<u8>) {
        if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
            || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
        {
            return;
        }
        let uid = peer_uid(&stream);
        let reply = match http::read_request(&mut stream, buf) {
            Ok(req) => {
                let env = Env {
                    now: unix_now(),
                    uptime_s: self.started.elapsed().as_secs(),
                };
                match self.gate.admit(uid, req.bearer.as_deref(), Instant::now()) {
                    Ok(caller) => {
                        match api::handle(
                            self.core,
                            self.journal,
                            self.hooks,
                            &req,
                            &caller,
                            self.agents,
                            env,
                        ) {
                            Answer::Reply(reply) => reply,
                            Answer::Park(logins) => {
                                let waiter = Parked {
                                    stream,
                                    client: caller.client,
                                    logins,
                                };
                                match park(self.core, self.parked, waiter, env.now) {
                                    Some((back, reply)) => {
                                        stream = back;
                                        reply
                                    }
                                    None => return,
                                }
                            }
                        }
                    }
                    Err(Denied::Unauthorized)
                        if req.method == Method::Get && req.path == paths::HEALTH =>
                    {
                        api::health(env)
                    }
                    Err(Denied::Unauthorized) => {
                        api::error(ErrorCode::Unauthorized, "unknown client")
                    }
                    Err(Denied::TooManyRequests) => {
                        api::error(ErrorCode::TooManyRequests, "rate limit exceeded")
                    }
                }
            }
            Err(ReadError::Closed | ReadError::Io(_) | ReadError::Refused { .. }) => return,
            Err(ReadError::Malformed) => {
                api::error(ErrorCode::BadRequest, "malformed HTTP request")
            }
            Err(ReadError::HeadTooLarge) => {
                api::error(ErrorCode::PayloadTooLarge, "request too large")
            }
            Err(ReadError::BodyTooLarge { unread }) => {
                discard(&stream, unread);
                api::error(ErrorCode::PayloadTooLarge, "request too large")
            }
            Err(ReadError::LengthRequired) => {
                api::error(ErrorCode::LengthRequired, "Content-Length required")
            }
        };
        send(&mut stream, &reply);
    }
}

/// Parks `waiter`, or gives its stream back with the answer to send now: a due probe job, or
/// 429 when its client already waits or [`MAX_PARKED`] connections do.
fn park(
    core: &mut Core,
    parked: &mut Vec<Parked>,
    waiter: Parked,
    now: u64,
) -> Option<(UnixStream, Reply)> {
    let busy = if parked.iter().any(|p| p.client == waiter.client) {
        Some("this agent is already waiting")
    } else if parked.len() >= MAX_PARKED {
        Some("too many agents are waiting")
    } else {
        None
    };
    if let Some(message) = busy {
        return Some((
            waiter.stream,
            api::error(ErrorCode::TooManyRequests, message),
        ));
    }
    if let Some(job) = core.probe_next(&waiter.client, &waiter.logins, now) {
        return Some((waiter.stream, api::job(&job)));
    }
    parked.push(waiter);
    None
}

fn send(stream: &mut UnixStream, reply: &Reply) {
    if reply.status >= 400 {
        drain_pending(&*stream);
    }
    if let Err(e) = http::write_response(stream, reply.status, &reply.body) {
        log::warn(&format!("write of a {} reply failed: {e}", reply.status));
    }
}

/// Most bytes read and dropped from a rejected request.
const DRAIN_CAP: usize = 1024 * 1024;

/// Reads and drops up to `len` declared body bytes within one I/O timeout, so a client still
/// writing an oversized body finishes its write and reads the 413 instead of `EPIPE`.
pub(crate) fn discard(stream: impl AsFd, len: usize) {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut left = len.min(DRAIN_CAP);
    let mut scratch = [0u8; 4096];
    while left > 0 {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() || set_socket_timeout(&stream, Timeout::Recv, Some(wait)).is_err() {
            break;
        }
        let take = left.min(scratch.len());
        match rustix::net::recv(&stream, &mut scratch[..take], RecvFlags::empty()) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => left -= n,
        }
    }
}

/// Reads whatever the peer already sent and we did not consume, without blocking.
///
/// Closing a stream socket with unread input makes the peer's next read fail with
/// `ECONNRESET`, so a client that sent an oversized or rejected body would lose our error reply.
pub(crate) fn drain_pending(stream: impl AsFd) {
    let mut scratch = [0u8; 4096];
    let mut total = 0;
    while total < DRAIN_CAP {
        match rustix::net::recv(&stream, &mut scratch, RecvFlags::DONTWAIT) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => total += n,
        }
    }
}

#[cfg(test)]
mod tests {
    use qb_core::{
        CandidateSpec, LoginSpec, LoginStatus, OutcomeClass, PickInput, ProbeSpec, ReportInput,
        ReportSubject, RoleSpec, Spec, StepSpec, Target, VendorSpec, WindowSpec,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn core() -> Core {
        let login = |name: &str| LoginSpec {
            name: name.into(),
            vendor: "vendor-a".into(),
        };
        Core::new(Spec {
            vendors: vec![VendorSpec {
                name: "vendor-a".into(),
                windows: Vec::new(),
            }],
            logins: vec![login("login-1"), login("login-2")],
            rate_limit_backoff_s: 60,
            ..Spec::default()
        })
        .expect("valid spec")
    }

    fn rate_limit(core: &mut Core, login: &str, now: u64) {
        let input = ReportInput {
            subject: ReportSubject::Login(login.into()),
            outcome: OutcomeClass::Http429,
            model: None,
            release: false,
            windows: Vec::new(),
        };
        core.report(&input, now).expect("known login");
    }

    fn statuses(core: &Core) -> Vec<LoginStatus> {
        core.snapshot(NOW).logins.iter().map(|l| l.status).collect()
    }

    #[test]
    fn no_deadline_waits_without_timeout() {
        assert_eq!(poll_timeout(&mut core(), NOW), None);
    }

    #[test]
    fn future_deadline_gives_the_remaining_time() {
        let mut core = core();
        rate_limit(&mut core, "login-1", NOW);
        assert_eq!(poll_timeout(&mut core, NOW), Some(Duration::from_secs(60)));
        assert_eq!(
            poll_timeout(&mut core, NOW + 59),
            Some(Duration::from_secs(1))
        );
        assert_eq!(statuses(&core)[0], LoginStatus::RateLimited);
    }

    #[test]
    fn due_deadline_ticks_before_waiting() {
        let mut core = core();
        rate_limit(&mut core, "login-1", NOW);
        rate_limit(&mut core, "login-2", NOW + 30);
        assert_eq!(
            poll_timeout(&mut core, NOW + 60),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            statuses(&core),
            [LoginStatus::Unknown, LoginStatus::RateLimited]
        );
        assert_eq!(poll_timeout(&mut core, NOW + 95), None);
        assert_eq!(
            statuses(&core),
            [LoginStatus::Unknown, LoginStatus::Unknown]
        );
    }

    /// Probes on with a 30 s back-off and a `worker` role on `vendor-a`, whose one window makes
    /// a login without a report stale; a pick has made `login-1` due.
    fn probing() -> Core {
        let mut core = Core::new(Spec {
            vendors: vec![VendorSpec {
                name: "vendor-a".into(),
                windows: vec![WindowSpec {
                    name: "five_hour".into(),
                    length_s: 5 * 3600,
                    t_burn_s: 1800,
                }],
            }],
            logins: vec![LoginSpec {
                name: "login-1".into(),
                vendor: "vendor-a".into(),
            }],
            roles: vec![RoleSpec {
                name: "worker".into(),
                ladder: vec![StepSpec {
                    difficulty: 1,
                    candidates: vec![CandidateSpec {
                        vendor: "vendor-a".into(),
                        model: "model-small".into(),
                        effort: None,
                        tier: 1,
                        cost_per_minute: None,
                    }],
                }],
                reserves: Vec::new(),
            }],
            snapshot_ttl_s: 300,
            lease_ttl_s: 3600,
            probe: Some(ProbeSpec {
                backoff_initial_s: 30,
                backoff_max_s: 120,
            }),
            ..Spec::default()
        })
        .expect("valid spec");
        core.pick(
            &PickInput {
                role: "worker".into(),
                target: Target::Difficulty(1),
                resume_of: None,
                avoid_vendor: None,
                client: "client-a".into(),
                expected_minutes: None,
                run_id: None,
                on_behalf_of: None,
            },
            NOW,
        );
        core
    }

    #[test]
    fn a_job_that_cannot_be_written_fails_at_once() {
        let mut core = probing();
        let (stream, peer) = UnixStream::pair().expect("socket pair");
        drop(peer);
        let mut parked = vec![Parked {
            stream,
            client: "agent-1".into(),
            logins: vec!["login-1".into()],
        }];
        dispatch(&mut core, &mut parked, NOW);
        assert!(parked.is_empty(), "the hung-up agent is no longer parked");
        assert_eq!(core.probe_login(1), None, "the probe is not in flight");
        assert_eq!(
            poll_timeout(&mut core, NOW),
            Some(Duration::from_secs(30)),
            "the back-off ends before the probe timeout would have"
        );
        let logins = ["login-1".to_owned()];
        assert_eq!(
            core.probe_next("agent-2", &logins, NOW),
            None,
            "backing off"
        );
    }
}
