//! `qb agent`: runs as the owner of vendor credentials, waits on the daemon for probe jobs,
//! fetches the login's usage endpoint through a [`Fetcher`] and answers with window numbers only.
//! The protocol is `POST /v1/agent/next` and `POST /v1/agent/result` in `docs/api.md`.

use std::path::Path;
use std::time::Duration;

use qb_proto::{AgentJob, AgentNextRequest, AgentResultRequest, ProbeOutcome, paths};

use crate::config::{AgentConfig, Kind};
use crate::{client, log, server};

/// First wait before reconnecting to an unreachable daemon; it doubles up to [`RECONNECT_MAX`].
pub const RECONNECT_INITIAL: Duration = Duration::from_millis(500);
/// Longest wait between reconnects.
pub const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// A vendor's HTTP answer to a usage request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// HTTP status.
    pub status: u16,
    /// `Retry-After` in seconds, when sent.
    pub retry_after_s: Option<u64>,
    /// Response body.
    pub body: Vec<u8>,
}

/// Fetches a login's usage endpoint.
pub trait Fetcher {
    /// Requests the usage of `login` of `kind` with the credentials in the file `credentials`.
    ///
    /// # Errors
    /// The request could not be made or answered; the message goes to the log.
    fn fetch(&mut self, login: &str, kind: Kind, credentials: &Path) -> Result<Fetched, String>;
}

/// The fetcher of this build: it makes no request, so every probe ends in `error`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHttps;

impl Fetcher for NoHttps {
    fn fetch(&mut self, _: &str, _: Kind, _: &Path) -> Result<Fetched, String> {
        Err("no HTTPS fetcher built in".to_owned())
    }
}

/// The result of `job` for a login of `kind`, from what the fetcher returned at `now`: 200 read
/// by the kind's parser is `ok`, 401 `http_401`, 429 `http_429`; anything else is `error`.
pub fn result(
    job: &AgentJob,
    kind: Kind,
    fetched: Result<Fetched, String>,
    now: u64,
) -> AgentResultRequest {
    let mut out = AgentResultRequest {
        probe_id: job.probe_id.clone(),
        outcome: ProbeOutcome::Error,
        windows: Vec::new(),
        retry_after_s: None,
    };
    let fetched = match fetched {
        Ok(f) => f,
        Err(e) => {
            log::warn(&format!("qb agent: probe of {}: {e}", job.login));
            return out;
        }
    };
    match fetched.status {
        200 => {
            let parsed = match kind {
                Kind::Claude => qb_vendors::claude::usage(&fetched.body),
                Kind::Codex => qb_vendors::codex::usage(&fetched.body, now),
            };
            match parsed {
                Ok(windows) => {
                    out.outcome = ProbeOutcome::Ok;
                    out.windows = windows;
                }
                Err(e) => log::warn(&format!("qb agent: probe of {}: {e}", job.login)),
            }
        }
        401 => out.outcome = ProbeOutcome::Http401,
        429 => {
            out.outcome = ProbeOutcome::Http429;
            out.retry_after_s = fetched.retry_after_s;
        }
        status => log::warn(&format!("qb agent: probe of {}: HTTP {status}", job.login)),
    }
    out
}

/// Answers probe jobs of the daemon at `socket` forever, reconnecting with a doubling wait
/// from [`RECONNECT_INITIAL`] to [`RECONNECT_MAX`] when it is unreachable or refuses.
pub fn run(
    socket: &Path,
    bearer: Option<&str>,
    config: &AgentConfig,
    fetcher: &mut impl Fetcher,
) -> ! {
    let mut wait = RECONNECT_INITIAL;
    loop {
        match answer_one(socket, bearer, config, fetcher) {
            Ok(()) => wait = RECONNECT_INITIAL,
            Err(e) => {
                log::warn(&format!(
                    "qb agent: {e}; retrying in {} ms",
                    wait.as_millis()
                ));
                std::thread::sleep(wait);
                wait = (wait * 2).min(RECONNECT_MAX);
            }
        }
    }
}

/// Waits for one job, probes and posts the result.
fn answer_one(
    socket: &Path,
    bearer: Option<&str>,
    config: &AgentConfig,
    fetcher: &mut impl Fetcher,
) -> Result<(), String> {
    let next = AgentNextRequest {
        logins: config.logins.iter().map(|l| l.name.clone()).collect(),
    };
    let body = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
    let (status, resp) =
        client::call_parked(socket, "POST", paths::AGENT_NEXT, Some(&body), bearer)
            .map_err(|e| format!("{}: {e}", socket.display()))?;
    if status != 200 {
        return Err(format!(
            "{} answered HTTP {status}: {}",
            paths::AGENT_NEXT,
            String::from_utf8_lossy(&resp)
        ));
    }
    let job: AgentJob = serde_json::from_slice(&resp).map_err(|e| format!("invalid job: {e}"))?;
    let login = config
        .logins
        .iter()
        .find(|l| l.name == job.login)
        .ok_or_else(|| format!("job for unlisted login `{}`", job.login))?;
    let answer = fetcher.fetch(&login.name, login.kind, &login.credentials);
    let result = result(&job, login.kind, answer, server::unix_now());
    let body = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    let (status, resp) = client::call(socket, "POST", paths::AGENT_RESULT, Some(&body), bearer)
        .map_err(|e| format!("{}: {e}", socket.display()))?;
    if status != 200 {
        log::warn(&format!(
            "qb agent: result of {} answered HTTP {status}: {}",
            job.probe_id,
            String::from_utf8_lossy(&resp)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn job() -> AgentJob {
        AgentJob {
            probe_id: "p-1".into(),
            login: "login-1".into(),
        }
    }

    const CLAUDE: &str = r#"{"five_hour":{"utilization":6.0,"resets_at":"2027-01-15T13:00:00Z"}}"#;
    const CODEX: &str = r#"{"rate_limit":{"primary_window":{"used_percent":20,"limit_window_seconds":18000,"reset_after_seconds":60}}}"#;

    fn http(status: u16, retry_after_s: Option<u64>, body: &str) -> Fetched {
        Fetched {
            status,
            retry_after_s,
            body: body.as_bytes().to_vec(),
        }
    }

    /// Outcome, `retry_after_s` and window count of the result.
    fn outcome(kind: Kind, fetched: Result<Fetched, String>) -> (ProbeOutcome, Option<u64>, usize) {
        let r = result(&job(), kind, fetched, NOW);
        assert_eq!(r.probe_id, "p-1");
        (r.outcome, r.retry_after_s, r.windows.len())
    }

    #[test]
    fn responses_map_to_outcomes() {
        use ProbeOutcome::{Error, Http401, Http429, Ok as Fine};
        let ok = |kind, status, retry_after_s, body| {
            outcome(kind, Ok(http(status, retry_after_s, body)))
        };
        assert_eq!(ok(Kind::Claude, 200, None, CLAUDE), (Fine, None, 1));
        assert_eq!(ok(Kind::Codex, 200, None, CODEX), (Fine, None, 1));
        assert_eq!(ok(Kind::Claude, 200, None, "[]"), (Error, None, 0));
        assert_eq!(ok(Kind::Codex, 200, None, "not json"), (Error, None, 0));
        assert_eq!(ok(Kind::Claude, 401, None, ""), (Http401, None, 0));
        assert_eq!(ok(Kind::Codex, 429, Some(90), ""), (Http429, Some(90), 0));
        assert_eq!(ok(Kind::Claude, 429, None, ""), (Http429, None, 0));
        assert_eq!(ok(Kind::Claude, 503, Some(5), CLAUDE), (Error, None, 0));
        assert_eq!(
            outcome(Kind::Codex, Err("refused".into())),
            (Error, None, 0)
        );
    }

    #[test]
    fn codex_relative_resets_count_from_now() {
        let r = result(&job(), Kind::Codex, Ok(http(200, None, CODEX)), NOW);
        assert_eq!(r.windows[0].resets_at, Some(NOW + 60));
    }
}
