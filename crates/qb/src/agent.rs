//! `qb agent`: runs as the owner of vendor credentials, waits on the daemon for probe jobs,
//! fetches the login's usage endpoint through a [`Fetcher`] and answers with window numbers only.
//! The protocol is `POST /v1/agent/next` and `POST /v1/agent/result` in `docs/api.md`.

use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;

use qb_proto::{AgentJob, AgentNextRequest, AgentResultRequest, ProbeOutcome, paths};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

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

/// Connect timeout of a usage request.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Limit on a whole usage request: connect, TLS, request and response body.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest usage response body read.
const MAX_BODY: u64 = 1024 * 1024;

/// A usage request: the endpoint and its headers. Header values are zeroized on drop.
pub struct UsageRequest {
    /// The vendor's usage endpoint.
    pub url: &'static str,
    /// Header names and values.
    pub headers: Vec<(&'static str, Zeroizing<String>)>,
}

/// A credential string, borrowed from the file's bytes unless it had JSON escapes; an owned copy
/// is zeroized on drop.
#[derive(Deserialize)]
#[serde(transparent)]
struct Secret<'a>(#[serde(borrow)] Cow<'a, str>);

impl Drop for Secret<'_> {
    fn drop(&mut self) {
        if let Cow::Owned(s) = &mut self.0 {
            s.zeroize();
        }
    }
}

#[derive(Deserialize)]
struct ClaudeFile<'a> {
    #[serde(rename = "claudeAiOauth", borrow)]
    oauth: Option<ClaudeOauth<'a>>,
}

#[derive(Deserialize)]
struct ClaudeOauth<'a> {
    #[serde(rename = "accessToken", borrow)]
    access_token: Option<Secret<'a>>,
}

#[derive(Deserialize)]
struct CodexFile<'a> {
    #[serde(borrow)]
    tokens: Option<CodexTokens<'a>>,
}

#[derive(Deserialize)]
struct CodexTokens<'a> {
    #[serde(borrow)]
    access_token: Option<Secret<'a>>,
    #[serde(borrow)]
    account_id: Option<Secret<'a>>,
}

/// The usage request of a login of `kind` whose credential file holds `credentials`.
///
/// # Errors
/// The bytes are not JSON or a field is missing or unusable; the message names the field and
/// never quotes the file.
pub fn usage_request(kind: Kind, credentials: &[u8]) -> Result<UsageRequest, String> {
    match kind {
        Kind::Claude => {
            let file: ClaudeFile = credential_json(credentials)?;
            let token = file.oauth.and_then(|o| o.access_token);
            let token = header_value("claudeAiOauth.accessToken", token.as_ref())?;
            Ok(UsageRequest {
                url: "https://api.anthropic.com/api/oauth/usage",
                headers: vec![
                    ("Authorization", bearer_value(&token)),
                    (
                        "anthropic-beta",
                        Zeroizing::new("oauth-2025-04-20".to_owned()),
                    ),
                ],
            })
        }
        Kind::Codex => {
            let file: CodexFile = credential_json(credentials)?;
            let (token, account) = file
                .tokens
                .map_or((None, None), |t| (t.access_token, t.account_id));
            let token = header_value("tokens.access_token", token.as_ref())?;
            let mut headers = vec![("Authorization", bearer_value(&token))];
            if let Some(account) = &account {
                let value = header_value("tokens.account_id", Some(account))?;
                headers.push(("ChatGPT-Account-Id", value));
            }
            Ok(UsageRequest {
                url: "https://chatgpt.com/backend-api/wham/usage",
                headers,
            })
        }
    }
}

/// `bytes` as JSON of type `T`; errors give the position or field path, never a value.
fn credential_json<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, String> {
    let syntax = |e: &serde_json::Error| {
        format!("not valid JSON (line {}, column {})", e.line(), e.column())
    };
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut de).map_err(|e| {
        if e.inner().is_data() {
            format!("`{}` has the wrong type", e.path())
        } else {
            syntax(e.inner())
        }
    })?;
    de.end().map_err(|e| syntax(&e))?;
    Ok(value)
}

/// `secret` copied into a zeroizing header value, if it is a non-empty run of visible ASCII.
fn header_value(field: &str, secret: Option<&Secret>) -> Result<Zeroizing<String>, String> {
    let value = secret.map_or("", |s| &s.0);
    if value.is_empty() {
        return Err(format!("no `{field}`"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!("`{field}` is not a visible ASCII string"));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

/// `Bearer <token>`, allocated once at its final size so no unzeroized copy is left behind.
fn bearer_value(token: &str) -> Zeroizing<String> {
    const PREFIX: &str = "Bearer ";
    let mut value = Zeroizing::new(String::with_capacity(PREFIX.len() + token.len()));
    value.push_str(PREFIX);
    value.push_str(token);
    value
}

/// The usage request of `kind` built from the credential file at `path`, read now into a buffer
/// that is zeroized on every path.
///
/// # Errors
/// The file cannot be read or [`usage_request`] fails; the message names the file.
pub fn read_request(kind: Kind, path: &Path) -> Result<UsageRequest, String> {
    let bytes =
        Zeroizing::new(std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?);
    usage_request(kind, &bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// `Retry-After` as whole seconds; an HTTP-date or any other form is `None`.
pub fn retry_after(value: Option<&str>) -> Option<u64> {
    let value = value?.trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Fetches usage endpoints over HTTPS with each login's credential file, read right before the
/// request. Redirects and proxies are not followed.
pub struct Https {
    agent: ureq::Agent,
}

impl Https {
    /// A fetcher with [`CONNECT_TIMEOUT`] and [`TOTAL_TIMEOUT`].
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(TOTAL_TIMEOUT))
            .build();
        Self {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

impl Default for Https {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for Https {
    fn fetch(&mut self, _: &str, kind: Kind, credentials: &Path) -> Result<Fetched, String> {
        let request = read_request(kind, credentials)?;
        let mut builder = self.agent.get(request.url);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value.as_str());
        }
        let sent = builder.call();
        drop(request);
        let mut response = sent.map_err(|e| e.to_string())?;
        let retry_after_s = retry_after(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
        );
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| e.to_string())?;
        Ok(Fetched {
            status: response.status().as_u16(),
            retry_after_s,
            body,
        })
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

    /// A synthetic marker standing in for a token; it must never appear in an error.
    const MARK: &str = "synthetic-token-7f3a";

    /// `(url, headers)` of the request built from `credentials`.
    fn built(kind: Kind, credentials: &str) -> (&'static str, Vec<(&'static str, String)>) {
        let r = usage_request(kind, credentials.as_bytes()).unwrap();
        let headers = r.headers.iter().map(|(n, v)| (*n, v.to_string())).collect();
        (r.url, headers)
    }

    #[test]
    fn requests_carry_the_credential_fields() {
        let claude = format!(
            r#"{{"claudeAiOauth":{{"accessToken":"{MARK}","refreshToken":"other","expiresAt":1}}}}"#
        );
        assert_eq!(
            built(Kind::Claude, &claude),
            (
                "https://api.anthropic.com/api/oauth/usage",
                vec![
                    ("Authorization", format!("Bearer {MARK}")),
                    ("anthropic-beta", "oauth-2025-04-20".to_owned()),
                ]
            )
        );
        let codex = format!(
            r#"{{"OPENAI_API_KEY":null,"tokens":{{"id_token":"x","access_token":"{MARK}","refresh_token":"y","account_id":"acct-1"}}}}"#
        );
        assert_eq!(
            built(Kind::Codex, &codex),
            (
                "https://chatgpt.com/backend-api/wham/usage",
                vec![
                    ("Authorization", format!("Bearer {MARK}")),
                    ("ChatGPT-Account-Id", "acct-1".to_owned()),
                ]
            )
        );
        for account in [r#","account_id":null"#, ""] {
            let codex = format!(r#"{{"tokens":{{"access_token":"{MARK}"{account}}}}}"#);
            assert_eq!(
                built(Kind::Codex, &codex).1,
                vec![("Authorization", format!("Bearer {MARK}"))],
                "{account}"
            );
        }
        let escaped = r#"{"claudeAiOauth":{"accessToken":"token"}}"#;
        assert_eq!(
            built(Kind::Claude, escaped).1[0].1,
            "Bearer token",
            "an escaped token is decoded"
        );
    }

    fn temp_file(name: &str, contents: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("qb-agent-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(name);
        if let Some(c) = contents {
            std::fs::write(&file, c).unwrap();
        }
        file
    }

    #[test]
    fn unusable_credentials_are_errors_naming_file_and_field_without_content() {
        let cases = [
            (Kind::Claude, "missing.json", None, "No such file"),
            (
                Kind::Claude,
                "truncated.json",
                Some(format!(r#"{{"claudeAiOauth":{{"accessToken":"{MARK}"#)),
                "not valid JSON",
            ),
            (
                Kind::Codex,
                "trailing.json",
                Some(format!(
                    r#"{{"tokens":{{"access_token":"{MARK}"}}}} {MARK}"#
                )),
                "not valid JSON",
            ),
            (
                Kind::Claude,
                "no-token.json",
                Some(format!(
                    r#"{{"claudeAiOauth":{{"refreshToken":"{MARK}"}}}}"#
                )),
                "no `claudeAiOauth.accessToken`",
            ),
            (
                Kind::Claude,
                "empty-token.json",
                Some(r#"{"claudeAiOauth":{"accessToken":""}}"#.to_owned()),
                "no `claudeAiOauth.accessToken`",
            ),
            (
                Kind::Codex,
                "no-tokens.json",
                Some(format!(r#"{{"OPENAI_API_KEY":"{MARK}"}}"#)),
                "no `tokens.access_token`",
            ),
            (
                Kind::Codex,
                "number-token.json",
                Some(r#"{"tokens":{"access_token":73519}}"#.to_owned()),
                "`tokens.access_token` has the wrong type",
            ),
            (
                Kind::Codex,
                "object-account.json",
                Some(format!(
                    r#"{{"tokens":{{"access_token":"a","account_id":{{"x":"{MARK}"}}}}}}"#
                )),
                "`tokens.account_id` has the wrong type",
            ),
            (
                Kind::Codex,
                "newline-token.json",
                Some(format!(
                    r#"{{"tokens":{{"access_token":"{MARK}\r\nX-Injected: 1"}}}}"#
                )),
                "`tokens.access_token` is not a visible ASCII string",
            ),
        ];
        for (kind, name, contents, expected) in cases {
            let file = temp_file(name, contents.as_deref());
            let Err(e) = read_request(kind, &file) else {
                panic!("{name} was accepted");
            };
            assert!(e.starts_with(&format!("{}: ", file.display())), "{e}");
            assert!(e.contains(expected), "{name}: {e}");
            assert!(!e.contains(MARK) && !e.contains("73519"), "{name}: {e}");
        }
    }

    #[test]
    fn retry_after_is_whole_seconds_only() {
        assert_eq!(retry_after(Some("120")), Some(120));
        assert_eq!(retry_after(Some(" 7 ")), Some(7));
        for value in [
            "Wed, 21 Oct 2015 07:28:00 GMT",
            "",
            "-5",
            "+5",
            "1.5",
            "99999999999999999999999",
        ] {
            assert_eq!(retry_after(Some(value)), None, "{value}");
        }
        assert_eq!(retry_after(None), None);
    }

    #[test]
    fn codex_relative_resets_count_from_now() {
        let r = result(&job(), Kind::Codex, Ok(http(200, None, CODEX)), NOW);
        assert_eq!(r.windows[0].resets_at, Some(NOW + 60));
    }
}
