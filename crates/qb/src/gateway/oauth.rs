//! The token endpoint client of OAuth logins: the [`Refresher`]'s refresh grant and the
//! authorization code grant of `qb login`, over ureq with rustls to the login's `token_url`, else
//! the vendor's token endpoints in order. The protocols are in `docs/anthropic.md`, "OAuth token
//! refresh" and "OAuth sign-in", and `docs/openai.md`, "Serving the upstream" and "OAuth sign-in".

use std::time::Duration;

use qb_anthropic::request::identity as anthropic;
use qb_openai::request::identity as openai;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::base64url;
use super::config::{CredentialKind, GatewayLogin};
use super::creds::{RefreshError, Refreshed, Refresher, Secret};
use super::vendor::{self, CONNECT_TIMEOUT};
use crate::server::unix_now;

/// Bound of one token request, from connect to the end of the answer.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest token answer read.
const MAX_ANSWER: u64 = 64 << 10;

/// OAuth error codes that mean the refresh token is spent: the login needs a new sign-in.
const SPENT: [&str; 4] = [
    "invalid_grant",
    "refresh_token_expired",
    "refresh_token_reused",
    "refresh_token_invalidated",
];

/// The vendor whose token endpoint refreshes a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Issuer {
    /// An `oauth_anthropic` login: the answer must carry `expires_in`.
    Anthropic,
    /// A `chatgpt_oauth` login: without `expires_in`, the `exp` of the returned JWTs.
    Openai,
}

impl Issuer {
    fn client_id(self) -> &'static str {
        match self {
            Self::Anthropic => anthropic::OAUTH_CLIENT_ID,
            Self::Openai => openai::OAUTH_CLIENT_ID,
        }
    }

    fn user_agent(self) -> &'static str {
        match self {
            Self::Anthropic => anthropic::OAUTH_TOKEN_USER_AGENT,
            Self::Openai => openai::CHATGPT_USER_AGENT,
        }
    }
}

/// The issuer of an OAuth login and its token endpoints in the order they are tried.
struct Grant {
    issuer: Issuer,
    urls: Vec<String>,
}

/// The tokens of a 2xx token answer, zeroized on drop.
pub(super) struct Tokens {
    pub(super) access_token: Zeroizing<String>,
    pub(super) refresh_token: Option<Zeroizing<String>>,
    pub(super) id_token: Option<Zeroizing<String>>,
    /// Unix time the access token expires.
    pub(super) expires_at: u64,
}

/// Why a token request failed. `message` names the endpoint, the status and the OAuth error
/// code, never a value.
pub(super) struct GrantError {
    /// The status of a non-2xx answer below 500, which ends the request; `None` for a transport
    /// failure or 5xx at every endpoint, or a 2xx without the required fields.
    pub(super) status: Option<u16>,
    /// The OAuth error code of that answer.
    code: Option<String>,
    pub(super) message: String,
}

impl GrantError {
    fn failed(message: String) -> Self {
        Self {
            status: None,
            code: None,
            message,
        }
    }
}

/// `application/x-www-form-urlencoded`.
const FORM: &str = "application/x-www-form-urlencoded";

impl Grant {
    /// The grant of `login`: its `token_url`, else the vendor's endpoints; `None` for an API key.
    fn of(login: &GatewayLogin) -> Option<Self> {
        let (issuer, default): (_, &[&str]) = match login.kind {
            CredentialKind::OauthAnthropic => (Issuer::Anthropic, &anthropic::OAUTH_TOKEN_URLS),
            CredentialKind::ChatgptOauth => (Issuer::Openai, &[openai::OAUTH_TOKEN_URL]),
            CredentialKind::ApiKey => return None,
        };
        let urls = match &login.token_url {
            Some(url) => vec![url.clone()],
            None => default.iter().map(|u| (*u).to_owned()).collect(),
        };
        Some(Self { issuer, urls })
    }
}

/// Refreshes the tokens of `oauth_anthropic` and `chatgpt_oauth` logins at the endpoints their
/// entries name.
pub struct OauthRefresher {
    config: ureq::config::Config,
}

impl Default for OauthRefresher {
    fn default() -> Self {
        Self::new()
    }
}

impl OauthRefresher {
    /// A refresher with [`CONNECT_TIMEOUT`] and [`REFRESH_TIMEOUT`], no proxy and no redirects.
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REFRESH_TIMEOUT))
            .build();
        Self { config }
    }

    /// The refresh grant of `refresh_token` at each endpoint of `grant` until one answers.
    fn exchange(&self, grant: &Grant, refresh_token: &str) -> Result<Refreshed, RefreshError> {
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", grant.issuer.client_id()),
        ]);
        let tokens = self
            .request(grant, FORM, body.as_bytes())
            .map_err(|e| RefreshError {
                rejected: e.status.is_some_and(|s| {
                    s != 429
                        && (matches!(s, 400 | 401)
                            || e.code.as_deref().is_some_and(|c| SPENT.contains(&c)))
                }),
                message: e.message,
            })?;
        Ok(Refreshed {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: tokens.expires_at,
        })
    }

    /// The authorization code grant of a sign-in of `login`: `code`, the `state` sent and the
    /// PKCE `verifier`, as JSON to Anthropic and as a form to OpenAI, at each endpoint of the
    /// login until one answers.
    pub(super) fn exchange_code(
        &self,
        login: &GatewayLogin,
        code: &str,
        state: &str,
        verifier: &str,
    ) -> Result<Tokens, GrantError> {
        let Some(grant) = Grant::of(login) else {
            return Err(GrantError::failed(format!(
                "`{}` is not an OAuth login",
                login.name
            )));
        };
        match grant.issuer {
            Issuer::Anthropic => {
                let fields = CodeGrant {
                    grant_type: "authorization_code",
                    code,
                    state,
                    client_id: anthropic::OAUTH_CLIENT_ID,
                    redirect_uri: anthropic::OAUTH_REDIRECT_URI,
                    code_verifier: verifier,
                };
                let mut body = Zeroizing::new(Vec::with_capacity(
                    256 + code.len() + state.len() + verifier.len(),
                ));
                serde_json::to_writer(&mut *body, &fields)
                    .map_err(|e| GrantError::failed(format!("encode failed: {e}")))?;
                self.request(&grant, "application/json", &body)
            }
            Issuer::Openai => {
                let body = form(&[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("redirect_uri", openai::OAUTH_REDIRECT_URI),
                    ("client_id", openai::OAUTH_CLIENT_ID),
                    ("code_verifier", verifier),
                ]);
                self.request(&grant, FORM, body.as_bytes())
            }
        }
    }

    /// One token request with `body` at each endpoint of `grant` until one answers.
    fn request(
        &self,
        grant: &Grant,
        content_type: &str,
        body: &[u8],
    ) -> Result<Tokens, GrantError> {
        let mut failures = Vec::new();
        for url in &grant.urls {
            match self.post(grant.issuer, url, content_type, body) {
                Ok(tokens) => return Ok(tokens),
                Err(Failed::Next(why)) => failures.push(why),
                Err(Failed::Last(e)) => return Err(e),
            }
        }
        Err(GrantError::failed(failures.join("; ")))
    }

    /// One token request of `issuer` to `url` with `body`.
    fn post(
        &self,
        issuer: Issuer,
        url: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<Tokens, Failed> {
        let agent = vendor::agent(&self.config);
        let mut response = agent
            .post(url)
            .header("content-type", content_type)
            .header("accept", "application/json")
            .header("user-agent", issuer.user_agent())
            .send(body)
            .map_err(|e| Failed::Next(format!("{url}: request failed: {e}")))?;
        let status = response.status().as_u16();
        if status >= 500 {
            return Err(Failed::Next(format!("{url}: HTTP {status}")));
        }
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_vec()
            .map_err(|e| Failed::Next(format!("{url}: answer cut: {e}")))?;
        let bytes = Zeroizing::new(bytes);
        let last = |what: &str| Failed::Last(GrantError::failed(format!("{url}: {what}")));
        if !(200..300).contains(&status) {
            let code = refusal_code(&bytes);
            let message = match &code {
                Some(code) => format!("{url}: HTTP {status} {code}"),
                None => format!("{url}: HTTP {status}"),
            };
            return Err(Failed::Last(GrantError {
                status: Some(status),
                code,
                message,
            }));
        }
        let answer: Answer = serde_json::from_slice(&bytes).map_err(|e| {
            let what = format!(
                "malformed answer (line {}, column {})",
                e.line(),
                e.column()
            );
            last(&what)
        })?;
        let Some(access_token) = answer.access_token else {
            return Err(last("answer has no `access_token`"));
        };
        let expires_at = match (answer.expires_in, issuer) {
            (Some(expires_in), _) => unix_now().saturating_add(expires_in),
            (None, Issuer::Anthropic) => return Err(last("answer has no `expires_in`")),
            (None, Issuer::Openai) => {
                let id_token = answer.id_token.as_ref().and_then(|t| jwt_exp(&t.0));
                let Some(exp) = id_token.or_else(|| jwt_exp(&access_token.0)) else {
                    return Err(last(
                        "answer has no `expires_in` and no token with an `exp` claim",
                    ));
                };
                exp
            }
        };
        Ok(Tokens {
            access_token: access_token.0,
            refresh_token: answer.refresh_token.map(|s| s.0),
            id_token: answer.id_token.map(|s| s.0),
            expires_at,
        })
    }
}

/// Why one token request failed: try the next endpoint, or end the request with this error.
enum Failed {
    Next(String),
    Last(GrantError),
}

/// The JSON body of Anthropic's authorization code grant.
#[derive(Serialize)]
struct CodeGrant<'a> {
    grant_type: &'static str,
    code: &'a str,
    state: &'a str,
    client_id: &'static str,
    redirect_uri: &'static str,
    code_verifier: &'a str,
}

/// The fields of a token answer the gateway uses; others are ignored.
#[derive(Deserialize)]
struct Answer {
    access_token: Option<Secret>,
    refresh_token: Option<Secret>,
    id_token: Option<Secret>,
    expires_in: Option<u64>,
}

/// A refusal: the OAuth `{"error": "code"}` or OpenAI's `{"error": {"code": "code"}}`.
#[derive(Deserialize)]
struct Refusal {
    error: Option<RefusalError>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RefusalError {
    Code(String),
    Object { code: Option<String> },
}

/// The error code of a refusal body, when it is lowercase letters and `_`, at most 64 bytes.
fn refusal_code(body: &[u8]) -> Option<String> {
    let code = match serde_json::from_slice::<Refusal>(body).ok()?.error? {
        RefusalError::Code(code) => code,
        RefusalError::Object { code } => code?,
    };
    plain_code(&code).then_some(code)
}

/// Whether `code` is an OAuth error code safe to log: lowercase letters and `_`, at most 64
/// bytes.
pub(super) fn plain_code(code: &str) -> bool {
    code.len() <= 64 && code.bytes().all(|b| b == b'_' || b.is_ascii_lowercase())
}

/// The `exp` claim of a JWT's payload, read as base64url JSON without a signature check.
fn jwt_exp(token: &str) -> Option<u64> {
    #[derive(Deserialize)]
    struct Claims {
        exp: Option<u64>,
    }
    let payload = base64url::decode(token.split('.').nth(1)?)?;
    serde_json::from_slice::<Claims>(&payload).ok()?.exp
}

impl Refresher for OauthRefresher {
    fn refresh(
        &self,
        login: &GatewayLogin,
        refresh_token: &str,
    ) -> Result<Refreshed, RefreshError> {
        let Some(grant) = Grant::of(login) else {
            return Err(RefreshError {
                rejected: false,
                message: format!("`{}` is not an OAuth login", login.name),
            });
        };
        self.exchange(&grant, refresh_token)
    }
}

/// The form body of `fields`, each value percent-encoded.
fn form(fields: &[(&str, &str)]) -> Zeroizing<String> {
    let len: usize = fields.iter().map(|(k, v)| k.len() + 3 * v.len() + 2).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    for (i, (key, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        percent_encode(value, &mut out);
    }
    out
}

/// Appends `s` percent-encoded, every byte but the unreserved ones of RFC 3986.
pub(super) fn percent_encode(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A synthetic marker standing in for a token; it must never appear in an error.
    const MARK: &str = "test-token-c41e";

    /// A loopback token endpoint that answers each request with the next `(status, body)`; its
    /// URL and the bodies it received.
    fn endpoint(answers: Vec<(u16, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/oauth/token", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        std::thread::spawn(move || {
            for (answer, conn) in answers.into_iter().zip(listener.incoming()) {
                let mut conn = conn.unwrap();
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    conn.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0u8; length];
                conn.read_exact(&mut body).unwrap();
                log.lock().unwrap().push(String::from_utf8(body).unwrap());
                let (status, body) = answer;
                let out = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                conn.write_all(out.as_bytes()).unwrap();
            }
        });
        (url, received)
    }

    /// A refresher whose one login exchanges its token at `urls`.
    struct Granted(OauthRefresher, Grant);

    impl Granted {
        fn refresh(&self, _login: &str, token: &str) -> Result<Refreshed, RefreshError> {
            self.0.exchange(&self.1, token)
        }
    }

    fn refresher_of(issuer: Issuer, urls: &[&str]) -> Granted {
        let urls = urls.iter().map(|u| (*u).to_owned()).collect();
        Granted(OauthRefresher::new(), Grant { issuer, urls })
    }

    fn refresher(urls: &[&str]) -> Granted {
        refresher_of(Issuer::Anthropic, urls)
    }

    fn granted(refresh: Option<&str>) -> (u16, String) {
        let rotated = refresh.map_or(String::new(), |r| format!(r#","refresh_token":"{r}""#));
        let body = format!(
            r#"{{"token_type":"Bearer","access_token":"access-{MARK}","expires_in":28800{rotated},"scope":"user:inference"}}"#
        );
        (200, body)
    }

    fn closed_port() -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/v1/oauth/token", l.local_addr().unwrap())
    }

    #[test]
    fn a_grant_posts_the_form_and_sets_the_expiry_from_expires_in() {
        let (url, received) = endpoint(vec![
            granted(Some(&format!("refresh-{MARK}-2"))),
            granted(None),
        ]);
        let r = refresher(&[&url]);
        let before = unix_now();
        let fresh = r.refresh("login-1", "test-refresh+/=").unwrap();
        let after = unix_now();
        assert_eq!(*fresh.access_token, format!("access-{MARK}"));
        assert_eq!(
            fresh.refresh_token.as_deref().map(String::as_str),
            Some(format!("refresh-{MARK}-2").as_str())
        );
        assert!((before + 28800..=after + 28800).contains(&fresh.expires_at));
        assert_eq!(
            received.lock().unwrap()[0],
            format!(
                "grant_type=refresh_token&refresh_token=test-refresh%2B%2F%3D&client_id={}",
                anthropic::OAUTH_CLIENT_ID
            )
        );
        let kept = r.refresh("login-1", "test-refresh").unwrap();
        assert!(
            kept.refresh_token.is_none(),
            "no rotation keeps the old one"
        );
    }

    #[test]
    fn a_5xx_or_unreachable_primary_falls_back_to_the_next_endpoint() {
        let (primary, first) = endpoint(vec![(503, "{}".into())]);
        let (fallback, second) = endpoint(vec![granted(None), granted(None)]);
        let r = refresher(&[&primary, &fallback]);
        assert!(r.refresh("login-1", "test-refresh").is_ok());
        let r = refresher(&[&closed_port(), &fallback]);
        assert!(r.refresh("login-1", "test-refresh").is_ok());
        assert_eq!(first.lock().unwrap().len(), 1);
        assert_eq!(second.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_refused_refresh_token_is_rejected_without_fallback() {
        for (status, body) in [
            (
                400,
                r#"{"error":"invalid_grant","error_description":"Refresh token not found or invalid"}"#,
            ),
            (401, "{}"),
            (403, r#"{"error":"invalid_grant"}"#),
        ] {
            let (primary, _) = endpoint(vec![(status, body.into())]);
            let (fallback, unused) = endpoint(vec![granted(None)]);
            let e = refresher(&[&primary, &fallback])
                .refresh("login-1", MARK)
                .err()
                .unwrap();
            assert!(e.rejected, "{status}: {e:?}");
            assert!(e.message.contains(&format!("HTTP {status}")), "{e:?}");
            assert!(!e.message.contains(MARK), "{e:?}");
            assert_eq!(unused.lock().unwrap().len(), 0, "{status}");
        }
    }

    #[test]
    fn transport_5xx_and_malformed_answers_are_not_rejected() {
        let cases = [
            (
                vec![(500, "{}".to_owned()), (502, "{}".to_owned())],
                "HTTP 502",
            ),
            (
                vec![(429, r#"{"error":"rate_limited"}"#.to_owned())],
                "HTTP 429",
            ),
            (
                vec![(200, format!(r#"{{"access_token":"{MARK}""#))],
                "malformed answer",
            ),
            (
                vec![(
                    200,
                    format!(r#"{{"access_token":"{MARK}","expires_in":"soon"}}"#),
                )],
                "malformed answer",
            ),
            (
                vec![(
                    200,
                    format!(r#"{{"refresh_token":"{MARK}","expires_in":60}}"#),
                )],
                "no `access_token`",
            ),
            (
                vec![(200, format!(r#"{{"access_token":"{MARK}"}}"#))],
                "no `expires_in`",
            ),
        ];
        for (answers, want) in cases {
            let n = answers.len();
            let (url, _) = endpoint(answers);
            let urls = vec![url.as_str(); n];
            let e = refresher(&urls).refresh("login-1", MARK).err().unwrap();
            assert!(!e.rejected, "{want}: {e:?}");
            assert!(e.message.contains(want), "{want}: {e:?}");
            assert!(!e.message.contains(MARK), "{want}: {e:?}");
        }
        let e = refresher(&[&closed_port()])
            .refresh("login-1", MARK)
            .err()
            .unwrap();
        assert!(!e.rejected && e.message.contains("request failed"), "{e:?}");
    }

    #[test]
    fn only_oauth_logins_refresh() {
        let login = GatewayLogin {
            name: "login-2".into(),
            kind: CredentialKind::ApiKey,
            api: crate::gateway::config::Api::Anthropic,
            base_url: None,
            referer: None,
            title: None,
            token_url: None,
            credentials: "/creds/login-2.json".into(),
            spend_cap: None,
        };
        let e = OauthRefresher::new().refresh(&login, MARK).err().unwrap();
        assert!(!e.rejected);
        assert!(e.message.contains("`login-2` is not an OAuth login"));
    }

    /// A JWT with the payload `claims` and no valid signature.
    fn jwt(claims: &serde_json::Value) -> String {
        const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut payload = String::new();
        for chunk in claims.to_string().as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..=chunk.len() {
                payload.push(char::from(ABC[(n >> (18 - 6 * i) & 63) as usize]));
            }
        }
        format!("e30.{payload}.c2lnbmF0dXJl")
    }

    fn codex_grant(fields: &serde_json::Value) -> (u16, String) {
        (200, fields.to_string())
    }

    #[test]
    fn a_chatgpt_grant_sends_the_codex_client_id_and_dates_the_token_by_its_jwts() {
        let access = jwt(&serde_json::json!({"exp": 1_900_000_200, "sub": MARK}));
        let id_token = jwt(&serde_json::json!({"exp": 1_900_000_100, "email": MARK}));
        let (url, received) = endpoint(vec![
            codex_grant(&serde_json::json!({
                "access_token": access, "id_token": id_token, "expires_in": 3600,
                "refresh_token": format!("refresh-{MARK}-2"),
            })),
            codex_grant(&serde_json::json!({"access_token": access, "id_token": id_token})),
            codex_grant(&serde_json::json!({"access_token": access})),
            codex_grant(&serde_json::json!({"access_token": MARK, "id_token": "a.%%.b"})),
        ]);
        let r = refresher_of(Issuer::Openai, &[&url]);
        let before = unix_now();
        let first = r.refresh("login-1", "test-refresh+1").unwrap();
        assert!((before + 3600..=unix_now() + 3600).contains(&first.expires_at));
        assert_eq!(*first.access_token, access);
        assert_eq!(
            first.refresh_token.as_deref().map(String::as_str),
            Some(format!("refresh-{MARK}-2").as_str())
        );
        let by_id = r.refresh("login-1", "test-refresh").unwrap();
        assert_eq!(by_id.expires_at, 1_900_000_100);
        assert!(
            by_id.refresh_token.is_none(),
            "no rotation keeps the old one"
        );
        let by_access = r.refresh("login-1", "test-refresh").unwrap();
        assert_eq!(by_access.expires_at, 1_900_000_200);
        let e = r.refresh("login-1", "test-refresh").err().unwrap();
        assert!(!e.rejected, "{e:?}");
        assert!(e.message.contains("no `expires_in`"), "{e:?}");
        assert!(!e.message.contains(MARK), "{e:?}");
        assert_eq!(
            received.lock().unwrap()[0],
            format!(
                "grant_type=refresh_token&refresh_token=test-refresh%2B1&client_id={}",
                openai::OAUTH_CLIENT_ID
            )
        );
    }

    #[test]
    fn a_chatgpt_refusal_is_rejected_on_400_401_or_a_spent_code_only() {
        let echo = format!(r#"{{"error":{{"code":"x","message":"{MARK}"}}}}"#);
        let cases = [
            (400, r#"{"error":"invalid_grant"}"#.to_owned(), true),
            (401, "{}".to_owned(), true),
            (
                403,
                format!(r#"{{"error":{{"code":"refresh_token_reused","message":"{MARK}"}}}}"#),
                true,
            ),
            (403, echo, false),
            (
                429,
                format!(r#"{{"error":{{"code":"refresh_token_expired","detail":"{MARK}"}}}}"#),
                false,
            ),
            (
                503,
                format!(r#"{{"error":"invalid_grant","detail":"{MARK}"}}"#),
                false,
            ),
        ];
        for (status, body, rejected) in cases {
            let (url, _) = endpoint(vec![(status, body.clone())]);
            let e = refresher_of(Issuer::Openai, &[&url])
                .refresh("login-1", MARK)
                .err()
                .unwrap();
            assert_eq!(e.rejected, rejected, "{status} {body}: {e:?}");
            assert!(e.message.contains(&format!("HTTP {status}")), "{e:?}");
            assert!(!e.message.contains(MARK), "{e:?}");
        }
    }
}
