//! The [`Refresher`] of `oauth_anthropic` logins: the OAuth refresh grant, form-encoded, over
//! ureq with rustls to the login's `token_url` or the vendor's token endpoints in order. The
//! protocol is in `docs/anthropic.md`, "OAuth token refresh".

use std::time::Duration;

use qb_anthropic::request::identity;
use serde::Deserialize;
use zeroize::Zeroizing;

use super::anthropic::CONNECT_TIMEOUT;
use super::config::{CredentialKind, GatewayConfig};
use super::creds::{RefreshError, Refreshed, Refresher, Secret};
use crate::server::unix_now;

/// Bound of one token request, from connect to the end of the answer.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

/// Largest token answer read.
const MAX_ANSWER: u64 = 64 << 10;

/// Refreshes the tokens of the `oauth_anthropic` logins of one gateway config.
pub struct AnthropicOauth {
    config: ureq::config::Config,
    /// Each OAuth login and its token endpoints in the order they are tried.
    endpoints: Vec<(String, Vec<String>)>,
}

impl AnthropicOauth {
    /// A refresher of `config`'s OAuth logins with [`CONNECT_TIMEOUT`] and [`REFRESH_TIMEOUT`],
    /// no proxy and no redirects.
    pub fn new(config: &GatewayConfig) -> Self {
        let endpoints = config
            .logins
            .iter()
            .filter(|l| l.kind == CredentialKind::OauthAnthropic)
            .map(|l| {
                let urls = match &l.token_url {
                    Some(url) => vec![url.clone()],
                    None => identity::OAUTH_TOKEN_URLS.map(str::to_owned).to_vec(),
                };
                (l.name.clone(), urls)
            })
            .collect();
        Self::with_endpoints(endpoints)
    }

    fn with_endpoints(endpoints: Vec<(String, Vec<String>)>) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(REFRESH_TIMEOUT))
            .build();
        Self { config, endpoints }
    }

    /// One token request to `url` with the form `body`.
    fn post(&self, url: &str, body: &[u8]) -> Result<Refreshed, Failed> {
        let agent = ureq::Agent::new_with_config(self.config.clone());
        let mut response = agent
            .post(url)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .header("user-agent", identity::OAUTH_TOKEN_USER_AGENT)
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
        let last = |rejected: bool, what: &str| {
            Failed::Last(RefreshError {
                rejected,
                message: format!("{url}: {what}"),
            })
        };
        if !(200..300).contains(&status) {
            let code = serde_json::from_slice::<Refusal>(&bytes)
                .ok()
                .and_then(|r| r.error)
                .filter(|c| {
                    c.len() <= 64 && c.bytes().all(|b| b == b'_' || b.is_ascii_lowercase())
                });
            let rejected = matches!(status, 400 | 401) || code.as_deref() == Some("invalid_grant");
            let what = match code {
                Some(code) => format!("HTTP {status} {code}"),
                None => format!("HTTP {status}"),
            };
            return Err(last(rejected, &what));
        }
        let answer: Answer = serde_json::from_slice(&bytes).map_err(|e| {
            let what = format!(
                "malformed answer (line {}, column {})",
                e.line(),
                e.column()
            );
            last(false, &what)
        })?;
        let Some(access_token) = answer.access_token else {
            return Err(last(false, "answer has no `access_token`"));
        };
        let Some(expires_in) = answer.expires_in else {
            return Err(last(false, "answer has no `expires_in`"));
        };
        Ok(Refreshed {
            access_token: access_token.0,
            refresh_token: answer.refresh_token.map(|s| s.0),
            expires_at: unix_now().saturating_add(expires_in),
        })
    }
}

/// Why one token request failed: try the next endpoint, or end the refresh with this error.
enum Failed {
    Next(String),
    Last(RefreshError),
}

/// The fields of a token answer the gateway uses; others are ignored.
#[derive(Deserialize)]
struct Answer {
    access_token: Option<Secret>,
    refresh_token: Option<Secret>,
    expires_in: Option<u64>,
}

/// The OAuth error code of a refusal.
#[derive(Deserialize)]
struct Refusal {
    error: Option<String>,
}

impl Refresher for AnthropicOauth {
    fn refresh(&self, login: &str, refresh_token: &str) -> Result<Refreshed, RefreshError> {
        let Some((_, urls)) = self.endpoints.iter().find(|(name, _)| name == login) else {
            return Err(RefreshError {
                rejected: false,
                message: format!("`{login}` is not an `oauth_anthropic` login"),
            });
        };
        let body = form(refresh_token);
        let mut failures = Vec::new();
        for url in urls {
            match self.post(url, body.as_bytes()) {
                Ok(fresh) => return Ok(fresh),
                Err(Failed::Next(why)) => failures.push(why),
                Err(Failed::Last(e)) => return Err(e),
            }
        }
        Err(RefreshError {
            rejected: false,
            message: failures.join("; "),
        })
    }
}

/// The form body of the refresh grant for `refresh_token`.
fn form(refresh_token: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(
        96 + 3 * refresh_token.len() + identity::OAUTH_CLIENT_ID.len(),
    ));
    out.push_str("grant_type=refresh_token&refresh_token=");
    encode(refresh_token, &mut out);
    out.push_str("&client_id=");
    encode(identity::OAUTH_CLIENT_ID, &mut out);
    out
}

/// Appends `s` percent-encoded, every byte but the unreserved ones of RFC 3986.
fn encode(s: &str, out: &mut String) {
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

    fn refresher(urls: &[&str]) -> AnthropicOauth {
        let urls = urls.iter().map(|u| (*u).to_owned()).collect();
        AnthropicOauth::with_endpoints(vec![("login-1".into(), urls)])
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
                identity::OAUTH_CLIENT_ID
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
    fn only_configured_oauth_logins_refresh() {
        let e = refresher(&[]).refresh("login-2", MARK).err().unwrap();
        assert!(!e.rejected);
        assert!(
            e.message
                .contains("`login-2` is not an `oauth_anthropic` login")
        );
    }
}
