//! `qb login`: signs an `oauth_anthropic` or `chatgpt_oauth` login in from scratch with PKCE
//! (RFC 7636, S256) on a host without a browser. The operator opens the authorize URL on any
//! device and pastes back `code#state` (Anthropic) or the redirect URL (OpenAI); the code is
//! exchanged at the token endpoint and the login's credential file written. No output and no
//! error carries the code, the verifier, a token or the account id, and every buffer that held
//! one is zeroized.

use std::fmt;
use std::path::PathBuf;

use qb_anthropic::request::identity as anthropic;
use qb_openai::request::identity as openai;
use zeroize::Zeroizing;

use super::base64url;
use super::config::{CredentialKind, GatewayLogin};
use super::creds::{self, Written};
use super::import::claimed_account;
use super::oauth::{OauthRefresher, percent_encode, plain_code};
use crate::sha256;

/// A sign-in waiting for the pasted code.
pub struct SignIn {
    login: GatewayLogin,
    verifier: Zeroizing<String>,
    challenge: String,
    state: String,
}

/// A credential written by [`SignIn::finish`].
#[derive(Debug)]
pub struct Signed {
    /// The credential file written.
    pub file: PathBuf,
    /// Its type.
    pub kind: CredentialKind,
    /// The login signed in.
    pub login: String,
}

impl fmt::Display for Signed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: wrote the `{}` credential of login `{}`",
            self.file.display(),
            self.kind.as_str(),
            self.login
        )
    }
}

impl SignIn {
    /// A sign-in of the `oauth_anthropic` or `chatgpt_oauth` entry `login`, whose credential
    /// file must not exist unless `force`, with a verifier and a state from the kernel's random
    /// source.
    ///
    /// # Errors
    /// The login has another kind, its file exists, or the random source failed.
    pub fn start(login: GatewayLogin, force: bool) -> Result<Self, String> {
        if login.kind == CredentialKind::ApiKey {
            return Err(format!(
                "login `{}` has kind `api_key`; `qb login` signs in `oauth_anthropic` and \
                 `chatgpt_oauth` logins, `qb login import --from env` writes an API key",
                login.name
            ));
        }
        creds::vacant(&login.credentials, force)?;
        let verifier = base64url::random()?;
        let challenge = base64url::encode(&sha256::digest(verifier.as_bytes()));
        let state = base64url::random()?.to_string();
        Ok(Self {
            login,
            verifier,
            challenge,
            state,
        })
    }

    /// What the operator does with the URL and pastes back.
    pub fn prompt(&self) -> &'static str {
        if self.login.kind == CredentialKind::ChatgptOauth {
            "open the URL below in a browser on any device and sign in; the browser then fails \
             to load a localhost page: paste that page's full address here"
        } else {
            "open the URL below in a browser on any device, sign in and paste the code the page \
             shows here"
        }
    }

    /// The authorize URL: the vendor's public parameters, the S256 challenge and the state.
    pub fn url(&self) -> String {
        let (authorize, params): (_, Vec<(&str, &str)>) =
            if self.login.kind == CredentialKind::ChatgptOauth {
                let mut params = vec![
                    ("response_type", "code"),
                    ("client_id", openai::OAUTH_CLIENT_ID),
                    ("redirect_uri", openai::OAUTH_REDIRECT_URI),
                    ("scope", openai::OAUTH_SCOPES),
                ];
                params.extend(openai::OAUTH_AUTHORIZE_EXTRA);
                (openai::OAUTH_AUTHORIZE_URL, params)
            } else {
                let params = vec![
                    ("code", "true"),
                    ("client_id", anthropic::OAUTH_CLIENT_ID),
                    ("response_type", "code"),
                    ("redirect_uri", anthropic::OAUTH_REDIRECT_URI),
                    ("scope", anthropic::OAUTH_SCOPES),
                ];
                (anthropic::OAUTH_AUTHORIZE_URL, params)
            };
        let mut url = authorize.to_owned();
        let pkce = [
            ("code_challenge", self.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", self.state.as_str()),
        ];
        for (i, (key, value)) in params.iter().chain(&pkce).enumerate() {
            url.push(if i == 0 { '?' } else { '&' });
            url.push_str(key);
            url.push('=');
            percent_encode(value, &mut url);
        }
        url
    }

    /// Takes the code from `pasted` once its state is the one sent, exchanges it at the login's
    /// `token_url`, else the vendor's endpoints, and writes the credential file atomically with
    /// mode 0600.
    ///
    /// # Errors
    /// The state differs or is missing, the paste holds no code, the vendor refused the code or
    /// could not be asked, the answer lacks a token or the account, or the write failed.
    pub fn finish(self, pasted: &str) -> Result<Signed, String> {
        let code = self.pasted_code(pasted.trim())?;
        let tokens = OauthRefresher::new()
            .exchange_code(&self.login, &code, &self.state, &self.verifier)
            .map_err(|e| match e.status {
                Some(_) => format!("the token endpoint refused the code: {}", e.message),
                None => format!("the token exchange failed: {}", e.message),
            })?;
        let file = self.login.credentials.as_path();
        let visible =
            |field: &str, value: &str| creds::visible(file, field, value).map_err(|e| e.message);
        visible("access_token", &tokens.access_token)?;
        let refresh_token = tokens
            .refresh_token
            .as_ref()
            .ok_or("the token answer has no `refresh_token`")?;
        visible("refresh_token", refresh_token)?;
        let account_id = if self.login.kind == CredentialKind::ChatgptOauth {
            let id = tokens
                .id_token
                .as_deref()
                .and_then(|t| claimed_account(t))
                .ok_or("the token answer has no `id_token` with a `chatgpt_account_id` claim")?;
            visible("chatgpt_account_id", &id)?;
            Some(id)
        } else {
            None
        };
        let body = Written {
            kind: self.login.kind.into(),
            access_token: Some(&tokens.access_token),
            refresh_token: Some(refresh_token),
            account_id: account_id.as_deref().map(String::as_str),
            expires_at: Some(tokens.expires_at),
            key: None,
        }
        .encode(file)
        .map_err(|e| e.message)?;
        creds::write_atomic(file, &body)
            .map_err(|e| format!("{}: cannot write: {e}", file.display()))?;
        Ok(Signed {
            file: file.to_owned(),
            kind: self.login.kind,
            login: self.login.name,
        })
    }

    /// The code of `pasted`: `code#state` for Anthropic, the redirect URL's `code` and `state`
    /// for OpenAI; refused unless the state is the one sent.
    fn pasted_code(&self, pasted: &str) -> Result<Zeroizing<String>, String> {
        let (code, state, error) = if self.login.kind == CredentialKind::ChatgptOauth {
            let query = pasted
                .split_once('?')
                .map(|(_, q)| q.split_once('#').map_or(q, |(q, _)| q))
                .ok_or("the pasted line is not a URL with a query")?;
            let (mut code, mut state, mut error) = (None, None, None);
            for pair in query.split('&') {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let slot = match key {
                    "code" => &mut code,
                    "state" => &mut state,
                    "error" => &mut error,
                    _ => continue,
                };
                *slot = Some(
                    percent_decode(value)
                        .ok_or_else(|| format!("the pasted `{key}` is not percent-encoded"))?,
                );
            }
            (code, state, error)
        } else {
            let (code, state) = pasted
                .split_once('#')
                .ok_or("the pasted line is not `code#state`")?;
            (
                Some(Zeroizing::new(code.to_owned())),
                Some(Zeroizing::new(state.to_owned())),
                None,
            )
        };
        if state.as_deref().map(String::as_str) != Some(self.state.as_str()) {
            return Err(
                "the pasted state is not the one this sign-in sent; run `qb login` again".into(),
            );
        }
        if let Some(error) = error {
            return Err(if plain_code(&error) {
                format!("the vendor refused the sign-in: `{}`", error.as_str())
            } else {
                "the vendor refused the sign-in".to_owned()
            });
        }
        let code = code.ok_or("the pasted URL has no `code`")?;
        if code.is_empty() || !code.bytes().all(|b| b.is_ascii_graphic()) {
            return Err("the pasted code is not a non-empty visible ASCII string".into());
        }
        Ok(code)
    }
}

/// A query value decoded: `%XX` to its byte, `+` to a space; `None` for a bad escape or text
/// that is not UTF-8.
fn percent_decode(value: &str) -> Option<Zeroizing<String>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        out.push(match b {
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                u8::try_from(high << 4 | low).ok()?
            }
            b'+' => b' ',
            b => b,
        });
    }
    let text = std::str::from_utf8(&out).ok()?;
    Some(Zeroizing::new(text.to_owned()))
}
