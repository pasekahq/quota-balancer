//! `qb login import`: copies a credential another client holds into a gateway login's own
//! credential file. The source is only read; every error names the file, the field and the
//! problem, never a value, and every buffer that held a secret is zeroized.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

use super::config::{CredentialKind, GatewayLogin};
use super::creds::{self, CredError, Secret, Written};

/// Largest source file read.
const MAX_SOURCE: u64 = 1024 * 1024;

/// Start of an Anthropic OAuth access token; Hermes takes such a token for OAuth whatever its
/// entry's `auth_type` says.
const ANTHROPIC_OAUTH_PREFIX: &str = "sk-ant-oat";

/// A provider of a Hermes credential pool that can be imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HermesProvider {
    /// `anthropic`: an OAuth token (`auth_type = "oauth"` or the `sk-ant-oat` prefix) or an API
    /// key.
    Anthropic,
    /// `openai-codex`: a ChatGPT login.
    OpenaiCodex,
}

impl HermesProvider {
    /// The provider of pool key `name`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "anthropic" => Some(Self::Anthropic),
            "openai-codex" => Some(Self::OpenaiCodex),
            _ => None,
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenaiCodex => "openai-codex",
        }
    }
}

/// Where the credential comes from and how to find it in the source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A Hermes `auth.json` credential pool entry, by id or label; the only one when `None`.
    Hermes {
        /// Pool key of the entry.
        provider: HermesProvider,
        /// Id or label of the entry.
        entry: Option<String>,
    },
    /// Claude Code's `.credentials.json`.
    ClaudeCode,
    /// The Codex CLI's `auth.json`.
    Codex,
    /// The variable `var` of an env file, an API key.
    Env {
        /// Variable name.
        var: String,
    },
}

impl Source {
    /// The client whose credential store this source is.
    fn client(&self) -> &'static str {
        match self {
            Self::Hermes { .. } => "Hermes",
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "the Codex CLI",
            Self::Env { .. } => "the env file",
        }
    }
}

/// A credential written by [`import`].
#[derive(Debug)]
pub struct Imported {
    /// The credential file written.
    pub file: PathBuf,
    /// Its type.
    pub kind: CredentialKind,
    /// The client that keeps using the imported refresh token; `None` without one.
    pub shared_with: Option<&'static str>,
}

/// A credential read from a source, in the gateway's terms.
struct Found {
    kind: CredentialKind,
    /// The access token, or the key of an `api_key` credential.
    secret: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    account_id: Option<Zeroizing<String>>,
    expires_at: Option<u64>,
}

/// The entry of `login` in the gateway config `config`.
///
/// # Errors
/// The config is unreadable or invalid, or has no such login.
pub fn login(config: &Path, login: &str) -> Result<GatewayLogin, String> {
    super::config::load(config)
        .map_err(|e| e.to_string())?
        .logins
        .into_iter()
        .find(|l| l.name == login)
        .ok_or_else(|| format!("login `{login}` is not in the gateway config"))
}

/// Copies the credential of `source` in the file `from` into the credential file of `entry`,
/// which must not exist unless `force`.
///
/// # Errors
/// The source is unreadable or malformed, holds no usable credential or one of another kind
/// than the login's, the target exists, or the write failed.
pub fn import(
    entry: &GatewayLogin,
    source: &Source,
    from: &Path,
    force: bool,
) -> Result<Imported, String> {
    let target = entry.credentials.as_path();
    if !force && std::fs::symlink_metadata(target).is_ok() {
        return Err(format!(
            "{}: exists; pass --force to replace it",
            target.display()
        ));
    }
    let bytes = read_source(from)?;
    let found = match source {
        Source::Hermes { provider, entry } => hermes(from, &bytes, *provider, entry.as_deref()),
        Source::ClaudeCode => claude_code(from, &bytes),
        Source::Codex => codex(from, &bytes),
        Source::Env { var } => env(from, &bytes, var),
    }
    .map_err(|e| e.message)?;
    drop(bytes);
    if found.kind != entry.kind {
        return Err(format!(
            "{}: holds a `{}` credential, login `{}` has kind `{}`",
            from.display(),
            found.kind.as_str(),
            entry.name,
            entry.kind.as_str()
        ));
    }
    let api_key = found.kind == CredentialKind::ApiKey;
    let body = Written {
        kind: found.kind.into(),
        access_token: (!api_key).then_some(found.secret.as_str()),
        refresh_token: found.refresh_token.as_deref().map(String::as_str),
        account_id: found.account_id.as_deref().map(String::as_str),
        expires_at: found.expires_at,
        key: api_key.then_some(found.secret.as_str()),
    }
    .encode(target)
    .map_err(|e| e.message)?;
    creds::write_atomic(target, &body)
        .map_err(|e| format!("{}: cannot write: {e}", target.display()))?;
    Ok(Imported {
        file: target.to_owned(),
        kind: found.kind,
        shared_with: found.refresh_token.is_some().then(|| source.client()),
    })
}

fn read_source(file: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let fail = |e: std::io::Error| format!("{}: {e}", file.display());
    let f = File::open(file).map_err(fail)?;
    let len = f.metadata().map_err(fail)?.len().min(MAX_SOURCE);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(len).unwrap_or(0).saturating_add(1),
    ));
    f.take(MAX_SOURCE + 1)
        .read_to_end(&mut bytes)
        .map_err(fail)?;
    if bytes.len() as u64 > MAX_SOURCE {
        return Err(format!("{}: is larger than 1 MiB", file.display()));
    }
    Ok(bytes)
}

/// `s` of `field` copied out when present; empty counts as absent.
fn optional(
    file: &Path,
    field: &str,
    s: Option<&Secret>,
) -> Result<Option<Zeroizing<String>>, CredError> {
    match s {
        Some(s) if !s.0.is_empty() => {
            creds::visible(file, field, &s.0)?;
            Ok(Some(s.0.clone()))
        }
        _ => Ok(None),
    }
}

#[derive(Deserialize)]
struct HermesFile {
    credential_pool: HermesPool,
}

#[derive(Deserialize)]
struct HermesPool {
    anthropic: Option<Vec<HermesEntry>>,
    #[serde(rename = "openai-codex")]
    openai_codex: Option<Vec<HermesEntry>>,
}

#[derive(Deserialize)]
struct HermesEntry {
    id: Option<String>,
    label: Option<String>,
    auth_type: Option<String>,
    access_token: Option<Secret>,
    refresh_token: Option<Secret>,
    expires_at: Option<String>,
    expires_at_ms: Option<u64>,
}

fn hermes(
    file: &Path,
    bytes: &[u8],
    provider: HermesProvider,
    name: Option<&str>,
) -> Result<Found, CredError> {
    let doc: HermesFile = creds::decode(file, bytes)?;
    let key = provider.key();
    let entries = match provider {
        HermesProvider::Anthropic => doc.credential_pool.anthropic,
        HermesProvider::OpenaiCodex => doc.credential_pool.openai_codex,
    }
    .unwrap_or_default();
    let field = |i: usize, f: &str| format!("credential_pool.{key}[{i}].{f}");
    let (i, entry) = pool_entry(file, key, &entries, name)?;
    let secret = creds::secret(file, &field(i, "access_token"), entry.access_token.as_ref())?;
    let kind = match (provider, entry.auth_type.as_deref()) {
        (HermesProvider::OpenaiCodex, _) => CredentialKind::ChatgptOauth,
        (HermesProvider::Anthropic, _)
            if entry.auth_type.as_deref() == Some("oauth")
                || secret.starts_with(ANTHROPIC_OAUTH_PREFIX) =>
        {
            CredentialKind::OauthAnthropic
        }
        (HermesProvider::Anthropic, _) => CredentialKind::ApiKey,
    };
    if kind == CredentialKind::ApiKey {
        return Ok(Found {
            kind,
            secret,
            refresh_token: None,
            account_id: None,
            expires_at: None,
        });
    }
    let refresh_token = optional(
        file,
        &field(i, "refresh_token"),
        entry.refresh_token.as_ref(),
    )?;
    let expires_at = match (entry.expires_at_ms, entry.expires_at.as_deref()) {
        (Some(ms), _) => Some(ms / 1000),
        (None, Some(iso)) if !iso.is_empty() => {
            Some(qb_vendors::rfc3339::parse(iso).map_err(|_| {
                creds::unusable(
                    file,
                    format_args!(
                        "`{}` is not an ISO 8601 timestamp with a time zone",
                        field(i, "expires_at")
                    ),
                )
            })?)
        }
        (None, _) => None,
    };
    let account_id = if kind == CredentialKind::ChatgptOauth {
        let id = claimed_account(&secret).ok_or_else(|| {
            creds::unusable(
                file,
                format_args!(
                    "no `chatgpt_account_id` claim in `{}`",
                    field(i, "access_token")
                ),
            )
        })?;
        creds::visible(file, "chatgpt_account_id", &id)?;
        Some(id)
    } else {
        None
    };
    Ok(Found {
        kind,
        secret,
        refresh_token,
        account_id,
        expires_at,
    })
}

/// The entry of the pool `key` whose id, else whose one label, is `name`; the only entry when
/// `name` is `None`.
fn pool_entry<'a>(
    file: &Path,
    key: &str,
    entries: &'a [HermesEntry],
    name: Option<&str>,
) -> Result<(usize, &'a HermesEntry), CredError> {
    Ok(match name {
        Some(name) => {
            let by_id = entries
                .iter()
                .enumerate()
                .find(|(_, e)| e.id.as_deref() == Some(name));
            let mut by_label = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.label.as_deref() == Some(name));
            match (by_id, by_label.next(), by_label.next()) {
                (Some(found), _, _) | (None, Some(found), None) => found,
                (None, Some(_), Some(_)) => {
                    return Err(creds::unusable(
                        file,
                        format_args!(
                            "several `credential_pool.{key}` entries have the label `{name}`; name one by id"
                        ),
                    ));
                }
                (None, None, _) => {
                    return Err(creds::unusable(
                        file,
                        format_args!(
                            "no `credential_pool.{key}` entry has the id or label `{name}`"
                        ),
                    ));
                }
            }
        }
        None => match entries {
            [only] => (0, only),
            [] => {
                return Err(creds::unusable(
                    file,
                    format_args!("no `credential_pool.{key}` entry"),
                ));
            }
            more => {
                return Err(creds::unusable(
                    file,
                    format_args!(
                        "{} `credential_pool.{key}` entries; name one with --entry",
                        more.len()
                    ),
                ));
            }
        },
    })
}

#[derive(Deserialize)]
struct ClaudeCodeFile {
    #[serde(rename = "claudeAiOauth")]
    oauth: ClaudeCodeOauth,
}

#[derive(Deserialize)]
struct ClaudeCodeOauth {
    #[serde(rename = "accessToken")]
    access_token: Option<Secret>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<Secret>,
    /// Unix milliseconds.
    #[serde(rename = "expiresAt")]
    expires_at: Option<u64>,
}

fn claude_code(file: &Path, bytes: &[u8]) -> Result<Found, CredError> {
    let doc: ClaudeCodeFile = creds::decode(file, bytes)?;
    let o = doc.oauth;
    Ok(Found {
        kind: CredentialKind::OauthAnthropic,
        secret: creds::secret(file, "claudeAiOauth.accessToken", o.access_token.as_ref())?,
        refresh_token: optional(file, "claudeAiOauth.refreshToken", o.refresh_token.as_ref())?,
        account_id: None,
        expires_at: o.expires_at.map(|ms| ms / 1000),
    })
}

#[derive(Deserialize)]
struct CodexFile {
    tokens: CodexTokens,
}

#[derive(Deserialize)]
struct CodexTokens {
    access_token: Option<Secret>,
    refresh_token: Option<Secret>,
    id_token: Option<Secret>,
    account_id: Option<Secret>,
}

fn codex(file: &Path, bytes: &[u8]) -> Result<Found, CredError> {
    let doc: CodexFile = creds::decode(file, bytes)?;
    let t = doc.tokens;
    let account_id = if let Some(id) = optional(file, "tokens.account_id", t.account_id.as_ref())? {
        id
    } else {
        let id = t
            .id_token
            .as_ref()
            .and_then(|jwt| claimed_account(&jwt.0))
            .ok_or_else(|| {
                creds::unusable(
                    file,
                    "no `tokens.account_id` and no `chatgpt_account_id` claim in `tokens.id_token`",
                )
            })?;
        creds::visible(file, "chatgpt_account_id", &id)?;
        id
    };
    Ok(Found {
        kind: CredentialKind::ChatgptOauth,
        secret: creds::secret(file, "tokens.access_token", t.access_token.as_ref())?,
        refresh_token: optional(file, "tokens.refresh_token", t.refresh_token.as_ref())?,
        account_id: Some(account_id),
        expires_at: None,
    })
}

/// The API key in the last `NAME=value` line of variable `var`; `export ` and one pair of
/// matching quotes around the value are dropped.
fn env(file: &Path, bytes: &[u8], var: &str) -> Result<Found, CredError> {
    let mut value = None;
    for line in bytes.split(|&b| b == b'\n') {
        let line = line.trim_ascii();
        let line = line
            .strip_prefix(b"export ")
            .map_or(line, <[u8]>::trim_ascii_start);
        let Some(eq) = line.iter().position(|&b| b == b'=') else {
            continue;
        };
        if line[..eq].trim_ascii() == var.as_bytes() {
            value = Some(unquote(line[eq + 1..].trim_ascii()));
        }
    }
    let value = value.ok_or_else(|| creds::unusable(file, format_args!("no variable `{var}`")))?;
    if value.is_empty() || !value.iter().all(u8::is_ascii_graphic) {
        return Err(creds::unusable(
            file,
            format_args!("`{var}` is not a non-empty visible ASCII string"),
        ));
    }
    let mut secret = Zeroizing::new(String::with_capacity(value.len()));
    secret.extend(value.iter().map(|&b| char::from(b)));
    Ok(Found {
        kind: CredentialKind::ApiKey,
        secret,
        refresh_token: None,
        account_id: None,
        expires_at: None,
    })
}

fn unquote(value: &[u8]) -> &[u8] {
    match value {
        [q @ (b'"' | b'\''), inner @ .., last] if last == q => inner,
        _ => value,
    }
}

#[derive(Deserialize)]
struct Claims {
    #[serde(rename = "https://api.openai.com/auth")]
    auth: Option<AuthClaims>,
}

#[derive(Deserialize)]
struct AuthClaims {
    chatgpt_account_id: Option<Secret>,
}

/// The `chatgpt_account_id` claim of the JWT `jwt`, unverified: the vendor checks the token.
fn claimed_account(jwt: &str) -> Option<Zeroizing<String>> {
    let payload = jwt.split('.').nth(1)?;
    let json = base64url(payload)?;
    let claims: Claims = serde_json::from_slice(&json).ok()?;
    claims.auth?.chatgpt_account_id.map(|s| s.0)
}

/// Decodes unpadded or padded base64url.
fn base64url(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let digits = text.trim_end_matches('=').as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(digits.len() * 3 / 4));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in digits {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}
