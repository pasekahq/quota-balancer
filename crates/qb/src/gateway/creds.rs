//! The gateway's credential files: one JSON file per login, mode 0600, owned by the gateway's
//! user, read for one attempt and zeroized. An expiring or vendor-rejected OAuth token
//! (`oauth_anthropic`, `chatgpt_oauth`) is refreshed through a [`Refresher`] and written back
//! atomically; a `chatgpt_oauth` file without `refresh_token` is used as it is. No error message
//! ever quotes a file's contents.
//!
//! ```json
//! {"type": "oauth_anthropic", "access_token": "...", "refresh_token": "...", "expires_at": 1800000000}
//! {"type": "api_key", "key": "..."}
//! {"type": "chatgpt_oauth", "access_token": "...", "account_id": "...", "refresh_token": "...", "expires_at": 1800000000}
//! ```

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::config::{CredentialKind, GatewayLogin};
use super::upstream::Credential;
use crate::rewrite::write_atomic;

/// An OAuth token is refreshed when it expires within this many seconds.
pub const REFRESH_MARGIN_S: u64 = 60;

/// Largest credential file read.
const MAX_FILE: u64 = 64 * 1024;

/// A new token pair from a refresh. Secrets are zeroized on drop.
pub struct Refreshed {
    /// New access token.
    pub access_token: Zeroizing<String>,
    /// New refresh token, when the vendor rotates it; else the old one is kept.
    pub refresh_token: Option<Zeroizing<String>>,
    /// Unix time the new access token expires.
    pub expires_at: u64,
}

/// Why a refresh failed. `message` never holds a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshError {
    /// The vendor refused the refresh token: the login needs a new sign-in.
    pub rejected: bool,
    /// Detail for the log.
    pub message: String,
}

/// Exchanges an OAuth refresh token for a new access token.
pub trait Refresher: Send + Sync {
    /// Refreshes the tokens of the login of entry `login` with `refresh_token`.
    ///
    /// # Errors
    /// The vendor refused (`rejected`) or could not be asked.
    fn refresh(&self, login: &GatewayLogin, refresh_token: &str)
    -> Result<Refreshed, RefreshError>;
}

/// Why a credential could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredError {
    /// The login's credential is unusable until an operator acts (bad file, rejected refresh);
    /// false for a failure that may pass by itself (refresh endpoint unreachable).
    pub unusable: bool,
    /// Names the file and the problem, never a value.
    pub message: String,
}

impl fmt::Display for CredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// A secret string of a JSON document, zeroized on drop.
pub(super) struct Secret(pub(super) Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    OauthAnthropic,
    ApiKey,
    ChatgptOauth,
}

impl From<CredentialKind> for Kind {
    fn from(kind: CredentialKind) -> Self {
        match kind {
            CredentialKind::OauthAnthropic => Self::OauthAnthropic,
            CredentialKind::ApiKey => Self::ApiKey,
            CredentialKind::ChatgptOauth => Self::ChatgptOauth,
        }
    }
}

impl From<Kind> for CredentialKind {
    fn from(kind: Kind) -> Self {
        match kind {
            Kind::OauthAnthropic => Self::OauthAnthropic,
            Kind::ApiKey => Self::ApiKey,
            Kind::ChatgptOauth => Self::ChatgptOauth,
        }
    }
}

/// The file as stored; flat rather than tagged so no buffered copy of a secret is left behind.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    #[serde(rename = "type")]
    kind: Kind,
    access_token: Option<Secret>,
    refresh_token: Option<Secret>,
    expires_at: Option<u64>,
    key: Option<Secret>,
    account_id: Option<Secret>,
}

/// A credential file's contents as the gateway writes them.
#[derive(Serialize)]
pub(super) struct Written<'a> {
    #[serde(rename = "type")]
    pub(super) kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) access_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) account_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key: Option<&'a str>,
}

impl Written<'_> {
    /// The JSON of the file `file`, in a buffer zeroized on drop.
    pub(super) fn encode(&self, file: &Path) -> Result<Zeroizing<Vec<u8>>, CredError> {
        let len = [
            self.access_token,
            self.refresh_token,
            self.account_id,
            self.key,
        ]
        .iter()
        .flatten()
        .map(|s| s.len())
        .sum::<usize>();
        let mut body = Zeroizing::new(Vec::with_capacity(160 + len));
        serde_json::to_writer(&mut *body, self).map_err(|e| CredError {
            unusable: false,
            message: format!("{}: encode failed: {e}", file.display()),
        })?;
        Ok(body)
    }
}

/// Hex digits of a credential fingerprint.
const FINGERPRINT_HEX: usize = 16;

/// The fingerprint of the credential in `file` that qbd keeps with a login's auth mark: the
/// first 16 hex digits of the SHA-256 of the file's bytes, mode and modification time, each
/// absent when it cannot be read. Any write of the file (a refresh included), a `chmod` or a
/// `touch` changes it; it reveals nothing of the secret.
pub fn fingerprint(file: &Path) -> String {
    let meta = std::fs::metadata(file).ok();
    // Room for the metadata too, so no growth leaves a copy of the secret behind.
    let size = meta.as_ref().map_or(0, std::fs::Metadata::len);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(size).unwrap_or(0).saturating_add(32),
    ));
    // At most the size seen, so a file that grows meanwhile cannot make the buffer move.
    if let Ok(f) = File::open(file) {
        if f.take(size).read_to_end(&mut bytes).is_err() {
            bytes.clear();
        }
    }
    if let Some(meta) = meta {
        bytes.extend_from_slice(&meta.mode().to_le_bytes());
        bytes.extend_from_slice(&meta.mtime().to_le_bytes());
        bytes.extend_from_slice(&meta.mtime_nsec().to_le_bytes());
    }
    let mut hex = crate::sha256::hex(crate::sha256::digest(&bytes));
    hex.truncate(FINGERPRINT_HEX);
    hex
}

/// Loads credentials and refreshes expired OAuth tokens, one refresh per credential file at a
/// time.
pub struct CredentialStore {
    refresher: Box<dyn Refresher>,
    /// The write lock of each credential file that was refreshed or written so far.
    refreshing: Mutex<Vec<(PathBuf, Arc<Mutex<()>>)>>,
}

impl CredentialStore {
    /// A store that refreshes through `refresher`.
    pub fn new(refresher: Box<dyn Refresher>) -> Self {
        Self {
            refresher,
            refreshing: Mutex::new(Vec::new()),
        }
    }

    /// The lock of `file` that its refresh and every other write of it by the gateway hold.
    pub(super) fn write_lock(&self, file: &Path) -> Arc<Mutex<()>> {
        let mut locks = self
            .refreshing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((_, l)) = locks.iter().find(|(path, _)| path == file) {
            return Arc::clone(l);
        }
        let l = Arc::new(Mutex::new(()));
        locks.push((file.to_owned(), Arc::clone(&l)));
        l
    }

    /// The credential of the entry `login` in its file, which must hold its kind, at `now`. An OAuth token
    /// expiring within [`REFRESH_MARGIN_S`], or any such token when `stale` (the vendor just
    /// rejected it), is refreshed first unless another attempt already replaced it; an expiring
    /// `chatgpt_oauth` token without `refresh_token` is used as it is.
    ///
    /// # Errors
    /// The file is unreadable, too open, malformed, or the refresh failed.
    pub fn load(
        &self,
        login: &GatewayLogin,
        now: u64,
        stale: bool,
    ) -> Result<Credential, CredError> {
        let (file, kind) = (login.credentials.as_path(), login.kind);
        let first = read(file)?;
        let found = CredentialKind::from(first.kind);
        if found != kind {
            return Err(unusable(
                file,
                format_args!(
                    "has type `{}`, the config says `{}`",
                    found.as_str(),
                    kind.as_str()
                ),
            ));
        }
        if first.kind == Kind::ApiKey {
            let key = secret(file, "key", first.key.as_ref())?;
            own_fields(file, &first)?;
            return Ok(Credential::ApiKey { key });
        }
        let token = secret(file, "access_token", first.access_token.as_ref())?;
        let account_id = account(file, &first)?;
        own_fields(file, &first)?;
        let expiring = first
            .expires_at
            .is_some_and(|at| at <= now.saturating_add(REFRESH_MARGIN_S));
        let as_is = first.kind == Kind::ChatgptOauth && first.refresh_token.is_none();
        if !stale && (!expiring || as_is) {
            return Ok(oauth(token, account_id));
        }
        let lock = self.write_lock(file);
        let _one = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let again = read(file)?;
        let current = secret(file, "access_token", again.access_token.as_ref())?;
        let account_id = account(file, &again)?;
        own_fields(file, &again)?;
        let replaced = *current != *token
            && again
                .expires_at
                .is_none_or(|at| at > now.saturating_add(REFRESH_MARGIN_S));
        if replaced {
            return Ok(oauth(current, account_id));
        }
        let refresh_token = secret(file, "refresh_token", again.refresh_token.as_ref())?;
        let fresh = self
            .refresher
            .refresh(login, &refresh_token)
            .map_err(|e| CredError {
                unusable: e.rejected,
                message: format!("{}: refresh failed: {}", file.display(), e.message),
            })?;
        visible(file, "access_token", &fresh.access_token)?;
        let kept = fresh.refresh_token.as_ref().unwrap_or(&refresh_token);
        visible(file, "refresh_token", kept)?;
        let body = Written {
            kind: first.kind,
            access_token: Some(&fresh.access_token),
            refresh_token: Some(kept),
            account_id: account_id.as_deref().map(String::as_str),
            expires_at: Some(fresh.expires_at),
            key: None,
        }
        .encode(file)?;
        write_atomic(file, &body).map_err(|e| CredError {
            unusable: false,
            message: format!("{}: cannot write the refreshed token: {e}", file.display()),
        })?;
        Ok(oauth(fresh.access_token, account_id))
    }
}

/// The account id of a `chatgpt_oauth` file, `None` for another kind.
fn account(file: &Path, stored: &Stored) -> Result<Option<Zeroizing<String>>, CredError> {
    match stored.kind {
        Kind::ChatgptOauth => secret(file, "account_id", stored.account_id.as_ref()).map(Some),
        Kind::OauthAnthropic | Kind::ApiKey => Ok(None),
    }
}

/// Refuses a field `stored` holds that its kind does not take, naming the field.
fn own_fields(file: &Path, stored: &Stored) -> Result<(), CredError> {
    let oauth = stored.kind != Kind::ApiKey;
    let foreign = [
        ("access_token", stored.access_token.is_some() && !oauth),
        ("refresh_token", stored.refresh_token.is_some() && !oauth),
        ("expires_at", stored.expires_at.is_some() && !oauth),
        (
            "account_id",
            stored.account_id.is_some() && stored.kind != Kind::ChatgptOauth,
        ),
        ("key", stored.key.is_some() && oauth),
    ];
    match foreign.iter().find(|(_, held)| *held) {
        Some((field, _)) => Err(unusable(
            file,
            format_args!(
                "`{field}` is not a field of type `{}`",
                CredentialKind::from(stored.kind).as_str()
            ),
        )),
        None => Ok(()),
    }
}

/// The OAuth credential of `access_token`: a ChatGPT login's when it has an `account_id`.
fn oauth(access_token: Zeroizing<String>, account_id: Option<Zeroizing<String>>) -> Credential {
    match account_id {
        Some(account_id) => Credential::ChatgptOauth {
            access_token,
            account_id,
        },
        None => Credential::OauthAnthropic { access_token },
    }
}

/// The error of `file` that leaves its login unusable: `<file>: <what>`.
pub(super) fn unusable(file: &Path, what: impl fmt::Display) -> CredError {
    CredError {
        unusable: true,
        message: format!("{}: {what}", file.display()),
    }
}

/// Reads and decodes `file` after checking it is a regular file of ours that nobody else may
/// read or write.
fn read(file: &Path) -> Result<Stored, CredError> {
    let (f, meta) = open_regular(file)?;
    if meta.mode() & 0o077 != 0 {
        return Err(unusable(
            file,
            format_args!(
                "mode {:04o} is too open; the gateway needs 0600",
                meta.mode() & 0o7777
            ),
        ));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(unusable(file, "is owned by another user"));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(4096));
    f.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| unusable(file, e))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(unusable(file, "is larger than 64 KiB"));
    }
    decode(file, &bytes)
}

/// `bytes`, the contents of `file`, decoded as one JSON document; an error names the field
/// path or the position, never a value.
pub(super) fn decode<T: DeserializeOwned>(file: &Path, bytes: &[u8]) -> Result<T, CredError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = serde_path_to_error::deserialize(&mut de).map_err(|e| {
        if e.inner().is_data() {
            // serde's "missing field `name`" holds a field name only; other data errors may
            // quote the value, so they are reduced to the path.
            let inner = e.inner().to_string();
            let missing = inner
                .strip_prefix("missing field `")
                .and_then(|rest| rest.split_once('`'))
                .map(|(field, _)| field);
            match (missing, e.path().to_string()) {
                (Some(field), path) if path == "." => unusable(file, format_args!("no `{field}`")),
                (Some(field), path) => unusable(file, format_args!("no `{path}.{field}`")),
                (None, path) => unusable(file, format_args!("`{path}` is missing or invalid")),
            }
        } else {
            unusable(
                file,
                format_args!(
                    "not valid JSON (line {}, column {})",
                    e.inner().line(),
                    e.inner().column()
                ),
            )
        }
    })?;
    de.end()
        .map_err(|_| unusable(file, "trailing data after the JSON object"))?;
    Ok(value)
}

/// `file` opened, when the path itself (not a symlink) names a regular file. A refresh may
/// replace the file between the `lstat` and the `open`; that is retried a few times.
fn open_regular(file: &Path) -> Result<(File, std::fs::Metadata), CredError> {
    for _ in 0..3 {
        let link = std::fs::symlink_metadata(file).map_err(|e| unusable(file, e))?;
        if !link.is_file() {
            break;
        }
        let f = File::open(file).map_err(|e| unusable(file, e))?;
        let meta = f.metadata().map_err(|e| unusable(file, e))?;
        if (link.dev(), link.ino()) == (meta.dev(), meta.ino()) {
            return Ok((f, meta));
        }
    }
    Err(unusable(file, "is not a regular file"))
}

/// `secret` copied out, if it is a non-empty run of visible ASCII (safe in a header).
pub(super) fn secret(
    file: &Path,
    field: &str,
    s: Option<&Secret>,
) -> Result<Zeroizing<String>, CredError> {
    let Some(s) = s else {
        return Err(unusable(file, format_args!("no `{field}`")));
    };
    visible(file, field, &s.0)?;
    Ok(s.0.clone())
}

/// Refuses `value` of `field` unless it is a non-empty run of visible ASCII.
pub(super) fn visible(file: &Path, field: &str, value: &str) -> Result<(), CredError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(unusable(
            file,
            format_args!("`{field}` is not a non-empty visible ASCII string"),
        ));
    }
    Ok(())
}

/// Refuses to replace the credential file `target` when it exists, unless `force`.
pub(super) fn vacant(target: &Path, force: bool) -> Result<(), String> {
    if !force && std::fs::symlink_metadata(target).is_ok() {
        return Err(format!(
            "{}: exists; pass --force to replace it",
            target.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    const KIND: CredentialKind = CredentialKind::OauthAnthropic;
    const KEY: CredentialKind = CredentialKind::ApiKey;
    /// A synthetic marker standing in for a token; it must never appear in an error.
    const MARK: &str = "test-token-7f3a";

    fn dir(tag: &str) -> PathBuf {
        crate::testdir::new(&format!("creds-{tag}"))
    }

    fn file(tag: &str, body: &str, mode: u32) -> PathBuf {
        let f = dir(tag).join("login-1.json");
        std::fs::write(&f, body).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    fn oauth(access: &str, expires_at: u64) -> String {
        format!(
            r#"{{"type":"oauth_anthropic","access_token":"{access}","refresh_token":"refresh-{MARK}","expires_at":{expires_at}}}"#
        )
    }

    /// Hands out `access-N` tokens, rotating the refresh token, and counts its calls.
    struct Counting {
        calls: Arc<AtomicUsize>,
        fail: Option<bool>,
    }

    impl Refresher for Counting {
        fn refresh(
            &self,
            _: &GatewayLogin,
            refresh_token: &str,
        ) -> Result<Refreshed, RefreshError> {
            assert!(refresh_token.starts_with("refresh-"));
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Some(rejected) = self.fail {
                return Err(RefreshError {
                    rejected,
                    message: "refused".into(),
                });
            }
            Ok(Refreshed {
                access_token: Zeroizing::new(format!("access-{n}")),
                refresh_token: Some(Zeroizing::new(format!("refresh-{MARK}-{n}"))),
                expires_at: NOW + 3600,
            })
        }
    }

    /// The `anthropic` entry of `login` with its credentials in `file` of `kind`.
    fn entry(login: &str, file: &Path, kind: CredentialKind) -> GatewayLogin {
        GatewayLogin {
            name: login.into(),
            kind,
            api: crate::gateway::config::Api::Anthropic,
            base_url: None,
            referer: None,
            title: None,
            token_url: None,
            credentials: file.to_owned(),
            spend_cap: None,
        }
    }

    fn store(fail: Option<bool>) -> (CredentialStore, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let s = CredentialStore::new(Box::new(Counting {
            calls: calls.clone(),
            fail,
        }));
        (s, calls)
    }

    #[test]
    fn api_keys_and_fresh_tokens_load_as_they_are() {
        let (s, calls) = store(None);
        let f = file("key", r#"{"type":"api_key","key":"test-token-1"}"#, 0o600);
        let c = s.load(&entry("login-1", &f, KEY), NOW, false).unwrap();
        assert_eq!((c.kind(), c.secret()), ("api_key", "test-token-1"));
        let f = file("fresh", &oauth("access-0", NOW + 600), 0o600);
        let c = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap();
        assert_eq!((c.kind(), c.secret()), ("oauth_anthropic", "access-0"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    const CHATGPT: CredentialKind = CredentialKind::ChatgptOauth;

    fn chatgpt(refresh: Option<&str>, expires_at: u64) -> String {
        let refresh = refresh.map_or(String::new(), |r| format!(r#","refresh_token":"{r}""#));
        format!(
            r#"{{"type":"chatgpt_oauth","access_token":"access-0","account_id":"account-1"{refresh},"expires_at":{expires_at}}}"#
        )
    }

    #[test]
    fn a_chatgpt_token_is_refreshed_when_expiring_or_stale_and_keeps_its_account() {
        for (expires_at, stale) in [(NOW + 30, false), (NOW + 600, true)] {
            let (s, calls) = store(None);
            let f = file(
                "chatgpt",
                &chatgpt(Some(&format!("refresh-{MARK}")), expires_at),
                0o600,
            );
            let c = s.load(&entry("login-1", &f, CHATGPT), NOW, stale).unwrap();
            assert_eq!(
                (c.kind(), c.secret(), c.account_id()),
                ("chatgpt_oauth", "access-1", Some("account-1"))
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o600);
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                format!(
                    r#"{{"type":"chatgpt_oauth","access_token":"access-1","refresh_token":"refresh-{MARK}-1","account_id":"account-1","expires_at":{}}}"#,
                    NOW + 3600
                )
            );
        }
    }

    #[test]
    fn a_fresh_chatgpt_token_or_one_without_refresh_token_is_used_as_it_is() {
        let (s, calls) = store(None);
        for body in [
            chatgpt(Some("refresh-0"), NOW + 600),
            chatgpt(None, NOW - 600),
        ] {
            let f = file("chatgpt-as-is", &body, 0o600);
            let c = s.load(&entry("login-1", &f, CHATGPT), NOW, false).unwrap();
            assert_eq!(
                (c.kind(), c.secret(), c.account_id()),
                ("chatgpt_oauth", "access-0", Some("account-1"))
            );
            assert_eq!(std::fs::read_to_string(&f).unwrap(), body);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let f = file("chatgpt-stale", &chatgpt(None, NOW + 600), 0o600);
        let e = s
            .load(&entry("login-1", &f, CHATGPT), NOW, true)
            .unwrap_err();
        assert!(e.unusable, "{e}");
        assert!(e.message.starts_with(&f.display().to_string()), "{e}");
        assert!(e.message.contains("no `refresh_token`"), "{e}");
    }

    #[test]
    fn a_chatgpt_file_is_checked_before_use() {
        let (s, _) = store(None);
        for (body, want) in [
            (
                format!(r#"{{"type":"chatgpt_oauth","access_token":"{MARK}"}}"#),
                "no `account_id`",
            ),
            (
                format!(
                    r#"{{"type":"chatgpt_oauth","account_id":"a\n{MARK}","access_token":"t"}}"#
                ),
                "`account_id` is not a non-empty visible ASCII",
            ),
            (
                format!(
                    r#"{{"type":"chatgpt_oauth","account_id":"a","access_token":"t","id":"{MARK}"}}"#
                ),
                "missing or invalid",
            ),
        ] {
            let f = file("chatgpt-bad", &body, 0o600);
            let e = s
                .load(&entry("login-1", &f, CHATGPT), NOW, false)
                .unwrap_err();
            assert!(e.unusable && e.message.contains(want), "{body}: {e}");
            assert!(!e.message.contains(MARK), "{body}: {e}");
        }
        let f = file("chatgpt-kind", &chatgpt(None, NOW), 0o600);
        let e = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap_err();
        assert!(
            e.message
                .contains("has type `chatgpt_oauth`, the config says `oauth_anthropic`"),
            "{e}"
        );
    }

    #[test]
    fn a_field_of_another_type_is_refused_by_name() {
        let (s, _) = store(None);
        for (body, kind, field, of) in [
            (
                format!(
                    r#"{{"type":"oauth_anthropic","access_token":"a","refresh_token":"r","key":"{MARK}"}}"#
                ),
                KIND,
                "key",
                "oauth_anthropic",
            ),
            (
                format!(r#"{{"type":"oauth_anthropic","access_token":"a","account_id":"{MARK}"}}"#),
                KIND,
                "account_id",
                "oauth_anthropic",
            ),
            (
                format!(
                    r#"{{"type":"chatgpt_oauth","access_token":"a","account_id":"b","key":"{MARK}"}}"#
                ),
                CHATGPT,
                "key",
                "chatgpt_oauth",
            ),
            (
                format!(r#"{{"type":"api_key","key":"k","account_id":"{MARK}"}}"#),
                KEY,
                "account_id",
                "api_key",
            ),
            (
                format!(r#"{{"type":"api_key","key":"k","refresh_token":"{MARK}"}}"#),
                KEY,
                "refresh_token",
                "api_key",
            ),
        ] {
            let f = file("foreign", &body, 0o600);
            let e = s.load(&entry("login-1", &f, kind), NOW, false).unwrap_err();
            assert!(e.unusable, "{e}");
            assert!(
                e.message
                    .contains(&format!("`{field}` is not a field of type `{of}`")),
                "{body}: {e}"
            );
            assert!(!e.message.contains(MARK), "{body}: {e}");
        }
    }

    #[test]
    fn a_file_of_another_kind_than_configured_is_refused() {
        let (s, _) = store(None);
        let f = file("kind", r#"{"type":"api_key","key":"test-token-1"}"#, 0o600);
        let e = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap_err();
        assert!(e.unusable, "{e}");
        assert!(
            e.message
                .contains("has type `api_key`, the config says `oauth_anthropic`"),
            "{e}"
        );
    }

    #[test]
    fn files_open_to_others_are_refused() {
        let (s, _) = store(None);
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let f = file("mode", r#"{"type":"api_key","key":"test-token-1"}"#, mode);
            let e = s.load(&entry("login-1", &f, KEY), NOW, false).unwrap_err();
            assert!(
                e.unusable && e.message.contains("too open"),
                "{mode:o}: {e}"
            );
        }
        let d = dir("link");
        let target = file("target", r#"{"type":"api_key","key":"k"}"#, 0o600);
        std::os::unix::fs::symlink(&target, d.join("link.json")).unwrap();
        assert!(
            s.load(&entry("login-1", &d.join("link.json"), KEY), NOW, false)
                .is_err()
        );
    }

    #[test]
    fn an_expiring_token_is_refreshed_and_written_back_atomically() {
        let (s, calls) = store(None);
        let f = file("refresh", &oauth("access-0", NOW + 30), 0o600);
        let c = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap();
        assert_eq!(c.secret(), "access-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let meta = std::fs::metadata(&f).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        assert_eq!(stored["access_token"], "access-1");
        assert_eq!(stored["refresh_token"], format!("refresh-{MARK}-1"));
        assert_eq!(stored["expires_at"], NOW + 3600);
        let left: Vec<_> = std::fs::read_dir(f.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["login-1.json"], "no temporary file is left");
        let again = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap();
        assert_eq!(again.secret(), "access-1");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh token is not refreshed"
        );
    }

    #[test]
    fn a_stale_token_is_refreshed_once_across_attempts() {
        let (s, calls) = store(None);
        let f = file("stale", &oauth("access-0", NOW + 600), 0o600);
        assert_eq!(
            s.load(&entry("login-1", &f, KIND), NOW, true)
                .unwrap()
                .secret(),
            "access-1"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_refresh_leaves_the_file_alone() {
        for rejected in [true, false] {
            let (s, _) = store(Some(rejected));
            let body = oauth("access-0", NOW);
            let f = file("fail", &body, 0o600);
            let e = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap_err();
            assert_eq!(e.unusable, rejected);
            assert!(!e.message.contains(MARK), "{e}");
            assert_eq!(std::fs::read_to_string(&f).unwrap(), body);
        }
    }

    #[test]
    fn an_unwritable_directory_keeps_the_old_file() {
        let (s, _) = store(None);
        let body = oauth("access-0", NOW);
        let f = file("ro", &body, 0o600);
        let d = f.parent().unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o500)).unwrap();
        let probe = d.join("probe");
        if std::fs::write(&probe, "").is_ok() {
            // Running as root: directory modes do not bind, nothing to check.
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let e = s.load(&entry("login-1", &f, KIND), NOW, false).unwrap_err();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(e.message.contains("cannot write"), "{e}");
        assert!(!e.message.contains(MARK), "{e}");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), body);
    }

    #[test]
    fn readers_never_see_a_partial_file_while_refreshes_run() {
        let (s, _) = store(None);
        let f = file("race", &oauth("access-0", NOW), 0o600);
        let reader = {
            let f = f.clone();
            std::thread::spawn(move || {
                let (s, _) = store(None);
                for _ in 0..300 {
                    let c = s
                        .load(&entry("login-1", &f, KIND), NOW - 7200, false)
                        .unwrap();
                    assert!(c.secret().starts_with("access-"));
                }
            })
        };
        for _ in 0..100 {
            s.load(&entry("login-1", &f, KIND), NOW, true).unwrap();
        }
        reader.join().unwrap();
    }

    /// Blocks the refresh of `login-1` until `release` gets a message; others refresh at once.
    struct Stuck {
        entered: Mutex<mpsc::Sender<()>>,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl Refresher for Stuck {
        fn refresh(&self, login: &GatewayLogin, _: &str) -> Result<Refreshed, RefreshError> {
            let login = login.name.as_str();
            if login == "login-1" {
                self.entered.lock().unwrap().send(()).unwrap();
                let release = self.release.lock().unwrap();
                release.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            Ok(Refreshed {
                access_token: Zeroizing::new(format!("access-{login}")),
                refresh_token: None,
                expires_at: NOW + 3600,
            })
        }
    }

    #[test]
    fn a_hanging_refresh_blocks_only_its_own_login() {
        let (entered, on_enter) = mpsc::channel();
        let (release, on_release) = mpsc::channel();
        let s = Arc::new(CredentialStore::new(Box::new(Stuck {
            entered: Mutex::new(entered),
            release: Mutex::new(on_release),
        })));
        let one = file("one", &oauth("access-0", NOW), 0o600);
        let two = file("two", &oauth("access-0", NOW), 0o600);
        let stuck = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || s.load(&entry("login-1", &one, KIND), NOW, true).unwrap())
        };
        on_enter.recv_timeout(Duration::from_secs(10)).unwrap();
        let (done, finished) = mpsc::channel();
        let other = {
            let s = Arc::clone(&s);
            std::thread::spawn(move || {
                let c = s.load(&entry("login-2", &two, KIND), NOW, true).unwrap();
                done.send(c.secret().to_owned()).unwrap();
            })
        };
        let got = finished.recv_timeout(Duration::from_secs(5));
        release.send(()).unwrap();
        assert_eq!(got.as_deref(), Ok("access-login-2"));
        other.join().unwrap();
        assert_eq!(stuck.join().unwrap().secret(), "access-login-1");
    }

    #[test]
    fn two_logins_of_one_file_refresh_it_once() {
        let (s, calls) = store(None);
        let s = Arc::new(s);
        let f = file("shared", &chatgpt(Some("refresh-0"), NOW + 30), 0o600);
        let load = |login: &'static str| {
            let (s, f) = (Arc::clone(&s), f.clone());
            std::thread::spawn(move || s.load(&entry(login, &f, CHATGPT), NOW, false).unwrap())
        };
        let (one, two) = (load("login-1"), load("login-2"));
        for t in [one, two] {
            assert_eq!(t.join().unwrap().secret(), "access-1");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn errors_name_the_file_and_field_never_the_value() {
        let (s, _) = store(None);
        let cases = [
            (
                format!(r#"{{"type":"api_key","key":"{MARK}""#),
                "not valid JSON",
            ),
            (
                format!(r#"{{"type":"api_key","token":"{MARK}"}}"#),
                "missing or invalid",
            ),
            (
                format!(r#"{{"type":"oauth","key":"{MARK}"}}"#),
                "`type` is missing or invalid",
            ),
            (
                format!(r#"{{"type":"oauth_anthropic","key":"{MARK}"}}"#),
                "no `access_token`",
            ),
            (
                format!(r#"{{"type":"api_key","key":"{MARK}\r\nX: 1"}}"#),
                "not a non-empty visible ASCII",
            ),
            (
                format!(r#"{{"type":"api_key","key":"a"}} {MARK}"#),
                "trailing data",
            ),
            (
                format!(r#"{{"type":"api_key","access_token":"{MARK}"}}"#),
                "no `key`",
            ),
            (
                format!(r#"{{"type":"oauth_anthropic","access_token":"{MARK}","expires_at":1}}"#),
                "no `refresh_token`",
            ),
        ];
        for (body, want) in cases {
            let f = file("leak", &body, 0o600);
            let kind = if body.contains("api_key") { KEY } else { KIND };
            let e = s.load(&entry("login-1", &f, kind), NOW, false).unwrap_err();
            assert!(e.message.starts_with(&f.display().to_string()), "{e}");
            assert!(e.message.contains(want), "{body}: {e}");
            assert!(!e.message.contains(MARK), "{body}: {e}");
        }
    }
}
