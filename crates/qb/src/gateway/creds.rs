//! The gateway's credential files: one JSON file per login, mode 0600, owned by the gateway's
//! user, read for one attempt and zeroized. An expired OAuth token is refreshed through a
//! [`Refresher`] and written back atomically. No error message ever quotes a file's contents.
//!
//! ```json
//! {"type": "oauth_anthropic", "access_token": "...", "refresh_token": "...", "expires_at": 1800000000}
//! {"type": "api_key", "key": "..."}
//! ```

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::upstream::Credential;

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
    /// Refreshes `login`'s tokens with `refresh_token`.
    ///
    /// # Errors
    /// The vendor refused (`rejected`) or could not be asked.
    fn refresh(&self, login: &str, refresh_token: &str) -> Result<Refreshed, RefreshError>;
}

/// A [`Refresher`] for builds without a vendor refresh: every refresh fails, not rejected.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRefresher;

impl Refresher for NoRefresher {
    fn refresh(&self, _: &str, _: &str) -> Result<Refreshed, RefreshError> {
        Err(RefreshError {
            rejected: false,
            message: "no OAuth refresher is configured".into(),
        })
    }
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

/// A secret string from a credential file, zeroized on drop.
struct Secret(Zeroizing<String>);

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Kind {
    OauthAnthropic,
    ApiKey,
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
}

#[derive(Serialize)]
struct Written<'a> {
    #[serde(rename = "type")]
    kind: Kind,
    access_token: &'a str,
    refresh_token: &'a str,
    expires_at: u64,
}

/// Loads credentials and refreshes expired OAuth tokens, one refresh at a time.
pub struct CredentialStore {
    refresher: Box<dyn Refresher>,
    refreshing: Mutex<()>,
}

impl CredentialStore {
    /// A store that refreshes through `refresher`.
    pub fn new(refresher: Box<dyn Refresher>) -> Self {
        Self {
            refresher,
            refreshing: Mutex::new(()),
        }
    }

    /// The credential of `login` in `file` at `now`. An OAuth token expiring within
    /// [`REFRESH_MARGIN_S`], or any token when `stale` (the vendor just rejected it), is
    /// refreshed first unless another attempt already replaced it.
    ///
    /// # Errors
    /// The file is unreadable, too open, malformed, or the refresh failed.
    pub fn load(
        &self,
        login: &str,
        file: &Path,
        now: u64,
        stale: bool,
    ) -> Result<Credential, CredError> {
        let first = read(file)?;
        let token = match first.kind {
            Kind::ApiKey => {
                let key = secret(file, "key", first.key.as_ref())?;
                return Ok(Credential::ApiKey { key });
            }
            Kind::OauthAnthropic => secret(file, "access_token", first.access_token.as_ref())?,
        };
        let expiring = first
            .expires_at
            .is_some_and(|at| at <= now.saturating_add(REFRESH_MARGIN_S));
        if !stale && !expiring {
            return Ok(Credential::OauthAnthropic {
                access_token: token,
            });
        }
        let _one = self
            .refreshing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let again = read(file)?;
        let current = secret(file, "access_token", again.access_token.as_ref())?;
        let replaced = *current != *token
            && again
                .expires_at
                .is_none_or(|at| at > now.saturating_add(REFRESH_MARGIN_S));
        if replaced {
            return Ok(Credential::OauthAnthropic {
                access_token: current,
            });
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
        let mut body = Zeroizing::new(Vec::with_capacity(
            128 + fresh.access_token.len() + kept.len(),
        ));
        let written = Written {
            kind: Kind::OauthAnthropic,
            access_token: &fresh.access_token,
            refresh_token: kept,
            expires_at: fresh.expires_at,
        };
        serde_json::to_writer(&mut *body, &written).map_err(|e| CredError {
            unusable: false,
            message: format!("{}: encode failed: {e}", file.display()),
        })?;
        write_atomic(file, &body).map_err(|e| CredError {
            unusable: false,
            message: format!("{}: cannot write the refreshed token: {e}", file.display()),
        })?;
        Ok(Credential::OauthAnthropic {
            access_token: fresh.access_token,
        })
    }
}

fn unusable(file: &Path, what: impl fmt::Display) -> CredError {
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
    let mut de = serde_json::Deserializer::from_slice(&bytes);
    let stored = serde_path_to_error::deserialize(&mut de).map_err(|e| {
        if e.inner().is_data() {
            unusable(file, format_args!("`{}` is missing or invalid", e.path()))
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
    Ok(stored)
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
fn secret(file: &Path, field: &str, s: Option<&Secret>) -> Result<Zeroizing<String>, CredError> {
    let Some(s) = s else {
        return Err(unusable(file, format_args!("no `{field}`")));
    };
    visible(file, field, &s.0)?;
    Ok(s.0.clone())
}

fn visible(file: &Path, field: &str, value: &str) -> Result<(), CredError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(unusable(
            file,
            format_args!("`{field}` is not a non-empty visible ASCII string"),
        ));
    }
    Ok(())
}

/// Replaces `file` with `bytes` so that a reader sees the old or the new file, never a part:
/// a 0600 temporary file in the same directory, fsync, rename, fsync of the directory.
///
/// # Errors
/// Any step failed; the temporary file is removed and `file` is unchanged.
pub fn write_atomic(file: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = file
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = file.file_name().map_or_else(
        || "credentials".into(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp: PathBuf = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, file)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    const NOW: u64 = 1_800_000_000;
    /// A synthetic marker standing in for a token; it must never appear in an error.
    const MARK: &str = "test-token-7f3a";

    fn dir(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "qb-creds-{}-{tag}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
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
        fn refresh(&self, _: &str, refresh_token: &str) -> Result<Refreshed, RefreshError> {
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
        let c = s.load("login-1", &f, NOW, false).unwrap();
        assert_eq!((c.kind(), c.secret()), ("api_key", "test-token-1"));
        let f = file("fresh", &oauth("access-0", NOW + 600), 0o600);
        let c = s.load("login-1", &f, NOW, false).unwrap();
        assert_eq!((c.kind(), c.secret()), ("oauth_anthropic", "access-0"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn files_open_to_others_are_refused() {
        let (s, _) = store(None);
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let f = file("mode", r#"{"type":"api_key","key":"test-token-1"}"#, mode);
            let e = s.load("login-1", &f, NOW, false).unwrap_err();
            assert!(
                e.unusable && e.message.contains("too open"),
                "{mode:o}: {e}"
            );
        }
        let d = dir("link");
        let target = file("target", r#"{"type":"api_key","key":"k"}"#, 0o600);
        std::os::unix::fs::symlink(&target, d.join("link.json")).unwrap();
        assert!(s.load("login-1", &d.join("link.json"), NOW, false).is_err());
    }

    #[test]
    fn an_expiring_token_is_refreshed_and_written_back_atomically() {
        let (s, calls) = store(None);
        let f = file("refresh", &oauth("access-0", NOW + 30), 0o600);
        let c = s.load("login-1", &f, NOW, false).unwrap();
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
        let again = s.load("login-1", &f, NOW, false).unwrap();
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
            s.load("login-1", &f, NOW, true).unwrap().secret(),
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
            let e = s.load("login-1", &f, NOW, false).unwrap_err();
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
        let e = s.load("login-1", &f, NOW, false).unwrap_err();
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
                    let c = s.load("login-1", &f, NOW - 7200, false).unwrap();
                    assert!(c.secret().starts_with("access-"));
                }
            })
        };
        for _ in 0..100 {
            s.load("login-1", &f, NOW, true).unwrap();
        }
        reader.join().unwrap();
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
                format!(r#"{{"type":"oauth_anthropic","access_token":"{MARK}","expires_at":1}}"#),
                "no `refresh_token`",
            ),
        ];
        for (body, want) in cases {
            let f = file("leak", &body, 0o600);
            let e = s.load("login-1", &f, NOW, false).unwrap_err();
            assert!(e.message.starts_with(&f.display().to_string()), "{e}");
            assert!(e.message.contains(want), "{body}: {e}");
            assert!(!e.message.contains(MARK), "{body}: {e}");
        }
    }
}
