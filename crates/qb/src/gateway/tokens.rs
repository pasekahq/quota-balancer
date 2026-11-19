//! The tokens of the named loopback clients with a `token_file`: the hash of each file's token,
//! read at start and on every reload, a rotation that writes a fresh token to the file, and the
//! previous hash, accepted until its grace runs out and kept in the `grace_file` across restarts.
//! Only hashes stay in memory or reach the grace file.

use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::path::Path;

use qb_proto::{ClientRotateAnswer, ErrorClass};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::config::{ClientToken, FrontClient, Fronts, GatewayConfig};
use super::creds::write_atomic;
use super::{Refusal, base64url};
use crate::auth::token_matches;
use crate::config::{BearerHash, Error};
use crate::{log, sha256};

/// Largest token file in bytes.
pub const MAX_TOKEN_FILE: usize = 4096;

/// Largest grace file in bytes.
const MAX_GRACE_FILE: usize = 1 << 20;

/// Hex characters of a token's SHA-256 that an answer or an audit line shows.
pub const PREFIX_HEX: usize = 12;

/// The previous token hash of `client`, accepted while the time is before `until`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Previous {
    client: String,
    sha256: BearerHash,
    until: u64,
}

/// The accepted hashes of the `token_file` clients: the current one of each and the previous
/// one within its grace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTokens {
    current: Vec<(String, BearerHash)>,
    previous: Vec<Previous>,
}

/// The grace file: the previous hash of each rotated client and its end of grace.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraceFile {
    previous: Vec<GraceLine>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraceLine {
    client: String,
    token_sha256: String,
    until: u64,
}

impl ClientTokens {
    /// The tokens of `config` at start: the hash of each `token_file`, and the previous hashes of
    /// its `grace_file` whose grace lasts past `now`.
    ///
    /// # Errors
    /// A token file fails [`read`], or the grace file cannot be read as one.
    pub fn load(config: &GatewayConfig, now: u64) -> Result<Self, String> {
        let current = read(config).map_err(|e| e.to_string())?;
        let previous = match config.fronts.as_ref().and_then(|f| f.grace_file.as_deref()) {
            Some(file) => read_grace(file, now).map_err(|e| format!("{}: {e}", file.display()))?,
            None => Vec::new(),
        };
        Ok(Self { current, previous })
    }

    /// These tokens with the current hashes `current`, as [`read`] returns them, and the same
    /// previous ones.
    #[must_use]
    pub fn with_current(&self, current: Vec<(String, BearerHash)>) -> Self {
        Self {
            current,
            previous: self.previous.clone(),
        }
    }

    /// Whether `token` is the token of `client` at `now`: its `token_sha256`, or the current or,
    /// within its grace, the previous token of its `token_file`. Each hash is compared in
    /// constant time.
    pub fn accepts(&self, client: &FrontClient, token: &str, now: u64) -> bool {
        match &client.token {
            ClientToken::Sha256(hash) => token_matches(token, hash),
            ClientToken::File(_) => {
                let current = self.current.iter().filter(|(name, _)| *name == client.name);
                let previous = self
                    .previous
                    .iter()
                    .filter(|p| p.client == client.name && now < p.until);
                current
                    .map(|(_, hash)| hash)
                    .chain(previous.map(|p| &p.sha256))
                    .any(|hash| token_matches(token, hash))
            }
        }
    }

    /// Writes a fresh token to the `token_file` of the named client `name` of `fronts` at `now`;
    /// the hash it replaces stays accepted for `rotate_grace_s`, in the grace file first. Returns
    /// the tokens that accept the new token and the answer.
    ///
    /// # Errors
    /// 404 for an unknown client, 409 for a client with `token_sha256`, 500 when a file cannot
    /// be written; the token file and these tokens stay as they were.
    pub fn rotate(
        &self,
        fronts: Option<&Fronts>,
        name: &str,
        now: u64,
    ) -> Result<(Self, ClientRotateAnswer), Refusal> {
        let found = fronts.and_then(|f| Some((f, f.clients.iter().find(|c| c.name == name)?)));
        let Some((fronts, client)) = found else {
            let message = format!("no `[[fronts.clients]]` entry is named `{name}`");
            return Err(Refusal::new(404, ErrorClass::BadRequest, message));
        };
        let ClientToken::File(file) = &client.token else {
            let message = format!(
                "client `{name}` has a `token_sha256`, not a `token_file` the gateway can write"
            );
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        };
        let failed = |message: String| Refusal::new(500, ErrorClass::Unavailable, message);
        let Some(grace_file) = fronts.grace_file.as_deref() else {
            return Err(failed("the config has no `fronts.grace_file`".into()));
        };
        let Some(&(_, old)) = self.current.iter().find(|(n, _)| n == name) else {
            return Err(failed(format!(
                "the token of client `{name}` was never read"
            )));
        };
        let token = base64url::random().map_err(failed)?;
        let hash = BearerHash(sha256::digest(token.as_bytes()));
        let grace_until = now + u64::from(fronts.rotate_grace_s);
        let kept = |p: &&Previous| now < p.until && p.client != name;
        let mut previous: Vec<Previous> = self.previous.iter().filter(kept).cloned().collect();
        if now < grace_until {
            previous.push(Previous {
                client: name.to_owned(),
                sha256: old,
                until: grace_until,
            });
        }
        write_grace(grace_file, &previous).map_err(|e| {
            failed(format!(
                "cannot write the grace file {}: {e}",
                grace_file.display()
            ))
        })?;
        if let Err(e) = write_atomic(file, token.as_bytes()) {
            let live: Vec<Previous> = self
                .previous
                .iter()
                .filter(|p| now < p.until)
                .cloned()
                .collect();
            if let Err(back) = write_grace(grace_file, &live) {
                log::error(&format!(
                    "gateway: the grace file {} keeps the hash of a rotation that failed: {back}",
                    grace_file.display()
                ));
            }
            let message = format!(
                "cannot write the token file {}: {e}; the previous token stays",
                file.display()
            );
            return Err(failed(message));
        }
        let current = self
            .current
            .iter()
            .map(|(n, h)| (n.clone(), if n == name { hash } else { *h }))
            .collect();
        let answer = ClientRotateAnswer {
            client: name.to_owned(),
            token_sha256_prefix: prefix(&hash),
            grace_until,
        };
        Ok((Self { current, previous }, answer))
    }
}

/// The first [`PREFIX_HEX`] hex characters of `hash`.
pub(super) fn prefix(hash: &BearerHash) -> String {
    let mut hex = sha256::hex(hash.0);
    hex.truncate(PREFIX_HEX);
    hex
}

/// The SHA-256 of the token in each `token_file` of `config`, by client name.
///
/// # Errors
/// A file cannot be read, is larger than [`MAX_TOKEN_FILE`], is empty after one trailing newline
/// is cut, or holds the token of another client; the error names the field and the file, never
/// the content.
pub fn read(config: &GatewayConfig) -> Result<Vec<(String, BearerHash)>, Error> {
    let Some(fronts) = &config.fronts else {
        return Ok(Vec::new());
    };
    let mut current: Vec<(String, BearerHash)> = Vec::new();
    for (i, c) in fronts.clients.iter().enumerate() {
        let ClientToken::File(file) = &c.token else {
            continue;
        };
        let fail = |reason: String| Error {
            file: config.file.clone(),
            field: format!("fronts.clients[{i}].token_file"),
            reason: format!("{}: {reason}", file.display()),
        };
        let hash = read_token(file).map_err(fail)?;
        let taken = fronts.token_sha256 == Some(hash)
            || fronts
                .clients
                .iter()
                .any(|o| o.token == ClientToken::Sha256(hash))
            || current.iter().any(|(_, h)| *h == hash);
        if taken {
            return Err(fail("holds the token of another client".into()));
        }
        current.push((c.name.clone(), hash));
    }
    Ok(current)
}

/// The SHA-256 of the token in `file`: its bytes without one trailing newline, zeroized after.
fn read_token(file: &Path) -> Result<BearerHash, String> {
    let f = File::open(file).map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_FILE + 1));
    f.take(MAX_TOKEN_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_TOKEN_FILE {
        return Err(format!("is larger than {MAX_TOKEN_FILE} bytes"));
    }
    let token = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    if token.is_empty() {
        return Err("is empty".into());
    }
    Ok(BearerHash(sha256::digest(token)))
}

/// The previous hashes in the grace file `file` whose grace lasts past `now`; none when the file
/// does not exist.
fn read_grace(file: &Path, now: u64) -> Result<Vec<Previous>, String> {
    let f = match File::open(file) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut bytes = Vec::new();
    f.take(MAX_GRACE_FILE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_GRACE_FILE {
        return Err(format!("is larger than {MAX_GRACE_FILE} bytes"));
    }
    let grace: GraceFile = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut previous = Vec::with_capacity(grace.previous.len());
    for (i, line) in grace.previous.into_iter().enumerate() {
        let Some(sha256) = BearerHash::from_hex(&line.token_sha256) else {
            return Err(format!(
                "previous[{i}].token_sha256 is not 64 hex characters"
            ));
        };
        if now < line.until {
            previous.push(Previous {
                client: line.client,
                sha256,
                until: line.until,
            });
        }
    }
    Ok(previous)
}

/// Replaces the grace file `file` with `previous`, mode 0600.
fn write_grace(file: &Path, previous: &[Previous]) -> io::Result<()> {
    let grace = GraceFile {
        previous: previous
            .iter()
            .map(|p| GraceLine {
                client: p.client.clone(),
                token_sha256: sha256::hex(p.sha256.0),
                until: p.until,
            })
            .collect(),
    };
    let mut bytes = serde_json::to_vec(&grace)?;
    bytes.push(b'\n');
    write_atomic(file, &bytes)
}
