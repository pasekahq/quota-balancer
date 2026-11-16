//! The daemon's TOML config: schema, parsing and validation. The format is described in
//! `docs/config.md`; [`load`] is the only way `qbd` obtains a [`Config`].

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use qb_core::{LoginSpec, MAX_CANDIDATES, MAX_LOGINS, MAX_WINDOWS};
use serde::Deserialize;
use serde::de::{self, Deserializer};

/// Why a config was refused: the file, the field path (empty for the whole file) and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The config file.
    pub file: PathBuf,
    /// Field path such as `roles[0].ladder[1].candidates[2].vendor`.
    pub field: String,
    /// What is wrong with it.
    pub reason: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            write!(f, "{}: {}", self.file.display(), self.reason)
        } else {
            write!(
                f,
                "{}: {}: {}",
                self.file.display(),
                self.field,
                self.reason
            )
        }
    }
}

impl std::error::Error for Error {}

/// A validated daemon config.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Vendors and their quota windows.
    pub vendors: Vec<Vendor>,
    /// Logins, at most [`MAX_LOGINS`].
    pub logins: Vec<Login>,
    /// Roles with their ladders and reserves.
    pub roles: Vec<Role>,
    /// Known clients.
    #[serde(default)]
    pub clients: Vec<Client>,
    /// Where leases and dead-until marks are journaled.
    pub journal: Journal,
    /// Quota snapshot freshness.
    #[serde(default)]
    pub snapshot: Snapshot,
    /// Back-off of the agent's vendor probes.
    #[serde(default)]
    pub probe: Probe,
    /// Per-client request rate limit.
    #[serde(default)]
    pub limits: Limits,
}

/// A vendor and the quota windows every login of it has.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vendor {
    /// Vendor id, e.g. `vendor-a`.
    pub name: String,
    /// Quota windows, at most [`MAX_WINDOWS`].
    pub windows: Vec<Window>,
}

/// A rolling quota window of a vendor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    /// Window name as reported by clients, e.g. `five_hour`.
    pub name: String,
    /// Window length in seconds.
    pub length_s: u64,
    /// `T_burn`: inside this many seconds before a reset the role reserves are dropped.
    pub t_burn_s: u64,
}

/// A login of a vendor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    /// Unique name, e.g. `login-1`.
    pub name: String,
    /// Declared vendor the login belongs to.
    pub vendor: String,
}

/// A role of work with its ladder and reserves.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    /// Role name used in `pick` requests, e.g. `worker`.
    pub name: String,
    /// Ladder steps, one per difficulty.
    pub ladder: Vec<Step>,
    /// Reserves `R(role, difficulty, window)`.
    #[serde(default)]
    pub reserves: Vec<Reserve>,
}

/// One ladder step: the candidates for a difficulty, in preference order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Difficulty this step serves.
    pub difficulty: u8,
    /// Candidates, 1 to [`MAX_CANDIDATES`].
    pub candidates: Vec<Candidate>,
}

/// A vendor/model/effort combination a ladder step may run on.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Declared vendor.
    pub vendor: String,
    /// Model name passed to the vendor CLI.
    pub model: String,
    /// Reasoning effort, if the vendor has one.
    pub effort: Option<String>,
    /// Tier; lower tiers are preferred.
    pub tier: u8,
}

/// Fraction of a window a role keeps free at a difficulty.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reserve {
    /// Difficulty of a ladder step of the same role.
    pub difficulty: u8,
    /// Name of a window declared by some vendor.
    pub window: String,
    /// Reserved fraction of the window.
    pub fraction: Fraction,
}

/// A client allowed to talk to the daemon, identified by peer uid, bearer token or both.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    /// Name used in leases and the journal.
    pub name: String,
    /// Local peer uid (`SO_PEERCRED`).
    pub uid: Option<u32>,
    /// SHA-256 of the client's bearer token.
    pub bearer_sha256: Option<BearerHash>,
    /// Declared role the client works as.
    pub role: String,
}

/// Journal mode.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Journal {
    /// Append to a file, rotating it at a size.
    Path {
        /// Absolute path of the journal file.
        path: PathBuf,
        /// Rotation size in bytes.
        #[serde(default = "default_rotate_bytes")]
        rotate_bytes: u64,
    },
    /// Write nothing to disk.
    Off {},
}

fn default_rotate_bytes() -> u64 {
    1 << 20
}

/// Quota snapshot settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Snapshot {
    /// Seconds after which a window snapshot is stale.
    pub ttl_s: u64,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self { ttl_s: 300 }
    }
}

/// Exponential back-off of the agent's vendor probes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Probe {
    /// First back-off in seconds.
    pub backoff_initial_s: u64,
    /// Back-off ceiling in seconds.
    pub backoff_max_s: u64,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            backoff_initial_s: 30,
            backoff_max_s: 3600,
        }
    }
}

/// Token bucket applied to each client separately.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Refill rate in requests per second.
    pub rate_per_s: f64,
    /// Bucket size in requests.
    pub burst: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            rate_per_s: 5.0,
            burst: 20,
        }
    }
}

/// A number in `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Fraction(f64);

impl Fraction {
    /// The value.
    pub fn get(self) -> f64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Fraction {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = f64::deserialize(d)?;
        if (0.0..=1.0).contains(&v) {
            Ok(Self(v))
        } else {
            Err(de::Error::custom(format_args!("{v} is outside 0.0..=1.0")))
        }
    }
}

/// SHA-256 digest of a bearer token, written as 64 hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BearerHash(pub [u8; 32]);

impl<'de> Deserialize<'de> for BearerHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(d)?;
        // The value is never echoed: a misplaced plaintext token must not reach the logs.
        let invalid = || de::Error::custom("expected the token's SHA-256 as 64 hex characters");
        if hex.len() != 64 {
            return Err(invalid());
        }
        let mut out = [0; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(out))
    }
}

/// Reads and validates the config file at `file`.
///
/// # Errors
/// The file cannot be read or does not validate.
pub fn load(file: &Path) -> Result<Config, Error> {
    let text = std::fs::read_to_string(file).map_err(|e| Error {
        file: file.to_owned(),
        field: String::new(),
        reason: format!("cannot read: {e}"),
    })?;
    parse(file, &text)
}

/// Parses and validates config `text`; `file` only names the source in errors.
///
/// # Errors
/// The text is not TOML or does not validate.
pub fn parse(file: &Path, text: &str) -> Result<Config, Error> {
    let error = |field: String, reason: String| Error {
        file: file.to_owned(),
        field,
        reason,
    };
    let tree: serde_json::Value =
        basic_toml::from_str(text).map_err(|e| error(String::new(), e.to_string()))?;
    let config: Config = serde_path_to_error::deserialize(tree).map_err(|e| {
        let field = e.path().to_string();
        let field = if field == "." { String::new() } else { field };
        error(field, e.into_inner().to_string())
    })?;
    config
        .validate()
        .map_err(|(field, reason)| error(field, reason))?;
    Ok(config)
}

/// A validation failure: field path and reason.
type Fault = (String, String);

impl Config {
    /// The configured logins as core types, in config order.
    pub fn login_specs(&self) -> Vec<LoginSpec> {
        self.logins
            .iter()
            .map(|l| LoginSpec {
                name: l.name.clone(),
                vendor: l.vendor.clone(),
            })
            .collect()
    }

    fn validate(&self) -> Result<(), Fault> {
        let vendors = declare("vendors", self.vendors.iter().map(|v| v.name.as_str()))?;
        let mut windows = HashSet::new();
        for (i, vendor) in self.vendors.iter().enumerate() {
            let at = format!("vendors[{i}].windows");
            if vendor.windows.len() > MAX_WINDOWS {
                return Err(too_many(at, vendor.windows.len(), MAX_WINDOWS));
            }
            declare(&at, vendor.windows.iter().map(|w| w.name.as_str()))?;
            for (j, w) in vendor.windows.iter().enumerate() {
                let at = format!("{at}[{j}]");
                if w.length_s == 0 {
                    return Err((format!("{at}.length_s"), "must be positive".into()));
                }
                if w.t_burn_s > w.length_s {
                    return Err((format!("{at}.t_burn_s"), "exceeds length_s".into()));
                }
                windows.insert(w.name.as_str());
            }
        }

        if self.logins.len() > MAX_LOGINS {
            return Err(too_many("logins".into(), self.logins.len(), MAX_LOGINS));
        }
        declare("logins", self.logins.iter().map(|l| l.name.as_str()))?;
        for (i, login) in self.logins.iter().enumerate() {
            known(
                &vendors,
                format!("logins[{i}].vendor"),
                "vendor",
                &login.vendor,
            )?;
        }

        let roles = declare("roles", self.roles.iter().map(|r| r.name.as_str()))?;
        for (i, role) in self.roles.iter().enumerate() {
            role.validate(&format!("roles[{i}]"), &vendors, &windows)?;
        }

        declare("clients", self.clients.iter().map(|c| c.name.as_str()))?;
        let (mut uids, mut bearers) = (HashSet::new(), HashSet::new());
        for (i, client) in self.clients.iter().enumerate() {
            let at = format!("clients[{i}]");
            if client.uid.is_none() && client.bearer_sha256.is_none() {
                return Err((at, "needs `uid`, `bearer_sha256` or both".into()));
            }
            if let Some(uid) = client.uid {
                if !uids.insert(uid) {
                    return Err((format!("{at}.uid"), format!("duplicate uid {uid}")));
                }
            }
            if let Some(hash) = client.bearer_sha256 {
                if !bearers.insert(hash) {
                    return Err((format!("{at}.bearer_sha256"), "duplicate hash".into()));
                }
            }
            known(&roles, format!("{at}.role"), "role", &client.role)?;
        }

        self.validate_settings()
    }

    fn validate_settings(&self) -> Result<(), Fault> {
        if let Journal::Path { path, rotate_bytes } = &self.journal {
            if !path.is_absolute() {
                return Err(("journal.path".into(), "must be absolute".into()));
            }
            if *rotate_bytes == 0 {
                return Err(("journal.rotate_bytes".into(), "must be positive".into()));
            }
        }
        if self.snapshot.ttl_s == 0 {
            return Err(("snapshot.ttl_s".into(), "must be positive".into()));
        }
        if self.probe.backoff_initial_s == 0 {
            return Err(("probe.backoff_initial_s".into(), "must be positive".into()));
        }
        if self.probe.backoff_max_s < self.probe.backoff_initial_s {
            return Err((
                "probe.backoff_max_s".into(),
                "is below backoff_initial_s".into(),
            ));
        }
        if !(self.limits.rate_per_s.is_finite() && self.limits.rate_per_s > 0.0) {
            return Err(("limits.rate_per_s".into(), "must be positive".into()));
        }
        if self.limits.burst == 0 {
            return Err(("limits.burst".into(), "must be positive".into()));
        }
        Ok(())
    }
}

impl Role {
    fn validate(
        &self,
        at: &str,
        vendors: &HashSet<&str>,
        windows: &HashSet<&str>,
    ) -> Result<(), Fault> {
        let mut steps = HashSet::new();
        for (j, step) in self.ladder.iter().enumerate() {
            let at = format!("{at}.ladder[{j}]");
            if !steps.insert(step.difficulty) {
                let reason = format!("duplicate difficulty {}", step.difficulty);
                return Err((format!("{at}.difficulty"), reason));
            }
            let n = step.candidates.len();
            if n == 0 {
                return Err((format!("{at}.candidates"), "is empty".into()));
            }
            if n > MAX_CANDIDATES {
                return Err(too_many(format!("{at}.candidates"), n, MAX_CANDIDATES));
            }
            for (k, c) in step.candidates.iter().enumerate() {
                let at = format!("{at}.candidates[{k}]");
                known(vendors, format!("{at}.vendor"), "vendor", &c.vendor)?;
                if c.model.is_empty() {
                    return Err((format!("{at}.model"), "is empty".into()));
                }
            }
        }
        let mut reserved = HashSet::new();
        for (j, r) in self.reserves.iter().enumerate() {
            let at = format!("{at}.reserves[{j}]");
            if !steps.contains(&r.difficulty) {
                let reason = format!("no ladder step with difficulty {}", r.difficulty);
                return Err((format!("{at}.difficulty"), reason));
            }
            known(windows, format!("{at}.window"), "window", &r.window)?;
            if !reserved.insert((r.difficulty, r.window.as_str())) {
                let reason = format!(
                    "duplicate reserve for difficulty {} and window `{}`",
                    r.difficulty, r.window
                );
                return Err((at, reason));
            }
        }
        Ok(())
    }
}

/// Checks that the names of list `list` are non-empty and unique and returns them.
fn declare<'a>(
    list: &str,
    names: impl Iterator<Item = &'a str>,
) -> Result<HashSet<&'a str>, Fault> {
    let mut set = HashSet::new();
    for (i, name) in names.enumerate() {
        let field = format!("{list}[{i}].name");
        if name.is_empty() {
            return Err((field, "is empty".into()));
        }
        if !set.insert(name) {
            return Err((field, format!("duplicate name `{name}`")));
        }
    }
    Ok(set)
}

fn known(declared: &HashSet<&str>, field: String, kind: &str, name: &str) -> Result<(), Fault> {
    if declared.contains(name) {
        Ok(())
    } else {
        Err((field, format!("undeclared {kind} `{name}`")))
    }
}

fn too_many(field: String, n: usize, max: usize) -> Fault {
    (field, format!("{n} entries, at most {max} allowed"))
}
