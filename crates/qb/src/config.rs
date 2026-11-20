//! The TOML configs of the daemon and the agent: schema, parsing and validation. The formats are
//! described in `docs/config.md`; [`load`] is the only way `qbd` obtains a [`Config`] and
//! [`load_agent`] the only way `qb agent` obtains an [`AgentConfig`].

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use qb_core::{
    CandidateSpec, LoginSpec, MAX_CANDIDATES, MAX_LOGINS, MAX_WINDOWS, ProbeSpec, ReserveSpec,
    RoleSpec, Spec, StepSpec, VendorSpec, WindowSpec,
};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use toml::de::DeTable;

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
    /// Absolute path of the file that holds the roles instead of this one.
    pub roles_file: Option<PathBuf>,
    /// Roles with their ladders and reserves, from this file or from `roles_file`.
    #[serde(default)]
    pub roles: Vec<Role>,
    /// Known clients.
    #[serde(default)]
    pub clients: Vec<Client>,
    /// Where leases and dead-until marks are journaled.
    pub journal: Journal,
    /// Quota snapshot freshness.
    #[serde(default)]
    pub snapshot: Snapshot,
    /// Lease lifetime and the default cost rate.
    #[serde(default)]
    pub leases: Leases,
    /// How long report outcome marks last.
    #[serde(default)]
    pub outcomes: Outcomes,
    /// Lazy probes by agents: on or off, who may act as an agent, back-off.
    #[serde(default)]
    pub probe: Probe,
    /// Per-client request rate limit.
    #[serde(default)]
    pub limits: Limits,
    /// Commands run when a login enters or leaves `auth_dead`.
    #[serde(default)]
    pub hooks: Hooks,
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

/// The contents of a `roles_file`: roles and nothing else.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesFile {
    roles: Vec<Role>,
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
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Difficulty this step serves.
    pub difficulty: u8,
    /// Candidates, 1 to [`MAX_CANDIDATES`].
    pub candidates: Vec<Candidate>,
}

/// A vendor/model/effort combination a ladder step may run on.
#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    /// Fraction of the vendor's shortest window one minute of work uses; defaults to
    /// [`Leases::cost_per_minute`].
    pub cost_per_minute: Option<Fraction>,
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
    /// Declared role the client works as; only a client listed in `[probe] agents` may omit it.
    pub role: Option<String>,
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

/// Lease settings.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Leases {
    /// A lease expires this long after its pick plus the task's `expected_minutes`.
    pub ttl_s: u64,
    /// Cost rate of candidates without their own and of pins without a matching candidate.
    pub cost_per_minute: Fraction,
}

impl Default for Leases {
    fn default() -> Self {
        Self {
            ttl_s: 3600,
            cost_per_minute: Fraction(0.002),
        }
    }
}

/// Durations of the marks report outcomes set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Outcomes {
    /// How long a login stays `rate_limited` after `http_429`.
    pub rate_limit_backoff_s: u64,
    /// How long a (login, model) pair stays dead after `model_unavailable`.
    pub model_unavailable_s: u64,
}

impl Default for Outcomes {
    fn default() -> Self {
        Self {
            rate_limit_backoff_s: 60,
            model_unavailable_s: 86_400,
        }
    }
}

/// Lazy probes by agents and their exponential back-off.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Probe {
    /// Hand out probe jobs; off, agents may wait but never get one.
    pub enabled: bool,
    /// Declared clients that may act as agents.
    pub agents: Vec<String>,
    /// First back-off in seconds.
    pub backoff_initial_s: u64,
    /// Back-off ceiling in seconds.
    pub backoff_max_s: u64,
}

impl Default for Probe {
    fn default() -> Self {
        Self {
            enabled: false,
            agents: Vec::new(),
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

/// Commands `qbd` execs, without a shell, on a login's `auth_dead` edges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Hooks {
    /// Absolute program path and arguments, run when a login becomes `auth_dead`.
    pub on_dead: Option<Vec<String>>,
    /// Absolute program path and arguments, run when a login leaves `auth_dead`.
    pub on_recover: Option<Vec<String>>,
}

impl Hooks {
    fn validate(&self) -> Result<(), Fault> {
        for (key, command) in [("on_dead", &self.on_dead), ("on_recover", &self.on_recover)] {
            let Some(command) = command else { continue };
            let Some(program) = command.first() else {
                return Err((format!("hooks.{key}"), "is empty".into()));
            };
            if !Path::new(program).is_absolute() {
                return Err((format!("hooks.{key}[0]"), "must be an absolute path".into()));
            }
        }
        Ok(())
    }
}

/// A validated agent config: the logins this agent probes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Logins, 1 to [`MAX_LOGINS`], named as in the daemon's config.
    pub logins: Vec<AgentLogin>,
}

/// A login the agent holds credentials for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentLogin {
    /// Login name in the daemon's config.
    pub name: String,
    /// Which vendor's usage endpoint and response format the login uses.
    pub kind: Kind,
    /// The vendor CLI's credential file; relative paths start at the working directory.
    pub credentials: PathBuf,
}

/// The usage endpoint family of a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Claude `oauth/usage`.
    Claude,
    /// Codex `wham/usage`.
    Codex,
}

impl AgentConfig {
    fn validate(&self) -> Result<(), Fault> {
        if self.logins.is_empty() {
            return Err(("logins".into(), "is empty".into()));
        }
        if self.logins.len() > MAX_LOGINS {
            return Err(too_many("logins".into(), self.logins.len(), MAX_LOGINS));
        }
        declare("logins", self.logins.iter().map(|l| l.name.as_str()))?;
        for (i, login) in self.logins.iter().enumerate() {
            if login.credentials.as_os_str().is_empty() {
                return Err((format!("logins[{i}].credentials"), "is empty".into()));
            }
        }
        Ok(())
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

impl BearerHash {
    /// The hash in `hex`, 64 hex characters.
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self(out))
    }
}

/// The value is never echoed: a misplaced plaintext token must not reach the logs.
pub(crate) const BEARER_HASH_EXPECTED: &str = "expected the token's SHA-256 as 64 hex characters";

impl<'de> Deserialize<'de> for BearerHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(d)?;
        Self::from_hex(&hex).ok_or_else(|| de::Error::custom(BEARER_HASH_EXPECTED))
    }
}

/// Reads and validates the config file at `file` together with its `roles_file`.
///
/// # Errors
/// Either file cannot be read or they do not validate.
pub fn load(file: &Path) -> Result<Config, Error> {
    parse(file, &read(file)?)
}

/// Parses config `text` and validates it together with the `roles_file` it names, which is
/// read from disk; `file` only names the source in errors.
///
/// # Errors
/// The text is not TOML, the roles file cannot be read, or they do not validate.
pub fn parse(file: &Path, text: &str) -> Result<Config, Error> {
    let mut config: Config = deserialize(file, text)?;
    let doc = DeTable::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))?;
    let here = Source {
        file,
        text,
        doc: doc.get_ref(),
    };
    let inline = here.doc.contains_key("roles");
    let Some(path) = config.roles_file.clone() else {
        if !inline {
            let reason = "is missing; declare `[[roles]]` here or name a `roles_file`";
            return Err(here.fault(("roles".into(), reason.into())));
        }
        config.validate().map_err(|f| here.fault(f))?;
        return Ok(config);
    };
    if inline {
        let reason = "is not allowed with `roles_file`, which holds the roles";
        return Err(here.fault(("roles".into(), reason.into())));
    }
    if !path.is_absolute() {
        return Err(here.fault(("roles_file".into(), "must be absolute".into())));
    }
    let roles_text = read(&path)?;
    let roles: RolesFile = deserialize(&path, &roles_text)?;
    config.roles = roles.roles;
    let roles_doc = DeTable::parse(&roles_text)
        .map_err(|e| toml_error(&path, &roles_text, String::new(), &e))?;
    let there = Source {
        file: &path,
        text: &roles_text,
        doc: roles_doc.get_ref(),
    };
    config.validate().map_err(|(field, reason)| {
        let in_roles = field == "roles" || field.starts_with("roles[");
        if in_roles { &there } else { &here }.fault((field, reason))
    })?;
    Ok(config)
}

/// The text of the config file `file`.
fn read(file: &Path) -> Result<String, Error> {
    std::fs::read_to_string(file).map_err(|e| Error {
        file: file.to_owned(),
        field: String::new(),
        reason: format!("cannot read: {e}"),
    })
}

/// A config file being validated: its name, text and parsed tree.
struct Source<'a> {
    file: &'a Path,
    text: &'a str,
    doc: &'a DeTable<'a>,
}

impl Source<'_> {
    /// `fault` as an error of this file, with the line of its field where the file holds it.
    fn fault(&self, (field, reason): Fault) -> Error {
        let reason = match offset(self.doc, &field) {
            Some(at) => format!("{reason} (line {})", line(self.text, at)),
            None => reason,
        };
        Error {
            file: self.file.to_owned(),
            field,
            reason,
        }
    }
}

/// The 1-based line of byte offset `at` of `text`.
fn line(text: &str, at: usize) -> usize {
    text.get(..at).map_or(0, |s| s.matches('\n').count()) + 1
}

/// Reads and validates the agent config file at `file`.
///
/// # Errors
/// The file cannot be read or does not validate.
pub fn load_agent(file: &Path) -> Result<AgentConfig, Error> {
    let text = std::fs::read_to_string(file).map_err(|e| Error {
        file: file.to_owned(),
        field: String::new(),
        reason: format!("cannot read: {e}"),
    })?;
    parse_agent(file, &text)
}

/// Parses and validates agent config `text`; `file` only names the source in errors.
///
/// # Errors
/// The text is not TOML or does not validate.
pub fn parse_agent(file: &Path, text: &str) -> Result<AgentConfig, Error> {
    let config: AgentConfig = deserialize(file, text)?;
    config.validate().map_err(|(field, reason)| Error {
        file: file.to_owned(),
        field,
        reason,
    })?;
    Ok(config)
}

/// `text` as TOML of type `T`, errors on one line with the field path and no quoted values.
pub(crate) fn deserialize<T: serde::de::DeserializeOwned>(
    file: &Path,
    text: &str,
) -> Result<T, Error> {
    let document =
        toml::Deserializer::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))?;
    serde_path_to_error::deserialize(document).map_err(|e| {
        let field = e.path().to_string();
        let field = if field == "." { String::new() } else { field };
        toml_error(file, text, field, e.inner())
    })
}

/// `e` as one line: the toml crate's own Display adds a multi-line source snippet.
pub(crate) fn toml_error(file: &Path, text: &str, field: String, e: &toml::de::Error) -> Error {
    let reason = match e.span() {
        Some(span) => format!(
            "{} (line {})",
            redact(e.message().trim_end()),
            line(text, span.start)
        ),
        None => redact(e.message().trim_end()),
    };
    Error {
        file: file.to_owned(),
        field,
        reason,
    }
}

/// The byte offset of the value at the field path `field` of `doc`, such as `routes[1].alias`
/// or `fronts.models."m"`; `None` when the file does not hold it.
pub(crate) fn offset(doc: &DeTable<'_>, field: &str) -> Option<usize> {
    let (mut table, mut rest, mut at) = (Some(doc), field, None);
    while !rest.is_empty() {
        let (key, after) = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split_at(quoted.find('"')?),
            None => rest.split_at(rest.find(['.', '[']).unwrap_or(rest.len())),
        };
        let mut value = table?.get(key)?;
        rest = after.strip_prefix('"').unwrap_or(after);
        while let Some(index) = rest.strip_prefix('[') {
            let (i, after) = index.split_at(index.find(']')?);
            value = value.get_ref().as_array()?.get(i.parse::<usize>().ok()?)?;
            rest = &after[1..];
        }
        at = Some(value.span().start);
        table = value.get_ref().as_table();
        rest = rest.strip_prefix('.').unwrap_or(rest);
    }
    at
}

/// `message` without the string values serde quotes in type and variant errors, so a token
/// pasted into the wrong field does not reach the logs.
fn redact(message: &str) -> String {
    const QUOTED: &str = "string \"";
    const VARIANT: &str = "unknown variant `";
    // The value may contain "`, " itself; serde's own list follows the last marker.
    const VARIANT_END: &str = "`, expected";
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let next = [QUOTED, VARIANT]
            .into_iter()
            .filter_map(|p| Some((rest.find(p)?, p)))
            .min();
        let Some((at, prefix)) = next else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..at]);
        out.push_str(&prefix[..prefix.len() - 2]);
        let value = &rest[at + prefix.len()..];
        rest = if prefix == QUOTED {
            after_debug_string(value)
        } else {
            value.rfind(VARIANT_END).map_or("", |end| &value[end + 1..])
        };
    }
}

/// What follows the closing quote of a `{:?}`-formatted string whose opening quote is gone.
fn after_debug_string(s: &str) -> &str {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match (escaped, c) {
            (true, _) => escaped = false,
            (false, '\\') => escaped = true,
            (false, '"') => return &s[i + 1..],
            _ => {}
        }
    }
    ""
}

/// A validation failure: field path and reason.
pub(crate) type Fault = (String, String);

impl Config {
    /// The policy part of the config as the core's spec, in config order.
    pub fn core_spec(&self) -> Spec {
        Spec {
            vendors: self
                .vendors
                .iter()
                .map(|v| VendorSpec {
                    name: v.name.clone(),
                    windows: v
                        .windows
                        .iter()
                        .map(|w| WindowSpec {
                            name: w.name.clone(),
                            length_s: w.length_s,
                            t_burn_s: w.t_burn_s,
                        })
                        .collect(),
                })
                .collect(),
            logins: self
                .logins
                .iter()
                .map(|l| LoginSpec {
                    name: l.name.clone(),
                    vendor: l.vendor.clone(),
                })
                .collect(),
            roles: self
                .roles
                .iter()
                .map(|r| RoleSpec {
                    name: r.name.clone(),
                    ladder: r
                        .ladder
                        .iter()
                        .map(|s| StepSpec {
                            difficulty: s.difficulty,
                            candidates: s
                                .candidates
                                .iter()
                                .map(|c| CandidateSpec {
                                    vendor: c.vendor.clone(),
                                    model: c.model.clone(),
                                    effort: c.effort.clone(),
                                    tier: c.tier,
                                    cost_per_minute: c.cost_per_minute.map(Fraction::get),
                                })
                                .collect(),
                        })
                        .collect(),
                    reserves: r
                        .reserves
                        .iter()
                        .map(|res| ReserveSpec {
                            difficulty: res.difficulty,
                            window: res.window.clone(),
                            fraction: res.fraction.get(),
                        })
                        .collect(),
                })
                .collect(),
            snapshot_ttl_s: self.snapshot.ttl_s,
            lease_ttl_s: self.leases.ttl_s,
            cost_per_minute: self.leases.cost_per_minute.get(),
            rate_limit_backoff_s: self.outcomes.rate_limit_backoff_s,
            model_unavailable_s: self.outcomes.model_unavailable_s,
            probe: self.probe.enabled.then_some(ProbeSpec {
                backoff_initial_s: self.probe.backoff_initial_s,
                backoff_max_s: self.probe.backoff_max_s,
            }),
        }
    }

    /// The first key other than `roles` and `clients` whose value `candidate` changes: a reload
    /// takes only a candidate without one.
    pub fn restart_only_change(&self, candidate: &Self) -> Option<&'static str> {
        let Self {
            vendors,
            logins,
            roles_file,
            roles: _,
            clients: _,
            journal,
            snapshot,
            leases,
            outcomes,
            probe,
            limits,
            hooks,
        } = self;
        let changed = [
            ("vendors", *vendors != candidate.vendors),
            ("logins", *logins != candidate.logins),
            ("roles_file", *roles_file != candidate.roles_file),
            ("journal", *journal != candidate.journal),
            ("snapshot", *snapshot != candidate.snapshot),
            ("leases", *leases != candidate.leases),
            ("outcomes", *outcomes != candidate.outcomes),
            ("probe", *probe != candidate.probe),
            ("limits", *limits != candidate.limits),
            ("hooks", *hooks != candidate.hooks),
        ];
        changed.into_iter().find_map(|(key, c)| c.then_some(key))
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

        let clients = declare("clients", self.clients.iter().map(|c| c.name.as_str()))?;
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
            match &client.role {
                Some(role) => known(&roles, format!("{at}.role"), "role", role)?,
                None if self.probe.agents.contains(&client.name) => {}
                None => {
                    return Err((
                        format!("{at}.role"),
                        "missing; only a client in `probe.agents` may omit it".into(),
                    ));
                }
            }
        }
        for (i, agent) in self.probe.agents.iter().enumerate() {
            known(&clients, format!("probe.agents[{i}]"), "client", agent)?;
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
        if self.leases.ttl_s == 0 {
            return Err(("leases.ttl_s".into(), "must be positive".into()));
        }
        if self.outcomes.rate_limit_backoff_s == 0 {
            return Err((
                "outcomes.rate_limit_backoff_s".into(),
                "must be positive".into(),
            ));
        }
        if self.outcomes.model_unavailable_s == 0 {
            return Err((
                "outcomes.model_unavailable_s".into(),
                "must be positive".into(),
            ));
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
        self.hooks.validate()
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
pub(crate) fn declare<'a>(
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

pub(crate) fn too_many(field: String, n: usize, max: usize) -> Fault {
    (field, format!("{n} entries, at most {max} allowed"))
}
