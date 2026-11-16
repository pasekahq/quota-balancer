//! Pure scheduling policy of quota-balancer.
//!
//! This crate owns the balancer's state (logins and their quota windows) and the two decisions
//! that change it: [`Core::pick`] and [`Core::report`]. It performs no I/O and reads no clock:
//! the caller passes `now` in. That keeps the policy deterministic, table-testable and
//! replayable from a journal.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::fmt;

/// Unix time in seconds.
pub type UnixSecs = u64;

/// Upper bound on configured logins; the state uses fixed-size tables of this length.
pub const MAX_LOGINS: usize = 32;
/// Upper bound on quota windows per login.
pub const MAX_WINDOWS: usize = 4;
/// Upper bound on candidates per ladder step.
pub const MAX_CANDIDATES: usize = 8;
/// Upper bound on live leases.
pub const MAX_LEASES: usize = 256;

/// Floor of the time-to-reset in the urgency score, so a window about to reset does not
/// dominate every other login.
const MIN_HORIZON_S: u64 = 3600;
/// Tolerance of the reserve comparison: reported fractions are decimal, `1 - used` is binary.
const EPS: f64 = 1e-9;

/// A quota window every login of a vendor has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowSpec {
    /// Window name as clients report it, e.g. `five_hour`.
    pub name: String,
    /// Window length in seconds.
    pub length_s: u64,
    /// Inside this many seconds before a reset the role reserves of the window are dropped.
    pub t_burn_s: u64,
}

/// A vendor and its quota windows (at most [`MAX_WINDOWS`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorSpec {
    /// Vendor id.
    pub name: String,
    /// Quota windows.
    pub windows: Vec<WindowSpec>,
}

/// A login of a declared vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSpec {
    /// Unique name, e.g. `login-1`.
    pub name: String,
    /// Declared vendor id.
    pub vendor: String,
}

/// A login-independent vendor/model/effort a ladder step may run on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSpec {
    /// Declared vendor id; the candidate runs on any login of it.
    pub vendor: String,
    /// Model name.
    pub model: String,
    /// Reasoning effort.
    pub effort: Option<String>,
    /// Lower tiers are preferred.
    pub tier: u8,
}

/// The candidates of one difficulty, in preference order (at most [`MAX_CANDIDATES`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepSpec {
    /// Difficulty the step serves.
    pub difficulty: u8,
    /// Candidates.
    pub candidates: Vec<CandidateSpec>,
}

/// Reserve `R(role, difficulty, window)`: the fraction of a window the role keeps free.
#[derive(Debug, Clone, PartialEq)]
pub struct ReserveSpec {
    /// Difficulty of a ladder step of the role.
    pub difficulty: u8,
    /// Window name; it constrains only candidates whose vendor declares that window.
    pub window: String,
    /// Fraction in `0.0..=1.0`.
    pub fraction: f64,
}

/// A role with its ladder and reserves.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleSpec {
    /// Role name used in pick requests.
    pub name: String,
    /// Ladder steps, unique by difficulty.
    pub ladder: Vec<StepSpec>,
    /// Reserves.
    pub reserves: Vec<ReserveSpec>,
}

/// Everything the policy needs from the configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Spec {
    /// Vendors.
    pub vendors: Vec<VendorSpec>,
    /// Logins, at most [`MAX_LOGINS`].
    pub logins: Vec<LoginSpec>,
    /// Roles.
    pub roles: Vec<RoleSpec>,
    /// Age in seconds after which a window snapshot is stale.
    pub snapshot_ttl_s: u64,
}

/// Why [`Core::new`] refused a [`Spec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// More logins than [`MAX_LOGINS`].
    TooManyLogins,
    /// A vendor with more windows than [`MAX_WINDOWS`].
    TooManyWindows(String),
    /// A ladder step with more candidates than [`MAX_CANDIDATES`]: role and difficulty.
    TooManyCandidates(String, u8),
    /// A login or candidate names a vendor the spec does not declare.
    UnknownVendor(String),
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyLogins => write!(f, "more than {MAX_LOGINS} logins"),
            Self::TooManyWindows(v) => {
                write!(f, "vendor `{v}` has more than {MAX_WINDOWS} windows")
            }
            Self::TooManyCandidates(role, d) => write!(
                f,
                "role `{role}` difficulty {d} has more than {MAX_CANDIDATES} candidates"
            ),
            Self::UnknownVendor(v) => write!(f, "undeclared vendor `{v}`"),
        }
    }
}

impl std::error::Error for SpecError {}

/// Health of a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStatus {
    /// Usable.
    Ok,
    /// Short back-off after a 429.
    RateLimited,
    /// A window is used up until its reset.
    Exhausted,
    /// One 401 seen; usable after the vendor CLI refreshes its token.
    AuthStale,
    /// Repeated 401; needs a manual re-login.
    AuthDead,
    /// No data yet.
    Unknown,
}

/// Where a window value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Reported by a client from the vendor's stream.
    Stream,
    /// Inferred: never observed, or the window passed its reset.
    Assumed,
}

/// What the caller asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Walk the ladder of the role from this difficulty step.
    Difficulty(u8),
    /// Exact vendor/model on any admissible login of the vendor.
    Pin {
        /// Vendor id.
        vendor: String,
        /// Model.
        model: String,
        /// Reasoning effort.
        effort: Option<String>,
        /// Optional login restriction.
        login: Option<String>,
    },
}

/// Input of [`Core::pick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickInput {
    /// Role of the work.
    pub role: String,
    /// Ladder step or pin.
    pub target: Target,
    /// Run being resumed; accepted and not yet used.
    pub resume_of: Option<String>,
    /// Vendor to avoid.
    pub avoid_vendor: Option<String>,
    /// Identity of the calling client, from peer credentials or a bearer token.
    pub client: String,
}

/// Why the core decided what it decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Best admissible candidate of the requested step by tier and urgency.
    SpendBeforeReset,
    /// Nothing admissible on the requested step; chosen from a neighbouring step.
    NeighbourStep,
    /// Best admissible login of the pinned vendor.
    Pinned,
    /// Every candidate is blocked until a known reset.
    AllExhausted,
    /// Every candidate is blocked by a window without a known reset.
    NoResetKnown,
    /// No configured candidate matches the request.
    NoCandidates,
}

impl Reason {
    /// Stable machine-readable name used on the wire and in the journal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendBeforeReset => "spend_before_reset",
            Self::NeighbourStep => "neighbour_step",
            Self::Pinned => "pinned",
            Self::AllExhausted => "all_exhausted",
            Self::NoResetKnown => "no_reset_known",
            Self::NoCandidates => "no_candidates",
        }
    }
}

/// A granted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Login name.
    pub login: String,
    /// Vendor id.
    pub vendor: String,
    /// Model.
    pub model: String,
    /// Reasoning effort.
    pub effort: Option<String>,
    /// Ladder tier; `None` for a pin.
    pub tier: Option<u8>,
    /// Some window of the login is older than the snapshot TTL or was never observed.
    pub stale: bool,
    /// Oldest observation behind the decision; `None` while a window was never observed.
    pub snapshot_at: Option<UnixSecs>,
}

/// Result of [`Core::pick`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run under the grant.
    Run(Grant, Reason),
    /// Nothing admissible now; retry at the given time.
    Wait {
        /// When to ask again.
        retry_after: UnixSecs,
        /// Why.
        reason: Reason,
        /// Some rejected candidate's data is stale.
        stale: bool,
    },
    /// Nothing will become admissible without outside help.
    Dead(Reason),
}

/// Outcome class reported by a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeClass {
    /// Normal progress or completion.
    Ok,
    /// Usage limit reached.
    UsageLimit,
    /// Rejected by the vendor's limiter.
    Rejected,
    /// HTTP 401.
    Http401,
    /// HTTP 429 without exhaustion.
    Http429,
    /// Model not available on the login.
    ModelUnavailable,
    /// Other failure.
    Error,
}

/// What a report refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportSubject {
    /// A lease id issued by [`Core::pick`].
    Lease(u64),
    /// A login by its configured name.
    Login(String),
}

/// A quota window as a client saw it in the vendor's stream.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowObservation {
    /// Window name; names the login's vendor does not declare are ignored.
    pub name: String,
    /// Used fraction in `0.0..=1.0`.
    pub used: f64,
    /// When the window resets.
    pub resets_at: Option<UnixSecs>,
}

/// Input of [`Core::report`].
#[derive(Debug, Clone, PartialEq)]
pub struct ReportInput {
    /// Lease or login.
    pub subject: ReportSubject,
    /// Outcome class.
    pub outcome: OutcomeClass,
    /// Release the lease.
    pub release: bool,
    /// Fresh windows; each overwrites the login's snapshot of that window.
    pub windows: Vec<WindowObservation>,
}

/// Why [`Core::report`] refused a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// No live lease with that id.
    UnknownLease,
    /// No configured login with that name.
    UnknownLogin,
    /// A window's used fraction is outside `0.0..=1.0`.
    InvalidUtilization,
}

/// A window of a login as `/v1/state` shows it, after reset inference.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowView {
    /// Window name.
    pub name: String,
    /// Used fraction.
    pub used: f64,
    /// Next reset, if known.
    pub resets_at: Option<UnixSecs>,
    /// When the value was observed; 0 when never.
    pub observed_at: UnixSecs,
    /// Origin of the value.
    pub source: Source,
    /// Older than the snapshot TTL or never observed.
    pub stale: bool,
}

/// A login as seen in a snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct LoginView {
    /// Configured name.
    pub name: String,
    /// Vendor id.
    pub vendor: String,
    /// Status.
    pub status: LoginStatus,
    /// The vendor's windows in declaration order.
    pub windows: Vec<WindowView>,
}

/// Read-only view of the state for `/v1/state`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    /// Configured logins.
    pub logins: Vec<LoginView>,
}

#[derive(Debug)]
struct Vendor {
    name: String,
    windows: Vec<WindowSpec>,
    /// Index of the longest window, the one urgency is scored on.
    longest: Option<usize>,
}

#[derive(Debug)]
struct Candidate {
    vendor: usize,
    model: String,
    effort: Option<String>,
    tier: u8,
}

/// Reserve per window of one vendor, by the vendor's window index.
type Reserves = [f64; MAX_WINDOWS];

#[derive(Debug)]
struct Step {
    difficulty: u8,
    candidates: Vec<Candidate>,
    /// Reserves of the step by vendor index.
    reserves: Vec<Reserves>,
}

#[derive(Debug)]
struct Role {
    name: String,
    /// Sorted by difficulty.
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Copy)]
struct Reading {
    used: f64,
    resets_at: Option<UnixSecs>,
    observed_at: UnixSecs,
}

#[derive(Debug)]
struct Login {
    name: String,
    vendor: usize,
    status: LoginStatus,
    windows: [Option<Reading>; MAX_WINDOWS],
}

/// A window value at `now`: a reset that has passed empties the window.
#[derive(Debug, Clone, Copy)]
struct Effective {
    used: f64,
    resets_at: Option<UnixSecs>,
    observed_at: UnixSecs,
    source: Source,
    stale: bool,
}

/// An admissible candidate on a login.
#[derive(Debug, Clone, Copy)]
struct Choice {
    tier: Option<u8>,
    urgency: f64,
    candidate: usize,
    login: usize,
}

impl Choice {
    /// Lexicographic order: tier ascending, urgency descending, candidate, login.
    fn better_than(&self, other: &Self) -> bool {
        self.tier
            .cmp(&other.tier)
            .then(other.urgency.total_cmp(&self.urgency))
            .then(self.candidate.cmp(&other.candidate))
            .then(self.login.cmp(&other.login))
            == Ordering::Less
    }
}

/// What the rejected candidates of a pick have in common.
#[derive(Debug, Default)]
struct Rejected {
    any: bool,
    retry_after: Option<UnixSecs>,
    stale: bool,
}

/// The balancer's state and policy. Single owner, no locks: the daemon calls it from one thread.
#[derive(Debug)]
pub struct Core {
    vendors: Vec<Vendor>,
    logins: Vec<Login>,
    roles: Vec<Role>,
    ttl_s: u64,
}

impl Core {
    /// A core for `spec`; every window starts never observed.
    ///
    /// # Errors
    /// The spec exceeds a table bound or references an undeclared vendor.
    pub fn new(spec: Spec) -> Result<Self, SpecError> {
        if spec.logins.len() > MAX_LOGINS {
            return Err(SpecError::TooManyLogins);
        }
        let mut vendors = Vec::with_capacity(spec.vendors.len());
        for v in spec.vendors {
            if v.windows.len() > MAX_WINDOWS {
                return Err(SpecError::TooManyWindows(v.name));
            }
            let longest = (0..v.windows.len()).max_by(|&a, &b| {
                v.windows[a]
                    .length_s
                    .cmp(&v.windows[b].length_s)
                    .then(b.cmp(&a))
            });
            vendors.push(Vendor {
                name: v.name,
                windows: v.windows,
                longest,
            });
        }
        let vendor_of = |name: &str| {
            vendors
                .iter()
                .position(|v| v.name == name)
                .ok_or_else(|| SpecError::UnknownVendor(name.to_owned()))
        };
        let mut logins = Vec::with_capacity(spec.logins.len());
        for l in spec.logins {
            logins.push(Login {
                vendor: vendor_of(&l.vendor)?,
                name: l.name,
                status: LoginStatus::Unknown,
                windows: [None; MAX_WINDOWS],
            });
        }
        let mut roles = Vec::with_capacity(spec.roles.len());
        for r in spec.roles {
            let mut steps = Vec::with_capacity(r.ladder.len());
            for s in r.ladder {
                if s.candidates.len() > MAX_CANDIDATES {
                    return Err(SpecError::TooManyCandidates(r.name, s.difficulty));
                }
                let mut candidates = Vec::with_capacity(s.candidates.len());
                for c in s.candidates {
                    candidates.push(Candidate {
                        vendor: vendor_of(&c.vendor)?,
                        model: c.model,
                        effort: c.effort,
                        tier: c.tier,
                    });
                }
                let reserves = vendors
                    .iter()
                    .map(|v| {
                        let mut out = [0.0; MAX_WINDOWS];
                        for (w, def) in v.windows.iter().enumerate() {
                            if let Some(res) = r.reserves.iter().find(|res| {
                                res.difficulty == s.difficulty && res.window == def.name
                            }) {
                                out[w] = res.fraction;
                            }
                        }
                        out
                    })
                    .collect();
                steps.push(Step {
                    difficulty: s.difficulty,
                    candidates,
                    reserves,
                });
            }
            steps.sort_by_key(|s| s.difficulty);
            roles.push(Role {
                name: r.name,
                steps,
            });
        }
        Ok(Self {
            vendors,
            logins,
            roles,
            ttl_s: spec.snapshot_ttl_s,
        })
    }

    /// Decides where a task should run.
    ///
    /// A ladder target tries the requested step, then the nearest lower step, then the nearest
    /// higher one. Within a step the admissible (candidate, login) pairs are ordered by tier,
    /// urgency (descending), candidate order and login index.
    pub fn pick(&mut self, input: &PickInput, now: UnixSecs) -> Verdict {
        let Some(role) = self.roles.iter().find(|r| r.name == input.role) else {
            return Verdict::Dead(Reason::NoCandidates);
        };
        let avoid = input.avoid_vendor.as_deref();
        let mut rejected = Rejected::default();
        match &input.target {
            Target::Difficulty(d) => {
                let Some(at) = role.steps.iter().position(|s| s.difficulty == *d) else {
                    return Verdict::Dead(Reason::NoCandidates);
                };
                let order = [Some(at), at.checked_sub(1), Some(at + 1)];
                for (n, i) in order.into_iter().enumerate() {
                    let Some(step) = i.and_then(|i| role.steps.get(i)) else {
                        continue;
                    };
                    if let Some(c) = self.best_on_step(step, avoid, now, &mut rejected) {
                        let cand = &step.candidates[c.candidate];
                        let reason = if n == 0 {
                            Reason::SpendBeforeReset
                        } else {
                            Reason::NeighbourStep
                        };
                        return Verdict::Run(
                            self.grant(c, &cand.model, cand.effort.as_ref(), now),
                            reason,
                        );
                    }
                }
            }
            Target::Pin {
                vendor,
                model,
                effort,
                login,
            } => {
                if avoid != Some(vendor.as_str()) {
                    if let Some(c) = self.best_pinned(vendor, login.as_deref(), now, &mut rejected)
                    {
                        return Verdict::Run(
                            self.grant(c, model, effort.as_ref(), now),
                            Reason::Pinned,
                        );
                    }
                }
            }
        }
        match (rejected.any, rejected.retry_after) {
            (false, _) => Verdict::Dead(Reason::NoCandidates),
            (true, Some(retry_after)) => Verdict::Wait {
                retry_after,
                reason: Reason::AllExhausted,
                stale: rejected.stale,
            },
            (true, None) => Verdict::Dead(Reason::NoResetKnown),
        }
    }

    fn best_on_step(
        &self,
        step: &Step,
        avoid: Option<&str>,
        now: UnixSecs,
        rejected: &mut Rejected,
    ) -> Option<Choice> {
        let mut best: Option<Choice> = None;
        for (ci, cand) in step.candidates.iter().enumerate() {
            if avoid == Some(self.vendors[cand.vendor].name.as_str()) {
                continue;
            }
            for li in (0..self.logins.len()).filter(|&li| self.logins[li].vendor == cand.vendor) {
                let choice = Choice {
                    tier: Some(cand.tier),
                    urgency: self.urgency(li, now),
                    candidate: ci,
                    login: li,
                };
                self.consider(
                    choice,
                    &step.reserves[cand.vendor],
                    now,
                    &mut best,
                    rejected,
                );
            }
        }
        best
    }

    fn best_pinned(
        &self,
        vendor: &str,
        login: Option<&str>,
        now: UnixSecs,
        rejected: &mut Rejected,
    ) -> Option<Choice> {
        let vi = self.vendors.iter().position(|v| v.name == vendor)?;
        let mut best: Option<Choice> = None;
        for (li, l) in self.logins.iter().enumerate() {
            if l.vendor != vi || login.is_some_and(|name| name != l.name) {
                continue;
            }
            let choice = Choice {
                tier: None,
                urgency: self.urgency(li, now),
                candidate: 0,
                login: li,
            };
            self.consider(choice, &[0.0; MAX_WINDOWS], now, &mut best, rejected);
        }
        best
    }

    fn consider(
        &self,
        choice: Choice,
        reserves: &Reserves,
        now: UnixSecs,
        best: &mut Option<Choice>,
        rejected: &mut Rejected,
    ) {
        match self.admit(choice.login, reserves, now) {
            Ok(()) => {
                if best.as_ref().is_none_or(|b| choice.better_than(b)) {
                    *best = Some(choice);
                }
            }
            Err(recover) => {
                rejected.any = true;
                rejected.stale |= self.stale(choice.login, now);
                if let Some(t) = recover {
                    rejected.retry_after = Some(rejected.retry_after.map_or(t, |r| r.min(t)));
                }
            }
        }
    }

    /// `Ok` when every window has quota left and at least its reserve, the reserve being
    /// dropped inside `T_burn`; otherwise the reset that unblocks the login (`None` if unknown).
    fn admit(&self, li: usize, reserves: &Reserves, now: UnixSecs) -> Result<(), Option<UnixSecs>> {
        let login = &self.logins[li];
        let mut blocked = false;
        let mut recover = Some(0);
        for (w, def) in self.vendors[login.vendor].windows.iter().enumerate() {
            let e = self.effective(login.windows[w], now);
            let reserve = if e.resets_at.is_some_and(|r| r - now < def.t_burn_s) {
                0.0
            } else {
                reserves[w]
            };
            let left = 1.0 - e.used;
            if !(left > 0.0 && left + EPS >= reserve) {
                blocked = true;
                recover = recover.zip(e.resets_at).map(|(a, r)| a.max(r));
            }
        }
        if blocked { Err(recover) } else { Ok(()) }
    }

    /// Spend-before-reset score on the vendor's longest window:
    /// `left / max(time to reset, 1 h) * length`.
    #[allow(clippy::cast_precision_loss)] // seconds stay far below 2^53
    fn urgency(&self, li: usize, now: UnixSecs) -> f64 {
        let login = &self.logins[li];
        let vendor = &self.vendors[login.vendor];
        let Some(w) = vendor.longest else {
            return 0.0;
        };
        let length = vendor.windows[w].length_s;
        let e = self.effective(login.windows[w], now);
        let horizon = e.resets_at.map_or(length, |r| r - now).max(MIN_HORIZON_S);
        (1.0 - e.used) / horizon as f64 * length as f64
    }

    fn effective(&self, obs: Option<Reading>, now: UnixSecs) -> Effective {
        let Some(o) = obs else {
            return Effective {
                used: 0.0,
                resets_at: None,
                observed_at: 0,
                source: Source::Assumed,
                stale: true,
            };
        };
        let stale = now.saturating_sub(o.observed_at) > self.ttl_s;
        if o.resets_at.is_none_or(|r| r > now) {
            Effective {
                used: o.used,
                resets_at: o.resets_at,
                observed_at: o.observed_at,
                source: Source::Stream,
                stale,
            }
        } else {
            Effective {
                used: 0.0,
                resets_at: None,
                observed_at: o.observed_at,
                source: Source::Assumed,
                stale,
            }
        }
    }

    fn windows_of(&self, li: usize, now: UnixSecs) -> impl Iterator<Item = Effective> + '_ {
        let login = &self.logins[li];
        (0..self.vendors[login.vendor].windows.len())
            .map(move |w| self.effective(login.windows[w], now))
    }

    fn stale(&self, li: usize, now: UnixSecs) -> bool {
        self.windows_of(li, now).any(|e| e.stale)
    }

    fn grant(&self, c: Choice, model: &str, effort: Option<&String>, now: UnixSecs) -> Grant {
        let login = &self.logins[c.login];
        let snapshot_at = if self.windows_of(c.login, now).any(|e| e.observed_at == 0) {
            None
        } else {
            self.windows_of(c.login, now).map(|e| e.observed_at).min()
        };
        Grant {
            login: login.name.clone(),
            vendor: self.vendors[login.vendor].name.clone(),
            model: model.to_owned(),
            effort: effort.cloned(),
            tier: c.tier,
            stale: self.stale(c.login, now),
            snapshot_at,
        }
    }

    /// Applies a client's report and returns the login's status afterwards.
    ///
    /// # Errors
    /// [`ReportError::UnknownLease`] or [`ReportError::UnknownLogin`] when the subject is not
    /// known; [`ReportError::InvalidUtilization`] when a window fraction is out of range, in
    /// which case nothing is applied.
    pub fn report(
        &mut self,
        input: &ReportInput,
        now: UnixSecs,
    ) -> Result<LoginStatus, ReportError> {
        let li = match &input.subject {
            ReportSubject::Lease(_) => return Err(ReportError::UnknownLease),
            ReportSubject::Login(name) => self
                .logins
                .iter()
                .position(|l| &l.name == name)
                .ok_or(ReportError::UnknownLogin)?,
        };
        if input.windows.iter().any(|w| !(0.0..=1.0).contains(&w.used)) {
            return Err(ReportError::InvalidUtilization);
        }
        let login = &mut self.logins[li];
        let defs = &self.vendors[login.vendor].windows;
        for obs in &input.windows {
            if let Some(w) = defs.iter().position(|d| d.name == obs.name) {
                login.windows[w] = Some(Reading {
                    used: obs.used,
                    resets_at: obs.resets_at,
                    observed_at: now,
                });
                if login.status == LoginStatus::Unknown {
                    login.status = LoginStatus::Ok;
                }
            }
        }
        Ok(login.status)
    }

    /// Read-only view of the state at `now`.
    pub fn snapshot(&self, now: UnixSecs) -> Snapshot {
        Snapshot {
            logins: self
                .logins
                .iter()
                .enumerate()
                .map(|(li, l)| LoginView {
                    name: l.name.clone(),
                    vendor: self.vendors[l.vendor].name.clone(),
                    status: l.status,
                    windows: self.vendors[l.vendor]
                        .windows
                        .iter()
                        .zip(self.windows_of(li, now))
                        .map(|(def, e)| WindowView {
                            name: def.name.clone(),
                            used: e.used,
                            resets_at: e.resets_at,
                            observed_at: e.observed_at,
                            source: e.source,
                            stale: e.stale,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}
