//! Pure scheduling policy of quota-balancer.
//!
//! This crate owns the balancer's state (logins, their quota windows, health marks and leases)
//! and the decisions that change it: [`Core::pick`], [`Core::report`] and [`Core::tick`]. It
//! performs no I/O and reads no clock: the caller passes `now` in. That keeps the policy
//! deterministic, table-testable and replayable from a journal.

#![forbid(unsafe_code)]

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
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
/// A window at or above this used fraction is the one a usage limit refers to.
const NEAR_FULL: f64 = 0.99;
/// A probe job without a result this long after it was handed out counts as a failure.
pub const PROBE_TIMEOUT_S: u64 = 30;

/// A quota window every login of a vendor has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowSpec {
    /// Window name as clients report it, e.g. `five_hour`.
    pub name: String,
    /// Window length in seconds, positive.
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
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateSpec {
    /// Declared vendor id; the candidate runs on any login of it.
    pub vendor: String,
    /// Model name.
    pub model: String,
    /// Reasoning effort.
    pub effort: Option<String>,
    /// Lower tiers are preferred.
    pub tier: u8,
    /// Fraction of the vendor's shortest window one minute of work uses; `None` takes
    /// [`Spec::cost_per_minute`].
    pub cost_per_minute: Option<f64>,
}

/// The candidates of one difficulty, in preference order (at most [`MAX_CANDIDATES`]).
#[derive(Debug, Clone, PartialEq)]
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
    /// A lease expires this long after its pick plus the task's expected minutes.
    pub lease_ttl_s: u64,
    /// Cost rate of candidates without their own and of pins without a matching candidate.
    pub cost_per_minute: f64,
    /// How long a login stays `rate_limited` after a 429.
    pub rate_limit_backoff_s: u64,
    /// How long a (login, model) pair stays dead after `model_unavailable`.
    pub model_unavailable_s: u64,
    /// Back-off of lazy probes; `None` turns probes off, so no job is ever handed out.
    pub probe: Option<ProbeSpec>,
}

/// Exponential back-off of a login's failed probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeSpec {
    /// Back-off after the first failure, positive.
    pub backoff_initial_s: u64,
    /// Ceiling of the doubling back-off, at least `backoff_initial_s`.
    pub backoff_max_s: u64,
}

/// What an agent's probe of a login's usage endpoint returned.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeOutcome {
    /// The vendor answered with these windows.
    Ok(Vec<WindowObservation>),
    /// HTTP 401.
    Http401,
    /// HTTP 429, with the vendor's `Retry-After` in seconds when it sent one.
    Http429 {
        /// Seconds the vendor asked to wait.
        retry_after_s: Option<u64>,
    },
    /// Any other failure.
    Error,
}

/// A probe handed to an agent by [`Core::probe_next`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeJob {
    /// Probe id; the result names it.
    pub id: u64,
    /// Login to probe.
    pub login: String,
}

/// Why [`Core::probe_result`] refused a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// No probe with that id is in flight: never issued, answered or timed out.
    UnknownProbe,
    /// The probe was handed to another client.
    OtherClient,
    /// A window's used fraction is outside `0.0..=1.0`.
    InvalidUtilization,
}

/// Why [`Core::new`] refused a [`Spec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecError {
    /// More logins than [`MAX_LOGINS`].
    TooManyLogins,
    /// A vendor with more windows than [`MAX_WINDOWS`].
    TooManyWindows(String),
    /// A vendor with a window of length 0.
    EmptyWindow(String),
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
            Self::EmptyWindow(v) => write!(f, "vendor `{v}` has a window of length 0"),
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
    /// Fetched by an agent's probe of the vendor's usage endpoint.
    Probe,
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
    /// Expected duration; without it the task costs nothing.
    pub expected_minutes: Option<u32>,
    /// Caller's id of the run, kept in the lease.
    pub run_id: Option<String>,
    /// End client a relaying caller picks for, kept in the lease; no decision reads it.
    pub on_behalf_of: Option<String>,
}

/// Declares [`Reason`] from one table, so `as_str`, `from_name` and `ALL` cannot disagree.
macro_rules! reasons {
    ($($(#[$doc:meta])* $variant:ident = $name:literal,)*) => {
        /// Why the core decided what it decided.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Reason {
            $($(#[$doc])* $variant,)*
        }

        impl Reason {
            /// Every reason in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// The reason whose [`Reason::as_str`] is `name`.
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($name => Some(Self::$variant),)*
                    _ => None,
                }
            }

            /// Stable machine-readable name used on the wire and in the journal.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)*
                }
            }
        }
    };
}

reasons! {
    /// Best admissible candidate of the requested step by tier and urgency.
    SpendBeforeReset = "spend_before_reset",
    /// Nothing admissible on the requested step; chosen from a neighbouring step.
    NeighbourStep = "neighbour_step",
    /// Best admissible login of the pinned vendor.
    Pinned = "pinned",
    /// Every candidate is blocked until a known time: a reset, a back-off or a lease expiry.
    AllExhausted = "all_exhausted",
    /// A candidate is admissible but every lease slot is taken.
    LeasesFull = "leases_full",
    /// Some candidate is blocked by a window without a known reset, none until a known time.
    NoResetKnown = "no_reset_known",
    /// Every candidate's login is `auth_dead` or its (login, model) pair is dead.
    AllDead = "all_dead",
    /// No configured candidate matches the request.
    NoCandidates = "no_candidates",
}

/// A granted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Lease that holds the run's reservation.
    pub lease: u64,
    /// When the lease expires unless released first.
    pub expires_at: UnixSecs,
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
    /// A lease id issued by [`Core::pick`]; the report acts on its login and model.
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
    /// Model of a login report; a lease report uses the lease's model.
    pub model: Option<String>,
    /// Release the lease; a login report holds none.
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
    /// `model_unavailable` on a login report without a model.
    MissingModel,
    /// `model_unavailable` for a model no ladder declares.
    UnknownModel,
}

/// A window of a login as `/v1/state` shows it, after reset inference.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowView {
    /// Window name.
    pub name: String,
    /// Used fraction.
    pub used: f64,
    /// Fraction held by live leases.
    pub reserved: f64,
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
    /// End of the `exhausted` or `rate_limited` mark, the later one when both are set.
    pub dead_until: Option<UnixSecs>,
    /// The vendor's windows in declaration order.
    pub windows: Vec<WindowView>,
}

/// A live lease as seen in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseView {
    /// Lease id.
    pub id: u64,
    /// Login name.
    pub login: String,
    /// Model.
    pub model: String,
    /// Client that took the lease.
    pub client: String,
    /// Caller's run id.
    pub run_id: Option<String>,
    /// End client the pick named.
    pub on_behalf_of: Option<String>,
    /// Expiry time.
    pub expires_at: UnixSecs,
}

/// Read-only view of the state for `/v1/state`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    /// Configured logins.
    pub logins: Vec<LoginView>,
    /// Live leases in slot order.
    pub leases: Vec<LeaseView>,
}

/// Authentication state of a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Auth {
    /// No 401 since the last successful report.
    #[default]
    Ok,
    /// One 401 seen.
    Stale,
    /// Repeated 401; only an observed window makes it `Ok` again.
    Dead,
}

/// The health marks of a login, everything about it that outlives a restart.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Marks {
    /// Authentication state.
    pub auth: Auth,
    /// End of the `exhausted` mark.
    pub exhausted_until: Option<UnixSecs>,
    /// End of the `rate_limited` mark.
    pub rate_limited_until: Option<UnixSecs>,
    /// Dead-until per model name.
    pub model_dead: Vec<(String, UnixSecs)>,
}

/// A live lease with everything [`Core::restore`] needs to rebuild it.
#[derive(Debug, Clone, PartialEq)]
pub struct LeaseRecord {
    /// Lease id; it names the lease's slot.
    pub id: u64,
    /// Login name.
    pub login: String,
    /// Model.
    pub model: String,
    /// Client that took the lease.
    pub client: String,
    /// Caller's run id.
    pub run_id: Option<String>,
    /// End client the pick named.
    pub on_behalf_of: Option<String>,
    /// Reserved fraction per window of the login's vendor, in declaration order.
    pub cost: Vec<f64>,
    /// Expiry time.
    pub expires_at: UnixSecs,
    /// Why the pick granted the lease; `None` when the record did not keep it.
    pub reason: Option<Reason>,
}

/// A state change as a journal keeps it. Restoring the records of a run in order rebuilds its
/// leases, marks and lease counter; restoring a record twice changes nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    /// Lease ids issued so far; later ids are higher.
    Issued(u64),
    /// A granted lease.
    Lease(LeaseRecord),
    /// A lease released by a report.
    Release(u64),
    /// The marks of a login after they changed.
    Marks {
        /// Login name.
        login: String,
        /// All marks of the login.
        marks: Marks,
    },
}

/// Why [`Core::restore`] could not apply a record to this core's config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreError {
    /// The record names a login the config does not declare.
    UnknownLogin(String),
    /// A lease's cost does not have one entry per window of the login's vendor.
    CostWindows {
        /// Login name.
        login: String,
        /// Windows of the login's vendor.
        expected: usize,
        /// Entries in the record.
        got: usize,
    },
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLogin(l) => write!(f, "undeclared login `{l}`"),
            Self::CostWindows {
                login,
                expected,
                got,
            } => write!(
                f,
                "lease cost has {got} windows, login `{login}` has {expected}"
            ),
        }
    }
}

impl std::error::Error for RestoreError {}

#[derive(Debug)]
struct Vendor {
    name: String,
    windows: Vec<WindowSpec>,
    /// Index of the longest window, the one urgency is scored on.
    longest: Option<usize>,
    /// Length of the shortest window, the unit of cost rates.
    shortest_s: Option<u64>,
}

#[derive(Debug)]
struct Candidate {
    vendor: usize,
    model: usize,
    effort: Option<String>,
    tier: u8,
    cost_per_minute: f64,
}

/// A fraction per window of one vendor, by the vendor's window index.
type PerWindow = [f64; MAX_WINDOWS];

#[derive(Debug)]
struct Step {
    difficulty: u8,
    candidates: Vec<Candidate>,
    /// Reserves of the step by vendor index.
    reserves: Vec<PerWindow>,
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
    source: Source,
}

#[derive(Debug)]
struct InFlight {
    id: u64,
    client: String,
    timeout_at: UnixSecs,
}

/// Lazy-probe bookkeeping of one login.
#[derive(Debug, Default)]
struct ProbeState {
    /// A pick considered the login while its data was stale, and nothing was observed since.
    wanted: bool,
    in_flight: Option<InFlight>,
    /// Back-off of the last failure; 0 after a success or before any failure.
    backoff_s: u64,
    /// No job is handed out before this time.
    backoff_until: Option<UnixSecs>,
}

#[derive(Debug)]
struct Login {
    name: String,
    vendor: usize,
    /// A declared window was reported at least once.
    seen: bool,
    auth: Auth,
    exhausted_until: Option<UnixSecs>,
    rate_limited_until: Option<UnixSecs>,
    /// Dead-until per model index.
    model_dead: Vec<Option<UnixSecs>>,
    windows: [Option<Reading>; MAX_WINDOWS],
    /// Sum of the live leases' costs per window.
    reserved: PerWindow,
    /// Number of live leases on the login.
    leases: usize,
    probe: ProbeState,
}

#[derive(Debug)]
struct Lease {
    id: u64,
    login: usize,
    model: String,
    model_index: Option<usize>,
    client: String,
    run_id: Option<String>,
    on_behalf_of: Option<String>,
    cost: PerWindow,
    expires_at: UnixSecs,
    reason: Option<Reason>,
}

/// What a deadline does when it is due; indexes are login, model and window indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    LeaseExpiry(u64),
    ExhaustedEnd(usize),
    RateLimitEnd(usize),
    ModelDeadEnd(usize, usize),
    WindowReset(usize, usize),
    SnapshotStale(usize, usize),
    ProbeTimeout(usize),
    ProbeBackoffEnd(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline {
    at: UnixSecs,
    event: Event,
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
    cost: PerWindow,
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

/// Why a (candidate, login) pair is not admissible.
#[derive(Debug, Clone, Copy)]
enum Blocked {
    /// Admissible again at this time, all else unchanged.
    Until(UnixSecs),
    /// Blocked by a window without a known reset.
    Unknown,
    /// `auth_dead` login or dead (login, model) pair.
    Dead,
}

/// What the rejected candidates of a pick have in common.
#[derive(Debug, Default)]
struct Rejected {
    any: bool,
    retry_after: Option<UnixSecs>,
    unknown: bool,
    stale: bool,
    /// Bit per login index of every considered login with stale data, admissible or not.
    stale_logins: u32,
}

/// The run a pick settled on, before its lease is issued.
struct Settled {
    choice: Choice,
    model: String,
    model_index: Option<usize>,
    effort: Option<String>,
    reason: Reason,
}

/// The balancer's state and policy. Single owner, no locks: the daemon calls it from one thread.
#[derive(Debug)]
pub struct Core {
    vendors: Vec<Vendor>,
    models: Vec<String>,
    logins: Vec<Login>,
    roles: Vec<Role>,
    ttl_s: u64,
    lease_ttl_s: u64,
    cost_per_minute: f64,
    rate_limit_backoff_s: u64,
    model_unavailable_s: u64,
    probe: Option<ProbeSpec>,
    /// Probe ids issued so far; the next id is one higher.
    probes_issued: u64,
    /// Lease table by slot; a lease id is `issued * MAX_LEASES + slot`.
    leases: Vec<Option<Lease>>,
    free_slots: Vec<usize>,
    issued: u64,
    /// Min-heap with lazy deletion: an entry counts only while the state still holds its time.
    deadlines: BinaryHeap<Reverse<Deadline>>,
    /// Compaction threshold of `deadlines`, twice the number of distinct live deadlines.
    deadline_cap: usize,
}

impl Core {
    /// A core for `spec`; every window starts never observed and no lease is live.
    ///
    /// # Errors
    /// The spec exceeds a table bound, has an empty window or references an undeclared vendor.
    pub fn new(spec: Spec) -> Result<Self, SpecError> {
        if spec.logins.len() > MAX_LOGINS {
            return Err(SpecError::TooManyLogins);
        }
        let mut vendors = Vec::with_capacity(spec.vendors.len());
        for v in spec.vendors {
            if v.windows.len() > MAX_WINDOWS {
                return Err(SpecError::TooManyWindows(v.name));
            }
            if v.windows.iter().any(|w| w.length_s == 0) {
                return Err(SpecError::EmptyWindow(v.name));
            }
            let longest = (0..v.windows.len()).max_by(|&a, &b| {
                v.windows[a]
                    .length_s
                    .cmp(&v.windows[b].length_s)
                    .then(b.cmp(&a))
            });
            vendors.push(Vendor {
                name: v.name,
                shortest_s: v.windows.iter().map(|w| w.length_s).min(),
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
                seen: false,
                auth: Auth::Ok,
                exhausted_until: None,
                rate_limited_until: None,
                model_dead: Vec::new(),
                windows: [None; MAX_WINDOWS],
                reserved: [0.0; MAX_WINDOWS],
                leases: 0,
                probe: ProbeState::default(),
            });
        }
        let mut models: Vec<String> = Vec::new();
        let mut roles = Vec::with_capacity(spec.roles.len());
        for r in spec.roles {
            roles.push(role(r, &vendors, &mut models, spec.cost_per_minute)?);
        }
        for l in &mut logins {
            l.model_dead = vec![None; models.len()];
        }
        let deadline_cap = 2 * (MAX_LEASES + logins.len() * (4 + models.len() + 2 * MAX_WINDOWS));
        Ok(Self {
            vendors,
            models,
            logins,
            roles,
            ttl_s: spec.snapshot_ttl_s,
            lease_ttl_s: spec.lease_ttl_s,
            cost_per_minute: spec.cost_per_minute,
            rate_limit_backoff_s: spec.rate_limit_backoff_s,
            model_unavailable_s: spec.model_unavailable_s,
            probe: spec.probe,
            probes_issued: 0,
            leases: (0..MAX_LEASES).map(|_| None).collect(),
            free_slots: (0..MAX_LEASES).rev().collect(),
            issued: 0,
            deadlines: BinaryHeap::new(),
            deadline_cap,
        })
    }

    /// Decides where a task should run and, for a `run`, issues its lease.
    ///
    /// A ladder target tries the requested step, then the nearest lower step, then the nearest
    /// higher one. Within a step the admissible (candidate, login) pairs are ordered by tier,
    /// urgency (descending), candidate order and login index. Due deadlines apply first. With
    /// probes on, every considered login whose data is stale is wanted for a probe.
    ///
    /// # Panics
    /// Never: a full lease table holds leases, so a `leases_full` wait has an expiry to name.
    pub fn pick(&mut self, input: &PickInput, now: UnixSecs) -> Verdict {
        self.tick(now);
        let mut rejected = Rejected::default();
        let settled = self.settle(input, now, &mut rejected);
        if self.probe.is_some() {
            for (li, login) in self.logins.iter_mut().enumerate() {
                login.probe.wanted |= rejected.stale_logins & (1 << li) != 0;
            }
        }
        let Some(settled) = settled else {
            return match (rejected.any, rejected.retry_after) {
                (false, _) => Verdict::Dead(Reason::NoCandidates),
                (true, Some(retry_after)) => Verdict::Wait {
                    retry_after,
                    reason: Reason::AllExhausted,
                    stale: rejected.stale,
                },
                (true, None) if rejected.unknown => Verdict::Dead(Reason::NoResetKnown),
                (true, None) => Verdict::Dead(Reason::AllDead),
            };
        };
        let Some(slot) = self.free_slots.pop() else {
            return Verdict::Wait {
                retry_after: self
                    .earliest_expiry(None)
                    .expect("a full table holds leases"),
                reason: Reason::LeasesFull,
                stale: self.stale(settled.choice.login, now),
            };
        };
        let c = settled.choice;
        self.issued += 1;
        let id = self.issued * MAX_LEASES as u64 + slot as u64;
        let minutes = u64::from(input.expected_minutes.unwrap_or(0));
        let expires_at = now + self.lease_ttl_s + 60 * minutes;
        let login = &mut self.logins[c.login];
        login.leases += 1;
        for (r, add) in login.reserved.iter_mut().zip(c.cost) {
            *r += add;
        }
        let login = &self.logins[c.login];
        let grant = Grant {
            lease: id,
            expires_at,
            login: login.name.clone(),
            vendor: self.vendors[login.vendor].name.clone(),
            model: settled.model.clone(),
            effort: settled.effort,
            tier: c.tier,
            stale: self.stale(c.login, now),
            snapshot_at: self.snapshot_at(c.login, now),
        };
        self.leases[slot] = Some(Lease {
            id,
            login: c.login,
            model: settled.model,
            model_index: settled.model_index,
            client: input.client.clone(),
            run_id: input.run_id.clone(),
            on_behalf_of: input.on_behalf_of.clone(),
            cost: c.cost,
            expires_at,
            reason: Some(settled.reason),
        });
        self.schedule(expires_at, Event::LeaseExpiry(id));
        Verdict::Run(grant, settled.reason)
    }

    /// The best admissible run for `input`, or `None` with the rejections in `rejected`.
    fn settle(&self, input: &PickInput, now: UnixSecs, rejected: &mut Rejected) -> Option<Settled> {
        let role = self.roles.iter().find(|r| r.name == input.role)?;
        let avoid = input.avoid_vendor.as_deref();
        let minutes = input.expected_minutes;
        match &input.target {
            Target::Difficulty(d) => {
                let at = role.steps.iter().position(|s| s.difficulty == *d)?;
                let order = [Some(at), at.checked_sub(1), Some(at + 1)];
                for (n, i) in order.into_iter().enumerate() {
                    let Some(step) = i.and_then(|i| role.steps.get(i)) else {
                        continue;
                    };
                    if let Some(c) = self.best_on_step(step, avoid, minutes, now, rejected) {
                        let cand = &step.candidates[c.candidate];
                        return Some(Settled {
                            choice: c,
                            model: self.models[cand.model].clone(),
                            model_index: Some(cand.model),
                            effort: cand.effort.clone(),
                            reason: if n == 0 {
                                Reason::SpendBeforeReset
                            } else {
                                Reason::NeighbourStep
                            },
                        });
                    }
                }
                None
            }
            Target::Pin {
                vendor,
                model,
                effort,
                login,
            } => {
                if avoid == Some(vendor.as_str()) {
                    return None;
                }
                let vi = self.vendors.iter().position(|v| v.name == *vendor)?;
                let model_index = self.models.iter().position(|m| m == model);
                let rate = role
                    .steps
                    .iter()
                    .flat_map(|s| &s.candidates)
                    .find(|c| c.vendor == vi && Some(c.model) == model_index)
                    .map_or(self.cost_per_minute, |c| c.cost_per_minute);
                let cost = self.cost(vi, rate, minutes);
                let mut best: Option<Choice> = None;
                for (li, l) in self.logins.iter().enumerate() {
                    if l.vendor != vi || login.as_ref().is_some_and(|name| *name != l.name) {
                        continue;
                    }
                    let choice = Choice {
                        tier: None,
                        urgency: self.urgency(li, &cost, now),
                        candidate: 0,
                        login: li,
                        cost,
                    };
                    let reserves = [0.0; MAX_WINDOWS];
                    self.consider(choice, model_index, &reserves, now, &mut best, rejected);
                }
                Some(Settled {
                    choice: best?,
                    model: model.clone(),
                    model_index,
                    effort: effort.clone(),
                    reason: Reason::Pinned,
                })
            }
        }
    }

    fn best_on_step(
        &self,
        step: &Step,
        avoid: Option<&str>,
        minutes: Option<u32>,
        now: UnixSecs,
        rejected: &mut Rejected,
    ) -> Option<Choice> {
        let mut best: Option<Choice> = None;
        for (ci, cand) in step.candidates.iter().enumerate() {
            if avoid == Some(self.vendors[cand.vendor].name.as_str()) {
                continue;
            }
            let cost = self.cost(cand.vendor, cand.cost_per_minute, minutes);
            for li in (0..self.logins.len()).filter(|&li| self.logins[li].vendor == cand.vendor) {
                let choice = Choice {
                    tier: Some(cand.tier),
                    urgency: self.urgency(li, &cost, now),
                    candidate: ci,
                    login: li,
                    cost,
                };
                let reserves = &step.reserves[cand.vendor];
                self.consider(choice, Some(cand.model), reserves, now, &mut best, rejected);
            }
        }
        best
    }

    fn consider(
        &self,
        choice: Choice,
        model: Option<usize>,
        reserves: &PerWindow,
        now: UnixSecs,
        best: &mut Option<Choice>,
        rejected: &mut Rejected,
    ) {
        if self.stale(choice.login, now) {
            rejected.stale_logins |= 1 << choice.login;
        }
        match self.admit(choice.login, model, reserves, &choice.cost, now) {
            Ok(()) => {
                if best.as_ref().is_none_or(|b| choice.better_than(b)) {
                    *best = Some(choice);
                }
            }
            Err(blocked) => {
                rejected.any = true;
                rejected.stale |= self.stale(choice.login, now);
                match blocked {
                    Blocked::Until(t) => {
                        rejected.retry_after = Some(rejected.retry_after.map_or(t, |r| r.min(t)));
                    }
                    Blocked::Unknown => rejected.unknown = true,
                    Blocked::Dead => {}
                }
            }
        }
    }

    /// `Ok` when the login and the (login, model) pair are not dead, no back-off or exhaustion
    /// mark is active and every window keeps `left = 1 - used - reserved - cost` above 0 and at
    /// least its reserve, the reserve being dropped inside `T_burn`. Otherwise the earliest time
    /// all blocking parts clear.
    fn admit(
        &self,
        li: usize,
        model: Option<usize>,
        reserves: &PerWindow,
        cost: &PerWindow,
        now: UnixSecs,
    ) -> Result<(), Blocked> {
        let login = &self.logins[li];
        let model_dead = model
            .and_then(|m| login.model_dead[m])
            .is_some_and(|t| t > now);
        if login.auth == Auth::Dead || model_dead {
            return Err(Blocked::Dead);
        }
        let mut blocked = false;
        let mut recover = Some(0);
        for t in [login.exhausted_until, login.rate_limited_until]
            .into_iter()
            .flatten()
            .filter(|&t| t > now)
        {
            blocked = true;
            recover = recover.map(|r: UnixSecs| r.max(t));
        }
        for (w, def) in self.vendors[login.vendor].windows.iter().enumerate() {
            let e = self.effective(login.windows[w], now);
            let in_burn = e.resets_at.is_some_and(|r| r - now < def.t_burn_s);
            let reserve = if in_burn { 0.0 } else { reserves[w] };
            let fits = |left: f64| left > 0.0 && left + EPS >= reserve;
            let unleased = 1.0 - e.used - cost[w];
            let left = unleased - login.reserved[w];
            if fits(left) {
                continue;
            }
            blocked = true;
            let lease_end = (login.reserved[w] > 0.0 && fits(unleased))
                .then(|| self.earliest_expiry(Some(li)))
                .flatten();
            let burn_start = (left > 0.0)
                .then(|| e.resets_at.map(|r| r - def.t_burn_s.saturating_sub(1)))
                .flatten();
            let clears = [lease_end, burn_start, e.resets_at]
                .into_iter()
                .flatten()
                .min();
            recover = recover.zip(clears).map(|(a, b)| a.max(b));
        }
        match (blocked, recover) {
            (false, _) => Ok(()),
            (true, Some(t)) => Err(Blocked::Until(t)),
            (true, None) => Err(Blocked::Unknown),
        }
    }

    /// Earliest expiry of the live leases, of login `li` only when given.
    fn earliest_expiry(&self, li: Option<usize>) -> Option<UnixSecs> {
        self.leases
            .iter()
            .flatten()
            .filter(|l| li.is_none_or(|li| l.login == li))
            .map(|l| l.expires_at)
            .min()
    }

    /// Per-window cost of `minutes` of work at `rate`: the rate is a fraction of the vendor's
    /// shortest window per minute and scales down with the window length.
    #[allow(clippy::cast_precision_loss)] // seconds stay far below 2^53
    fn cost(&self, vendor: usize, rate: f64, minutes: Option<u32>) -> PerWindow {
        let mut out = [0.0; MAX_WINDOWS];
        let v = &self.vendors[vendor];
        if let (Some(m), Some(shortest)) = (minutes, v.shortest_s) {
            for (o, def) in out.iter_mut().zip(&v.windows) {
                *o = f64::from(m) * rate * shortest as f64 / def.length_s as f64;
            }
        }
        out
    }

    /// Spend-before-reset score on the vendor's longest window:
    /// `left / max(time to reset, 1 h) * length` with `left = 1 - used - reserved - cost`.
    #[allow(clippy::cast_precision_loss)] // seconds stay far below 2^53
    fn urgency(&self, li: usize, cost: &PerWindow, now: UnixSecs) -> f64 {
        let login = &self.logins[li];
        let vendor = &self.vendors[login.vendor];
        let Some(w) = vendor.longest else {
            return 0.0;
        };
        let length = vendor.windows[w].length_s;
        let e = self.effective(login.windows[w], now);
        let horizon = e.resets_at.map_or(length, |r| r - now).max(MIN_HORIZON_S);
        (1.0 - e.used - login.reserved[w] - cost[w]) / horizon as f64 * length as f64
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
                source: o.source,
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

    fn snapshot_at(&self, li: usize, now: UnixSecs) -> Option<UnixSecs> {
        if self.windows_of(li, now).any(|e| e.observed_at == 0) {
            None
        } else {
            self.windows_of(li, now).map(|e| e.observed_at).min()
        }
    }

    /// Applies a client's report and returns the login's status afterwards.
    ///
    /// Windows overwrite the snapshot first, then the outcome class sets its mark; a lease
    /// report with `release` frees the lease last. Due deadlines apply first.
    ///
    /// # Errors
    /// An unknown lease, login or model, a `model_unavailable` login report without a model, or
    /// a window fraction out of range; nothing is applied then.
    pub fn report(
        &mut self,
        input: &ReportInput,
        now: UnixSecs,
    ) -> Result<LoginStatus, ReportError> {
        self.tick(now);
        let (li, lease_slot, model) = match &input.subject {
            ReportSubject::Lease(id) => {
                let slot = self.lease_slot(*id).ok_or(ReportError::UnknownLease)?;
                let lease = self.leases[slot]
                    .as_ref()
                    .ok_or(ReportError::UnknownLease)?;
                let model = lease.model_index.ok_or(ReportError::UnknownModel);
                (lease.login, Some(slot), model)
            }
            ReportSubject::Login(name) => {
                let li = self
                    .logins
                    .iter()
                    .position(|l| &l.name == name)
                    .ok_or(ReportError::UnknownLogin)?;
                let model = match &input.model {
                    Some(name) => self
                        .models
                        .iter()
                        .position(|m| m == name)
                        .ok_or(ReportError::UnknownModel),
                    None => Err(ReportError::MissingModel),
                };
                (li, None, model)
            }
        };
        if input.windows.iter().any(|w| !(0.0..=1.0).contains(&w.used)) {
            return Err(ReportError::InvalidUtilization);
        }
        let dead_model = if input.outcome == OutcomeClass::ModelUnavailable {
            Some(model?)
        } else {
            None
        };

        let observed = self.observe(li, &input.windows, Source::Stream, now);
        let login = &mut self.logins[li];
        match input.outcome {
            OutcomeClass::Ok => {
                if observed {
                    login.auth = Auth::Ok;
                }
            }
            OutcomeClass::UsageLimit | OutcomeClass::Rejected => {
                let until = self.exhausted_until(li, now);
                self.logins[li].exhausted_until = Some(until);
                self.schedule(until, Event::ExhaustedEnd(li));
            }
            OutcomeClass::Http401 => login.auth = unauthorized(login.auth),
            OutcomeClass::Http429 => {
                let until = now + self.rate_limit_backoff_s;
                login.rate_limited_until = Some(until);
                self.schedule(until, Event::RateLimitEnd(li));
            }
            OutcomeClass::ModelUnavailable => {
                if let Some(m) = dead_model {
                    let until = now + self.model_unavailable_s;
                    login.model_dead[m] = Some(until);
                    self.schedule(until, Event::ModelDeadEnd(li, m));
                }
            }
            OutcomeClass::Error => {}
        }
        if let (true, Some(slot)) = (input.release, lease_slot) {
            self.release(slot);
        }
        Ok(self.status(li))
    }

    /// Overwrites the login's declared windows named in `windows`; true when any matched, which
    /// also satisfies a wanted probe.
    fn observe(
        &mut self,
        li: usize,
        windows: &[WindowObservation],
        source: Source,
        now: UnixSecs,
    ) -> bool {
        let mut observed = false;
        for obs in windows {
            let login = &mut self.logins[li];
            let Some(w) = self.vendors[login.vendor]
                .windows
                .iter()
                .position(|d| d.name == obs.name)
            else {
                continue;
            };
            let before = login.windows[w].and_then(|r| r.resets_at);
            login.windows[w] = Some(Reading {
                used: obs.used,
                resets_at: obs.resets_at,
                observed_at: now,
                source,
            });
            login.seen = true;
            login.probe.wanted = false;
            observed = true;
            if let Some(r) = obs.resets_at.filter(|&r| r > now && Some(r) != before) {
                self.schedule(r, Event::WindowReset(li, w));
            }
            self.schedule(now + self.ttl_s + 1, Event::SnapshotStale(li, w));
        }
        observed
    }

    /// End of an exhaustion mark: the earliest reset of a window at or above [`NEAR_FULL`],
    /// else the longest window's reset, else one longest-window length (one hour without
    /// windows) from `now`.
    fn exhausted_until(&self, li: usize, now: UnixSecs) -> UnixSecs {
        let login = &self.logins[li];
        let vendor = &self.vendors[login.vendor];
        self.windows_of(li, now)
            .filter(|e| e.used >= NEAR_FULL)
            .filter_map(|e| e.resets_at)
            .min()
            .or_else(|| {
                let w = vendor.longest?;
                self.effective(login.windows[w], now).resets_at
            })
            .unwrap_or_else(|| {
                now + vendor
                    .longest
                    .map_or(MIN_HORIZON_S, |w| vendor.windows[w].length_s)
            })
    }

    fn status(&self, li: usize) -> LoginStatus {
        let l = &self.logins[li];
        if l.auth == Auth::Dead {
            LoginStatus::AuthDead
        } else if l.exhausted_until.is_some() {
            LoginStatus::Exhausted
        } else if l.rate_limited_until.is_some() {
            LoginStatus::RateLimited
        } else if l.auth == Auth::Stale {
            LoginStatus::AuthStale
        } else if l.seen {
            LoginStatus::Ok
        } else {
            LoginStatus::Unknown
        }
    }

    fn lease_slot(&self, id: u64) -> Option<usize> {
        let slot = usize::try_from(id % MAX_LEASES as u64).ok()?;
        self.leases[slot]
            .as_ref()
            .is_some_and(|l| l.id == id)
            .then_some(slot)
    }

    fn release(&mut self, slot: usize) {
        let Some(lease) = self.leases[slot].take() else {
            return;
        };
        let login = &mut self.logins[lease.login];
        login.leases -= 1;
        if login.leases == 0 {
            login.reserved = [0.0; MAX_WINDOWS];
        } else {
            for (r, sub) in login.reserved.iter_mut().zip(lease.cost) {
                *r = (*r - sub).max(0.0);
            }
        }
        self.free_slots.push(slot);
    }

    fn schedule(&mut self, at: UnixSecs, event: Event) {
        self.deadlines.push(Reverse(Deadline { at, event }));
        if self.deadlines.len() > self.deadline_cap {
            let mut live = std::mem::take(&mut self.deadlines).into_vec();
            live.retain(|Reverse(d)| self.pending(*d));
            live.sort_unstable();
            live.dedup();
            self.deadlines = live.into();
        }
    }

    /// The state still holds the deadline's time, so the heap entry is not stale.
    fn pending(&self, d: Deadline) -> bool {
        let login = |li: usize| &self.logins[li];
        let reading = |li: usize, w: usize| login(li).windows[w];
        match d.event {
            Event::LeaseExpiry(id) => self
                .lease_slot(id)
                .and_then(|s| self.leases[s].as_ref())
                .is_some_and(|l| l.expires_at == d.at),
            Event::ExhaustedEnd(li) => login(li).exhausted_until == Some(d.at),
            Event::RateLimitEnd(li) => login(li).rate_limited_until == Some(d.at),
            Event::ModelDeadEnd(li, m) => login(li).model_dead[m] == Some(d.at),
            Event::WindowReset(li, w) => reading(li, w).is_some_and(|r| r.resets_at == Some(d.at)),
            Event::SnapshotStale(li, w) => {
                reading(li, w).is_some_and(|r| r.observed_at + self.ttl_s + 1 == d.at)
            }
            Event::ProbeTimeout(li) => {
                login(li).probe.in_flight.as_ref().map(|p| p.timeout_at) == Some(d.at)
            }
            Event::ProbeBackoffEnd(li) => login(li).probe.backoff_until == Some(d.at),
        }
    }

    /// The earliest pending deadline: a lease expiry, the end of a mark, a window reset, the
    /// moment a snapshot turns stale, a probe timeout or the end of a probe back-off. Stale heap
    /// entries are dropped on the way.
    pub fn next_deadline(&mut self) -> Option<UnixSecs> {
        while let Some(&Reverse(d)) = self.deadlines.peek() {
            if self.pending(d) {
                return Some(d.at);
            }
            self.deadlines.pop();
        }
        None
    }

    /// Applies every deadline due at `now`: expired leases free their reservation, ended marks
    /// are lifted and a timed-out probe fails at its timeout. Window resets, staleness and
    /// back-off ends need no action; they are inferred from `now` wherever they matter.
    pub fn tick(&mut self, now: UnixSecs) {
        while let Some(&Reverse(d)) = self.deadlines.peek() {
            if d.at > now {
                break;
            }
            self.deadlines.pop();
            if !self.pending(d) {
                continue;
            }
            match d.event {
                Event::LeaseExpiry(id) => {
                    if let Some(slot) = self.lease_slot(id) {
                        self.release(slot);
                    }
                }
                Event::ExhaustedEnd(li) => self.logins[li].exhausted_until = None,
                Event::RateLimitEnd(li) => self.logins[li].rate_limited_until = None,
                Event::ModelDeadEnd(li, m) => self.logins[li].model_dead[m] = None,
                Event::ProbeTimeout(li) => {
                    self.logins[li].probe.in_flight = None;
                    self.probe_failed(li, d.at, 0);
                }
                Event::WindowReset(..) | Event::SnapshotStale(..) | Event::ProbeBackoffEnd(_) => {}
            }
        }
    }

    /// View of the state as of the last [`Core::tick`], [`Core::pick`] or [`Core::report`],
    /// with windows inferred at `now`.
    pub fn snapshot(&self, now: UnixSecs) -> Snapshot {
        Snapshot {
            logins: self
                .logins
                .iter()
                .enumerate()
                .map(|(li, l)| LoginView {
                    name: l.name.clone(),
                    vendor: self.vendors[l.vendor].name.clone(),
                    status: self.status(li),
                    dead_until: l.exhausted_until.max(l.rate_limited_until),
                    windows: self.vendors[l.vendor]
                        .windows
                        .iter()
                        .zip(self.windows_of(li, now))
                        .zip(l.reserved)
                        .map(|((def, e), reserved)| WindowView {
                            name: def.name.clone(),
                            used: e.used,
                            reserved,
                            resets_at: e.resets_at,
                            observed_at: e.observed_at,
                            source: e.source,
                            stale: e.stale,
                        })
                        .collect(),
                })
                .collect(),
            leases: self
                .leases
                .iter()
                .flatten()
                .map(|l| LeaseView {
                    id: l.id,
                    login: self.logins[l.login].name.clone(),
                    model: l.model.clone(),
                    client: l.client.clone(),
                    run_id: l.run_id.clone(),
                    on_behalf_of: l.on_behalf_of.clone(),
                    expires_at: l.expires_at,
                })
                .collect(),
        }
    }

    /// The live lease `id`.
    pub fn lease(&self, id: u64) -> Option<LeaseRecord> {
        let l = self.leases[self.lease_slot(id)?].as_ref()?;
        let windows = self.vendors[self.logins[l.login].vendor].windows.len();
        Some(LeaseRecord {
            id: l.id,
            login: self.logins[l.login].name.clone(),
            model: l.model.clone(),
            client: l.client.clone(),
            run_id: l.run_id.clone(),
            on_behalf_of: l.on_behalf_of.clone(),
            cost: l.cost[..windows].to_vec(),
            expires_at: l.expires_at,
            reason: l.reason,
        })
    }

    /// The marks of the configured login `login`.
    pub fn marks(&self, login: &str) -> Option<Marks> {
        let l = self.logins.iter().find(|l| l.name == login)?;
        Some(Marks {
            auth: l.auth,
            exhausted_until: l.exhausted_until,
            rate_limited_until: l.rate_limited_until,
            model_dead: self
                .models
                .iter()
                .zip(&l.model_dead)
                .filter_map(|(m, t)| Some((m.clone(), (*t)?)))
                .collect(),
        })
    }

    /// The live state as records: the lease counter, every live lease in slot order and the
    /// marks of every login that has any.
    pub fn records(&self) -> Vec<Record> {
        let mut out = vec![Record::Issued(self.issued)];
        out.extend(
            self.leases
                .iter()
                .flatten()
                .filter_map(|l| self.lease(l.id))
                .map(Record::Lease),
        );
        out.extend(
            self.logins
                .iter()
                .filter_map(|l| Some((l.name.clone(), self.marks(&l.name)?)))
                .filter(|(_, m)| *m != Marks::default())
                .map(|(login, marks)| Record::Marks { login, marks }),
        );
        out
    }

    /// Applies `record` as of `at`, after the deadlines due at `at`. A lease replaces whatever
    /// holds its slot; marks replace the login's marks, models no ladder declares are ignored.
    ///
    /// # Errors
    /// The record does not fit this core's config; nothing is applied then.
    pub fn restore(&mut self, record: &Record, at: UnixSecs) -> Result<(), RestoreError> {
        self.tick(at);
        match record {
            Record::Issued(n) => self.issued = self.issued.max(*n),
            Record::Lease(r) => self.restore_lease(r)?,
            Record::Release(id) => {
                if let Some(slot) = self.lease_slot(*id) {
                    self.release(slot);
                }
            }
            Record::Marks { login, marks } => {
                let li = self.login_index(login)?;
                let models: Vec<Option<UnixSecs>> = self
                    .models
                    .iter()
                    .map(|m| {
                        marks
                            .model_dead
                            .iter()
                            .find(|(name, _)| name == m)
                            .map(|&(_, t)| t)
                    })
                    .collect();
                let l = &mut self.logins[li];
                l.auth = marks.auth;
                l.exhausted_until = marks.exhausted_until;
                l.rate_limited_until = marks.rate_limited_until;
                l.model_dead.clone_from(&models);
                if let Some(t) = marks.exhausted_until {
                    self.schedule(t, Event::ExhaustedEnd(li));
                }
                if let Some(t) = marks.rate_limited_until {
                    self.schedule(t, Event::RateLimitEnd(li));
                }
                for (m, t) in models.into_iter().enumerate() {
                    if let Some(t) = t {
                        self.schedule(t, Event::ModelDeadEnd(li, m));
                    }
                }
            }
        }
        Ok(())
    }

    fn restore_lease(&mut self, r: &LeaseRecord) -> Result<(), RestoreError> {
        let li = self.login_index(&r.login)?;
        let windows = self.vendors[self.logins[li].vendor].windows.len();
        if r.cost.len() != windows {
            return Err(RestoreError::CostWindows {
                login: r.login.clone(),
                expected: windows,
                got: r.cost.len(),
            });
        }
        let mut cost = [0.0; MAX_WINDOWS];
        cost[..windows].copy_from_slice(&r.cost);
        let slot = usize::try_from(r.id % MAX_LEASES as u64).expect("a slot index fits usize");
        self.release(slot);
        self.free_slots.retain(|&s| s != slot);
        let login = &mut self.logins[li];
        login.leases += 1;
        for (sum, add) in login.reserved.iter_mut().zip(cost) {
            *sum += add;
        }
        self.issued = self.issued.max(r.id / MAX_LEASES as u64);
        self.leases[slot] = Some(Lease {
            id: r.id,
            login: li,
            model: r.model.clone(),
            model_index: self.models.iter().position(|m| *m == r.model),
            client: r.client.clone(),
            run_id: r.run_id.clone(),
            on_behalf_of: r.on_behalf_of.clone(),
            cost,
            expires_at: r.expires_at,
            reason: r.reason,
        });
        self.schedule(r.expires_at, Event::LeaseExpiry(r.id));
        Ok(())
    }

    /// Hands `client` a probe of the first due login among `logins`, in their order, and puts
    /// it in flight until its result or [`PROBE_TIMEOUT_S`]. A login is due while it is wanted,
    /// not `auth_dead`, has no probe in flight and is not backing off. Always `None` with probes
    /// off; names the config does not declare are skipped. Due deadlines apply first.
    pub fn probe_next(
        &mut self,
        client: &str,
        logins: &[String],
        now: UnixSecs,
    ) -> Option<ProbeJob> {
        self.tick(now);
        self.probe?;
        let li = logins.iter().find_map(|name| {
            let li = self.logins.iter().position(|l| l.name == *name)?;
            let l = &self.logins[li];
            let p = &l.probe;
            let due = p.wanted
                && l.auth != Auth::Dead
                && p.in_flight.is_none()
                && p.backoff_until.is_none_or(|t| t <= now);
            due.then_some(li)
        })?;
        self.probes_issued += 1;
        let id = self.probes_issued;
        let timeout_at = now + PROBE_TIMEOUT_S;
        let probe = &mut self.logins[li].probe;
        probe.wanted = false;
        probe.in_flight = Some(InFlight {
            id,
            client: client.to_owned(),
            timeout_at,
        });
        self.schedule(timeout_at, Event::ProbeTimeout(li));
        Some(ProbeJob {
            id,
            login: self.logins[li].name.clone(),
        })
    }

    /// The login of the probe `id` while it is in flight.
    pub fn probe_login(&self, id: u64) -> Option<&str> {
        Some(self.logins[self.probe_slot(id)?].name.as_str())
    }

    fn probe_slot(&self, id: u64) -> Option<usize> {
        self.logins
            .iter()
            .position(|l| l.probe.in_flight.as_ref().is_some_and(|p| p.id == id))
    }

    /// Applies the result of probe `id` from `client` and returns the login and its status.
    ///
    /// `Ok` overwrites the named declared windows with `source = probe`, as a stream report
    /// does, clears the auth state when a declared window is among them, and ends the back-off. `Http401` steps the login's auth like a 401 report. It,
    /// `Http429` and `Error` are failures: the back-off starts at the configured initial value
    /// and doubles up to the ceiling; a 429 waits at least its `retry_after_s`.
    ///
    /// # Errors
    /// The probe is not in flight, was handed to another client, or a window fraction is out
    /// of range; nothing is applied then.
    pub fn probe_result(
        &mut self,
        id: u64,
        client: &str,
        outcome: &ProbeOutcome,
        now: UnixSecs,
    ) -> Result<(String, LoginStatus), ProbeError> {
        self.tick(now);
        let li = self.probe_slot(id).ok_or(ProbeError::UnknownProbe)?;
        if self.logins[li]
            .probe
            .in_flight
            .as_ref()
            .is_some_and(|p| p.client != client)
        {
            return Err(ProbeError::OtherClient);
        }
        if let ProbeOutcome::Ok(windows) = outcome {
            if windows.iter().any(|w| !(0.0..=1.0).contains(&w.used)) {
                return Err(ProbeError::InvalidUtilization);
            }
        }
        self.logins[li].probe.in_flight = None;
        match outcome {
            ProbeOutcome::Ok(windows) => {
                let observed = self.observe(li, windows, Source::Probe, now);
                let login = &mut self.logins[li];
                if observed {
                    login.auth = Auth::Ok;
                }
                login.probe.backoff_s = 0;
                login.probe.backoff_until = None;
            }
            ProbeOutcome::Http401 => {
                let login = &mut self.logins[li];
                login.auth = unauthorized(login.auth);
                self.probe_failed(li, now, 0);
            }
            ProbeOutcome::Http429 { retry_after_s } => {
                self.probe_failed(li, now, retry_after_s.unwrap_or(0));
            }
            ProbeOutcome::Error => self.probe_failed(li, now, 0),
        }
        Ok((self.logins[li].name.clone(), self.status(li)))
    }

    /// Doubles the login's probe back-off from the initial value up to the ceiling and holds
    /// its next job until `at` plus the longer of that back-off and `at_least_s`.
    fn probe_failed(&mut self, li: usize, at: UnixSecs, at_least_s: u64) {
        let Some(spec) = self.probe else {
            return;
        };
        let probe = &mut self.logins[li].probe;
        probe.backoff_s = if probe.backoff_s == 0 {
            spec.backoff_initial_s
        } else {
            probe.backoff_s.saturating_mul(2).min(spec.backoff_max_s)
        };
        let until = at.saturating_add(probe.backoff_s.max(at_least_s));
        probe.backoff_until = Some(until);
        self.schedule(until, Event::ProbeBackoffEnd(li));
    }

    fn login_index(&self, name: &str) -> Result<usize, RestoreError> {
        self.logins
            .iter()
            .position(|l| l.name == name)
            .ok_or_else(|| RestoreError::UnknownLogin(name.to_owned()))
    }
}

/// Auth after a 401: `ok` becomes `stale`, a repeated 401 makes it `dead`.
fn unauthorized(auth: Auth) -> Auth {
    match auth {
        Auth::Ok => Auth::Stale,
        Auth::Stale | Auth::Dead => Auth::Dead,
    }
}

/// Compiles a role, interning its candidates' models into `models`.
fn role(
    r: RoleSpec,
    vendors: &[Vendor],
    models: &mut Vec<String>,
    default_rate: f64,
) -> Result<Role, SpecError> {
    let mut steps = Vec::with_capacity(r.ladder.len());
    for s in r.ladder {
        if s.candidates.len() > MAX_CANDIDATES {
            return Err(SpecError::TooManyCandidates(r.name, s.difficulty));
        }
        let mut candidates = Vec::with_capacity(s.candidates.len());
        for c in s.candidates {
            let vendor = vendors
                .iter()
                .position(|v| v.name == c.vendor)
                .ok_or(SpecError::UnknownVendor(c.vendor))?;
            let model = models
                .iter()
                .position(|m| *m == c.model)
                .unwrap_or_else(|| {
                    models.push(c.model);
                    models.len() - 1
                });
            candidates.push(Candidate {
                vendor,
                model,
                effort: c.effort,
                tier: c.tier,
                cost_per_minute: c.cost_per_minute.unwrap_or(default_rate),
            });
        }
        let reserves = vendors
            .iter()
            .map(|v| {
                let mut out = [0.0; MAX_WINDOWS];
                for (w, def) in v.windows.iter().enumerate() {
                    if let Some(res) = r
                        .reserves
                        .iter()
                        .find(|res| res.difficulty == s.difficulty && res.window == def.name)
                    {
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
    Ok(Role {
        name: r.name,
        steps,
    })
}
