//! Pure scheduling policy of quota-balancer.
//!
//! This crate owns the balancer's state (logins, quota windows, leases) and the two decisions
//! that change it: [`Core::pick`] and [`Core::report`]. It performs no I/O and reads no clock:
//! the caller passes `now` in. That keeps the policy deterministic, table-testable and
//! replayable from a journal.
//!
//! Status: skeleton. The state model and the decision types are in place; the ladder,
//! admissibility, spend-before-reset scoring and lease accounting are the next milestone (see
//! `docs/roadmap.md`). With no logins configured, `pick` answers `dead` / `no_candidates`.

#![forbid(unsafe_code)]

/// Unix time in seconds.
pub type UnixSecs = u64;

/// Index of a login in the configured login table (at most [`MAX_LOGINS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LoginIdx(pub u8);

/// Upper bound on configured logins; the state uses fixed-size tables of this length.
pub const MAX_LOGINS: usize = 32;
/// Upper bound on quota windows per login.
pub const MAX_WINDOWS: usize = 4;
/// Upper bound on candidates per ladder step.
pub const MAX_CANDIDATES: usize = 8;
/// Upper bound on live leases.
pub const MAX_LEASES: usize = 256;

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

/// What the caller asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Walk the ladder of the role from this difficulty step.
    Difficulty(u8),
    /// Exact vendor/model.
    Pin {
        /// Vendor id.
        vendor: String,
        /// Model.
        model: String,
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
    /// Run being resumed (sticks to its login).
    pub resume_of: Option<String>,
    /// Vendor to avoid.
    pub avoid_vendor: Option<String>,
    /// Identity of the calling client, from peer credentials or a bearer token.
    pub client: String,
}

/// Why the core decided what it decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No configured candidate matches the request.
    NoCandidates,
}

impl Reason {
    /// Stable machine-readable name used on the wire and in the journal.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCandidates => "no_candidates",
        }
    }
}

/// A granted run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Lease id.
    pub lease_id: u64,
    /// Login.
    pub login: LoginIdx,
    /// Model.
    pub model: String,
    /// Ladder tier.
    pub tier: u8,
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

/// Input of [`Core::report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportInput {
    /// Lease or login.
    pub subject: ReportSubject,
    /// Outcome class.
    pub outcome: OutcomeClass,
    /// Release the lease.
    pub release: bool,
}

/// Why [`Core::report`] refused a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    /// No live lease with that id.
    UnknownLease,
    /// No configured login with that name.
    UnknownLogin,
}

/// A login as seen in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginView {
    /// Configured name.
    pub name: String,
    /// Vendor id.
    pub vendor: String,
    /// Status.
    pub status: LoginStatus,
}

/// Read-only view of the state for `/v1/state`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// Configured logins.
    pub logins: Vec<LoginView>,
}

/// A login as declared in the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSpec {
    /// Unique name, e.g. `vendor-a-main`.
    pub name: String,
    /// Vendor id the login belongs to.
    pub vendor: String,
}

/// Configured login.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Login {
    name: String,
    vendor: String,
    status: LoginStatus,
}

/// The balancer's state and policy. Single owner, no locks: the daemon calls it from one thread.
#[derive(Debug, Default)]
pub struct Core {
    logins: Vec<Login>,
}

impl Core {
    /// A core with no logins configured.
    pub fn new() -> Self {
        Self::default()
    }

    /// A core with the given logins, all in [`LoginStatus::Unknown`] until data arrives.
    /// Logins beyond [`MAX_LOGINS`] are ignored; config validation rejects them earlier.
    pub fn with_logins(specs: impl IntoIterator<Item = LoginSpec>) -> Self {
        let logins = specs
            .into_iter()
            .take(MAX_LOGINS)
            .map(|s| Login {
                name: s.name,
                vendor: s.vendor,
                status: LoginStatus::Unknown,
            })
            .collect();
        Self { logins }
    }

    /// Decides where a task should run.
    pub fn pick(&mut self, input: &PickInput, now: UnixSecs) -> Verdict {
        let _ = (input, now);
        // Skeleton: the ladder and admissibility checks land in the S1 policy milestone.
        Verdict::Dead(Reason::NoCandidates)
    }

    /// Applies a client's report and returns the login's status afterwards.
    ///
    /// # Errors
    /// [`ReportError::UnknownLease`] or [`ReportError::UnknownLogin`] when the subject is not known.
    pub fn report(
        &mut self,
        input: &ReportInput,
        now: UnixSecs,
    ) -> Result<LoginStatus, ReportError> {
        let _ = now;
        match &input.subject {
            ReportSubject::Lease(_) => Err(ReportError::UnknownLease),
            ReportSubject::Login(name) => self
                .logins
                .iter()
                .find(|l| &l.name == name)
                .map(|l| l.status)
                .ok_or(ReportError::UnknownLogin),
        }
    }

    /// Read-only view of the state.
    pub fn snapshot(&self, now: UnixSecs) -> Snapshot {
        let _ = now;
        Snapshot {
            logins: self
                .logins
                .iter()
                .map(|l| LoginView {
                    name: l.name.clone(),
                    vendor: l.vendor.clone(),
                    status: l.status,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(target: Target) -> PickInput {
        PickInput {
            role: "worker".into(),
            target,
            resume_of: None,
            avoid_vendor: None,
            client: "test".into(),
        }
    }

    #[test]
    fn empty_core_has_no_candidates() {
        let mut core = Core::new();
        for target in [
            Target::Difficulty(0),
            Target::Pin {
                vendor: "v".into(),
                model: "m".into(),
                login: None,
            },
        ] {
            assert_eq!(
                core.pick(&input(target), 1_800_000_000),
                Verdict::Dead(Reason::NoCandidates)
            );
        }
    }

    #[test]
    fn report_on_unknown_subjects_is_refused() {
        let mut core = Core::new();
        let lease = ReportInput {
            subject: ReportSubject::Lease(1),
            outcome: OutcomeClass::Ok,
            release: true,
        };
        assert_eq!(core.report(&lease, 0), Err(ReportError::UnknownLease));
        let login = ReportInput {
            subject: ReportSubject::Login("nope".into()),
            outcome: OutcomeClass::UsageLimit,
            release: false,
        };
        assert_eq!(core.report(&login, 0), Err(ReportError::UnknownLogin));
    }

    #[test]
    fn configured_logins_start_unknown() {
        let mut core = Core::with_logins([LoginSpec {
            name: "login-1".into(),
            vendor: "vendor-a".into(),
        }]);
        let report = ReportInput {
            subject: ReportSubject::Login("login-1".into()),
            outcome: OutcomeClass::Ok,
            release: false,
        };
        assert_eq!(core.report(&report, 0), Ok(LoginStatus::Unknown));
        let snap = core.snapshot(0);
        assert_eq!(snap.logins.len(), 1);
        assert_eq!(snap.logins[0].vendor, "vendor-a");
    }

    #[test]
    fn empty_snapshot() {
        assert_eq!(Core::new().snapshot(0), Snapshot::default());
    }

    #[test]
    fn reason_names_are_stable() {
        assert_eq!(Reason::NoCandidates.as_str(), "no_candidates");
    }
}
