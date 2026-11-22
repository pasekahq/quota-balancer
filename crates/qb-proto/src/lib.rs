//! Wire types of the quota-balancer `/v1` API.
//!
//! Every message that crosses a socket is declared here exactly once. The daemon, the CLI and
//! the contract tests all use these types; JSON Schema / `OpenAPI` generation will be derived
//! from them later.
//!
//! Conventions:
//! - all timestamps are Unix seconds (`u64`);
//! - utilisation is a fraction in `0.0..=1.0`;
//! - enums are serialised in `snake_case`;
//! - requests reject unknown fields, responses may grow new optional fields within `v1`.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod gateway;

pub use gateway::{
    ApiFamily, Attempt, AuditAction, AuditAnswer, AuditEntry, AuditResult, Block, CacheMode,
    CancelAnswer, CancelRequest, ClientRotateAnswer, ConfigRoute, ConfigRoutes, ConfigRoutesPut,
    ConfigRoutesWritten, ConfigStep, Effort, Elsewhere, ErrorClass, GatewayError, LadderAnswer,
    LadderCandidateState, LadderStepState, LoginKey, LoginKeyAnswer, LoginOauthCode,
    LoginOauthSigned, LoginOauthStarted, LoginSpend, MediaType, Message, NativeApi, NativeTool,
    OauthPaste, Object, ReloadAnswer, Role, RouteInfo, RouteState, RouteStatus, RoutesAnswer,
    SpendAnswer, SpendReset, StopReason, StreamEvent, Thinking, Tool, ToolCall, TurnRequest,
    TurnRequestError, Usage, UsageAnswer, UsageBucket, UsageGroupBy, UsageLine, UsageQuery,
    UsageRow, UsdSource, validate_login_key,
};

/// API version reported by `/v1/health` and used as the URL prefix.
pub const API_VERSION: &str = "v1";

/// Paths of the `/v1` endpoints.
pub mod paths {
    /// `POST`: ask which vendor/model/login to run a task on.
    pub const PICK: &str = "/v1/pick";
    /// `POST`: report an outcome or fresh quota windows observed by a client.
    pub const REPORT: &str = "/v1/report";
    /// `GET`: snapshot of logins, windows and live leases.
    pub const STATE: &str = "/v1/state";
    /// `GET`: liveness and version.
    pub const HEALTH: &str = "/v1/health";
    /// `GET`: the roles and ladders `qbd` runs.
    pub const ROLES: &str = "/v1/roles";
    /// `GET`, followed by a lease id: why a live lease was granted.
    pub const WHY: &str = "/v1/why/";
    /// `POST`: an agent waits for a probe job.
    pub const AGENT_NEXT: &str = "/v1/agent/next";
    /// `POST`: an agent answers a probe job.
    pub const AGENT_RESULT: &str = "/v1/agent/result";
    /// Prefix of the endpoints only an admin client of `qbd` may call.
    pub const ADMIN: &str = "/v1/admin/";
    /// `GET`: the roles and ladders of `qbd`'s config files on disk; `PUT`: replaces the
    /// `roles_file` and runs it; admin only.
    pub const ADMIN_ROLES: &str = "/v1/admin/roles";
    /// `POST`: `qbd` reloads its roles and clients as on SIGHUP; admin only.
    pub const ADMIN_RELOAD: &str = "/v1/admin/reload";
    /// `POST`: clears the `auth_stale` and `auth_dead` marks of logins; admin only.
    pub const ADMIN_LOGINS_RESET: &str = "/v1/admin/logins/reset";
    /// Gateway, `POST`: run one model turn and stream its events as NDJSON.
    pub const MODEL_TURN: &str = "/v1/model/turn";
    /// Gateway, `GET`: route aliases and where a turn would run now.
    pub const MODEL_ROUTES: &str = "/v1/model/routes";
    /// Gateway, `GET` with `route` or `role`: the ladder steps the caller's routes run on, with
    /// the state of each candidate.
    pub const MODEL_LADDER: &str = "/v1/model/ladder";
    /// Gateway, `POST`: stop a running turn of the caller.
    pub const MODEL_CANCEL: &str = "/v1/model/cancel";
    /// Gateway, `POST`: read the gateway's config file again; only the gateway's own uid.
    pub const MODEL_RELOAD: &str = "/v1/model/reload";
    /// Gateway, `GET`: the month's spend of each capped login; only the gateway's own uid.
    pub const MODEL_SPEND: &str = "/v1/model/spend";
    /// Gateway, `POST`: set a login's spend count to zero; only the gateway's own uid.
    pub const MODEL_SPEND_RESET: &str = "/v1/model/spend/reset";
    /// Gateway, `GET`: the lines of the gateway's audit file; only the gateway's own uid.
    pub const MODEL_AUDIT: &str = "/v1/model/audit";
    /// Gateway, `GET`: sums of the gateway's usage ledger; only the gateway's own uid.
    pub const MODEL_USAGE: &str = "/v1/model/usage";
    /// Gateway, `POST` to `{MODEL_CLIENTS}/{name}/rotate`: write a fresh token to a named
    /// loopback client's `token_file`; only the gateway's own uid.
    pub const MODEL_CLIENTS: &str = "/v1/model/clients";
    /// Gateway, `GET` and `PUT`: the `[[routes]]` of the gateway's config file, read and
    /// replaced; only the gateway's own uid.
    pub const MODEL_CONFIG_ROUTES: &str = "/v1/model/config/routes";
    /// Gateway, `POST` to `{MODEL_LOGINS}/{name}/key`: write a new key to an `api_key` login's
    /// credential file; to `{MODEL_LOGINS}/{name}/oauth/start` and `.../oauth/code`: sign an
    /// OAuth login in again; only the gateway's own uid.
    pub const MODEL_LOGINS: &str = "/v1/model/logins";
    /// Gateway, `POST`: an Anthropic Messages request, answered in the Messages format.
    pub const MESSAGES: &str = "/v1/messages";
    /// Gateway, `POST`: an OpenAI Chat Completions request, answered in that format.
    pub const CHAT_COMPLETIONS: &str = "/v1/chat/completions";
    /// Gateway, `POST`: an OpenAI Responses request, answered in that format.
    pub const RESPONSES: &str = "/v1/responses";
}

/// `POST /v1/pick` request.
///
/// Exactly one of [`PickRequest::difficulty`] and [`PickRequest::pin`] must be set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PickRequest {
    /// Role of the work, e.g. `worker`, `reviewer`, `observer`. Roles are defined in the config.
    pub role: String,
    /// Difficulty step on the configured ladder (0 = cheapest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<u8>,
    /// Pin an exact vendor/model instead of walking the ladder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<Pin>,
    /// Run id of a session being resumed; the answer stays on the same login or waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_of: Option<String>,
    /// Vendor to avoid (independent review).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avoid_vendor: Option<String>,
    /// Required capabilities. Accepted but not used yet: no candidate declares capabilities, so
    /// it filters nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub need: Vec<String>,
    /// Expected duration of the task, used for the cost estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_minutes: Option<u32>,
    /// Caller's id of the run, echoed into the lease and the journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// End client a relaying caller picks for, echoed into the lease and the journal; at most
    /// [`ON_BEHALF_OF_MAX`] bytes, not empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Allow-list of logins: a `run` lands only on one of them; 1 to [`PICK_LOGINS_MAX`]
    /// distinct names, each a declared login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logins: Option<Vec<String>>,
}

/// Longest accepted [`PickRequest::on_behalf_of`], in bytes.
pub const ON_BEHALF_OF_MAX: usize = 128;

/// Most names in [`PickRequest::logins`].
pub const PICK_LOGINS_MAX: usize = 32;

/// Why a [`PickRequest`] is malformed beyond what JSON decoding catches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickRequestError {
    /// Neither `difficulty` nor `pin` was given.
    NoTarget,
    /// Both `difficulty` and `pin` were given.
    AmbiguousTarget,
    /// `role` is empty.
    EmptyRole,
    /// `on_behalf_of` is empty or longer than [`ON_BEHALF_OF_MAX`] bytes.
    BadOnBehalfOf,
    /// `logins` is empty, longer than [`PICK_LOGINS_MAX`], repeats a name or names an
    /// undeclared login.
    BadLogins,
}

impl PickRequestError {
    /// Human-readable message for an error body.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoTarget => "one of `difficulty` or `pin` is required",
            Self::AmbiguousTarget => "`difficulty` and `pin` are mutually exclusive",
            Self::EmptyRole => "`role` must not be empty",
            Self::BadOnBehalfOf => "`on_behalf_of` must be 1 to 128 bytes",
            Self::BadLogins => "`logins` must be 1 to 32 distinct declared login names",
        }
    }
}

impl PickRequest {
    /// Checks the invariants that the type system does not express.
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate(&self) -> Result<(), PickRequestError> {
        if self.role.trim().is_empty() {
            return Err(PickRequestError::EmptyRole);
        }
        if self
            .on_behalf_of
            .as_ref()
            .is_some_and(|o| o.is_empty() || o.len() > ON_BEHALF_OF_MAX)
        {
            return Err(PickRequestError::BadOnBehalfOf);
        }
        if let Some(logins) = &self.logins {
            let repeated = logins
                .iter()
                .enumerate()
                .any(|(i, name)| logins[..i].contains(name));
            if logins.is_empty() || logins.len() > PICK_LOGINS_MAX || repeated {
                return Err(PickRequestError::BadLogins);
            }
        }
        match (&self.difficulty, &self.pin) {
            (None, None) => Err(PickRequestError::NoTarget),
            (Some(_), Some(_)) => Err(PickRequestError::AmbiguousTarget),
            _ => Ok(()),
        }
    }
}

/// An exact vendor/model choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// Vendor id from the config.
    pub vendor: String,
    /// Model name as the vendor's CLI expects it.
    pub model: String,
    /// Reasoning effort, if the vendor has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Restrict to one login of the vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
}

/// What the client should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Run now on the returned vendor/model/login under the returned lease.
    Run,
    /// Nothing is admissible now; retry after `retry_after`.
    Wait,
    /// Every candidate is dead (exhausted, auth dead, unavailable); a human may be needed.
    Dead,
}

/// `POST /v1/pick` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PickResponse {
    /// The decision.
    pub decision: Decision,
    /// Machine-readable reason, e.g. `spend_before_reset`, `no_candidates`.
    pub reason: String,
    /// Lease to report against; present when `decision = run`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Chosen vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// Chosen model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Chosen reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Chosen login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// Ladder tier of the choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    /// When to ask again; present when `decision = wait`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// The quota data behind the decision is older than its TTL.
    #[serde(default)]
    pub stale: bool,
    /// When the quota snapshot behind the decision was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_snapshot_at: Option<u64>,
}

/// Outcome class a client reports for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The run finished or is progressing normally (window update only).
    Ok,
    /// The vendor said the usage limit is reached.
    UsageLimit,
    /// The vendor rejected the request (`rate_limit_event.status = rejected`).
    Rejected,
    /// HTTP 401: credentials expired or revoked.
    #[serde(rename = "http_401")]
    Http401,
    /// HTTP 429 without exhaustion: short back-off.
    #[serde(rename = "http_429")]
    Http429,
    /// The model is not available on this login.
    ModelUnavailable,
    /// Any other failure; does not change login state.
    Error,
}

/// One quota window as observed by a client in the vendor's stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowReport {
    /// Window name, e.g. `five_hour`, `seven_day`.
    pub name: String,
    /// Used fraction, `0.0..=1.0`.
    pub utilization: f64,
    /// When the window resets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
    /// Window length in seconds, if the vendor states it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length_s: Option<u32>,
}

/// `POST /v1/report` request. At least one of `lease_id` and `login` must be set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRequest {
    /// Lease the report is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// Login the report is about, when there is no lease (e.g. a stream outside the balancer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<String>,
    /// Outcome class.
    pub outcome: Outcome,
    /// Model the outcome applies to (for `model_unavailable`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Fresh windows seen in the stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<WindowReport>,
    /// The run is over; release the lease.
    #[serde(default)]
    pub release: bool,
    /// Fingerprint of the credential the reported request used: 8 to 64 lowercase hex digits
    /// of a hash, never the secret. An `auth_stale` or `auth_dead` mark keeps the fingerprint
    /// it was reported with; a report of another fingerprint clears the mark first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// Fewest hex digits of a [`ReportRequest::credential`] fingerprint.
pub const CREDENTIAL_MIN: usize = 8;

/// Most hex digits of a [`ReportRequest::credential`] fingerprint.
pub const CREDENTIAL_MAX: usize = 64;

/// Whether `fingerprint` is a valid [`ReportRequest::credential`]: [`CREDENTIAL_MIN`] to
/// [`CREDENTIAL_MAX`] lowercase hex digits.
pub fn credential_valid(fingerprint: &str) -> bool {
    (CREDENTIAL_MIN..=CREDENTIAL_MAX).contains(&fingerprint.len())
        && fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `POST /v1/agent/next` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNextRequest {
    /// Logins this agent can probe, by config name.
    pub logins: Vec<String>,
}

/// `POST /v1/agent/next` response: probe one login now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentJob {
    /// Id the result must name.
    pub probe_id: String,
    /// Login to probe.
    pub login: String,
}

/// What an agent's probe of a usage endpoint returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// HTTP 200 with a body the vendor's parser read.
    Ok,
    /// HTTP 401.
    #[serde(rename = "http_401")]
    Http401,
    /// HTTP 429.
    #[serde(rename = "http_429")]
    Http429,
    /// Any other status, an unreadable body or a transport failure.
    Error,
}

/// `POST /v1/agent/result` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentResultRequest {
    /// The job's `probe_id`.
    pub probe_id: String,
    /// Outcome class.
    pub outcome: ProbeOutcome,
    /// Windows of an `ok` outcome.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<WindowReport>,
    /// The vendor's `Retry-After` in seconds, for `http_429`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u64>,
}

/// Health of a login as the balancer sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginStatus {
    /// Usable.
    Ok,
    /// Short back-off after a 429.
    RateLimited,
    /// A window is used up until its reset.
    Exhausted,
    /// Got 401 once; usable again after the CLI refreshes its token.
    AuthStale,
    /// Repeated 401; needs a manual re-login.
    AuthDead,
    /// No data yet.
    Unknown,
}

/// `POST /v1/report` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportResponse {
    /// The report was applied.
    pub accepted: bool,
    /// Login status after applying the report.
    pub login_status: LoginStatus,
}

/// Where a window value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Reported by a client from the vendor's own stream.
    Stream,
    /// Fetched by the agent's lazy probe.
    Probe,
    /// Inferred: the window passed its reset time.
    Assumed,
}

/// A window in the state snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowState {
    /// Window name.
    pub name: String,
    /// Used fraction.
    pub used: f64,
    /// Fraction held by live leases.
    pub reserved: f64,
    /// Reset time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<u64>,
    /// When the value was observed.
    pub observed_at: u64,
    /// Origin of the value.
    pub source: Source,
    /// Older than its TTL.
    pub stale: bool,
}

/// A login in the state snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginState {
    /// Login id from the config.
    pub login: String,
    /// Vendor id.
    pub vendor: String,
    /// Current status.
    pub status: LoginStatus,
    /// Dead/backed-off until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_until: Option<u64>,
    /// Known windows.
    pub windows: Vec<WindowState>,
}

/// A live lease in the state snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaseState {
    /// Lease id.
    pub lease_id: String,
    /// Login the lease holds.
    pub login: String,
    /// Model of the lease.
    pub model: String,
    /// Client that took the lease.
    pub client: String,
    /// Caller's run id from the pick request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// End client the pick request named in `on_behalf_of`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// When the lease expires unless released first.
    pub expires_at: u64,
}

/// The fraction a lease reserves in one window of its login.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowCost {
    /// Window name.
    pub name: String,
    /// Reserved fraction.
    pub cost: f64,
}

/// `GET /v1/why/{lease_id}` response: a live lease, why it was granted and its login now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhyResponse {
    /// Lease id.
    pub lease_id: String,
    /// Login the lease holds.
    pub login: String,
    /// Model of the lease.
    pub model: String,
    /// Client that took the lease.
    pub client: String,
    /// Caller's run id from the pick request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// End client the pick request named in `on_behalf_of`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// When the lease expires unless released first.
    pub expires_at: u64,
    /// Reservation per window of the login's vendor, in declaration order.
    pub cost: Vec<WindowCost>,
    /// The pick `reason` the lease was granted with; absent when the journal did not keep it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The lease's login as `GET /v1/state` shows it.
    pub login_state: LoginState,
}

/// `GET /v1/state` response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateResponse {
    /// API version.
    pub api_version: String,
    /// Server time of the snapshot.
    pub now: u64,
    /// Configured logins.
    pub logins: Vec<LoginState>,
    /// Live leases.
    pub leases: Vec<LeaseState>,
}

/// Liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    /// Serving.
    Ok,
}

/// `GET /v1/health` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Liveness.
    pub status: HealthStatus,
    /// API version.
    pub api_version: String,
    /// Server build version.
    pub version: String,
    /// Seconds since the daemon started.
    pub uptime_s: u64,
}

/// Which file of `qbd` holds the roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolesSource {
    /// The `roles_file` the config names.
    RolesFile,
    /// The config file itself, as `[[roles]]` tables.
    Config,
}

/// `GET /v1/admin/roles` response: the roles of `qbd`'s files on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminRoles {
    /// Which file holds the roles.
    pub source: RolesSource,
    /// Path of that file.
    pub file: String,
    /// Hex SHA-256 of that file's bytes; also the answer's `ETag`.
    pub sha256: String,
    /// The roles in file order.
    pub roles: Vec<RoleConfig>,
}

/// `GET /v1/roles` response: the roles `qbd` runs since its start or last reload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolesResponse {
    /// The roles in file order.
    pub roles: Vec<RoleConfig>,
}

/// A role as its config file declares it; `PUT /v1/admin/roles` takes the same shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleConfig {
    /// Role name.
    pub name: String,
    /// Ladder steps in file order.
    pub ladder: Vec<LadderStep>,
    /// Reserves in file order.
    #[serde(default)]
    pub reserves: Vec<RoleReserve>,
}

/// One ladder step of a role.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LadderStep {
    /// Difficulty the step serves.
    pub difficulty: u8,
    /// Candidates in preference order.
    pub candidates: Vec<LadderCandidate>,
}

/// A vendor/model/effort combination of a ladder step.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LadderCandidate {
    /// Declared vendor.
    pub vendor: String,
    /// Model name.
    pub model: String,
    /// Reasoning effort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// Tier; lower tiers are preferred.
    pub tier: u8,
    /// Fraction of the vendor's shortest window one minute of work uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_per_minute: Option<f64>,
}

/// Fraction of a window a role keeps free at a difficulty.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReserve {
    /// Difficulty of a ladder step of the role.
    pub difficulty: u8,
    /// Window name.
    pub window: String,
    /// Reserved fraction, `0.0..=1.0`.
    pub fraction: f64,
}

/// `PUT /v1/admin/roles` request: the roles that replace the `roles_file`, in the `GET` shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminRolesPut {
    /// The roles in file order.
    pub roles: Vec<RoleConfig>,
}

/// `PUT /v1/admin/roles` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminRolesWritten {
    /// Hex SHA-256 of the roles file written and now running, or of the file left as it was.
    pub sha256: String,
    /// Path of the copy of the file it replaced; absent when the roles change no byte and
    /// nothing was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<String>,
}

/// `POST /v1/admin/reload` response: the counts of the config now running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminReloadAnswer {
    /// Roles of the new config.
    pub roles: usize,
    /// Clients of the new config.
    pub clients: usize,
}

/// `POST /v1/admin/logins/reset` request: the logins whose `auth_stale` or `auth_dead` mark
/// to clear, or `all` of them.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminLoginsReset {
    /// Declared logins, by config name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logins: Vec<String>,
    /// Every declared login instead.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
}

impl AdminLoginsReset {
    /// Checks that exactly one of `logins` and `all` is given.
    ///
    /// # Errors
    /// Both or neither are given.
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.logins.is_empty(), self.all) {
            (false, false) | (true, true) => Ok(()),
            (true, false) => Err("`logins` or `all` is required"),
            (false, true) => Err("`logins` and `all` are exclusive"),
        }
    }
}

/// `POST /v1/admin/logins/reset` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLoginsResetAnswer {
    /// One entry per login asked for, in declaration order with `all`, else in request order.
    pub logins: Vec<LoginReset>,
}

/// What a reset did to one login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginReset {
    /// Login name.
    pub login: String,
    /// The login had an `auth_stale` or `auth_dead` mark, now cleared.
    pub cleared: bool,
    /// Login status after the reset.
    pub status: LoginStatus,
}

/// Machine-readable error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed HTTP or JSON, or a violated request invariant.
    BadRequest,
    /// Authentication required or failed.
    Unauthorized,
    /// Authenticated but not allowed.
    Forbidden,
    /// Unknown path, lease or login.
    NotFound,
    /// Known path, wrong method.
    MethodNotAllowed,
    /// `POST` without `Content-Length`.
    LengthRequired,
    /// Body or headers over the limit.
    PayloadTooLarge,
    /// `If-Match` is not the current hash of the file it guards.
    PreconditionFailed,
    /// An edit without the `If-Match` it needs.
    PreconditionRequired,
    /// Too many requests from this client.
    TooManyRequests,
    /// Bug, or a file the daemon cannot read or write.
    Internal,
}

impl ErrorCode {
    /// HTTP status for the error class.
    pub fn http_status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::MethodNotAllowed => 405,
            Self::LengthRequired => 411,
            Self::PayloadTooLarge => 413,
            Self::PreconditionFailed => 412,
            Self::PreconditionRequired => 428,
            Self::TooManyRequests => 429,
            Self::Internal => 500,
        }
    }
}

/// Body of every non-2xx response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Error class.
    pub error: ErrorCode,
    /// Human-readable detail.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> PickRequest {
        PickRequest {
            role: "worker".into(),
            difficulty: Some(2),
            pin: None,
            resume_of: None,
            avoid_vendor: None,
            need: Vec::new(),
            expected_minutes: None,
            run_id: None,
            on_behalf_of: None,
            logins: None,
        }
    }

    #[test]
    fn validate_accepts_difficulty_or_pin() {
        assert_eq!(req().validate(), Ok(()));
        let pinned = PickRequest {
            difficulty: None,
            pin: Some(Pin {
                vendor: "v".into(),
                model: "m".into(),
                effort: None,
                login: None,
            }),
            ..req()
        };
        assert_eq!(pinned.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_bad_targets_and_roles() {
        let none = PickRequest {
            difficulty: None,
            ..req()
        };
        assert_eq!(none.validate(), Err(PickRequestError::NoTarget));
        let both = PickRequest {
            pin: Some(Pin {
                vendor: "v".into(),
                model: "m".into(),
                effort: None,
                login: None,
            }),
            ..req()
        };
        assert_eq!(both.validate(), Err(PickRequestError::AmbiguousTarget));
        let blank = PickRequest {
            role: "  ".into(),
            ..req()
        };
        assert_eq!(blank.validate(), Err(PickRequestError::EmptyRole));
    }

    #[test]
    fn validate_bounds_on_behalf_of() {
        let with = |name: &str| PickRequest {
            on_behalf_of: Some(name.into()),
            ..req()
        };
        assert_eq!(with("client-1").validate(), Ok(()));
        assert_eq!(with(&"a".repeat(128)).validate(), Ok(()));
        assert_eq!(with("").validate(), Err(PickRequestError::BadOnBehalfOf));
        assert_eq!(
            with(&"a".repeat(129)).validate(),
            Err(PickRequestError::BadOnBehalfOf)
        );
    }

    #[test]
    fn validate_bounds_logins() {
        let with = |names: Vec<String>| PickRequest {
            logins: Some(names),
            ..req()
        };
        let names = |n: usize| (0..n).map(|i| format!("login-{i}")).collect::<Vec<_>>();
        assert_eq!(with(names(1)).validate(), Ok(()));
        assert_eq!(with(names(32)).validate(), Ok(()));
        for (case, logins) in [
            ("empty", names(0)),
            ("too many", names(33)),
            ("repeated", vec!["login-1".into(), "login-1".into()]),
        ] {
            assert_eq!(
                with(logins).validate(),
                Err(PickRequestError::BadLogins),
                "{case}"
            );
        }
    }

    #[test]
    fn outcome_names_are_stable() {
        let names: Vec<String> = [
            Outcome::Ok,
            Outcome::UsageLimit,
            Outcome::Rejected,
            Outcome::Http401,
            Outcome::Http429,
            Outcome::ModelUnavailable,
            Outcome::Error,
        ]
        .iter()
        .map(|o| serde_json::to_string(o).expect("encode"))
        .collect();
        assert_eq!(
            names,
            [
                r#""ok""#,
                r#""usage_limit""#,
                r#""rejected""#,
                r#""http_401""#,
                r#""http_429""#,
                r#""model_unavailable""#,
                r#""error""#
            ]
        );
    }

    #[test]
    fn error_codes_map_to_http() {
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        assert_eq!(ErrorCode::PayloadTooLarge.http_status(), 413);
    }
}
