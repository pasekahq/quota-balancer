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
    Attempt, Block, CacheMode, CancelAnswer, CancelRequest, Effort, ErrorClass, GatewayError,
    MediaType, Message, Object, Role, RouteInfo, RouteState, RouteStatus, RoutesAnswer, StopReason,
    StreamEvent, Thinking, Tool, ToolCall, TurnRequest, TurnRequestError, Usage,
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
    /// `GET`, followed by a lease id: why a live lease was granted.
    pub const WHY: &str = "/v1/why/";
    /// `POST`: an agent waits for a probe job.
    pub const AGENT_NEXT: &str = "/v1/agent/next";
    /// `POST`: an agent answers a probe job.
    pub const AGENT_RESULT: &str = "/v1/agent/result";
    /// Gateway, `POST`: run one model turn and stream its events as NDJSON.
    pub const MODEL_TURN: &str = "/v1/model/turn";
    /// Gateway, `GET`: route aliases and where a turn would run now.
    pub const MODEL_ROUTES: &str = "/v1/model/routes";
    /// Gateway, `POST`: stop a running turn of the caller.
    pub const MODEL_CANCEL: &str = "/v1/model/cancel";
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
    /// Required capabilities; a candidate must have all of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub need: Vec<String>,
    /// Expected duration of the task, used for the cost estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_minutes: Option<u32>,
    /// Caller's id of the run, echoed into the lease and the journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

/// Why a [`PickRequest`] is malformed beyond what JSON decoding catches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickRequestError {
    /// Neither `difficulty` nor `pin` was given.
    NoTarget,
    /// Both `difficulty` and `pin` were given.
    AmbiguousTarget,
    /// `role` is empty.
    EmptyRole,
}

impl PickRequestError {
    /// Human-readable message for an error body.
    pub fn message(self) -> &'static str {
        match self {
            Self::NoTarget => "one of `difficulty` or `pin` is required",
            Self::AmbiguousTarget => "`difficulty` and `pin` are mutually exclusive",
            Self::EmptyRole => "`role` must not be empty",
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
    /// Too many requests from this client.
    TooManyRequests,
    /// Bug.
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
