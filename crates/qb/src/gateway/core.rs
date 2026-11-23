//! The gateway core every front shares: admit a turn, then per attempt ask qbd for a login of
//! the route, load its credential, run the vendor adapter and report the outcome to qbd. Until
//! the client has seen an event a failure moves on within the turn (ADR 0001, "Rotation
//! boundary"), on a chain route also to its next step; after that, or when qbd has nothing
//! left, the turn ends with `error`.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    ApiFamily, Attempt, AuditAction, AuditEntry, Block, ClientRotateAnswer, ConfigRoutes,
    ConfigRoutesPut, ConfigRoutesWritten, Decision, ErrorClass, GatewayError, LadderAnswer,
    LadderCandidateState, LadderStepState, LoginKeyAnswer, LoginOauthSigned, LoginOauthStarted,
    LoginSpend, LoginStatus, OauthPaste, Outcome, PickRequest, PickResponse, ReloadAnswer,
    ReportRequest, RolesResponse, RouteInfo, RouteState, RouteStatus, RoutesAnswer, SpendAnswer,
    StopReason, StreamEvent, TurnRequest, Usage, UsageLine, WindowReport, gateway::MAX_NAME,
    gateway::MAX_USAGE_TOOLS, paths, validate_login_key,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use super::Refusal;
use super::batches::Store;
use super::config::{
    Api, ClientEffort, ClientToken, CredentialKind, GatewayConfig, GatewayLogin, Route,
};
use super::creds::{self, CredentialStore, Kind, Refresher, Written};
use super::front::Caller;
use super::signin::SignIn;
use super::spend::{self, Ledger};
use super::tokens::{self, ClientTokens};
use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Flow, Picked, Upstream,
};
use super::{audit, config_edit, secret_body, usage};
use crate::config::{BearerHash, Error};
use crate::rewrite::{self, Unwritten, write_atomic};
use crate::sandbox::{file_dir, gateway_files};
use crate::server::unix_now;
use crate::{client, http, log, sha256};

/// Seconds a started sign-in takes its code.
pub const SIGN_IN_EXPIRY_S: u64 = 600;

/// How long `cancel` waits for the cancelled turn to end.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// Vendor adapters by the API family they serve.
pub type Upstreams = Vec<(Api, Box<dyn Upstream>)>;

/// A config a reload may take and the hashes of its client token files.
type Admissible = (GatewayConfig, Vec<(String, BearerHash)>);

/// What `cancel` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancel {
    /// The turn was running and is stopped.
    Cancelled,
    /// No turn with this `request_id` is running.
    Unknown,
    /// Another caller started the turn.
    Forbidden,
}

struct Entry {
    /// Unique per admission, so a finished turn never removes a later one with its `request_id`.
    id: u64,
    client: String,
    request_id: String,
    cancel: CancelToken,
}

struct Running {
    turns: Mutex<Vec<Entry>>,
    admitted: AtomicU64,
    ended: Condvar,
}

/// A sign-in of `POST /v1/model/logins/{name}/oauth/start` waiting for its code.
struct Pending {
    signin: SignIn,
    expires_at: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A turn that passed admission: it counts against `max_turns` and can be cancelled until it is
/// dropped. It runs on the config snapshot current at its admission.
pub struct Admitted {
    id: u64,
    client: String,
    request_id: String,
    config: Arc<GatewayConfig>,
    route: Route,
    cancel: CancelToken,
    running: Arc<Running>,
}

impl Admitted {
    /// The token `POST /v1/model/cancel` sets for this turn.
    pub fn cancel_token(&self) -> &CancelToken {
        &self.cancel
    }

    fn log(&self, what: &str) {
        log::info(&format!(
            "gateway: turn {} of {}: {what}",
            self.request_id, self.client
        ));
    }
}

impl Admitted {
    /// Takes the turn out of the registry: it no longer counts against `max_turns` and a cancel
    /// answers `Unknown`. Called before the terminal event, whose write may block.
    fn finish(&self) {
        let mut turns = lock(&self.running.turns);
        turns.retain(|e| e.id != self.id);
        drop(turns);
        self.running.ended.notify_all();
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The gateway's shared state. One value serves every connection thread.
pub struct Gateway {
    /// The snapshot later admissions take; a reload swaps it.
    config: Mutex<Arc<GatewayConfig>>,
    /// The config of the start: the restart-only fields and the qbd connection.
    startup: Arc<GatewayConfig>,
    /// Held for a whole reload, so the last file read is the one that serves.
    reloading: Mutex<()>,
    /// Shared by every snapshot, so a file's write lock outlives a reload.
    store: CredentialStore,
    upstreams: Upstreams,
    qbd_bearer: Option<Zeroizing<String>>,
    running: Arc<Running>,
    /// The counts of the startup `spend_file`; every snapshot with a `spend_cap` has that file.
    spend: Option<Mutex<Ledger>>,
    /// The directories of the gateway's own files that the sandbox opened; without a sandbox,
    /// those of `startup`.
    opened: Vec<PathBuf>,
    /// The hashes of the `token_file` clients; a reload or a rotation swaps them.
    tokens: Mutex<Arc<ClientTokens>>,
    /// The ledger of the startup `[usage]`.
    usage: Option<usage::Ledger>,
    /// The batch store of the startup `[batches]`.
    batches: Option<Store>,
    /// At most one per login; its verifier and state never leave this memory.
    sign_ins: Mutex<Vec<Pending>>,
    /// Seconds a started sign-in takes its code.
    sign_in_expiry: u64,
    /// The credential fingerprint of each login that qbd last took from an announcement.
    announced: Mutex<HashMap<String, String>>,
}

/// Logs once per run that `model` has no price, so capped logins count nothing for it.
fn warn_unpriced(ledger: &mut Ledger, model: &str) {
    if ledger.first_unpriced(model) {
        log::warn(&format!(
            "gateway: model `{model}` has no price and its vendor reports no cost; \
             turns and batches on capped logins count nothing for it"
        ));
    }
}

fn bad_request(message: impl Into<String>) -> GatewayError {
    GatewayError::new(ErrorClass::BadRequest, false, message)
}

fn retryable(class: ErrorClass) -> bool {
    matches!(class, ErrorClass::Overloaded | ErrorClass::Unavailable)
}

/// The qbd outcome and the client's error class of a failure of `kind`.
fn classify(kind: FailureKind) -> (Outcome, ErrorClass) {
    match kind {
        FailureKind::UsageLimit { .. } => (Outcome::UsageLimit, ErrorClass::QuotaExhausted),
        FailureKind::Auth => (Outcome::Http401, ErrorClass::Auth),
        FailureKind::RateLimited { .. } => (Outcome::Http429, ErrorClass::Overloaded),
        FailureKind::ModelUnavailable => (Outcome::ModelUnavailable, ErrorClass::Unavailable),
        FailureKind::Overloaded { .. } => (Outcome::Error, ErrorClass::Overloaded),
        FailureKind::Unavailable => (Outcome::Error, ErrorClass::Unavailable),
        FailureKind::BadRequest => (Outcome::Error, ErrorClass::BadRequest),
        FailureKind::ContextTooLong => (Outcome::Error, ErrorClass::ContextTooLong),
        FailureKind::Cancelled => (Outcome::Error, ErrorClass::Cancelled),
    }
}

/// The qbd outcome of an adapter or vendor `failure` and the error the client gets: its class,
/// retryability, `resets_at` of a usage limit, `retry_after` of a 429 or overload, and its
/// message, which [`redact`] cleaned at the seam.
pub(super) fn refusal(failure: &Failure) -> (Outcome, GatewayError) {
    let (outcome, class) = classify(failure.kind);
    let mut error = GatewayError::new(class, retryable(class), failure.message.clone());
    match failure.kind {
        FailureKind::UsageLimit { resets_at } => error.resets_at = resets_at,
        FailureKind::RateLimited { retry_after } | FailureKind::Overloaded { retry_after } => {
            error.retry_after = retry_after;
        }
        _ => {}
    }
    (outcome, error)
}

/// A failure that qbd marks on the login only, so another login may succeed.
fn login_scoped(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::UsageLimit { .. }
            | FailureKind::Auth
            | FailureKind::RateLimited { .. }
            | FailureKind::ModelUnavailable
    )
}

/// The message of a body of one string `field` that does not decode; serde's own may quote the
/// body.
fn body_error(e: &serde_json::Error, field: &str) -> String {
    if e.is_data() {
        format!("the body must be one object with the string `{field}` only")
    } else {
        format!(
            "the body is not valid JSON (line {}, column {})",
            e.line(),
            e.column()
        )
    }
}

/// The audit action of a config edit of body `put`: `config_spend_caps` when it carries only
/// `spend_caps`, `config_routes` otherwise, an undecodable body included.
pub(crate) fn edit_action(put: Option<&ConfigRoutesPut>) -> AuditAction {
    match put {
        Some(ConfigRoutesPut {
            routes: None,
            spend_caps: Some(_),
        }) => AuditAction::ConfigSpendCaps,
        _ => AuditAction::ConfigRoutes,
    }
}

/// `req` without `thinking` blocks of another vendor than `vendor`; borrowed when it has none.
fn own_thinking<'a>(req: &'a TurnRequest, vendor: &str) -> Cow<'a, TurnRequest> {
    let foreign = |b: &Block| matches!(b, Block::Thinking { vendor: v, .. } if v != vendor);
    if !req.messages.iter().flat_map(|m| &m.content).any(foreign) {
        return Cow::Borrowed(req);
    }
    let mut owned = req.clone();
    for m in &mut owned.messages {
        m.content.retain(|b| !foreign(b));
    }
    owned.messages.retain(|m| !m.content.is_empty());
    Cow::Owned(owned)
}

/// `req` without the client's effort on a route whose turns send the pick's only.
fn route_effort<'a>(req: &'a TurnRequest, route: &Route) -> Cow<'a, TurnRequest> {
    if route.client_effort != Some(ClientEffort::Ignore) || req.effort.is_none() {
        return Cow::Borrowed(req);
    }
    let mut owned = req.clone();
    owned.effort = None;
    Cow::Owned(owned)
}

fn cancelled() -> GatewayError {
    GatewayError::new(ErrorClass::Cancelled, false, "cancelled by the client")
}

/// Passes an adapter's events on: the held `route` event goes first, terminal and `route`
/// events of the adapter are dropped, `thinking` is stamped with the picked vendor.
struct Relay<'e> {
    route: Option<StreamEvent>,
    emitted: bool,
    /// The last `usage` of the attempt, whether or not it reached the client.
    usage: Option<Usage>,
    /// Names of the attempt's tool calls, each cut to [`MAX_NAME`] bytes.
    tools: BTreeSet<String>,
    /// When the attempt began, before its credential was loaded.
    started: Instant,
    /// The client is gone: nothing more reaches it.
    gone: bool,
    /// The fingerprint of the credential file read for the attempt.
    fingerprint: String,
    emit: &'e mut dyn FnMut(StreamEvent) -> Flow,
}

impl Relay<'_> {
    fn send(&mut self, event: StreamEvent) -> Flow {
        if !self.gone && (self.emit)(event) == Flow::Stop {
            self.gone = true;
        }
        if self.gone {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn pass(&mut self, mut event: StreamEvent, vendor: &str, cancel: &CancelToken) -> Flow {
        match &event {
            StreamEvent::Usage { usage } => self.usage = Some(*usage),
            StreamEvent::ToolCall { tool_call } => {
                let mut end = tool_call.name.len().min(MAX_NAME);
                while !tool_call.name.is_char_boundary(end) {
                    end -= 1;
                }
                self.tools.insert(tool_call.name[..end].to_owned());
            }
            _ => {}
        }
        if cancel.is_cancelled() {
            return Flow::Stop;
        }
        match &mut event {
            StreamEvent::Route { .. } | StreamEvent::Stop { .. } | StreamEvent::Error { .. } => {
                return if self.gone {
                    Flow::Stop
                } else {
                    Flow::Continue
                };
            }
            StreamEvent::Thinking { thinking } => vendor.clone_into(&mut thinking.vendor),
            _ => {}
        }
        if let Some(route) = self.route.take() {
            if self.send(route) == Flow::Stop {
                return Flow::Stop;
            }
        }
        self.emitted = true;
        self.send(event)
    }
}

/// How an adapter attempt ended, as its usage line says.
#[derive(Clone, Copy)]
struct Ended {
    /// What the gateway reported to qbd.
    outcome: Outcome,
    /// The vendor's stop reason, or the failure class the turn saw.
    end: Result<StopReason, ErrorClass>,
    /// The cost the vendor reported.
    cost: Option<f64>,
}

/// What a turn carries from one attempt to the next.
struct Progress {
    tried: Vec<Attempt>,
    /// Logins that failed in this turn; they are not tried again.
    failed: Vec<String>,
    /// Vendor to avoid after a vendor-scoped failure; set at most once per turn.
    avoid: Option<String>,
    /// Send `resume_of`; cleared by the first `wait` it causes.
    resume: bool,
    /// Index of the chain step the next pick pins.
    step: usize,
    /// Every chain step that ended so far was spent or waiting.
    spent: bool,
    /// Nearest reset of the chain steps that ended.
    resets_at: Option<u64>,
    /// Unix time at which the soonest `retry-after` of a login's 429 in this turn runs out; qbd
    /// hears only the outcome, so the turn's final error carries it.
    vendor_wait: Option<u64>,
}

/// A `run` answer of qbd with the login's credential entry and adapter.
struct Ready<'g> {
    pick: PickResponse,
    lease: String,
    login: String,
    attempt: Attempt,
    entry: &'g GatewayLogin,
    upstream: &'g dyn Upstream,
}

/// What a turn does after an attempt.
enum Next {
    /// Pick again.
    Retry,
    /// The turn is over; the text goes to the log.
    Done(String),
}

/// What `GET /v1/model/ladder` reads: the step of a ladder route, or the steps of a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderQuery {
    /// `route=<alias>`.
    Route(String),
    /// `role=<role>`.
    Role(String),
}

impl LadderQuery {
    /// The query string `query` of a `GET /v1/model/ladder`.
    ///
    /// # Errors
    /// A message for an unknown or repeated parameter, or not exactly one of `route` and `role`.
    pub fn parse(query: Option<&str>) -> Result<Self, String> {
        match http::query_params(query, ["route", "role"])? {
            [Some(route), None] => Ok(Self::Route(route.to_owned())),
            [None, Some(role)] => Ok(Self::Role(role.to_owned())),
            _ => Err("give exactly one of `route` and `role`".to_owned()),
        }
    }
}

/// The parts of qbd's `GET /v1/state` the routes and ladder answers read; other fields are
/// skipped.
#[derive(Deserialize)]
struct State {
    logins: Vec<StateLogin>,
}

#[derive(Deserialize)]
struct StateLogin {
    login: String,
    vendor: String,
    status: LoginStatus,
    dead_until: Option<u64>,
    windows: Vec<StateWindow>,
}

#[derive(Deserialize)]
struct StateWindow {
    used: f64,
    resets_at: Option<u64>,
}

impl Gateway {
    /// A gateway for `config` with vendor adapters `upstreams`, OAuth refreshes through
    /// `refresher` and `qbd_bearer` for qbd, if qbd knows the gateway by token.
    ///
    /// # Errors
    /// The config's `spend_file` or `batches.file` exists but cannot be read as one, a
    /// `token_file` cannot be read as a token, the `grace_file` exists but cannot be read as one,
    /// or the `audit_file` exists with a mode wider than 0600 that cannot be narrowed.
    pub fn new(
        config: GatewayConfig,
        upstreams: Upstreams,
        refresher: Box<dyn Refresher>,
        qbd_bearer: Option<Zeroizing<String>>,
    ) -> Result<Self, String> {
        let spend = match &config.spend_file {
            Some(f) => Some(Mutex::new(Ledger::open(f, unix_now())?)),
            None => None,
        };
        if let Some(file) = &config.audit_file {
            audit::narrow(file)?;
        }
        let usage = config.usage.clone().map(usage::Ledger::new);
        let batches = match &config.batches {
            Some(b) => Some(Store::open(&b.file)?),
            None => None,
        };
        let tokens = ClientTokens::load(&config, unix_now())?;
        let startup = Arc::new(sorted(config));
        let mut opened: Vec<PathBuf> = Vec::new();
        for dir in gateway_files(&startup).filter_map(|f| file_dir(f).ok()) {
            if !opened.contains(&dir) {
                opened.push(dir);
            }
        }
        Ok(Self {
            config: Mutex::new(Arc::clone(&startup)),
            startup,
            reloading: Mutex::new(()),
            store: CredentialStore::new(refresher),
            upstreams,
            qbd_bearer,
            running: Arc::new(Running {
                turns: Mutex::new(Vec::new()),
                admitted: AtomicU64::new(0),
                ended: Condvar::new(),
            }),
            spend,
            opened,
            usage,
            batches,
            tokens: Mutex::new(Arc::new(tokens)),
            sign_ins: Mutex::new(Vec::new()),
            sign_in_expiry: SIGN_IN_EXPIRY_S,
            announced: Mutex::new(HashMap::new()),
        })
    }

    /// The gateway under a sandbox that opened the directories `opened`: a reload may add
    /// credential and token files in these only.
    #[must_use]
    pub fn sandboxed(mut self, opened: Vec<PathBuf>) -> Self {
        self.opened = opened;
        self
    }

    /// The gateway with sign-ins that take their code for `seconds` instead of
    /// [`SIGN_IN_EXPIRY_S`].
    #[must_use]
    pub fn sign_in_expiry(mut self, seconds: u64) -> Self {
        self.sign_in_expiry = seconds;
        self
    }

    /// The current config snapshot.
    pub fn config(&self) -> Arc<GatewayConfig> {
        Arc::clone(&lock(&self.config))
    }

    /// The batch store; `None` without `[batches]`.
    pub(super) fn batches(&self) -> Option<&Store> {
        self.batches.as_ref()
    }

    /// The usage ledger; `None` without `[usage]`.
    pub(super) fn usage(&self) -> Option<&usage::Ledger> {
        self.usage.as_ref()
    }

    /// The credential of `login` from its file at `now`, refreshed when it is about to expire.
    pub(super) fn credential(&self, login: &GatewayLogin, now: u64) -> Result<Credential, String> {
        self.store.load(login, now, false).map_err(|e| e.message)
    }

    /// The current hashes of the `token_file` clients.
    pub fn client_tokens(&self) -> Arc<ClientTokens> {
        Arc::clone(&lock(&self.tokens))
    }

    /// Appends `entry` to the `audit_file`; without one it is dropped. Every admin action
    /// records through here.
    pub(crate) fn record(&self, entry: &AuditEntry) {
        if let Some(file) = &self.startup.audit_file {
            audit::append(file, entry);
        }
    }

    /// The audit entry of a reload by `actor` that turned the config of SHA-256 `before` into
    /// that of `after`.
    fn reload_entry(&self, actor: &str, before: [u8; 32], after: [u8; 32]) -> AuditEntry {
        let object = Some(self.startup.file.display().to_string());
        let mut entry = audit::entry(actor, AuditAction::Reload, object);
        entry.config_sha256_before = Some(sha256::hex(before));
        entry.config_sha256_after = Some(sha256::hex(after));
        entry
    }

    /// Records a reload by `actor` refused for `reason` before the file was read.
    pub(crate) fn refuse_reload(&self, actor: &str, reason: &str) {
        let sha256 = self.config().sha256;
        let entry = self.reload_entry(actor, sha256, sha256);
        self.record(&audit::refused(entry, reason));
    }

    /// Reads the config file and its `token_file`s again for `actor`. A config that parses and
    /// validates as at startup, keeps every restart-only field and whose token files read
    /// becomes the snapshot of later admissions; admitted turns keep theirs. Logs one line and
    /// records one audit entry either way, narrowing a wide `audit_file` first. Once the lock is
    /// released, a taken config's changed credential files are announced to qbd
    /// ([`Self::announce_credentials`]).
    ///
    /// # Errors
    /// The file is unreadable or invalid, changes a restart-only field, or a token file cannot
    /// be read as a token; the running config stays.
    pub fn reload(&self, actor: &str) -> Result<ReloadAnswer, String> {
        let answer = self.reload_locked(actor)?;
        self.announce_credentials();
        Ok(answer)
    }

    /// [`Self::reload`] under the reload lock, without the announcements that follow it.
    fn reload_locked(&self, actor: &str) -> Result<ReloadAnswer, String> {
        let _one = lock(&self.reloading);
        if let Some(file) = &self.startup.audit_file {
            if let Err(e) = audit::narrow(file) {
                log::error(&format!("gateway: {e}"));
            }
        }
        let before = self.config().sha256;
        let (config, current) = match self.admissible(super::config::load(&self.startup.file)) {
            Ok(loaded) => loaded,
            Err(e) => {
                log::warn(&format!("gateway: reload refused: {e}"));
                let entry = self.reload_entry(actor, before, before);
                self.record(&audit::refused(entry, e.as_str()));
                return Err(e);
            }
        };
        let after = config.sha256;
        let answer = self.install(config, current);
        self.record(&self.reload_entry(actor, before, after));
        Ok(answer)
    }

    /// The config `loaded` and its client token hashes when a reload may take it: it parsed and
    /// validated, keeps every restart-only field, and its token files read.
    fn admissible(&self, loaded: Result<GatewayConfig, Error>) -> Result<Admissible, String> {
        loaded
            .map_err(|e| e.to_string())
            .and_then(|c| restart_only(&self.startup, &c, &self.opened).map_or(Ok(c), Err))
            .and_then(|c| tokens::read(&c).map(|t| (c, t)).map_err(|e| e.to_string()))
    }

    /// Makes the [`Self::admissible`] `config` with the token hashes `current` the snapshot of
    /// later admissions and logs it. Call it under `reloading`.
    fn install(&self, config: GatewayConfig, current: Vec<(String, BearerHash)>) -> ReloadAnswer {
        let config = Arc::new(sorted(config));
        let answer = ReloadAnswer {
            routes: config.routes.len(),
            logins: config.logins.len(),
        };
        // The hashes go first: a connection that takes the old config meanwhile finds no hash
        // of a client the new one adds.
        let tokens = self.client_tokens().with_current(current);
        *lock(&self.tokens) = Arc::new(tokens);
        let old = std::mem::replace(&mut *lock(&self.config), Arc::clone(&config));
        for login in &config.logins {
            let before = old.login(&login.name).and_then(|l| l.spend_cap);
            if login.spend_cap != before {
                self.publish_spend(&login.name, login.spend_cap);
            }
        }
        log::info(&format!(
            "gateway: reloaded {}: {} routes, {} logins",
            self.startup.file.display(),
            answer.routes,
            answer.logins
        ));
        answer
    }

    /// The `[[routes]]` and the `api_key` logins' `spend_cap`s of the config file as it is on
    /// disk, which a reload has not necessarily taken, and the file's hash.
    ///
    /// # Errors
    /// The file cannot be read or does not validate.
    pub fn config_routes(&self) -> Result<ConfigRoutes, Error> {
        let config = super::config::load(&self.startup.file)?;
        Ok(ConfigRoutes {
            sha256: sha256::hex(config.sha256),
            routes: config_edit::routes_of(&config.routes),
            spend_caps: config_edit::spend_caps_of(&config.logins),
        })
    }

    /// Edits the config file as the [`qb_proto::ConfigRoutesPut`] `body` for `actor` asks, when
    /// `if_match` is the file's hash, and reloads it: its `[[routes]]` replaced, `spend_cap`s set
    /// or removed. The candidate file must pass a reload's checks; the old file is kept as a
    /// 0600 backup, the new one written atomically. A candidate equal to the file is neither
    /// written nor reloaded and has no backup. Serialised with reloads and rotations; logs
    /// one line and records one audit entry either way, `config_spend_caps` for a body of
    /// `spend_caps` only and `config_routes` otherwise.
    ///
    /// # Errors
    /// 428 without `if_match`, 412 when it is not the file's hash, 400 for a body or candidate
    /// that does not validate, 500 when a file cannot be read or written. The file, its backups
    /// and the running config stay as they were, except that a failed write which replaced the
    /// file keeps the backup.
    pub fn put_config(
        &self,
        actor: &str,
        if_match: Option<&str>,
        body: &[u8],
    ) -> Result<ConfigRoutesWritten, Refusal> {
        let _one = lock(&self.reloading);
        let put = serde_json::from_slice::<ConfigRoutesPut>(body).map_err(|e| e.to_string());
        let action = edit_action(put.as_ref().ok());
        let object = Some(self.startup.file.display().to_string());
        let mut entry = audit::entry(actor, action, object);
        match self.write_config(if_match, put, &mut entry) {
            Ok(written) => {
                let file = self.startup.file.display();
                log::info(&match &written.backup {
                    Some(backup) => {
                        format!("gateway: {file} edited, the old file kept as {backup}")
                    }
                    None => format!("gateway: {file} left as it was: the edit changes no byte"),
                });
                self.record(&entry);
                Ok(written)
            }
            Err(refusal) => {
                log::warn(&format!(
                    "gateway: config edit refused: {}",
                    refusal.message
                ));
                self.record(&audit::refused(entry, refusal.message.as_str()));
                Err(refusal)
            }
        }
    }

    /// The steps of [`Self::put_config`] under `reloading` for the decoded body `put`, filling
    /// the hashes and backup of `entry`.
    fn write_config(
        &self,
        if_match: Option<&str>,
        put: Result<ConfigRoutesPut, String>,
        entry: &mut AuditEntry,
    ) -> Result<ConfigRoutesWritten, Refusal> {
        let file = &self.startup.file;
        let failed = |message: String| Refusal::new(500, ErrorClass::Unavailable, message);
        let invalid = |message: String| Refusal::new(400, ErrorClass::BadRequest, message);
        let text = std::fs::read_to_string(file)
            .map_err(|e| failed(format!("cannot read {}: {e}", file.display())))?;
        let before = sha256::hex(sha256::digest(text.as_bytes()));
        entry.config_sha256_before = Some(before.clone());
        entry.config_sha256_after = Some(before.clone());
        let Some(tag) = if_match else {
            let message = "`If-Match` with the config file's sha256 is required".to_owned();
            return Err(Refusal::new(428, ErrorClass::BadRequest, message));
        };
        if tag.trim_matches('"') != before {
            let message = format!("`If-Match` is not the config file's sha256 {before}");
            return Err(Refusal::new(412, ErrorClass::BadRequest, message));
        }
        let put = put.map_err(invalid)?;
        let what = match (&put.routes, &put.spend_caps) {
            (None, None) => return Err(invalid("give `routes`, `spend_caps` or both".into())),
            (Some(_), _) => "routes",
            (None, Some(_)) => "spend_caps",
        };
        let refused = |e: String| invalid(format!("{what} refused: {e}"));
        let mut candidate = text.clone();
        if let Some(routes) = &put.routes {
            let items = config_edit::render(routes);
            candidate = config_edit::splice(file, &candidate, &items)
                .map_err(|e| refused(e.to_string()))?;
        }
        if let Some(caps) = &put.spend_caps {
            candidate = config_edit::set_spend_caps(file, &candidate, caps)
                .map_err(|e| refused(e.to_string()))?;
        }
        let (config, current) = self
            .admissible(super::config::parse(file, &candidate))
            .map_err(refused)?;
        if candidate == text {
            return Ok(ConfigRoutesWritten {
                sha256: before,
                backup: None,
            });
        }
        let backup = rewrite::rewrite(file, text.as_bytes(), candidate.as_bytes(), unix_now())
            .map_err(|f| {
                if let rewrite::Failed::Replaced { backup, .. } = &f {
                    if let Ok(now) = std::fs::read(file) {
                        entry.config_sha256_after = Some(sha256::hex(sha256::digest(&now)));
                    }
                    entry.backup = Some(backup.display().to_string());
                }
                failed(f.message(file))
            })?;
        let after = sha256::hex(config.sha256);
        self.install(config, current);
        let backup = backup.display().to_string();
        entry.config_sha256_after = Some(after.clone());
        entry.backup = Some(backup.clone());
        Ok(ConfigRoutesWritten {
            sha256: after,
            backup: Some(backup),
        })
    }

    /// Writes a fresh token to the `token_file` of the named loopback client `name` for `actor`;
    /// the next loopback connection accepts it, and the previous token stays accepted for
    /// `rotate_grace_s`. Logs one line and records one audit entry either way, never the token.
    ///
    /// # Errors
    /// As [`ClientTokens::rotate`]; the token file and the accepted tokens stay as they were.
    pub fn rotate_client(&self, actor: &str, name: &str) -> Result<ClientRotateAnswer, Refusal> {
        // A reload reads the token files; it must not read one a rotation is replacing.
        let _one = lock(&self.reloading);
        let config = self.config();
        let rotated = self
            .client_tokens()
            .rotate(config.fronts.as_ref(), name, unix_now());
        let mut entry = audit::entry(actor, AuditAction::ClientRotate, Some(name.to_owned()));
        match rotated {
            Ok((tokens, answer)) => {
                *lock(&self.tokens) = Arc::new(tokens);
                log::info(&format!(
                    "gateway: rotated the token of client `{name}`: sha256 {}…, the previous \
                     one accepted until {}",
                    answer.token_sha256_prefix, answer.grace_until
                ));
                entry.token_sha256_prefix = Some(answer.token_sha256_prefix.clone());
                self.record(&entry);
                Ok(answer)
            }
            Err(refusal) => {
                log::warn(&format!(
                    "gateway: rotation of client `{name}` refused: {}",
                    refusal.message
                ));
                self.record(&audit::refused(entry, refusal.message.as_str()));
                Err(refusal)
            }
        }
    }

    /// Writes the key of the [`qb_proto::LoginKey`] `body` to the credential file of the
    /// `api_key` login `name` for `actor`; the login's next attempt sends it. The old file is kept
    /// as a 0600 backup, the new one written atomically. Serialised with reloads, config edits
    /// and rotations; logs one line and records one audit entry either way, never the key.
    ///
    /// # Errors
    /// 404 an unknown login, 409 a login of another kind, 400 a body that does not decode or a
    /// key that does not validate, 500 a file that cannot be read or written; the old file stays
    /// in force, unless the write failed after replacing it, which keeps the backup.
    pub fn replace_login_key(
        &self,
        actor: &str,
        name: &str,
        body: &[u8],
    ) -> Result<LoginKeyAnswer, Refusal> {
        // A reload must not take a config whose credential file is half replaced.
        let one = lock(&self.reloading);
        let before = self.fingerprint_of(name);
        let mut entry = audit::entry(actor, AuditAction::LoginKey, Some(name.to_owned()));
        let result = match self.write_login_key(name, body, &mut entry) {
            Ok(answer) => {
                let backup = answer.backup.as_deref().unwrap_or("none");
                log::info(&format!(
                    "gateway: replaced the key of login `{name}`: sha256 {}…, backup {backup}",
                    answer.key_sha256_prefix
                ));
                entry.key_sha256_prefix = Some(answer.key_sha256_prefix.clone());
                entry.backup.clone_from(&answer.backup);
                self.record(&entry);
                Ok(answer)
            }
            Err(refusal) => {
                log::warn(&format!(
                    "gateway: key replacement of login `{name}` refused: {}",
                    refusal.message
                ));
                self.record(&audit::refused(entry, refusal.message.as_str()));
                Err(refusal)
            }
        };
        drop(one);
        if result.is_ok() {
            self.announce_replaced(name, before);
        }
        result
    }

    /// The fingerprint of the credential file of login `name` of the current config.
    fn fingerprint_of(&self, name: &str) -> Option<String> {
        let config = self.config();
        config
            .login(name)
            .map(|l| creds::fingerprint(&l.credentials))
    }

    /// Records the `action` on login `name` by `actor` refused for `reason` before its handler.
    pub(crate) fn refuse_login(&self, actor: &str, action: AuditAction, name: &str, reason: &str) {
        let entry = audit::entry(actor, action, Some(name.to_owned()));
        self.record(&audit::refused(entry, reason));
    }

    /// The steps of [`Self::replace_login_key`] under `reloading`; a failure that replaced the
    /// file sets the backup of `entry`.
    fn write_login_key(
        &self,
        name: &str,
        body: &[u8],
        entry: &mut AuditEntry,
    ) -> Result<LoginKeyAnswer, Refusal> {
        let config = self.config();
        let Some(login) = config.login(name) else {
            let message = format!("no login `{name}`");
            return Err(Refusal::new(404, ErrorClass::BadRequest, message));
        };
        if login.kind != CredentialKind::ApiKey {
            let message = format!("login `{name}` is `{}`, not `api_key`", login.kind.as_str());
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        }
        let invalid = |message: String| Refusal::new(400, ErrorClass::BadRequest, message);
        let key = secret_body::decode(body, "key").map_err(|e| invalid(body_error(&e, "key")))?;
        validate_login_key(&key).map_err(|e| invalid(e.to_owned()))?;
        let file = login.credentials.as_path();
        let bytes = Written {
            kind: Kind::ApiKey,
            access_token: None,
            refresh_token: None,
            account_id: None,
            expires_at: None,
            key: Some(&key),
        }
        .encode(file)
        .map_err(|e| Refusal::new(500, ErrorClass::Unavailable, e.message))?;
        let backup = replace_credential(file, &bytes, entry)?;
        Ok(LoginKeyAnswer {
            login: name.to_owned(),
            backup,
            key_sha256_prefix: tokens::prefix(&BearerHash(sha256::digest(key.as_bytes()))),
        })
    }

    /// Starts a PKCE sign-in of the OAuth login `name` for `actor`, replacing a pending one of the
    /// login: the authorize URL, what to paste back and when the sign-in expires. Logs one line
    /// and records one audit entry either way, never the URL.
    ///
    /// # Errors
    /// 404 an unknown login, 409 an `api_key` login, 500 the random source failed.
    pub fn start_sign_in(&self, actor: &str, name: &str) -> Result<LoginOauthStarted, Refusal> {
        let entry = audit::entry(actor, AuditAction::LoginOauthStart, Some(name.to_owned()));
        let started = self.oauth_login(name).and_then(|login| {
            SignIn::start(login, true).map_err(|e| Refusal::new(500, ErrorClass::Unavailable, e))
        });
        let signin = match started {
            Ok(signin) => signin,
            Err(refusal) => {
                log::warn(&format!(
                    "gateway: sign-in of login `{name}` refused: {}",
                    refusal.message
                ));
                self.record(&audit::refused(entry, refusal.message.as_str()));
                return Err(refusal);
            }
        };
        let now = unix_now();
        let expires_at = now.saturating_add(self.sign_in_expiry);
        let answer = LoginOauthStarted {
            login: name.to_owned(),
            url: signin.url(),
            paste: if signin.login().kind == CredentialKind::ChatgptOauth {
                OauthPaste::RedirectUrl
            } else {
                OauthPaste::CodeState
            },
            expires_at,
        };
        let mut pending = lock(&self.sign_ins);
        pending.retain(|p| p.expires_at > now && p.signin.login().name != name);
        pending.push(Pending { signin, expires_at });
        drop(pending);
        log::info(&format!(
            "gateway: sign-in of login `{name}` started, it takes a code until {expires_at}"
        ));
        self.record(&entry);
        Ok(answer)
    }

    /// Exchanges the code of the [`qb_proto::LoginOauthCode`] `body` for the pending sign-in of
    /// login `name` by `actor` and writes the new credential: the old file kept as a 0600 backup,
    /// the new one written atomically, read by the login's next attempt. A paste that holds no
    /// code or another state leaves the sign-in pending; any exchange consumes it. The file write
    /// is serialised with reloads, config edits, rotations and the login's refreshes. Logs one
    /// line and records one audit entry either way, never a value.
    ///
    /// # Errors
    /// 404 an unknown login, 409 an `api_key` login, no live sign-in or a login whose entry
    /// changed since the start, 400 a body that does not decode or a paste without a code or
    /// with another state, 502 a refused or failed exchange, 500 a file that cannot be read or
    /// written, as for [`Self::replace_login_key`].
    pub fn finish_sign_in(
        &self,
        actor: &str,
        name: &str,
        body: &[u8],
    ) -> Result<LoginOauthSigned, Refusal> {
        let mut entry = audit::entry(actor, AuditAction::LoginOauthCode, Some(name.to_owned()));
        let before = self.fingerprint_of(name);
        match self.sign_in(name, body, &mut entry) {
            Ok(answer) => {
                let backup = answer.backup.as_deref().unwrap_or("none");
                log::info(&format!(
                    "gateway: signed in login `{name}`, backup {backup}"
                ));
                entry.backup.clone_from(&answer.backup);
                self.record(&entry);
                self.announce_replaced(name, before);
                Ok(answer)
            }
            Err(refusal) => {
                log::warn(&format!(
                    "gateway: sign-in code of login `{name}` refused: {}",
                    refusal.message
                ));
                self.record(&audit::refused(entry, refusal.message.as_str()));
                Err(refusal)
            }
        }
    }

    /// The `oauth_anthropic` or `chatgpt_oauth` entry `name` of the running config.
    fn oauth_login(&self, name: &str) -> Result<GatewayLogin, Refusal> {
        let config = self.config();
        let Some(login) = config.login(name) else {
            let message = format!("no login `{name}`");
            return Err(Refusal::new(404, ErrorClass::BadRequest, message));
        };
        if login.kind == CredentialKind::ApiKey {
            let message = format!("login `{name}` is `api_key`, not an OAuth login");
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        }
        Ok(login.clone())
    }

    /// The steps of [`Self::finish_sign_in`]; a failure that replaced the file sets the backup
    /// of `entry`.
    fn sign_in(
        &self,
        name: &str,
        body: &[u8],
        entry: &mut AuditEntry,
    ) -> Result<LoginOauthSigned, Refusal> {
        self.oauth_login(name)?;
        let invalid = |message: String| Refusal::new(400, ErrorClass::BadRequest, message);
        let pasted =
            secret_body::decode(body, "pasted").map_err(|e| invalid(body_error(&e, "pasted")))?;
        let now = unix_now();
        let mut pending = lock(&self.sign_ins);
        let Some(at) = pending.iter().position(|p| p.signin.login().name == name) else {
            let message = format!(
                "no sign-in of login `{name}` is pending; start one with POST {}/{name}/oauth/start",
                paths::MODEL_LOGINS
            );
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        };
        if pending[at].expires_at <= now {
            let expired = pending.swap_remove(at).expires_at;
            let message =
                format!("the sign-in of login `{name}` expired at {expired}; start a new one");
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        }
        let code = pending[at].signin.code(&pasted).map_err(invalid)?;
        let signin = pending.swap_remove(at).signin;
        drop(pending);
        // The exchange runs outside the reload lock, so a SIGHUP reload never waits on a vendor.
        let bytes = signin.credential(&code).map_err(|e| {
            let class = if e.refused {
                ErrorClass::Auth
            } else {
                ErrorClass::Unavailable
            };
            Refusal::new(502, class, e.message)
        })?;
        let _one = lock(&self.reloading);
        let started = signin.login();
        let current = self.config();
        let same = current
            .login(name)
            .is_some_and(|l| l.kind == started.kind && l.credentials == started.credentials);
        if !same {
            let message = format!(
                "login `{name}` changed its kind or credentials while it signed in; start a new \
                 sign-in"
            );
            return Err(Refusal::new(409, ErrorClass::BadRequest, message));
        }
        let file = started.credentials.as_path();
        let refreshing = self.store.write_lock(file);
        let _writing = lock(&refreshing);
        let backup = replace_credential(file, &bytes, entry)?;
        Ok(LoginOauthSigned {
            login: name.to_owned(),
            backup,
        })
    }

    /// Admits `client`'s turn `req`: valid, a known route, images inline, its `request_id` not
    /// running, and fewer than `max_turns` turns running.
    ///
    /// # Errors
    /// `bad_request` for an invalid request, `overloaded` at the turn limit.
    pub fn admit(&self, client: &str, req: &TurnRequest) -> Result<Admitted, GatewayError> {
        req.validate().map_err(|e| bad_request(e.0))?;
        let config = self.config();
        let route = config
            .route(&req.route)
            .ok_or_else(|| bad_request(format!("unknown route alias `{}`", req.route)))?
            .clone();
        let by_path = |b: &Block| matches!(b, Block::Image { path: Some(_), .. });
        if req.messages.iter().flat_map(|m| &m.content).any(by_path) {
            return Err(bad_request(
                "images must be sent inline as base64; the gateway reads no file a client names",
            ));
        }
        let mut turns = lock(&self.running.turns);
        if turns.iter().any(|e| e.request_id == req.request_id) {
            return Err(bad_request(format!(
                "turn `{}` is already running",
                req.request_id
            )));
        }
        if turns.len() >= config.max_turns as usize {
            let mut e = GatewayError::new(
                ErrorClass::Overloaded,
                true,
                "the gateway runs its maximum number of turns",
            );
            e.retry_after = Some(1);
            return Err(e);
        }
        let cancel = CancelToken::new();
        let id = self.running.admitted.fetch_add(1, Ordering::Relaxed);
        turns.push(Entry {
            id,
            client: client.to_owned(),
            request_id: req.request_id.clone(),
            cancel: cancel.clone(),
        });
        Ok(Admitted {
            id,
            client: client.to_owned(),
            request_id: req.request_id.clone(),
            config,
            route,
            cancel,
            running: Arc::clone(&self.running),
        })
    }

    /// Stops the running turn `request_id` of `client` and waits up to [`CANCEL_WAIT`] for it
    /// to end.
    pub fn cancel(&self, client: &str, request_id: &str) -> Cancel {
        let deadline = Instant::now() + CANCEL_WAIT;
        let mut turns = lock(&self.running.turns);
        let Some(entry) = turns.iter().find(|e| e.request_id == request_id) else {
            return Cancel::Unknown;
        };
        if entry.client != client {
            return Cancel::Forbidden;
        }
        let token = entry.cancel.clone();
        drop(turns);
        // The token's hook may shut the vendor stream down; it runs without the registry lock.
        token.cancel();
        turns = lock(&self.running.turns);
        while turns.iter().any(|e| e.request_id == request_id) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            turns = self
                .running
                .ended
                .wait_timeout(turns, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Cancel::Cancelled
    }

    /// Runs an admitted turn, handing `emit` its events: `route` and content events, then one
    /// `stop` or `error`; nothing more once `emit` returns [`Flow::Stop`].
    pub fn run(
        &self,
        turn: &Admitted,
        req: &TurnRequest,
        emit: &mut dyn FnMut(StreamEvent) -> Flow,
    ) {
        let req = route_effort(req, &turn.route);
        let req = req.as_ref();
        let emit = &mut |event: StreamEvent| {
            if matches!(event, StreamEvent::Stop { .. } | StreamEvent::Error { .. }) {
                turn.finish();
            }
            emit(event)
        };
        let mut progress = Progress {
            tried: Vec::new(),
            failed: Vec::new(),
            avoid: None,
            resume: req.session_key.is_some(),
            step: 0,
            spent: true,
            resets_at: None,
            vendor_wait: None,
        };
        // Bounds adapter attempts; a chain step that qbd cannot run takes none.
        while progress.tried.len() < turn.config.max_attempts as usize {
            if turn.cancel.is_cancelled() {
                emit(StreamEvent::Error { error: cancelled() });
                return turn.log("cancelled");
            }
            match self.attempt(turn, req, &mut progress, emit) {
                Next::Retry => {}
                Next::Done(what) => return turn.log(&what),
            }
        }
        let class = progress
            .tried
            .last()
            .map_or(ErrorClass::Unavailable, |a| a.class);
        let mut error = GatewayError::new(
            class,
            retryable(class),
            format!("gave up after {} attempts", turn.config.max_attempts),
        );
        error.tried = progress.tried;
        with_vendor_wait(&mut error, progress.vendor_wait, unix_now());
        emit(StreamEvent::Error { error });
        turn.log("out of attempts");
    }

    /// One pick, resolved to the login's credential entry and adapter; `Err` ends or retries
    /// the turn.
    fn ready<'t>(
        &'t self,
        turn: &'t Admitted,
        req: &TurnRequest,
        progress: &mut Progress,
        emit: &mut dyn FnMut(StreamEvent) -> Flow,
    ) -> Result<Ready<'t>, Next> {
        let pick = match self.pick(turn, req, progress) {
            Ok(p) => p,
            Err(e) => return Err(fail(emit, e, progress, "qbd failed")),
        };
        let (Decision::Run, Some(lease), Some(vendor), Some(model), Some(login)) = (
            pick.decision,
            pick.lease_id.clone(),
            pick.vendor.clone(),
            pick.model.clone(),
            pick.login.clone(),
        ) else {
            if !turn.route.chain.is_empty() {
                let error = unpickable(&pick, &turn.route.alias);
                return Err(next_step(&turn.route, progress, error, emit));
            }
            let error = match progress.tried.last() {
                // The re-pick after a failure of this turn found nothing else: that failure
                // stands. A `wait` keeps its reset.
                Some(last) if progress.avoid.is_some() || pick.decision == Decision::Dead => {
                    let other = if progress.avoid.is_some() {
                        "vendor"
                    } else {
                        "login"
                    };
                    let message = format!("no other {other} for route `{}`", turn.route.alias);
                    GatewayError::new(last.class, retryable(last.class), message)
                }
                _ => unpickable(&pick, &turn.route.alias),
            };
            let what = format!("{} ({})", error.class.as_str(), pick.reason);
            return Err(fail(emit, error, progress, &what));
        };
        if progress.failed.contains(&login) {
            self.report(&lease, Outcome::Error, Vec::new());
            let class = progress
                .tried
                .last()
                .map_or(ErrorClass::Unavailable, |a| a.class);
            let message = format!("qbd has no other login for route `{}`", turn.route.alias);
            let error = GatewayError::new(class, retryable(class), message);
            if !turn.route.chain.is_empty() {
                return Err(next_step(&turn.route, progress, error, emit));
            }
            return Err(fail(emit, error, progress, "no login left"));
        }
        // A config mismatch: a chain moves to its next step, other routes end the turn.
        let mut mismatch = |message: String, what: &str| {
            self.report(&lease, Outcome::Error, Vec::new());
            let error = GatewayError::new(ErrorClass::Unavailable, false, message);
            if turn.route.chain.is_empty() {
                fail(emit, error, progress, what)
            } else {
                next_step(&turn.route, progress, error, emit)
            }
        };
        let Some(entry) = turn.config.login(&login) else {
            log::error(&format!(
                "gateway: qbd picked login `{login}`, which has no credential entry"
            ));
            let message = format!("login `{login}` has no credential entry in the gateway config");
            return Err(mismatch(message, "login without credentials"));
        };
        let Some((_, upstream)) = self.upstreams.iter().find(|(a, _)| *a == entry.api) else {
            let message = format!("no adapter serves `{}` logins", entry.api.as_str());
            return Err(mismatch(message, "no adapter"));
        };
        let attempt = Attempt {
            vendor,
            model,
            login_label: Some(login.clone()),
            class: ErrorClass::Auth,
        };
        Ok(Ready {
            pick,
            lease,
            login,
            attempt,
            entry,
            upstream: upstream.as_ref(),
        })
    }

    /// One pick and, when it runs, the adapter call; twice after a 401 and a token refresh.
    fn attempt(
        &self,
        turn: &Admitted,
        req: &TurnRequest,
        progress: &mut Progress,
        emit: &mut dyn FnMut(StreamEvent) -> Flow,
    ) -> Next {
        let now = unix_now();
        let Ready {
            pick,
            lease,
            login,
            attempt,
            entry,
            upstream,
        } = match self.ready(turn, req, progress, emit) {
            Ok(r) => r,
            Err(next) => return next,
        };
        if let Some(window) = self.over_cap(entry, now) {
            // `error`, not `usage_limit`: qbd's exhaustion mark would outlast a reset or a raised
            // cap, while the full spend window keeps qbd off the login until either.
            self.report(&lease, Outcome::Error, vec![window]);
            log::warn(&format!(
                "gateway: turn {} on {login}: the login reached its spend cap",
                turn.request_id
            ));
            let mut attempt = attempt;
            attempt.class = ErrorClass::QuotaExhausted;
            progress.tried.push(attempt);
            progress.failed.push(login);
            return Next::Retry;
        }
        let mut refreshed = false;
        let started = Instant::now();
        loop {
            let loaded = self.store.load(entry, now, refreshed);
            // After the load, which may have refreshed the file, and before the request, so a 401
            // blames the credential this attempt sends and not a file replaced meanwhile.
            let fingerprint = creds::fingerprint(&entry.credentials);
            let credential = match loaded {
                Ok(c) => c,
                Err(e) => {
                    log::warn(&format!("gateway: {e}"));
                    progress.tried.push(attempt);
                    if e.unusable {
                        self.report_401(&lease, &login, &fingerprint, Vec::new());
                        self.report_dead(&login, &fingerprint);
                        progress.failed.push(login);
                        return Next::Retry;
                    }
                    self.report(&lease, Outcome::Error, Vec::new());
                    let message = "a login's token could not be refreshed";
                    let error = GatewayError::new(ErrorClass::Unavailable, true, message);
                    return fail(emit, error, progress, "refresh failed");
                }
            };
            let at = Picked {
                vendor: &attempt.vendor,
                model: &attempt.model,
                effort: pick.effort.as_deref(),
                reasoning: turn.config.reasoning(&attempt.model),
                login: &login,
                base_url: entry.base_url.as_deref(),
                referer: entry.referer.as_deref(),
                title: entry.title.as_deref(),
            };
            let mut relay = Relay {
                route: Some(StreamEvent::Route {
                    route: RouteInfo {
                        vendor: attempt.vendor.clone(),
                        model: attempt.model.clone(),
                        login_label: login.clone(),
                        lease: lease.clone(),
                    },
                }),
                emitted: false,
                usage: None,
                tools: BTreeSet::new(),
                started,
                gone: false,
                fingerprint,
                emit: &mut *emit,
            };
            let result = upstream.turn(
                &at,
                &credential,
                &own_thinking(req, at.vendor),
                &mut |e| relay.pass(e, at.vendor, &turn.cancel),
                &turn.cancel,
            );
            let result = result.map_err(|f| redact(f, &credential));
            drop(credential);
            turn.cancel.clear();
            let refresh = matches!(&result, Err(f) if f.kind == FailureKind::Auth)
                && !relay.emitted
                && !refreshed
                && matches!(
                    entry.kind,
                    CredentialKind::OauthAnthropic | CredentialKind::ChatgptOauth
                )
                && !turn.cancel.is_cancelled();
            if refresh {
                refreshed = true;
                continue;
            }
            return self.settle(turn, &lease, result, relay, attempt, progress);
        }
    }

    /// Reports how an adapter call ended and decides what the turn does next.
    fn settle(
        &self,
        turn: &Admitted,
        lease: &str,
        mut result: Result<Finished, Failure>,
        mut relay: Relay<'_>,
        mut attempt: Attempt,
        progress: &mut Progress,
    ) -> Next {
        let login = attempt.login_label.clone().unwrap_or_default();
        let (cost, windows) = match &mut result {
            Ok(done) => (done.cost, &mut done.windows),
            Err(f) => (f.cost, &mut f.windows),
        };
        let usage = relay.usage.as_ref();
        windows.extend(self.count(&turn.config, &login, &attempt.model, cost, usage));
        let step = progress.step;
        let failure = match result {
            Ok(done) => {
                self.report(lease, Outcome::Ok, done.windows);
                let stopped = turn.cancel.is_cancelled();
                let end = (!stopped).then_some(done.stop).ok_or(ErrorClass::Cancelled);
                let outcome = Outcome::Ok;
                let ended = Ended { outcome, end, cost };
                self.record_usage(turn, &relay, &attempt, &login, step, ended);
                if stopped {
                    relay.send(StreamEvent::Error { error: cancelled() });
                    return Next::Done("cancelled".into());
                }
                if let Some(route) = relay.route.take() {
                    relay.send(route);
                }
                relay.send(StreamEvent::Stop { reason: done.stop });
                return Next::Done(format!("{} on {login}", done.stop.as_str()));
            }
            Err(f) => f,
        };
        let (outcome, mut error) = refusal(&failure);
        let class = error.class;
        // A stream that started shows the login works, however it ended.
        let outcome = if relay.emitted && outcome == Outcome::Error {
            Outcome::Ok
        } else {
            outcome
        };
        self.report_attempt(lease, &login, outcome, failure.windows, &relay.fingerprint);
        let stopped = turn.cancel.is_cancelled();
        let end = Err(if stopped {
            ErrorClass::Cancelled
        } else {
            class
        });
        let ended = Ended { outcome, end, cost };
        self.record_usage(turn, &relay, &attempt, &login, step, ended);
        if relay.gone {
            return Next::Done("client gone".into());
        }
        if stopped || failure.kind == FailureKind::Cancelled {
            relay.send(StreamEvent::Error { error: cancelled() });
            return Next::Done("cancelled".into());
        }
        log::warn(&format!(
            "gateway: turn {} on {login}: {}: {}",
            turn.request_id,
            failure.kind.as_str(),
            failure.message
        ));
        attempt.class = class;
        let vendor = attempt.vendor.clone();
        progress.tried.push(attempt);
        if !relay.emitted {
            if let FailureKind::RateLimited {
                retry_after: Some(wait),
            } = failure.kind
            {
                let until = unix_now().saturating_add(wait);
                progress.vendor_wait = nearest(progress.vendor_wait, Some(until));
            }
            if login_scoped(failure.kind) {
                if failure.kind == FailureKind::Auth {
                    self.report_dead(&login, &relay.fingerprint);
                }
                progress.failed.push(login);
                return Next::Retry;
            }
            let vendor_scoped = matches!(
                failure.kind,
                FailureKind::Overloaded { .. } | FailureKind::Unavailable
            );
            if vendor_scoped && !turn.route.chain.is_empty() {
                return next_step(&turn.route, progress, error, &mut |e| relay.send(e));
            }
            if vendor_scoped && progress.avoid.is_none() {
                progress.avoid = Some(vendor);
                return Next::Retry;
            }
        }
        error.tried = std::mem::take(&mut progress.tried);
        with_vendor_wait(&mut error, progress.vendor_wait, unix_now());
        relay.send(StreamEvent::Error { error });
        Next::Done(class.as_str().to_owned())
    }

    /// Appends the usage line of `attempt` on `login` and chain step `step` of `turn`, which
    /// ended as `ended` with `relay`'s usage and tool calls; without a `[usage]` ledger it is
    /// dropped.
    fn record_usage(
        &self,
        turn: &Admitted,
        relay: &Relay<'_>,
        attempt: &Attempt,
        login: &str,
        step: usize,
        ended: Ended,
    ) {
        let Some(ledger) = &self.usage else {
            return;
        };
        let usage = relay.usage.unwrap_or_default();
        let price = turn.config.price(&attempt.model);
        let usd = spend::attempt_usd(ended.cost, price, relay.usage.as_ref())
            .filter(|(usd, _)| usd.is_finite());
        let now = unix_now();
        let line = UsageLine {
            at: now,
            duration_ms: u64::try_from(relay.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            request_id: turn.request_id.clone(),
            custom_id: None,
            batch: false,
            client: turn.client.clone(),
            route: turn.route.alias.clone(),
            step: u32::try_from(step).unwrap_or(u32::MAX),
            login: login.to_owned(),
            model: attempt.model.clone(),
            outcome: ended.outcome,
            stop: ended.end.ok(),
            error: ended.end.err(),
            usage,
            usd: usd.map(|u| u.0),
            usd_source: usd.map(|u| u.1),
            tools: relay.tools.iter().take(MAX_USAGE_TOOLS).cloned().collect(),
        };
        ledger.append(&line, now);
    }

    /// The spend window of `entry` when it has a `spend_cap` and spent it by `now`.
    fn over_cap(&self, entry: &GatewayLogin, now: u64) -> Option<WindowReport> {
        let cap = entry.spend_cap?;
        let window = lock(self.ledger()).window(&entry.name, cap, now);
        (window.utilization >= 1.0).then_some(window)
    }

    /// The ledger; only called for a login with a `spend_cap`, which needs the startup file.
    fn ledger(&self) -> &Mutex<Ledger> {
        self.spend
            .as_ref()
            .expect("a config with a spend_cap has the startup spend_file")
    }

    /// Adds an attempt's cost on `login` of `config` to its count when the login has a cap: the
    /// vendor's `cost`, else `usage` at the price of `model`. The login's spend window after it.
    fn count(
        &self,
        config: &GatewayConfig,
        login: &str,
        model: &str,
        cost: Option<f64>,
        usage: Option<&Usage>,
    ) -> Option<WindowReport> {
        let cap = config.login(login)?.spend_cap?;
        let mut ledger = lock(self.ledger());
        let usd = spend::attempt_usd(cost, config.price(model), usage).map(|(usd, _)| usd);
        if usd.is_none() {
            warn_unpriced(&mut ledger, model);
        }
        let usd = usd.unwrap_or(0.0);
        let now = unix_now();
        if usd.is_finite() && usd > 0.0 {
            if let Err(e) = ledger.add(login, usd, now) {
                log::error(&format!("gateway: spend of {login}: {e}"));
            }
        }
        Some(ledger.window(login, cap, now))
    }

    /// Adds `usd`, the cost of the message batch `batch_id` of `model` on `login` of `config`, to
    /// the login's count once when it has a cap, and then reports its spend window to qbd; `None`
    /// is a model without a price and adds nothing.
    ///
    /// # Errors
    /// The spend file could not be written; the count stays as it was.
    pub(super) fn count_batch(
        &self,
        config: &GatewayConfig,
        (login, model): (&str, &str),
        batch_id: &str,
        usd: Option<f64>,
    ) -> Result<(), String> {
        let Some(cap) = config.login(login).and_then(|l| l.spend_cap) else {
            return Ok(());
        };
        let mut ledger = lock(self.ledger());
        let Some(usd) = usd.filter(|usd| usd.is_finite() && *usd > 0.0) else {
            if usd.is_none() {
                warn_unpriced(&mut ledger, model);
            }
            return Ok(());
        };
        let added = ledger.add_batch(login, batch_id, usd, unix_now())?;
        drop(ledger);
        if added {
            self.publish_spend(login, Some(cap));
        }
        Ok(())
    }

    /// Reports the spend window of `login` under `cap` to qbd, or an empty one without a cap.
    fn publish_spend(&self, login: &str, cap: Option<f64>) {
        let now = unix_now();
        let window = match cap {
            Some(cap) => lock(self.ledger()).window(login, cap, now),
            None => WindowReport {
                name: spend::WINDOW.to_owned(),
                utilization: 0.0,
                resets_at: None,
                length_s: None,
            },
        };
        // `error` marks nothing; `ok` would also clear an auth mark of the login.
        self.send_report(&ReportRequest {
            lease_id: None,
            login: Some(login.to_owned()),
            outcome: Outcome::Error,
            model: None,
            windows: vec![window],
            release: false,
            credential: None,
        });
    }

    /// The month's spend of each login of the current config with a `spend_cap`.
    pub fn spend(&self) -> SpendAnswer {
        let config = self.config();
        let now = unix_now();
        let logins = config
            .logins
            .iter()
            .filter_map(|l| {
                let cap = l.spend_cap?;
                let mut ledger = lock(self.ledger());
                Some(LoginSpend {
                    login: l.name.clone(),
                    spent_usd: ledger.spent(&l.name, now),
                    cap_usd: cap,
                    period_end: ledger.period_end(now),
                })
            })
            .collect();
        SpendAnswer { logins }
    }

    /// Sets the count of `login` to zero for `actor` and tells qbd, so the login runs again;
    /// records one audit entry either way.
    ///
    /// # Errors
    /// `bad_request` when the current config gives `login` no `spend_cap`, `unavailable` when
    /// the spend file cannot be written; the count is zero in memory either way.
    pub fn reset_spend(&self, actor: &str, login: &str) -> Result<LoginSpend, GatewayError> {
        let reset = self.reset_count(login);
        let entry = audit::entry(actor, AuditAction::SpendReset, Some(login.to_owned()));
        match &reset {
            Ok(_) => self.record(&entry),
            Err(e) => {
                let reason = e
                    .message
                    .clone()
                    .unwrap_or_else(|| e.class.as_str().to_owned());
                self.record(&audit::refused(entry, reason));
            }
        }
        reset
    }

    /// [`Self::reset_spend`] without the audit entry.
    fn reset_count(&self, login: &str) -> Result<LoginSpend, GatewayError> {
        let config = self.config();
        let Some(cap) = config.login(login).and_then(|l| l.spend_cap) else {
            return Err(bad_request(format!("login `{login}` has no spend_cap")));
        };
        let now = unix_now();
        let written = lock(self.ledger()).reset(login, now);
        self.publish_spend(login, Some(cap));
        if let Err(e) = written {
            log::error(&format!("gateway: spend reset of {login}: {e}"));
            let message = format!("the count of `{login}` is zero but not saved");
            return Err(GatewayError::new(ErrorClass::Unavailable, true, message));
        }
        log::info(&format!("gateway: spend of {login} reset"));
        let period_end = lock(self.ledger()).period_end(now);
        Ok(LoginSpend {
            login: login.to_owned(),
            spent_usd: 0.0,
            cap_usd: cap,
            period_end,
        })
    }

    /// Each route alias, sorted, with the state of the logins it can run on in qbd's
    /// `GET /v1/state`: this gateway's logins of the pinned vendor, of each step's vendor of a
    /// chain route, or every login of this gateway for a ladder route, each within the route's
    /// `logins` when it has them.
    pub fn routes(&self) -> RoutesAnswer {
        let config = self.config();
        let state = self.state();
        let routes = config
            .routes
            .iter()
            .map(|r| {
                let mut status = RouteStatus {
                    alias: r.alias.clone(),
                    state: RouteState::Unavailable,
                    vendor: r.vendor.clone(),
                    model: r.model.clone(),
                    resets_at: None,
                };
                let Some(state) = &state else {
                    return status;
                };
                if r.chain.is_empty() {
                    (status.state, status.resets_at) =
                        standing(&config, state, r.vendor.as_deref(), r.logins.as_deref());
                    return status;
                }
                for step in &r.chain {
                    match standing(&config, state, Some(&step.vendor), r.logins.as_deref()) {
                        (RouteState::Ready, _) => {
                            status.state = RouteState::Ready;
                            status.vendor = Some(step.vendor.clone());
                            status.model = Some(step.model.clone());
                            status.resets_at = None;
                            return status;
                        }
                        (RouteState::Exhausted, at) => {
                            status.state = RouteState::Exhausted;
                            status.resets_at = nearest(status.resets_at, at);
                        }
                        _ => {}
                    }
                }
                status
            })
            .collect();
        RoutesAnswer { routes }
    }

    /// The bearer the gateway shows `qbd`, from `qbd_bearer_file`.
    pub(super) fn bearer(&self) -> Option<&str> {
        self.qbd_bearer.as_ref().map(|b| b.as_str())
    }

    fn state(&self) -> Option<State> {
        self.read_qbd(paths::STATE).ok()
    }

    /// `qbd`'s answer to `GET path`; a failure is logged and its message returned.
    fn read_qbd<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let socket = &self.startup.qbd_socket;
        let read = match client::call(socket, "GET", path, None, self.bearer()) {
            Ok((200, body)) => serde_json::from_slice(&body)
                .map_err(|e| format!("qbd answered {path} with an invalid body: {e}")),
            Ok((status, _)) => Err(format!("qbd answered {path} with HTTP {status}")),
            Err(e) => Err(format!("qbd is unreachable for {path}: {e}")),
        };
        read.inspect_err(|e| log::warn(&format!("gateway: {e}")))
    }

    /// The ladder `query` names for `caller`: the steps of `qbd`'s running role that its ladder
    /// routes name, each candidate with the state of this gateway's logins of its vendor in
    /// `qbd`'s `GET /v1/state`, within the logins of the queried route or, for a role, the union
    /// of the logins of the step's routes, a route without `logins` adding every login. Takes no
    /// lease.
    ///
    /// # Errors
    /// 403 a route `caller` may not run or a role none of its routes names, before `qbd` is
    /// asked; 400 a pin or chain route; 404 an unknown route, a role no ladder route names, a
    /// role `qbd` does not run or a route's step it lacks; 503 `qbd` cannot be read.
    pub(super) fn ladder(
        &self,
        caller: &Caller,
        query: &LadderQuery,
    ) -> Result<LadderAnswer, Refusal> {
        let config = self.config();
        let forbid = |what: String| {
            Refusal::new(
                403,
                ErrorClass::Auth,
                format!("client `{}` may not use {what}", caller.name),
            )
        };
        let missing = |message: String| Refusal::new(404, ErrorClass::BadRequest, message);
        let (role, only) = match query {
            LadderQuery::Route(alias) => {
                if !caller.may_run(alias) {
                    return Err(forbid(format!("route `{alias}`")));
                }
                let route = config
                    .route(alias)
                    .ok_or_else(|| missing(format!("no route `{alias}`")))?;
                let Some(difficulty) = route.difficulty else {
                    let message = format!("route `{alias}` pins its models and has no ladder step");
                    return Err(Refusal::new(400, ErrorClass::BadRequest, message));
                };
                (route.role.as_str(), Some((difficulty, route)))
            }
            LadderQuery::Role(role) => {
                let mut named = config
                    .routes
                    .iter()
                    .filter(|r| r.role == *role && r.difficulty.is_some())
                    .peekable();
                if named.peek().is_none() {
                    return Err(missing(format!("no ladder route names role `{role}`")));
                }
                if !named.any(|r| caller.may_run(&r.alias)) {
                    return Err(forbid(format!("a route of role `{role}`")));
                }
                (role.as_str(), None)
            }
        };
        let unreadable = |message: String| Refusal::new(503, ErrorClass::Unavailable, message);
        let running: RolesResponse = self.read_qbd(paths::ROLES).map_err(unreadable)?;
        let logins: State = self.read_qbd(paths::STATE).map_err(unreadable)?;
        let Some(spec) = running.roles.into_iter().find(|r| r.name == role) else {
            return Err(missing(format!("qbd runs no role `{role}`")));
        };
        let mut steps: Vec<LadderStepState> = spec
            .ladder
            .into_iter()
            .filter(|s| only.is_none_or(|(d, _)| d == s.difficulty))
            .filter_map(|s| {
                let named: Vec<&Route> = config
                    .routes
                    .iter()
                    .filter(|r| r.role == role && r.difficulty == Some(s.difficulty))
                    .filter(|r| caller.may_run(&r.alias))
                    .collect();
                if named.is_empty() {
                    return None;
                }
                let listed = match only {
                    Some((_, route)) => route.logins.clone(),
                    None => union(&named),
                };
                let candidates = s
                    .candidates
                    .into_iter()
                    .map(|c| {
                        let (state, resets_at) =
                            standing(&config, &logins, Some(&c.vendor), listed.as_deref());
                        LadderCandidateState {
                            api: family(&config, &logins, &c.vendor, listed.as_deref()),
                            vendor: c.vendor,
                            model: c.model,
                            effort: c.effort,
                            tier: c.tier,
                            state,
                            resets_at,
                        }
                    })
                    .collect();
                Some(LadderStepState {
                    difficulty: s.difficulty,
                    routes: named.iter().map(|r| r.alias.clone()).collect(),
                    candidates,
                })
            })
            .collect();
        steps.sort_by_key(|s| s.difficulty);
        if let (Some((difficulty, _)), true) = (only, steps.is_empty()) {
            let message = format!("qbd's role `{role}` has no step of difficulty {difficulty}");
            return Err(missing(message));
        }
        Ok(LadderAnswer {
            role: role.to_owned(),
            steps,
        })
    }

    /// A pick for `turn`'s route on behalf of its caller; a `wait` caused by `resume_of` is
    /// asked again once without it.
    fn pick(
        &self,
        turn: &Admitted,
        req: &TurnRequest,
        progress: &mut Progress,
    ) -> Result<PickResponse, GatewayError> {
        let route = &turn.route;
        let session = req.session_key.as_ref();
        let mut pick = PickRequest {
            role: route.role.clone(),
            difficulty: route.difficulty,
            pin: route.pin(progress.step),
            resume_of: session.filter(|_| progress.resume).cloned(),
            avoid_vendor: progress.avoid.clone(),
            need: Vec::new(),
            expected_minutes: route.expected_minutes,
            run_id: Some(session.unwrap_or(&req.request_id).clone()),
            on_behalf_of: Some(turn.client.clone()),
            logins: route.logins.clone(),
        };
        let p = self.pick_once(&pick)?;
        if p.decision != Decision::Wait || pick.resume_of.is_none() {
            return Ok(p);
        }
        progress.resume = false;
        pick.resume_of = None;
        self.pick_once(&pick)
    }

    pub(super) fn pick_once(&self, req: &PickRequest) -> Result<PickResponse, GatewayError> {
        let unavailable = |m: String| GatewayError::new(ErrorClass::Unavailable, true, m);
        let body = serde_json::to_vec(req).map_err(|e| unavailable(e.to_string()))?;
        let socket = &self.startup.qbd_socket;
        let (status, resp) = client::call(socket, "POST", paths::PICK, Some(&body), self.bearer())
            .map_err(|e| {
                log::warn(&format!("gateway: qbd pick: {e}"));
                unavailable("qbd is unreachable".into())
            })?;
        match status {
            200 => serde_json::from_slice(&resp)
                .map_err(|e| unavailable(format!("qbd answered an invalid pick: {e}"))),
            429 => {
                let message = "qbd rate-limits the gateway";
                let mut e = GatewayError::new(ErrorClass::Overloaded, true, message);
                e.retry_after = Some(1);
                Err(e)
            }
            _ => {
                let detail = String::from_utf8_lossy(&resp);
                log::warn(&format!(
                    "gateway: qbd pick answered HTTP {status}: {detail}"
                ));
                Err(unavailable(format!(
                    "qbd refused the pick with HTTP {status}"
                )))
            }
        }
    }

    /// Reports `outcome` and `windows` for `lease` and releases it; failures are logged only.
    pub(super) fn report(&self, lease: &str, outcome: Outcome, windows: Vec<WindowReport>) {
        self.send_report(&ReportRequest {
            lease_id: Some(lease.to_owned()),
            login: None,
            outcome,
            model: None,
            windows,
            release: true,
            credential: None,
        });
    }

    /// [`Self::report`] of an attempt on `login` that read the credential of fingerprint `fp`,
    /// which an `http_401` carries.
    pub(super) fn report_attempt(
        &self,
        lease: &str,
        login: &str,
        outcome: Outcome,
        windows: Vec<WindowReport>,
        fp: &str,
    ) {
        match outcome {
            Outcome::Http401 => self.report_401(lease, login, fp, windows),
            _ => self.report(lease, outcome, windows),
        }
    }

    /// Reports an `http_401` for `lease` on `login`, whose attempt read the credential of
    /// fingerprint `fp`, and releases it: qbd keeps the fingerprint with the auth mark.
    fn report_401(&self, lease: &str, login: &str, fp: &str, windows: Vec<WindowReport>) {
        let took = self.send_report(&ReportRequest {
            lease_id: Some(lease.to_owned()),
            login: None,
            outcome: Outcome::Http401,
            model: None,
            windows,
            release: true,
            credential: Some(fp.to_owned()),
        });
        self.took(took, login, fp);
    }

    /// Remembers that qbd holds `fp` for `login`, when it `took` a report of it: a refresh by
    /// the gateway changes the file behind the last announcement.
    fn took(&self, took: bool, login: &str, fp: &str) {
        if took {
            lock(&self.announced).insert(login.to_owned(), fp.to_owned());
        }
    }

    /// Reports one more `http_401` on `login` after its lease report, so qbd marks it
    /// `auth_dead` and the next pick of the turn skips it: the credential of fingerprint `fp`
    /// failed even after a refresh, or its file is unusable, and neither passes by itself. A
    /// credential written later has another fingerprint, which [`Self::announce_credential`]
    /// brings to qbd.
    fn report_dead(&self, login: &str, fp: &str) {
        let took = self.send_report(&ReportRequest {
            lease_id: None,
            login: Some(login.to_owned()),
            outcome: Outcome::Http401,
            model: None,
            windows: Vec::new(),
            release: false,
            credential: Some(fp.to_owned()),
        });
        self.took(took, login, fp);
    }

    /// Tells qbd that the credential of `login` has the fingerprint `fp`, with an `error` report
    /// that marks nothing: an auth mark qbd keeps for another fingerprint clears, one without a
    /// fingerprint takes it. Remembers `fp` once qbd took it.
    fn announce(&self, login: &str, fp: &str) {
        let took = self.send_report(&ReportRequest {
            lease_id: None,
            login: Some(login.to_owned()),
            outcome: Outcome::Error,
            model: None,
            windows: Vec::new(),
            release: false,
            credential: Some(fp.to_owned()),
        });
        self.took(took, login, fp);
    }

    /// [`Self::announce`] of the fingerprint of `login`'s credential file as it is now, unless
    /// qbd already took that one. When qbd took another one before, that one goes again first,
    /// so a mark set without a fingerprint takes it and the new one clears the mark.
    fn announce_credential(&self, login: &GatewayLogin) {
        let fp = creds::fingerprint(&login.credentials);
        let before = lock(&self.announced).get(&login.name).cloned();
        if before.as_ref() == Some(&fp) {
            return;
        }
        if let Some(before) = before {
            self.announce(&login.name, &before);
        }
        self.announce(&login.name, &fp);
    }

    /// [`Self::announce_credential`] of every login of the current config. The gateway calls it
    /// once it serves and after each reload, so a credential file replaced while it was down, or
    /// by `qb login` or `qb login import`, clears the auth mark of its old credential.
    pub fn announce_credentials(&self) {
        for login in &self.config().logins {
            self.announce_credential(login);
        }
    }

    /// Announces that the gateway replaced the credential file of login `name`, whose old
    /// fingerprint was `before`: the old one first, which a mark without a fingerprint takes,
    /// then the new one, which clears it.
    fn announce_replaced(&self, name: &str, before: Option<String>) {
        if let Some(before) = before {
            self.announce(name, &before);
        }
        if let Some(login) = self.config().login(name) {
            self.announce_credential(login);
        }
    }

    /// Sends `req` to qbd: whether qbd took it; a refusal or failure is logged.
    fn send_report(&self, req: &ReportRequest) -> bool {
        let Ok(body) = serde_json::to_vec(req) else {
            return false;
        };
        let of = req.lease_id.as_ref().or(req.login.as_ref());
        let of = of.map_or("", String::as_str);
        let socket = &self.startup.qbd_socket;
        match client::call(socket, "POST", paths::REPORT, Some(&body), self.bearer()) {
            Ok((200, _)) => return true,
            // A qbd older than `credential` refuses it: the mark matters more than its
            // fingerprint.
            Ok((400, _)) if req.credential.is_some() && req.outcome == Outcome::Http401 => {
                let plain = ReportRequest {
                    credential: None,
                    ..req.clone()
                };
                return self.send_report(&plain);
            }
            Ok((status, resp)) => log::warn(&format!(
                "gateway: qbd report of {of} answered HTTP {status}: {}",
                String::from_utf8_lossy(&resp)
            )),
            Err(e) => log::warn(&format!("gateway: qbd report of {of}: {e}")),
        }
        false
    }
}

/// Replaces the credential file `file` with `bytes`, its old content, when there was a file,
/// kept as a 0600 backup: the backup's path. A failure that replaced the file sets the backup of
/// `entry`.
///
/// # Errors
/// 500: the file cannot be read, the backup or the file cannot be written; the old file stays in
/// force, unless the write failed after replacing it, which keeps the backup.
fn replace_credential(
    file: &Path,
    bytes: &[u8],
    entry: &mut AuditEntry,
) -> Result<Option<String>, Refusal> {
    let failed = |message: String| Refusal::new(500, ErrorClass::Unavailable, message);
    let old = match std::fs::read(file) {
        Ok(bytes) => Some(Zeroizing::new(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(failed(format!("cannot read {}: {e}", file.display()))),
    };
    let backup = old
        .as_ref()
        .map(|old| rewrite::backup(file, old, unix_now()))
        .transpose()
        .map_err(|e| failed(format!("cannot write a backup of {}: {e}", file.display())))?;
    let written = match (&old, &backup) {
        (Some(old), Some(backup)) => rewrite::replace(file, old, bytes, backup, write_atomic),
        _ => write_atomic(file, bytes).map_err(|error| Unwritten {
            replaced: std::fs::symlink_metadata(file).is_ok(),
            error,
        }),
    };
    let backup = backup.map(|b| b.display().to_string());
    if let Err(u) = written {
        let file = file.display();
        if !u.replaced {
            let message = format!("cannot write {file}: {}; the old file stays", u.error);
            return Err(failed(message));
        }
        entry.backup.clone_from(&backup);
        let kept = backup.map_or_else(
            || "there was no old file".to_owned(),
            |b| format!("the old file is kept as {b}"),
        );
        return Err(failed(format!(
            "{file} was replaced but the write failed: {}; {kept}",
            u.error
        )));
    }
    Ok(backup)
}

/// The union of the `logins` of `routes`; `None`, every login, when one of them has none.
fn union(routes: &[&Route]) -> Option<Vec<String>> {
    let mut names = BTreeSet::new();
    for r in routes {
        names.extend(r.logins.as_ref()?.iter().cloned());
    }
    Some(names.into_iter().collect())
}

/// Whether `login` is one of `config`'s logins and of `listed`, if given.
fn ours(config: &GatewayConfig, listed: Option<&[String]>, login: &str) -> bool {
    config.login(login).is_some() && listed.is_none_or(|names| names.iter().any(|n| n == login))
}

/// The state of the logins of `config` of `vendor`, or of all of them, within `listed`, if
/// given, in `state`: `ready` when one is usable, else `exhausted` with the nearest reset when
/// one waits, else `unavailable`. A login with a full window waits for its reset, as qbd does not
/// pick it before.
fn standing(
    config: &GatewayConfig,
    state: &State,
    vendor: Option<&str>,
    listed: Option<&[String]>,
) -> (RouteState, Option<u64>) {
    let mut standing = (RouteState::Unavailable, None);
    for l in &state.logins {
        if !ours(config, listed, &l.login) || vendor.is_some_and(|v| v != l.vendor) {
            continue;
        }
        let full = l
            .windows
            .iter()
            .filter(|w| w.used >= 1.0)
            .filter_map(|w| w.resets_at)
            .max();
        match l.status {
            LoginStatus::Ok | LoginStatus::Unknown | LoginStatus::AuthStale if full.is_some() => {
                standing = (RouteState::Exhausted, nearest(standing.1, full));
            }
            LoginStatus::Ok | LoginStatus::Unknown | LoginStatus::AuthStale => {
                return (RouteState::Ready, None);
            }
            LoginStatus::Exhausted | LoginStatus::RateLimited => {
                standing = (RouteState::Exhausted, nearest(standing.1, l.dead_until));
            }
            LoginStatus::AuthDead => {}
        }
    }
    standing
}

/// The API family of the first login of `config` within `listed`, if given, that `state` puts on
/// `vendor`.
fn family(
    config: &GatewayConfig,
    state: &State,
    vendor: &str,
    listed: Option<&[String]>,
) -> Option<ApiFamily> {
    let login = config.logins.iter().find(|g| {
        ours(config, listed, &g.name)
            && state
                .logins
                .iter()
                .any(|l| l.login == g.name && l.vendor == vendor)
    })?;
    Some(match login.api {
        Api::Anthropic => ApiFamily::Anthropic,
        Api::Openai => ApiFamily::Openai,
        Api::ChatCompletions => ApiFamily::ChatCompletions,
    })
}

/// `config` with its routes sorted by alias, for `routes`.
fn sorted(mut config: GatewayConfig) -> GatewayConfig {
    // A handful of entries needs no generic sort.
    let routes = &mut config.routes;
    for i in 1..routes.len() {
        let mut j = i;
        while j > 0 && routes[j - 1].alias > routes[j].alias {
            routes.swap(j - 1, j);
            j -= 1;
        }
    }
    config
}

/// The first restart-only change of `new` against the startup config `old`, naming its file
/// and field: the listeners, the qbd connection, the spend, audit and grace files, the usage
/// ledger, the batch store, and a credential or token file outside the directories `opened` the sandbox opened
/// at startup.
fn restart_only(old: &GatewayConfig, new: &GatewayConfig, opened: &[PathBuf]) -> Option<String> {
    let fail = |field: String, reason: &str| {
        let e = Error {
            file: new.file.clone(),
            field,
            reason: format!("{reason}; it takes effect only on a restart"),
        };
        Some(e.to_string())
    };
    let listen = |c: &GatewayConfig| c.fronts.as_ref().and_then(|f| f.listen);
    let grace = |c: &GatewayConfig| c.fronts.as_ref().and_then(|f| f.grace_file.clone());
    let changed = [
        ("socket", old.socket != new.socket),
        ("socket_mode", old.socket_mode != new.socket_mode),
        ("qbd_socket", old.qbd_socket != new.qbd_socket),
        (
            "qbd_bearer_file",
            old.qbd_bearer_file != new.qbd_bearer_file,
        ),
        ("spend_file", old.spend_file != new.spend_file),
        ("audit_file", old.audit_file != new.audit_file),
        ("usage", old.usage != new.usage),
        ("batches", old.batches != new.batches),
        ("fronts.listen", listen(old) != listen(new)),
        ("fronts.grace_file", grace(old) != grace(new)),
    ];
    if let Some((field, _)) = changed.into_iter().find(|(_, c)| *c) {
        return fail(field.to_owned(), "changed");
    }
    let outside = |file: &std::path::Path| !file_dir(file).is_ok_and(|d| opened.contains(&d));
    for (i, login) in new.logins.iter().enumerate() {
        if outside(&login.credentials) {
            let reason = "lies outside the credential directories the sandbox opened";
            return fail(format!("logins[{i}].credentials"), reason);
        }
    }
    let clients = new.fronts.iter().flat_map(|f| f.clients.iter().enumerate());
    for (i, client) in clients {
        let ClientToken::File(file) = &client.token else {
            continue;
        };
        if outside(file) {
            let reason = "lies outside the directories the sandbox opened";
            return fail(format!("fronts.clients[{i}].token_file"), reason);
        }
    }
    None
}

/// Ends the turn with `error`, carrying the attempts so far.
fn fail(
    emit: &mut dyn FnMut(StreamEvent) -> Flow,
    mut error: GatewayError,
    progress: &mut Progress,
    what: &str,
) -> Next {
    error.tried = std::mem::take(&mut progress.tried);
    with_vendor_wait(&mut error, progress.vendor_wait, unix_now());
    emit(StreamEvent::Error { error });
    Next::Done(what.to_owned())
}

/// Puts the vendor's wait, which runs out at Unix time `until`, on a retryable `error` at `now`
/// that has no `retry_after` of its own: `retry_after` is the seconds left (at least 1), and a
/// `resets_at` moves no earlier than `until`, since a login that answered 429 is not free before.
fn with_vendor_wait(error: &mut GatewayError, until: Option<u64>, now: u64) {
    let Some(until) = until else {
        return;
    };
    if !error.retryable || error.retry_after.is_some() {
        return;
    }
    error.retry_after = Some(until.saturating_sub(now).max(1));
    if let Some(at) = error.resets_at {
        error.resets_at = Some(at.max(until));
    }
}

/// Ends the current step of chain `route` with `error`: the next pick pins the next step, and
/// without one the turn ends with `quota_exhausted` at the nearest reset when every step was
/// spent or waiting, else with `error`.
fn next_step(
    route: &Route,
    progress: &mut Progress,
    error: GatewayError,
    emit: &mut dyn FnMut(StreamEvent) -> Flow,
) -> Next {
    progress.step += 1;
    progress.spent &= error.class == ErrorClass::QuotaExhausted;
    progress.resets_at = nearest(progress.resets_at, error.resets_at);
    if progress.step < route.chain.len() {
        return Next::Retry;
    }
    let error = if progress.spent {
        let message = format!("every step of route `{}` is spent or waits", route.alias);
        let mut e = GatewayError::new(ErrorClass::QuotaExhausted, true, message);
        e.resets_at = progress.resets_at;
        e
    } else {
        error
    };
    let what = format!("{} after the last step", error.class.as_str());
    fail(emit, error, progress, &what)
}

/// The earlier of two optional times.
fn nearest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The error for a pick that is not `run`: `quota_exhausted` until the `retry_after` of a
/// `wait`, `no_route` for `dead`.
pub(super) fn unpickable(p: &PickResponse, alias: &str) -> GatewayError {
    if p.decision == Decision::Wait {
        let message = format!("every candidate of route `{alias}` waits ({})", p.reason);
        let mut e = GatewayError::new(ErrorClass::QuotaExhausted, true, message);
        e.resets_at = p.retry_after;
        return e;
    }
    let message = format!("qbd has no candidate for route `{alias}` ({})", p.reason);
    GatewayError::new(ErrorClass::NoRoute, false, message)
}

/// `f` with the credential's secret and account id replaced by `[redacted]`: the adapter must
/// never quote them, and if it does, the copy stops here.
pub(super) fn redact(mut f: Failure, credential: &Credential) -> Failure {
    for value in [Some(credential.secret()), credential.account_id()]
        .into_iter()
        .flatten()
    {
        if f.message.contains(value) {
            f.message = f.message.replace(value, "[redacted]");
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::path::Path;

    use super::*;

    fn config(logins: &[&str]) -> GatewayConfig {
        let mut text = String::from(
            "socket = \"/run/qb/gw.sock\"\nqbd_socket = \"/run/qb/qb.sock\"\n\
             [[routes]]\nalias = \"chat\"\nrole = \"gateway\"\ndifficulty = 1\n",
        );
        for (i, file) in logins.iter().enumerate() {
            let _ = write!(
                text,
                "[[logins]]\nname = \"login-{i}\"\nkind = \"api_key\"\napi = \"anthropic\"\n\
                 credentials = \"{file}\"\n"
            );
        }
        super::super::config::parse(Path::new("/etc/qb/gateway.toml"), &text).unwrap()
    }

    #[test]
    fn a_reload_may_add_credentials_only_in_a_directory_the_sandbox_opened() {
        let startup = config(&["/srv/a/login-0.json", "/srv/gap/login-1.json"]);
        let opened = [PathBuf::from("/srv/a")];
        let in_opened = config(&["/srv/a/login-0.json", "/srv/a/login-1.json"]);
        assert_eq!(restart_only(&startup, &in_opened, &opened), None);
        let in_gap = config(&["/srv/a/login-0.json", "/srv/gap/login-2.json"]);
        let refused = restart_only(&startup, &in_gap, &opened).unwrap();
        assert!(
            refused.contains("logins[1].credentials: lies outside"),
            "{refused}"
        );
    }
}
