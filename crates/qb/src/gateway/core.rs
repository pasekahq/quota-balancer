//! The gateway core every front shares: admit a turn, then per attempt ask qbd for a login of
//! the route, load its credential, run the vendor adapter and report the outcome to qbd. Until
//! the client has seen an event a failure moves on within the turn (ADR 0001, "Rotation
//! boundary"), on a chain route also to its next step; after that, or when qbd has nothing
//! left, the turn ends with `error`.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    Attempt, Block, Decision, ErrorClass, GatewayError, LoginSpend, LoginStatus, Outcome,
    PickRequest, PickResponse, ReloadAnswer, ReportRequest, RouteInfo, RouteState, RouteStatus,
    RoutesAnswer, SpendAnswer, StreamEvent, TurnRequest, Usage, WindowReport, paths,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::config::{Api, CredentialKind, GatewayConfig, GatewayLogin, Route};
use super::creds::{CredentialStore, Refresher};
use super::spend::{self, Ledger};
use super::upstream::{
    CancelToken, Credential, Failure, FailureKind, Finished, Flow, Picked, Upstream,
};
use crate::config::Error;
use crate::sandbox::file_dir;
use crate::server::unix_now;
use crate::{client, log};

/// How long `cancel` waits for the cancelled turn to end.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// Vendor adapters by the API family they serve.
pub type Upstreams = Vec<(Api, Box<dyn Upstream>)>;

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
    /// Shared by every snapshot, so a file's refresh lock outlives a reload.
    store: CredentialStore,
    upstreams: Upstreams,
    qbd_bearer: Option<Zeroizing<String>>,
    running: Arc<Running>,
    /// The counts of the startup `spend_file`; every snapshot with a `spend_cap` has that file.
    spend: Option<Mutex<Ledger>>,
    /// The credential directories the sandbox opened; without a sandbox, those of `startup`.
    opened: Vec<PathBuf>,
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
    /// The client is gone: nothing more reaches it.
    gone: bool,
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
        if let StreamEvent::Usage { usage } = &event {
            self.usage = Some(*usage);
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

/// The parts of qbd's `GET /v1/state` the routes answer reads; other fields are skipped.
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
    /// The config's `spend_file` exists but cannot be read as one.
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
        let startup = Arc::new(sorted(config));
        let opened = startup
            .logins
            .iter()
            .filter_map(|l| file_dir(&l.credentials).ok())
            .collect();
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
        })
    }

    /// The gateway under a sandbox that opened the credential directories `opened`: a reload
    /// may add credential files in these only.
    #[must_use]
    pub fn sandboxed(mut self, opened: Vec<PathBuf>) -> Self {
        self.opened = opened;
        self
    }

    /// The current config snapshot.
    pub fn config(&self) -> Arc<GatewayConfig> {
        Arc::clone(&lock(&self.config))
    }

    /// Reads the config file again. A config that parses and validates as at startup and keeps
    /// every restart-only field becomes the snapshot of later admissions; admitted turns keep
    /// theirs. Logs one line either way.
    ///
    /// # Errors
    /// The file is unreadable or invalid, or changes a restart-only field; the running config
    /// stays.
    pub fn reload(&self) -> Result<ReloadAnswer, String> {
        let _one = lock(&self.reloading);
        let loaded = super::config::load(&self.startup.file)
            .map_err(|e| e.to_string())
            .and_then(|c| restart_only(&self.startup, &c, &self.opened).map_or(Ok(c), Err));
        let config = match loaded {
            Ok(c) => sorted(c),
            Err(e) => {
                log::warn(&format!("gateway: reload refused: {e}"));
                return Err(e);
            }
        };
        let answer = ReloadAnswer {
            routes: config.routes.len(),
            logins: config.logins.len(),
        };
        let config = Arc::new(config);
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
        Ok(answer)
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
        loop {
            let loaded = self.store.load(entry, now, refreshed);
            let credential = match loaded {
                Ok(c) => c,
                Err(e) => {
                    log::warn(&format!("gateway: {e}"));
                    progress.tried.push(attempt);
                    if e.unusable {
                        self.report(&lease, Outcome::Http401, Vec::new());
                        self.report_dead(&login);
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
                gone: false,
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
        let failure = match result {
            Ok(done) => {
                self.report(lease, Outcome::Ok, done.windows);
                if turn.cancel.is_cancelled() {
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
        let (outcome, class) = classify(failure.kind);
        // A stream that started shows the login works, however it ended.
        let outcome = if relay.emitted && outcome == Outcome::Error {
            Outcome::Ok
        } else {
            outcome
        };
        self.report(lease, outcome, failure.windows);
        if relay.gone {
            return Next::Done("client gone".into());
        }
        if turn.cancel.is_cancelled() || failure.kind == FailureKind::Cancelled {
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
        let mut error = GatewayError::new(class, retryable(class), failure.message);
        match failure.kind {
            FailureKind::UsageLimit { resets_at } => error.resets_at = resets_at,
            FailureKind::RateLimited { retry_after } | FailureKind::Overloaded { retry_after } => {
                error.retry_after = retry_after;
            }
            _ => {}
        }
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
                    self.report_dead(&login);
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
        let usd = match (cost, config.price(model)) {
            (Some(usd), _) => usd,
            (None, Some(price)) => usage.map_or(0.0, |u| spend::priced(u, price)),
            (None, None) => {
                if ledger.first_unpriced(model) {
                    log::warn(&format!(
                        "gateway: model `{model}` has no price and its vendor reports no cost; \
                         turns on capped logins count nothing for it"
                    ));
                }
                0.0
            }
        };
        let now = unix_now();
        if usd.is_finite() && usd > 0.0 {
            if let Err(e) = ledger.add(login, usd, now) {
                log::error(&format!("gateway: spend of {login}: {e}"));
            }
        }
        Some(ledger.window(login, cap, now))
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

    /// Sets the count of `login` to zero and tells qbd, so the login runs again.
    ///
    /// # Errors
    /// `bad_request` when the current config gives `login` no `spend_cap`, `unavailable` when
    /// the spend file cannot be written; the count is zero in memory either way.
    pub fn reset_spend(&self, login: &str) -> Result<LoginSpend, GatewayError> {
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
    /// chain route, or every login of this gateway for a ladder route.
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
                        standing(&config, state, r.vendor.as_deref());
                    return status;
                }
                for step in &r.chain {
                    match standing(&config, state, Some(&step.vendor)) {
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

    fn bearer(&self) -> Option<&str> {
        self.qbd_bearer.as_ref().map(|b| b.as_str())
    }

    fn state(&self) -> Option<State> {
        match client::call(
            &self.startup.qbd_socket,
            "GET",
            paths::STATE,
            None,
            self.bearer(),
        ) {
            Ok((200, body)) => serde_json::from_slice(&body).ok(),
            Ok((status, _)) => {
                log::warn(&format!("gateway: qbd state answered HTTP {status}"));
                None
            }
            Err(e) => {
                log::warn(&format!("gateway: qbd state: {e}"));
                None
            }
        }
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
        };
        let p = self.pick_once(&pick)?;
        if p.decision != Decision::Wait || pick.resume_of.is_none() {
            return Ok(p);
        }
        progress.resume = false;
        pick.resume_of = None;
        self.pick_once(&pick)
    }

    fn pick_once(&self, req: &PickRequest) -> Result<PickResponse, GatewayError> {
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
    fn report(&self, lease: &str, outcome: Outcome, windows: Vec<WindowReport>) {
        self.send_report(&ReportRequest {
            lease_id: Some(lease.to_owned()),
            login: None,
            outcome,
            model: None,
            windows,
            release: true,
        });
    }

    /// Reports one more `http_401` on `login` after its lease report, so qbd marks it
    /// `auth_dead` and the next pick of the turn skips it: the credential failed even after a
    /// refresh, or its file is unusable, and neither passes by itself.
    fn report_dead(&self, login: &str) {
        self.send_report(&ReportRequest {
            lease_id: None,
            login: Some(login.to_owned()),
            outcome: Outcome::Http401,
            model: None,
            windows: Vec::new(),
            release: false,
        });
    }

    fn send_report(&self, req: &ReportRequest) {
        let Ok(body) = serde_json::to_vec(req) else {
            return;
        };
        let of = req.lease_id.as_ref().or(req.login.as_ref());
        let of = of.map_or("", String::as_str);
        let socket = &self.startup.qbd_socket;
        match client::call(socket, "POST", paths::REPORT, Some(&body), self.bearer()) {
            Ok((200, _)) => {}
            Ok((status, resp)) => log::warn(&format!(
                "gateway: qbd report of {of} answered HTTP {status}: {}",
                String::from_utf8_lossy(&resp)
            )),
            Err(e) => log::warn(&format!("gateway: qbd report of {of}: {e}")),
        }
    }
}

/// The state of the logins of `config` of `vendor`, or of all of them, in `state`: `ready` when
/// one is usable, else `exhausted` with the nearest reset when one waits, else `unavailable`. A
/// login with a full window waits for its reset, as qbd does not pick it before.
fn standing(
    config: &GatewayConfig,
    state: &State,
    vendor: Option<&str>,
) -> (RouteState, Option<u64>) {
    let mut standing = (RouteState::Unavailable, None);
    for l in &state.logins {
        let ours = config.login(&l.login).is_some() && vendor.is_none_or(|v| v == l.vendor);
        if !ours {
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
/// and field: the listeners, the qbd connection, the spend file, and a credential file outside
/// the directories `opened` the sandbox opened at startup.
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
    let changed = [
        ("socket", old.socket != new.socket),
        ("socket_mode", old.socket_mode != new.socket_mode),
        ("qbd_socket", old.qbd_socket != new.qbd_socket),
        (
            "qbd_bearer_file",
            old.qbd_bearer_file != new.qbd_bearer_file,
        ),
        ("spend_file", old.spend_file != new.spend_file),
        ("fronts.listen", listen(old) != listen(new)),
    ];
    if let Some((field, _)) = changed.into_iter().find(|(_, c)| *c) {
        return fail(field.to_owned(), "changed");
    }
    for (i, login) in new.logins.iter().enumerate() {
        if !file_dir(&login.credentials).is_ok_and(|d| opened.contains(&d)) {
            let reason = "lies outside the credential directories the sandbox opened";
            return fail(format!("logins[{i}].credentials"), reason);
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
fn unpickable(p: &PickResponse, alias: &str) -> GatewayError {
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
fn redact(mut f: Failure, credential: &Credential) -> Failure {
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
