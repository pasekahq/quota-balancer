//! The gateway core every front shares: admit a turn, then per attempt ask qbd for a login of
//! the route, load its credential, run the vendor adapter and report the outcome to qbd. A
//! login-local failure before any content event reached the client moves on to the next login
//! invisibly; after that, or when qbd has nothing left, the turn ends with an `error` event.

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use qb_proto::{
    Attempt, Block, Decision, ErrorClass, GatewayError, Outcome, PickRequest, PickResponse, Pin,
    ReportRequest, RouteInfo, RouteState, RouteStatus, RoutesAnswer, StreamEvent, TurnRequest,
    WindowReport, paths,
};
use zeroize::Zeroizing;

use super::config::{GatewayConfig, Route};
use super::creds::{CredentialStore, Refresher};
use super::upstream::{CancelToken, Failure, FailureKind, Finished, Flow, Picked, Upstream};
use crate::server::unix_now;
use crate::{client, log};

/// Most attempts of one turn; each is one pick, so this also bounds the leases a turn takes.
pub const MAX_ATTEMPTS: usize = 8;

/// Most sessions whose login the gateway remembers; the oldest is forgotten first.
pub const MAX_SESSIONS: usize = 256;

/// How long `cancel` waits for the cancelled turn to end.
pub const CANCEL_WAIT: Duration = Duration::from_secs(5);

/// `run_id` of the picks behind `GET /v1/model/routes`.
const ROUTES_RUN_ID: &str = "routes";

/// Vendor adapters by vendor name.
pub type Upstreams = Vec<(String, Box<dyn Upstream>)>;

/// The login a session last ran on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sticky {
    vendor: String,
    model: String,
    effort: Option<String>,
    login: String,
}

struct Running {
    turns: Mutex<Vec<(String, String, CancelToken)>>,
    ended: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A turn that passed admission: it counts against `max_turns` and can be cancelled until it is
/// dropped.
pub struct Admitted {
    client: String,
    request_id: String,
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

impl Drop for Admitted {
    fn drop(&mut self) {
        let mut turns = lock(&self.running.turns);
        turns.retain(|(c, r, _)| !(*c == self.client && *r == self.request_id));
        drop(turns);
        self.running.ended.notify_all();
    }
}

/// The gateway's shared state. One value serves every connection thread.
pub struct Gateway {
    config: GatewayConfig,
    media: Vec<PathBuf>,
    store: CredentialStore,
    upstreams: Upstreams,
    qbd_bearer: Option<Zeroizing<String>>,
    sessions: Mutex<Vec<(String, Sticky)>>,
    running: Arc<Running>,
}

fn bad_request(message: impl Into<String>) -> GatewayError {
    GatewayError::new(ErrorClass::BadRequest, false, message)
}

/// The qbd outcome, the client's error class and whether another login may succeed, for a
/// failure of `kind`.
fn classify(kind: FailureKind) -> (Outcome, ErrorClass, bool) {
    match kind {
        FailureKind::UsageLimit { .. } => (Outcome::UsageLimit, ErrorClass::QuotaExhausted, true),
        FailureKind::Auth => (Outcome::Http401, ErrorClass::Auth, true),
        FailureKind::RateLimited { .. } => (Outcome::Http429, ErrorClass::Overloaded, true),
        FailureKind::ModelUnavailable => (Outcome::ModelUnavailable, ErrorClass::Unavailable, true),
        FailureKind::Overloaded { .. } => (Outcome::Error, ErrorClass::Overloaded, false),
        FailureKind::Unavailable | FailureKind::Cancelled => {
            (Outcome::Error, ErrorClass::Unavailable, false)
        }
        FailureKind::BadRequest => (Outcome::Error, ErrorClass::BadRequest, false),
        FailureKind::ContextTooLong => (Outcome::Error, ErrorClass::ContextTooLong, false),
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

/// What a turn carries from one attempt to the next.
struct Progress {
    /// `client\nsession_key`, when the request names a session.
    session: Option<String>,
    /// The session's login, tried first on the first attempt only.
    sticky: Option<Sticky>,
    tried: Vec<Attempt>,
    /// Logins whose token the vendor rejected in this turn; refreshed before their next use.
    stale: Vec<String>,
}

/// What a turn does after an attempt.
enum Next {
    /// Pick again.
    Retry,
    /// The turn is over; the text goes to the log.
    Done(String),
}

/// Passes an adapter's events on: the held `route` event goes first, terminal and `route`
/// events of the adapter are dropped, `thinking` is stamped with the picked vendor.
struct Relay<'e> {
    route: Option<StreamEvent>,
    emitted: bool,
    gone: bool,
    emit: &'e mut dyn FnMut(StreamEvent) -> Flow,
}

impl Relay<'_> {
    fn send(&mut self, event: StreamEvent) -> Flow {
        if self.gone {
            return Flow::Stop;
        }
        if (self.emit)(event) == Flow::Stop {
            self.gone = true;
        }
        if self.gone {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }

    fn pass(&mut self, mut event: StreamEvent, vendor: &str, cancel: &CancelToken) -> Flow {
        if cancel.is_cancelled() {
            self.gone = true;
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

impl Gateway {
    /// A gateway for `config` with vendor adapters `upstreams`, OAuth refreshes through
    /// `refresher` and `qbd_bearer` for qbd, if qbd knows the gateway by token.
    pub fn new(
        mut config: GatewayConfig,
        upstreams: Upstreams,
        refresher: Box<dyn Refresher>,
        qbd_bearer: Option<Zeroizing<String>>,
    ) -> Self {
        // Sorted once by alias for `routes`; a handful of entries needs no generic sort.
        let routes = &mut config.routes;
        for i in 1..routes.len() {
            let mut j = i;
            while j > 0 && routes[j - 1].alias > routes[j].alias {
                routes.swap(j - 1, j);
                j -= 1;
            }
        }
        let media = config
            .media_dirs
            .iter()
            .map(|d| std::fs::canonicalize(d).unwrap_or_else(|_| d.clone()))
            .collect();
        Self {
            config,
            media,
            store: CredentialStore::new(refresher),
            upstreams,
            qbd_bearer,
            sessions: Mutex::new(Vec::new()),
            running: Arc::new(Running {
                turns: Mutex::new(Vec::new()),
                ended: Condvar::new(),
            }),
        }
    }

    /// The config the gateway runs with.
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Admits `client`'s turn `req`: valid, a known route, images beneath `media_dirs`, its
    /// `request_id` not running for `client`, and fewer than `max_turns` turns running.
    ///
    /// # Errors
    /// `bad_request` for an invalid request, `overloaded` at the turn limit.
    pub fn admit(&self, client: &str, req: &TurnRequest) -> Result<Admitted, GatewayError> {
        req.validate().map_err(|e| bad_request(e.0))?;
        let route = self
            .config
            .route(&req.route)
            .ok_or_else(|| bad_request(format!("unknown route alias `{}`", req.route)))?;
        for block in req.messages.iter().flat_map(|m| &m.content) {
            if let Block::Image {
                path: Some(path), ..
            } = block
            {
                let real = std::fs::canonicalize(path)
                    .map_err(|_| bad_request(format!("image `{path}` cannot be resolved")))?;
                if !self.media.iter().any(|d| real.starts_with(d)) {
                    return Err(bad_request(format!(
                        "image `{path}` is outside the gateway's media_dirs"
                    )));
                }
            }
        }
        let mut turns = lock(&self.running.turns);
        if turns
            .iter()
            .any(|(c, r, _)| c == client && *r == req.request_id)
        {
            return Err(bad_request(format!(
                "turn `{}` is already running",
                req.request_id
            )));
        }
        if turns.len() >= self.config.max_turns as usize {
            let mut e = GatewayError::new(
                ErrorClass::Overloaded,
                true,
                "the gateway runs its maximum number of turns",
            );
            e.retry_after = Some(1);
            return Err(e);
        }
        let cancel = CancelToken::new();
        turns.push((client.to_owned(), req.request_id.clone(), cancel.clone()));
        Ok(Admitted {
            client: client.to_owned(),
            request_id: req.request_id.clone(),
            route: route.clone(),
            cancel,
            running: Arc::clone(&self.running),
        })
    }

    /// Stops `client`'s running turn `request_id` and waits up to [`CANCEL_WAIT`] for it to
    /// end. Returns whether such a turn was running.
    pub fn cancel(&self, client: &str, request_id: &str) -> bool {
        let deadline = Instant::now() + CANCEL_WAIT;
        let running = |turns: &[(String, String, CancelToken)]| {
            turns.iter().any(|(c, r, _)| c == client && r == request_id)
        };
        let mut turns = lock(&self.running.turns);
        let Some((_, _, token)) = turns
            .iter()
            .find(|(c, r, _)| c == client && r == request_id)
        else {
            return false;
        };
        token.cancel();
        while running(&turns) {
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
        true
    }

    /// Runs an admitted turn, handing `emit` its events: `route`, content events, then one
    /// `stop` or `error`, or nothing more once `emit` returns [`Flow::Stop`] or it is cancelled.
    pub fn run(
        &self,
        turn: &Admitted,
        req: &TurnRequest,
        emit: &mut dyn FnMut(StreamEvent) -> Flow,
    ) {
        let session = req
            .session_key
            .as_ref()
            .map(|k| format!("{}\n{k}", turn.client));
        let mut progress = Progress {
            sticky: session.as_ref().and_then(|k| self.sticky(k)),
            session,
            tried: Vec::new(),
            stale: Vec::new(),
        };
        for _ in 0..MAX_ATTEMPTS {
            if turn.cancel.is_cancelled() {
                return turn.log("cancelled");
            }
            match self.attempt(turn, req, &mut progress, emit) {
                Next::Retry => {}
                Next::Done(what) => return turn.log(&what),
            }
        }
        let mut error = GatewayError::new(
            ErrorClass::Unavailable,
            true,
            format!("gave up after {MAX_ATTEMPTS} attempts"),
        );
        error.tried = progress.tried;
        emit(StreamEvent::Error { error });
        turn.log("too many attempts");
    }

    /// One pick and, when it runs, one adapter call.
    fn attempt(
        &self,
        turn: &Admitted,
        req: &TurnRequest,
        progress: &mut Progress,
        emit: &mut dyn FnMut(StreamEvent) -> Flow,
    ) -> Next {
        let mut fail = |mut error: GatewayError, progress: &mut Progress, what: &str| {
            error.tried = std::mem::take(&mut progress.tried);
            emit(StreamEvent::Error { error });
            Next::Done(what.to_owned())
        };
        let now = unix_now();
        let sticky = progress.sticky.take();
        let pick = match self.pick(&turn.route, &req.request_id, sticky.as_ref()) {
            Ok(p) => p,
            Err(e) => return fail(e, progress, "qbd failed"),
        };
        let (Decision::Run, Some(lease), Some(vendor), Some(model), Some(login)) = (
            pick.decision,
            pick.lease_id.clone(),
            pick.vendor.clone(),
            pick.model.clone(),
            pick.login.clone(),
        ) else {
            let error = unpickable(&pick, now, &progress.tried, &turn.route.alias);
            let what = format!("{} ({})", error.class.as_str(), pick.reason);
            return fail(error, progress, &what);
        };
        let Some(file) = self.config.credentials(&login) else {
            self.report(&lease, Outcome::Error, Vec::new());
            let message = format!("login `{login}` has no credential file in the gateway config");
            let error = GatewayError::new(ErrorClass::Unavailable, false, message);
            return fail(error, progress, "login without credentials");
        };
        let attempt = Attempt {
            vendor,
            model,
            login_label: Some(login.clone()),
            class: ErrorClass::Auth,
        };
        let credential = match self
            .store
            .load(&login, file, now, progress.stale.contains(&login))
        {
            Ok(c) => c,
            Err(e) => {
                log::warn(&format!("gateway: {e}"));
                progress.tried.push(attempt);
                if e.unusable {
                    self.report(&lease, Outcome::Http401, Vec::new());
                    return Next::Retry;
                }
                self.report(&lease, Outcome::Error, Vec::new());
                let message = "a login's credential could not be refreshed";
                let error = GatewayError::new(ErrorClass::Unavailable, true, message);
                return fail(error, progress, "credential refresh failed");
            }
        };
        let Some((_, upstream)) = self.upstreams.iter().find(|(v, _)| *v == attempt.vendor) else {
            drop(credential);
            self.report(&lease, Outcome::Error, Vec::new());
            let message = format!("no adapter serves vendor `{}`", attempt.vendor);
            let error = GatewayError::new(ErrorClass::Unavailable, false, message);
            return fail(error, progress, "no adapter");
        };
        let at = Picked {
            vendor: &attempt.vendor,
            model: &attempt.model,
            effort: pick.effort.as_deref(),
            login: &login,
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
            gone: false,
            emit,
        };
        let result = upstream.turn(
            &at,
            &credential,
            &own_thinking(req, at.vendor),
            &mut |e| relay.pass(e, at.vendor, &turn.cancel),
            &turn.cancel,
        );
        drop(credential);
        let sticky = Sticky {
            vendor: attempt.vendor.clone(),
            model: attempt.model.clone(),
            effort: pick.effort.clone(),
            login,
        };
        self.settle(turn, &lease, result, relay, attempt, sticky, progress)
    }

    /// Reports how an adapter call ended and decides what the turn does next.
    #[allow(clippy::too_many_arguments)] // the pieces of one attempt, each used once
    fn settle(
        &self,
        turn: &Admitted,
        lease: &str,
        result: Result<Finished, Failure>,
        mut relay: Relay<'_>,
        mut attempt: Attempt,
        sticky: Sticky,
        progress: &mut Progress,
    ) -> Next {
        let gone = relay.gone || turn.cancel.is_cancelled();
        let failure = match result {
            Ok(done) => {
                self.report(lease, Outcome::Ok, done.windows);
                if gone {
                    return Next::Done("cut".into());
                }
                if let Some(route) = relay.route.take() {
                    relay.send(route);
                }
                relay.send(StreamEvent::Stop { reason: done.stop });
                let what = format!("{} on {}", done.stop.as_str(), sticky.login);
                if let Some(key) = progress.session.take() {
                    self.remember(key, sticky);
                }
                return Next::Done(what);
            }
            Err(f) => f,
        };
        let (outcome, class, rotates) = classify(failure.kind);
        self.report(lease, outcome, failure.windows);
        if gone || failure.kind == FailureKind::Cancelled {
            return Next::Done("cut".into());
        }
        log::warn(&format!(
            "gateway: turn {} on {}: {}: {}",
            turn.request_id,
            sticky.login,
            failure.kind.as_str(),
            failure.message
        ));
        attempt.class = class;
        progress.tried.push(attempt);
        if failure.kind == FailureKind::Auth {
            progress.stale.push(sticky.login);
        }
        if rotates && !relay.emitted {
            return Next::Retry;
        }
        let retryable = matches!(class, ErrorClass::Overloaded | ErrorClass::Unavailable);
        let mut error = GatewayError::new(class, retryable, failure.message);
        match failure.kind {
            FailureKind::UsageLimit { resets_at } => error.resets_at = resets_at,
            FailureKind::RateLimited { retry_after } | FailureKind::Overloaded { retry_after } => {
                error.retry_after = retry_after;
            }
            _ => {}
        }
        error.tried = std::mem::take(&mut progress.tried);
        relay.send(StreamEvent::Error { error });
        Next::Done(class.as_str().to_owned())
    }

    /// Where a turn on each route would run now, by a pick that is released at once; sorted by
    /// alias.
    pub fn routes(&self) -> RoutesAnswer {
        let routes = self
            .config
            .routes
            .iter()
            .map(|r| {
                let mut status = RouteStatus {
                    alias: r.alias.clone(),
                    state: RouteState::Unavailable,
                    vendor: None,
                    model: None,
                    resets_at: None,
                };
                let Ok(p) = self.pick_once(&Self::request(r, ROUTES_RUN_ID, None)) else {
                    return status;
                };
                match (p.decision, p.reason.as_str()) {
                    (Decision::Run, reason) => {
                        if let Some(lease) = &p.lease_id {
                            self.report(lease, Outcome::Error, Vec::new());
                        }
                        status.state = if reason == "neighbour_step" {
                            RouteState::Degraded
                        } else {
                            RouteState::Ready
                        };
                        status.vendor = p.vendor;
                        status.model = p.model;
                    }
                    (Decision::Wait, "leases_full") => status.state = RouteState::Ready,
                    (Decision::Wait, _) => {
                        status.state = RouteState::Exhausted;
                        status.resets_at = p.retry_after;
                    }
                    (Decision::Dead, "no_reset_known") => status.state = RouteState::Exhausted,
                    (Decision::Dead, _) => {}
                }
                status
            })
            .collect();
        RoutesAnswer { routes }
    }

    fn request(route: &Route, run_id: &str, sticky: Option<&Sticky>) -> PickRequest {
        let (difficulty, pin) = match sticky {
            Some(s) => (
                None,
                Some(Pin {
                    vendor: s.vendor.clone(),
                    model: s.model.clone(),
                    effort: s.effort.clone(),
                    login: Some(s.login.clone()),
                }),
            ),
            None => (route.difficulty, route.pin()),
        };
        PickRequest {
            role: route.role.clone(),
            difficulty,
            pin,
            resume_of: None,
            avoid_vendor: None,
            need: Vec::new(),
            expected_minutes: route.expected_minutes,
            run_id: Some(run_id.to_owned()),
        }
    }

    /// A pick for `route`; the session's login first when `sticky` names one and it can run.
    fn pick(
        &self,
        route: &Route,
        run_id: &str,
        sticky: Option<&Sticky>,
    ) -> Result<PickResponse, GatewayError> {
        if sticky.is_some() {
            let p = self.pick_once(&Self::request(route, run_id, sticky))?;
            if p.decision == Decision::Run {
                return Ok(p);
            }
        }
        self.pick_once(&Self::request(route, run_id, None))
    }

    fn pick_once(&self, req: &PickRequest) -> Result<PickResponse, GatewayError> {
        let unavailable = |m: String| GatewayError::new(ErrorClass::Unavailable, true, m);
        let body = serde_json::to_vec(req).map_err(|e| unavailable(e.to_string()))?;
        let (status, resp) = client::call(
            &self.config.qbd_socket,
            "POST",
            paths::PICK,
            Some(&body),
            self.qbd_bearer.as_ref().map(|b| b.as_str()),
        )
        .map_err(|e| {
            log::warn(&format!("gateway: qbd pick: {e}"));
            unavailable("qbd is unreachable".into())
        })?;
        match status {
            200 => serde_json::from_slice(&resp)
                .map_err(|e| unavailable(format!("qbd answered an invalid pick: {e}"))),
            429 => {
                let mut e =
                    GatewayError::new(ErrorClass::Overloaded, true, "qbd rate-limits the gateway");
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
        let req = ReportRequest {
            lease_id: Some(lease.to_owned()),
            login: None,
            outcome,
            model: None,
            windows,
            release: true,
        };
        let Ok(body) = serde_json::to_vec(&req) else {
            return;
        };
        match client::call(
            &self.config.qbd_socket,
            "POST",
            paths::REPORT,
            Some(&body),
            self.qbd_bearer.as_ref().map(|b| b.as_str()),
        ) {
            Ok((200, _)) => {}
            Ok((status, resp)) => log::warn(&format!(
                "gateway: qbd report of {lease} answered HTTP {status}: {}",
                String::from_utf8_lossy(&resp)
            )),
            Err(e) => log::warn(&format!("gateway: qbd report of {lease}: {e}")),
        }
    }

    fn sticky(&self, key: &str) -> Option<Sticky> {
        lock(&self.sessions)
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, s)| s.clone())
    }

    fn remember(&self, key: String, sticky: Sticky) {
        let mut sessions = lock(&self.sessions);
        sessions.retain(|(k, _)| *k != key);
        if sessions.len() >= MAX_SESSIONS {
            sessions.remove(0);
        }
        sessions.push((key, sticky));
    }
}

/// The error for a pick that is not `run`: `quota_exhausted` with the nearest reset while every
/// candidate waits for one, `overloaded` while they wait only for back-offs or leases, `auth` or
/// `unavailable` when nothing can run.
fn unpickable(p: &PickResponse, now: u64, tried: &[Attempt], alias: &str) -> GatewayError {
    let backed_off = !tried.is_empty() && tried.iter().all(|a| a.class == ErrorClass::Overloaded);
    let quota = || {
        let mut e = GatewayError::new(
            ErrorClass::QuotaExhausted,
            false,
            format!("every login of route `{alias}` is out of quota"),
        );
        e.resets_at = p.retry_after;
        e
    };
    match (p.decision, p.reason.as_str()) {
        (Decision::Wait, reason) if reason == "leases_full" || backed_off => {
            let mut e = GatewayError::new(
                ErrorClass::Overloaded,
                true,
                format!("every login of route `{alias}` is backing off"),
            );
            e.retry_after = Some(p.retry_after.map_or(1, |at| at.saturating_sub(now).max(1)));
            e
        }
        (Decision::Wait, _) | (Decision::Dead, "no_reset_known") => quota(),
        (Decision::Dead, "all_dead") => {
            let class = if tried.iter().any(|a| a.class == ErrorClass::Auth) {
                ErrorClass::Auth
            } else {
                ErrorClass::Unavailable
            };
            GatewayError::new(
                class,
                false,
                format!("every login of route `{alias}` needs a new sign-in or lacks the model"),
            )
        }
        _ => GatewayError::new(
            ErrorClass::Unavailable,
            false,
            format!("qbd has no candidate for route `{alias}` ({})", p.reason),
        ),
    }
}
