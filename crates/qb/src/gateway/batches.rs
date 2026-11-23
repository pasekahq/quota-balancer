//! Anthropic Message Batches on `api_key` logins: `POST /v1/model/batches` creates one on the
//! login qbd picks for a route, `GET /v1/model/batches/{batch_id}` reads its status through the
//! same login. The store binds each batch to its caller, login and idempotency key; it is one
//! JSON file replaced by rename (mode 0600) on each change.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use qb_anthropic::limits;
use qb_anthropic::request::AuthMode;
use qb_proto::{
    BatchCounts, BatchProcessing, BatchStatus, BatchSubmit, Decision, ErrorClass, GatewayError,
    Object, Outcome, PickRequest, WindowReport,
};
use qb_vendors::rfc3339;
use serde::{Deserialize, Serialize};

use super::anthropic::{self, DEFAULT_BASE_URL};
use super::config::{Api, CredentialKind, GatewayConfig, GatewayLogin, Route};
use super::core::{Gateway, redact, refusal, unpickable};
use super::creds;
use super::upstream::{CancelToken, Failure};
use super::vendor::{self, Request};
use crate::rewrite::write_atomic;
use crate::server::unix_now;
use crate::{log, sha256};

/// Path of the Message Batches API below the base URL.
const BATCHES_PATH: &str = "/v1/messages/batches";

/// A refusal or failure: the answer's status and its body.
pub(super) type Refused = (u16, GatewayError);

fn refused(status: u16, class: ErrorClass, message: impl Into<String>) -> Refused {
    (status, GatewayError::new(class, false, message))
}

fn no_store() -> Refused {
    let message = "this gateway runs no batches: its config has no `[batches]` table";
    refused(404, ErrorClass::BadRequest, message)
}

/// One batch the gateway created, or a submit whose create request is under way or ended
/// without a known outcome: then `batch_id` is absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batch_id: Option<String>,
    client: String,
    route: String,
    login: String,
    model: String,
    idempotency_key: String,
    /// Hex SHA-256 of the submit's body.
    body_sha256: String,
    /// Unix time of the submit.
    created_at: u64,
}

/// The file's contents.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    batches: Vec<Record>,
}

struct State {
    records: Vec<Record>,
    /// `(client, idempotency_key)` of the submits running now.
    running: Vec<(String, String)>,
}

/// The batch store of `[batches]`.
pub(super) struct Store {
    file: PathBuf,
    state: Mutex<State>,
}

/// What a submit's idempotency key found.
enum Found<'s> {
    /// The batch an earlier submit of the same body created, and its id.
    Batch(String, Record),
    /// Nothing: the key is the caller's until the claim drops.
    Claimed(Claim<'s>),
}

/// A running submit's hold on its `(client, idempotency_key)`; dropping it lets the key go.
struct Claim<'s> {
    store: &'s Store,
    client: String,
    key: String,
}

impl Store {
    /// The store in `file`; a missing file holds no batch.
    ///
    /// # Errors
    /// The file cannot be read or is not a batch store.
    pub(super) fn open(file: &Path) -> Result<Self, String> {
        let records = match std::fs::read(file) {
            Ok(bytes) => {
                serde_json::from_slice::<Stored>(&bytes)
                    .map_err(|e| format!("{}: not a batch store: {e}", file.display()))?
                    .batches
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("{}: {e}", file.display())),
        };
        Ok(Self {
            file: file.to_owned(),
            state: Mutex::new(State {
                records,
                running: Vec::new(),
            }),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes `records` to the file.
    fn save(&self, records: &[Record]) -> Result<(), String> {
        let stored = Stored {
            batches: records.to_vec(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|e| e.to_string())?;
        write_atomic(&self.file, &bytes).map_err(|e| format!("{}: {e}", self.file.display()))
    }

    /// The record of the batch `batch_id`.
    fn find(&self, batch_id: &str) -> Option<Record> {
        let state = self.state();
        let found = state
            .records
            .iter()
            .find(|r| r.batch_id.as_deref() == Some(batch_id));
        found.cloned()
    }

    /// Looks up `client`'s `key` for a body of hash `sha`: its batch, or a claim on the key.
    ///
    /// # Errors
    /// 409 when a submit with the key is running, the key was used with another body, or its
    /// earlier submit has no known outcome.
    fn claim(&self, client: &str, key: &str, sha: &str) -> Result<Found<'_>, Refused> {
        let mut state = self.state();
        let taken = |c: &str, k: &str| c == client && k == key;
        let conflict = |message: String| refused(409, ErrorClass::BadRequest, message);
        // Before the records: a running submit's pending record is no unknown outcome yet.
        if state.running.iter().any(|(c, k)| taken(c, k)) {
            return Err(conflict(format!(
                "a submit with idempotency_key `{key}` is running"
            )));
        }
        if let Some(r) = state
            .records
            .iter()
            .find(|r| taken(&r.client, &r.idempotency_key))
        {
            if r.body_sha256 != sha {
                return Err(conflict(format!(
                    "idempotency_key `{key}` was used with another body"
                )));
            }
            return match &r.batch_id {
                Some(id) => Ok(Found::Batch(id.clone(), r.clone())),
                None => Err(conflict(format!(
                    "the outcome of the earlier submit with idempotency_key `{key}` is unknown: it \
                     may have created a batch on login `{}`; submit with a new key",
                    r.login
                ))),
            };
        }
        state.running.push((client.to_owned(), key.to_owned()));
        Ok(Found::Claimed(Claim {
            store: self,
            client: client.to_owned(),
            key: key.to_owned(),
        }))
    }
}

impl Claim<'_> {
    fn ours(&self, r: &Record) -> bool {
        r.client == self.client && r.idempotency_key == self.key
    }

    /// Stores `record`, which has no `batch_id`, before its create request goes out.
    ///
    /// # Errors
    /// The file could not be written; the store stays as it was.
    fn pending(&self, record: Record) -> Result<(), String> {
        let mut state = self.store.state();
        state.records.push(record);
        let saved = self.store.save(&state.records);
        if saved.is_err() {
            state.records.pop();
        }
        saved
    }

    /// Binds the pending record to the vendor's `batch_id`.
    ///
    /// # Errors
    /// The file could not be written; the bound record stays in memory, so a repeat answers it
    /// until a restart.
    fn bind(&self, batch_id: &str) -> Result<(), String> {
        let mut state = self.store.state();
        for r in state.records.iter_mut().filter(|r| self.ours(r)) {
            r.batch_id = Some(batch_id.to_owned());
        }
        self.store.save(&state.records)
    }

    /// Removes the pending record of a create the vendor refused, so the key may be used again.
    fn forget(&self) {
        let mut state = self.store.state();
        state.records.retain(|r| !self.ours(r));
        if let Err(e) = self.store.save(&state.records) {
            log::error(&format!("gateway: batch store: {e}"));
        }
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        let mut state = self.store.state();
        state
            .running
            .retain(|(c, k)| c != &self.client || k != &self.key);
    }
}

/// The vendor's `message_batch` object, the fields the gateway reads.
#[derive(Deserialize)]
struct MessageBatch {
    id: String,
    processing_status: BatchProcessing,
    request_counts: BatchCounts,
    created_at: String,
    ended_at: Option<String>,
    expires_at: String,
}

/// The body of the vendor's create request: each request's `params` with `model` first.
#[derive(Serialize)]
struct Create<'a> {
    requests: Vec<CreateRequest<'a>>,
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    custom_id: &'a str,
    params: Params<'a>,
}

#[derive(Serialize)]
struct Params<'a> {
    model: &'a str,
    #[serde(flatten)]
    rest: &'a Object,
}

/// The status of `record`'s batch from the vendor's `batch` object.
fn status(record: &Record, batch: MessageBatch) -> Result<BatchStatus, String> {
    let time = |field: &str, text: &str| {
        rfc3339::parse(text).map_err(|e| format!("the vendor's batch `{field}`: {e}"))
    };
    Ok(BatchStatus {
        created_at: time("created_at", &batch.created_at)?,
        ended_at: batch.ended_at.map(|t| time("ended_at", &t)).transpose()?,
        expires_at: time("expires_at", &batch.expires_at)?,
        batch_id: batch.id,
        route: record.route.clone(),
        login: record.login.clone(),
        model: record.model.clone(),
        processing_status: batch.processing_status,
        request_counts: batch.request_counts,
    })
}

/// Whether `login` may run batches: an `api_key` login of the Anthropic API family.
fn runs_batches(login: &GatewayLogin) -> bool {
    login.kind == CredentialKind::ApiKey && login.api == Api::Anthropic
}

/// The logins of `route` that may run batches, every login of `config` when it lists none.
fn batch_logins(config: &GatewayConfig, route: &Route) -> Vec<String> {
    let listed = |name: &str| {
        route
            .logins
            .as_ref()
            .is_none_or(|names| names.iter().any(|n| n == name))
    };
    config
        .logins
        .iter()
        .filter(|l| listed(&l.name) && runs_batches(l))
        .map(|l| l.name.clone())
        .collect()
}

/// How a vendor request on a login ended.
enum Sent {
    /// 200 with the batch object.
    Batch(MessageBatch, Vec<WindowReport>),
    /// The vendor refused it.
    Failed(Failure),
    /// It never went out: the credential could not be read.
    Unsent(String),
    /// No answer that tells the outcome: the request failed or the body is not a batch.
    Lost(String),
}

/// Sends a request of the Message Batches API at `path` below the base URL of `login`: a `POST`
/// of `body`, else a `GET`.
fn call(gateway: &Gateway, login: &GatewayLogin, path: &str, body: Option<Vec<u8>>) -> Sent {
    let credential = match gateway.credential(login, unix_now()) {
        Ok(c) => c,
        Err(message) => return Sent::Unsent(message),
    };
    let base = login.base_url.as_deref().unwrap_or(DEFAULT_BASE_URL);
    let url = format!("{base}{path}");
    let headers = AuthMode::ApiKey.headers();
    let post = body.is_some();
    let request = Request {
        url: &url,
        headers: headers
            .iter()
            .filter(|(n, _)| *n != "accept" && (post || *n != "content-type"))
            .map(|(n, v)| (*n, v.as_str()))
            .collect(),
        secret_header: AuthMode::ApiKey.secret_header(),
        body: body.unwrap_or_default(),
    };
    let config = vendor::attempt_config();
    let cancel = CancelToken::new();
    let sent = if post {
        vendor::send(&config, request, credential.secret(), &cancel)
    } else {
        vendor::get(&config, &request, credential.secret(), &cancel)
    };
    let read = sent.and_then(|mut answer| {
        let body = answer.short_body(&cancel)?;
        Ok((
            answer.status,
            limits::rate_limits(&answer.headers()),
            answer,
            body,
        ))
    });
    let (status, rate, answer, body) = match read {
        Ok(read) => read,
        Err(f) => return Sent::Lost(redact(f, &credential).message),
    };
    if status != 200 {
        let f = limits::classify_response(status, &answer.headers(), &body);
        return Sent::Failed(redact(anthropic::failure(f), &credential));
    }
    match serde_json::from_slice::<MessageBatch>(&body) {
        Ok(batch) => Sent::Batch(batch, rate.windows),
        Err(e) => Sent::Lost(format!("the vendor answered 200 without a batch: {e}")),
    }
}

/// Answers `POST /v1/model/batches` of `client` with `body`: creates the batch on a login qbd
/// picks among the route's `api_key` Anthropic logins and stores it before the answer, or
/// answers the batch an earlier submit of the same body and key created.
///
/// # Errors
/// 404 without `[batches]`; 400 a body that does not validate, an unknown or chain route, a
/// route without an `api_key` Anthropic login; 409 a key used with another body, an earlier
/// submit of unknown outcome or a running one; qbd's and the vendor's refusals; 502 a create
/// whose outcome is unknown; 500 the store could not be written.
pub(super) fn submit(gateway: &Gateway, client: &str, body: &[u8]) -> Result<BatchStatus, Refused> {
    let store = gateway.batches().ok_or_else(no_store)?;
    let bad = |message: String| refused(400, ErrorClass::BadRequest, message);
    let submit: BatchSubmit = serde_json::from_slice(body).map_err(|e| bad(e.to_string()))?;
    submit.validate().map_err(bad)?;
    let sha = sha256::hex(sha256::digest(body));
    let claim = match store.claim(client, &submit.idempotency_key, &sha)? {
        Found::Batch(batch_id, record) => return read(gateway, &record, &batch_id),
        Found::Claimed(claim) => claim,
    };
    let config = gateway.config();
    let alias = submit.route.as_str();
    let route = config
        .route(alias)
        .ok_or_else(|| bad(format!("unknown route alias `{alias}`")))?;
    if !route.chain.is_empty() {
        return Err(bad(format!(
            "route `{alias}` is a chain route; a batch runs on a pin or ladder route"
        )));
    }
    let logins = batch_logins(&config, route);
    if logins.is_empty() {
        return Err(bad(format!(
            "route `{alias}` has no `api_key` Anthropic login; OAuth logins cannot run batches"
        )));
    }
    let pick = gateway
        .pick_once(&PickRequest {
            role: route.role.clone(),
            difficulty: route.difficulty,
            pin: route.pin(0),
            resume_of: None,
            avoid_vendor: None,
            need: Vec::new(),
            expected_minutes: route.expected_minutes,
            run_id: Some(submit.idempotency_key.clone()),
            on_behalf_of: Some(client.to_owned()),
            logins: Some(logins.clone()),
        })
        .map_err(|e| (e.class.http_status(), e))?;
    let (Decision::Run, Some(lease), Some(model), Some(login)) = (
        pick.decision,
        pick.lease_id.as_deref(),
        pick.model.as_deref(),
        pick.login.as_deref(),
    ) else {
        let e = unpickable(&pick, alias);
        return Err((e.class.http_status(), e));
    };
    let Some(entry) = config.login(login).filter(|l| logins.contains(&l.name)) else {
        gateway.report(lease, Outcome::Error, Vec::new());
        let message = format!("qbd picked login `{login}`, which cannot run batches");
        return Err(refused(502, ErrorClass::Unavailable, message));
    };
    let record = Record {
        batch_id: None,
        client: client.to_owned(),
        route: alias.to_owned(),
        login: login.to_owned(),
        model: model.to_owned(),
        idempotency_key: submit.idempotency_key.clone(),
        body_sha256: sha,
        created_at: unix_now(),
    };
    if let Err(e) = claim.pending(record.clone()) {
        gateway.report(lease, Outcome::Error, Vec::new());
        log::error(&format!("gateway: batch store: {e}"));
        let message = format!("cannot write the batch store: {e}");
        return Err(refused(500, ErrorClass::Unavailable, message));
    }
    let create = Create {
        requests: submit
            .requests
            .iter()
            .map(|r| CreateRequest {
                custom_id: &r.custom_id,
                params: Params {
                    model,
                    rest: &r.params,
                },
            })
            .collect(),
    };
    let fingerprint = creds::fingerprint(&entry.credentials);
    let sent = match serde_json::to_vec(&create) {
        Ok(body) => call(gateway, entry, BATCHES_PATH, Some(body)),
        Err(e) => Sent::Unsent(e.to_string()),
    };
    created(gateway, (lease, &fingerprint), &claim, &record, sent)
}

/// Reports the create request `sent` of the submit `record` on lease `lease` and stores or forgets
/// the batch; `fp` is the fingerprint of the credential file it read.
fn created(
    gateway: &Gateway,
    (lease, fp): (&str, &str),
    claim: &Claim<'_>,
    record: &Record,
    sent: Sent,
) -> Result<BatchStatus, Refused> {
    let (key, login) = (&record.idempotency_key, &record.login);
    let batch = match sent {
        Sent::Batch(batch, windows) => {
            gateway.report(lease, Outcome::Ok, windows);
            batch
        }
        Sent::Failed(f) => {
            let (outcome, e) = refusal(&f);
            gateway.report_attempt(lease, login, outcome, f.windows, fp);
            claim.forget();
            log::warn(&format!(
                "gateway: batch `{key}` of {} on {login}: {}: {}",
                record.client,
                f.kind.as_str(),
                f.message
            ));
            return Err((e.class.http_status(), e));
        }
        Sent::Unsent(message) => {
            gateway.report(lease, Outcome::Error, Vec::new());
            claim.forget();
            log::warn(&format!(
                "gateway: batch `{key}` of {} on {login}: not sent: {message}",
                record.client
            ));
            return Err(refused(502, ErrorClass::Unavailable, message));
        }
        Sent::Lost(message) => {
            gateway.report(lease, Outcome::Error, Vec::new());
            log::warn(&format!(
                "gateway: batch `{key}` of {} on {login}: outcome unknown: {message}",
                record.client
            ));
            let message = format!(
                "the outcome of the batch create is unknown ({message}); idempotency_key `{key}` \
                 stays refused"
            );
            return Err(refused(502, ErrorClass::Unavailable, message));
        }
    };
    if let Err(e) = claim.bind(&batch.id) {
        log::error(&format!("gateway: batch store: {e}"));
        let message = format!(
            "batch `{}` was created but the batch store could not be written: {e}",
            batch.id
        );
        return Err(refused(500, ErrorClass::Unavailable, message));
    }
    log::info(&format!(
        "gateway: batch {} of {} created on {login}",
        batch.id, record.client
    ));
    status(record, batch).map_err(|e| refused(502, ErrorClass::Unavailable, e))
}

/// Answers `GET /v1/model/batches/{batch_id}` of `client`, the gateway's own uid when `own`.
///
/// # Errors
/// 404 without `[batches]` or for an unknown batch, 403 another caller's batch, as [`read`].
pub(super) fn get(
    gateway: &Gateway,
    client: &str,
    own: bool,
    batch_id: &str,
) -> Result<BatchStatus, Refused> {
    let store = gateway.batches().ok_or_else(no_store)?;
    let record = store.find(batch_id).ok_or_else(|| {
        refused(
            404,
            ErrorClass::BadRequest,
            format!("no batch `{batch_id}`"),
        )
    })?;
    if record.client != client && !own {
        let message = format!("batch `{batch_id}` belongs to another caller");
        return Err(refused(403, ErrorClass::Auth, message));
    }
    read(gateway, &record, batch_id)
}

/// The vendor's status of the batch `batch_id` of `record`, read through its login without a
/// pick.
///
/// # Errors
/// 409 a login no longer in the config or no longer an `api_key` Anthropic login, the vendor's
/// refusal, 502 no answer or one without a batch.
fn read(gateway: &Gateway, record: &Record, batch_id: &str) -> Result<BatchStatus, Refused> {
    let config = gateway.config();
    let login = &record.login;
    let entry = config.login(login).filter(|l| runs_batches(l)).ok_or_else(|| {
        let message = format!(
            "login `{login}` of the batch is no longer an `api_key` Anthropic login of the config"
        );
        refused(409, ErrorClass::Unavailable, message)
    })?;
    match call(gateway, entry, &format!("{BATCHES_PATH}/{batch_id}"), None) {
        Sent::Batch(batch, _) => {
            status(record, batch).map_err(|e| refused(502, ErrorClass::Unavailable, e))
        }
        Sent::Failed(f) => {
            let e = refusal(&f).1;
            Err((e.class.http_status(), e))
        }
        Sent::Unsent(message) | Sent::Lost(message) => {
            Err(refused(502, ErrorClass::Unavailable, message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_keeps_its_records_across_opens() {
        let dir = crate::testdir::new("batches");
        let file = dir.join("batches.json");
        let store = Store::open(&file).unwrap();
        let Ok(Found::Claimed(claim)) = store.claim("client-a", "key-1", "aa") else {
            panic!("a fresh key is claimed");
        };
        let record = Record {
            batch_id: None,
            client: "client-a".into(),
            route: "batch".into(),
            login: "key-1".into(),
            model: "model-large".into(),
            idempotency_key: "key-1".into(),
            body_sha256: "aa".into(),
            created_at: 1_800_000_000,
        };
        claim.pending(record.clone()).unwrap();
        claim.bind("msgbatch_1").unwrap();
        drop(claim);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&file).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        let again = Store::open(&file).unwrap();
        let bound = Record {
            batch_id: Some("msgbatch_1".into()),
            ..record
        };
        assert_eq!(again.find("msgbatch_1"), Some(bound.clone()));
        assert!(matches!(
            again.claim("client-a", "key-1", "aa"),
            Ok(Found::Batch(id, r)) if id == "msgbatch_1" && r == bound
        ));
        assert!(matches!(
            again.claim("client-b", "key-1", "bb"),
            Ok(Found::Claimed(_))
        ));
        std::fs::write(&file, "{}").unwrap();
        let e = Store::open(&file).err().unwrap();
        assert!(e.contains("not a batch store"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
