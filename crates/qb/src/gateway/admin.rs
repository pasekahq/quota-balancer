//! `qbd`'s `/v1/admin/*` forwarded for the gateway's own uid: each request goes to `qbd` as the
//! gateway, a `PUT` of the roles, a reload and a reset of logins leave an audit line.

use qb_proto::{AdminRolesWritten, AuditAction, ErrorBody, ErrorClass, ErrorCode, paths};

use super::Refusal;
use super::audit;
use super::core::Gateway;
use crate::client::{self, Answer};
use crate::http::{Method, Request};
use crate::log;

/// Who may call `qbd`'s admin API through the gateway.
const OWNER: &str = "only the gateway's own uid may call qbd's admin API";

/// Whether `path` is one of `qbd`'s admin endpoints the gateway forwards.
pub(crate) fn serves(path: &str) -> bool {
    matches!(
        path,
        paths::ADMIN_ROLES | paths::ADMIN_RELOAD | paths::ADMIN_LOGINS_RESET
    )
}

/// What `qbd` answered a forwarded request with 200: its `ETag` and its body.
pub(crate) struct Passed {
    /// `qbd`'s `ETag`, if it sent one.
    pub(crate) etag: Option<String>,
    /// `qbd`'s body, unchanged.
    pub(crate) body: Vec<u8>,
}

/// Forwards `req` of `actor` to one of [`serves`]'s paths to `qbd`; only the gateway's `own` uid
/// may. A `PUT` of the roles and a reload are recorded, refusals included.
///
/// # Errors
/// 403 `auth` for another caller, 405 for another method, 503 `unavailable` when `qbd` cannot be
/// asked, else `qbd`'s status with its message.
pub(crate) fn forward(
    gateway: &Gateway,
    req: &Request,
    actor: &str,
    own: bool,
) -> Result<Passed, Refusal> {
    let audited = match (req.method, req.path.as_str()) {
        (Method::Put, paths::ADMIN_ROLES) => Some(AuditAction::AdminRoles),
        (Method::Post, paths::ADMIN_RELOAD) => Some(AuditAction::AdminReload),
        (Method::Post, paths::ADMIN_LOGINS_RESET) => Some(AuditAction::AdminLoginsReset),
        _ => None,
    };
    let result = exchange(gateway, req, own);
    if let Some(action) = audited {
        let socket = gateway.config().qbd_socket.display().to_string();
        let mut entry = audit::entry(actor, action, Some(socket));
        match &result {
            Ok(passed) if action == AuditAction::AdminRoles => {
                if let Ok(written) = serde_json::from_slice::<AdminRolesWritten>(&passed.body) {
                    let before = req.if_match.as_deref().map(|t| t.trim_matches('"'));
                    entry.config_sha256_before = before.map(str::to_owned);
                    entry.config_sha256_after = Some(written.sha256);
                    entry.backup = written.backup;
                }
            }
            Ok(_) => {}
            Err(r) => entry = audit::refused(entry, r.message.clone()),
        }
        gateway.record(&entry);
    }
    result
}

/// [`forward`] without its audit line.
fn exchange(gateway: &Gateway, req: &Request, own: bool) -> Result<Passed, Refusal> {
    if !own {
        return Err(Refusal::new(403, ErrorClass::Auth, OWNER.to_owned()));
    }
    let (body, if_match) = match (req.method, req.path.as_str()) {
        (Method::Get, paths::ADMIN_ROLES) => (None, None),
        (Method::Put, paths::ADMIN_ROLES) => (Some(&req.body[..]), req.if_match.as_deref()),
        (Method::Post, paths::ADMIN_RELOAD | paths::ADMIN_LOGINS_RESET) => {
            (Some(&req.body[..]), None)
        }
        _ => {
            let message = "method not allowed".to_owned();
            return Err(Refusal::new(405, ErrorClass::BadRequest, message));
        }
    };
    let socket = &gateway.config().qbd_socket;
    let method = req.method.as_str();
    let answer = client::call_tagged(socket, method, &req.path, body, gateway.bearer(), if_match)
        .map_err(|e| {
        let message = format!("qbd is unreachable: {e}");
        log::warn(&format!("gateway: {method} {}: {message}", req.path));
        Refusal::new(503, ErrorClass::Unavailable, message)
    })?;
    match answer {
        Answer {
            status: 200,
            etag,
            body,
        } => Ok(Passed { etag, body }),
        Answer { status, body, .. } => Err(refusal_of(status, &body)),
    }
}

/// The refusal of `qbd`'s answer of `status` with `body`: the same status, the class of `qbd`'s
/// code and its message. A 403 says the gateway is not an admin client of `qbd`.
fn refusal_of(status: u16, body: &[u8]) -> Refusal {
    let Ok(e) = serde_json::from_slice::<ErrorBody>(body) else {
        let message = format!("qbd answered HTTP {status} without an error body");
        return Refusal::new(status, ErrorClass::Unavailable, message);
    };
    let (class, message) = match e.error {
        ErrorCode::Forbidden => (
            ErrorClass::Auth,
            format!(
                "qbd refused the gateway as an admin client: {}; the gateway's `[[clients]]` \
                 entry in qbd's config needs `admin = true`",
                e.message
            ),
        ),
        ErrorCode::Unauthorized => (ErrorClass::Auth, e.message),
        ErrorCode::TooManyRequests => (ErrorClass::Overloaded, e.message),
        ErrorCode::Internal => (ErrorClass::Unavailable, e.message),
        _ => (ErrorClass::BadRequest, e.message),
    };
    Refusal::new(status, class, message)
}
