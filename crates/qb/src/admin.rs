//! `qbd`'s `/v1/admin/*`: only a client declared with `admin = true` reaches it. The roles of the
//! config files on disk, their `roles_file` replaced, the reload SIGHUP also runs, and the auth
//! marks of logins cleared. Every call logs one line naming its caller.

use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use qb_core::Core;
use qb_proto::{
    AdminLoginsReset, AdminLoginsResetAnswer, AdminReloadAnswer, AdminRoles, AdminRolesPut,
    AdminRolesWritten, ErrorCode, LoginReset, RoleConfig, RolesSource, paths,
};

use crate::api::{self, Caller, Reply, error, json};
use crate::auth::Gate;
use crate::config;
use crate::hooks::Runner;
use crate::http::{Method, Request};
use crate::journal::Journal;
use crate::rewrite::{self, basic, float};
use crate::server::{Reload, unix_now};
use crate::{log, sha256};

/// The daemon state an admin request may change.
pub struct State<'a> {
    /// The policy core.
    pub core: &'a mut Core,
    /// The clients and their tokens.
    pub gate: &'a mut Gate,
    /// Where changed marks go.
    pub journal: &'a mut Journal,
    /// The hooks of `auth_dead` edges.
    pub hooks: &'a mut Runner,
}

/// Answers `req` to a path under [`paths::ADMIN`] from `caller` at `now`; without `reload`,
/// there are no files to read and every admin path but [`paths::ADMIN_LOGINS_RESET`] is 404.
pub fn handle(
    state: State<'_>,
    reload: Option<&mut Reload>,
    req: &Request,
    caller: &Caller,
    now: u64,
) -> Reply {
    let mut trail = None;
    let reply = route(state, reload, req, caller, now, &mut trail);
    let mut line = format!(
        "qbd: admin {} {} by {}: {}",
        req.method.as_str(),
        log::peer_text(&req.path),
        caller.client,
        reply.status
    );
    if let Some(trail) = trail {
        let _ = write!(line, ", {trail}");
    }
    if reply.status < 400 {
        log::info(&line);
    } else {
        log::warn(&line);
    }
    reply
}

/// [`handle`] without its log line; a `PUT` of the roles and a reset of logins fill `trail`.
fn route(
    state: State<'_>,
    reload: Option<&mut Reload>,
    req: &Request,
    caller: &Caller,
    now: u64,
    trail: &mut Option<String>,
) -> Reply {
    if !caller.admin {
        return error(ErrorCode::Forbidden, "not an admin client");
    }
    match (req.method, req.path.as_str()) {
        (Method::Post, paths::ADMIN_LOGINS_RESET) => return reset_logins(state, req, now, trail),
        (_, paths::ADMIN_LOGINS_RESET) => {
            return error(ErrorCode::MethodNotAllowed, "method not allowed");
        }
        _ => {}
    }
    let State { core, gate, .. } = state;
    let Some(reload) = reload else {
        return error(ErrorCode::NotFound, "no config file");
    };
    match (req.method, req.path.as_str()) {
        (Method::Get, paths::ADMIN_ROLES) => roles(&reload.file),
        (Method::Put, paths::ADMIN_ROLES) => {
            let mut t = Trail::default();
            let reply = match put_roles(core, gate, reload, req, &mut t) {
                Ok(written) => json(200, &written),
                Err(refused) => refused,
            };
            *trail = Some(t.to_string());
            reply
        }
        (Method::Post, paths::ADMIN_RELOAD) => match reload.run(core, gate) {
            Ok(()) => json(
                200,
                &AdminReloadAnswer {
                    roles: reload.running.roles.len(),
                    clients: reload.running.clients.len(),
                },
            ),
            Err(e) => error(ErrorCode::BadRequest, format!("reload refused: {e}")),
        },
        (_, paths::ADMIN_ROLES | paths::ADMIN_RELOAD) => {
            error(ErrorCode::MethodNotAllowed, "method not allowed")
        }
        _ => error(ErrorCode::NotFound, "no such endpoint"),
    }
}

/// Clears the auth marks of the logins of the [`AdminLoginsReset`] body of `req` at `now`, each
/// changed login journaled as after a report; `trail` names the logins cleared.
fn reset_logins(state: State<'_>, req: &Request, now: u64, trail: &mut Option<String>) -> Reply {
    let body: AdminLoginsReset = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(e) => return error(ErrorCode::BadRequest, format!("invalid reset: {e}")),
    };
    if let Err(e) = body.validate() {
        return error(ErrorCode::BadRequest, format!("invalid reset: {e}"));
    }
    let State {
        core,
        journal,
        hooks,
        ..
    } = state;
    let logins: Vec<String> = if body.all {
        core.login_names().map(str::to_owned).collect()
    } else {
        body.logins
    };
    if let Some(unknown) = logins.iter().find(|l| !core.has_login(l)) {
        return error(
            ErrorCode::NotFound,
            format!("no login `{}`", log::peer_text(unknown)),
        );
    }
    // Marks that end by time end first, so the journal records only what the reset changed.
    core.tick(now);
    let mut answer = AdminLoginsResetAnswer { logins: Vec::new() };
    for login in logins {
        let before = core.marks(&login);
        let Some((cleared, status)) = core.reset_auth(&login, now) else {
            continue;
        };
        api::record_marks(journal, hooks, core, login.clone(), before.as_ref(), now);
        answer.logins.push(LoginReset {
            login,
            cleared,
            status: api::login_status(status),
        });
    }
    let cleared: Vec<&str> = answer
        .logins
        .iter()
        .filter(|l| l.cleared)
        .map(|l| l.login.as_str())
        .collect();
    *trail = Some(if cleared.is_empty() {
        "no auth mark cleared".to_owned()
    } else {
        format!("auth marks cleared: {}", cleared.join(" "))
    });
    json(200, &answer)
}

/// The roles of the config file `file` and its `roles_file` as they are on disk, with the hash of
/// the file that holds them also as the `ETag`.
fn roles(file: &Path) -> Reply {
    let sourced = match config::load_sourced(file) {
        Ok(s) => s,
        Err(e) => {
            let message = format!("cannot read the roles: {e}");
            log::error(&format!("qbd: {message}"));
            return error(ErrorCode::Internal, message);
        }
    };
    let digest = sha256::hex(sourced.roles_sha256);
    let answer = AdminRoles {
        source: if sourced.config.roles_file.is_some() {
            RolesSource::RolesFile
        } else {
            RolesSource::Config
        },
        file: sourced.roles_from.display().to_string(),
        sha256: digest.clone(),
        roles: sourced
            .config
            .core_spec()
            .roles
            .iter()
            .map(api::role)
            .collect(),
    };
    Reply {
        etag: Some(format!("\"{digest}\"")),
        ..json(200, &answer)
    }
}

/// What a `PUT` of the roles did to the `roles_file`, for its log line.
#[derive(Debug, Default)]
struct Trail {
    /// Hex SHA-256 of the file before.
    before: Option<String>,
    /// Hex SHA-256 of the file after, when it was written.
    after: Option<String>,
    /// The backup of the old file, kept.
    backup: Option<PathBuf>,
}

impl fmt::Display for Trail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(before) = &self.before {
            let after = self.after.as_ref().unwrap_or(before);
            write!(f, "roles sha256 {before} -> {after}, ")?;
        }
        match &self.backup {
            Some(backup) => write!(f, "backup {}", backup.display()),
            None => f.write_str("nothing written"),
        }
    }
}

/// Replaces the `roles_file` of `reload` with the [`AdminRolesPut`] body of `req` when its
/// `If-Match` is the file's hash and the candidate validates with the config file on disk as at
/// startup, then installs it with [`Reload::run`]. A candidate equal to the file is neither
/// written nor installed.
///
/// # Errors
/// 404 without `roles_file`, 428 without `If-Match`, 412 for another hash, 400 for a body or
/// candidate that does not validate, 500 when a file cannot be read or written or the written
/// file is not installed. Only the last two can leave a written file, which keeps its backup.
fn put_roles(
    core: &mut Core,
    gate: &mut Gate,
    reload: &mut Reload,
    req: &Request,
    trail: &mut Trail,
) -> Result<AdminRolesWritten, Reply> {
    let Some(file) = reload.running.roles_file.clone() else {
        let message = format!("no roles_file: the roles are in {}", reload.file.display());
        return Err(error(ErrorCode::NotFound, message));
    };
    let failed = |message: String| {
        log::error(&format!("qbd: {message}"));
        error(ErrorCode::Internal, message)
    };
    let old =
        std::fs::read(&file).map_err(|e| failed(format!("cannot read {}: {e}", file.display())))?;
    let before = sha256::hex(sha256::digest(&old));
    trail.before = Some(before.clone());
    let Some(tag) = req.if_match.as_deref() else {
        let message = "`If-Match` with the roles file's sha256 is required";
        return Err(error(ErrorCode::PreconditionRequired, message));
    };
    if tag.trim_matches('"') != before {
        let message = format!("`If-Match` is not the roles file's sha256 {before}");
        return Err(error(ErrorCode::PreconditionFailed, message));
    }
    let put: AdminRolesPut = serde_json::from_slice(&req.body)
        .map_err(|e| error(ErrorCode::BadRequest, e.to_string()))?;
    let candidate = render(&put.roles);
    let refused = |e: config::Error| error(ErrorCode::BadRequest, format!("roles refused: {e}"));
    let config = config::load_with_roles(&reload.file, &candidate).map_err(refused)?;
    reload.check(&config).map_err(refused)?;
    if candidate.as_bytes() == old.as_slice() {
        return Ok(AdminRolesWritten {
            sha256: before,
            backup: None,
        });
    }
    let after = sha256::hex(sha256::digest(candidate.as_bytes()));
    let backup = rewrite::rewrite(&file, &old, candidate.as_bytes(), unix_now()).map_err(|f| {
        if let rewrite::Failed::Replaced { backup, .. } = &f {
            if let Ok(now) = std::fs::read(&file) {
                trail.after = Some(sha256::hex(sha256::digest(&now)));
            }
            trail.backup = Some(backup.clone());
        }
        failed(f.message(&file))
    })?;
    trail.after = Some(after.clone());
    trail.backup = Some(backup.clone());
    if let Err(e) = reload.run(core, gate) {
        return Err(failed(rewrite::not_installed(&file, e, &backup)));
    }
    Ok(AdminRolesWritten {
        sha256: after,
        backup: Some(backup.display().to_string()),
    })
}

/// `roles` as the text of a `roles_file`: one `[[roles]]` table each, its ladder steps and
/// reserves as sub-tables, keys in a fixed order. An empty list of tables renders nothing.
fn render(roles: &[RoleConfig]) -> String {
    let mut out = String::new();
    for r in roles {
        if !out.is_empty() {
            out.push('\n');
        }
        let _ = writeln!(out, "[[roles]]\nname = {}", basic(&r.name));
        for step in &r.ladder {
            let _ = writeln!(out, "\n[[roles.ladder]]\ndifficulty = {}", step.difficulty);
            if step.candidates.is_empty() {
                out.push_str("candidates = []\n");
                continue;
            }
            out.push_str("candidates = [\n");
            for c in &step.candidates {
                let _ = write!(
                    out,
                    "  {{ vendor = {}, model = {}",
                    basic(&c.vendor),
                    basic(&c.model)
                );
                if let Some(effort) = &c.effort {
                    let _ = write!(out, ", effort = {}", basic(effort));
                }
                let _ = write!(out, ", tier = {}", c.tier);
                if let Some(cost) = c.cost_per_minute {
                    let _ = write!(out, ", cost_per_minute = {}", float(cost));
                }
                out.push_str(" },\n");
            }
            out.push_str("]\n");
        }
        for res in &r.reserves {
            let _ = writeln!(
                out,
                "\n[[roles.reserves]]\ndifficulty = {}\nwindow = {}\nfraction = {}",
                res.difficulty,
                basic(&res.window),
                float(res.fraction)
            );
        }
    }
    out
}
