//! `qbd`'s `/v1/admin/*`: only a client declared with `admin = true` reaches it. The roles of the
//! config files on disk, and the reload SIGHUP also runs. Every call logs one line naming its
//! caller.

use std::path::Path;

use qb_core::Core;
use qb_proto::{
    AdminReloadAnswer, AdminRoles, ErrorCode, LadderCandidate, LadderStep, RoleConfig, RoleReserve,
    RolesSource, paths,
};

use crate::api::{Caller, Reply, error, json};
use crate::auth::Gate;
use crate::config::{self, Role};
use crate::http::{Method, Request};
use crate::log;
use crate::server::Reload;
use crate::sha256;

/// Answers `req` to a path under [`paths::ADMIN`] from `caller`; without `reload`, there are no
/// files to read and every admin path is 404.
pub fn handle(
    core: &mut Core,
    gate: &mut Gate,
    reload: Option<&mut Reload>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    let reply = route(core, gate, reload, req, caller);
    let line = format!(
        "qbd: admin {} {} by {}: {}",
        req.method.as_str(),
        log::peer_text(&req.path),
        caller.client,
        reply.status
    );
    if reply.status < 400 {
        log::info(&line);
    } else {
        log::warn(&line);
    }
    reply
}

fn route(
    core: &mut Core,
    gate: &mut Gate,
    reload: Option<&mut Reload>,
    req: &Request,
    caller: &Caller,
) -> Reply {
    if !caller.admin {
        return error(ErrorCode::Forbidden, "not an admin client");
    }
    let Some(reload) = reload else {
        return error(ErrorCode::NotFound, "no config file");
    };
    match (req.method, req.path.as_str()) {
        (Method::Get, paths::ADMIN_ROLES) => roles(&reload.file),
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
        roles: sourced.config.roles.iter().map(role).collect(),
    };
    Reply {
        etag: Some(format!("\"{digest}\"")),
        ..json(200, &answer)
    }
}

fn role(r: &Role) -> RoleConfig {
    RoleConfig {
        name: r.name.clone(),
        ladder: r
            .ladder
            .iter()
            .map(|s| LadderStep {
                difficulty: s.difficulty,
                candidates: s
                    .candidates
                    .iter()
                    .map(|c| LadderCandidate {
                        vendor: c.vendor.clone(),
                        model: c.model.clone(),
                        effort: c.effort.clone(),
                        tier: c.tier,
                        cost_per_minute: c.cost_per_minute.map(config::Fraction::get),
                    })
                    .collect(),
            })
            .collect(),
        reserves: r
            .reserves
            .iter()
            .map(|res| RoleReserve {
                difficulty: res.difficulty,
                window: res.window.clone(),
                fraction: res.fraction.get(),
            })
            .collect(),
    }
}
