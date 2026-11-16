//! The `on_dead` and `on_recover` hooks: commands `qbd` execs without a shell on a login's
//! `auth_dead` edges. Spawning never waits for a hook; the loop reaps finished ones.

use std::process::{Child, Command, Stdio};

use crate::config::Config;
use crate::log;

/// Most hooks running at once: `TasksMax=4` of `qbd.service` counts the daemon's own task too.
pub const MAX_RUNNING: usize = 2;

/// An `auth_dead` edge of a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The login became `auth_dead`.
    Dead,
    /// The login left `auth_dead`.
    Recover,
}

impl Event {
    /// The `QB_EVENT` value.
    pub fn name(self) -> &'static str {
        match self {
            Self::Dead => "dead",
            Self::Recover => "recover",
        }
    }
}

struct Running {
    child: Child,
    event: Event,
    login: String,
}

/// The configured hook commands and the hooks still running.
#[derive(Default)]
pub struct Runner {
    on_dead: Option<Vec<String>>,
    on_recover: Option<Vec<String>>,
    /// (login, vendor) of every configured login.
    vendors: Vec<(String, String)>,
    running: Vec<Running>,
}

impl Runner {
    /// The hooks of `config`.
    pub fn new(config: &Config) -> Self {
        Self {
            on_dead: config.hooks.on_dead.clone(),
            on_recover: config.hooks.on_recover.clone(),
            vendors: config
                .logins
                .iter()
                .map(|l| (l.name.clone(), l.vendor.clone()))
                .collect(),
            running: Vec::with_capacity(MAX_RUNNING),
        }
    }

    /// Starts the hook of `event` for `login`, if one is configured; with [`MAX_RUNNING`]
    /// hooks still running the run is dropped with a warning.
    pub fn fire(&mut self, event: Event, login: &str) {
        self.reap();
        let command = match event {
            Event::Dead => &self.on_dead,
            Event::Recover => &self.on_recover,
        };
        let Some((program, args)) = command.as_deref().and_then(<[String]>::split_first) else {
            return;
        };
        let what = format!("hook {} of {login}", event.name());
        let Some((_, vendor)) = self.vendors.iter().find(|(l, _)| l == login) else {
            log::error(&format!("{what}: undeclared login"));
            return;
        };
        if self.running.len() >= MAX_RUNNING {
            log::warn(&format!(
                "{what} dropped: {MAX_RUNNING} hooks are still running"
            ));
            return;
        }
        let spawned = Command::new(program)
            .args(args)
            .env("QB_EVENT", event.name())
            .env("QB_LOGIN", login)
            .env("QB_VENDOR", vendor)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn();
        match spawned {
            Ok(child) => self.running.push(Running {
                child,
                event,
                login: login.to_owned(),
            }),
            Err(e) => log::error(&format!("{what}: cannot run {program}: {e}")),
        }
    }

    /// Reaps the hooks that have exited, logging failures; never waits.
    pub fn reap(&mut self) {
        self.running.retain_mut(reap);
    }
}

/// Whether `r` still runs; an exit that is not a success is logged.
fn reap(r: &mut Running) -> bool {
    let failure = match r.child.try_wait() {
        Ok(None) => return true,
        Ok(Some(status)) if status.success() => return false,
        Ok(Some(status)) => status.to_string(),
        Err(e) => format!("wait failed: {e}"),
    };
    log::warn(&format!(
        "hook {} of {}: {failure}",
        r.event.name(),
        r.login
    ));
    false
}
