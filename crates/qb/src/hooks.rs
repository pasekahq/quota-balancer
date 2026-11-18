//! The `on_dead` and `on_recover` hooks: commands `qbd` execs without a shell on a login's
//! `auth_dead` edges. Spawning never waits for a hook; the loop reaps finished ones and kills
//! the ones past [`TIMEOUT`].

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::log;

/// Most hooks running at once: `TasksMax=4` of `qbd.service` counts the daemon's own task too.
pub const MAX_RUNNING: usize = 2;

/// A hook still running this long after its spawn is killed on the next loop pass, or when an
/// event needs its slot; no timer wakes the loop for it.
pub const TIMEOUT: Duration = Duration::from_secs(60);

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
    started: Instant,
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
        self.reap_at(Instant::now());
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
                started: Instant::now(),
                event,
                login: login.to_owned(),
            }),
            Err(e) => log::error(&format!("{what}: cannot run {program}: {e}")),
        }
    }

    /// Reaps the hooks that have exited and kills those past [`TIMEOUT`], logging failures;
    /// never waits for a hook that was not killed.
    pub fn reap(&mut self) {
        self.reap_at(Instant::now());
    }

    fn reap_at(&mut self, now: Instant) {
        self.running.retain_mut(|r| reap(r, now));
    }
}

/// Whether `r` still runs at `now`; an exit that is not a success is logged. A hook past
/// [`TIMEOUT`] gets `SIGKILL` and is waited for, which the kernel ends at once; processes it
/// started are not tracked and keep running.
fn reap(r: &mut Running, now: Instant) -> bool {
    let failure = match r.child.try_wait() {
        Ok(None) if now.saturating_duration_since(r.started) < TIMEOUT => return true,
        Ok(None) => match r.child.kill().and_then(|()| r.child.wait()) {
            Ok(_) => format!("killed after {} s", TIMEOUT.as_secs()),
            Err(e) => format!("kill after {} s failed: {e}", TIMEOUT.as_secs()),
        },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sleeper() -> Runner {
        Runner {
            on_dead: Some(vec!["sleep".into(), "1000".into()]),
            on_recover: None,
            vendors: vec![
                ("login-1".into(), "vendor-a".into()),
                ("login-2".into(), "vendor-a".into()),
                ("login-3".into(), "vendor-a".into()),
            ],
            running: Vec::new(),
        }
    }

    #[test]
    fn a_hook_past_its_timeout_is_killed_and_frees_its_slot() {
        let mut hooks = sleeper();
        hooks.fire(Event::Dead, "login-1");
        hooks.fire(Event::Dead, "login-2");
        assert_eq!(hooks.running.len(), MAX_RUNNING);
        let started = hooks.running[0].started;
        hooks.reap_at(started + TIMEOUT / 2);
        assert_eq!(hooks.running.len(), MAX_RUNNING, "not yet due");
        hooks.reap_at(Instant::now() + TIMEOUT);
        assert!(hooks.running.is_empty(), "both were killed and reaped");
        hooks.fire(Event::Dead, "login-3");
        assert_eq!(hooks.running.len(), 1, "a later event runs");
        hooks.reap_at(Instant::now() + TIMEOUT);
        assert!(hooks.running.is_empty());
    }
}
