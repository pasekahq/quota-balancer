//! The gateway's TOML config: its socket, qbd, callers, limits, credential files and route
//! aliases. The format is in `docs/config.md`; [`load`] is the only way `qb gateway` obtains a
//! [`GatewayConfig`].

use std::path::{Path, PathBuf};

use qb_core::MAX_LOGINS;
use qb_proto::Pin;
use serde::Deserialize;

use crate::config::{BearerHash, Client, Error, Fault, declare, deserialize, too_many};

/// A validated gateway config.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Absolute path of the gateway's unix socket.
    pub socket: PathBuf,
    /// Absolute directories whose files `image` blocks may name by `path`.
    #[serde(default)]
    pub media_dirs: Vec<PathBuf>,
    /// How to reach qbd.
    #[serde(default)]
    pub qbd: Qbd,
    /// Callers allowed on the socket; none means every peer the socket mode lets in.
    #[serde(default)]
    pub clients: Vec<GatewayClient>,
    /// Concurrency, body size and per-caller rate.
    #[serde(default)]
    pub limits: GatewayLimits,
    /// Logins this gateway holds credentials for, 1 to [`MAX_LOGINS`].
    pub logins: Vec<GatewayLogin>,
    /// Route aliases.
    pub routes: Vec<Route>,
}

/// The qbd the gateway picks from and reports to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Qbd {
    /// qbd's socket.
    pub socket: PathBuf,
    /// File with the gateway's bearer token for qbd; without it qbd knows the gateway by uid.
    pub bearer_file: Option<PathBuf>,
}

impl Default for Qbd {
    fn default() -> Self {
        Self {
            socket: PathBuf::from(crate::DEFAULT_SOCKET),
            bearer_file: None,
        }
    }
}

/// A caller of the gateway, by peer uid, bearer token or both.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayClient {
    /// Name in logs and in the cancel registry.
    pub name: String,
    /// Local peer uid (`SO_PEERCRED`).
    pub uid: Option<u32>,
    /// SHA-256 of the caller's bearer token.
    pub bearer_sha256: Option<BearerHash>,
}

impl GatewayClient {
    /// The same caller as a daemon client, for [`crate::auth::Gate`].
    pub fn as_client(&self) -> Client {
        Client {
            name: self.name.clone(),
            uid: self.uid,
            bearer_sha256: self.bearer_sha256,
            role: None,
        }
    }
}

/// Gateway limits.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayLimits {
    /// Turns running at once; a further turn is refused with `overloaded`.
    pub max_turns: u32,
    /// Largest request body in bytes.
    pub max_body_bytes: u32,
    /// Per-caller refill rate in requests per second.
    pub rate_per_s: f64,
    /// Per-caller bucket size.
    pub burst: u32,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            max_turns: 4,
            max_body_bytes: 8 << 20,
            rate_per_s: 5.0,
            burst: 20,
        }
    }
}

/// A login and its credential file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayLogin {
    /// Login name as declared in qbd's config.
    pub name: String,
    /// Absolute path of the credential file, mode 0600.
    pub credentials: PathBuf,
}

/// A route alias and what to ask qbd for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Alias clients name in `route`.
    pub alias: String,
    /// qbd role of the pick.
    pub role: String,
    /// Ladder step of the role; exclusive with `pin`.
    pub difficulty: Option<u8>,
    /// Exact vendor and model (and optionally login); exclusive with `difficulty`.
    pub pin: Option<Pin>,
    /// Expected minutes of a turn, for the lease's cost estimate.
    pub expected_minutes: Option<u32>,
}

/// Most route aliases.
pub const MAX_ROUTES: usize = 64;

/// Reads and validates the gateway config in `file`.
///
/// # Errors
/// The file cannot be read, is not valid TOML of this schema, or breaks a rule of
/// `docs/config.md`.
pub fn load(file: &Path) -> Result<GatewayConfig, Error> {
    let text = std::fs::read_to_string(file).map_err(|e| Error {
        file: file.to_owned(),
        field: String::new(),
        reason: format!("cannot read: {e}"),
    })?;
    parse(file, &text)
}

/// Parses and validates `text` as the gateway config named `file` in errors.
///
/// # Errors
/// As [`load`], without the read.
pub fn parse(file: &Path, text: &str) -> Result<GatewayConfig, Error> {
    let config: GatewayConfig = deserialize(file, text)?;
    config.validate().map_err(|(field, reason)| Error {
        file: file.to_owned(),
        field,
        reason,
    })?;
    Ok(config)
}

fn absolute(field: &str, path: &Path) -> Result<(), Fault> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err((field.into(), "must be an absolute path".into()))
    }
}

impl GatewayConfig {
    fn validate(&self) -> Result<(), Fault> {
        absolute("socket", &self.socket)?;
        absolute("qbd.socket", &self.qbd.socket)?;
        for (i, dir) in self.media_dirs.iter().enumerate() {
            absolute(&format!("media_dirs[{i}]"), dir)?;
        }
        declare("clients", self.clients.iter().map(|c| c.name.as_str()))?;
        for (i, c) in self.clients.iter().enumerate() {
            if c.uid.is_none() && c.bearer_sha256.is_none() {
                return Err((
                    format!("clients[{i}]"),
                    "needs `uid`, `bearer_sha256` or both".into(),
                ));
            }
            let earlier = &self.clients[..i];
            if c.uid.is_some() && earlier.iter().any(|o| o.uid == c.uid) {
                return Err((format!("clients[{i}].uid"), "duplicate uid".into()));
            }
            if c.bearer_sha256.is_some()
                && earlier.iter().any(|o| o.bearer_sha256 == c.bearer_sha256)
            {
                return Err((
                    format!("clients[{i}].bearer_sha256"),
                    "duplicate hash".into(),
                ));
            }
        }
        let l = &self.limits;
        for (key, value) in [
            ("max_turns", l.max_turns),
            ("max_body_bytes", l.max_body_bytes),
            ("burst", l.burst),
        ] {
            if value == 0 {
                return Err((format!("limits.{key}"), "must be positive".into()));
            }
        }
        if !(l.rate_per_s.is_finite() && l.rate_per_s > 0.0) {
            return Err(("limits.rate_per_s".into(), "must be positive".into()));
        }
        if self.logins.is_empty() {
            return Err(("logins".into(), "is empty".into()));
        }
        if self.logins.len() > MAX_LOGINS {
            return Err(too_many("logins".into(), self.logins.len(), MAX_LOGINS));
        }
        declare("logins", self.logins.iter().map(|l| l.name.as_str()))?;
        for (i, login) in self.logins.iter().enumerate() {
            absolute(&format!("logins[{i}].credentials"), &login.credentials)?;
        }
        self.validate_routes()
    }

    fn validate_routes(&self) -> Result<(), Fault> {
        if self.routes.is_empty() {
            return Err(("routes".into(), "is empty".into()));
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(too_many("routes".into(), self.routes.len(), MAX_ROUTES));
        }
        for (i, r) in self.routes.iter().enumerate() {
            let at = format!("routes[{i}]");
            if !qb_proto::gateway::is_alias(&r.alias) {
                return Err((
                    format!("{at}.alias"),
                    "must match ^[a-z][a-z0-9_-]{0,63}$".into(),
                ));
            }
            if self.routes[..i].iter().any(|o| o.alias == r.alias) {
                return Err((format!("{at}.alias"), format!("duplicate `{}`", r.alias)));
            }
            if r.role.trim().is_empty() {
                return Err((format!("{at}.role"), "is empty".into()));
            }
            match (&r.difficulty, &r.pin) {
                (Some(_), None) | (None, Some(_)) => {}
                _ => return Err((at, "needs exactly one of `difficulty` and `pin`".into())),
            }
        }
        Ok(())
    }

    /// The route named `alias`.
    pub fn route(&self, alias: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.alias == alias)
    }

    /// The credential file of `login`.
    pub fn credentials(&self, login: &str) -> Option<&Path> {
        self.logins
            .iter()
            .find(|l| l.name == login)
            .map(|l| l.credentials.as_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
socket = "/run/qb-gateway/gateway.sock"
[[logins]]
name = "login-1"
credentials = "/var/lib/qb-gateway/login-1.json"
[[routes]]
alias = "chat"
role = "gateway"
difficulty = 1
"#;

    fn check(extra: &str) -> Result<GatewayConfig, String> {
        parse(Path::new("gw.toml"), &format!("{BASE}{extra}")).map_err(|e| e.to_string())
    }

    #[test]
    fn minimal_config_takes_defaults() {
        let c = check("").unwrap();
        assert_eq!(c.qbd.socket, Path::new(crate::DEFAULT_SOCKET));
        assert_eq!(c.limits.max_turns, 4);
        assert_eq!(
            c.credentials("login-1"),
            Some(Path::new("/var/lib/qb-gateway/login-1.json"))
        );
        assert_eq!(c.route("chat").and_then(|r| r.difficulty), Some(1));
    }

    #[test]
    fn rule_violations_name_the_field() {
        let cases = [
            (
                "[[routes]]\nalias = \"chat\"\nrole = \"r\"\ndifficulty = 1\n",
                "routes[1].alias: duplicate `chat`",
            ),
            (
                "[[routes]]\nalias = \"Bad\"\nrole = \"r\"\ndifficulty = 1\n",
                "routes[1].alias: must match",
            ),
            (
                "[[routes]]\nalias = \"two\"\nrole = \"r\"\ndifficulty = 1\npin = { vendor = \"v\", model = \"m\" }\n",
                "routes[1]: needs exactly one",
            ),
            (
                "[[logins]]\nname = \"login-2\"\ncredentials = \"rel.json\"\n",
                "logins[1].credentials: must be an absolute path",
            ),
            (
                "[limits]\nmax_turns = 0\n",
                "limits.max_turns: must be positive",
            ),
            ("[[clients]]\nname = \"c\"\n", "clients[0]: needs"),
            (
                "[[routes]]\nalias = \"x\"\nrole = \"r\"\nmodel = 1\n",
                "unknown field",
            ),
        ];
        for (extra, want) in cases {
            let err = check(extra).unwrap_err();
            assert!(err.contains(want), "{extra}: {err}");
        }
        let top = format!("media_dirs = [\"media\"]\n{BASE}");
        let err = parse(Path::new("gw.toml"), &top).unwrap_err().to_string();
        assert!(err.contains("media_dirs[0]: must be an absolute"), "{err}");
    }
}
