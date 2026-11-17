//! The gateway's TOML config: its socket, qbd, callers, limits, credential files and route
//! aliases. The format is in `docs/config.md`; [`load`] is the only way `qb gateway` obtains a
//! [`GatewayConfig`].
//!
//! The file is read by walking toml's parsed tree rather than through serde: per-type serde code
//! would not fit the binary budget. Errors still name the field path and the line.

use std::path::{Path, PathBuf};

use qb_core::MAX_LOGINS;
use qb_proto::Pin;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::config::{Error, Fault, declare, toml_error, too_many};

/// Most turns one gateway runs at once.
pub const MAX_TURNS: u32 = 16;
/// Largest `max_request_bytes`.
pub const MAX_REQUEST_BYTES: u32 = 32 << 20;
/// Most route aliases.
pub const MAX_ROUTES: usize = 64;
/// Most attempts `max_attempts` may allow.
pub const MAX_ATTEMPTS: u32 = 16;

/// A validated gateway config. Top-level keys come before the `[[clients]]`, `[[logins]]` and
/// `[[routes]]` tables.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayConfig {
    /// Absolute path of the gateway's unix socket.
    pub socket: PathBuf,
    /// Mode of the socket file: 0o600 (the gateway's own user only) or 0o660 (its group too).
    pub socket_mode: u32,
    /// qbd's socket.
    pub qbd_socket: PathBuf,
    /// File with the gateway's bearer token for qbd; without it qbd knows the gateway by uid.
    pub qbd_bearer_file: Option<PathBuf>,
    /// Turns running at once, 1 to [`MAX_TURNS`].
    pub max_turns: u32,
    /// Largest request body in bytes, at most [`MAX_REQUEST_BYTES`].
    pub max_request_bytes: u32,
    /// Picks per turn, 1 to [`MAX_ATTEMPTS`].
    pub max_attempts: u32,
    /// Callers besides the gateway's own uid.
    pub clients: Vec<GatewayClient>,
    /// Logins this gateway holds credentials for, 1 to [`MAX_LOGINS`].
    pub logins: Vec<GatewayLogin>,
    /// Route aliases.
    pub routes: Vec<Route>,
}

/// A caller of the gateway by peer uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayClient {
    /// Name in logs.
    pub name: String,
    /// Peer uid (`SO_PEERCRED`).
    pub uid: u32,
}

/// The type of a credential file; it selects the vendor adapter and its auth mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// Anthropic subscription OAuth tokens.
    OauthAnthropic,
    /// A vendor API key.
    ApiKey,
}

impl CredentialKind {
    /// The name in the config and the credential file, e.g. `oauth_anthropic`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OauthAnthropic => "oauth_anthropic",
            Self::ApiKey => "api_key",
        }
    }
}

/// A login and its credential file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayLogin {
    /// Login name as declared in qbd's config.
    pub name: String,
    /// Credential type.
    pub kind: CredentialKind,
    /// Absolute path of the credential file, mode 0600.
    pub credentials: PathBuf,
}

/// A route alias and what to ask qbd for: a ladder step of a role, or a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Alias clients name in `route`.
    pub alias: String,
    /// qbd role of the pick.
    pub role: String,
    /// Ladder step of the role; exclusive with `vendor` and `model`.
    pub difficulty: Option<u8>,
    /// Pinned vendor; goes with `model`.
    pub vendor: Option<String>,
    /// Pinned model; goes with `vendor`.
    pub model: Option<String>,
    /// Reasoning effort of the pin.
    pub effort: Option<String>,
    /// Expected minutes of a turn, for the lease's cost estimate.
    pub expected_minutes: Option<u32>,
}

impl Route {
    /// The pin of a pinned route.
    pub fn pin(&self) -> Option<Pin> {
        Some(Pin {
            vendor: self.vendor.clone()?,
            model: self.model.clone()?,
            effort: self.effort.clone(),
            login: None,
        })
    }
}

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
    let doc = DeTable::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))?;
    let fail = |(field, reason): Fault| Error {
        file: file.to_owned(),
        field,
        reason,
    };
    let config = walk_config(doc.get_ref()).map_err(|(field, reason, at)| {
        let reason = match at {
            Some(at) => {
                let line = text.get(..at).map_or(0, |s| s.matches('\n').count()) + 1;
                format!("{reason} (line {line})")
            }
            None => reason,
        };
        fail((field, reason))
    })?;
    config.validate().map_err(fail)?;
    Ok(config)
}

/// A field error with the byte offset of the value, for the line number.
type WalkError = (String, String, Option<usize>);

type Value<'i> = Spanned<DeValue<'i>>;

fn wrong(at: &str, v: &Value<'_>, expected: &str) -> WalkError {
    (
        at.to_owned(),
        format!("expected {expected}, found {}", v.get_ref().type_str()),
        Some(v.span().start),
    )
}

/// Calls `field` with each key of `table`, refusing keys outside `known` and requiring the keys
/// in `required`.
fn fields<'v, 'i>(
    at: &str,
    table: &'v DeTable<'i>,
    known: &[&str],
    required: &[&str],
    mut field: impl FnMut(&str, &str, &'v Value<'i>) -> Result<(), WalkError>,
) -> Result<(), WalkError> {
    let path = |key: &str| {
        if at.is_empty() {
            key.to_owned()
        } else {
            format!("{at}.{key}")
        }
    };
    for (key, value) in table {
        let key = key.get_ref().as_ref();
        if !known.contains(&key) {
            return Err((
                path(key),
                format!("unknown field, expected one of {}", known.join(", ")),
                Some(value.span().start),
            ));
        }
        field(key, &path(key), value)?;
    }
    for key in required {
        if table.get(*key).is_none() {
            return Err((path(key), "is missing".into(), None));
        }
    }
    Ok(())
}

fn string(at: &str, v: &Value<'_>) -> Result<String, WalkError> {
    v.get_ref()
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| wrong(at, v, "a string"))
}

fn integer<T: TryFrom<i64>>(at: &str, v: &Value<'_>) -> Result<T, WalkError> {
    let n = v
        .get_ref()
        .as_integer()
        .ok_or_else(|| wrong(at, v, "an integer"))?;
    i64::from_str_radix(n.as_str(), n.radix())
        .ok()
        .and_then(|n| T::try_from(n).ok())
        .ok_or_else(|| {
            (
                at.to_owned(),
                "is out of range".into(),
                Some(v.span().start),
            )
        })
}

/// Each element of the array of tables `v` with its path `at[i]`.
fn tables<'v, 'i>(at: &str, v: &'v Value<'i>) -> Result<Vec<(String, &'v DeTable<'i>)>, WalkError> {
    let items = v
        .get_ref()
        .as_array()
        .ok_or_else(|| wrong(at, v, "an array of tables"))?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let at = format!("{at}[{i}]");
            match item.get_ref().as_table() {
                Some(t) => Ok((at, t)),
                None => Err(wrong(&at, item, "a table")),
            }
        })
        .collect()
}

/// The config's fields out of the parsed TOML tree.
fn walk_config(doc: &DeTable<'_>) -> Result<GatewayConfig, WalkError> {
    let mut c = GatewayConfig {
        socket: PathBuf::new(),
        socket_mode: 0o600,
        qbd_socket: PathBuf::from(crate::DEFAULT_SOCKET),
        qbd_bearer_file: None,
        max_turns: 4,
        max_request_bytes: 8 << 20,
        max_attempts: 4,
        clients: Vec::new(),
        logins: Vec::new(),
        routes: Vec::new(),
    };
    let known = [
        "socket",
        "socket_mode",
        "qbd_socket",
        "qbd_bearer_file",
        "max_turns",
        "max_request_bytes",
        "max_attempts",
        "clients",
        "logins",
        "routes",
    ];
    let required = ["socket", "logins", "routes"];
    fields("", doc, &known, &required, |key, at, v| {
        match key {
            "socket" => c.socket = string(at, v)?.into(),
            "socket_mode" => c.socket_mode = integer(at, v)?,
            "qbd_socket" => c.qbd_socket = string(at, v)?.into(),
            "qbd_bearer_file" => c.qbd_bearer_file = Some(string(at, v)?.into()),
            "max_turns" => c.max_turns = integer(at, v)?,
            "max_request_bytes" => c.max_request_bytes = integer(at, v)?,
            "max_attempts" => c.max_attempts = integer(at, v)?,
            "clients" => {
                for (at, t) in tables(at, v)? {
                    c.clients.push(walk_client(&at, t)?);
                }
            }
            "logins" => {
                for (at, t) in tables(at, v)? {
                    c.logins.push(walk_login(&at, t)?);
                }
            }
            _ => {
                for (at, t) in tables(at, v)? {
                    c.routes.push(walk_route(&at, t)?);
                }
            }
        }
        Ok(())
    })?;
    Ok(c)
}

fn walk_client(at: &str, t: &DeTable<'_>) -> Result<GatewayClient, WalkError> {
    let mut c = GatewayClient {
        name: String::new(),
        uid: 0,
    };
    let keys = ["name", "uid"];
    fields(at, t, &keys, &keys, |key, at, v| {
        match key {
            "name" => c.name = string(at, v)?,
            _ => c.uid = integer(at, v)?,
        }
        Ok(())
    })?;
    Ok(c)
}

fn walk_login(at: &str, t: &DeTable<'_>) -> Result<GatewayLogin, WalkError> {
    let mut l = GatewayLogin {
        name: String::new(),
        kind: CredentialKind::ApiKey,
        credentials: PathBuf::new(),
    };
    let keys = ["name", "kind", "credentials"];
    fields(at, t, &keys, &keys, |key, at, v| {
        match key {
            "name" => l.name = string(at, v)?,
            "kind" => {
                l.kind = match string(at, v)?.as_str() {
                    "oauth_anthropic" => CredentialKind::OauthAnthropic,
                    "api_key" => CredentialKind::ApiKey,
                    _ => {
                        let reason = "expected `oauth_anthropic` or `api_key`".into();
                        return Err((at.to_owned(), reason, Some(v.span().start)));
                    }
                };
            }
            _ => l.credentials = string(at, v)?.into(),
        }
        Ok(())
    })?;
    Ok(l)
}

fn walk_route(at: &str, t: &DeTable<'_>) -> Result<Route, WalkError> {
    let mut r = Route {
        alias: String::new(),
        role: String::new(),
        difficulty: None,
        vendor: None,
        model: None,
        effort: None,
        expected_minutes: None,
    };
    let known = [
        "alias",
        "role",
        "difficulty",
        "vendor",
        "model",
        "effort",
        "expected_minutes",
    ];
    fields(at, t, &known, &["alias", "role"], |key, at, v| {
        match key {
            "alias" => r.alias = string(at, v)?,
            "role" => r.role = string(at, v)?,
            "difficulty" => r.difficulty = Some(integer(at, v)?),
            "vendor" => r.vendor = Some(string(at, v)?),
            "model" => r.model = Some(string(at, v)?),
            "effort" => r.effort = Some(string(at, v)?),
            _ => r.expected_minutes = Some(integer(at, v)?),
        }
        Ok(())
    })?;
    Ok(r)
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
        if ![0o600, 0o660].contains(&self.socket_mode) {
            return Err(("socket_mode".into(), "must be 0o600 or 0o660".into()));
        }
        absolute("qbd_socket", &self.qbd_socket)?;
        if let Some(f) = &self.qbd_bearer_file {
            absolute("qbd_bearer_file", f)?;
        }
        for (key, value, max) in [
            ("max_turns", self.max_turns, MAX_TURNS),
            (
                "max_request_bytes",
                self.max_request_bytes,
                MAX_REQUEST_BYTES,
            ),
            ("max_attempts", self.max_attempts, MAX_ATTEMPTS),
        ] {
            if value == 0 || value > max {
                return Err((key.into(), format!("must be 1 to {max}")));
            }
        }
        declare("clients", self.clients.iter().map(|c| c.name.as_str()))?;
        for (i, c) in self.clients.iter().enumerate() {
            if self.clients[..i].iter().any(|o| o.uid == c.uid) {
                return Err((format!("clients[{i}].uid"), "duplicate uid".into()));
            }
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
            match (r.difficulty, &r.vendor, &r.model) {
                (Some(_), None, None) | (None, Some(_), Some(_)) => {}
                _ => {
                    return Err((
                        at,
                        "needs either `difficulty` or both `vendor` and `model`".into(),
                    ));
                }
            }
            if r.difficulty.is_some() && r.effort.is_some() {
                return Err((at, "`effort` belongs to a pin".into()));
            }
        }
        Ok(())
    }

    /// The route named `alias`.
    pub fn route(&self, alias: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.alias == alias)
    }

    /// The credential entry of `login`.
    pub fn login(&self, login: &str) -> Option<&GatewayLogin> {
        self.logins.iter().find(|l| l.name == login)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
socket = "/run/qb-gateway/gateway.sock"
[[logins]]
name = "login-1"
kind = "api_key"
credentials = "/var/lib/qb-gateway/login-1.json"
[[routes]]
alias = "chat"
role = "gateway"
difficulty = 1
"#;

    fn check(top: &str, extra: &str) -> Result<GatewayConfig, String> {
        parse(Path::new("gw.toml"), &format!("{top}\n{BASE}{extra}")).map_err(|e| e.to_string())
    }

    #[test]
    fn minimal_config_takes_defaults() {
        let c = check("", "").unwrap();
        assert_eq!(c.qbd_socket, Path::new(crate::DEFAULT_SOCKET));
        assert_eq!(
            (
                c.socket_mode,
                c.max_turns,
                c.max_request_bytes,
                c.max_attempts
            ),
            (0o600, 4, 8 << 20, 4)
        );
        let login = c.login("login-1").unwrap();
        assert_eq!(login.kind, CredentialKind::ApiKey);
        assert_eq!(
            login.credentials,
            Path::new("/var/lib/qb-gateway/login-1.json")
        );
        assert_eq!(c.route("chat").and_then(|r| r.difficulty), Some(1));
        let pinned = check(
            "",
            "[[routes]]\nalias = \"fast\"\nrole = \"r\"\nvendor = \"v\"\nmodel = \"m\"\neffort = \"low\"\n",
        )
        .unwrap();
        let pin = pinned.route("fast").unwrap().pin().unwrap();
        assert_eq!(
            (pin.vendor.as_str(), pin.effort.as_deref()),
            ("v", Some("low"))
        );
    }

    #[test]
    fn rule_violations_name_the_field_and_line() {
        let cases = [
            (
                "",
                "[[routes]]\nalias = \"chat\"\nrole = \"r\"\ndifficulty = 1\n",
                "gw.toml: routes[1].alias: duplicate `chat`",
            ),
            (
                "",
                "[[routes]]\nalias = \"Bad\"\nrole = \"r\"\ndifficulty = 1\n",
                "routes[1].alias: must match",
            ),
            (
                "",
                "[[routes]]\nalias = \"two\"\nrole = \"r\"\ndifficulty = 1\nvendor = \"v\"\nmodel = \"m\"\n",
                "routes[1]: needs either",
            ),
            (
                "",
                "[[routes]]\nalias = \"x\"\nrole = \"r\"\nmodle = 1\n",
                "routes[1].modle: unknown field, expected one of alias",
            ),
            (
                "",
                "[[routes]]\nalias = \"x\"\ndifficulty = 1\n",
                "routes[1].role: is missing",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\ncredentials = \"rel.json\"\n",
                "logins[1].credentials: must be an absolute path",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"oauth\"\ncredentials = \"/c.json\"\n",
                "logins[1].kind: expected `oauth_anthropic` or `api_key` (line 14)",
            ),
            (
                "",
                "[[clients]]\nname = \"c\"\n",
                "clients[0].uid: is missing",
            ),
            (
                "",
                "[[clients]]\nname = \"c\"\nuid = \"1000\"\n",
                "clients[0].uid: expected an integer, found string",
            ),
            ("max_turns = 17", "", "max_turns: must be 1 to 16"),
            ("max_attempts = 0", "", "max_attempts: must be 1 to 16"),
            (
                "socket_mode = 0o666",
                "",
                "socket_mode: must be 0o600 or 0o660",
            ),
            (
                "qbd_socket = \"qb.sock\"",
                "",
                "qbd_socket: must be an absolute",
            ),
            (
                "max_request_bytes = -1",
                "",
                "max_request_bytes: is out of range (line 1)",
            ),
            ("bogus = 1", "", "bogus: unknown field"),
        ];
        for (top, extra, want) in cases {
            let err = check(top, extra).unwrap_err();
            assert!(err.contains(want), "{top}{extra}: {err}");
        }
    }
}
