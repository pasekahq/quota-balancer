//! The gateway's TOML config: its socket, qbd, callers, limits, credential files and route
//! aliases. The format is in `docs/config.md`; [`load`] is the only way `qb gateway` obtains a
//! [`GatewayConfig`].

use std::path::{Path, PathBuf};

use qb_core::MAX_LOGINS;
use qb_proto::Pin;

use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::config::{
    BEARER_HASH_EXPECTED, BearerHash, Client, Error, Fault, declare, toml_error, too_many,
};

/// A validated gateway config. Top-level keys come before the `[[clients]]`, `[[logins]]` and
/// `[[routes]]` tables. It is read by walking the TOML tree rather than by serde, which keeps
/// the binary small.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayConfig {
    /// Absolute path of the gateway's unix socket.
    pub socket: PathBuf,
    /// qbd's socket.
    pub qbd_socket: PathBuf,
    /// File with the gateway's bearer token for qbd; without it qbd knows the gateway by uid.
    pub qbd_bearer_file: Option<PathBuf>,
    /// Absolute directories whose files `image` blocks may name by `path`.
    pub media_dirs: Vec<PathBuf>,
    /// Turns running at once; a further turn is refused with `overloaded`.
    pub max_turns: u32,
    /// Largest request body in bytes.
    pub max_body_bytes: u32,
    /// Per-caller refill rate in requests per second.
    pub rate_per_s: f64,
    /// Per-caller bucket size.
    pub burst: u32,
    /// Callers allowed on the socket; none means every peer the socket mode lets in.
    pub clients: Vec<GatewayClient>,
    /// Logins this gateway holds credentials for, 1 to [`MAX_LOGINS`].
    pub logins: Vec<GatewayLogin>,
    /// Route aliases.
    pub routes: Vec<Route>,
}

/// A caller of the gateway, by peer uid, bearer token or both.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// A login and its credential file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayLogin {
    /// Login name as declared in qbd's config.
    pub name: String,
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
    /// One login of the pinned vendor.
    pub login: Option<String>,
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
            login: self.login.clone(),
        })
    }
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
    let doc = DeTable::parse(text).map_err(|e| toml_error(file, text, String::new(), &e))?;
    let fail = |(field, reason): Fault| Error {
        file: file.to_owned(),
        field,
        reason,
    };
    let config = walk_config(doc.get_ref()).map_err(|(field, reason, span)| {
        let reason = match span {
            Some(at) => format!("{reason} (line {})", line(text, at)),
            None => reason,
        };
        fail((field, reason))
    })?;
    config.validate().map_err(fail)?;
    Ok(config)
}

fn line(text: &str, at: usize) -> usize {
    text.get(..at).map_or(0, |s| s.matches('\n').count()) + 1
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

/// Calls `field` with each key of `table`, refusing keys outside `known`.
fn fields<'v, 'i>(
    at: &str,
    table: &'v DeTable<'i>,
    known: &[&str],
    mut field: impl FnMut(&str, &str, &'v Value<'i>) -> Result<(), WalkError>,
) -> Result<(), WalkError> {
    for (key, value) in table {
        let key = key.get_ref().as_ref();
        let path = if at.is_empty() {
            key.to_owned()
        } else {
            format!("{at}.{key}")
        };
        if !known.contains(&key) {
            return Err((
                path,
                format!("unknown field, expected one of {}", known.join(", ")),
                Some(value.span().start),
            ));
        }
        field(key, &path, value)?;
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

fn float(at: &str, v: &Value<'_>) -> Result<f64, WalkError> {
    match v.get_ref() {
        DeValue::Float(f) => f.as_str().parse().map_err(|_| {
            (
                at.to_owned(),
                "is not a number".into(),
                Some(v.span().start),
            )
        }),
        DeValue::Integer(_) => integer::<i32>(at, v).map(f64::from),
        _ => Err(wrong(at, v, "a number")),
    }
}

fn table<'v, 'i>(at: &str, v: &'v Value<'i>) -> Result<&'v DeTable<'i>, WalkError> {
    v.get_ref()
        .as_table()
        .ok_or_else(|| wrong(at, v, "a table"))
}

/// Each element of the array `v` with its path `at[i]`.
fn array<'v, 'i>(
    at: &str,
    v: &'v Value<'i>,
) -> Result<impl Iterator<Item = (String, &'v Value<'i>)>, WalkError> {
    let items = v
        .get_ref()
        .as_array()
        .ok_or_else(|| wrong(at, v, "an array"))?;
    Ok(items
        .iter()
        .enumerate()
        .map(move |(i, item)| (format!("{at}[{i}]"), item)))
}

/// The config's fields out of the parsed TOML tree.
fn walk_config(doc: &DeTable<'_>) -> Result<GatewayConfig, WalkError> {
    let mut c = GatewayConfig {
        socket: PathBuf::new(),
        qbd_socket: PathBuf::from(crate::DEFAULT_SOCKET),
        qbd_bearer_file: None,
        media_dirs: Vec::new(),
        max_turns: 4,
        max_body_bytes: 8 << 20,
        rate_per_s: 5.0,
        burst: 20,
        clients: Vec::new(),
        logins: Vec::new(),
        routes: Vec::new(),
    };
    let mut seen = Vec::new();
    let known = [
        "socket",
        "qbd_socket",
        "qbd_bearer_file",
        "media_dirs",
        "max_turns",
        "max_body_bytes",
        "rate_per_s",
        "burst",
        "clients",
        "logins",
        "routes",
    ];
    fields("", doc, &known, |key, at, v| {
        seen.push(key.to_owned());
        match key {
            "socket" => c.socket = string(at, v)?.into(),
            "qbd_socket" => c.qbd_socket = string(at, v)?.into(),
            "qbd_bearer_file" => c.qbd_bearer_file = Some(string(at, v)?.into()),
            "media_dirs" => {
                for (at, d) in array(at, v)? {
                    c.media_dirs.push(string(&at, d)?.into());
                }
            }
            "max_turns" => c.max_turns = integer(at, v)?,
            "max_body_bytes" => c.max_body_bytes = integer(at, v)?,
            "rate_per_s" => c.rate_per_s = float(at, v)?,
            "burst" => c.burst = integer(at, v)?,
            "clients" => {
                for (at, t) in array(at, v)? {
                    c.clients.push(walk_client(&at, table(&at, t)?)?);
                }
            }
            "logins" => {
                for (at, t) in array(at, v)? {
                    c.logins.push(walk_login(&at, table(&at, t)?)?);
                }
            }
            _ => {
                for (at, t) in array(at, v)? {
                    c.routes.push(walk_route(&at, table(&at, t)?)?);
                }
            }
        }
        Ok(())
    })?;
    for required in ["socket", "logins", "routes"] {
        if !seen.iter().any(|k| k == required) {
            return Err((required.into(), "is missing".into(), None));
        }
    }
    Ok(c)
}

fn walk_client(at: &str, t: &DeTable<'_>) -> Result<GatewayClient, WalkError> {
    let mut c = GatewayClient {
        name: String::new(),
        uid: None,
        bearer_sha256: None,
    };
    fields(at, t, &["name", "uid", "bearer_sha256"], |key, at, v| {
        match key {
            "name" => c.name = string(at, v)?,
            "uid" => c.uid = Some(integer(at, v)?),
            _ => {
                let hash = BearerHash::from_hex(&string(at, v)?).ok_or_else(|| {
                    (
                        at.to_owned(),
                        BEARER_HASH_EXPECTED.into(),
                        Some(v.span().start),
                    )
                })?;
                c.bearer_sha256 = Some(hash);
            }
        }
        Ok(())
    })?;
    Ok(c)
}

fn walk_login(at: &str, t: &DeTable<'_>) -> Result<GatewayLogin, WalkError> {
    let mut l = GatewayLogin {
        name: String::new(),
        credentials: PathBuf::new(),
    };
    fields(at, t, &["name", "credentials"], |key, at, v| {
        match key {
            "name" => l.name = string(at, v)?,
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
        login: None,
        expected_minutes: None,
    };
    let known = [
        "alias",
        "role",
        "difficulty",
        "vendor",
        "model",
        "effort",
        "login",
        "expected_minutes",
    ];
    fields(at, t, &known, |key, at, v| {
        match key {
            "alias" => r.alias = string(at, v)?,
            "role" => r.role = string(at, v)?,
            "difficulty" => r.difficulty = Some(integer(at, v)?),
            "vendor" => r.vendor = Some(string(at, v)?),
            "model" => r.model = Some(string(at, v)?),
            "effort" => r.effort = Some(string(at, v)?),
            "login" => r.login = Some(string(at, v)?),
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
        absolute("qbd_socket", &self.qbd_socket)?;
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
        for (key, value) in [
            ("max_turns", self.max_turns),
            ("max_body_bytes", self.max_body_bytes),
            ("burst", self.burst),
        ] {
            if value == 0 {
                return Err((key.into(), "must be positive".into()));
            }
        }
        if !(self.rate_per_s.is_finite() && self.rate_per_s > 0.0) {
            return Err(("rate_per_s".into(), "must be positive".into()));
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
            if r.difficulty.is_some() && (r.effort.is_some() || r.login.is_some()) {
                return Err((at, "`effort` and `login` belong to a pin".into()));
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
        assert_eq!(c.qbd_socket, Path::new(crate::DEFAULT_SOCKET));
        assert_eq!(c.max_turns, 4);
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
                "[[routes]]\nalias = \"two\"\nrole = \"r\"\ndifficulty = 1\nvendor = \"v\"\nmodel = \"m\"\n",
                "routes[1]: needs either",
            ),
            (
                "[[logins]]\nname = \"login-2\"\ncredentials = \"rel.json\"\n",
                "logins[1].credentials: must be an absolute path",
            ),
            ("[[clients]]\nname = \"c\"\n", "clients[0]: needs"),
            (
                "[[routes]]\nalias = \"x\"\nrole = \"r\"\nmodle = 1\n",
                "unknown field",
            ),
        ];
        for (extra, want) in cases {
            let err = check(extra).unwrap_err();
            assert!(err.contains(want), "{extra}: {err}");
        }
        for (top, want) in [
            (
                "media_dirs = [\"media\"]",
                "media_dirs[0]: must be an absolute",
            ),
            ("max_turns = 0", "max_turns: must be positive"),
            (
                "qbd_socket = \"qb.sock\"",
                "qbd_socket: must be an absolute",
            ),
            ("rate_per_s = -1.0", "rate_per_s: must be positive"),
        ] {
            let text = format!("{top}\n{BASE}");
            let err = parse(Path::new("gw.toml"), &text).unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
        }
    }
}
