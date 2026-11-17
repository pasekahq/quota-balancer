//! The gateway's TOML config: its socket, qbd, callers, limits, credential files and route
//! aliases. The format is in `docs/config.md`; [`load`] is the only way `qb gateway` obtains a
//! [`GatewayConfig`].
//!
//! The file is read by walking toml's parsed tree rather than through serde: per-type serde code
//! would not fit the binary budget. Errors still name the field path and the line.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use qb_core::MAX_LOGINS;
use qb_openai::chat_upstream;
use qb_proto::Pin;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::config::{
    BEARER_HASH_EXPECTED, BearerHash, Error, Fault, declare, toml_error, too_many,
};

/// Most turns one gateway runs at once.
pub const MAX_TURNS: u32 = 16;
/// Largest `max_request_bytes`.
pub const MAX_REQUEST_BYTES: u32 = 32 << 20;
/// Most route aliases.
pub const MAX_ROUTES: usize = 64;
/// Most attempts `max_attempts` may allow.
pub const MAX_ATTEMPTS: u32 = 16;
/// Most entries of `fronts.models`.
pub const MAX_MODELS: usize = 256;
/// Default of `fronts.ping_interval_s`.
pub const PING_INTERVAL_S: u32 = 10;
/// Largest `fronts.ping_interval_s`.
pub const MAX_PING_INTERVAL_S: u32 = 30;

/// A validated gateway config. Top-level keys come before the `[[clients]]`, `[[logins]]`,
/// `[[routes]]` and `[fronts]` tables.
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
    /// The HTTP fronts; without it their endpoints answer 404.
    pub fronts: Option<Fronts>,
}

/// The settings the HTTP fronts share and the fronts this gateway serves; at least one is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fronts {
    /// Client `model` names and the route alias each runs on.
    pub models: Vec<(String, String)>,
    /// Loopback TCP address that serves the fronts besides the unix socket.
    pub listen: Option<SocketAddr>,
    /// SHA-256 of the local client token every TCP request carries; set exactly when `listen` is.
    pub token_sha256: Option<BearerHash>,
    /// Seconds of silence in a started stream before a keep-alive, 1 to [`MAX_PING_INTERVAL_S`].
    pub ping_interval_s: u32,
    /// `/v1/messages`; without it that endpoint answers 404.
    pub messages: Option<MessagesFront>,
    /// `/v1/chat/completions` and `/v1/responses`; without it they answer 404.
    pub openai: Option<OpenaiFront>,
}

/// The `/v1/messages` front's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagesFront {
    /// `qbd` vendor whose thinking blocks are Anthropic blocks: they pass to clients as such, and
    /// clients' thinking blocks come back as this vendor's.
    pub vendor: String,
}

/// The settings of the `/v1/chat/completions` and `/v1/responses` fronts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenaiFront {
    /// `qbd` vendor whose thinking is an OpenAI reasoning item: it passes to Responses clients as
    /// such, and their reasoning items come back as this vendor's.
    pub vendor: String,
    /// Output bound of a request that names none, at least 1.
    pub max_tokens: u32,
}

/// A caller of the gateway by peer uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayClient {
    /// Name in logs.
    pub name: String,
    /// Peer uid (`SO_PEERCRED`).
    pub uid: u32,
}

/// The type of a credential file; it selects the adapter's auth mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    /// Anthropic subscription OAuth tokens.
    OauthAnthropic,
    /// A vendor API key.
    ApiKey,
    /// ChatGPT subscription OAuth access token and account id.
    ChatgptOauth,
}

impl CredentialKind {
    /// The name in the config and the credential file, e.g. `oauth_anthropic`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OauthAnthropic => "oauth_anthropic",
            Self::ApiKey => "api_key",
            Self::ChatgptOauth => "chatgpt_oauth",
        }
    }
}

/// The vendor API family a login speaks; it selects the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Api {
    /// The Anthropic Messages API.
    Anthropic,
    /// The OpenAI APIs.
    Openai,
    /// The Chat Completions API of an OpenAI-compatible vendor.
    ChatCompletions,
}

impl Api {
    /// The name in the config, e.g. `anthropic`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openai => "openai",
            Self::ChatCompletions => "chat_completions",
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
    /// API family; `anthropic` for an `oauth_anthropic` login, `openai` for a `chatgpt_oauth` one.
    pub api: Api,
    /// Base URL of the vendor API without a trailing `/`; `None` for the adapter's public
    /// endpoint. Always set on a `chat_completions` login.
    pub base_url: Option<String>,
    /// `http-referer` header of a `chat_completions` login; non-empty printable ASCII.
    pub referer: Option<String>,
    /// `x-title` header of a `chat_completions` login; non-empty printable ASCII.
    pub title: Option<String>,
    /// URL of the OAuth token endpoint of an `oauth_anthropic` login; `None` for the vendor's
    /// endpoints.
    pub token_url: Option<String>,
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
        fronts: None,
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
        "fronts",
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
            "routes" => {
                for (at, t) in tables(at, v)? {
                    c.routes.push(walk_route(&at, t)?);
                }
            }
            _ => c.fronts = Some(walk_fronts(at, table(at, v)?)?),
        }
        Ok(())
    })?;
    Ok(c)
}

fn table<'v, 'i>(at: &str, v: &'v Value<'i>) -> Result<&'v DeTable<'i>, WalkError> {
    v.get_ref()
        .as_table()
        .ok_or_else(|| wrong(at, v, "a table"))
}

fn walk_fronts(at: &str, t: &DeTable<'_>) -> Result<Fronts, WalkError> {
    let mut f = Fronts {
        models: Vec::new(),
        listen: None,
        token_sha256: None,
        ping_interval_s: PING_INTERVAL_S,
        messages: None,
        openai: None,
    };
    let (mut listen_at, mut token_at) = (None, None);
    let keys = [
        "models",
        "listen",
        "token_sha256",
        "ping_interval_s",
        "messages",
        "openai",
    ];
    fields(at, t, &keys, &[], |key, at, v| {
        let bad = |reason: &str| (at.to_owned(), reason.to_owned(), Some(v.span().start));
        match key {
            "listen" => {
                let addr: SocketAddr = string(at, v)?
                    .parse()
                    .map_err(|_| bad("expected `127.0.0.1:<port>` or `[::1]:<port>`"))?;
                if !addr.ip().is_loopback() {
                    return Err(bad("must be a loopback address"));
                }
                if addr.port() == 0 {
                    return Err(bad("needs a port other than 0"));
                }
                f.listen = Some(addr);
                listen_at = Some(v.span().start);
            }
            "token_sha256" => {
                let hash = BearerHash::from_hex(&string(at, v)?);
                f.token_sha256 = Some(hash.ok_or_else(|| bad(BEARER_HASH_EXPECTED))?);
                token_at = Some(v.span().start);
            }
            "ping_interval_s" => {
                f.ping_interval_s = integer(at, v)?;
                if !(1..=MAX_PING_INTERVAL_S).contains(&f.ping_interval_s) {
                    return Err(bad(&format!("must be 1 to {MAX_PING_INTERVAL_S}")));
                }
            }
            "messages" => {
                let mut m = MessagesFront {
                    vendor: String::new(),
                };
                fields(at, table(at, v)?, &["vendor"], &["vendor"], |_, at, v| {
                    m.vendor = string(at, v)?;
                    Ok(())
                })?;
                f.messages = Some(m);
            }
            "openai" => {
                let mut o = OpenaiFront {
                    vendor: String::new(),
                    max_tokens: 0,
                };
                let keys = ["vendor", "max_tokens"];
                fields(at, table(at, v)?, &keys, &keys, |key, at, v| {
                    match key {
                        "vendor" => o.vendor = string(at, v)?,
                        _ => o.max_tokens = integer(at, v)?,
                    }
                    Ok(())
                })?;
                f.openai = Some(o);
            }
            _ => {
                for (model, alias) in table(at, v)? {
                    let model = model.get_ref().as_ref();
                    let alias = string(&format!("{at}.\"{model}\""), alias)?;
                    f.models.push((model.to_owned(), alias));
                }
            }
        }
        Ok(())
    })?;
    match (listen_at, token_at) {
        (Some(line), None) => Err((
            format!("{at}.token_sha256"),
            "is missing; `listen` needs the client token's hash".into(),
            Some(line),
        )),
        (None, Some(line)) => Err((
            format!("{at}.token_sha256"),
            "belongs to a `listen` address".into(),
            Some(line),
        )),
        _ => Ok(f),
    }
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
        api: Api::Anthropic,
        base_url: None,
        referer: None,
        title: None,
        token_url: None,
        credentials: PathBuf::new(),
    };
    let mut api = None;
    let mut token_url_at = None;
    let mut header_at = None;
    let keys = [
        "name",
        "kind",
        "api",
        "base_url",
        "referer",
        "title",
        "token_url",
        "credentials",
    ];
    let required = ["name", "kind", "credentials"];
    fields(at, t, &keys, &required, |key, at, v| {
        match key {
            "name" => l.name = string(at, v)?,
            "api" => {
                let family = match string(at, v)?.as_str() {
                    "anthropic" => Api::Anthropic,
                    "openai" => Api::Openai,
                    "chat_completions" => Api::ChatCompletions,
                    _ => {
                        let reason = "expected `anthropic`, `openai` or `chat_completions`".into();
                        return Err((at.to_owned(), reason, Some(v.span().start)));
                    }
                };
                api = Some((family, v.span().start));
            }
            "base_url" => l.base_url = Some(url(at, v)?),
            "referer" | "title" => {
                let value = string(at, v)?;
                if chat_upstream::headers(Some(&value), None).is_err() {
                    let reason = "must be non-empty printable ASCII".into();
                    return Err((at.to_owned(), reason, Some(v.span().start)));
                }
                header_at.get_or_insert((at.to_owned(), v.span().start));
                match key {
                    "referer" => l.referer = Some(value),
                    _ => l.title = Some(value),
                }
            }
            "token_url" => {
                l.token_url = Some(url(at, v)?);
                token_url_at = Some(v.span().start);
            }
            "kind" => {
                l.kind = match string(at, v)?.as_str() {
                    "oauth_anthropic" => CredentialKind::OauthAnthropic,
                    "api_key" => CredentialKind::ApiKey,
                    "chatgpt_oauth" => CredentialKind::ChatgptOauth,
                    _ => {
                        let reason =
                            "expected `oauth_anthropic`, `chatgpt_oauth` or `api_key`".into();
                        return Err((at.to_owned(), reason, Some(v.span().start)));
                    }
                };
            }
            _ => l.credentials = string(at, v)?.into(),
        }
        Ok(())
    })?;
    l.api = family(at, l.kind, api)?;
    if let (CredentialKind::ApiKey | CredentialKind::ChatgptOauth, Some(span)) =
        (l.kind, token_url_at)
    {
        let reason = "belongs to an `oauth_anthropic` login".into();
        return Err((format!("{at}.token_url"), reason, Some(span)));
    }
    if l.api == Api::ChatCompletions {
        if l.base_url.is_none() {
            let span = api.map(|(_, span)| span);
            let reason = "is missing; a `chat_completions` login names its vendor's URL".into();
            return Err((format!("{at}.base_url"), reason, span));
        }
    } else if let Some((field, span)) = header_at {
        let reason = "belongs to a `chat_completions` login".into();
        return Err((field, reason, Some(span)));
    }
    Ok(l)
}

/// The API family of a login of `kind` whose `api` key, if given, names `api` at its span.
fn family(at: &str, kind: CredentialKind, api: Option<(Api, usize)>) -> Result<Api, WalkError> {
    match (kind, api) {
        (CredentialKind::OauthAnthropic, None | Some((Api::Anthropic, _))) => Ok(Api::Anthropic),
        (CredentialKind::OauthAnthropic, Some((_, span))) => {
            let reason = "an `oauth_anthropic` login is `anthropic`".into();
            Err((format!("{at}.api"), reason, Some(span)))
        }
        (CredentialKind::ChatgptOauth, None | Some((Api::Openai, _))) => Ok(Api::Openai),
        (CredentialKind::ChatgptOauth, Some((_, span))) => {
            let reason = "a `chatgpt_oauth` login is `openai`".into();
            Err((format!("{at}.api"), reason, Some(span)))
        }
        (CredentialKind::ApiKey, Some((family, _))) => Ok(family),
        (CredentialKind::ApiKey, None) => {
            let reason = "is missing; an `api_key` login names its API".into();
            Err((format!("{at}.api"), reason, None))
        }
    }
}

/// A URL without its trailing `/`: `https://` with port 443, or `http://` with a loopback host,
/// then an optional path; no user, query or fragment.
fn url(at: &str, v: &Value<'_>) -> Result<String, WalkError> {
    let url = string(at, v)?;
    let bad = |reason: &str| (at.to_owned(), reason.to_owned(), Some(v.span().start));
    let (https, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        (None, None) => return Err(bad("must start with `https://` or `http://`")),
    };
    if rest.contains(['@', '?', '#']) || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad("must have no user, query, fragment or blank"));
    }
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.contains(']') => (host, Some(port)),
        _ => (authority, None),
    };
    if host.is_empty() {
        return Err(bad("has no host"));
    }
    let port = match port.map(str::parse::<u16>) {
        None => None,
        Some(Ok(p)) => Some(p),
        Some(Err(_)) => return Err(bad("has an invalid port")),
    };
    if https && port.is_some_and(|p| p != 443) {
        return Err(bad(
            "an `https` URL uses port 443, the only one the sandbox connects to",
        ));
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = bare == "localhost" || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !https && !loopback {
        return Err(bad("plain `http` is accepted only for a loopback host"));
    }
    Ok(url.trim_end_matches('/').to_owned())
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
        self.validate_routes()?;
        self.validate_fronts()
    }

    fn validate_fronts(&self) -> Result<(), Fault> {
        let Some(f) = &self.fronts else {
            return Ok(());
        };
        if f.messages.is_none() && f.openai.is_none() {
            return Err((
                "fronts".into(),
                "serves no front: needs `[fronts.messages]` or `[fronts.openai]`".into(),
            ));
        }
        if f.messages
            .as_ref()
            .is_some_and(|m| m.vendor.trim().is_empty())
        {
            return Err(("fronts.messages.vendor".into(), "is empty".into()));
        }
        if let Some(o) = &f.openai {
            if o.vendor.trim().is_empty() {
                return Err(("fronts.openai.vendor".into(), "is empty".into()));
            }
            if o.max_tokens == 0 {
                return Err((
                    "fronts.openai.max_tokens".into(),
                    "must be at least 1".into(),
                ));
            }
        }
        if f.models.len() > MAX_MODELS {
            return Err(too_many("fronts.models".into(), f.models.len(), MAX_MODELS));
        }
        for (model, alias) in &f.models {
            let at = format!("fronts.models.\"{model}\"");
            if model.is_empty() {
                return Err((at, "an empty model name".into()));
            }
            if self.route(model).is_some() {
                return Err((at, "is a route alias, which needs no entry".into()));
            }
            if self.route(alias).is_none() {
                return Err((at, format!("unknown route alias `{alias}`")));
            }
        }
        Ok(())
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

    /// The route a front request for `model` runs on: the alias `fronts.models` maps it to, or
    /// the alias `model` itself.
    pub fn route_of_model(&self, model: &str) -> Option<&Route> {
        let models = self.fronts.as_ref().map_or(&[][..], |f| &f.models);
        match models.iter().find(|(name, _)| name == model) {
            Some((_, alias)) => self.route(alias),
            None => self.route(model),
        }
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
api = "anthropic"
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
        assert_eq!(
            (login.kind, login.api, login.base_url.as_deref()),
            (CredentialKind::ApiKey, Api::Anthropic, None)
        );
        assert_eq!(
            login.credentials,
            Path::new("/var/lib/qb-gateway/login-1.json")
        );
        assert_eq!(c.route("chat").and_then(|r| r.difficulty), Some(1));
        for (url, want) in [
            ("https://api.example.com/", "https://api.example.com"),
            (
                "https://api.example.com:443/proxy",
                "https://api.example.com:443/proxy",
            ),
            ("http://127.0.0.1:8080/", "http://127.0.0.1:8080"),
            ("http://[::1]:9", "http://[::1]:9"),
            ("http://localhost", "http://localhost"),
        ] {
            let extra = format!(
                "[[logins]]\nname = \"login-2\"\nkind = \"oauth_anthropic\"\nbase_url = \"{url}\"\ncredentials = \"/c.json\"\n"
            );
            let c = check("", &extra).unwrap();
            let login = c.login("login-2").unwrap();
            assert_eq!(login.api, Api::Anthropic, "the default of an OAuth login");
            assert_eq!(login.base_url.as_deref(), Some(want));
        }
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
    fn a_chatgpt_login_speaks_openai() {
        let login = |api: &str| {
            format!(
                "[[logins]]\nname = \"login-2\"\nkind = \"chatgpt_oauth\"\n{api}credentials = \"/c.json\"\n"
            )
        };
        for api in ["", "api = \"openai\"\n"] {
            let c = check("", &login(api)).unwrap();
            let l = c.login("login-2").unwrap();
            assert_eq!((l.kind, l.api), (CredentialKind::ChatgptOauth, Api::Openai));
        }
        let err = check("", &login("api = \"anthropic\"\n")).unwrap_err();
        assert!(
            err.contains("logins[1].api: a `chatgpt_oauth` login is `openai` (line 16)"),
            "{err}"
        );
    }

    #[test]
    fn a_chat_completions_login_is_an_api_key_with_a_base_url_and_attribution() {
        let login = |kind: &str, api: &str, rest: &str| {
            format!(
                "[[logins]]\nname = \"login-2\"\nkind = \"{kind}\"\napi = \"{api}\"\n{rest}credentials = \"/c.json\"\n"
            )
        };
        let url = "base_url = \"https://vendor.example.com/api/v1/\"\n";
        let full = login(
            "api_key",
            "chat_completions",
            &format!("{url}referer = \"https://app.example.com\"\ntitle = \"Test App\"\n"),
        );
        let c = check("", &full).unwrap();
        let l = c.login("login-2").unwrap();
        assert_eq!(
            (l.kind, l.api, l.base_url.as_deref()),
            (
                CredentialKind::ApiKey,
                Api::ChatCompletions,
                Some("https://vendor.example.com/api/v1")
            )
        );
        assert_eq!(
            (l.referer.as_deref(), l.title.as_deref()),
            (Some("https://app.example.com"), Some("Test App"))
        );
        let bare = check("", &login("api_key", "chat_completions", url)).unwrap();
        let l = bare.login("login-2").unwrap();
        assert_eq!((l.referer.as_deref(), l.title.as_deref()), (None, None));

        for (extra, want) in [
            (
                login("api_key", "chat_completions", ""),
                "logins[1].base_url: is missing; a `chat_completions` login names its vendor's URL (line 16)",
            ),
            (
                login("oauth_anthropic", "chat_completions", url),
                "logins[1].api: an `oauth_anthropic` login is `anthropic` (line 16)",
            ),
            (
                login("chatgpt_oauth", "chat_completions", url),
                "logins[1].api: a `chatgpt_oauth` login is `openai` (line 16)",
            ),
            (
                login(
                    "api_key",
                    "openai",
                    "referer = \"https://app.example.com\"\n",
                ),
                "logins[1].referer: belongs to a `chat_completions` login (line 17)",
            ),
            (
                login("api_key", "anthropic", "title = \"Test App\"\n"),
                "logins[1].title: belongs to a `chat_completions` login (line 17)",
            ),
            (
                login(
                    "api_key",
                    "chat_completions",
                    &format!("{url}title = \"\"\n"),
                ),
                "logins[1].title: must be non-empty printable ASCII (line 18)",
            ),
            (
                login(
                    "api_key",
                    "chat_completions",
                    &format!("{url}referer = \"https://a.example\\r\\nx: 1\"\n"),
                ),
                "logins[1].referer: must be non-empty printable ASCII (line 18)",
            ),
            (
                login("api_key", "chat", url),
                "logins[1].api: expected `anthropic`, `openai` or `chat_completions` (line 16)",
            ),
        ] {
            let err = check("", &extra).unwrap_err();
            assert!(err.contains(want), "{err}");
        }
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
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\napi = \"openai\"\ncredentials = \"rel.json\"\n",
                "logins[1].credentials: must be an absolute path",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\ncredentials = \"/c.json\"\n",
                "logins[1].api: is missing; an `api_key` login names its API",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"oauth_anthropic\"\napi = \"openai\"\ncredentials = \"/c.json\"\n",
                "logins[1].api: an `oauth_anthropic` login is `anthropic` (line 16)",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"oauth\"\ncredentials = \"/c.json\"\n",
                "logins[1].kind: expected `oauth_anthropic`, `chatgpt_oauth` or `api_key` (line 15)",
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
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\napi = \"openai\"\nbase_url = \"http://example.com\"\ncredentials = \"/c.json\"\n",
                "logins[1].base_url: plain `http` is accepted only for a loopback host",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\napi = \"openai\"\nbase_url = \"https://example.com:8443\"\ncredentials = \"/c.json\"\n",
                "logins[1].base_url: an `https` URL uses port 443",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\napi = \"openai\"\nbase_url = \"https://u@example.com\"\ncredentials = \"/c.json\"\n",
                "logins[1].base_url: must have no user",
            ),
            (
                "",
                "[[logins]]\nname = \"login-2\"\nkind = \"api_key\"\napi = \"openai\"\nbase_url = \"example.com\"\ncredentials = \"/c.json\"\n",
                "logins[1].base_url: must start with `https://` or `http://`",
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

    #[test]
    fn front_models_map_client_model_names_to_route_aliases() {
        let c = check(
            "",
            "[fronts]\nmodels = { \"model-2025-01-01\" = \"chat\" }\n\
             [fronts.messages]\nvendor = \"vendor-a\"\n\
             [fronts.openai]\nvendor = \"vendor-b\"\nmax_tokens = 4096\n",
        )
        .unwrap();
        let alias = |model: &str| c.route_of_model(model).map(|r| r.alias.as_str());
        assert_eq!(alias("model-2025-01-01"), Some("chat"));
        assert_eq!(alias("chat"), Some("chat"), "an alias names itself");
        assert_eq!(alias("model-unknown"), None);
        let fronts = c.fronts.clone().unwrap();
        assert_eq!(fronts.messages.unwrap().vendor, "vendor-a");
        let openai = fronts.openai.unwrap();
        assert_eq!(
            (openai.vendor.as_str(), openai.max_tokens),
            ("vendor-b", 4096)
        );
        assert_eq!(
            check("", "").unwrap().route_of_model("chat").unwrap().alias,
            "chat"
        );
        let only_openai = "[fronts.openai]\nvendor = \"v\"\nmax_tokens = 1\n";
        assert_eq!(
            check("", only_openai).unwrap().fronts.unwrap().messages,
            None
        );

        let messages = "[fronts.messages]\nvendor = \"v\"\n";
        let cases = [
            ("[fronts]\nmodels = {}\n".into(), "fronts: serves no front"),
            (
                "[fronts.messages]\nmodels = {}\n".into(),
                "fronts.messages.models: unknown field",
            ),
            (
                "[fronts.messages]\n".into(),
                "fronts.messages.vendor: is missing",
            ),
            (
                "[fronts.openai]\nvendor = \"v\"\n".into(),
                "fronts.openai.max_tokens: is missing",
            ),
            (
                "[fronts.openai]\nvendor = \"v\"\nmax_tokens = 0\n".into(),
                "fronts.openai.max_tokens: must be at least 1",
            ),
            (
                "[fronts.openai]\nvendor = \"v\"\nmax_tokens = -1\n".into(),
                "fronts.openai.max_tokens: is out of range",
            ),
            (
                "[fronts.openai]\nvendor = \"\"\nmax_tokens = 1\n".into(),
                "fronts.openai.vendor: is empty",
            ),
            (
                format!("[fronts]\nmodels = {{ m = \"nope\" }}\n{messages}"),
                "fronts.models.\"m\": unknown route alias `nope`",
            ),
            (
                format!("[fronts]\nmodels = {{ chat = \"chat\" }}\n{messages}"),
                "fronts.models.\"chat\": is a route alias",
            ),
            (
                format!("[fronts]\nmodels = {{ m = 1 }}\n{messages}"),
                "fronts.models.\"m\": expected a string, found integer (line 14)",
            ),
            (
                format!("[fronts]\nmodels = [\"m\"]\n{messages}"),
                "fronts.models: expected a table, found array",
            ),
            (
                "[fronts.messages]\nvendor = \" \"\n".into(),
                "fronts.messages.vendor: is empty",
            ),
        ];
        for (extra, want) in cases {
            let err = check("", &extra).unwrap_err();
            assert!(err.contains(want), "{extra}: {err}");
        }
    }

    #[test]
    fn a_loopback_listener_needs_the_client_token_hash() {
        let hash = "ab".repeat(32);
        let front =
            |keys: &str| format!("[fronts]\n{keys}\n[fronts.messages]\nvendor = \"vendor-a\"\n");
        let listen = |addr: &str| format!("listen = \"{addr}\"\ntoken_sha256 = \"{hash}\"");
        let f = check(
            "",
            &front(&format!(
                "{}\nping_interval_s = 30",
                listen("127.0.0.1:8080")
            )),
        )
        .unwrap()
        .fronts
        .unwrap();
        assert_eq!(f.listen, Some(SocketAddr::from(([127, 0, 0, 1], 8080))));
        assert_eq!(f.token_sha256, Some(BearerHash([0xab; 32])));
        assert_eq!(f.ping_interval_s, 30);
        let f = check("", &front(&listen("[::1]:8080")))
            .unwrap()
            .fronts
            .unwrap();
        assert_eq!(f.listen.map(|a| a.ip().is_loopback()), Some(true));
        assert_eq!(f.ping_interval_s, 10, "the default");
        let without = check("", &front("")).unwrap().fronts.unwrap();
        assert_eq!((without.listen, without.token_sha256), (None, None));

        let cases = [
            (
                listen("0.0.0.0:8080"),
                "fronts.listen: must be a loopback address (line 14)",
            ),
            (
                listen("192.0.2.1:8080"),
                "fronts.listen: must be a loopback address",
            ),
            (
                listen("localhost:8080"),
                "fronts.listen: expected `127.0.0.1:<port>` or `[::1]:<port>`",
            ),
            (
                listen("127.0.0.1:0"),
                "fronts.listen: needs a port other than 0",
            ),
            (
                "listen = \"127.0.0.1:8080\"".into(),
                "fronts.token_sha256: is missing; `listen` needs the client token's hash (line 14)",
            ),
            (
                listen("127.0.0.1:8080").replace(&hash, "qb-plaintext-token"),
                "fronts.token_sha256: expected the token's SHA-256 as 64 hex characters (line 15)",
            ),
            (
                format!("token_sha256 = \"{hash}\""),
                "fronts.token_sha256: belongs to a `listen` address",
            ),
            (
                "ping_interval_s = 31".into(),
                "fronts.ping_interval_s: must be 1 to 30 (line 14)",
            ),
            (
                "ping_interval_s = 0".into(),
                "fronts.ping_interval_s: must be 1 to 30",
            ),
        ];
        for (keys, want) in cases {
            let err = check("", &front(&keys)).unwrap_err();
            assert!(err.contains(want), "{keys}: {err}");
            assert!(!err.contains("qb-plaintext-token"), "{err}");
        }
    }

    #[test]
    fn a_token_url_follows_the_url_rules_on_oauth_logins_only() {
        let login = |kind: &str, url: &str| {
            format!(
                "[[logins]]\nname = \"login-2\"\n{kind}\ntoken_url = \"{url}\"\ncredentials = \"/c.json\"\n"
            )
        };
        let oauth = "kind = \"oauth_anthropic\"";
        let c = check("", &login(oauth, "http://127.0.0.1:443/v1/oauth/token/")).unwrap();
        assert_eq!(
            c.login("login-2").unwrap().token_url.as_deref(),
            Some("http://127.0.0.1:443/v1/oauth/token")
        );
        assert_eq!(c.login("login-1").unwrap().token_url, None);
        let cases = [
            (
                login(oauth, "https://example.com:8443/t"),
                "logins[1].token_url: an `https` URL uses port 443",
            ),
            (
                login(oauth, "http://example.com/t"),
                "logins[1].token_url: plain `http` is accepted only for a loopback host",
            ),
            (
                login(
                    "kind = \"api_key\"\napi = \"anthropic\"",
                    "https://example.com/t",
                ),
                "logins[1].token_url: belongs to an `oauth_anthropic` login (line 17)",
            ),
            (
                login("kind = \"chatgpt_oauth\"", "https://example.com/t"),
                "logins[1].token_url: belongs to an `oauth_anthropic` login (line 16)",
            ),
        ];
        for (extra, want) in cases {
            let err = check("", &extra).unwrap_err();
            assert!(err.contains(want), "{extra}: {err}");
        }
    }
}
