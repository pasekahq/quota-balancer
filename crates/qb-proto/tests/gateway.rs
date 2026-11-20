//! Gateway contract fixtures: valid ones decode, validate and re-encode to the same JSON; invalid
//! ones fail to decode or to validate.

#![allow(clippy::unwrap_used)]

use qb_proto::{
    AuditAction, AuditAnswer, AuditResult, Block, CacheMode, CancelAnswer, CancelRequest,
    ClientRotateAnswer, ConfigRoutes, ConfigRoutesPut, ConfigRoutesWritten, Effort, Elsewhere,
    ErrorClass, GatewayError, HealthStatus, LoginKey, LoginKeyAnswer, LoginOauthCode,
    LoginOauthSigned, LoginOauthStarted, MediaType, Message, NativeApi, OauthPaste, Object,
    Outcome, ReloadAnswer, Role, RolesSource, RouteInfo, RouteState, RoutesAnswer, SpendAnswer,
    SpendReset, StopReason, StreamEvent, Thinking, ToolCall, TurnRequest, Usage, UsageAnswer,
    UsageBucket, UsageGroupBy, UsageLine, UsageQuery, UsdSource,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn same<T: Serialize>(name: &str, raw: &str, value: &T) {
    let original: Value = serde_json::from_str(raw).expect("fixture is JSON");
    let again = serde_json::to_value(value).expect("encode");
    assert_eq!(original, again, "{name} does not round-trip");
}

fn roundtrip<T: Serialize + DeserializeOwned>(name: &str) -> T {
    let raw = fixture(name);
    let value: T = serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name}: {e}"));
    same(name, &raw, &value);
    value
}

#[test]
fn turn_requests() {
    let all: TurnRequest = roundtrip("gateway_turn_request_all_blocks.json");
    assert_eq!(all.validate(), Ok(()));
    let kinds: Vec<&str> = all
        .messages
        .iter()
        .flat_map(|m| &m.content)
        .map(|b| match b {
            Block::Text { .. } => "text",
            Block::Image { .. } => "image",
            Block::ToolUse { .. } => "tool_use",
            Block::ToolResult { .. } => "tool_result",
            Block::Thinking { .. } => "thinking",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "text",
            "image",
            "image",
            "thinking",
            "text",
            "tool_use",
            "tool_result"
        ]
    );
    let min: TurnRequest = roundtrip("gateway_turn_request_minimal.json");
    assert_eq!(min.validate(), Ok(()));
    assert_eq!(min.route, "compact");
    let native: TurnRequest = roundtrip("gateway_turn_request_native.json");
    assert_eq!(native.validate(), Ok(()));
    assert_eq!(native.messages[1].role, Role::System);
    assert_eq!(
        native
            .tools
            .iter()
            .map(|t| t.native.as_ref().map(|n| n.elsewhere))
            .collect::<Vec<_>>(),
        [Some(Elsewhere::Function), Some(Elsewhere::Omit)]
    );
}

#[test]
fn stream_events_in_order() {
    let raw = fixture("gateway_stream.ndjson");
    let mut types = Vec::new();
    for line in raw.lines() {
        let event: StreamEvent = serde_json::from_str(line).unwrap_or_else(|e| panic!("{e}"));
        same(line, line, &event);
        let v: Value = serde_json::from_str(line).unwrap();
        types.push(v["type"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        types,
        [
            "route",
            "thinking",
            "text_delta",
            "tool_call",
            "usage",
            "stop"
        ]
    );
    let last: StreamEvent = serde_json::from_str(raw.lines().last().unwrap()).unwrap();
    assert_eq!(
        last,
        StreamEvent::Stop {
            reason: StopReason::ToolUse
        }
    );
}

#[test]
fn stream_events_ignore_fields_a_later_version_adds() {
    let line = r#"{"type":"text_delta","text":"Hi","index":0}"#;
    let event: StreamEvent = serde_json::from_str(line).unwrap();
    assert_eq!(event, StreamEvent::TextDelta { text: "Hi".into() });
}

#[test]
fn errors_routes_cancel() {
    let StreamEvent::Error { error } = roundtrip("gateway_error_quota_exhausted.json") else {
        panic!("not an error event");
    };
    assert_eq!(
        (error.class, error.resets_at, error.tried.len()),
        (ErrorClass::QuotaExhausted, Some(1_800_018_000), 2)
    );
    let StreamEvent::Error { error } = roundtrip("gateway_error_overloaded.json") else {
        panic!("not an error event");
    };
    assert_eq!(error.retry_after, Some(30));
    for (name, class) in [
        ("gateway_error_cancelled.json", ErrorClass::Cancelled),
        ("gateway_error_no_route.json", ErrorClass::NoRoute),
    ] {
        let StreamEvent::Error { error } = roundtrip(name) else {
            panic!("not an error event");
        };
        assert_eq!(error.class, class);
    }
    let body: GatewayError = roundtrip("gateway_error_body.json");
    assert_eq!(body.class, ErrorClass::BadRequest);
    let routes: RoutesAnswer = roundtrip("gateway_routes_answer.json");
    assert_eq!(routes.routes[1].state, RouteState::Exhausted);
    let cancel: CancelRequest = roundtrip("gateway_cancel_request.json");
    assert_eq!(cancel.request_id, "turn-0001");
    let answer: CancelAnswer = roundtrip("gateway_cancel_answer.json");
    assert!(answer.cancelled);
    let reloaded: ReloadAnswer = roundtrip("gateway_reload_answer.json");
    assert_eq!((reloaded.routes, reloaded.logins), (3, 2));
    let spend: SpendAnswer = roundtrip("gateway_spend_answer.json");
    assert_eq!(spend.logins[0].period_end, 1_800_000_000);
    let reset: SpendReset = roundtrip("gateway_spend_reset_request.json");
    assert_eq!(reset.login, "key-1");
    let rotated: ClientRotateAnswer = roundtrip("gateway_client_rotate_answer.json");
    assert_eq!(
        (rotated.client.as_str(), rotated.grace_until),
        ("client-a", 1_800_003_600)
    );
    let key: LoginKey = roundtrip("gateway_login_key_request.json");
    assert_eq!(key.validate(), Ok(()));
    let replaced: LoginKeyAnswer = roundtrip("gateway_login_key_answer.json");
    assert_eq!(
        replaced.backup.as_deref(),
        Some("/etc/qb/credentials/key-1.json.bak-1800000480")
    );
    let first: LoginKeyAnswer = roundtrip("gateway_login_key_answer_first.json");
    assert_eq!(first.backup, None);
}

#[test]
fn audit_lines() {
    let audit: AuditAnswer = roundtrip("gateway_audit_answer.json");
    let lines: Vec<_> = audit
        .entries
        .iter()
        .map(|e| (e.actor.as_str(), e.action, e.result, e.object.as_deref()))
        .collect();
    assert_eq!(
        lines,
        [
            (
                "uid:1000",
                AuditAction::Reload,
                AuditResult::Ok,
                Some("/etc/qb/gateway.toml")
            ),
            (
                "signal",
                AuditAction::Reload,
                AuditResult::Refused,
                Some("/etc/qb/gateway.toml")
            ),
            (
                "uid:1000",
                AuditAction::SpendReset,
                AuditResult::Ok,
                Some("key-1")
            ),
            (
                "uid:1001",
                AuditAction::SpendReset,
                AuditResult::Refused,
                None
            ),
            (
                "uid:1000",
                AuditAction::ClientRotate,
                AuditResult::Ok,
                Some("client-a")
            ),
            (
                "uid:1000",
                AuditAction::ClientRotate,
                AuditResult::Refused,
                Some("client-b")
            ),
            (
                "uid:1000",
                AuditAction::ConfigRoutes,
                AuditResult::Ok,
                Some("/etc/qb/gateway.toml")
            ),
            (
                "uid:1000",
                AuditAction::ConfigSpendCaps,
                AuditResult::Refused,
                Some("/etc/qb/gateway.toml")
            ),
            (
                "uid:1000",
                AuditAction::LoginKey,
                AuditResult::Ok,
                Some("key-1")
            ),
            (
                "uid:1000",
                AuditAction::LoginKey,
                AuditResult::Refused,
                Some("login-1")
            ),
        ]
    );
    let prefixes: Vec<_> = audit
        .entries
        .iter()
        .map(|e| e.token_sha256_prefix.as_deref())
        .collect();
    assert_eq!(
        prefixes,
        [
            None,
            None,
            None,
            None,
            Some("5d35a058cf51"),
            None,
            None,
            None,
            None,
            None
        ]
    );
    let edit = &audit.entries[6];
    assert_eq!(
        edit.backup.as_deref(),
        Some("/etc/qb/gateway.toml.bak-1800000360")
    );
    assert_eq!(audit.skipped, 1);
}

#[test]
fn audit_lines_of_key_replacements() {
    let audit: AuditAnswer = roundtrip("gateway_audit_answer.json");
    let keys: Vec<_> = audit
        .entries
        .iter()
        .map(|e| (e.key_sha256_prefix.as_deref(), e.backup.as_deref()))
        .collect();
    assert_eq!(
        keys[8..],
        [
            (
                Some("5bcc977b51d5"),
                Some("/etc/qb/credentials/key-1.json.bak-1800000480")
            ),
            (None, None)
        ]
    );
}

#[test]
fn sign_ins() {
    let started: LoginOauthStarted = roundtrip("gateway_login_oauth_started.json");
    assert_eq!(
        (started.paste, started.expires_at),
        (OauthPaste::CodeState, 1_800_000_600)
    );
    let redirect: LoginOauthStarted = roundtrip("gateway_login_oauth_started_redirect.json");
    assert_eq!(redirect.paste, OauthPaste::RedirectUrl);
    let code: LoginOauthCode = roundtrip("gateway_login_oauth_code_request.json");
    assert!(code.pasted.starts_with("synthetic-code-0001#"));
    let signed: LoginOauthSigned = roundtrip("gateway_login_oauth_signed.json");
    assert_eq!(
        signed.backup.as_deref(),
        Some("/etc/qb/credentials/login-1.json.bak-1800000300")
    );
    let first: LoginOauthSigned = roundtrip("gateway_login_oauth_signed_first.json");
    assert_eq!(first.backup, None);
    let audit: AuditAnswer = roundtrip("gateway_audit_answer_sign_in.json");
    let lines: Vec<_> = audit
        .entries
        .iter()
        .map(|e| (e.action, e.result, e.object.as_deref(), e.backup.as_deref()))
        .collect();
    assert_eq!(
        lines,
        [
            (
                AuditAction::LoginOauthStart,
                AuditResult::Ok,
                Some("login-1"),
                None
            ),
            (
                AuditAction::LoginOauthCode,
                AuditResult::Refused,
                Some("login-1"),
                None
            ),
            (
                AuditAction::LoginOauthCode,
                AuditResult::Ok,
                Some("login-1"),
                Some("/etc/qb/credentials/login-1.json.bak-1800000300")
            ),
            (
                AuditAction::LoginOauthStart,
                AuditResult::Refused,
                Some("login-2"),
                None
            ),
        ]
    );
}

#[test]
fn config_routes() {
    let read: ConfigRoutes = roundtrip("gateway_config_routes.json");
    let shapes: Vec<_> = read
        .routes
        .iter()
        .map(|r| {
            (
                r.difficulty,
                r.vendor.is_some(),
                r.chain.as_ref().map(Vec::len),
            )
        })
        .collect();
    assert_eq!(
        shapes,
        [
            (Some(1), false, None),
            (None, true, None),
            (None, false, Some(2))
        ]
    );
    let caps: Vec<_> = read.spend_caps.into_iter().collect();
    assert_eq!(caps, [("key-1".into(), Some(25.0)), ("key-2".into(), None)]);
    let put: ConfigRoutesPut = roundtrip("gateway_config_routes_put.json");
    let chain = put.routes.unwrap()[0].chain.clone().unwrap();
    assert_eq!(chain[1].effort.as_deref(), Some("low"));
    assert_eq!(put.spend_caps, None);
    let put: ConfigRoutesPut = roundtrip("gateway_config_spend_caps_put.json");
    assert_eq!(put.routes, None);
    let caps: Vec<_> = put.spend_caps.unwrap().into_iter().collect();
    assert_eq!(caps, [("key-1".into(), Some(40.5)), ("key-2".into(), None)]);
    let written: ConfigRoutesWritten = roundtrip("gateway_config_routes_written.json");
    assert_eq!(
        written.backup.as_deref(),
        Some("/etc/qb/gateway.toml.bak-1800000360")
    );
    let unchanged: ConfigRoutesWritten = roundtrip("gateway_config_routes_unchanged.json");
    assert_eq!(unchanged.backup, None);
}

#[test]
fn usage_lines() {
    let lines: Vec<UsageLine> = roundtrip("gateway_usage_lines.json");
    let ends: Vec<_> = lines
        .iter()
        .map(|l| (l.step, l.outcome, l.stop, l.error, l.usd_source))
        .collect();
    assert_eq!(
        ends,
        [
            (
                0,
                Outcome::UsageLimit,
                None,
                Some(ErrorClass::QuotaExhausted),
                None
            ),
            (
                1,
                Outcome::Ok,
                Some(StopReason::ToolUse),
                None,
                Some(UsdSource::Prices)
            ),
            (
                0,
                Outcome::Error,
                None,
                Some(ErrorClass::Cancelled),
                Some(UsdSource::Vendor)
            ),
        ]
    );
    assert_eq!(lines[1].usage.cache_read, 8000);
    assert_eq!(lines[1].tools, ["read_file", "search"]);
    assert_eq!(lines[0].usd, None);
}

#[test]
fn usage_query_and_answer() {
    let query: UsageQuery = roundtrip("gateway_usage_query.json");
    assert_eq!(
        (query.from, query.to, query.group_by, query.bucket),
        (
            1_800_000_000,
            Some(1_800_172_800),
            Some(UsageGroupBy::Login),
            Some(UsageBucket::Day)
        )
    );
    let unknown = serde_json::from_str::<UsageQuery>(r#"{"from":1,"limit":2}"#);
    assert!(unknown.is_err(), "{unknown:?}");
    let answer: UsageAnswer = roundtrip("gateway_usage_answer.json");
    let rows: Vec<_> = answer
        .rows
        .iter()
        .map(|r| {
            (
                r.start,
                r.group.as_deref(),
                r.attempts,
                r.failed,
                r.unpriced,
            )
        })
        .collect();
    assert_eq!(
        rows,
        [
            (1_799_971_200, Some("login-1"), 12, 1, 2),
            (1_799_971_200, Some("login-2"), 3, 3, 3),
            (1_800_057_600, Some("login-1"), 4, 0, 0),
        ]
    );
    assert_eq!(answer.skipped, 1);
}

/// A turn request around one block, for the block fixtures.
fn around(block: Block) -> TurnRequest {
    TurnRequest {
        route: "chat".into(),
        system: None,
        messages: vec![Message {
            role: Role::User,
            content: vec![block],
        }],
        tools: Vec::new(),
        max_tokens: 1,
        effort: None,
        session_key: None,
        cache: None,
        request_id: "turn-1".into(),
    }
}

/// Whether the fixture fails to decode as `T` or, when it decodes, fails `valid`.
fn rejected<T: DeserializeOwned>(raw: &str, valid: impl Fn(T) -> bool) -> bool {
    serde_json::from_str::<T>(raw).map_or(true, |v| !valid(v))
}

#[test]
fn invalid_fixtures_are_rejected() {
    let dir = format!(
        "{}/tests/fixtures/gateway/invalid",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let raw = std::fs::read_to_string(&path).unwrap();
        let kind = name.split('.').next().unwrap();
        let refused = match kind {
            "TurnRequest" => rejected(&raw, |r: TurnRequest| r.validate().is_ok()),
            "Block" => rejected(&raw, |b: Block| around(b).validate().is_ok()),
            // The decoder ignores fields a later version adds, so the rule that an event
            // carries only its own payload is checked here: it must re-encode to itself.
            "StreamEvent" => rejected(&raw, |e: StreamEvent| {
                serde_json::to_value(e).unwrap() == serde_json::from_str::<Value>(&raw).unwrap()
            }),
            "CancelRequest" => rejected(&raw, |_: CancelRequest| true),
            "ConfigRoutesPut" => rejected(&raw, |_: ConfigRoutesPut| true),
            "LoginKey" => rejected(&raw, |k: LoginKey| k.validate().is_ok()),
            "LoginOauthCode" => rejected(&raw, |_: LoginOauthCode| true),
            "Error" => rejected(&raw, |_: GatewayError| true),
            other => panic!("{name}: no type {other}"),
        };
        assert!(refused, "{name} was accepted");
        seen += 1;
    }
    assert!(seen >= 15, "only {seen} invalid fixtures");
}

/// The names `values` serialize to.
fn names<T: Serialize>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|v| {
            serde_json::to_value(v)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// The `type` tags `values` serialize with.
fn tags<T: Serialize>(values: &[T]) -> Vec<String> {
    values
        .iter()
        .map(|v| {
            serde_json::to_value(v).unwrap()["type"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// The JSON pointer and the values of every `enum` in `v` at `at`.
fn enums(at: &str, v: &Value, out: &mut Vec<(String, Vec<String>)>) {
    match v {
        Value::Object(map) => {
            if let Some(values) = map.get("enum") {
                let values = values.as_array().unwrap();
                let values = values.iter().map(|v| v.as_str().unwrap().to_owned());
                out.push((at.to_owned(), values.collect()));
            }
            for (key, v) in map {
                enums(&format!("{at}/{key}"), v, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                enums(&format!("{at}/{i}"), v, out);
            }
        }
        _ => {}
    }
}

/// Every variant of the enum `$t`, built as given: the `match` stops compiling when `$t` gains a
/// variant the listing lacks, and a variant listed twice is an unreachable pattern.
macro_rules! every {
    ($t:ident: $($v:ident $({ $($field:tt)* })?),+ $(,)?) => {{
        let _exhaustive = |x: &$t| match x {
            $($t::$v { .. } => ()),+
        };
        [$($t::$v $({ $($field)* })?),+]
    }};
}

/// One block of each kind.
fn every_block() -> [Block; 5] {
    let text = || "t".to_owned();
    every!(Block:
        Text { text: text() },
        Image {
            media_type: MediaType::Png,
            path: None,
            base64: Some(text()),
        },
        ToolUse {
            id: text(),
            name: text(),
            input: Object::new(),
        },
        ToolResult {
            id: text(),
            content: text(),
            is_error: None,
        },
        Thinking {
            vendor: text(),
            opaque: text(),
        },
    )
}

/// One event of each kind.
fn every_event() -> [StreamEvent; 7] {
    let text = || "t".to_owned();
    every!(StreamEvent:
        Route {
            route: RouteInfo {
                vendor: text(),
                model: text(),
                login_label: text(),
                lease: text(),
            },
        },
        TextDelta { text: text() },
        Thinking {
            thinking: Thinking {
                vendor: text(),
                opaque: text(),
            },
        },
        ToolCall {
            tool_call: ToolCall {
                id: text(),
                name: text(),
                input: Object::new(),
            },
        },
        Usage {
            usage: Usage::default(),
        },
        Stop {
            reason: StopReason::End,
        },
        Error {
            error: GatewayError::new(ErrorClass::Auth, false, text()),
        },
    )
}

/// The JSON pointer of each `enum` of `docs/openapi-gateway.json` and the names of every variant
/// of its qb-proto type.
fn typed_enums() -> Vec<(String, Vec<String>)> {
    let schema = |name: &str| format!("/components/schemas/{name}");
    let group_by = every!(UsageGroupBy: Client, Login, Model, Route, Tool);
    assert_eq!(group_by, UsageGroupBy::ALL, "`ALL` lists every grouping");
    let bucket = every!(UsageBucket: Hour, Day, Month);
    assert_eq!(bucket, UsageBucket::ALL, "`ALL` lists every bucket");
    vec![
        (
            schema("Effort"),
            names(&every!(Effort: Low, Medium, High, Max)),
        ),
        (schema("CacheMode"), names(&every!(CacheMode: Auto))),
        (
            schema("Role"),
            names(&every!(Role: User, Assistant, System)),
        ),
        (schema("BlockType"), tags(&every_block())),
        (
            schema("MediaType"),
            names(&every!(MediaType: Png, Jpeg, Gif, Webp)),
        ),
        (
            schema("NativeTool/properties/api"),
            names(&every!(NativeApi: OpenaiResponses)),
        ),
        (
            schema("NativeTool/properties/elsewhere"),
            names(&every!(Elsewhere: Function, Omit, Refuse)),
        ),
        (schema("EventType"), tags(&every_event())),
        (
            schema("StopReason"),
            names(&every!(StopReason: End, ToolUse, MaxTokens, Refusal)),
        ),
        (schema("ErrorClass"), names(&every_class())),
        (
            schema("RouteState"),
            names(&every!(RouteState: Ready, Degraded, Exhausted, Unavailable)),
        ),
        (
            schema("OauthPaste"),
            names(&every!(OauthPaste: CodeState, RedirectUrl)),
        ),
        (
            schema("AuditAction"),
            names(&every!(AuditAction:
                Reload,
                SpendReset,
                ClientRotate,
                ConfigRoutes,
                ConfigSpendCaps,
                LoginKey,
                LoginOauthStart,
                LoginOauthCode,
                AdminRoles,
                AdminReload,
            )),
        ),
        (
            schema("AdminRoles/properties/source"),
            names(&every!(RolesSource: RolesFile, Config)),
        ),
        (
            schema("AuditResult"),
            names(&every!(AuditResult: Ok, Refused)),
        ),
        (schema("UsageGroupBy"), names(&group_by)),
        (schema("UsageBucket"), names(&bucket)),
        (
            schema("Health/properties/status"),
            names(&every!(HealthStatus: Ok)),
        ),
    ]
}

/// Every [`ErrorClass`].
fn every_class() -> [ErrorClass; 8] {
    every!(ErrorClass:
        QuotaExhausted,
        Auth,
        Unavailable,
        Overloaded,
        BadRequest,
        ContextTooLong,
        Cancelled,
        NoRoute,
    )
}

#[test]
fn openapi_enums_match_the_types() {
    let path = format!(
        "{}/../../docs/openapi-gateway.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for c in every_class() {
        assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
    }
    let typed = typed_enums();
    let mut found = Vec::new();
    enums("", &doc, &mut found);
    for (at, values) in &found {
        let (_, want) = typed
            .iter()
            .find(|(path, _)| path == at)
            .unwrap_or_else(|| panic!("the enum at {at} maps to no qb-proto type"));
        assert_eq!(values, want, "{at}");
    }
    let mut paths: Vec<&str> = found.iter().map(|(at, _)| at.as_str()).collect();
    let mut mapped: Vec<&str> = typed.iter().map(|(at, _)| at.as_str()).collect();
    paths.sort_unstable();
    mapped.sort_unstable();
    assert_eq!(paths, mapped, "every mapped type has its enum");
}

#[test]
fn audit_lines_of_forwarded_admin_requests() {
    let audit: AuditAnswer = roundtrip("gateway_audit_answer_admin.json");
    let lines: Vec<_> = audit
        .entries
        .iter()
        .map(|e| (e.action, e.result, e.backup.as_deref()))
        .collect();
    assert_eq!(
        lines,
        [
            (
                AuditAction::AdminRoles,
                AuditResult::Ok,
                Some("/var/lib/qb/roles.toml.bak-1800000000")
            ),
            (AuditAction::AdminRoles, AuditResult::Refused, None),
            (AuditAction::AdminReload, AuditResult::Ok, None),
        ]
    );
}
