//! Gateway contract fixtures: valid ones decode, validate and re-encode to the same JSON; invalid
//! ones fail to decode or to validate.

#![allow(clippy::unwrap_used)]

use qb_proto::{
    Block, CancelAnswer, CancelRequest, ErrorClass, GatewayError, Message, ReloadAnswer, Role,
    RouteState, RoutesAnswer, SpendAnswer, SpendReset, StopReason, StreamEvent, TurnRequest,
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

#[test]
fn openapi_enums_match_the_types() {
    use qb_proto::{ErrorClass as C, RouteState as R, StopReason as S};
    let path = format!(
        "{}/../../docs/openapi-gateway.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let schema = |name: &str| -> Vec<String> {
        doc["components"]["schemas"][name]["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}"))
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    let classes = [
        C::QuotaExhausted,
        C::Auth,
        C::Unavailable,
        C::Overloaded,
        C::BadRequest,
        C::ContextTooLong,
        C::Cancelled,
        C::NoRoute,
    ];
    assert_eq!(schema("ErrorClass"), names(&classes));
    for c in classes {
        assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
    }
    let stops = [S::End, S::ToolUse, S::MaxTokens, S::Refusal];
    assert_eq!(schema("StopReason"), names(&stops));
    let states = [R::Ready, R::Degraded, R::Exhausted, R::Unavailable];
    assert_eq!(schema("RouteState"), names(&states));
}
