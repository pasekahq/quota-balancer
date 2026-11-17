//! Gateway contract fixtures: valid ones decode, validate and re-encode to the same JSON; invalid
//! ones fail to decode or to validate.

use qb_proto::{
    Block, CancelAnswer, CancelRequest, ErrorClass, GatewayError, Message, Role, RouteState,
    RoutesAnswer, StopReason, StreamEvent, TurnRequest,
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
            "StreamEvent" => rejected(&raw, |_: StreamEvent| true),
            "CancelRequest" => rejected(&raw, |_: CancelRequest| true),
            "Error" => rejected(&raw, |_: GatewayError| true),
            other => panic!("{name}: no type {other}"),
        };
        assert!(refused, "{name} was accepted");
        seen += 1;
    }
    assert!(seen >= 15, "only {seen} invalid fixtures");
}
