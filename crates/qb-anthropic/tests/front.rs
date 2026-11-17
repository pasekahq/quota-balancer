//! Client direction: an SDK-shaped Messages request to a canonical turn, canonical events to a
//! Messages SSE stream and response body, canonical errors to Messages error answers.

mod common;

use common::{NOW, VENDOR, fixture, run};
use qb_anthropic::front::{
    Assembler, FOREIGN_THINKING, SseEncoder, decode_request, error_response,
};
use qb_anthropic::wire::ContentBlock;
use qb_proto::{
    Block, CacheMode, Effort, ErrorClass, GatewayError, Object, Role, RouteInfo, StopReason,
    StreamEvent, Thinking, ToolCall, Usage,
};
use serde_json::{Value, json};

fn route_of(model: &str) -> Option<String> {
    (model == "claude-opus-5-5").then(|| "chat".to_owned())
}

fn obj(v: Value) -> Object {
    match v {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

#[test]
fn sdk_request_decodes_to_a_canonical_turn() {
    let got = decode_request(
        &fixture("client_sdk_request.json"),
        "msg-1",
        VENDOR,
        &route_of,
    )
    .expect("decodes");
    assert!(got.stream);
    assert_eq!(got.model, "claude-opus-5-5");
    let t = got.turn;
    assert_eq!(t.route, "chat");
    assert_eq!(t.request_id, "msg-1");
    assert_eq!(t.system.as_deref(), Some("You are a helpful assistant."));
    assert_eq!(t.max_tokens, 32_000);
    assert_eq!(t.effort, Some(Effort::High));
    assert_eq!(t.session_key.as_deref(), Some("session-test-1"));
    assert_eq!(t.cache, Some(CacheMode::Auto));
    assert_eq!(t.tools.len(), 1);
    assert_eq!(t.messages.len(), 4);
    assert_eq!(
        t.messages[0].content,
        vec![Block::Text {
            text: "What is in this picture and in notes.txt?".into()
        }]
    );
    assert!(matches!(
        &t.messages[1].content[0],
        Block::Image { base64: Some(b), path: None, .. } if b.starts_with("iVBOR")
    ));
    let assistant = &t.messages[2];
    assert_eq!(assistant.role, Role::Assistant);
    assert_eq!(
        assistant.content[0],
        Block::Thinking {
            vendor: VENDOR.into(),
            opaque: r#"{"type":"thinking","thinking":"Read the file first.","signature":"c2lnbmF0dXJlLXRlc3QtMQ=="}"#.into()
        }
    );
    assert_eq!(
        assistant.content[3],
        Block::ToolUse {
            id: "toolu_test_1".into(),
            name: "read".into(),
            input: obj(json!({"path": "notes.txt"}))
        }
    );
    assert_eq!(
        t.messages[3].content,
        vec![Block::ToolResult {
            id: "toolu_test_1".into(),
            content: "line one\nline two".into(),
            is_error: Some(false)
        }]
    );
}

#[test]
fn rejected_requests_are_bad_requests() {
    let base: Value = serde_json::from_slice(&fixture("client_sdk_request.json")).expect("json");
    let mut cases: Vec<(&str, Value)> = Vec::new();
    let mut v = base.clone();
    v["model"] = json!("model-unknown");
    cases.push(("unknown model", v));
    let mut v = base.clone();
    v["messages"][0]["content"] =
        json!([{"type": "document", "source": {"type": "text", "data": "x"}}]);
    cases.push(("document block", v));
    let mut v = base.clone();
    v["messages"][1]["content"][0]["source"] =
        json!({"type": "url", "url": "https://example.invalid/a.png"});
    cases.push(("url image", v));
    let mut v = base.clone();
    v["messages"][0]["role"] = json!("system");
    cases.push(("system role", v));
    let mut v = base.clone();
    v["messages"] = json!([]);
    cases.push(("no messages", v));
    let mut v = base.clone();
    v["max_tokens"] = json!("many");
    cases.push(("mistyped max_tokens", v));
    for (what, body) in cases {
        let e = decode_request(body.to_string().as_bytes(), "msg-1", VENDOR, &route_of)
            .expect_err(what);
        assert_eq!(e.class, ErrorClass::BadRequest, "{what}");
        assert_eq!(error_response(&e, NOW).status, 400, "{what}");
    }
    let e = decode_request(b"{not json", "msg-1", VENDOR, &route_of).expect_err("garbage");
    assert_eq!(e.class, ErrorClass::BadRequest);
}

#[test]
fn a_plain_request_has_no_cache_and_no_stream() {
    let body = json!({
        "model": "claude-opus-5-5",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "Hi"}]
    });
    let got = decode_request(body.to_string().as_bytes(), "m", VENDOR, &route_of).expect("ok");
    assert!(!got.stream);
    assert_eq!(got.turn.cache, None);
    assert_eq!(got.turn.system, None);
}

fn turn_events() -> Vec<StreamEvent> {
    vec![
        StreamEvent::Route {
            route: RouteInfo {
                vendor: VENDOR.into(),
                model: "model-a".into(),
                login_label: "login-1".into(),
                lease: "lease-1".into(),
            },
        },
        StreamEvent::Usage {
            usage: Usage {
                input: 25,
                output: 1,
                cache_read: 2000,
                cache_write: 100,
            },
        },
        StreamEvent::Thinking {
            thinking: Thinking {
                vendor: VENDOR.into(),
                opaque: r#"{"type":"thinking","thinking":"Plan.","signature":"c2lnLTE="}"#.into(),
            },
        },
        StreamEvent::TextDelta {
            text: "Reading ".into(),
        },
        StreamEvent::TextDelta {
            text: "the file.".into(),
        },
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "toolu_test_1".into(),
                name: "read".into(),
                input: obj(json!({"path": "notes.txt"})),
            },
        },
        StreamEvent::Usage {
            usage: Usage {
                input: 25,
                output: 40,
                cache_read: 2000,
                cache_write: 100,
            },
        },
        StreamEvent::Stop {
            reason: StopReason::ToolUse,
        },
    ]
}

fn encode_all(events: &[StreamEvent]) -> Vec<u8> {
    let mut enc = SseEncoder::new("msg_test_1", "claude-opus-5-5", VENDOR);
    let mut out = Vec::new();
    for e in events {
        out.extend(enc.push(e));
    }
    out
}

#[test]
fn canonical_events_encode_to_the_recorded_client_stream() {
    let got = encode_all(&turn_events());
    assert_eq!(
        String::from_utf8(got).expect("utf-8"),
        String::from_utf8(fixture("client_stream.sse")).expect("utf-8")
    );
}

#[test]
fn the_client_stream_reads_back_as_the_same_events() {
    let events = turn_events();
    let got = run(&encode_all(&events));
    assert_eq!(got.end, Ok(StopReason::ToolUse));
    // `route` and `stop` are the core's; the second `usage` arrives with `message_delta`.
    let want = &events[1..events.len() - 1];
    assert_eq!(got.events, want);
}

#[test]
fn non_streaming_response_body() {
    let mut a = Assembler::new("msg_test_1", "claude-opus-5-5", VENDOR);
    for e in turn_events() {
        a.push(&e);
    }
    let body = serde_json::to_value(a.finish().expect("stopped")).expect("json");
    assert_eq!(
        body,
        json!({
            "id": "msg_test_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5-5",
            "content": [
                {"type": "thinking", "thinking": "Plan.", "signature": "c2lnLTE="},
                {"type": "text", "text": "Reading the file."},
                {"type": "tool_use", "id": "toolu_test_1", "name": "read", "input": {"path": "notes.txt"}}
            ],
            "stop_reason": "tool_use",
            "stop_sequence": null,
            "usage": {
                "input_tokens": 25,
                "cache_creation_input_tokens": 100,
                "cache_read_input_tokens": 2000,
                "output_tokens": 40
            }
        })
    );
}

#[test]
fn foreign_thinking_survives_a_messages_client_round_trip() {
    let foreign = Thinking {
        vendor: "vendor-b".into(),
        opaque: "b3BhcXVlLWI=".into(),
    };
    let mut a = Assembler::new("m", "claude-opus-5-5", VENDOR);
    a.push(&StreamEvent::Thinking {
        thinking: foreign.clone(),
    });
    a.push(&StreamEvent::Stop {
        reason: StopReason::End,
    });
    let answer = a.finish().expect("stopped");
    let ContentBlock::RedactedThinking { data } = &answer.content[0] else {
        panic!("{:?}", answer.content);
    };
    assert!(data.starts_with(FOREIGN_THINKING));
    let echo = json!({
        "model": "claude-opus-5-5",
        "max_tokens": 16,
        "messages": [
            {"role": "user", "content": "Hi"},
            {"role": "assistant", "content": [answer.content[0].clone()]},
            {"role": "user", "content": "Again"}
        ]
    });
    let got = decode_request(echo.to_string().as_bytes(), "m", VENDOR, &route_of).expect("ok");
    assert_eq!(
        got.turn.messages[1].content,
        vec![Block::Thinking {
            vendor: foreign.vendor,
            opaque: foreign.opaque
        }]
    );
}

#[test]
fn errors_map_to_messages_answers() {
    let mut quota = GatewayError::new(ErrorClass::QuotaExhausted, true, "out of quota");
    quota.resets_at = Some(NOW + 3600);
    let r = error_response(&quota, NOW);
    assert_eq!((r.status, r.retry_after), (429, Some(3600)));
    assert_eq!(r.body.error.kind, "rate_limit_error");
    assert_eq!(
        serde_json::to_value(&r.body).expect("json"),
        json!({"type": "error", "error": {"type": "rate_limit_error", "message": "out of quota"}})
    );
    quota.resets_at = Some(NOW - 5);
    assert_eq!(error_response(&quota, NOW).retry_after, Some(1));

    let mut over = GatewayError::new(ErrorClass::Overloaded, true, "busy");
    over.retry_after = Some(7);
    let r = error_response(&over, NOW);
    assert_eq!((r.status, r.retry_after), (529, Some(7)));
    assert_eq!(r.body.error.kind, "overloaded_error");

    for (class, status, kind) in [
        (ErrorClass::Auth, 401, "authentication_error"),
        (ErrorClass::BadRequest, 400, "invalid_request_error"),
        (ErrorClass::ContextTooLong, 400, "invalid_request_error"),
        (ErrorClass::Unavailable, 502, "api_error"),
    ] {
        let r = error_response(&GatewayError::new(class, false, "x"), NOW);
        assert_eq!(
            (r.status, r.body.error.kind.as_str()),
            (status, kind),
            "{class:?}"
        );
    }
    let r = error_response(
        &GatewayError::new(ErrorClass::ContextTooLong, false, "x"),
        NOW,
    );
    assert!(r.body.error.message.starts_with("prompt is too long"));
}

#[test]
fn an_error_after_the_start_is_an_error_event() {
    let mut enc = SseEncoder::new("m", "claude-opus-5-5", VENDOR);
    assert_eq!(enc.push(&turn_events()[0]), b"");
    assert!(!enc.started());
    enc.push(&StreamEvent::TextDelta { text: "Hi".into() });
    assert!(enc.started());
    let bytes = enc.push(&StreamEvent::Error {
        error: GatewayError::new(ErrorClass::Overloaded, true, "busy"),
    });
    assert_eq!(
        String::from_utf8(bytes).expect("utf-8"),
        "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"busy\"}}\n\n"
    );
    let after = enc.push(&StreamEvent::Stop {
        reason: StopReason::End,
    });
    assert_eq!(after, b"");
}
