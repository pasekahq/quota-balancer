//! The `/v1/responses` front: request decoding, the SSE stream with its item lifecycle, the
//! response object and in-stream errors.

mod common;

use common::{NOW, OTHER, VENDOR, anthropic_events, check_responses, fixture, frames};
use qb_openai::front::ForeignThinking;
use qb_openai::responses::{Assembler, SseEncoder, decode_request};
use qb_proto::{Block, Effort, ErrorClass, GatewayError, Role, StopReason, StreamEvent, Thinking};
use serde_json::{Value, json};

fn route_of(model: &str) -> Option<String> {
    (model == "gpt-chat").then(|| "chat".to_owned())
}

fn decode(body: &Value) -> Result<qb_openai::front::FrontRequest, GatewayError> {
    decode_request(
        body.to_string().as_bytes(),
        "turn-1",
        VENDOR,
        &route_of,
        1000,
    )
}

#[test]
fn sdk_request_flags_and_native_reasoning() {
    let req = decode_request(
        &fixture("responses_sdk_request.json"),
        "turn-1",
        VENDOR,
        &route_of,
        1000,
    )
    .expect("decodes");
    assert!(req.stream);
    assert_eq!(req.turn.effort, Some(Effort::High));
    assert_eq!(req.turn.max_tokens, 2048);
    assert_eq!(req.turn.session_key.as_deref(), Some("session-1"));
    let assistant = &req.turn.messages[1];
    assert_eq!(assistant.role, Role::Assistant);
    assert_eq!(
        assistant.content[0],
        Block::Thinking {
            vendor: VENDOR.into(),
            opaque: r#"{"type":"reasoning","summary":[{"type":"summary_text","text":"**Plan**"}],"encrypted_content":"ZW5jcnlwdGVkLXRlc3Q="}"#
                .into(),
        },
        "id and status are dropped, the rest kept"
    );
}

#[test]
fn string_input_and_defaults() {
    let req = decode(&json!({"model": "gpt-chat", "input": "Hi", "instructions": "Be brief."}))
        .expect("decodes");
    assert!(!req.stream);
    assert_eq!(req.turn.max_tokens, 1000);
    assert_eq!(req.turn.system.as_deref(), Some("Be brief."));
    assert_eq!(
        req.turn.messages[0].content,
        vec![Block::Text { text: "Hi".into() }]
    );
    let none = json!({"model": "gpt-chat", "input": [
        {"type": "reasoning", "id": "rs_1", "summary": []},
        {"role": "user", "content": "Hi"}
    ]});
    assert_eq!(
        decode(&none).expect("decodes").turn.messages.len(),
        1,
        "reasoning without encrypted content cannot be passed on and is dropped"
    );
}

#[test]
fn stateful_and_unsupported_requests_are_rejected_clearly() {
    let cases: Vec<(Value, &str)> = vec![
        (json!({"previous_response_id": "resp_1"}), "stateless"),
        (json!({"conversation": "conv_1"}), "stateless"),
        (json!({"background": true}), "`background`"),
        (
            json!({"text": {"format": {"type": "json_schema", "name": "x", "schema": {}}}}),
            "`text.format`",
        ),
        (json!({"tools": [{"type": "web_search"}]}), "`tools[0]`"),
        (json!({"model": "other"}), "model `other`"),
        (
            json!({"input": [{"type": "item_reference", "id": "msg_1"}]}),
            "item reference",
        ),
        (
            json!({"input": [{"type": "web_search_call", "id": "ws_1"}]}),
            "`web_search_call`",
        ),
        (
            json!({"input": [{"role": "user", "content": [{"type": "input_image", "file_id": "file-1"}]}]}),
            "stored files",
        ),
        (
            json!({"input": [{"role": "user", "content": [{"type": "input_file", "file_data": "AA=="}]}]}),
            "`input_file`",
        ),
        (
            json!({"input": [{"role": "user", "content": "a"}, {"type": "function_call_output", "call_id": "call_x", "output": "b"}]}),
            "call_x",
        ),
        (
            json!({"input": [{"type": "reasoning", "summary": [], "encrypted_content": "qb-thinking:{broken"}]}),
            "damaged",
        ),
        (
            json!({"reasoning": {"effort": "extreme"}}),
            "`reasoning.effort`",
        ),
        (json!({"input": 5}), "not a Responses request"),
    ];
    for (patch, want) in cases {
        let mut body = json!({"model": "gpt-chat", "input": "Hi"});
        for (k, v) in patch.as_object().expect("object") {
            body[k] = v.clone();
        }
        let e = decode(&body).expect_err(&body.to_string());
        assert_eq!(e.class, ErrorClass::BadRequest);
        let m = e.message.unwrap_or_default();
        assert!(m.contains(want), "{body}: {m}");
    }
}

fn encode(events: &[StreamEvent], policy: ForeignThinking) -> Vec<u8> {
    let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, VENDOR).foreign_thinking(policy);
    let mut out = Vec::new();
    for e in events {
        out.extend(enc.push(e));
    }
    out
}

#[test]
fn golden_stream() {
    let bytes = encode(&anthropic_events(), ForeignThinking::Keep);
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8"),
        String::from_utf8(fixture("client_responses_stream.sse")).expect("utf-8")
    );
    let (last, response) = check_responses(&bytes);
    assert_eq!(last, "response.completed");
    assert_eq!(response["status"], "completed");
    assert_eq!(response["id"], "resp_test1");
    let kinds: Vec<&str> = response["output"]
        .as_array()
        .expect("output")
        .iter()
        .map(|i| i["type"].as_str().expect("type"))
        .collect();
    assert_eq!(
        kinds,
        ["reasoning", "message", "function_call", "function_call"]
    );
    assert_eq!(
        response["usage"],
        json!({"input_tokens": 2125, "input_tokens_details": {"cached_tokens": 2000},
               "output_tokens": 90, "output_tokens_details": {"reasoning_tokens": 0},
               "total_tokens": 2215})
    );
}

#[test]
fn native_reasoning_streams_its_summary_and_encrypted_content() {
    let opaque = r#"{"type":"reasoning","summary":[{"type":"summary_text","text":"Plan A"},{"type":"summary_text","text":"Plan B"}],"encrypted_content":"ZW5j"}"#;
    let events = [
        StreamEvent::Thinking {
            thinking: Thinking {
                vendor: VENDOR.into(),
                opaque: opaque.into(),
            },
        },
        StreamEvent::Stop {
            reason: StopReason::End,
        },
    ];
    let bytes = encode(&events, ForeignThinking::Drop);
    let (_, response) = check_responses(&bytes);
    let item = &response["output"][0];
    assert_eq!(item["encrypted_content"], "ZW5j");
    assert_eq!(item["summary"][1]["text"], "Plan B");
    let deltas: Vec<String> = frames(&bytes)
        .into_iter()
        .filter(|(e, _)| e == "response.reasoning_summary_text.delta")
        .map(|(_, d)| {
            serde_json::from_str::<Value>(&d).expect("json")["delta"]
                .as_str()
                .expect("delta")
                .to_owned()
        })
        .collect();
    assert_eq!(deltas, ["Plan A", "Plan B"]);
}

#[test]
fn foreign_thinking_is_wrapped_or_dropped() {
    let keep = encode(&anthropic_events(), ForeignThinking::Keep);
    let (_, response) = check_responses(&keep);
    let wrapped = response["output"][0]["encrypted_content"]
        .as_str()
        .expect("wrapped");
    assert!(wrapped.starts_with("qb-thinking:"), "{wrapped}");

    let drop = encode(&anthropic_events(), ForeignThinking::Drop);
    let (_, response) = check_responses(&drop);
    assert_eq!(response["output"][0]["type"], "message");
    assert_eq!(response["output"].as_array().map(Vec::len), Some(3));
}

#[test]
fn length_and_refusal_stops_are_incomplete() {
    for (reason, want) in [
        (StopReason::MaxTokens, "max_output_tokens"),
        (StopReason::Refusal, "content_filter"),
    ] {
        let events = [
            StreamEvent::TextDelta { text: "abc".into() },
            StreamEvent::Stop { reason },
        ];
        let (last, response) = check_responses(&encode(&events, ForeignThinking::Keep));
        assert_eq!(last, "response.incomplete");
        assert_eq!(response["status"], "incomplete");
        assert_eq!(response["incomplete_details"]["reason"], want);
    }
}

#[test]
fn an_error_after_the_start_is_an_error_event_and_a_failed_response() {
    let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, VENDOR);
    let mut out = enc.push(&StreamEvent::TextDelta { text: "Hi".into() });
    assert!(enc.started());
    let e = GatewayError::new(ErrorClass::ContextTooLong, false, "too long");
    out.extend(enc.push(&StreamEvent::Error { error: e }));
    let (last, response) = check_responses(&out);
    assert_eq!(last, "response.failed");
    assert_eq!(
        response["error"],
        json!({"code": "context_length_exceeded", "message": "too long"})
    );
    let error = frames(&out)
        .into_iter()
        .find(|(e, _)| e == "error")
        .expect("an error event");
    let v: Value = serde_json::from_str(&error.1).expect("json");
    assert_eq!(v["code"], "context_length_exceeded");
    assert_eq!(v["message"], "too long");
    assert_eq!(
        enc.push(&StreamEvent::Stop {
            reason: StopReason::End
        }),
        Vec::<u8>::new(),
        "nothing after the end"
    );
}

#[test]
fn the_object_equals_the_streamed_final_response() {
    let events = anthropic_events();
    let (_, streamed) = check_responses(&encode(&events, ForeignThinking::Keep));
    let mut asm = Assembler::new("test1", "gpt-chat", NOW, VENDOR);
    for e in &events {
        asm.push(e);
    }
    let object = serde_json::to_value(asm.finish().expect("finished")).expect("json");
    assert_eq!(object, streamed);
    assert_eq!(object["object"], "response");
    assert_eq!(object["created_at"], NOW);
    assert_eq!(object["error"], Value::Null);
    assert_eq!(object["incomplete_details"], Value::Null);

    let mut failed = Assembler::new("t", "gpt-chat", NOW, OTHER);
    failed.push(&StreamEvent::Error {
        error: GatewayError::new(ErrorClass::Overloaded, true, "busy"),
    });
    assert_eq!(
        failed.finish().expect_err("error").class,
        ErrorClass::Overloaded
    );
}

#[test]
fn a_short_wait_in_the_stream_is_a_rate_limit() {
    for (resets_in, code) in [(20, "rate_limit_exceeded"), (3600, "insufficient_quota")] {
        let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, VENDOR);
        let mut out = enc.push(&StreamEvent::TextDelta { text: "Hi".into() });
        let mut e = GatewayError::new(ErrorClass::QuotaExhausted, true, "all logins wait");
        e.resets_at = Some(NOW + resets_in);
        out.extend(enc.push(&StreamEvent::Error { error: e }));
        let (_, response) = check_responses(&out);
        assert_eq!(response["error"]["code"], code, "{resets_in}");
    }
}

#[test]
fn a_tool_choice_the_turn_cannot_honour_is_refused() {
    let tools = json!([{"type": "function", "name": "f", "parameters": {}}]);
    let body = json!({"model": "gpt-chat", "input": "Hi", "tools": tools, "tool_choice": "auto"});
    assert!(decode(&body).is_ok());
    for choice in [
        json!("none"),
        json!("required"),
        json!({"type": "function", "name": "f"}),
    ] {
        let body =
            json!({"model": "gpt-chat", "input": "Hi", "tools": tools, "tool_choice": choice});
        let e = decode(&body).expect_err(&choice.to_string());
        assert!(
            e.message.unwrap_or_default().contains("`tool_choice`"),
            "{choice}"
        );
    }
}
