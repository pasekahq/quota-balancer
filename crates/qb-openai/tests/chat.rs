//! The `/v1/chat/completions` front: request decoding, the SSE stream, the response body and
//! error answers.

mod common;

use common::{NOW, accumulate_chat as accumulate, anthropic_events, fixture, frames};
use qb_openai::chat::{Assembler, SseEncoder, decode_request};
use qb_openai::front::error_response;
use qb_proto::{Effort, ErrorClass, GatewayError, StopReason, StreamEvent};
use serde_json::{Value, json};

fn route_of(model: &str) -> Option<String> {
    (model == "gpt-chat").then(|| "chat".to_owned())
}

fn decode(body: &Value) -> Result<qb_openai::front::FrontRequest, GatewayError> {
    decode_request(body.to_string().as_bytes(), "turn-1", &route_of, 1000)
}

fn minimal() -> Value {
    json!({"model": "gpt-chat", "messages": [{"role": "user", "content": "Hi"}]})
}

#[test]
fn sdk_request_flags() {
    let req = decode_request(&fixture("chat_sdk_request.json"), "turn-1", &route_of, 1000)
        .expect("decodes");
    assert!(req.stream);
    assert!(req.include_usage);
    assert_eq!(req.model, "gpt-chat");
    assert_eq!(req.turn.effort, Some(Effort::High));
    assert_eq!(req.turn.max_tokens, 2048);
    assert_eq!(req.turn.session_key.as_deref(), Some("session-1"));
}

#[test]
fn defaults_and_mappings() {
    let req = decode(&minimal()).expect("decodes");
    assert!(!req.stream && !req.include_usage);
    assert_eq!(req.turn.max_tokens, 1000, "the caller's default");
    assert_eq!(req.turn.system, None);

    let mut body = minimal();
    body["max_tokens"] = json!(77);
    body["reasoning_effort"] = json!("minimal");
    body["prompt_cache_key"] = json!("k".repeat(300));
    body["user"] = json!("ignored-when-a-cache-key-is-set");
    let req = decode(&body).expect("decodes");
    assert_eq!(req.turn.max_tokens, 77);
    assert_eq!(req.turn.effort, Some(Effort::Low));
    let key = req.turn.session_key.expect("key");
    assert!(key.starts_with("qb-sk:") && key.len() <= 128, "{key}");

    body["reasoning_effort"] = json!("xhigh");
    assert_eq!(
        decode(&body).expect("decodes").turn.effort,
        Some(Effort::Max)
    );
}

#[test]
fn system_messages_anywhere_join_the_system_prompt() {
    let body = json!({"model": "gpt-chat", "messages": [
        {"role": "system", "content": "A"},
        {"role": "user", "content": "Hi"},
        {"role": "developer", "content": [{"type": "text", "text": "B"}]}
    ]});
    let req = decode(&body).expect("decodes");
    assert_eq!(req.turn.system.as_deref(), Some("A\n\nB"));
    assert_eq!(req.turn.messages.len(), 1);
}

#[test]
fn unsupported_requests_are_rejected_clearly() {
    let cases: Vec<(Value, &str)> = vec![
        (json!({"n": 2}), "`n`"),
        (json!({"logprobs": true}), "`logprobs`"),
        (json!({"audio": {"voice": "x", "format": "wav"}}), "`audio`"),
        (json!({"modalities": ["text", "audio"]}), "modality"),
        (
            json!({"response_format": {"type": "json_object"}}),
            "`response_format`",
        ),
        (json!({"model": "other"}), "model `other`"),
        (
            json!({"tools": [{"type": "custom", "custom": {"name": "x"}}]}),
            "`tools[0]`",
        ),
        (json!({"max_completion_tokens": 0}), "`max_tokens`"),
        (
            json!({"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://example.invalid/a.png"}}]}]}),
            "data: URL",
        ),
        (
            json!({"messages": [{"role": "user", "content": [{"type": "input_audio", "input_audio": {"data": "AA==", "format": "wav"}}]}]}),
            "`input_audio`",
        ),
        (
            json!({"messages": [{"role": "user", "content": "a"}, {"role": "tool", "tool_call_id": "call_x", "content": "b"}]}),
            "call_x",
        ),
        (
            json!({"messages": [{"role": "function", "name": "f", "content": "x"}]}),
            "`function`",
        ),
        (
            json!({"messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "[1]"}}]}]}),
            "not a JSON object",
        ),
        (json!({"messages": "hi"}), "not a Chat Completions request"),
    ];
    for (patch, want) in cases {
        let mut body = minimal();
        for (k, v) in patch.as_object().expect("object") {
            body[k] = v.clone();
        }
        let e = decode(&body).expect_err(&body.to_string());
        assert_eq!(e.class, ErrorClass::BadRequest);
        let m = e.message.unwrap_or_default();
        assert!(m.contains(want), "{body}: {m}");
    }
}

fn encode(events: &[StreamEvent], include_usage: bool) -> Vec<u8> {
    let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, include_usage);
    let mut out = Vec::new();
    for e in events {
        out.extend(enc.push(e));
    }
    out
}

#[test]
fn golden_stream() {
    let bytes = encode(&anthropic_events(), true);
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8"),
        String::from_utf8(fixture("client_chat_stream.sse")).expect("utf-8")
    );
    let acc = accumulate(&bytes);
    assert_eq!(acc.role, "assistant");
    assert_eq!(acc.content, "Reading both.");
    assert_eq!(
        acc.calls,
        vec![
            (
                "toolu_01".into(),
                "read_file".into(),
                r#"{"path":"notes.txt"}"#.into()
            ),
            (
                "toolu_02".into(),
                "list_dir".into(),
                r#"{"dir":"src"}"#.into()
            ),
        ]
    );
    assert_eq!(acc.finish.as_deref(), Some("tool_calls"));
    assert_eq!(
        acc.usage,
        Some(
            json!({"prompt_tokens": 2125, "completion_tokens": 90, "total_tokens": 2215,
                    "prompt_tokens_details": {"cached_tokens": 2000},
                    "completion_tokens_details": {"reasoning_tokens": 0}})
        )
    );
    assert!(acc.done);
}

#[test]
fn finish_reasons_and_no_usage_chunk_unless_asked() {
    for (reason, want) in [
        (StopReason::End, "stop"),
        (StopReason::ToolUse, "tool_calls"),
        (StopReason::MaxTokens, "length"),
        (StopReason::Refusal, "content_filter"),
    ] {
        let bytes = encode(&[StreamEvent::Stop { reason }], false);
        let acc = accumulate(&bytes);
        assert_eq!(acc.finish.as_deref(), Some(want));
        assert_eq!(acc.usage, None);
        assert!(acc.done);
    }
}

#[test]
fn an_error_after_the_start_is_an_error_chunk_without_done() {
    let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, true);
    assert!(
        enc.push(&anthropic_events()[0]).is_empty(),
        "route writes nothing"
    );
    assert!(!enc.started());
    let first = enc.push(&StreamEvent::TextDelta { text: "Hi".into() });
    assert!(enc.started() && !first.is_empty());
    let mut e = GatewayError::new(ErrorClass::Unavailable, true, "vendor stream cut");
    e.retry_after = Some(3);
    let bytes = enc.push(&StreamEvent::Error { error: e });
    let f = frames(&bytes);
    assert_eq!(f.len(), 1);
    let v: Value = serde_json::from_str(&f[0].1).expect("JSON");
    assert_eq!(
        v,
        json!({"error": {"message": "vendor stream cut", "type": "server_error", "param": null,
                         "code": "upstream_unavailable"}})
    );
    assert_eq!(
        enc.push(&StreamEvent::Stop {
            reason: StopReason::End
        }),
        Vec::<u8>::new(),
        "nothing after the end"
    );
}

#[test]
fn non_streaming_body() {
    let mut asm = Assembler::new("test1", "gpt-chat", NOW);
    for e in anthropic_events() {
        asm.push(&e);
    }
    let body = serde_json::to_value(asm.finish().expect("finished")).expect("json");
    assert_eq!(
        body,
        json!({
            "id": "chatcmpl-test1",
            "object": "chat.completion",
            "created": NOW,
            "model": "gpt-chat",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Reading both.",
                    "tool_calls": [
                        {"id": "toolu_01", "type": "function",
                         "function": {"name": "read_file", "arguments": "{\"path\":\"notes.txt\"}"}},
                        {"id": "toolu_02", "type": "function",
                         "function": {"name": "list_dir", "arguments": "{\"dir\":\"src\"}"}}
                    ]
                },
                "finish_reason": "tool_calls",
                "logprobs": null
            }],
            "usage": {"prompt_tokens": 2125, "completion_tokens": 90, "total_tokens": 2215,
                      "prompt_tokens_details": {"cached_tokens": 2000},
                    "completion_tokens_details": {"reasoning_tokens": 0}}
        })
    );

    let mut calls_only = Assembler::new("t", "gpt-chat", NOW);
    calls_only.push(&anthropic_events()[5]);
    calls_only.push(&StreamEvent::Stop {
        reason: StopReason::ToolUse,
    });
    let body = serde_json::to_value(calls_only.finish().expect("finished")).expect("json");
    assert_eq!(body["choices"][0]["message"]["content"], Value::Null);

    let mut cut = Assembler::new("t", "gpt-chat", NOW);
    cut.push(&StreamEvent::TextDelta { text: "x".into() });
    assert_eq!(
        cut.finish().expect_err("no stop").class,
        ErrorClass::Unavailable
    );
}

#[test]
fn error_answers() {
    let mut quota = GatewayError::new(ErrorClass::QuotaExhausted, true, "all logins wait");
    quota.resets_at = Some(NOW + 3600);
    let r = error_response(&quota, NOW);
    assert_eq!(r.status, 429);
    assert_eq!(
        r.headers(),
        vec![
            ("retry-after", "3600".to_owned()),
            ("x-should-retry", "false".to_owned())
        ]
    );
    assert_eq!(
        serde_json::to_value(&r.body).expect("json"),
        json!({"error": {"message": "all logins wait", "type": "insufficient_quota",
                         "param": null, "code": "insufficient_quota"}})
    );

    quota.resets_at = Some(NOW + 30);
    let r = error_response(&quota, NOW);
    assert_eq!(r.retry_after, Some(30));
    assert_eq!(r.should_retry, None, "a near reset lets the SDK retry");

    let cases = [
        (
            ErrorClass::ContextTooLong,
            400,
            Some("context_length_exceeded"),
        ),
        (ErrorClass::BadRequest, 400, None),
        (ErrorClass::Auth, 502, Some("upstream_auth_failed")),
        (ErrorClass::Overloaded, 429, Some("rate_limit_exceeded")),
        (ErrorClass::Unavailable, 503, Some("upstream_unavailable")),
        (ErrorClass::NoRoute, 503, Some("no_route")),
        (ErrorClass::Cancelled, 409, Some("cancelled")),
    ];
    for (class, status, code) in cases {
        let mut e = GatewayError::new(class, false, "");
        e.retry_after = Some(5);
        let r = error_response(&e, NOW);
        assert_eq!(r.status, status, "{class:?}");
        assert_eq!(r.body.error.code.as_deref(), code, "{class:?}");
        assert!(
            !r.body.error.message.is_empty(),
            "{class:?} has a default message"
        );
        assert_eq!(r.retry_after, Some(5));
    }
}

#[test]
fn an_assistant_refusal_stays_in_the_history() {
    let body = json!({"model": "gpt-chat", "messages": [
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": null, "refusal": "I can't"},
        {"role": "user", "content": "b"}
    ]});
    let req = decode(&body).expect("decodes");
    assert_eq!(req.turn.messages.len(), 3);
    assert_eq!(
        req.turn.messages[1].content,
        vec![qb_proto::Block::Text {
            text: "I can't".into()
        }]
    );
}

#[test]
fn errors_that_a_retry_cannot_fix_stop_sdk_retries() {
    for class in [ErrorClass::Auth, ErrorClass::Cancelled, ErrorClass::NoRoute] {
        let r = error_response(&GatewayError::new(class, false, "x"), NOW);
        assert_eq!(r.should_retry, Some(false), "{class:?}");
        assert!(
            r.headers()
                .contains(&("x-should-retry", "false".to_owned())),
            "{class:?}"
        );
    }
}

#[test]
fn a_quota_error_without_a_known_reset_still_says_when_to_retry() {
    let e = GatewayError::new(ErrorClass::QuotaExhausted, true, "all logins wait");
    let r = error_response(&e, NOW);
    assert_eq!(r.status, 429);
    assert_eq!(r.retry_after, Some(qb_openai::front::QUOTA_RETRY_AFTER_S));
    assert_eq!(r.should_retry, None, "a short default lets the SDK retry");
}

#[test]
fn a_vendor_back_off_is_a_rate_limit_as_on_the_c4_front() {
    let mut e = GatewayError::new(ErrorClass::Overloaded, true, "");
    e.retry_after = Some(20);
    let r = error_response(&e, NOW);
    assert_eq!(r.status, ErrorClass::Overloaded.http_status());
    assert_eq!(r.body.error.kind, "requests");
    assert_eq!(r.body.error.code.as_deref(), Some("rate_limit_exceeded"));
    assert_eq!(r.headers(), vec![("retry-after", "20".to_owned())]);
}

#[test]
fn a_short_wait_is_a_rate_limit_and_a_far_reset_is_out_of_quota() {
    let quota = |resets_at: Option<u64>, retry_after: Option<u64>| {
        let mut e = GatewayError::new(ErrorClass::QuotaExhausted, true, "all logins wait");
        e.resets_at = resets_at;
        e.retry_after = retry_after;
        e
    };
    let kind = |e: &GatewayError| {
        let r = error_response(e, NOW);
        assert_eq!(r.status, 429);
        (r.body.error.kind.clone(), r.body.error.code.clone())
    };
    let rate = (
        "requests".to_owned(),
        Some("rate_limit_exceeded".to_owned()),
    );
    let spent = (
        "insufficient_quota".to_owned(),
        Some("insufficient_quota".to_owned()),
    );
    // A full lease table or a short back-off in qbd.
    assert_eq!(kind(&quota(Some(NOW + 20), None)), rate);
    assert_eq!(kind(&quota(None, Some(300))), rate);
    assert_eq!(kind(&quota(None, None)), rate);
    // A window that resets in hours.
    assert_eq!(kind(&quota(Some(NOW + 301), None)), spent);
    assert_eq!(kind(&quota(None, Some(7200))), spent);

    // The stream labels it the same way at its own time.
    for (e, code) in [
        (quota(Some(NOW + 20), None), "rate_limit_exceeded"),
        (quota(Some(NOW + 3600), None), "insufficient_quota"),
    ] {
        let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, false);
        enc.push(&StreamEvent::TextDelta { text: "Hi".into() });
        let f = frames(&enc.push(&StreamEvent::Error { error: e }));
        let v: Value = serde_json::from_str(&f[0].1).expect("JSON");
        assert_eq!(v["error"]["code"], code);
    }
}
