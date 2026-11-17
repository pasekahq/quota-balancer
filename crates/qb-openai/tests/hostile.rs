//! Hostile input: any chunking of a stream gives the same events, garbage in any parser gives an
//! error value and never a panic, and every bound holds.

mod common;

use common::{
    Answer, NOW, Rng, Run, VENDOR, accumulate_chat, check_responses, fixture, object, run,
    run_chat, run_chat_chunked, run_chunked,
};
use qb_openai::limits::{
    FailureKind, RateLimits, classify_chat_response, classify_response, rate_limits,
};
use qb_openai::stream::{MAX_BLOCK_BYTES, Reader};
use qb_openai::{chat, responses};
use qb_proto::{StopReason, StreamEvent, Thinking, ToolCall, Usage};
use serde_json::json;

type Runner = fn(&[u8], &[usize]) -> Run;

const STREAMS: &[(&str, Runner)] = &[
    ("upstream_text.sse", run_chunked),
    ("upstream_text_crlf.sse", run_chunked),
    ("upstream_tool_calls.sse", run_chunked),
    ("upstream_reasoning.sse", run_chunked),
    ("upstream_incomplete.sse", run_chunked),
    ("upstream_failed.sse", run_chunked),
    ("upstream_error_event.sse", run_chunked),
    ("upstream_cut.sse", run_chunked),
    ("client_responses_stream.sse", run_chunked),
    ("chat_upstream_openai.sse", run_chat_chunked),
    ("chat_upstream_openrouter.sse", run_chat_chunked),
    ("chat_upstream_error.sse", run_chat_chunked),
    ("chat_upstream_cut.sse", run_chat_chunked),
    ("client_chat_stream.sse", run_chat_chunked),
];

#[test]
fn every_chunking_gives_the_same_events() {
    let mut rng = Rng(0x00c0_ffee);
    for (name, runner) in STREAMS {
        let bytes = fixture(name);
        let whole = runner(&bytes, &[bytes.len().max(1)]);
        for split in 1..=3 {
            assert_eq!(runner(&bytes, &[split]), whole, "{name} by {split}");
        }
        for _ in 0..200 {
            let sizes: Vec<usize> = (0..8).map(|_| 1 + rng.below(64)).collect();
            assert_eq!(runner(&bytes, &sizes), whole, "{name} {sizes:?}");
        }
    }
}

fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    const INTERESTING: &[u8] = b"{}[]\":,\r\n \\\xff\x00:ade0";
    if input.is_empty() {
        input.push(b'{');
        return;
    }
    let at = rng.below(input.len());
    match rng.below(5) {
        0 => input[at] ^= 1 << rng.below(8),
        1 => input[at] = INTERESTING[rng.below(INTERESTING.len())],
        2 => input.insert(at, INTERESTING[rng.below(INTERESTING.len())]),
        3 => {
            input.remove(at);
        }
        _ => input.truncate(at),
    }
}

#[test]
fn mutated_streams_never_panic() {
    let mut rng = Rng(0xbad5_eed5);
    for (name, runner) in STREAMS {
        let original = fixture(name);
        for _ in 0..500 {
            let mut bytes = original.clone();
            for _ in 0..=rng.below(6) {
                mutate(&mut rng, &mut bytes);
            }
            let sizes = [1 + rng.below(40), 1 + rng.below(400)];
            let _ = runner(&bytes, &sizes);
        }
    }
}

fn route(model: &str) -> Option<String> {
    (!model.is_empty()).then(|| "chat".into())
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(42);
    for _ in 0..500 {
        let n = rng.below(512);
        let bytes: Vec<u8> = (0..n).map(|_| rng.next().to_le_bytes()[0]).collect();
        let _ = run(&bytes);
        let _ = run_chat(&bytes);
        let _ = chat::decode_request(&bytes, "m", &route, 16);
        let _ = responses::decode_request(&bytes, "m", VENDOR, &route, 16);
        let _ = classify_response(429, &[], &bytes, NOW);
        let _ = classify_chat_response(400, &[], &bytes, NOW);
    }
}

#[test]
fn an_oversized_event_fails() {
    let mut reader = Reader::new(VENDOR, RateLimits::default());
    let mut out = Vec::new();
    let line = vec![b'a'; 1 << 19];
    let failed = (0..4).any(|_| {
        reader
            .feed(b"data: ", &mut out)
            .and_then(|_| reader.feed(&line, &mut out))
            .is_err()
    });
    assert!(failed, "an unbounded event must fail");
}

fn event(v: &serde_json::Value) -> Vec<u8> {
    format!(
        "event: {}\ndata: {v}\n\n",
        v["type"].as_str().unwrap_or_default()
    )
    .into_bytes()
}

#[test]
fn unbounded_arguments_fail_as_malformed() {
    let mut bytes = event(&json!({"type": "response.created", "response": {}}));
    for i in 0..2 {
        bytes.extend(event(&json!({"type": "response.output_item.added", "output_index": i,
            "item": {"type": "function_call", "call_id": format!("c{i}"), "name": "f", "arguments": ""}})));
    }
    let piece = "x".repeat(200 << 10);
    for i in 0..4 {
        bytes.extend(event(
            &json!({"type": "response.function_call_arguments.delta",
            "output_index": i % 2, "delta": piece}),
        ));
    }
    let got = run(&bytes);
    let f = got.end.expect_err("bounded");
    assert_eq!(f.kind, FailureKind::Unavailable);
    assert!(f.message.contains("size bound"), "{}", f.message);
    assert!(4 * piece.len() > MAX_BLOCK_BYTES);
}

#[test]
fn too_many_open_items_fail_as_malformed() {
    let mut bytes = event(&json!({"type": "response.created", "response": {}}));
    for i in 0..100 {
        bytes.extend(event(
            &json!({"type": "response.output_item.added", "output_index": i,
            "item": {"type": "message", "role": "assistant", "content": []}}),
        ));
    }
    let f = run(&bytes).end.expect_err("bounded");
    assert!(f.message.contains("too many open items"), "{}", f.message);
}

#[test]
fn events_out_of_order_fail_as_malformed() {
    let created = event(&json!({"type": "response.created", "response": {}}));
    let delta =
        event(&json!({"type": "response.output_text.delta", "output_index": 0, "delta": "x"}));
    let completed =
        event(&json!({"type": "response.completed", "response": {"status": "completed"}}));
    for (name, bytes) in [
        ("delta before created", delta.clone()),
        (
            "delta outside an item",
            [created.clone(), delta.clone()].concat(),
        ),
        (
            "event after the end",
            [created.clone(), completed.clone(), completed.clone()].concat(),
        ),
        (
            "second created",
            [created.clone(), created.clone()].concat(),
        ),
    ] {
        let f = run(&bytes).end.expect_err(name);
        assert_eq!(f.kind, FailureKind::Unavailable, "{name}");
        assert!(
            f.message.starts_with("malformed vendor stream"),
            "{name}: {}",
            f.message
        );
    }
}

#[test]
fn mutated_requests_and_headers_never_panic() {
    let mut rng = Rng(7);
    for name in ["chat_sdk_request.json", "responses_sdk_request.json"] {
        let original = fixture(name);
        for _ in 0..2000 {
            let mut bytes = original.clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut rng, &mut bytes);
            }
            let _ = chat::decode_request(&bytes, "m", &route, 16);
            let _ = responses::decode_request(&bytes, "m", VENDOR, &route, 16);
        }
    }
    for name in [
        "answer_429_usage_limit.json",
        "answer_200_api_key.json",
        "answer_429_rate_limit.json",
    ] {
        let answer = Answer::load(name);
        for _ in 0..2000 {
            let mut headers = answer.headers.clone();
            for (_, v) in &mut headers {
                let mut b = v.clone().into_bytes();
                mutate(&mut rng, &mut b);
                *v = String::from_utf8_lossy(&b).into_owned();
            }
            let pairs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let limits = rate_limits(&pairs, NOW);
            assert!(
                limits
                    .windows
                    .iter()
                    .all(|w| (0.0..=1.0).contains(&w.utilization))
            );
            let mut body = answer.body.clone();
            mutate(&mut rng, &mut body);
            let _ = classify_response(answer.status, &pairs, &body, u64::MAX);
            let _ = classify_chat_response(answer.status, &pairs, &body, u64::MAX);
        }
    }
}

fn random_event(rng: &mut Rng, i: usize) -> StreamEvent {
    match rng.below(6) {
        0 | 1 => StreamEvent::TextDelta {
            text: ["", "a", "é\n\"", "</x>"][rng.below(4)].into(),
        },
        2 => StreamEvent::Thinking {
            thinking: Thinking {
                vendor: ["vendor-o", "vendor-a"][rng.below(2)].into(),
                opaque: [
                    "{}",
                    "not json",
                    r#"{"type":"reasoning","encrypted_content":"e"}"#,
                ][rng.below(3)]
                .into(),
            },
        },
        3 => StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: format!("call_{i}"),
                name: "f".into(),
                input: object(json!({"i": i})),
            },
        },
        _ => StreamEvent::Usage {
            usage: Usage {
                input: rng.next(),
                output: 1,
                cache_read: 2,
                cache_write: 3,
            },
        },
    }
}

#[test]
fn any_event_sequence_encodes_to_valid_streams() {
    let mut rng = Rng(99);
    for _ in 0..300 {
        let events: Vec<StreamEvent> = (0..rng.below(10))
            .map(|i| random_event(&mut rng, i))
            .collect();
        let reason = [
            StopReason::End,
            StopReason::ToolUse,
            StopReason::MaxTokens,
            StopReason::Refusal,
        ][rng.below(4)];
        let end = if rng.below(4) == 0 {
            StreamEvent::Error {
                error: qb_proto::GatewayError::new(qb_proto::ErrorClass::Unavailable, true, "cut"),
            }
        } else {
            StreamEvent::Stop { reason }
        };
        let mut r = responses::SseEncoder::new("h", "m", 1, VENDOR);
        let mut c = chat::SseEncoder::new("h", "m", 1, true);
        let (mut rb, mut cb) = (Vec::new(), Vec::new());
        for e in events.iter().chain([&end]) {
            rb.extend(r.push(e));
            cb.extend(c.push(e));
        }
        let _ = check_responses(&rb);
        if matches!(end, StreamEvent::Stop { .. }) {
            assert!(accumulate_chat(&cb).done);
        }
    }
}

#[test]
fn unbounded_chat_tool_calls_fail_as_malformed() {
    let piece = "x".repeat(200 << 10);
    let mut bytes = Vec::new();
    for i in 0..4 {
        let c = json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": i % 2,
            "id": format!("c{i}"), "function": {"name": "f", "arguments": piece}}]}}]});
        bytes.extend(format!("data: {c}\n\n").into_bytes());
    }
    let f = run_chat(&bytes).end.expect_err("bounded");
    assert_eq!(f.kind, FailureKind::Unavailable);
    assert!(f.message.contains("size bound"), "{}", f.message);

    let mut many = Vec::new();
    for i in 0..100 {
        let c = json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": i,
            "id": format!("c{i}"), "function": {"name": "f"}}]}}]});
        many.extend(format!("data: {c}\n\n").into_bytes());
    }
    let f = run_chat(&many).end.expect_err("bounded");
    assert!(f.message.contains("too many tool calls"), "{}", f.message);
}
