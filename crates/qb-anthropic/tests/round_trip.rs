//! Round trips through both directions: a canonical turn sent upstream and read back by the
//! front, and canonical events written by the front and read back by the upstream reader.

mod common;

use common::{Rng, VENDOR, run};
use qb_anthropic::front::{SseEncoder, decode_request};
use qb_anthropic::request::{AuthMode, Target, build};
use qb_proto::{
    Block, CacheMode, Effort, MediaType, Message, Object, Role, StopReason, StreamEvent, Thinking,
    Tool, ToolCall, TurnRequest, Usage,
};
use serde_json::json;

fn turn() -> TurnRequest {
    let mut input = Object::new();
    input.insert("path".into(), json!("notes.txt"));
    TurnRequest {
        route: "chat".into(),
        system: Some("Be brief.".into()),
        messages: vec![
            Message {
                role: Role::User,
                content: vec![
                    Block::Text { text: "Hi".into() },
                    Block::Image {
                        media_type: MediaType::Webp,
                        path: None,
                        base64: Some("UklGRg==".into()),
                    },
                ],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Thinking {
                        vendor: VENDOR.into(),
                        opaque: r#"{"type":"redacted_thinking","data":"ZGF0YQ=="}"#.into(),
                    },
                    Block::ToolUse {
                        id: "call_01".into(),
                        name: "read".into(),
                        input,
                    },
                ],
            },
            Message {
                role: Role::User,
                content: vec![Block::ToolResult {
                    id: "call_01".into(),
                    content: "text".into(),
                    is_error: None,
                }],
            },
        ],
        tools: vec![Tool {
            name: "read".into(),
            description: "Read a file.".into(),
            input_schema: Object::new(),
        }],
        max_tokens: 1024,
        effort: Some(Effort::Max),
        session_key: None,
        cache: Some(CacheMode::Auto),
        request_id: "turn-1".into(),
    }
}

#[test]
fn canonical_turn_survives_upstream_body_and_front_decoding() {
    let req = turn();
    let at = Target {
        vendor: VENDOR,
        model: "model-a",
        effort: None,
        auth: AuthMode::ApiKey,
        adaptive_thinking: true,
    };
    let body = build(&req, &at, &mut |_| None).expect("builds");
    let bytes = serde_json::to_vec(&body).expect("json");
    let route_of = |m: &str| (m == "model-a").then(|| "chat".to_owned());
    let back = decode_request(&bytes, "turn-1", VENDOR, &route_of).expect("decodes");
    assert!(back.stream);
    assert_eq!(back.turn, req);
}

fn random_events(rng: &mut Rng) -> Vec<StreamEvent> {
    let mut out = vec![StreamEvent::Usage {
        usage: Usage {
            input: 10,
            output: 1,
            cache_read: 0,
            cache_write: 0,
        },
    }];
    for i in 0..rng.below(12) {
        out.push(match rng.below(4) {
            0 | 1 => StreamEvent::TextDelta {
                text: ["a", "é\n", "{\"x\":1}", " ", "\r\ndata: x"][rng.below(5)].into(),
            },
            2 => StreamEvent::Thinking {
                thinking: Thinking {
                    vendor: [VENDOR, "vendor-b"][rng.below(2)].into(),
                    opaque: [
                        r#"{"type":"thinking","thinking":"t","signature":"s"}"#,
                        r#"{"type":"redacted_thinking","data":"d"}"#,
                        "not json",
                    ][rng.below(3)]
                    .into(),
                },
            },
            _ => {
                let mut input = Object::new();
                if rng.below(2) == 0 {
                    input.insert("k".into(), json!([i, "v", {"n": null}]));
                }
                StreamEvent::ToolCall {
                    tool_call: ToolCall {
                        id: format!("toolu_{i}"),
                        name: "tool".into(),
                        input,
                    },
                }
            }
        });
    }
    out.push(StreamEvent::Usage {
        usage: Usage {
            input: 10,
            output: 99,
            cache_read: 0,
            cache_write: 0,
        },
    });
    out
}

/// A foreign or unreadable thinking block reaches the reader as the front's redacted wrapper.
fn as_read_back(e: &StreamEvent) -> StreamEvent {
    match e {
        StreamEvent::Thinking { thinking } => {
            let block = qb_anthropic::front::thinking_block(thinking, VENDOR);
            StreamEvent::Thinking {
                thinking: Thinking {
                    vendor: VENDOR.into(),
                    opaque: qb_anthropic::request::thinking_to_opaque(&block),
                },
            }
        }
        other => other.clone(),
    }
}

#[test]
fn random_event_sequences_survive_the_front_stream() {
    let mut rng = Rng(0x5eed_0001);
    for case in 0..300 {
        let events = random_events(&mut rng);
        let reason = [
            StopReason::End,
            StopReason::ToolUse,
            StopReason::MaxTokens,
            StopReason::Refusal,
        ][rng.below(4)];
        let mut enc = SseEncoder::new("m", "model", VENDOR);
        let mut bytes = Vec::new();
        for e in &events {
            bytes.extend(enc.push(e));
        }
        bytes.extend(enc.push(&StreamEvent::Stop { reason }));
        let got = run(&bytes);
        assert_eq!(got.end, Ok(reason), "case {case}");
        let want: Vec<StreamEvent> = events.iter().map(as_read_back).collect();
        assert_eq!(got.events, want, "case {case}");
    }
}
