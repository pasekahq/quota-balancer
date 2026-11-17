//! Round trips through both directions: a canonical turn sent upstream as a Responses body and
//! read back by the Responses front, and canonical events written by the Responses front and read
//! back by the upstream reader.

mod common;

use common::{Rng, VENDOR, object, run};
use qb_openai::request::{AuthMode, Target, build};
use qb_openai::responses::{SseEncoder, decode_request};
use qb_proto::{
    Block, CacheMode, Effort, MediaType, Message, Role, StopReason, StreamEvent, Thinking, Tool,
    ToolCall, TurnRequest, Usage,
};
use serde_json::json;

fn turn(effort: Effort) -> TurnRequest {
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
                        opaque: r#"{"type":"reasoning","summary":[{"type":"summary_text","text":"s"}],"encrypted_content":"ZW5j"}"#.into(),
                    },
                    Block::Text { text: "Let me look.".into() },
                    Block::ToolUse {
                        id: "call_01".into(),
                        name: "read".into(),
                        input: object(json!({"path": "notes.txt", "n": [1, 2]})),
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
            input_schema: object(json!({"type": "object"})),
        }],
        max_tokens: 1024,
        effort: Some(effort),
        session_key: Some("conv-7".into()),
        cache: Some(CacheMode::Auto),
        request_id: "turn-1".into(),
    }
}

#[test]
fn canonical_turn_survives_upstream_body_and_front_decoding() {
    for effort in [Effort::Low, Effort::Medium, Effort::High, Effort::Max] {
        let req = turn(effort);
        let at = Target {
            vendor: VENDOR,
            model: "model-o",
            effort: None,
            auth: AuthMode::ApiKey,
            reasoning: true,
        };
        let bytes = serde_json::to_vec(&build(&req, &at).expect("builds")).expect("json");
        let route_of = |m: &str| (m == "model-o").then(|| "chat".to_owned());
        let back = decode_request(&bytes, "turn-1", VENDOR, &route_of, 1).expect("decodes");
        assert!(back.stream);
        assert_eq!(back.turn, req, "{effort:?}");
    }
}

fn random_events(rng: &mut Rng) -> (Vec<StreamEvent>, StopReason) {
    let mut out = Vec::new();
    let mut calls = 0;
    for i in 0..rng.below(12) {
        match rng.below(5) {
            0 | 1 => out.push(StreamEvent::TextDelta {
                text: format!("t{i}é "),
            }),
            2 => out.push(StreamEvent::Thinking {
                thinking: Thinking {
                    vendor: VENDOR.into(),
                    opaque: format!(
                        r#"{{"type":"reasoning","summary":[{{"type":"summary_text","text":"s{i}"}}],"encrypted_content":"e{i}"}}"#
                    ),
                },
            }),
            3 => {
                calls += 1;
                out.push(StreamEvent::ToolCall {
                    tool_call: ToolCall {
                        id: format!("call_{i}"),
                        name: "tool".into(),
                        input: object(json!({"i": i, "s": "x\ny"})),
                    },
                });
            }
            _ => out.push(StreamEvent::Usage {
                usage: Usage {
                    input: rng.next() % 1000,
                    output: rng.next() % 1000,
                    cache_read: rng.next() % 1000,
                    cache_write: 0,
                },
            }),
        }
    }
    let stop = match (calls > 0, rng.below(3)) {
        (_, 0) => StopReason::MaxTokens,
        (true, _) => StopReason::ToolUse,
        (false, 1) => StopReason::Refusal,
        (false, _) => StopReason::End,
    };
    (out, stop)
}

#[test]
fn front_stream_reads_back_through_the_upstream_reader() {
    let mut rng = Rng(0x5eed);
    for _ in 0..300 {
        let (events, stop) = random_events(&mut rng);
        let mut enc = SseEncoder::new("rt", "model-o", 1, VENDOR);
        let mut bytes = Vec::new();
        for e in &events {
            bytes.extend(enc.push(e));
        }
        bytes.extend(enc.push(&StreamEvent::Stop { reason: stop }));
        let read = run(&bytes);
        assert_eq!(read.end, Ok(stop));
        let content = |v: &[StreamEvent]| {
            v.iter()
                .filter(|e| !matches!(e, StreamEvent::Usage { .. }))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(content(&read.events), content(&events));
        let last_usage = events
            .iter()
            .rev()
            .find_map(|e| match e {
                StreamEvent::Usage { usage } => Some(*usage),
                _ => None,
            })
            .unwrap_or_default();
        assert_eq!(
            read.events.last(),
            Some(&StreamEvent::Usage { usage: last_usage })
        );
    }
}
