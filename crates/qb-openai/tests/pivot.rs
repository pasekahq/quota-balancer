//! The canonical turn as the pivot between formats: a Chat Completions request and a Responses
//! request decode to the same turn as the equivalent Anthropic-shaped one, and an
//! Anthropic-shaped answer (thinking with a signature, text, tool calls) streams as valid Chat
//! Completions and Responses and comes back intact in the client's next turn.

mod common;

use common::{
    NOW, OTHER, VENDOR, accumulate_chat, anthropic_events, check_responses, fixture, object,
};
use qb_openai::chat;
use qb_openai::request::{AuthMode, Target, build};
use qb_openai::responses;
use qb_proto::{
    Block, CacheMode, Effort, MediaType, Message, Role, StreamEvent, Tool, TurnRequest,
};
use serde_json::{Value, json};

fn route_of(model: &str) -> Option<String> {
    (model == "gpt-chat").then(|| "chat".to_owned())
}

fn tool(name: &str, description: &str, arg: &str) -> Tool {
    Tool {
        name: name.into(),
        description: description.into(),
        input_schema: object(json!({
            "type": "object",
            "properties": {arg: {"type": "string"}},
            "required": [arg],
            "additionalProperties": false
        })),
        native: None,
    }
}

/// The turn an Anthropic Messages client would send for the same conversation, written by hand.
fn anthropic_turn(thinking: Option<Block>) -> TurnRequest {
    let mut assistant: Vec<Block> = thinking.into_iter().collect();
    assistant.extend([
        Block::Text {
            text: "Reading both.".into(),
        },
        Block::ToolUse {
            id: "call_a1".into(),
            name: "read_file".into(),
            input: object(json!({"path": "notes.txt"})),
        },
        Block::ToolUse {
            id: "call_b2".into(),
            name: "list_dir".into(),
            input: object(json!({"dir": "src"})),
        },
    ]);
    TurnRequest {
        route: "chat".into(),
        system: Some("Be brief.".into()),
        messages: vec![
            Message {
                role: Role::User,
                content: vec![
                    Block::Text {
                        text: "What is in notes.txt?".into(),
                    },
                    Block::Image {
                        media_type: MediaType::Png,
                        path: None,
                        base64: Some("iVBORw0KGgo=".into()),
                    },
                ],
            },
            Message {
                role: Role::Assistant,
                content: assistant,
            },
            Message {
                role: Role::User,
                content: vec![
                    Block::ToolResult {
                        id: "call_a1".into(),
                        content: "hello".into(),
                        is_error: None,
                    },
                    Block::ToolResult {
                        id: "call_b2".into(),
                        content: "main.rs".into(),
                        is_error: None,
                    },
                    Block::Text {
                        text: "Thanks. Summarise.".into(),
                    },
                ],
            },
        ],
        tools: vec![
            tool("read_file", "Read a file.", "path"),
            tool("list_dir", "List a directory.", "dir"),
        ],
        max_tokens: 2048,
        effort: Some(Effort::High),
        session_key: Some("session-1".into()),
        cache: Some(CacheMode::Auto),
        request_id: "turn-1".into(),
    }
}

#[test]
fn chat_and_responses_requests_decode_to_the_anthropic_shaped_turn() {
    let chat = chat::decode_request(&fixture("chat_sdk_request.json"), "turn-1", &route_of, 1)
        .expect("chat decodes");
    assert_eq!(chat.turn, anthropic_turn(None));

    let resp = responses::decode_request(
        &fixture("responses_sdk_request.json"),
        "turn-1",
        VENDOR,
        &route_of,
        1,
    )
    .expect("responses decodes");
    let native = Block::Thinking {
        vendor: VENDOR.into(),
        opaque: r#"{"type":"reasoning","summary":[{"type":"summary_text","text":"**Plan**"}],"encrypted_content":"ZW5jcnlwdGVkLXRlc3Q="}"#
            .into(),
    };
    assert_eq!(resp.turn, anthropic_turn(Some(native)));
}

fn first_turn() -> Value {
    json!([{"role": "user", "content": "What is in notes.txt?"}])
}

#[test]
fn an_anthropic_answer_survives_the_next_responses_turn() {
    let events = anthropic_events();
    let mut enc = responses::SseEncoder::new("t1", "gpt-chat", NOW, VENDOR);
    let bytes: Vec<u8> = events.iter().flat_map(|e| enc.push(e)).collect();
    let (_, response) = check_responses(&bytes);

    // The client appends the output items and its tool outputs, as a stateless SDK user does.
    let mut input = first_turn().as_array().cloned().expect("array");
    input.extend(response["output"].as_array().cloned().expect("output"));
    input.push(json!({"type": "function_call_output", "call_id": "toolu_01", "output": "hello"}));
    input.push(json!({"type": "function_call_output", "call_id": "toolu_02", "output": "main.rs"}));
    let body = json!({"model": "gpt-chat", "input": input, "store": false});
    let next =
        responses::decode_request(body.to_string().as_bytes(), "turn-2", VENDOR, &route_of, 64)
            .expect("decodes");

    let StreamEvent::Thinking { thinking } = &events[2] else {
        panic!("the third event is thinking");
    };
    assert_eq!(
        next.turn.messages[1],
        Message {
            role: Role::Assistant,
            content: vec![
                Block::Thinking {
                    vendor: OTHER.into(),
                    opaque: thinking.opaque.clone(),
                },
                Block::Text {
                    text: "Reading both.".into()
                },
                Block::ToolUse {
                    id: "toolu_01".into(),
                    name: "read_file".into(),
                    input: object(json!({"path": "notes.txt"})),
                },
                Block::ToolUse {
                    id: "toolu_02".into(),
                    name: "list_dir".into(),
                    input: object(json!({"dir": "src"})),
                },
            ],
        },
        "the Anthropic thinking block comes back byte for byte"
    );
    assert_eq!(next.turn.messages.len(), 3);

    // Sent to an OpenAI-family vendor instead, the foreign thinking is left out and the calls
    // keep their ids.
    let at = Target {
        vendor: VENDOR,
        model: "model-o",
        effort: None,
        auth: AuthMode::ApiKey,
        reasoning: true,
    };
    let upstream = serde_json::to_value(build(&next.turn, &at).expect("builds")).expect("json");
    let kinds: Vec<&str> = upstream["input"]
        .as_array()
        .expect("input")
        .iter()
        .map(|i| i["type"].as_str().expect("type"))
        .collect();
    assert_eq!(
        kinds,
        [
            "message",
            "message",
            "function_call",
            "function_call",
            "function_call_output",
            "function_call_output"
        ]
    );
    assert_eq!(upstream["input"][2]["call_id"], "toolu_01");
}

#[test]
fn an_anthropic_answer_continues_over_chat_completions_without_its_thinking() {
    let mut enc = chat::SseEncoder::new("t1", "gpt-chat", NOW, true);
    let bytes: Vec<u8> = anthropic_events()
        .iter()
        .flat_map(|e| enc.push(e))
        .collect();
    let acc = accumulate_chat(&bytes);

    let mut messages = first_turn().as_array().cloned().expect("array");
    messages.push(json!({
        "role": acc.role,
        "content": acc.content,
        "tool_calls": acc.calls.iter().map(|(id, name, args)| json!({
            "id": id, "type": "function", "function": {"name": name, "arguments": args}
        })).collect::<Vec<_>>()
    }));
    for (id, _, _) in &acc.calls {
        messages.push(json!({"role": "tool", "tool_call_id": id, "content": "ok"}));
    }
    let body = json!({"model": "gpt-chat", "messages": messages});
    let next = chat::decode_request(body.to_string().as_bytes(), "turn-2", &route_of, 64)
        .expect("decodes");
    let assistant = &next.turn.messages[1];
    assert_eq!(assistant.role, Role::Assistant);
    assert_eq!(
        assistant.content[0],
        Block::Text {
            text: "Reading both.".into()
        }
    );
    assert!(
        matches!(&assistant.content[1], Block::ToolUse { id, .. } if id == "toolu_01"),
        "{assistant:?}"
    );
    assert_eq!(
        next.turn.messages[2].content.len(),
        2,
        "both tool results in one message"
    );
}
