//! The Chat Completions upstream direction: a canonical turn becomes a Chat Completions body and
//! headers; recorded-shape Chat Completions streams become canonical events; vendor answers
//! become failures.

mod common;

use common::{Answer, NOW, OTHER, VENDOR, drive, fixture, object, run_chat};
use qb_openai::chat_upstream::{InvalidHeader, Reader, build, headers, secret_header};
use qb_openai::limits::{FailureKind, classify_chat_response};
use qb_openai::request::BuildError;
use qb_openai::stream::Progress;
use qb_proto::{
    Block, Effort, Elsewhere, MediaType, Message, NativeApi, NativeTool, Role, StopReason,
    StreamEvent, Tool, ToolCall, TurnRequest, Usage,
};
use serde_json::{Value, json};

fn text(t: &str) -> StreamEvent {
    StreamEvent::TextDelta { text: t.into() }
}

fn call(id: &str, name: &str, input: Value) -> StreamEvent {
    StreamEvent::ToolCall {
        tool_call: ToolCall {
            id: id.into(),
            name: name.into(),
            input: object(input),
        },
    }
}

fn usage(input: u64, output: u64, cache_read: u64) -> StreamEvent {
    StreamEvent::Usage {
        usage: Usage {
            input,
            output,
            cache_read,
            cache_write: 0,
        },
    }
}

fn turn() -> TurnRequest {
    TurnRequest {
        route: "chat".into(),
        system: Some("Be brief.".into()),
        messages: vec![
            Message {
                role: Role::User,
                content: vec![
                    Block::Text {
                        text: "Look".into(),
                    },
                    Block::Image {
                        media_type: MediaType::Png,
                        path: None,
                        base64: Some("iVBORw0K".into()),
                    },
                ],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Thinking {
                        vendor: OTHER.into(),
                        opaque: r#"{"type":"thinking","thinking":"x","signature":"sig"}"#.into(),
                    },
                    Block::Thinking {
                        vendor: VENDOR.into(),
                        opaque: r#"{"type":"reasoning","summary":[],"encrypted_content":"ZW5j"}"#
                            .into(),
                    },
                    Block::Text {
                        text: "On it.".into(),
                    },
                    Block::Text {
                        text: String::new(),
                    },
                    Block::ToolUse {
                        id: "toolu_01".into(),
                        name: "read_file".into(),
                        input: object(json!({"path": "a"})),
                    },
                    Block::ToolUse {
                        id: "toolu_02".into(),
                        name: "list_dir".into(),
                        input: object(json!({})),
                    },
                ],
            },
            Message {
                role: Role::User,
                content: vec![
                    Block::ToolResult {
                        id: "toolu_01".into(),
                        content: "contents".into(),
                        is_error: Some(true),
                    },
                    Block::ToolResult {
                        id: "toolu_02".into(),
                        content: "a.txt".into(),
                        is_error: None,
                    },
                    Block::Text {
                        text: "Go on".into(),
                    },
                ],
            },
        ],
        tools: vec![Tool {
            name: "read_file".into(),
            description: "Read a file.".into(),
            input_schema: object(json!({"type": "object"})),
            native: None,
        }],
        max_tokens: 4096,
        effort: Some(Effort::Max),
        session_key: Some("conv-1".into()),
        cache: None,
        request_id: "turn-1".into(),
    }
}

#[test]
fn request_body() {
    let body = build(&turn(), "vendor-x/model-r").expect("builds");
    let got = serde_json::to_value(&body).expect("json");
    let want = json!({
        "model": "vendor-x/model-r",
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": [
                {"type": "text", "text": "Look"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0K"}}
            ]},
            {"role": "assistant", "content": "On it.", "tool_calls": [
                {"id": "toolu_01", "type": "function",
                 "function": {"name": "read_file", "arguments": "{\"path\":\"a\"}"}},
                {"id": "toolu_02", "type": "function",
                 "function": {"name": "list_dir", "arguments": "{}"}}
            ]},
            {"role": "tool", "content": "contents", "tool_call_id": "toolu_01"},
            {"role": "tool", "content": "a.txt", "tool_call_id": "toolu_02"},
            {"role": "user", "content": [{"type": "text", "text": "Go on"}]}
        ],
        "tools": [{"type": "function", "function": {"name": "read_file",
                   "description": "Read a file.", "parameters": {"type": "object"}}}],
        "tool_choice": "auto",
        "max_tokens": 4096,
        "stream": true,
        "stream_options": {"include_usage": true}
    });
    assert_eq!(got, want);
}

#[test]
fn an_assistant_turn_of_tool_calls_only_has_null_content_and_no_system_without_one() {
    let mut req = turn();
    req.system = None;
    req.tools.clear();
    req.messages[1]
        .content
        .retain(|b| matches!(b, Block::ToolUse { .. }));
    let got = serde_json::to_value(build(&req, "m").expect("builds")).expect("json");
    assert_eq!(got["messages"][0]["role"], json!("user"));
    assert_eq!(got["messages"][1]["role"], json!("assistant"));
    assert_eq!(got["messages"][1]["content"], Value::Null);
    assert!(got.get("tools").is_none() && got.get("tool_choice").is_none());
}

/// A history of two tool rounds with these ids, each call answered by its result.
fn rounds(ids: &[&str]) -> TurnRequest {
    let mut messages = vec![Message {
        role: Role::User,
        content: vec![Block::Text { text: "Go".into() }],
    }];
    for id in ids {
        messages.push(Message {
            role: Role::Assistant,
            content: vec![Block::ToolUse {
                id: (*id).into(),
                name: "read".into(),
                input: object(json!({"path": "a"})),
            }],
        });
        messages.push(Message {
            role: Role::User,
            content: vec![Block::ToolResult {
                id: (*id).into(),
                content: "ok".into(),
                is_error: None,
            }],
        });
    }
    TurnRequest { messages, ..turn() }
}

/// The ids of the body's assistant tool calls and of its tool messages, in order.
fn sent_ids(req: &TurnRequest) -> (Vec<String>, Vec<String>) {
    let got = serde_json::to_value(build(req, "m").expect("builds")).expect("json");
    let messages = got["messages"].as_array().expect("messages");
    let calls = messages
        .iter()
        .filter_map(|m| m["tool_calls"].as_array())
        .flatten()
        .map(|c| c["id"].as_str().expect("id").to_owned())
        .collect();
    let results = messages
        .iter()
        .filter(|m| m["role"] == "tool")
        .map(|m| m["tool_call_id"].as_str().expect("id").to_owned())
        .collect();
    (calls, results)
}

#[test]
fn tool_ids_over_40_bytes_go_out_shortened_and_still_paired() {
    let short = "call_abc.def:0";
    let at_limit = "x".repeat(40);
    let long_a = format!("{}a", "functions.read:".repeat(3));
    let long_b = format!("{}b", "functions.read:".repeat(3));
    let ids = [short, at_limit.as_str(), long_a.as_str(), long_b.as_str()];
    let (calls, results) = sent_ids(&rounds(&ids));
    assert_eq!(calls, results, "each tool message answers its call");
    assert_eq!(calls[0], short, "an id within the bound goes out unchanged");
    assert_eq!(calls[1], at_limit);
    for long in &calls[2..] {
        assert!(long.len() <= 40, "{long}");
        assert!(long.starts_with("qbh_"), "{long}");
        assert!(long.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }
    assert_ne!(calls[2], calls[3], "two long ids never merge");
    assert_eq!(
        calls[2], "qbh_3ec158b254665c91196a4a89031ce6d7",
        "the hash of a history in flight never changes"
    );
    let (again, _) = sent_ids(&rounds(&ids));
    assert_eq!(again, calls, "the map is deterministic across turns");
}

#[test]
fn an_image_path_is_refused() {
    let mut req = turn();
    req.messages[0].content[1] = Block::Image {
        media_type: MediaType::Png,
        path: Some("/srv/a.png".into()),
        base64: None,
    };
    assert_eq!(
        build(&req, "m"),
        Err(BuildError::ImagePath("/srv/a.png".into()))
    );
}

#[test]
fn header_set_secret_and_path() {
    let plain = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "text/event-stream".to_owned()),
        ("user-agent", "qb-gateway".to_owned()),
    ];
    assert_eq!(headers(None, None), Ok(plain.clone()));
    let mut attributed = plain;
    attributed.push(("http-referer", "https://example.com/app".to_owned()));
    attributed.push(("x-title", "Example App".to_owned()));
    assert_eq!(
        headers(Some("https://example.com/app"), Some("Example App")),
        Ok(attributed)
    );
    assert_eq!(
        headers(Some("https://example.com\r\nx-injected: 1"), None),
        Err(InvalidHeader("http-referer"))
    );
    assert_eq!(headers(None, Some("")), Err(InvalidHeader("x-title")));
    assert_eq!(secret_header(), ("authorization", "Bearer "));
}

#[test]
fn openai_stream_with_two_split_tool_calls() {
    let want = vec![
        text("Reading "),
        text("both."),
        call("call_a1", "read_file", json!({"path": "notes.txt"})),
        call("call_b2", "list_dir", json!({"dir": "src"})),
        usage(300, 40, 2000),
    ];
    let lf = fixture("chat_upstream_openai.sse");
    let crlf = String::from_utf8(lf.clone())
        .expect("utf-8")
        .replace('\n', "\r\n")
        .into_bytes();
    for bytes in [lf, crlf] {
        let got = run_chat(&bytes);
        assert_eq!(got.events, want);
        assert_eq!(got.end, Ok(StopReason::ToolUse));
    }
}

#[test]
fn openrouter_stream_with_comments_reasoning_and_cost() {
    let bytes = fixture("chat_upstream_openrouter.sse");
    let mut reader = Reader::new();
    let got = drive(&mut reader, &bytes, &[7, 1, 33]);
    assert_eq!(
        got.events,
        vec![
            text("Reading both."),
            call("call_or_1", "read_file", json!({"path": "notes.txt"})),
            call("call_or_2", "list_dir", json!({"dir": "src"})),
            usage(116, 60, 64),
        ]
    );
    assert_eq!(got.end, Ok(StopReason::ToolUse));
    assert_eq!(reader.cost(), Some(0.000_42));
}

fn chunk(delta: &Value, finish: Option<&str>) -> String {
    let c = json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]});
    format!("data: {c}\n\n")
}

fn stream(chunks: &[String], done: bool) -> Vec<u8> {
    let mut s = chunks.concat();
    if done {
        s.push_str("data: [DONE]\n\n");
    }
    s.into_bytes()
}

#[test]
fn finish_reasons_map_to_stop_reasons() {
    for (reason, want) in [
        ("stop", StopReason::End),
        ("tool_calls", StopReason::ToolUse),
        ("length", StopReason::MaxTokens),
        ("content_filter", StopReason::Refusal),
    ] {
        let bytes = stream(
            &[
                chunk(&json!({"content": "Hi"}), None),
                chunk(&json!({}), Some(reason)),
            ],
            true,
        );
        let got = run_chat(&bytes);
        assert_eq!(got.events, vec![text("Hi")], "{reason}");
        assert_eq!(got.end, Ok(want), "{reason}");
    }
    let mut reader = Reader::new();
    let bytes = stream(&[chunk(&json!({"content": "Hi"}), Some("stop"))], true);
    assert_eq!(
        reader.feed(&bytes, &mut Vec::new()),
        Ok(Progress::Finished(StopReason::End))
    );
    assert_eq!(reader.cost(), None);
}

#[test]
fn a_finish_reason_without_done_ends_the_stream_when_the_vendor_closes_it() {
    let bytes = stream(&[chunk(&json!({"content": "Hi"}), Some("stop"))], false);
    assert_eq!(run_chat(&bytes).end, Ok(StopReason::End));
}

#[test]
fn a_cut_stream_is_unavailable_and_keeps_what_was_delivered() {
    let got = run_chat(&fixture("chat_upstream_cut.sse"));
    assert_eq!(got.events, vec![text("Cut "), text("here")]);
    let f = got.end.expect_err("cut");
    assert_eq!(f.kind, FailureKind::Unavailable);
    assert!(
        f.message.contains("before a finish reason"),
        "{}",
        f.message
    );

    let early_done = stream(&[chunk(&json!({"content": "Hi"}), None)], true);
    let f = run_chat(&early_done)
        .end
        .expect_err("[DONE] without a reason");
    assert_eq!(f.kind, FailureKind::Unavailable);
}

#[test]
fn an_in_stream_error_after_content_is_classified() {
    let got = run_chat(&fixture("chat_upstream_error.sse"));
    assert_eq!(got.events, vec![text("Partial")]);
    let f = got.end.expect_err("error chunk");
    assert_eq!(f.kind, FailureKind::Unavailable);
    assert!(f.message.contains("Provider disconnected"), "{}", f.message);
    assert!(!f.message.chars().any(char::is_control), "{}", f.message);

    for (code, want) in [
        (json!(429), FailureKind::RateLimited { retry_after: None }),
        (json!(402), FailureKind::UsageLimit { resets_at: None }),
        (json!(503), FailureKind::Overloaded { retry_after: None }),
        (
            json!("rate_limit_exceeded"),
            FailureKind::RateLimited { retry_after: None },
        ),
    ] {
        let e = json!({"error": {"code": code, "message": "stopped"}});
        let bytes = format!("{}data: {e}\n\n", chunk(&json!({"content": "a"}), None));
        let f = run_chat(bytes.as_bytes()).end.expect_err("error chunk");
        assert_eq!(f.kind, want, "{code}");
    }

    let reason = stream(&[chunk(&json!({"content": "a"}), Some("error"))], true);
    let f = run_chat(&reason).end.expect_err("finish_reason error");
    assert_eq!(f.kind, FailureKind::Unavailable);
}

#[test]
fn malformed_tool_calls_and_order_fail_as_unavailable() {
    let piece = |index: u32, id: Option<&str>, name: Option<&str>, args: &str| {
        chunk(
            &json!({"tool_calls": [{"index": index, "id": id, "type": "function",
                "function": {"name": name, "arguments": args}}]}),
            None,
        )
    };
    let end = chunk(&json!({}), Some("tool_calls"));
    for (what, bytes) in [
        (
            "unparsable arguments",
            stream(
                &[piece(0, Some("c1"), Some("f"), "{\"a\": "), end.clone()],
                true,
            ),
        ),
        (
            "arguments not an object",
            stream(&[piece(0, Some("c1"), Some("f"), "[1]"), end.clone()], true),
        ),
        (
            "no id",
            stream(&[piece(0, None, Some("f"), "{}"), end.clone()], true),
        ),
        (
            "content after the finish reason",
            stream(
                &[end.clone(), chunk(&json!({"content": "late"}), None)],
                true,
            ),
        ),
        (
            "data after [DONE]",
            [
                stream(std::slice::from_ref(&end), true),
                stream(std::slice::from_ref(&end), false),
            ]
            .concat(),
        ),
        ("not JSON", b"data: {\"choices\": [\n\n".to_vec()),
        ("not a chunk", b"data: {\"choices\": \"none\"}\n\n".to_vec()),
    ] {
        let f = run_chat(&bytes).end.expect_err(what);
        assert_eq!(f.kind, FailureKind::Unavailable, "{what}");
        assert!(
            f.message.starts_with("malformed vendor stream"),
            "{what}: {}",
            f.message
        );
    }
}

#[test]
fn a_tool_call_cut_by_length_is_dropped_and_the_turn_stops_for_max_tokens() {
    let bytes = stream(
        &[
            chunk(
                &json!({"tool_calls": [{"index": 0, "id": "c1", "type": "function",
                    "function": {"name": "now", "arguments": "{}"}}]}),
                None,
            ),
            chunk(
                &json!({"tool_calls": [{"index": 1, "id": "c2", "type": "function",
                    "function": {"name": "write", "arguments": "{\"text\": \"abc"}}]}),
                None,
            ),
            chunk(&json!({}), Some("length")),
        ],
        true,
    );
    let got = run_chat(&bytes);
    assert_eq!(got.events, vec![call("c1", "now", json!({}))]);
    assert_eq!(got.end, Ok(StopReason::MaxTokens));
}

#[test]
fn empty_arguments_are_an_empty_object_and_calls_on_stop_are_tool_use() {
    let bytes = stream(
        &[
            chunk(
                &json!({"tool_calls": [{"index": 0, "id": "c1", "type": "function",
                    "function": {"name": "now", "arguments": ""}}]}),
                None,
            ),
            chunk(&json!({}), Some("stop")),
        ],
        true,
    );
    let got = run_chat(&bytes);
    assert_eq!(got.events, vec![call("c1", "now", json!({}))]);
    assert_eq!(got.end, Ok(StopReason::ToolUse));
}

fn usage_chunk(prompt: u64, completion: u64) -> String {
    let c = json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": "m",
        "choices": [], "usage": {"prompt_tokens": prompt, "completion_tokens": completion}});
    format!("data: {c}\n\n")
}

#[test]
fn refusal_text_is_text_and_stops_the_turn_with_refusal() {
    let bytes = stream(
        &[
            chunk(&json!({"refusal": "I can't "}), None),
            chunk(&json!({"refusal": "help with that."}), None),
            chunk(&json!({}), Some("stop")),
        ],
        true,
    );
    let got = run_chat(&bytes);
    assert_eq!(got.events, vec![text("I can't "), text("help with that.")]);
    assert_eq!(got.end, Ok(StopReason::Refusal));

    let got = run_chat(&fixture("chat_upstream_refusal.sse"));
    assert_eq!(
        got.events,
        vec![text("I can't help "), text("with that."), usage(12, 6, 0)]
    );
    assert_eq!(got.end, Ok(StopReason::Refusal));
}

#[test]
fn tool_call_pieces_without_index_continue_the_last_call_or_start_one_by_id() {
    let piece = |id: Option<&str>, name: Option<&str>, args: &str| {
        chunk(
            &json!({"tool_calls": [{"id": id, "type": "function",
                "function": {"name": name, "arguments": args}}]}),
            None,
        )
    };
    let bytes = stream(
        &[
            piece(Some("c1"), Some("read_file"), "{\"path\""),
            piece(None, None, ": \"notes.txt\"}"),
            piece(Some("c2"), Some("list_dir"), "{\"dir\": "),
            piece(Some("c2"), None, "\"src\"}"),
            piece(Some("c3"), Some("now"), ""),
            chunk(&json!({}), Some("tool_calls")),
        ],
        true,
    );
    let got = run_chat(&bytes);
    assert_eq!(
        got.events,
        vec![
            call("c1", "read_file", json!({"path": "notes.txt"})),
            call("c2", "list_dir", json!({"dir": "src"})),
            call("c3", "now", json!({})),
        ]
    );
    assert_eq!(got.end, Ok(StopReason::ToolUse));

    let got = run_chat(&fixture("chat_upstream_no_index.sse"));
    assert_eq!(
        got.events,
        vec![
            text("Both."),
            call("call_n1", "read_file", json!({"path": "notes.txt"})),
            call("call_n2", "list_dir", json!({"dir": "src"})),
            usage(90, 31, 0),
        ]
    );
    assert_eq!(got.end, Ok(StopReason::ToolUse));
}

#[test]
fn only_the_last_usage_is_emitted_once_at_the_end_of_the_stream() {
    let chunks = [
        usage_chunk(10, 0),
        chunk(&json!({"content": "Hi"}), None),
        usage_chunk(20, 3),
        chunk(&json!({}), Some("stop")),
        usage_chunk(30, 7),
    ];
    for done in [true, false] {
        let got = run_chat(&stream(&chunks, done));
        assert_eq!(
            got.events,
            vec![text("Hi"), usage(30, 7, 0)],
            "[DONE] {done}"
        );
        assert_eq!(got.end, Ok(StopReason::End), "[DONE] {done}");
    }

    let mut reader = Reader::new();
    let mut events = Vec::new();
    let progress = reader.feed(&stream(&chunks[..4], false), &mut events);
    assert_eq!(progress, Ok(Progress::Continue));
    assert_eq!(events, vec![text("Hi")], "usage waits for the end");

    let cut = stream(&chunks[..3], false);
    let got = run_chat(&cut);
    assert_eq!(got.events, vec![text("Hi")], "a failed stream has no usage");
    assert!(got.end.is_err());
}

#[test]
fn error_answers_classify_by_status() {
    let cases = [
        ("answer_401.json", FailureKind::Auth),
        ("answer_403.json", FailureKind::Auth),
        ("answer_403_html.json", FailureKind::Auth),
        (
            "chat_answer_402_credits.json",
            FailureKind::UsageLimit { resets_at: None },
        ),
        (
            "chat_answer_429_retry.json",
            FailureKind::RateLimited {
                retry_after: Some(12),
            },
        ),
        (
            "answer_429_insufficient_quota.json",
            FailureKind::UsageLimit { resets_at: None },
        ),
        ("answer_404_model.json", FailureKind::ModelUnavailable),
        ("chat_answer_400_model.json", FailureKind::ModelUnavailable),
        ("chat_answer_400_context.json", FailureKind::ContextTooLong),
        ("answer_400_context.json", FailureKind::ContextTooLong),
        ("answer_400_invalid.json", FailureKind::BadRequest),
        ("chat_answer_422_invalid.json", FailureKind::BadRequest),
        (
            "answer_503_overloaded.json",
            FailureKind::Overloaded {
                retry_after: Some(7),
            },
        ),
        ("answer_500_html.json", FailureKind::Unavailable),
        ("chat_answer_502_empty.json", FailureKind::Unavailable),
    ];
    for (name, want) in cases {
        let a = Answer::load(name);
        let f = classify_chat_response(a.status, &a.pairs(), &a.body, NOW);
        assert_eq!(f.kind, want, "{name}");
        assert!(f.windows.is_empty(), "{name}");
        assert!(
            f.message
                .starts_with(&format!("vendor answered HTTP {}", a.status)),
            "{name}: {}",
            f.message
        );
        assert!(!f.message.chars().any(char::is_control), "{name}");
    }
    assert_eq!(
        classify_chat_response(429, &[], b"", NOW).kind,
        FailureKind::RateLimited { retry_after: None }
    );
    for error in [
        json!({"code": "insufficient_quota", "message": "credit spent"}),
        json!({"type": "insufficient_quota", "message": "credit spent"}),
    ] {
        let body = json!({ "error": error }).to_string();
        let retry = [("retry-after", "30")];
        assert_eq!(
            classify_chat_response(429, &retry, body.as_bytes(), NOW).kind,
            FailureKind::UsageLimit { resets_at: None },
            "{error}"
        );
    }
    assert_eq!(
        classify_chat_response(413, &[], b"<html>context length</html>", NOW).kind,
        FailureKind::BadRequest,
        "an HTML body classifies by status alone"
    );
}

#[test]
fn a_failure_message_is_shortened_and_never_quotes_a_header_value() {
    let a = Answer::load("answer_401.json");
    let mut pairs = a.pairs();
    pairs.push(("authorization", "Bearer test-token-1"));
    let f = classify_chat_response(a.status, &pairs, &a.body, NOW);
    assert!(!f.message.contains("test-token-1"), "{}", f.message);

    let long = json!({"error": {"code": 400, "message": "é\n".repeat(400)}}).to_string();
    let f = classify_chat_response(400, &[], long.as_bytes(), NOW);
    assert!(f.message.chars().count() < 340, "{}", f.message);
    assert!(!f.message.chars().any(char::is_control));
}

fn native(name: &str, kind: &str, elsewhere: Elsewhere) -> Tool {
    Tool {
        name: name.into(),
        description: format!("{name} tool"),
        input_schema: object(json!({"type": "object"})),
        native: Some(NativeTool {
            api: NativeApi::OpenaiResponses,
            spec: object(json!({"type": kind})),
            elsewhere,
        }),
    }
}

#[test]
fn system_messages_join_the_system_prompt_and_native_tools_follow_their_rule() {
    let mut req = turn();
    req.messages.insert(
        1,
        Message {
            role: Role::System,
            content: vec![Block::Text {
                text: "Mid-conversation.".into(),
            }],
        },
    );
    req.tools
        .push(native("apply_patch", "custom", Elsewhere::Function));
    req.tools
        .push(native("web_search", "web_search", Elsewhere::Omit));
    let got = serde_json::to_value(build(&req, "model-c").expect("builds")).expect("json");
    let messages = got["messages"].as_array().expect("messages");
    assert_eq!(messages[0]["role"], "system");
    assert!(
        messages[0]["content"]
            .as_str()
            .is_some_and(|s| s.ends_with("\n\nMid-conversation."))
    );
    assert_eq!(messages.iter().filter(|m| m["role"] == "system").count(), 1);
    let names: Vec<&str> = got["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["function"]["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names.last(), Some(&"apply_patch"));
    assert!(!names.contains(&"web_search"));

    req.tools
        .push(native("local_shell", "local_shell", Elsewhere::Refuse));
    assert_eq!(
        build(&req, "model-c").expect_err("refused"),
        BuildError::Tool("local_shell".into())
    );
}
