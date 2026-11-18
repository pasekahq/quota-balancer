//! The `/v1/responses` front: request decoding, the SSE stream with its item lifecycle, the
//! response object and in-stream errors.

mod common;

use common::{NOW, OTHER, VENDOR, anthropic_events, check_responses, fixture, frames};
use qb_openai::front::ForeignThinking;
use qb_openai::responses::{Assembler, SseEncoder, decode_request};
use qb_proto::{
    Block, Effort, Elsewhere, ErrorClass, GatewayError, NativeApi, Role, StopReason, StreamEvent,
    Thinking, ToolCall,
};
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
        (json!({"tools": [{"type": "function"}]}), "`tools[0]`"),
        (json!({"tools": [{"name": "x"}]}), "`tools[0]`"),
        (json!({"model": "other"}), "model `other`"),
        (
            json!({"input": [{"type": "item_reference", "id": "msg_1"}]}),
            "item reference",
        ),
        (
            json!({"input": [{"type": "local_shell_call", "id": "lsh_1"}]}),
            "`local_shell_call`",
        ),
        (
            json!({"input": [{"role": "user", "content": "a"}, {"type": "tool_search_output", "execution": "client", "call_id": "call_t", "tools": []}]}),
            "call_t",
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

fn codex_route_of(model: &str) -> Option<String> {
    (model == "gpt-5.5").then(|| "codex".to_owned())
}

fn decode_codex(body: &[u8]) -> Result<qb_openai::front::FrontRequest, GatewayError> {
    decode_request(body, "turn-1", VENDOR, &codex_route_of, 1000)
}

/// A request as Codex CLI 0.159.2 sends it (recorded, texts and ids replaced): a function tool,
/// the freeform `apply_patch` custom tool, a client `tool_search` and `web_search`.
#[test]
fn codex_request_keeps_its_native_tools() {
    let req = decode_codex(&fixture("codex_cli_request.json")).expect("a Codex request decodes");
    let t = &req.turn;
    assert_eq!(t.route, "codex");
    assert_eq!(t.effort, Some(Effort::Medium));
    let tools: Vec<(&str, Option<Elsewhere>)> = t
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t.native.as_ref().map(|n| n.elsewhere)))
        .collect();
    assert_eq!(
        tools,
        [
            ("exec_command", None),
            ("apply_patch", Some(Elsewhere::Function)),
            ("tool_search", Some(Elsewhere::Omit)),
            ("web_search", Some(Elsewhere::Omit)),
        ]
    );
    let body: Value = serde_json::from_slice(&fixture("codex_cli_request.json")).expect("json");
    for (i, tool) in t.tools.iter().enumerate().skip(1) {
        let n = tool.native.as_ref().expect("native");
        assert_eq!(n.api, NativeApi::OpenaiResponses);
        assert_eq!(
            Value::Object(n.spec.clone()),
            body["tools"][i],
            "kept as sent"
        );
    }
    let patch = &t.tools[1];
    assert_eq!(
        Value::Object(patch.input_schema.clone()),
        json!({"type": "object", "properties": {"input": {"type": "string"}}, "required": ["input"]})
    );
    assert!(patch.description.contains("FREEFORM"));
    assert!(
        patch.description.contains("begin_patch"),
        "the grammar is in the description"
    );
    // The leading developer message joins the instructions; the user messages follow.
    let system = t.system.as_deref().expect("system");
    assert!(system.starts_with("You are a coding agent"));
    assert!(system.contains("Sandbox: read-only."));
    assert_eq!(
        t.messages.iter().map(|m| m.role).collect::<Vec<_>>(),
        [Role::User]
    );
}

#[test]
fn codex_history_of_native_calls_decodes() {
    let mut body: Value = serde_json::from_slice(&fixture("codex_cli_request.json")).expect("json");
    let input = body["input"].as_array_mut().expect("input");
    input.extend([
        json!({"type": "web_search_call", "id": "ws_1", "status": "completed", "action": {"type": "search", "query": "q"}}),
        json!({"type": "custom_tool_call", "id": "ctc_1", "call_id": "call_p", "name": "apply_patch", "input": "*** Begin Patch\n*** End Patch\n"}),
        json!({"type": "custom_tool_call_output", "call_id": "call_p", "output": "Done!"}),
        json!({"type": "tool_search_call", "execution": "client", "call_id": "call_s", "status": "completed", "arguments": {"query": "calendar"}}),
        json!({"type": "tool_search_output", "execution": "client", "call_id": "call_s", "status": "completed",
               "tools": [{"type": "function", "name": "cal_list", "defer_loading": true, "parameters": {"type": "object"}}]}),
        json!({"type": "tool_search_call", "execution": "server", "call_id": null, "arguments": {"paths": ["crm"]}}),
        json!({"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "Sandbox: workspace-write."}]}),
        json!({"type": "message", "role": "user", "content": [{"type": "input_text", "text": "go on"}]}),
    ]);
    let req = decode_codex(body.to_string().as_bytes()).expect("decodes");
    let m = &req.turn.messages;
    assert_eq!(
        m.iter().map(|m| m.role).collect::<Vec<_>>(),
        [
            Role::User,
            Role::Assistant,
            Role::User,
            Role::Assistant,
            Role::User,
            Role::System,
            Role::User
        ]
    );
    assert_eq!(
        m[1].content,
        vec![Block::ToolUse {
            id: "call_p".into(),
            name: "apply_patch".into(),
            input: common::object(json!({"input": "*** Begin Patch\n*** End Patch\n"})),
        }]
    );
    assert_eq!(
        m[2].content,
        vec![Block::ToolResult {
            id: "call_p".into(),
            content: "Done!".into(),
            is_error: None
        }]
    );
    assert_eq!(
        m[3].content,
        vec![Block::ToolUse {
            id: "call_s".into(),
            name: "tool_search".into(),
            input: common::object(json!({"query": "calendar"})),
        }]
    );
    let Block::ToolResult { content, .. } = &m[4].content[0] else {
        panic!("tool result")
    };
    let loaded: Value = serde_json::from_str(content).expect("tools as JSON");
    assert_eq!(loaded[0]["name"], "cal_list");
    assert_eq!(
        m[5].content,
        vec![Block::Text {
            text: "Sandbox: workspace-write.".into()
        }]
    );
}

#[test]
fn unknown_tool_types_are_kept_and_refused_elsewhere() {
    let body = json!({"model": "gpt-chat", "input": "Hi", "tools": [
        {"type": "local_shell"},
        {"type": "function", "name": "lookup", "defer_loading": true, "parameters": {"type": "object"}},
        {"type": "mcp", "server_label": "docs", "server_url": "https://example.invalid/mcp"},
        {"type": "mcp", "server_label": "docs", "server_url": "https://example.invalid/mcp2"},
    ]});
    let req = decode(&body).expect("decodes");
    let tools: Vec<(&str, Option<Elsewhere>)> = req
        .turn
        .tools
        .iter()
        .map(|t| (t.name.as_str(), t.native.as_ref().map(|n| n.elsewhere)))
        .collect();
    assert_eq!(
        tools,
        [
            ("local_shell", Some(Elsewhere::Refuse)),
            ("lookup", Some(Elsewhere::Function)),
            ("docs", Some(Elsewhere::Omit)),
            ("docs_2", Some(Elsewhere::Omit)),
        ]
    );
}

#[test]
fn calls_of_custom_and_tool_search_tools_stream_as_their_own_items() {
    let req = decode_codex(&fixture("codex_cli_request.json")).expect("decodes");
    let events = [
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "call_p".into(),
                name: "apply_patch".into(),
                input: common::object(json!({"input": "*** Begin Patch\n*** End Patch\n"})),
            },
        },
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "call_s".into(),
                name: "tool_search".into(),
                input: common::object(json!({"query": "calendar"})),
            },
        },
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "call_e".into(),
                name: "exec_command".into(),
                input: common::object(json!({"cmd": "ls"})),
            },
        },
        StreamEvent::Stop {
            reason: StopReason::ToolUse,
        },
    ];
    let mut enc = SseEncoder::new("test1", "gpt-5.5", NOW, VENDOR).tools(&req.turn.tools);
    let mut bytes = Vec::new();
    for e in &events {
        bytes.extend(enc.push(e));
    }
    let (_, last) = check_responses(&bytes);
    let output = last["output"].as_array().expect("output");
    assert_eq!(
        output[0],
        json!({"type": "custom_tool_call", "id": "ctc_test1_0", "status": "completed",
               "call_id": "call_p", "name": "apply_patch", "input": "*** Begin Patch\n*** End Patch\n"})
    );
    assert_eq!(
        output[1],
        json!({"type": "tool_search_call", "id": "tsc_test1_1", "status": "completed",
               "call_id": "call_s", "execution": "client", "arguments": {"query": "calendar"}})
    );
    assert_eq!(output[2]["type"], "function_call");
    assert_eq!(output[2]["arguments"], r#"{"cmd":"ls"}"#);

    let mut asm = Assembler::new("test1", "gpt-5.5", NOW, VENDOR).tools(&req.turn.tools);
    for e in &events {
        asm.push(e);
    }
    let obj = serde_json::to_value(asm.finish().expect("object")).expect("json");
    assert_eq!(&obj["output"], &last["output"]);
}

/// A tool a client-run tool search loaded inside a namespace is called by namespace and name;
/// the canonical name is `namespace/name` and the item gets both back.
#[test]
fn namespaced_calls_keep_their_namespace() {
    let body = json!({"model": "gpt-chat", "input": [
        {"role": "user", "content": "mail"},
        {"type": "function_call", "call_id": "call_m", "namespace": "mcp__apps__gmail", "name": "send", "arguments": "{}"},
        {"type": "function_call_output", "call_id": "call_m", "output": "sent"}
    ]});
    let req = decode(&body).expect("decodes");
    let Block::ToolUse { name, .. } = &req.turn.messages[1].content[0] else {
        panic!("tool use")
    };
    assert_eq!(name, "mcp__apps__gmail/send");

    let mut enc = SseEncoder::new("test1", "gpt-chat", NOW, VENDOR);
    let mut bytes = enc.push(&StreamEvent::ToolCall {
        tool_call: ToolCall {
            id: "call_n".into(),
            name: "mcp__apps__gmail/send".into(),
            input: common::object(json!({"to": "a"})),
        },
    });
    bytes.extend(enc.push(&StreamEvent::Stop {
        reason: StopReason::ToolUse,
    }));
    let (_, last) = check_responses(&bytes);
    assert_eq!(last["output"][0]["namespace"], "mcp__apps__gmail");
    assert_eq!(last["output"][0]["name"], "send");

    let e = decode(&json!({"model": "gpt-chat", "input": "Hi", "tools": [
        {"type": "tool_search", "execution": "client"}, {"type": "tool_search", "execution": "client"}
    ]}))
    .expect_err("two tool searches");
    assert!(e.message.unwrap_or_default().contains("second tool_search"));
}
