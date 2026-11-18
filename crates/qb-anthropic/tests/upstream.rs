//! Upstream direction: canonical request to Anthropic body and headers, recorded Anthropic
//! streams to canonical events, and vendor answers to failures and quota windows.

mod common;

use common::{Answer, NOW, VENDOR, fixture, run};
use qb_anthropic::limits::{FailureKind, classify_response, rate_limits};
use qb_anthropic::request::{AuthMode, BuildError, Target, build, identity};
use qb_proto::{
    Block, CacheMode, Effort, Elsewhere, ErrorClass, Message, NativeApi, NativeTool, Object,
    Outcome, Role, StopReason, StreamEvent, Thinking, Tool, ToolCall, TurnRequest, Usage,
    WindowReport,
};
use serde_json::{Value, json};

fn obj(v: Value) -> Object {
    match v {
        Value::Object(m) => m,
        _ => panic!("not an object"),
    }
}

fn text(s: &str) -> StreamEvent {
    StreamEvent::TextDelta { text: s.into() }
}

fn usage(input: u64, output: u64) -> StreamEvent {
    StreamEvent::Usage {
        usage: Usage {
            input,
            output,
            cache_read: 2000,
            cache_write: 100,
        },
    }
}

fn thinking(opaque: &str) -> StreamEvent {
    StreamEvent::Thinking {
        thinking: Thinking {
            vendor: VENDOR.into(),
            opaque: opaque.into(),
        },
    }
}

#[test]
fn text_stream() {
    let got = run(&fixture("upstream_text.sse"));
    assert_eq!(got.end, Ok(StopReason::End));
    assert_eq!(
        got.events,
        vec![
            usage(25, 1),
            text("Hello"),
            text(", wor"),
            text("ld — ünïcode!"),
            usage(25, 12)
        ]
    );
}

#[test]
fn crlf_comments_and_unknown_events_change_nothing() {
    assert_eq!(
        run(&fixture("upstream_text_crlf.sse")),
        run(&fixture("upstream_text.sse"))
    );
}

#[test]
fn tool_use_with_split_input_json() {
    let got = run(&fixture("upstream_tool_use.sse"));
    assert_eq!(got.end, Ok(StopReason::ToolUse));
    assert_eq!(
        got.events,
        vec![
            usage(25, 1),
            text("Reading the file first."),
            StreamEvent::ToolCall {
                tool_call: ToolCall {
                    id: "toolu_test_1".into(),
                    name: "read".into(),
                    input: obj(json!({"path": "notes.txt", "lines": [1, 2]})),
                }
            },
            StreamEvent::ToolCall {
                tool_call: ToolCall {
                    id: "toolu_test_2".into(),
                    name: "list".into(),
                    input: Object::new(),
                }
            },
            usage(25, 48)
        ]
    );
}

#[test]
fn thinking_with_signature_and_redacted_thinking() {
    let got = run(&fixture("upstream_thinking.sse"));
    assert_eq!(got.end, Ok(StopReason::End));
    assert_eq!(
        got.events,
        vec![
            usage(25, 1),
            thinking(
                r#"{"type":"thinking","thinking":"The user wants a greeting.","signature":"c2lnbmF0dXJlLXRlc3QtMQ=="}"#
            ),
            thinking(r#"{"type":"redacted_thinking","data":"cmVkYWN0ZWQtdGVzdC0x"}"#),
            text("Hi!"),
            usage(25, 30)
        ]
    );
}

#[test]
fn max_tokens_stop() {
    let got = run(&fixture("upstream_max_tokens.sse"));
    assert_eq!(got.end, Ok(StopReason::MaxTokens));
    assert_eq!(got.events[1], text("A very long ans"));
}

#[test]
fn error_mid_stream_keeps_delivered_events() {
    let got = run(&fixture("upstream_error_overloaded.sse"));
    assert_eq!(got.events, vec![usage(25, 1), text("Partial")]);
    let failure = got.end.expect_err("error event");
    assert_eq!(failure.kind, FailureKind::Overloaded { retry_after: None });
    assert!(
        failure.message.contains("Overloaded"),
        "{}",
        failure.message
    );
}

#[test]
fn stream_cut_before_message_stop_is_unavailable() {
    let bytes = fixture("upstream_text.sse");
    let cut = &bytes[..bytes.len() - 40];
    let failure = run(cut).end.expect_err("cut");
    assert_eq!(failure.kind, FailureKind::Unavailable);
}

fn turn() -> TurnRequest {
    TurnRequest {
        route: "chat".into(),
        system: Some("You are a helpful assistant.".into()),
        messages: vec![
            Message {
                role: Role::User,
                content: vec![
                    Block::Text {
                        text: "Look at this.".into(),
                    },
                    Block::Image {
                        media_type: qb_proto::MediaType::Png,
                        path: Some("/media/photo-1.png".into()),
                        base64: None,
                    },
                ],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Thinking {
                        vendor: "vendor-b".into(),
                        opaque: "foreign".into(),
                    },
                    Block::Thinking {
                        vendor: VENDOR.into(),
                        opaque: json!({"type": "thinking", "thinking": "t", "signature": "s"})
                            .to_string(),
                    },
                    Block::Thinking {
                        vendor: VENDOR.into(),
                        opaque: "c3ludGhldGljLW9wYXF1ZQ==".into(),
                    },
                    Block::ToolUse {
                        id: "call_01".into(),
                        name: "read".into(),
                        input: obj(json!({"path": "notes.txt"})),
                    },
                ],
            },
            Message {
                role: Role::User,
                content: vec![Block::ToolResult {
                    id: "call_01".into(),
                    content: "no such file".into(),
                    is_error: Some(true),
                }],
            },
        ],
        tools: vec![Tool {
            name: "read".into(),
            description: "Read a text file.".into(),
            input_schema: obj(json!({"type": "object"})),
            native: None,
        }],
        max_tokens: 4096,
        effort: Some(Effort::Medium),
        session_key: None,
        cache: Some(CacheMode::Auto),
        request_id: "turn-0001".into(),
    }
}

fn target(auth: AuthMode) -> Target<'static> {
    Target {
        vendor: VENDOR,
        model: "model-a",
        effort: Some("xhigh"),
        auth,
        adaptive_thinking: true,
    }
}

fn load(path: &str) -> Option<String> {
    (path == "/media/photo-1.png").then(|| "iVBORw0K".to_owned())
}

#[test]
fn request_body_in_api_key_mode() {
    let body = build(&turn(), &target(AuthMode::ApiKey), &mut load).expect("builds");
    let got = serde_json::to_value(&body).expect("serialises");
    let want = json!({
        "model": "model-a",
        "max_tokens": 4096,
        "system": [{
            "type": "text",
            "text": "You are a helpful assistant.",
            "cache_control": {"type": "ephemeral"}
        }],
        "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "Look at this."},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0K"},
                 "cache_control": {"type": "ephemeral"}}
            ]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "t", "signature": "s"},
                {"type": "tool_use", "id": "call_01", "name": "read", "input": {"path": "notes.txt"}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "call_01", "content": "no such file", "is_error": true,
                 "cache_control": {"type": "ephemeral"}}
            ]}
        ],
        "tools": [{"name": "read", "description": "Read a text file.", "input_schema": {"type": "object"}}],
        "stream": true,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "medium"}
    });
    assert_eq!(got, want);
}

#[test]
fn oauth_mode_adds_the_identity_prefix_and_headers() {
    let body = build(&turn(), &target(AuthMode::Oauth), &mut load).expect("builds");
    let system = serde_json::to_value(&body.system).expect("serialises");
    assert_eq!(
        system,
        json!([
            {"type": "text", "text": identity::OAUTH_SYSTEM_PREFIX},
            {"type": "text", "text": "You are a helpful assistant.", "cache_control": {"type": "ephemeral"}}
        ])
    );
    let headers = AuthMode::Oauth.headers();
    let get = |n: &str| {
        headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(
        get("anthropic-beta"),
        Some("oauth-2025-04-20,claude-code-20250219")
    );
    assert_eq!(get("x-app"), Some("cli"));
    assert_eq!(get("anthropic-version"), Some(identity::ANTHROPIC_VERSION));
    assert!(get("user-agent").is_some_and(|ua| ua.starts_with("claude-cli/")));
    assert_eq!(
        AuthMode::Oauth.secret_header(),
        ("authorization", "Bearer ")
    );
    assert_eq!(AuthMode::ApiKey.secret_header(), ("x-api-key", ""));
    let api = AuthMode::ApiKey.headers();
    assert!(
        api.iter()
            .all(|(k, _)| *k != "anthropic-beta" && *k != "x-app")
    );
}

#[test]
fn oauth_user_agent_meets_the_subscription_endpoint_minimum() {
    // The subscription endpoint refuses newer models for older CLI versions with HTTP 400
    // "version 2.1.280 or newer is required" (claude-opus-5-5, November 2026).
    let version = identity::OAUTH_USER_AGENT
        .strip_prefix("claude-cli/")
        .and_then(|rest| rest.split(' ').next())
        .expect("claude-cli/<version> user agent");
    let parts: Vec<u32> = version
        .split('.')
        .map(|p| p.parse().expect("numeric version part"))
        .collect();
    assert!(parts >= vec![2, 1, 280], "{version} is below 2.1.280");
}

#[test]
fn ladder_effort_applies_without_a_request_effort_and_unknown_efforts_are_dropped() {
    let mut req = turn();
    req.effort = None;
    let body = build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds");
    assert_eq!(
        body.output_config.and_then(|o| o.effort).as_deref(),
        Some("xhigh")
    );
    let t = Target {
        effort: Some("turbo"),
        adaptive_thinking: false,
        ..target(AuthMode::ApiKey)
    };
    let body = build(&req, &t, &mut load).expect("builds");
    assert!(body.output_config.is_none());
    assert!(body.thinking.is_none());
}

#[test]
fn without_cache_auto_no_breakpoints_and_without_system_the_last_tool_is_marked() {
    let mut req = turn();
    req.cache = None;
    let body = build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds");
    assert!(
        !serde_json::to_string(&body)
            .expect("json")
            .contains("cache_control")
    );

    req.cache = Some(CacheMode::Auto);
    req.system = None;
    let body = build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds");
    assert!(body.tools[0].cache_control.is_some());
    assert!(body.system.is_none());
}

fn signed_thinking(vendor: &str) -> Block {
    Block::Thinking {
        vendor: vendor.into(),
        opaque: json!({"type": "thinking", "thinking": "t", "signature": "s"}).to_string(),
    }
}

fn call(id: &str) -> Block {
    Block::ToolUse {
        id: id.into(),
        name: "read".into(),
        input: obj(json!({"path": "notes.txt"})),
    }
}

fn result(id: &str) -> Block {
    Block::ToolResult {
        id: id.into(),
        content: "line one".into(),
        is_error: None,
    }
}

fn says(text: &str) -> Block {
    Block::Text { text: text.into() }
}

/// `turn()` with the history `user: Hi`, then each assistant message followed by a user message.
fn history(rounds: Vec<(Vec<Block>, Block)>) -> TurnRequest {
    let mut messages = vec![Message {
        role: Role::User,
        content: vec![says("Hi")],
    }];
    for (assistant, user) in rounds {
        messages.push(Message {
            role: Role::Assistant,
            content: assistant,
        });
        messages.push(Message {
            role: Role::User,
            content: vec![user],
        });
    }
    TurnRequest { messages, ..turn() }
}

#[test]
fn thinking_is_requested_unless_the_last_assistant_tool_call_lost_its_thinking() {
    let cases = [
        (
            "tool loop with the last assistant thinking",
            history(vec![(
                vec![signed_thinking(VENDOR), call("c1")],
                result("c1"),
            )]),
            true,
        ),
        (
            "stripped last assistant",
            history(vec![(vec![call("c1")], result("c1"))]),
            false,
        ),
        (
            "last assistant with thinking of another vendor only",
            history(vec![(
                vec![signed_thinking("vendor-b"), call("c1")],
                result("c1"),
            )]),
            false,
        ),
        (
            "stripped earlier assistant only",
            history(vec![
                (vec![call("c1")], result("c1")),
                (vec![signed_thinking(VENDOR), call("c2")], result("c2")),
            ]),
            true,
        ),
        (
            "no tool calls",
            history(vec![(vec![says("(thinking elided)")], says("Go on."))]),
            true,
        ),
    ];
    for (name, req, kept) in cases {
        let body = build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds");
        assert_eq!(body.thinking.is_some(), kept, "{name}");
        assert_eq!(body.messages.len(), req.messages.len(), "{name}");
    }
}

#[test]
fn unreadable_image_is_a_build_error() {
    let mut none = |_: &str| None;
    assert_eq!(
        build(&turn(), &target(AuthMode::ApiKey), &mut none),
        Err(BuildError::Image("/media/photo-1.png".into()))
    );
}

fn window(name: &str, utilization: f64, resets_at: u64, length_s: u32) -> WindowReport {
    WindowReport {
        name: name.into(),
        utilization,
        resets_at: Some(resets_at),
        length_s: Some(length_s),
    }
}

#[test]
fn unified_headers_become_windows() {
    let a = Answer::load("answer_200_allowed.json");
    let limits = rate_limits(&a.pairs());
    assert_eq!(limits.status.as_deref(), Some("allowed"));
    assert_eq!(limits.resets_at, Some(1_800_003_600));
    assert_eq!(limits.representative_claim.as_deref(), Some("five_hour"));
    assert_eq!(
        limits.windows,
        vec![
            window("five_hour", 0.42, 1_800_003_600, 18_000),
            window("seven_day", 0.1, 1_800_500_000, 604_800),
            window("seven_day_opus", 0.25, 1_800_500_000, 604_800),
        ]
    );
}

/// The mapping the gateway core applies to its seam's `FailureKind`, by the seam's names: the
/// binary converts this crate's mirror by name, so the names and both columns must agree.
#[test]
fn failure_kinds_map_as_the_gateway_core_does() {
    let cases = [
        (
            FailureKind::UsageLimit { resets_at: None },
            "usage_limit",
            ErrorClass::QuotaExhausted,
            Outcome::UsageLimit,
        ),
        (
            FailureKind::Auth,
            "auth",
            ErrorClass::Auth,
            Outcome::Http401,
        ),
        (
            FailureKind::RateLimited { retry_after: None },
            "rate_limited",
            ErrorClass::Overloaded,
            Outcome::Http429,
        ),
        (
            FailureKind::ModelUnavailable,
            "model_unavailable",
            ErrorClass::Unavailable,
            Outcome::ModelUnavailable,
        ),
        (
            FailureKind::Overloaded { retry_after: None },
            "overloaded",
            ErrorClass::Overloaded,
            Outcome::Error,
        ),
        (
            FailureKind::Unavailable,
            "unavailable",
            ErrorClass::Unavailable,
            Outcome::Error,
        ),
        (
            FailureKind::BadRequest,
            "bad_request",
            ErrorClass::BadRequest,
            Outcome::Error,
        ),
        (
            FailureKind::ContextTooLong,
            "context_too_long",
            ErrorClass::ContextTooLong,
            Outcome::Error,
        ),
    ];
    for (kind, name, class, outcome) in cases {
        assert_eq!(
            (kind.as_str(), kind.error_class(), kind.outcome()),
            (name, class, outcome)
        );
    }
}

#[test]
fn vendor_answers_classify() {
    let cases: &[(&str, FailureKind, ErrorClass, Outcome)] = &[
        (
            "answer_429_usage_limit.json",
            FailureKind::UsageLimit {
                resets_at: Some(1_800_018_000),
            },
            ErrorClass::QuotaExhausted,
            Outcome::UsageLimit,
        ),
        (
            "answer_429_limit_message.json",
            FailureKind::UsageLimit { resets_at: None },
            ErrorClass::QuotaExhausted,
            Outcome::UsageLimit,
        ),
        (
            "answer_429_short.json",
            FailureKind::RateLimited {
                retry_after: Some(30),
            },
            ErrorClass::Overloaded,
            Outcome::Http429,
        ),
        (
            "answer_401.json",
            FailureKind::Auth,
            ErrorClass::Auth,
            Outcome::Http401,
        ),
        (
            "answer_403.json",
            FailureKind::Auth,
            ErrorClass::Auth,
            Outcome::Http401,
        ),
        (
            "answer_404_model.json",
            FailureKind::ModelUnavailable,
            ErrorClass::Unavailable,
            Outcome::ModelUnavailable,
        ),
        (
            "answer_529.json",
            FailureKind::Overloaded {
                retry_after: Some(5),
            },
            ErrorClass::Overloaded,
            Outcome::Error,
        ),
        (
            "answer_400_too_long.json",
            FailureKind::ContextTooLong,
            ErrorClass::ContextTooLong,
            Outcome::Error,
        ),
        (
            "answer_400_invalid.json",
            FailureKind::BadRequest,
            ErrorClass::BadRequest,
            Outcome::Error,
        ),
        (
            "answer_400_credit_balance.json",
            FailureKind::UsageLimit { resets_at: None },
            ErrorClass::QuotaExhausted,
            Outcome::UsageLimit,
        ),
        (
            "answer_500_html.json",
            FailureKind::Unavailable,
            ErrorClass::Unavailable,
            Outcome::Error,
        ),
    ];
    for (name, kind, class, outcome) in cases {
        let a = Answer::load(name);
        let f = classify_response(a.status, &a.pairs(), &a.body);
        assert_eq!(f.kind, *kind, "{name}");
        assert_eq!(f.kind.error_class(), *class, "{name}");
        assert_eq!(f.kind.outcome(), *outcome, "{name}");
        assert!(f.message.contains(&a.status.to_string()), "{name}");
    }
}

#[test]
fn a_usage_limit_reports_the_rejected_window_as_full() {
    let a = Answer::load("answer_429_usage_limit.json");
    let f = classify_response(a.status, &a.pairs(), &a.body);
    assert_eq!(
        f.windows,
        vec![
            window("five_hour", 1.0, 1_800_018_000, 18_000),
            window("seven_day", 0.8, 1_800_500_000, 604_800),
        ]
    );
    assert!(f.windows.iter().all(|w| w.resets_at > Some(NOW)));
}

fn msg(role: Role, text: &str) -> Message {
    Message {
        role,
        content: vec![Block::Text { text: text.into() }],
    }
}

fn roles_and_system(req: &TurnRequest) -> (Vec<String>, Vec<String>) {
    let body =
        serde_json::to_value(build(req, &target(AuthMode::ApiKey), &mut load).expect("builds"))
            .expect("json");
    let roles = body["messages"]
        .as_array()
        .expect("messages")
        .iter()
        .map(|m| m["role"].as_str().unwrap_or_default().to_owned())
        .collect();
    let system = body["system"]
        .as_array()
        .map(|b| {
            b.iter()
                .map(|x| x["text"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default();
    (roles, system)
}

#[test]
fn a_system_message_after_a_user_turn_stays_in_place() {
    let mut req = turn();
    req.cache = None;
    req.messages = vec![
        msg(Role::User, "Hi"),
        msg(Role::System, "Be brief."),
        msg(Role::System, "Use metric units."),
    ];
    let (roles, system) = roles_and_system(&req);
    assert_eq!(roles, ["user", "system", "system"]);
    assert_eq!(system, ["You are a helpful assistant."]);
    let body =
        serde_json::to_value(build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds"))
            .expect("json");
    assert_eq!(
        body["messages"][1],
        json!({"role": "system", "content": [{"type": "text", "text": "Be brief."}]})
    );

    req.messages.push(msg(Role::Assistant, "Done."));
    req.messages.push(msg(Role::User, "Again"));
    let (roles, _) = roles_and_system(&req);
    assert_eq!(roles, ["user", "system", "system", "assistant", "user"]);
}

#[test]
fn a_misplaced_system_message_joins_the_system_prompt() {
    let mut req = turn();
    req.cache = None;
    req.messages = vec![
        msg(Role::System, "First of all."),
        msg(Role::User, "Hi"),
        msg(Role::Assistant, "Hello."),
        msg(Role::System, "After the model."),
        msg(Role::User, "Bye"),
    ];
    let (roles, system) = roles_and_system(&req);
    assert_eq!(roles, ["user", "assistant", "user"]);
    assert_eq!(
        system,
        [
            "You are a helpful assistant.",
            "First of all.",
            "After the model."
        ]
    );

    // After a user turn but followed by another user turn: also lifted.
    req.messages = vec![
        msg(Role::User, "Hi"),
        msg(Role::System, "Between users."),
        msg(Role::User, "Again"),
    ];
    let (roles, system) = roles_and_system(&req);
    assert_eq!(roles, ["user", "user"]);
    assert_eq!(system, ["You are a helpful assistant.", "Between users."]);
}

#[test]
fn a_cached_turn_marks_the_trailing_system_message() {
    let mut req = turn();
    req.messages = vec![msg(Role::User, "Hi"), msg(Role::System, "Context.")];
    let body =
        serde_json::to_value(build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds"))
            .expect("json");
    assert_eq!(body["messages"][1]["role"], "system");
    assert_eq!(
        body["messages"][1]["content"][0]["cache_control"],
        json!({"type": "ephemeral"})
    );
    assert_eq!(
        body["messages"][0]["content"][0]["cache_control"],
        json!({"type": "ephemeral"})
    );
}

fn native(name: &str, spec: Value, elsewhere: Elsewhere) -> Tool {
    Tool {
        name: name.into(),
        description: format!("{name} tool"),
        input_schema: obj(json!({"type": "object", "properties": {"input": {"type": "string"}}})),
        native: Some(NativeTool {
            api: NativeApi::OpenaiResponses,
            spec: obj(spec),
            elsewhere,
        }),
    }
}

#[test]
fn native_tools_of_another_api_become_functions_are_left_out_or_refused() {
    let mut req = turn();
    req.tools.push(native(
        "apply_patch",
        json!({"type": "custom", "name": "apply_patch"}),
        Elsewhere::Function,
    ));
    req.tools.push(native(
        "web_search",
        json!({"type": "web_search"}),
        Elsewhere::Omit,
    ));
    let body =
        serde_json::to_value(build(&req, &target(AuthMode::ApiKey), &mut load).expect("builds"))
            .expect("json");
    let names: Vec<&str> = body["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, ["read", "apply_patch"]);
    assert_eq!(body["tools"][1]["description"], "apply_patch tool");
    assert!(body["tools"][1].get("type").is_none());

    req.tools.push(native(
        "local_shell",
        json!({"type": "local_shell"}),
        Elsewhere::Refuse,
    ));
    let e = build(&req, &target(AuthMode::ApiKey), &mut load).expect_err("refused");
    assert_eq!(e, BuildError::Tool("local_shell".into()));
    assert!(e.to_string().contains("local_shell"));
}
