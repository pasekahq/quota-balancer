//! The upstream direction: a canonical turn becomes a Responses body and headers; recorded-shape
//! Responses streams become canonical events; vendor answers become windows and failures.

mod common;

use common::{Answer, NOW, OTHER, VENDOR, fixture, object, run};
use qb_openai::limits::{
    FailureKind, RateLimits, classify_response, classify_stream_error, rate_limits,
};
use qb_openai::request::{AuthMode, BuildError, Target, build, identity};
use qb_openai::stream::{Progress, Reader, event_bound};
use qb_proto::{
    Block, Effort, ErrorClass, MediaType, Message, Outcome, Role, StopReason, StreamEvent,
    Thinking, Tool, ToolCall, TurnRequest, Usage, WindowReport,
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

#[test]
fn text_stream_with_unknown_events_and_comments() {
    let want = vec![
        text("Hello"),
        text(", wörld"),
        text("!"),
        usage(120, 12, 2000),
    ];
    for name in ["upstream_text.sse", "upstream_text_crlf.sse"] {
        let got = run(&fixture(name));
        assert_eq!(got.events, want, "{name}");
        assert_eq!(got.end, Ok(StopReason::End), "{name}");
    }
}

#[test]
fn parallel_tool_calls_with_split_arguments() {
    let got = run(&fixture("upstream_tool_calls.sse"));
    assert_eq!(
        got.events,
        vec![
            call("call_a1", "read_file", json!({"path": "notes.txt"})),
            call("call_b2", "list_dir", json!({"dir": "src"})),
            usage(300, 40, 0),
        ]
    );
    assert_eq!(got.end, Ok(StopReason::ToolUse));
}

#[test]
fn reasoning_becomes_thinking_with_the_encrypted_content() {
    let got = run(&fixture("upstream_reasoning.sse"));
    let opaque = r#"{"type":"reasoning","summary":[{"type":"summary_text","text":"**Checking the file**"}],"encrypted_content":"Z0FBQUFBQnN5bnRoZXRpYy1lbmNyeXB0ZWQ="}"#;
    assert_eq!(
        got.events,
        vec![
            StreamEvent::Thinking {
                thinking: Thinking {
                    vendor: VENDOR.into(),
                    opaque: opaque.into(),
                },
            },
            text("Reading it now."),
            call("call_c3", "read_file", json!({"path": "a.txt"})),
            usage(372, 200, 128),
        ]
    );
    assert_eq!(got.end, Ok(StopReason::ToolUse));
}

#[test]
fn incomplete_is_a_length_stop() {
    let got = run(&fixture("upstream_incomplete.sse"));
    assert_eq!(
        got.events,
        vec![text("The list goes on and"), usage(50, 16, 0)]
    );
    assert_eq!(got.end, Ok(StopReason::MaxTokens));
}

#[test]
fn errors_mid_stream_are_classified() {
    let failed = run(&fixture("upstream_failed.sse"));
    assert_eq!(failed.events, vec![text("Partial")]);
    let f = failed.end.expect_err("failed");
    assert_eq!(
        f.kind,
        FailureKind::RateLimited {
            retry_after: Some(20)
        }
    );
    assert!(f.message.contains("rate_limit_exceeded"), "{}", f.message);

    let error = run(&fixture("upstream_error_event.sse"));
    let f = error.end.expect_err("error event");
    assert_eq!(f.kind, FailureKind::Overloaded { retry_after: None });
    assert!(!f.message.contains('\n'), "{}", f.message);
}

#[test]
fn a_cut_stream_is_unavailable_and_keeps_what_was_delivered() {
    let got = run(&fixture("upstream_cut.sse"));
    assert_eq!(got.events, vec![text("Cut here")]);
    let f = got.end.expect_err("cut");
    assert_eq!(f.kind, FailureKind::Unavailable);
    assert!(
        f.message.contains("before response.completed"),
        "{}",
        f.message
    );
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
                        media_type: MediaType::Jpeg,
                        path: None,
                        base64: Some("/9j/4AAQ".into()),
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
                        id: "call_1".into(),
                        name: "read_file".into(),
                        input: object(json!({"path": "a"})),
                    },
                ],
            },
            Message {
                role: Role::User,
                content: vec![
                    Block::ToolResult {
                        id: "call_1".into(),
                        content: "contents".into(),
                        is_error: Some(true),
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
        }],
        max_tokens: 4096,
        effort: Some(Effort::Max),
        session_key: Some("conv-1".into()),
        cache: None,
        request_id: "turn-1".into(),
    }
}

fn target(auth: AuthMode) -> Target<'static> {
    Target {
        vendor: VENDOR,
        model: "model-o",
        effort: None,
        auth,
        reasoning: true,
    }
}

#[test]
fn api_key_body() {
    let body = build(&turn(), &target(AuthMode::ApiKey)).expect("builds");
    let got = serde_json::to_value(&body).expect("json");
    let want = json!({
        "model": "model-o",
        "instructions": "Be brief.",
        "input": [
            {"type": "message", "role": "user", "content": [
                {"type": "input_text", "text": "Look"},
                {"type": "input_image", "image_url": "data:image/jpeg;base64,/9j/4AAQ", "detail": "auto"}
            ]},
            {"type": "reasoning", "summary": [], "encrypted_content": "ZW5j"},
            {"type": "message", "role": "assistant", "content": [
                {"type": "output_text", "text": "On it.", "annotations": []}
            ]},
            {"type": "function_call", "call_id": "call_1", "name": "read_file", "arguments": "{\"path\":\"a\"}"},
            {"type": "function_call_output", "call_id": "call_1", "output": "contents"},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Go on"}]}
        ],
        "tools": [{"type": "function", "name": "read_file", "description": "Read a file.",
                   "parameters": {"type": "object"}, "strict": false}],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "max_output_tokens": 4096,
        "reasoning": {"effort": "xhigh", "summary": "auto"},
        "include": ["reasoning.encrypted_content"],
        "store": false,
        "stream": true,
        "prompt_cache_key": "conv-1"
    });
    assert_eq!(got, want);
    assert_eq!(AuthMode::ApiKey.url(), identity::API_KEY_URL);
    assert_eq!(
        AuthMode::ApiKey.secret_header(),
        ("authorization", "Bearer ")
    );
    assert_eq!(AuthMode::ApiKey.account_header(), None);
    assert_eq!(
        AuthMode::ApiKey.headers(Some("conv-1")),
        vec![
            ("content-type", "application/json".to_owned()),
            ("accept", "text/event-stream".to_owned()),
            ("user-agent", identity::API_KEY_USER_AGENT.to_owned()),
        ]
    );
}

#[test]
fn chatgpt_body_and_headers() {
    let mut req = turn();
    req.system = None;
    let body = build(&req, &target(AuthMode::ChatgptOauth)).expect("builds");
    let got = serde_json::to_value(&body).expect("json");
    assert_eq!(
        got["instructions"],
        json!(""),
        "the endpoint needs instructions"
    );
    assert!(
        got.get("max_output_tokens").is_none(),
        "the endpoint refuses it"
    );
    assert_eq!(got["store"], json!(false));
    assert_eq!(AuthMode::ChatgptOauth.url(), identity::CHATGPT_URL);
    assert_eq!(
        AuthMode::ChatgptOauth.account_header(),
        Some(identity::ACCOUNT_HEADER)
    );
    let headers = AuthMode::ChatgptOauth.headers(Some("conv-1"));
    for (name, value) in [
        ("openai-beta", identity::OPENAI_BETA),
        ("originator", identity::ORIGINATOR),
        ("user-agent", identity::CHATGPT_USER_AGENT),
        (identity::SESSION_HEADER, "conv-1"),
        ("accept", "text/event-stream"),
    ] {
        assert!(
            headers.iter().any(|(n, v)| *n == name && v == value),
            "{name}: {headers:?}"
        );
    }
    let unsafe_session = AuthMode::ChatgptOauth.headers(Some("a\r\nx-injected: 1"));
    assert!(
        unsafe_session
            .iter()
            .all(|(n, _)| *n != identity::SESSION_HEADER)
    );
}

#[test]
fn effort_precedence_and_models_without_reasoning() {
    let mut req = turn();
    req.effort = None;
    let mut at = target(AuthMode::ApiKey);
    at.effort = Some("max");
    let body = build(&req, &at).expect("builds");
    assert_eq!(
        body.reasoning.and_then(|r| r.effort).as_deref(),
        Some("xhigh")
    );
    at.effort = Some("turbo");
    let body = build(&req, &at).expect("builds");
    assert_eq!(body.reasoning.and_then(|r| r.effort), None);
    at.reasoning = false;
    let body = build(&req, &at).expect("builds");
    assert!(body.reasoning.is_none() && body.include.is_none());
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
        build(&req, &target(AuthMode::ApiKey)),
        Err(BuildError::ImagePath("/srv/a.png".into()))
    );
}

fn window(
    name: &str,
    utilization: f64,
    resets_at: Option<u64>,
    length_s: Option<u32>,
) -> WindowReport {
    WindowReport {
        name: name.into(),
        utilization,
        resets_at,
        length_s,
    }
}

#[test]
fn subscription_headers_become_codex_windows() {
    let a = Answer::load("answer_200_chatgpt.json");
    let limits = rate_limits(&a.pairs(), NOW);
    assert_eq!(
        limits.windows,
        vec![
            window("five_hour", 0.425, Some(1_800_010_000), Some(18_000)),
            window("seven_day", 0.07, Some(NOW + 86_400), Some(604_800)),
        ]
    );
    assert!(!limits.exhausted());

    // The same windows as qb-vendors reads from a Codex rollout line.
    let line = json!({"payload": {"rate_limits": {
        "primary": {"used_percent": 42.5, "window_minutes": 300, "resets_at": 1_800_010_000_u64},
        "secondary": {"used_percent": 7, "window_minutes": 10080, "resets_in_seconds": 86400}
    }}});
    let rollout = qb_vendors::codex::rollout_line(line.to_string().as_bytes(), NOW)
        .expect("parses")
        .expect("has limits");
    assert_eq!(limits.windows, rollout);
}

#[test]
fn api_key_headers_become_request_and_token_windows() {
    let a = Answer::load("answer_200_api_key.json");
    let limits = rate_limits(&a.pairs(), NOW);
    assert_eq!(
        limits.windows,
        vec![
            window("requests", 1.0 / 500.0, Some(NOW + 1), None),
            window("tokens", 0.1, Some(NOW + 360), None),
        ]
    );
    assert!(
        !limits.exhausted(),
        "API key windows are never a usage limit"
    );
}

struct Case {
    fixture: &'static str,
    kind: FailureKind,
    class: ErrorClass,
    outcome: Outcome,
}

const CASES: [Case; 17] = [
    Case {
        fixture: "answer_429_too_large.json",
        kind: FailureKind::ContextTooLong,
        class: ErrorClass::ContextTooLong,
        outcome: Outcome::Error,
    },
    Case {
        fixture: "answer_400_unverified.json",
        kind: FailureKind::ModelUnavailable,
        class: ErrorClass::Unavailable,
        outcome: Outcome::ModelUnavailable,
    },
    Case {
        fixture: "answer_403_html.json",
        kind: FailureKind::Unavailable,
        class: ErrorClass::Unavailable,
        outcome: Outcome::Error,
    },
    Case {
        fixture: "answer_429_usage_limit.json",
        kind: FailureKind::UsageLimit {
            resets_at: Some(1_800_018_000),
        },
        class: ErrorClass::QuotaExhausted,
        outcome: Outcome::UsageLimit,
    },
    Case {
        fixture: "answer_429_usage_limit_relative.json",
        kind: FailureKind::UsageLimit {
            resets_at: Some(NOW + 3600),
        },
        class: ErrorClass::QuotaExhausted,
        outcome: Outcome::UsageLimit,
    },
    Case {
        fixture: "answer_429_insufficient_quota.json",
        kind: FailureKind::UsageLimit { resets_at: None },
        class: ErrorClass::QuotaExhausted,
        outcome: Outcome::UsageLimit,
    },
    Case {
        fixture: "answer_429_rate_limit.json",
        kind: FailureKind::RateLimited {
            retry_after: Some(2),
        },
        class: ErrorClass::Overloaded,
        outcome: Outcome::Http429,
    },
    Case {
        fixture: "answer_429_message_only.json",
        kind: FailureKind::RateLimited {
            retry_after: Some(360),
        },
        class: ErrorClass::Overloaded,
        outcome: Outcome::Http429,
    },
    Case {
        fixture: "answer_401.json",
        kind: FailureKind::Auth,
        class: ErrorClass::Auth,
        outcome: Outcome::Http401,
    },
    Case {
        fixture: "answer_401_detail.json",
        kind: FailureKind::Auth,
        class: ErrorClass::Auth,
        outcome: Outcome::Http401,
    },
    Case {
        fixture: "answer_403.json",
        kind: FailureKind::Auth,
        class: ErrorClass::Auth,
        outcome: Outcome::Http401,
    },
    Case {
        fixture: "answer_400_context.json",
        kind: FailureKind::ContextTooLong,
        class: ErrorClass::ContextTooLong,
        outcome: Outcome::Error,
    },
    Case {
        fixture: "answer_400_invalid.json",
        kind: FailureKind::BadRequest,
        class: ErrorClass::BadRequest,
        outcome: Outcome::Error,
    },
    Case {
        fixture: "answer_400_model_unsupported.json",
        kind: FailureKind::ModelUnavailable,
        class: ErrorClass::Unavailable,
        outcome: Outcome::ModelUnavailable,
    },
    Case {
        fixture: "answer_404_model.json",
        kind: FailureKind::ModelUnavailable,
        class: ErrorClass::Unavailable,
        outcome: Outcome::ModelUnavailable,
    },
    Case {
        fixture: "answer_500_html.json",
        kind: FailureKind::Unavailable,
        class: ErrorClass::Unavailable,
        outcome: Outcome::Error,
    },
    Case {
        fixture: "answer_503_overloaded.json",
        kind: FailureKind::Overloaded {
            retry_after: Some(7),
        },
        class: ErrorClass::Overloaded,
        outcome: Outcome::Error,
    },
];

#[test]
fn recorded_error_answers() {
    for c in CASES {
        let a = Answer::load(c.fixture);
        let f = classify_response(a.status, &a.pairs(), &a.body, NOW);
        assert_eq!(f.kind, c.kind, "{}", c.fixture);
        assert_eq!(f.kind.error_class(), c.class, "{}", c.fixture);
        assert_eq!(f.kind.outcome(), c.outcome, "{}", c.fixture);
        assert!(
            f.message
                .starts_with(&format!("vendor answered HTTP {}", a.status)),
            "{}: {}",
            c.fixture,
            f.message
        );
        assert!(!f.message.chars().any(char::is_control), "{}", c.fixture);
    }
}

#[test]
fn a_usage_limit_carries_the_windows_and_never_a_header_value() {
    let a = Answer::load("answer_429_usage_limit.json");
    let f = classify_response(a.status, &a.pairs(), &a.body, NOW);
    assert_eq!(f.windows.len(), 2);
    assert_eq!(f.windows[0].name, "five_hour");
    assert!((f.windows[0].utilization - 1.0).abs() < f64::EPSILON);

    let secret = Answer::load("answer_401.json");
    let mut headers = secret.pairs();
    headers.push(("authorization", "Bearer test-token-1"));
    let f = classify_response(secret.status, &headers, &secret.body, NOW);
    assert!(!f.message.contains("test-token-1"), "{}", f.message);
}

#[test]
fn a_429_without_body_reads_exhaustion_from_the_headers() {
    let headers = [
        ("x-codex-primary-used-percent", "100.0"),
        ("x-codex-primary-window-minutes", "300"),
        ("x-codex-primary-reset-after-seconds", "600"),
    ];
    let f = classify_response(429, &headers, b"", NOW);
    assert_eq!(
        f.kind,
        FailureKind::UsageLimit {
            resets_at: Some(NOW + 600)
        }
    );
    assert_eq!(f.message, "vendor answered HTTP 429");
}

#[test]
fn small_output_bounds_are_raised_to_the_vendor_minimum() {
    let mut req = turn();
    req.max_tokens = 1;
    let body = build(&req, &target(AuthMode::ApiKey)).expect("builds");
    assert_eq!(
        body.max_output_tokens,
        Some(qb_openai::request::MIN_OUTPUT_TOKENS)
    );
}

#[test]
fn lifecycle_events_that_repeat_a_large_request_fit_the_event_bound() {
    let instructions = "x".repeat(1_200_000);
    let created = json!({"type": "response.created", "response": {"status": "in_progress",
        "instructions": instructions, "output": []}});
    let completed = json!({"type": "response.completed", "response": {"status": "completed",
        "instructions": instructions, "output": []}});
    let bytes = format!(
        "event: response.created\ndata: {created}\n\nevent: response.completed\ndata: {completed}\n\n"
    );
    let mut small = Reader::new(VENDOR, RateLimits::default());
    assert!(
        small.feed(bytes.as_bytes(), &mut Vec::new()).is_err(),
        "the default bound"
    );
    let mut reader = Reader::with_event_bound(
        VENDOR,
        RateLimits::default(),
        event_bound(instructions.len() + 100),
    );
    assert_eq!(
        reader.feed(bytes.as_bytes(), &mut Vec::new()),
        Ok(Progress::Finished(StopReason::End))
    );
}

#[test]
fn a_usage_limit_puts_its_limiting_window_at_full_use() {
    // The body names the reset; the headers name the windows but none at 100 %.
    let headers = [
        ("x-codex-primary-used-percent", "97"),
        ("x-codex-primary-window-minutes", "300"),
        ("x-codex-primary-reset-after-seconds", "3590"),
        ("x-codex-secondary-used-percent", "40"),
        ("x-codex-secondary-window-minutes", "10080"),
        ("x-codex-secondary-reset-after-seconds", "500000"),
    ];
    let a = Answer::load("answer_429_usage_limit_relative.json");
    let f = classify_response(a.status, &headers, &a.body, NOW);
    assert_eq!(
        f.windows,
        vec![
            window("five_hour", 1.0, Some(NOW + 3600), Some(18_000)),
            window("seven_day", 0.4, Some(NOW + 500_000), Some(604_800)),
        ]
    );
    // Without subscription windows there is none to name.
    let f = classify_response(a.status, &[], &a.body, NOW);
    assert_eq!(f.windows, Vec::<WindowReport>::new());
}

#[test]
fn a_stream_rate_limit_on_an_exhausted_window_is_a_usage_limit() {
    let exhausted = [
        ("x-codex-primary-used-percent", "100.0"),
        ("x-codex-primary-window-minutes", "300"),
        ("x-codex-primary-reset-after-seconds", "600"),
    ];
    let f = classify_stream_error(
        "rate_limit_exceeded",
        "Rate limit reached",
        &rate_limits(&exhausted, NOW),
    );
    assert_eq!(
        f.kind,
        FailureKind::UsageLimit {
            resets_at: Some(NOW + 600)
        }
    );
    assert_eq!(
        f.windows,
        vec![window("five_hour", 1.0, Some(NOW + 600), Some(18_000))]
    );

    let open = [
        ("x-codex-primary-used-percent", "40.0"),
        ("x-codex-primary-window-minutes", "300"),
    ];
    let f = classify_stream_error(
        "rate_limit_exceeded",
        "Rate limit reached. Please try again in 2s.",
        &rate_limits(&open, NOW),
    );
    assert_eq!(
        f.kind,
        FailureKind::RateLimited {
            retry_after: Some(2)
        }
    );
}
