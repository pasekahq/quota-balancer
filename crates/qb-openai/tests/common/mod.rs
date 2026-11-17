//! Fixture loading, a stream driver, canonical builders and a deterministic RNG shared by the
//! tests.

#![allow(dead_code, unreachable_pub, clippy::missing_panics_doc)]

use qb_openai::chat_upstream;
use qb_openai::limits::{Failure, RateLimits};
use qb_openai::stream::{Progress, Reader};
use qb_proto::{Object, RouteInfo, StopReason, StreamEvent, Thinking, ToolCall, Usage};
use serde_json::{Value, json};

/// The native OpenAI-family vendor of the tests.
pub const VENDOR: &str = "vendor-o";
/// Another vendor, Anthropic-shaped.
pub const OTHER: &str = "vendor-a";
pub const NOW: u64 = 1_800_000_000;

pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

pub fn object(v: Value) -> Object {
    match v {
        Value::Object(m) => m,
        other => panic!("not an object: {other}"),
    }
}

/// A vendor answer in the recorded shape: status, headers and body bytes.
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Answer {
    pub fn load(name: &str) -> Self {
        let v: Value = serde_json::from_slice(&fixture(name)).expect("answer fixture is JSON");
        let headers = v["headers"]
            .as_array()
            .expect("headers")
            .iter()
            .map(|p| {
                (
                    p[0].as_str().expect("name").to_owned(),
                    p[1].as_str().expect("value").to_owned(),
                )
            })
            .collect();
        let body = match &v["body"] {
            Value::Null => Vec::new(),
            Value::String(s) => s.clone().into_bytes(),
            other => other.to_string().into_bytes(),
        };
        Self {
            status: u16::try_from(v["status"].as_u64().expect("status")).expect("u16"),
            headers,
            body,
        }
    }

    pub fn pairs(&self) -> Vec<(&str, &str)> {
        self.headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect()
    }
}

/// Everything a reader made of a stream.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub events: Vec<StreamEvent>,
    pub end: Result<StopReason, Failure>,
}

/// A stream reader of either upstream API.
pub trait Feed {
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure>;
    fn finish(&self) -> Result<StopReason, Failure>;
}

impl Feed for Reader {
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        Reader::feed(self, chunk, out)
    }
    fn finish(&self) -> Result<StopReason, Failure> {
        Reader::finish(self)
    }
}

impl Feed for chat_upstream::Reader {
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<StreamEvent>) -> Result<Progress, Failure> {
        chat_upstream::Reader::feed(self, chunk, out)
    }
    fn finish(&self) -> Result<StopReason, Failure> {
        chat_upstream::Reader::finish(self)
    }
}

/// Feeds `bytes` to `reader` in the given chunk sizes (cycled) until it finishes or fails.
pub fn drive(reader: &mut impl Feed, bytes: &[u8], sizes: &[usize]) -> Run {
    let mut events = Vec::new();
    let mut rest = bytes;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes[i % sizes.len()].clamp(1, rest.len());
        i += 1;
        let (chunk, tail) = rest.split_at(n);
        rest = tail;
        match reader.feed(chunk, &mut events) {
            Ok(Progress::Continue) => {}
            Ok(Progress::Finished(stop)) => {
                return Run {
                    events,
                    end: Ok(stop),
                };
            }
            Err(f) => {
                return Run {
                    events,
                    end: Err(f),
                };
            }
        }
    }
    Run {
        end: reader.finish(),
        events,
    }
}

/// A Responses stream through [`Reader`].
pub fn run_chunked(bytes: &[u8], sizes: &[usize]) -> Run {
    drive(
        &mut Reader::new(VENDOR, RateLimits::default()),
        bytes,
        sizes,
    )
}

pub fn run(bytes: &[u8]) -> Run {
    run_chunked(bytes, &[bytes.len().max(1)])
}

/// A Chat Completions stream through [`chat_upstream::Reader`].
pub fn run_chat_chunked(bytes: &[u8], sizes: &[usize]) -> Run {
    drive(&mut chat_upstream::Reader::new(), bytes, sizes)
}

pub fn run_chat(bytes: &[u8]) -> Run {
    run_chat_chunked(bytes, &[bytes.len().max(1)])
}

/// Splits an SSE byte stream into `(event, data)` pairs; tests use it as an independent reader.
pub fn frames(bytes: &[u8]) -> Vec<(String, String)> {
    let text = std::str::from_utf8(bytes).expect("utf-8");
    text.split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .filter_map(|f| {
            let mut event = String::new();
            let mut data = String::new();
            for line in f.lines() {
                if let Some(v) = line.strip_prefix("event: ") {
                    v.clone_into(&mut event);
                } else if let Some(v) = line.strip_prefix("data: ") {
                    v.clone_into(&mut data);
                }
            }
            (!data.is_empty()).then_some((event, data))
        })
        .collect()
}

/// xorshift64*: deterministic, so a failing case reproduces from its seed.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }
}

/// An Anthropic-shaped turn as the core streams it: thinking with a signature, text, two tool
/// calls, usage and a stop.
pub fn anthropic_events() -> Vec<StreamEvent> {
    vec![
        StreamEvent::Route {
            route: RouteInfo {
                vendor: OTHER.into(),
                model: "model-a".into(),
                login_label: "login-1".into(),
                lease: "lease-1".into(),
            },
        },
        StreamEvent::Usage {
            usage: Usage {
                input: 25,
                output: 1,
                cache_read: 2000,
                cache_write: 100,
            },
        },
        StreamEvent::Thinking {
            thinking: Thinking {
                vendor: OTHER.into(),
                opaque:
                    r#"{"type":"thinking","thinking":"Check both.","signature":"c2lnLXRlc3Q="}"#
                        .into(),
            },
        },
        StreamEvent::TextDelta {
            text: "Reading ".into(),
        },
        StreamEvent::TextDelta {
            text: "both.".into(),
        },
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "toolu_01".into(),
                name: "read_file".into(),
                input: object(json!({"path": "notes.txt"})),
            },
        },
        StreamEvent::ToolCall {
            tool_call: ToolCall {
                id: "toolu_02".into(),
                name: "list_dir".into(),
                input: object(json!({"dir": "src"})),
            },
        },
        StreamEvent::Usage {
            usage: Usage {
                input: 25,
                output: 90,
                cache_read: 2000,
                cache_write: 100,
            },
        },
        StreamEvent::Stop {
            reason: StopReason::ToolUse,
        },
    ]
}

/// What an SDK makes of a Chat Completions stream: the message, the finish reason and usage.
#[derive(Debug, Default)]
pub struct Accumulated {
    pub role: String,
    pub content: String,
    pub calls: Vec<(String, String, String)>,
    pub finish: Option<String>,
    pub usage: Option<Value>,
    pub done: bool,
}

pub fn accumulate_chat(bytes: &[u8]) -> Accumulated {
    let mut acc = Accumulated::default();
    let mut ids = Vec::new();
    for (event, data) in frames(bytes) {
        assert!(event.is_empty(), "chat chunks are unnamed");
        assert!(!acc.done, "nothing after [DONE]");
        if data == "[DONE]" {
            acc.done = true;
            continue;
        }
        let c: Value = serde_json::from_str(&data).expect("chunk JSON");
        assert_eq!(c["object"], "chat.completion.chunk");
        ids.push((c["id"].clone(), c["created"].clone(), c["model"].clone()));
        if let Some(u) = c.get("usage") {
            assert_eq!(c["choices"], json!([]), "the usage chunk has no choices");
            acc.usage = Some(u.clone());
            continue;
        }
        let choice = &c["choices"][0];
        assert_eq!(choice["index"], 0);
        let d = &choice["delta"];
        if let Some(r) = d["role"].as_str() {
            acc.role = r.into();
        }
        if let Some(t) = d["content"].as_str() {
            acc.content.push_str(t);
        }
        for tc in d["tool_calls"].as_array().into_iter().flatten() {
            let i = usize::try_from(tc["index"].as_u64().expect("index")).expect("small");
            if i == acc.calls.len() {
                acc.calls.push(Default::default());
            }
            let slot = &mut acc.calls[i];
            if let Some(id) = tc["id"].as_str() {
                slot.0 = id.into();
            }
            if let Some(n) = tc["function"]["name"].as_str() {
                slot.1 = n.into();
            }
            if let Some(a) = tc["function"]["arguments"].as_str() {
                slot.2.push_str(a);
            }
        }
        if let Some(f) = choice["finish_reason"].as_str() {
            acc.finish = Some(f.into());
        }
    }
    assert!(
        ids.windows(2).all(|w| w[0] == w[1]),
        "stable id, created and model"
    );
    acc
}

/// Checks a Responses stream the way a strict client reads it and returns the final event's
/// type and response: event names match `type`, sequence numbers count from 0, the lifecycle
/// starts with `response.created` and `response.in_progress`, every item is added before its
/// events and done once, deltas add up to their done values, and the final response lists the
/// done items in order.
pub fn check_responses(bytes: &[u8]) -> (String, Value) {
    let frames = frames(bytes);
    let mut items: Vec<Value> = Vec::new();
    let mut done: Vec<Option<Value>> = Vec::new();
    let mut texts: Vec<String> = Vec::new();
    let mut last = None;
    for (n, (event, data)) in frames.iter().enumerate() {
        let v: Value = serde_json::from_str(data).expect("event JSON");
        let kind = v["type"].as_str().expect("type").to_owned();
        assert_eq!(&kind, event, "event name and type agree");
        assert_eq!(v["sequence_number"], json!(n), "sequence number of {kind}");
        assert!(last.is_none(), "{kind} after the final event");
        match (n, kind.as_str()) {
            (0, k) => assert_eq!(k, "response.created"),
            (1, k) => assert_eq!(k, "response.in_progress"),
            _ => {}
        }
        let index = v["output_index"]
            .as_u64()
            .map(|i| usize::try_from(i).expect("small"));
        match kind.as_str() {
            "response.output_item.added" => {
                let i = index.expect("index");
                assert_eq!(i, items.len(), "items are added in order");
                items.push(v["item"].clone());
                done.push(None);
                texts.push(String::new());
            }
            "response.output_item.done" => {
                let i = index.expect("index");
                assert!(done[i].is_none(), "done once");
                assert_eq!(v["item"]["id"], items[i]["id"]);
                assert_eq!(v["item"]["type"], items[i]["type"]);
                let item = &v["item"];
                match item["type"].as_str() {
                    Some("message") => {
                        assert_eq!(item["content"][0]["text"].as_str(), Some(texts[i].as_str()));
                    }
                    Some("function_call") => {
                        assert_eq!(item["arguments"].as_str(), Some(texts[i].as_str()));
                    }
                    _ => {}
                }
                done[i] = Some(item.clone());
            }
            "response.output_text.delta"
            | "response.function_call_arguments.delta"
            | "response.reasoning_summary_text.delta" => {
                let i = index.expect("index");
                assert!(done[i].is_none(), "delta after done");
                assert_eq!(v["item_id"], items[i]["id"]);
                if kind != "response.reasoning_summary_text.delta" {
                    texts[i].push_str(v["delta"].as_str().expect("delta"));
                }
            }
            "response.output_text.done" => {
                let i = index.expect("index");
                assert_eq!(v["text"].as_str(), Some(texts[i].as_str()));
            }
            "response.function_call_arguments.done" => {
                let i = index.expect("index");
                assert_eq!(v["arguments"].as_str(), Some(texts[i].as_str()));
            }
            "response.completed" | "response.incomplete" | "response.failed" => {
                assert!(done.iter().all(Option::is_some), "every item is done");
                let output: Vec<Value> = done.iter().flatten().cloned().collect();
                assert_eq!(v["response"]["output"], Value::Array(output));
                last = Some((kind.clone(), v["response"].clone()));
            }
            _ => {
                if let Some(i) = index {
                    assert!(
                        i < items.len() && done[i].is_none(),
                        "{kind} on an open item"
                    );
                    assert_eq!(v["item_id"], items[i]["id"]);
                }
            }
        }
    }
    last.expect("a final event")
}
