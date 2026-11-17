//! Upstream direction, request side: a canonical [`TurnRequest`] becomes a Responses
//! [`CreateResponse`] body and a set of request headers for one of two [`AuthMode`]s.
//!
//! The Responses API serves both an API key (`api_key`) and a ChatGPT subscription login
//! (`chatgpt_oauth`, the endpoint the Codex CLI uses); the body is the same apart from
//! `max_output_tokens`, which the subscription endpoint refuses.

use std::fmt;

use qb_proto::{Block, Effort, MediaType, Role, TurnRequest};
use serde_json::Value;

use crate::wire::{
    Content, CreateResponse, Item, Part, ReasoningConfig, ResponseTool, SummaryPart,
};

/// Every vendor-identity value the adapter sends, in one place.
pub mod identity {
    /// Responses endpoint of an API key.
    pub const API_KEY_URL: &str = "https://api.openai.com/v1/responses";
    /// Responses endpoint of a ChatGPT subscription login.
    pub const CHATGPT_URL: &str = "https://chatgpt.com/backend-api/codex/responses";
    /// `openai-beta` of the subscription mode.
    pub const OPENAI_BETA: &str = "responses=experimental";
    /// `originator` of the subscription mode: the Codex CLI's.
    pub const ORIGINATOR: &str = "codex_cli_rs";
    /// `user-agent` of the subscription mode: the Codex CLI's.
    pub const CHATGPT_USER_AGENT: &str = "codex_cli_rs/0.63.0";
    /// Header that names the ChatGPT account of the subscription mode.
    pub const ACCOUNT_HEADER: &str = "chatgpt-account-id";
    /// Header that carries the session of the subscription mode.
    pub const SESSION_HEADER: &str = "session_id";
    /// `user-agent` of the API key mode.
    pub const API_KEY_USER_AGENT: &str = "qb-gateway";
    /// `include` value that returns reasoning as encrypted content, which `store: false` needs to
    /// pass reasoning on to the next turn.
    pub const INCLUDE_REASONING: &str = "reasoning.encrypted_content";
}

/// How the gateway authenticates to the vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// An API key as `Authorization: Bearer`.
    ApiKey,
    /// A ChatGPT subscription OAuth access token as `Authorization: Bearer`, the account id in
    /// [`identity::ACCOUNT_HEADER`], and the Codex CLI's identity headers.
    ChatgptOauth,
}

impl AuthMode {
    /// The endpoint of this mode.
    pub fn url(self) -> &'static str {
        match self {
            Self::ApiKey => identity::API_KEY_URL,
            Self::ChatgptOauth => identity::CHATGPT_URL,
        }
    }

    /// The header that carries the secret and the prefix of its value; the caller appends the
    /// secret, so this crate never holds it.
    pub fn secret_header(self) -> (&'static str, &'static str) {
        ("authorization", "Bearer ")
    }

    /// The header that carries the account id, which the caller reads from the credential file;
    /// `None` when the mode has none.
    pub fn account_header(self) -> Option<&'static str> {
        match self {
            Self::ApiKey => None,
            Self::ChatgptOauth => Some(identity::ACCOUNT_HEADER),
        }
    }

    /// Every request header except the secret and the account id, lowercase names. The
    /// subscription mode sends `session` (the turn's `session_key`) as its session header when
    /// it is visible ASCII.
    pub fn headers(self, session: Option<&str>) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("content-type", "application/json".to_owned()),
            ("accept", "text/event-stream".to_owned()),
        ];
        match self {
            Self::ApiKey => out.push(("user-agent", identity::API_KEY_USER_AGENT.to_owned())),
            Self::ChatgptOauth => {
                out.push(("openai-beta", identity::OPENAI_BETA.to_owned()));
                out.push(("originator", identity::ORIGINATOR.to_owned()));
                out.push(("user-agent", identity::CHATGPT_USER_AGENT.to_owned()));
                if let Some(s) =
                    session.filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()))
                {
                    out.push((identity::SESSION_HEADER, s.to_owned()));
                }
            }
        }
        out
    }
}

/// What the core knows about an attempt beyond the request.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    /// Vendor name of the picked route; `thinking` blocks of other vendors are dropped.
    pub vendor: &'a str,
    /// Model id to request.
    pub model: &'a str,
    /// Effort of the ladder candidate (`none` … `xhigh`, or `max`); the request's effort wins.
    pub effort: Option<&'a str>,
    /// Authentication mode of the login.
    pub auth: AuthMode,
    /// The model reasons: send `reasoning` and ask for its encrypted content; off for models
    /// that refuse the parameter.
    pub reasoning: bool,
}

/// Why a request cannot be sent; the core reports it as `bad_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// An image given by `path`: the gateway reads no file a client names.
    ImagePath(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImagePath(path) => write!(f, "image `{path}` is a path; send it as base64"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Effort values the vendor accepts in `reasoning.effort`.
const EFFORTS: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh"];

/// The vendor effort of a canonical effort; `max` is the vendor's highest, `xhigh`.
pub fn effort_name(e: Effort) -> &'static str {
    match e {
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Max => "xhigh",
    }
}

/// The wire name of a media type.
pub fn media_type_name(m: MediaType) -> &'static str {
    match m {
        MediaType::Png => "image/png",
        MediaType::Jpeg => "image/jpeg",
        MediaType::Gif => "image/gif",
        MediaType::Webp => "image/webp",
    }
}

/// A `data:` URL of base64 image bytes.
pub fn data_url(media_type: MediaType, base64: &str) -> String {
    format!("data:{};base64,{base64}", media_type_name(media_type))
}

/// The upstream body of `req` on `at`, always streaming and never stored.
///
/// User text and images become `message` items, assistant text an assistant `message` item,
/// tool uses `function_call` items and tool results `function_call_output` items, in order.
/// Empty text, thinking of another vendor and own thinking whose payload is not a reasoning item
/// are dropped. Item ids are never sent: with `store: false` the vendor keeps none.
///
/// # Errors
/// [`BuildError::ImagePath`] for an image given by path.
pub fn build(req: &TurnRequest, at: &Target<'_>) -> Result<CreateResponse, BuildError> {
    let input = input_items(req, at.vendor)?;
    let effort = req
        .effort
        .map(effort_name)
        .or_else(|| at.effort.map(|e| if e == "max" { "xhigh" } else { e }))
        .filter(|e| EFFORTS.contains(e));
    let tools: Vec<ResponseTool> = req
        .tools
        .iter()
        .map(|t| ResponseTool {
            kind: "function".into(),
            name: Some(t.name.clone()),
            description: Some(t.description.clone()),
            parameters: Some(t.input_schema.clone()),
            strict: Some(false),
        })
        .collect();
    let has_tools = !tools.is_empty();
    Ok(CreateResponse {
        model: at.model.into(),
        instructions: match at.auth {
            AuthMode::ChatgptOauth => Some(req.system.clone().unwrap_or_default()),
            AuthMode::ApiKey => req.system.clone().filter(|s| !s.is_empty()),
        },
        input: Some(crate::wire::Input::Items(input)),
        tools: has_tools.then_some(tools),
        tool_choice: has_tools.then(|| Value::String("auto".into())),
        parallel_tool_calls: has_tools.then_some(true),
        max_output_tokens: match at.auth {
            AuthMode::ApiKey => Some(req.max_tokens),
            AuthMode::ChatgptOauth => None,
        },
        reasoning: at.reasoning.then(|| ReasoningConfig {
            effort: effort.map(str::to_owned),
            summary: Some("auto".into()),
        }),
        include: at
            .reasoning
            .then(|| vec![identity::INCLUDE_REASONING.to_owned()]),
        store: Some(false),
        stream: Some(true),
        prompt_cache_key: req.session_key.clone(),
        ..CreateResponse::default()
    })
}

/// The input items of the conversation, in order.
fn input_items(req: &TurnRequest, vendor: &str) -> Result<Vec<Item>, BuildError> {
    let mut input: Vec<Item> = Vec::with_capacity(req.messages.len());
    for m in &req.messages {
        let role = match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
        };
        let mut parts: Vec<Part> = Vec::new();
        for b in &m.content {
            match b {
                Block::Text { text } if text.is_empty() => {}
                Block::Text { text } => parts.push(match m.role {
                    Role::User => text_part("input_text", text),
                    Role::Assistant => output_text(text),
                }),
                Block::Image {
                    media_type,
                    path,
                    base64,
                } => match (base64, path) {
                    (Some(b), _) => parts.push(Part {
                        kind: "input_image".into(),
                        image_url: Some(data_url(*media_type, b)),
                        detail: Some("auto".into()),
                        ..Part::default()
                    }),
                    (None, p) => return Err(BuildError::ImagePath(p.clone().unwrap_or_default())),
                },
                Block::ToolUse {
                    id,
                    name,
                    input: args,
                } => {
                    flush(&mut input, role, &mut parts);
                    input.push(Item {
                        kind: Some("function_call".into()),
                        call_id: Some(id.clone()),
                        name: Some(name.clone()),
                        arguments: Some(Value::Object(args.clone()).to_string()),
                        ..Item::default()
                    });
                }
                Block::ToolResult { id, content, .. } => {
                    flush(&mut input, role, &mut parts);
                    input.push(Item {
                        kind: Some("function_call_output".into()),
                        call_id: Some(id.clone()),
                        output: Some(Content::Text(content.clone())),
                        ..Item::default()
                    });
                }
                Block::Thinking {
                    vendor: from,
                    opaque,
                } => {
                    if from != vendor {
                        continue;
                    }
                    if let Some(item) = reasoning_from_opaque(opaque) {
                        flush(&mut input, role, &mut parts);
                        input.push(item);
                    }
                }
            }
        }
        flush(&mut input, role, &mut parts);
    }

    Ok(input)
}

fn text_part(kind: &str, text: &str) -> Part {
    Part {
        kind: kind.into(),
        text: Some(text.into()),
        ..Part::default()
    }
}

/// An `output_text` part with no annotations.
pub(crate) fn output_text(text: &str) -> Part {
    Part {
        annotations: Some(Vec::new()),
        ..text_part("output_text", text)
    }
}

fn flush(input: &mut Vec<Item>, role: &str, parts: &mut Vec<Part>) {
    if parts.is_empty() {
        return;
    }
    input.push(Item {
        kind: Some("message".into()),
        role: Some(role.into()),
        content: Some(Content::Parts(std::mem::take(parts))),
        ..Item::default()
    });
}

/// The reasoning item an opaque payload of this adapter holds: `type`, `summary` and
/// `encrypted_content`, without id or status. `None` for any other payload.
pub fn reasoning_from_opaque(opaque: &str) -> Option<Item> {
    let item: Item = serde_json::from_str(opaque).ok()?;
    normal_reasoning(&item)
}

/// A reasoning item reduced to what the vendor needs back: `type`, `summary` and
/// `encrypted_content`. `None` when it is not a reasoning item or has no encrypted content.
pub fn normal_reasoning(item: &Item) -> Option<Item> {
    if item.kind.as_deref() != Some("reasoning") {
        return None;
    }
    let encrypted = item.encrypted_content.clone().filter(|e| !e.is_empty())?;
    Some(Item {
        kind: Some("reasoning".into()),
        summary: Some(
            item.summary
                .iter()
                .flatten()
                .map(|s| SummaryPart {
                    kind: "summary_text".into(),
                    text: s.text.clone(),
                })
                .collect(),
        ),
        encrypted_content: Some(encrypted),
        ..Item::default()
    })
}

/// The opaque payload of a reasoning item: its normal form as JSON; `None` when the item has no
/// encrypted content and so cannot be passed back.
pub fn reasoning_to_opaque(item: &Item) -> Option<String> {
    serde_json::to_string(&normal_reasoning(item)?).ok()
}
