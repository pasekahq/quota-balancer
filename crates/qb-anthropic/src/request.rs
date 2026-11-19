//! Upstream direction, request side: a canonical [`TurnRequest`] becomes an Anthropic
//! [`CreateMessage`] body and a set of request headers for one of two [`AuthMode`]s.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use qb_proto::{Block, CacheMode, Effort, Elsewhere, MediaType, Role, TurnRequest};
use serde_json::Value;

use crate::wire::{
    CacheControl, Content, ContentBlock, CreateMessage, ImageSource, MessageParam, OutputConfig,
    System, TextBlock, TextKind, ThinkingConfig, ToolParam, ToolResultContent,
};

/// Every vendor-identity value the adapter sends, in one place.
pub mod identity {
    /// `anthropic-version` header.
    pub const ANTHROPIC_VERSION: &str = "2023-06-01";
    /// `anthropic-beta` values of the OAuth mode: OAuth access tokens, and the Claude Code
    /// client the subscription endpoint expects.
    pub const OAUTH_BETAS: &[&str] = &["oauth-2025-04-20", "claude-code-20250219"];
    /// `user-agent` of the OAuth mode: the vendor CLI's own.
    pub const OAUTH_USER_AGENT: &str = "claude-cli/2.1.319 (external, cli)";
    /// `x-app` of the OAuth mode.
    pub const OAUTH_X_APP: &str = "cli";
    /// Prefix of every client tool name on the wire of an OAuth request. The subscription
    /// endpoint bills a request whose tools carry bare names as a third-party app (extra usage,
    /// a 400 "You're out of extra usage" when that is off), and one whose tools carry this
    /// prefix, as Claude Code's MCP tools do, against the plan.
    pub const OAUTH_TOOL_PREFIX: &str = "mcp__";
    /// First system block of every OAuth request, ahead of the client's system prompt.
    pub const OAUTH_SYSTEM_PREFIX: &str =
        "You are Claude Code, Anthropic's official CLI for Claude.";
    /// `user-agent` of the API key mode.
    pub const API_KEY_USER_AGENT: &str = "qb-gateway";
    /// The vendor CLI's public OAuth client id, sent with every token refresh.
    pub const OAUTH_CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
    /// `user-agent` of token requests, the one the vendor CLI's HTTP client sends; the token
    /// endpoint throttles [`OAUTH_USER_AGENT`].
    pub const OAUTH_TOKEN_USER_AGENT: &str = "axios/1.7.9";
    /// OAuth token endpoints of the vendor, the primary first.
    pub const OAUTH_TOKEN_URLS: [&str; 2] = [
        "https://platform.claude.com/v1/oauth/token",
        "https://console.anthropic.com/v1/oauth/token",
    ];
    /// The vendor's OAuth authorize page of a sign-in.
    pub const OAUTH_AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
    /// Redirect URI of a sign-in: a vendor page that shows the code to paste as `code#state`.
    pub const OAUTH_REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";
    /// Scopes a sign-in asks for.
    pub const OAUTH_SCOPES: &str = "org:create_api_key user:profile user:inference";
}

/// How the gateway authenticates to the vendor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// An API key in `x-api-key`.
    ApiKey,
    /// A subscription OAuth access token as `Authorization: Bearer`, with the vendor CLI's
    /// identity: beta headers, user agent and system prompt prefix.
    Oauth,
}

impl AuthMode {
    /// The header that carries the secret and the prefix of its value; the caller appends the
    /// secret, so this crate never holds it.
    pub fn secret_header(self) -> (&'static str, &'static str) {
        match self {
            Self::ApiKey => ("x-api-key", ""),
            Self::Oauth => ("authorization", "Bearer "),
        }
    }

    /// Every request header except the secret one, lowercase names.
    pub fn headers(self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("anthropic-version", identity::ANTHROPIC_VERSION.to_owned()),
            ("content-type", "application/json".to_owned()),
            ("accept", "text/event-stream".to_owned()),
        ];
        match self {
            Self::ApiKey => out.push(("user-agent", identity::API_KEY_USER_AGENT.to_owned())),
            Self::Oauth => {
                out.push(("anthropic-beta", identity::OAUTH_BETAS.join(",")));
                out.push(("user-agent", identity::OAUTH_USER_AGENT.to_owned()));
                out.push(("x-app", identity::OAUTH_X_APP.to_owned()));
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
    /// Effort of the ladder candidate (`low` … `max`, `xhigh`); the request's effort wins.
    pub effort: Option<&'a str>,
    /// Authentication mode of the login.
    pub auth: AuthMode,
    /// Send `thinking: {type: adaptive}`; off for models that do not accept it.
    pub adaptive_thinking: bool,
}

/// Longest tool name the vendor takes.
const MAX_TOOL_NAME: usize = 64;

/// Wire names of the client tools of `req` under `auth`, client name to wire name: under
/// [`AuthMode::Oauth`] each name without [`identity::OAUTH_TOOL_PREFIX`] gets it, unless the
/// prefixed name is a client tool too or longer than the vendor's 64 characters; empty under [`AuthMode::ApiKey`]. The inverse map goes
/// to [`crate::stream::Reader::with_tool_names`] so the client sees its own names.
pub fn wire_tool_names(req: &TurnRequest, auth: AuthMode) -> HashMap<String, String> {
    if auth != AuthMode::Oauth {
        return HashMap::new();
    }
    let p = identity::OAUTH_TOOL_PREFIX;
    req.tools
        .iter()
        .filter(|t| !t.name.starts_with(p))
        .map(|t| (t.name.clone(), format!("{p}{}", t.name)))
        .filter(|(_, wire)| {
            wire.len() <= MAX_TOOL_NAME && !req.tools.iter().any(|t| &t.name == wire)
        })
        .collect()
}

/// Why a request cannot be sent; the core reports it as `bad_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// An image `path` the caller's loader could not turn into base64.
    Image(String),
    /// A tool of another vendor API that this vendor cannot offer and the client cannot do
    /// without.
    Tool(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Image(path) => write!(f, "image `{path}` cannot be read"),
            Self::Tool(name) => write!(
                f,
                "tool `{name}` is a tool of another vendor API that this vendor cannot run"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Effort values the vendor accepts in `output_config.effort`.
const EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];

/// The upstream body of `req` on `at`, always streaming. `load` turns an image `path` (already
/// checked against the gateway's media dirs) into standard base64.
///
/// Empty text blocks, thinking blocks of another vendor and own blocks whose payload is not an
/// Anthropic thinking block are dropped, and so is a message left without blocks. With `cache: auto`, breakpoints follow [`place_cache_breakpoints`].
/// The `thinking` config is left out when the last assistant message calls a tool and does not
/// start with a thinking block, a history the vendor refuses while thinking is on. System messages stay in
/// place where the vendor and the model take them and join the system prompt otherwise; tools
/// of another API follow their `elsewhere`.
///
/// # Errors
/// [`BuildError::Image`] when `load` fails, [`BuildError::Tool`] for a tool whose `elsewhere`
/// is `refuse`.
pub fn build(
    req: &TurnRequest,
    at: &Target<'_>,
    load: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<CreateMessage, BuildError> {
    let mut messages = Vec::with_capacity(req.messages.len());
    for m in &req.messages {
        let mut blocks = Vec::with_capacity(m.content.len());
        for b in &m.content {
            if let Some(block) = block(b, at.vendor, load)? {
                blocks.push(block);
            }
        }
        if blocks.is_empty() {
            continue;
        }
        let role = match m.role {
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::System => "system",
        };
        messages.push(MessageParam {
            role: role.into(),
            content: Content::Blocks(blocks),
            clear_at: None,
        });
    }
    let lifted = lift_misplaced_system(&mut messages, takes_system_messages(at.model));

    let mut system = Vec::new();
    if at.auth == AuthMode::Oauth {
        system.push(text_block(identity::OAUTH_SYSTEM_PREFIX));
    }
    if let Some(s) = req.system.as_deref().filter(|s| !s.is_empty()) {
        system.push(text_block(s));
    }
    system.extend(lifted.iter().map(|s| text_block(s)));

    let renamed = wire_tool_names(req, at.auth);
    if !renamed.is_empty() {
        for m in &mut messages {
            if let Content::Blocks(blocks) = &mut m.content {
                for b in blocks {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        if let Some(wire) = renamed.get(name.as_str()) {
                            name.clone_from(wire);
                        }
                    }
                }
            }
        }
    }
    let mut tools = Vec::with_capacity(req.tools.len());
    for t in &req.tools {
        match t.native.as_ref().map(|n| n.elsewhere) {
            None | Some(Elsewhere::Function) => {}
            Some(Elsewhere::Omit) => continue,
            Some(Elsewhere::Refuse) => return Err(BuildError::Tool(t.name.clone())),
        }
        tools.push(ToolParam {
            name: renamed.get(&t.name).unwrap_or(&t.name).clone(),
            description: Some(t.description.clone()),
            input_schema: t.input_schema.clone(),
            cache_control: None,
        });
    }

    let effort = req
        .effort
        .map(effort_name)
        .or(at.effort)
        .filter(|e| EFFORTS.contains(e));

    let thinking = at.adaptive_thinking && !tool_call_lacks_thinking(&messages);
    let mut body = CreateMessage {
        model: at.model.into(),
        max_tokens: req.max_tokens,
        system: (!system.is_empty()).then_some(System::Blocks(system)),
        messages,
        tools,
        stream: Some(true),
        thinking: thinking.then(|| ThinkingConfig {
            kind: "adaptive".into(),
            budget_tokens: None,
        }),
        output_config: effort.map(|e| OutputConfig {
            effort: Some(e.into()),
        }),
        cache_control: None,
        metadata: None,
    };
    if req.cache == Some(CacheMode::Auto) {
        place_cache_breakpoints(&mut body);
    }
    Ok(body)
}

/// Model id prefixes of the models that take mid-conversation system messages, from the vendor's
/// list; `claude-sonnet-5` itself does not, nor do older models. Any other model gets every
/// system message in the system prompt.
const SYSTEM_MESSAGE_MODELS: &[&str] = &[
    "claude-fable-5",
    "claude-mythos-5",
    "claude-opus-5",
    "claude-opus-4-8",
    "claude-sonnet-5-5",
    "claude-haiku-5-5",
];

/// Whether `model` takes mid-conversation system messages.
pub fn takes_system_messages(model: &str) -> bool {
    SYSTEM_MESSAGE_MODELS.iter().any(|p| model.starts_with(p))
}

/// Keeps each run of system messages where the vendor accepts one (when `in_place`), right after
/// a `user` message and followed by an `assistant` message or the end, and takes every other run
/// out, returning its text, in order, for the system prompt.
fn lift_misplaced_system(messages: &mut Vec<MessageParam>, in_place: bool) -> Vec<String> {
    let mut lifted = Vec::new();
    let mut out: Vec<MessageParam> = Vec::with_capacity(messages.len());
    let mut i = 0;
    let all = std::mem::take(messages);
    while i < all.len() {
        if all[i].role != "system" {
            out.push(all[i].clone());
            i += 1;
            continue;
        }
        let end = all[i..]
            .iter()
            .position(|m| m.role != "system")
            .map_or(all.len(), |p| i + p);
        let after_user = out.last().is_some_and(|m| m.role == "user");
        let before_assistant = all.get(end).is_none_or(|m| m.role == "assistant");
        if in_place && after_user && before_assistant {
            out.extend_from_slice(&all[i..end]);
        } else {
            for m in &all[i..end] {
                if let Content::Blocks(blocks) = &m.content {
                    let text: Vec<&str> = blocks
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .collect();
                    lifted.push(text.join("\n\n"));
                }
            }
        }
        i = end;
    }
    *messages = out;
    lifted
}

/// The last assistant message of `messages` calls a tool and does not start with a thinking
/// block, which the vendor requires of it while thinking is on.
fn tool_call_lacks_thinking(messages: &[MessageParam]) -> bool {
    let Some(last) = messages.iter().rev().find(|m| m.role == "assistant") else {
        return false;
    };
    let Content::Blocks(blocks) = &last.content else {
        return false;
    };
    let calls = blocks
        .iter()
        .any(|b| matches!(b, ContentBlock::ToolUse { .. }));
    let starts_thinking = matches!(
        blocks.first(),
        Some(ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. })
    );
    calls && !starts_thinking
}

fn text_block(text: &str) -> TextBlock {
    TextBlock {
        kind: TextKind::Text,
        text: text.into(),
        cache_control: None,
    }
}

/// The wire name of an effort.
pub fn effort_name(e: Effort) -> &'static str {
    match e {
        Effort::Low => "low",
        Effort::Medium => "medium",
        Effort::High => "high",
        Effort::Max => "max",
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

fn block(
    b: &Block,
    vendor: &str,
    load: &mut dyn FnMut(&str) -> Option<String>,
) -> Result<Option<ContentBlock>, BuildError> {
    Ok(Some(match b {
        Block::Text { text } if text.is_empty() => return Ok(None),
        Block::Text { text } => ContentBlock::Text {
            text: text.clone(),
            cache_control: None,
        },
        Block::Image {
            media_type,
            path,
            base64,
        } => {
            let data = match (base64, path) {
                (Some(b), _) => b.clone(),
                (None, Some(p)) => load(p).ok_or_else(|| BuildError::Image(p.clone()))?,
                (None, None) => return Err(BuildError::Image(String::new())),
            };
            ContentBlock::Image {
                source: ImageSource::Base64 {
                    media_type: media_type_name(*media_type).into(),
                    data,
                },
                cache_control: None,
            }
        }
        Block::ToolUse { id, name, input } => ContentBlock::ToolUse {
            id: tool_id(id).into_owned(),
            name: name.clone(),
            input: Value::Object(input.clone()),
            cache_control: None,
        },
        Block::ToolResult {
            id,
            content,
            is_error,
        } => ContentBlock::ToolResult {
            tool_use_id: tool_id(id).into_owned(),
            content: Some(ToolResultContent::Text(content.clone())),
            is_error: *is_error,
            cache_control: None,
        },
        Block::Thinking {
            vendor: from,
            opaque,
        } => {
            if from != vendor {
                return Ok(None);
            }
            match thinking_from_opaque(opaque) {
                Some(block) => block,
                None => return Ok(None),
            }
        }
    }))
}

/// Prefix of a tool id outside the vendor's pattern, rewritten by [`tool_id`].
pub const MAPPED_TOOL_ID_PREFIX: &str = "qbx_";

/// `id` as the vendor accepts it: unchanged when it matches `^[a-zA-Z0-9_-]+$`, else
/// [`MAPPED_TOOL_ID_PREFIX`] and the lowercase hex of its bytes. The map is deterministic, so a
/// `tool_use` and its `tool_result` still pair, and injective, so two ids never merge; ids of
/// another vendor (`functions.read:0` of some Chat Completions providers) then reach Anthropic
/// instead of a 400.
pub fn tool_id(id: &str) -> Cow<'_, str> {
    let fits = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    if !id.is_empty() && id.bytes().all(fits) {
        return Cow::Borrowed(id);
    }
    let mut out = String::with_capacity(MAPPED_TOOL_ID_PREFIX.len() + 2 * id.len());
    out.push_str(MAPPED_TOOL_ID_PREFIX);
    for b in id.bytes() {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    Cow::Owned(out)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The Anthropic thinking block an opaque payload of this adapter holds: the block's own JSON.
pub fn thinking_from_opaque(opaque: &str) -> Option<ContentBlock> {
    match serde_json::from_str(opaque).ok()? {
        b @ (ContentBlock::Thinking { .. } | ContentBlock::RedactedThinking { .. }) => Some(b),
        _ => None,
    }
}

/// The opaque payload of an Anthropic thinking or redacted thinking block.
pub fn thinking_to_opaque(block: &ContentBlock) -> String {
    serde_json::to_string(block).unwrap_or_default()
}

/// Places the `cache: auto` breakpoints, at most three of the vendor's four:
///
/// 1. the last system block, or the last tool when there is no system prompt: caches tools and
///    system, which every turn of a session repeats;
/// 2. the last block of the last message: the whole request, which the next turn extends;
/// 3. the last block of the previous `user` message: the prefix the next turn still shares when
///    the client rewrites the newest message.
///
/// A breakpoint goes on the last block of a message that can carry one; thinking blocks cannot.
pub fn place_cache_breakpoints(body: &mut CreateMessage) {
    let mut marked_prefix = false;
    if let Some(System::Blocks(blocks)) = &mut body.system {
        if let Some(last) = blocks.last_mut() {
            last.cache_control = Some(CacheControl::ephemeral());
            marked_prefix = true;
        }
    }
    if !marked_prefix {
        if let Some(last) = body.tools.last_mut() {
            last.cache_control = Some(CacheControl::ephemeral());
        }
    }
    let n = body.messages.len();
    if n == 0 {
        return;
    }
    mark_message(&mut body.messages[n - 1]);
    if let Some(prev) = body.messages[..n - 1]
        .iter_mut()
        .rev()
        .find(|m| m.role == "user")
    {
        mark_message(prev);
    }
}

fn mark_message(m: &mut MessageParam) {
    if let Content::Text(text) = &mut m.content {
        m.content = Content::Blocks(vec![ContentBlock::Text {
            text: std::mem::take(text),
            cache_control: None,
        }]);
    }
    let Content::Blocks(blocks) = &mut m.content else {
        return;
    };
    for b in blocks.iter_mut().rev() {
        let (ContentBlock::Text {
            cache_control: slot,
            ..
        }
        | ContentBlock::Image {
            cache_control: slot,
            ..
        }
        | ContentBlock::ToolUse {
            cache_control: slot,
            ..
        }
        | ContentBlock::ToolResult {
            cache_control: slot,
            ..
        }) = b
        else {
            continue;
        };
        *slot = Some(CacheControl::ephemeral());
        return;
    }
}
