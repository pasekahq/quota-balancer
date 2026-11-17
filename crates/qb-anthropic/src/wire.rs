//! Anthropic Messages wire types, declared once and used in both directions: the gateway sends
//! [`CreateMessage`] upstream and reads [`Event`]s back, and the `/v1/messages` front reads a
//! client's [`CreateMessage`] and writes [`Event`]s or a [`MessageResponse`].
//!
//! Decoding is lenient: unknown fields are ignored and unknown block, delta and event types decode
//! to an `Other` variant, because vendors and SDKs add fields faster than this crate changes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use qb_proto::Object;

/// `POST /v1/messages` request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateMessage {
    /// Model id upstream; the route alias on the front.
    pub model: String,
    /// Upper bound of output tokens.
    pub max_tokens: u32,
    /// System prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<System>,
    /// Conversation, oldest first.
    pub messages: Vec<MessageParam>,
    /// Tools the model may call.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolParam>,
    /// Answer as server-sent events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Thinking configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
    /// Output configuration (`effort`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_config: Option<OutputConfig>,
    /// Request-level automatic cache breakpoint, as SDK clients may send it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
    /// Request metadata; `user_id` is the only field read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
}

/// System prompt: a string or text blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum System {
    /// Plain text.
    Text(String),
    /// Text blocks, concatenated by the model.
    Blocks(Vec<TextBlock>),
}

/// A text block of a system prompt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextBlock {
    /// Always `text`.
    #[serde(rename = "type")]
    pub kind: TextKind,
    /// The text.
    pub text: String,
    /// Cache breakpoint after this block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

/// The `type` of a [`TextBlock`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextKind {
    /// `text`.
    Text,
}

/// A prompt cache breakpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheControl {
    /// Always `ephemeral`.
    #[serde(rename = "type")]
    pub kind: String,
}

impl CacheControl {
    /// The default five-minute breakpoint.
    pub fn ephemeral() -> Self {
        Self {
            kind: "ephemeral".into(),
        }
    }
}

/// Request metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    /// Opaque end-user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

/// One conversation message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageParam {
    /// `user` or `assistant`.
    pub role: String,
    /// A string or blocks.
    pub content: Content,
}

/// Message content: a string or blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    /// One text block.
    Text(String),
    /// Blocks in order.
    Blocks(Vec<ContentBlock>),
}

/// A content block of a request message or a response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text.
    Text {
        /// The text.
        text: String,
        /// Cache breakpoint after this block.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// An image.
    Image {
        /// Where the bytes are.
        source: ImageSource,
        /// Cache breakpoint after this block.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// A tool call of the model.
    ToolUse {
        /// Tool-call id.
        id: String,
        /// Tool name.
        name: String,
        /// Arguments.
        input: Value,
        /// Cache breakpoint after this block.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// The output of a tool call.
    ToolResult {
        /// Id of the `tool_use` it answers.
        tool_use_id: String,
        /// Output: a string or blocks.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content: Option<ToolResultContent>,
        /// The tool failed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
        /// Cache breakpoint after this block.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// Thinking with the vendor's signature.
    Thinking {
        /// Thinking text; may be empty when the vendor omits it.
        thinking: String,
        /// Signature the vendor checks when the block is sent back.
        signature: String,
    },
    /// Encrypted thinking.
    RedactedThinking {
        /// Opaque payload.
        data: String,
    },
    /// Any block type this crate does not translate.
    #[serde(other)]
    Other,
}

/// Where an image's bytes are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    /// Inline base64.
    Base64 {
        /// Media type, e.g. `image/png`.
        media_type: String,
        /// Standard base64.
        data: String,
    },
    /// Any other source (URL, file id); not supported by the gateway.
    #[serde(other)]
    Other,
}

/// Tool output: a string or blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    /// Plain text.
    Text(String),
    /// Blocks.
    Blocks(Vec<ContentBlock>),
}

/// A tool definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolParam {
    /// Tool name.
    pub name: String,
    /// What the tool does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema of the arguments.
    pub input_schema: Object,
    /// Cache breakpoint after this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

/// Thinking configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinkingConfig {
    /// `adaptive`, `enabled`, `disabled` or another mode.
    #[serde(rename = "type")]
    pub kind: String,
    /// Token budget of the `enabled` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
}

/// Output configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Effort: `low`, `medium`, `high`, `xhigh` or `max`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
}

/// A non-streaming answer, and the `message` of `message_start`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageResponse {
    /// Message id.
    pub id: String,
    /// Always `message`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Always `assistant`.
    pub role: String,
    /// Model.
    pub model: String,
    /// Answer blocks.
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    /// Why the model stopped; `null` in `message_start`.
    pub stop_reason: Option<String>,
    /// Stop sequence that matched; always `null` from the gateway.
    #[serde(default)]
    pub stop_sequence: Option<String>,
    /// Token counts.
    #[serde(default)]
    pub usage: WireUsage,
}

/// Token counts as the vendor states them; absent counts read as zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireUsage {
    /// Input tokens not read from or written to the cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u64>,
    /// Input tokens written to the cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u64>,
    /// Input tokens read from the cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u64>,
    /// Output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u64>,
}

/// One server-sent event of a streaming answer, by its `type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// The answer starts; carries the input usage.
    MessageStart {
        /// The message so far, without content.
        message: MessageResponse,
    },
    /// A content block starts at `index`.
    ContentBlockStart {
        /// Block index.
        index: u32,
        /// The block's initial state.
        content_block: ContentBlock,
    },
    /// More of the block at `index`.
    ContentBlockDelta {
        /// Block index.
        index: u32,
        /// The increment.
        delta: Delta,
    },
    /// The block at `index` is complete.
    ContentBlockStop {
        /// Block index.
        index: u32,
    },
    /// Top-level changes: stop reason and cumulative usage.
    MessageDelta {
        /// Stop reason and sequence.
        delta: MessageDeltaBody,
        /// Cumulative counts.
        #[serde(default)]
        usage: WireUsage,
    },
    /// The answer is complete.
    MessageStop,
    /// Keep-alive.
    Ping,
    /// The vendor failed mid-stream.
    Error {
        /// What failed.
        error: ErrorDetail,
    },
    /// Any event type this crate does not translate.
    #[serde(other)]
    Other,
}

/// The increment of a `content_block_delta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    /// More text.
    TextDelta {
        /// The text.
        text: String,
    },
    /// More of a tool call's input JSON.
    InputJsonDelta {
        /// A fragment of the JSON text.
        partial_json: String,
    },
    /// More thinking text.
    ThinkingDelta {
        /// The text.
        thinking: String,
    },
    /// The thinking block's signature.
    SignatureDelta {
        /// The signature.
        signature: String,
    },
    /// Any delta type this crate does not translate.
    #[serde(other)]
    Other,
}

/// The `delta` of `message_delta`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageDeltaBody {
    /// Why the model stopped.
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Stop sequence that matched.
    #[serde(default)]
    pub stop_sequence: Option<String>,
}

/// An error: the body of a non-200 answer and the payload of an `error` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Always `error`.
    #[serde(rename = "type")]
    pub kind: String,
    /// What failed.
    pub error: ErrorDetail,
}

/// Type and message of an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// E.g. `rate_limit_error`, `overloaded_error`, `invalid_request_error`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Human-readable detail.
    #[serde(default)]
    pub message: String,
}

impl ErrorBody {
    /// An error body of `kind` with `message`.
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: "error".into(),
            error: ErrorDetail {
                kind: kind.into(),
                message: message.into(),
            },
        }
    }
}
