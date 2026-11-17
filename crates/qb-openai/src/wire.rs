//! OpenAI wire types, declared once and used in both directions: the gateway sends
//! [`CreateResponse`] upstream and reads [`ResponseEvent`]s back; the `/v1/responses` front reads
//! a client's [`CreateResponse`] and writes [`ResponseEvent`]s or a [`ResponseObject`]; the
//! `/v1/chat/completions` front reads a [`ChatRequest`] and writes [`ChatChunk`]s or a
//! [`ChatResponse`].
//!
//! Items, parts and events are flat structs with a `type` string and optional fields rather than
//! tagged enums: decoding stays lenient (unknown fields and types pass through), and the code stays
//! small. Absent optional fields are not serialised, except where OpenAI always writes `null`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use qb_proto::Object;

/// An OpenAI error answer: `{"error": {"message", "type", "param", "code"}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error.
    pub error: ErrorDetail,
}

/// The `error` object of an [`ErrorBody`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ErrorDetail {
    /// Human-readable message.
    #[serde(default)]
    pub message: String,
    /// Error type, e.g. `invalid_request_error`.
    #[serde(rename = "type", default)]
    pub kind: String,
    /// The request parameter at fault, if any.
    #[serde(default)]
    pub param: Option<String>,
    /// Machine-readable code, e.g. `context_length_exceeded`.
    #[serde(default)]
    pub code: Option<String>,
}

impl ErrorBody {
    /// An error body of `kind` with `message`, `code` and no `param`.
    pub fn new(kind: &str, code: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                message: message.into(),
                kind: kind.to_owned(),
                param: None,
                code: code.map(str::to_owned),
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Chat Completions
// ---------------------------------------------------------------------------------------------

/// `POST /v1/chat/completions` request body. Fields the gateway rejects when set are declared so
/// that the front can name them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Model; the route alias on the front.
    pub model: String,
    /// Conversation, oldest first.
    pub messages: Vec<ChatMessage>,
    /// Tools the model may call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ChatTool>>,
    /// `auto`, `none`, `required` or a named function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    /// Legacy bound of output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Bound of output tokens, reasoning included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_completion_tokens: Option<u32>,
    /// `none`, `minimal`, `low`, `medium`, `high` or `xhigh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// Answer as server-sent events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Stream options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>,
    /// End-user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Prompt cache key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_key: Option<String>,
    /// Number of choices; only 1 is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// Token log probabilities; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<bool>,
    /// Token log probabilities; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_logprobs: Option<u32>,
    /// Audio output; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<Value>,
    /// Output modalities; only `text` is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modalities: Option<Vec<String>>,
    /// Structured output; only `{"type": "text"}` is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_format: Option<Value>,
}

/// `stream_options` of a [`ChatRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StreamOptions {
    /// Send a final chunk with usage and no choices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_usage: Option<bool>,
}

/// One chat message, in a request or as a response's `choices[].message`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatMessage {
    /// `system`, `developer`, `user`, `assistant` or `tool`.
    pub role: String,
    /// A string or parts; `null` for an assistant message with tool calls only.
    #[serde(default)]
    pub content: Option<ChatContent>,
    /// Participant name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Tool calls of an assistant message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ChatToolCall>>,
    /// The call a `tool` message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// A refusal of the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

/// Chat message content: a string or parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChatContent {
    /// Plain text.
    Text(String),
    /// Parts in order.
    Parts(Vec<ChatPart>),
}

/// One content part: `text`, `image_url`, `refusal`, or another type the front rejects.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatPart {
    /// Part type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Text of a `text` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Image of an `image_url` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_url: Option<ImageUrl>,
    /// Text of a `refusal` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

/// The image of an `image_url` part.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImageUrl {
    /// A `data:` URL or an `https:` URL.
    pub url: String,
    /// `auto`, `low` or `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A tool call of an assistant message.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChatToolCall {
    /// Tool-call id.
    pub id: String,
    /// Always `function`.
    #[serde(rename = "type", default = "function_kind")]
    pub kind: String,
    /// Function and arguments.
    pub function: FunctionCall,
}

fn function_kind() -> String {
    "function".into()
}

/// The function of a [`ChatToolCall`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Function name.
    pub name: String,
    /// Arguments as a JSON string.
    #[serde(default)]
    pub arguments: String,
}

/// A tool of a [`ChatRequest`]: `{"type": "function", "function": {...}}`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatTool {
    /// `function`, or another type the front rejects.
    #[serde(rename = "type")]
    pub kind: String,
    /// The function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionDef>,
}

/// A function the model may call.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct FunctionDef {
    /// Function name.
    pub name: String,
    /// What it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema of the arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Object>,
    /// Strict schema adherence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// A non-streaming Chat Completions response.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatResponse {
    /// `chatcmpl-…`.
    pub id: String,
    /// `chat.completion`.
    pub object: String,
    /// Unix seconds.
    pub created: u64,
    /// Model as the client named it.
    pub model: String,
    /// Exactly one choice.
    pub choices: Vec<Choice>,
    /// Token counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<ChatUsage>,
}

/// One choice of a [`ChatResponse`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Choice {
    /// Always 0.
    pub index: u32,
    /// The assistant message.
    pub message: ChatMessage,
    /// `stop`, `length`, `tool_calls` or `content_filter`.
    #[serde(default)]
    pub finish_reason: Option<String>,
    /// Always `null`.
    #[serde(default)]
    pub logprobs: Option<Value>,
}

/// Token counts of a Chat Completions answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChatUsage {
    /// Input tokens, cached ones included.
    #[serde(default)]
    pub prompt_tokens: u64,
    /// Output tokens, reasoning included.
    #[serde(default)]
    pub completion_tokens: u64,
    /// The sum.
    #[serde(default)]
    pub total_tokens: u64,
    /// Cached input tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens_details: Option<PromptTokensDetails>,
    /// Reasoning tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens_details: Option<CompletionTokensDetails>,
}

/// `prompt_tokens_details` and `input_tokens_details`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PromptTokensDetails {
    /// Input tokens read from the prompt cache.
    #[serde(default)]
    pub cached_tokens: u64,
}

/// `completion_tokens_details` and `output_tokens_details`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CompletionTokensDetails {
    /// Output tokens spent on reasoning.
    #[serde(default)]
    pub reasoning_tokens: u64,
}

/// One `chat.completion.chunk` of a Chat Completions stream.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChatChunk {
    /// Same in every chunk of a stream.
    pub id: String,
    /// `chat.completion.chunk`.
    pub object: String,
    /// Same in every chunk of a stream.
    pub created: u64,
    /// Same in every chunk of a stream.
    pub model: String,
    /// One choice, or none in the final usage chunk.
    pub choices: Vec<ChunkChoice>,
    /// Token counts, in the final usage chunk only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<ChatUsage>,
}

/// The choice of a [`ChatChunk`].
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ChunkChoice {
    /// Always 0.
    pub index: u32,
    /// What this chunk adds.
    pub delta: ChunkDelta,
    /// Set in the last chunk with choices.
    #[serde(default)]
    pub finish_reason: Option<String>,
}

/// The `delta` of a [`ChunkChoice`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChunkDelta {
    /// `assistant`, in the first chunk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Next piece of the text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Tool-call pieces, by `index`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ChunkToolCall>>,
}

/// A piece of a tool call in a [`ChunkDelta`]; `id`, `type` and `name` come with the first piece
/// of each `index`, `arguments` may be split over many.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChunkToolCall {
    /// Position of the call in the message.
    pub index: u32,
    /// Tool-call id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `function`.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Name and argument piece.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<ChunkFunction>,
}

/// The function piece of a [`ChunkToolCall`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ChunkFunction {
    /// Function name, in the first piece.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Next piece of the arguments string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------------------------

/// `POST /v1/responses` request body. Fields the gateway rejects when set are declared so that
/// the front can name them.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CreateResponse {
    /// Model id upstream; the route alias on the front.
    pub model: String,
    /// System prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    /// A string or items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
    /// Tools the model may call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<ResponseTool>>,
    /// `auto`, `none`, `required` or a named function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    /// Allow several tool calls in one answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Bound of output tokens, reasoning included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    /// Reasoning effort and summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<ReasoningConfig>,
    /// Extra output, e.g. `reasoning.encrypted_content`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    /// Keep the response on the vendor side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    /// Answer as server-sent events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Prompt cache key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_key: Option<String>,
    /// End-user id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// A stored earlier response; not supported, the gateway is stateless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// A stored conversation; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Value>,
    /// Background mode; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    /// Text output format; only `{"format": {"type": "text"}}` is supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<Value>,
}

/// `reasoning` of a [`CreateResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReasoningConfig {
    /// `none`, `minimal`, `low`, `medium`, `high` or `xhigh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// `auto`, `concise` or `detailed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// Responses input: a string or items.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Input {
    /// One user message.
    Text(String),
    /// Items in order.
    Items(Vec<Item>),
}

/// One input or output item: `message`, `function_call`, `function_call_output`, `reasoning`,
/// or another type. An input item without `type` is a message.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Item {
    /// Item type.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Item id (`msg_…`, `fc_…`, `rs_…`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `in_progress`, `completed` or `incomplete`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Role of a message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Content of a message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Content>,
    /// Tool-call id of a `function_call` or `function_call_output`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// Function name of a `function_call`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Arguments of a `function_call`, as a JSON string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// Output of a `function_call_output`: a string or parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Content>,
    /// Summary parts of a `reasoning` item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<Vec<SummaryPart>>,
    /// Vendor-encrypted reasoning of a `reasoning` item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<String>,
}

/// Message content or tool output: a string or parts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    /// Plain text.
    Text(String),
    /// Parts in order.
    Parts(Vec<Part>),
}

/// One content part: `input_text`, `input_image`, `output_text`, `refusal`, or another type.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Part {
    /// Part type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Text of a text part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Annotations of an `output_text` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Vec<Value>>,
    /// Image of an `input_image` part, as a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    /// Detail of an `input_image` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A stored file; not supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    /// Text of a `refusal` part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

/// One part of a reasoning summary.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SummaryPart {
    /// `summary_text`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The text.
    #[serde(default)]
    pub text: String,
}

/// A tool of a [`CreateResponse`]: `{"type": "function", "name", "description", "parameters"}`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ResponseTool {
    /// `function`, or another type the front rejects.
    #[serde(rename = "type")]
    pub kind: String,
    /// Function name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema of the arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Object>,
    /// Strict schema adherence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// A response object: the non-streaming answer, and the `response` of lifecycle events.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseObject {
    /// `resp_…`.
    pub id: String,
    /// `response`.
    pub object: String,
    /// Unix seconds.
    pub created_at: u64,
    /// `in_progress`, `completed`, `incomplete` or `failed`.
    pub status: String,
    /// Model as the client named it.
    pub model: String,
    /// Output items in order.
    pub output: Vec<Item>,
    /// Token counts, once the response ended.
    pub usage: Option<ResponsesUsage>,
    /// Why the response is `incomplete`.
    pub incomplete_details: Option<IncompleteDetails>,
    /// Why the response `failed`.
    pub error: Option<ResponseError>,
}

/// `incomplete_details` of a [`ResponseObject`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IncompleteDetails {
    /// `max_output_tokens` or `content_filter`.
    #[serde(default)]
    pub reason: String,
}

/// `error` of a failed [`ResponseObject`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResponseError {
    /// Machine-readable code.
    #[serde(default)]
    pub code: Option<String>,
    /// Human-readable message.
    #[serde(default)]
    pub message: Option<String>,
}

/// Token counts of a Responses answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResponsesUsage {
    /// Input tokens, cached ones included.
    #[serde(default)]
    pub input_tokens: u64,
    /// Cached input tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_tokens_details: Option<PromptTokensDetails>,
    /// Output tokens, reasoning included.
    #[serde(default)]
    pub output_tokens: u64,
    /// Reasoning tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_tokens_details: Option<CompletionTokensDetails>,
    /// The sum.
    #[serde(default)]
    pub total_tokens: u64,
}

/// Names of the Responses stream events this crate reads or writes.
pub mod event {
    /// The response was created.
    pub const CREATED: &str = "response.created";
    /// The response is running.
    pub const IN_PROGRESS: &str = "response.in_progress";
    /// An output item starts.
    pub const OUTPUT_ITEM_ADDED: &str = "response.output_item.added";
    /// An output item is complete.
    pub const OUTPUT_ITEM_DONE: &str = "response.output_item.done";
    /// A content part of a message starts.
    pub const CONTENT_PART_ADDED: &str = "response.content_part.added";
    /// A content part of a message is complete.
    pub const CONTENT_PART_DONE: &str = "response.content_part.done";
    /// Next piece of an `output_text` part.
    pub const OUTPUT_TEXT_DELTA: &str = "response.output_text.delta";
    /// An `output_text` part is complete.
    pub const OUTPUT_TEXT_DONE: &str = "response.output_text.done";
    /// Next piece of a `refusal` part.
    pub const REFUSAL_DELTA: &str = "response.refusal.delta";
    /// Next piece of a function call's arguments.
    pub const FUNCTION_CALL_ARGUMENTS_DELTA: &str = "response.function_call_arguments.delta";
    /// A function call's arguments are complete.
    pub const FUNCTION_CALL_ARGUMENTS_DONE: &str = "response.function_call_arguments.done";
    /// A reasoning summary part starts.
    pub const REASONING_SUMMARY_PART_ADDED: &str = "response.reasoning_summary_part.added";
    /// A reasoning summary part is complete.
    pub const REASONING_SUMMARY_PART_DONE: &str = "response.reasoning_summary_part.done";
    /// Next piece of a reasoning summary.
    pub const REASONING_SUMMARY_TEXT_DELTA: &str = "response.reasoning_summary_text.delta";
    /// A reasoning summary text is complete.
    pub const REASONING_SUMMARY_TEXT_DONE: &str = "response.reasoning_summary_text.done";
    /// The response finished.
    pub const COMPLETED: &str = "response.completed";
    /// The response ended early (`max_output_tokens`, `content_filter`).
    pub const INCOMPLETE: &str = "response.incomplete";
    /// The response failed.
    pub const FAILED: &str = "response.failed";
    /// A stream error.
    pub const ERROR: &str = "error";
}

/// One Responses stream event. Which fields are set depends on `type` (see [`event`]).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ResponseEvent {
    /// Event type, e.g. `response.output_text.delta`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Position of the event in the stream, from 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u64>,
    /// The response, in lifecycle events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Box<ResponseObject>>,
    /// Position of the item in `output`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
    /// Id of the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    /// Position of the part in the item's `content`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_index: Option<u32>,
    /// Position of the part in the item's `summary`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary_index: Option<u32>,
    /// The item, in `output_item.*` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<Item>,
    /// The part, in `content_part.*` and `reasoning_summary_part.*` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<Part>,
    /// The next piece, in `*.delta` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    /// The whole text, in `*_text.done` events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// The whole arguments, in `function_call_arguments.done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// Log probabilities of text events; always empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logprobs: Option<Vec<Value>>,
    /// Error code, in `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Error message, in `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Request parameter at fault, in `error`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
}

impl ResponseEvent {
    /// An event of `kind` with every other field empty.
    pub fn of(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            ..Self::default()
        }
    }
}
