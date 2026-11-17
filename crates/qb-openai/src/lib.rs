//! Pure translation between the gateway's canonical C4 turns (`qb_proto::gateway`) and the
//! OpenAI Chat Completions and Responses APIs, in both directions.
//!
//! Upstream through the Responses API (an OpenAI API key or a ChatGPT subscription login):
//! [`request::build`] and [`request::AuthMode`] make the body and headers, [`stream::Reader`]
//! turns the SSE answer into canonical events, and [`limits`] reads rate-limit headers and
//! classifies failures. Upstream through the Chat Completions API (OpenRouter and other
//! OpenAI-compatible API keys): [`chat_upstream`] makes the body and headers and reads the SSE
//! answer, and [`limits::classify_chat_response`] classifies failures. Client side: [`chat`] is the
//! `/v1/chat/completions` front and [`responses`] the `/v1/responses` front; each decodes a
//! request into a canonical turn and encodes canonical events as SSE or one response body;
//! [`front`] holds what they share, such as the error answer.
//!
//! The canonical turn is the pivot: any front can run on any vendor's adapter.
//!
//! No I/O, no clock, no secrets: callers pass `now` and the credential header values. Mapping
//! rules are in `docs/openai.md`.

#![forbid(unsafe_code)]

pub mod chat;
pub mod chat_upstream;
pub mod front;
pub mod limits;
pub mod request;
pub mod responses;
pub mod sse;
pub mod stream;
pub mod wire;
