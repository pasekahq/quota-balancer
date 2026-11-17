//! Pure translation between the gateway's canonical C4 turns (`qb_proto::gateway`) and the
//! Anthropic Messages API, in both directions.
//!
//! Upstream (the gateway calls the vendor): [`request::build`] and [`request::AuthMode`] make the
//! body and headers, [`stream::Reader`] turns the SSE answer into canonical events, and
//! [`limits`] reads rate-limit headers and classifies failures. Client side (the `/v1/messages`
//! front): [`front`] decodes a Messages request and encodes canonical events as Messages SSE,
//! a response body or an error answer.
//!
//! No I/O, no clock, no secrets: callers pass `now`, image bytes and the credential header value.
//! Mapping rules are in `docs/anthropic.md`.

#![forbid(unsafe_code)]

pub mod front;
pub mod limits;
pub mod request;
pub mod sse;
pub mod stream;
pub mod wire;
