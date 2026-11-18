# Anthropic Messages translation

`crates/qb-anthropic` translates between the gateway's canonical C4 turns (`qb_proto::gateway`,
see [api.md](api.md)) and the Anthropic Messages API, in both directions:

- **upstream**: the gateway calls the vendor. A `TurnRequest` becomes a Messages request body and
  header set; the SSE answer becomes canonical content events; rate-limit headers and errors
  become quota windows and a vendor-neutral failure for `qbd`'s report;
- **client side**: the gateway's `/v1/messages` front. A Messages request from an Anthropic SDK
  client becomes a `TurnRequest`; canonical events become Messages SSE, a response body or an
  error answer.

The crate is pure: no I/O, no clock, no secrets. The caller passes `now`, loads image files, and
builds the credential header value itself. Every parser is total: any bytes give a value or a
typed error, never a panic.

## Upstream request

`request::build(req, target, load)` returns the body; `AuthMode::headers()` returns every header
except the secret one, and `AuthMode::secret_header()` names that header and the prefix of its
value.

| Canonical | Messages |
|---|---|
| `system` | a text block in `system` (absent when empty) |
| `messages[].role` | `user`, `assistant`, `system` (below) |
| `text` | `text`; an empty text block is dropped |
| `image` (`base64`) | `image` with a `base64` source |
| `image` (`path`) | the same, with the bytes from the caller's loader; a load failure is a `BuildError` |
| `tool_use{id,name,input}` | `tool_use` with the same id (below) |
| `tool_result{id,content,is_error}` | `tool_result{tool_use_id,content,is_error}` (below) |
| `thinking{vendor,opaque}` of the picked vendor | the block whose JSON `opaque` holds (`thinking` with `signature`, or `redacted_thinking`) |
| `thinking` of another vendor, or an `opaque` that is not such a block | dropped |
| `tools[]` | `tools[]{name,description,input_schema}`; a tool with `native` follows its `elsewhere`: `function` goes out like any tool, `omit` is left out, `refuse` is a `BuildError` |
| `max_tokens` | `max_tokens` |
| `effort`, else the ladder candidate's effort | `output_config.effort`; a value other than `low`, `medium`, `high`, `xhigh`, `max` is dropped |
| — | `stream: true`; `thinking: {type: adaptive}` unless the target turns it off or the history lost its thinking (below) |

A message left without blocks is dropped. The model id comes from `qbd`'s pick.

The vendor accepts a tool id only when it matches `^[a-zA-Z0-9_-]+$`. Such an id goes out
unchanged; any other (some Chat Completions providers issue `functions.read:0`, and a chain turn
may bring it back to Anthropic) goes out as `qbx_` and the lowercase hex of its bytes, in both
`tool_use` and `tool_result`, so the pair still matches and two ids never merge. The vendor answers
with ids of its own, so the client never sees the rewritten form.

A canonical `system` message is the vendor's mid-conversation system message
(`{role: system, content: [text blocks]}`, stable in the Messages API, no beta header). The vendor
accepts a run of them only right after a `user` message and followed by an `assistant` message
or the end of `messages`, and only on the models it lists (ids starting with `claude-fable-5`,
`claude-mythos-5`, `claude-opus-5`, `claude-opus-4-8`, `claude-sonnet-5-5`, `claude-haiku-5-5`;
not `claude-sonnet-5` or older models). Such a run stays in place, so the cached prefix before
it holds. On any other model every run, and on a listed model any other run (first in the conversation, after an assistant message, before another user message)
leaves `messages` and its text joins the system prompt as further text blocks, after the
client's `system`, which is what a client that knows no mid-conversation messages does with it.

With thinking on, the vendor refuses (400 `invalid_request_error`) a request whose last assistant
message calls a tool and does not start with a thinking block; earlier assistant messages may lack
thinking. Clients that strip thinking from their history send exactly that in every tool loop, so
when the last assistant message of the built request holds a `tool_use` and its first block is not
`thinking` or `redacted_thinking` (none of the picked vendor survived the table above, or the
history put text before it), the request goes without `thinking`. The model then answers that turn without thinking.

### Prompt cache (`cache: auto`)

With `cache: auto` the adapter places at most three of the vendor's four breakpoints
(`cache_control: {type: ephemeral}`):

1. on the last system block, or on the last tool when there is no system prompt: tools and
   system repeat in every turn of a session;
2. on the last block of the last message: the whole request, which the next turn extends;
3. on the last block of the previous `user` message: the prefix the next turn still shares when
   the client rewrites the newest message.

A breakpoint goes on the last block of a message that can carry one (text, image, tool use, tool
result); thinking blocks cannot. Without `cache` the request has no breakpoints.

### Header modes

| Mode | Secret header | Other headers | System prompt |
|---|---|---|---|
| `api_key` | `x-api-key: <key>` | `anthropic-version`, `content-type`, `accept: text/event-stream`, `user-agent: qb-gateway` | the client's |
| `oauth` | `authorization: Bearer <access token>` | as `api_key`, plus `anthropic-beta: oauth-2025-04-20,claude-code-20250219`, the vendor CLI's `user-agent` and `x-app: cli` | the vendor CLI's identity line as the first block, then the client's |

All identity values (version, betas, user agent, `x-app`, identity line) are constants in
`request::identity`, the one place to change them. Clients of the gateway never see or send them.
The subscription endpoint refuses newer models for an old CLI version in the user agent
(HTTP 400 `version 2.1.280 or newer is required` for `claude-opus-5-5`), so the version in
`OAUTH_USER_AGENT` follows the current vendor CLI; a test pins the known minimum.

## Upstream answer

`stream::Reader` takes response bytes in chunks of any size. Its SSE parser accepts `\n`,
`\r\n` and `\r` line ends split anywhere, ignores comments, `id` and `retry`, joins multi-line
`data`, and fails once one event exceeds 256 KiB. Unknown event types, unknown block types and
unknown delta types are skipped.

Text deltas go out as they arrive; a tool call's input JSON and a thinking block's text and
signature are held until the block stops, and one such block may hold at most 768 KiB. Together
the two bounds keep what one upstream stream holds at 1 MiB, the per-turn allowance of the
gateway's memory budget in [ADR 0001](adr/0001-model-gateway.md) ("≲ 1 MiB plus twice its
request body"). 768 KiB is beyond the longest output a model writes into one block. Either bound
exceeded is an `unavailable` failure (`malformed vendor stream`).

| Messages event | Canonical event |
|---|---|
| `message_start` | `usage` with the input counts |
| `text` block, `text_delta` | `text_delta` per non-empty delta |
| `tool_use` block, `input_json_delta`… `content_block_stop` | one `tool_call` with the assembled input; empty input is `{}` |
| `thinking` block, `thinking_delta`, `signature_delta`… stop | one `thinking{vendor, opaque}`, `opaque` = the complete block as JSON |
| `redacted_thinking` block … stop | one `thinking`, `opaque` = the block as JSON |
| `message_delta` | `usage` with the cumulative counts; the stop reason is kept |
| `message_stop` | `Progress::Finished(reason)` |
| `error` | a classified `Failure` |
| `ping`, other | nothing |

Usage: `input` = `input_tokens`, `output` = `output_tokens`, `cache_read` =
`cache_read_input_tokens`, `cache_write` = `cache_creation_input_tokens`; a count missing from a
later event keeps its earlier value.

Stop reasons: `end_turn`, `stop_sequence`, `pause_turn` and unknown values are `end`; `tool_use`
is `tool_use`; `max_tokens` and `model_context_window_exceeded` are `max_tokens`; `refusal` is
`refusal`.

Events out of order (a delta outside its block, a second `message_start`, events after
`message_stop`), tool input that is not a JSON object, undecodable event data, and a stream that
ends before `message_stop` are `unavailable` failures. Events already returned stay delivered.

## Rate limits and failures

`limits::rate_limits(headers)` reads, case-insensitively:

| Header | Field |
|---|---|
| `anthropic-ratelimit-unified-status` | `status` (`allowed`, `allowed_warning`, `rejected`, …) |
| `anthropic-ratelimit-unified-reset` | `resets_at` |
| `anthropic-ratelimit-unified-representative-claim` | `representative_claim`, as a window name |
| `anthropic-ratelimit-unified-<claim>-utilization` | one window: `utilization` (fraction, clamped to 1.0) |
| `anthropic-ratelimit-unified-<claim>-reset` | its `resets_at` |
| `anthropic-ratelimit-unified-<claim>-status` | `rejected` makes its utilisation 1.0 |
| `retry-after` | `retry_after`, whole seconds only |

Claims map to the window names of [vendors.md](vendors.md): `5h` is `five_hour` (18000 s), `7d`
is `seven_day` and `7d_<model>` is `seven_day_<model>` (604800 s); other claims such as
`overage` are not windows. Times are Unix seconds, or milliseconds at or above 10^11. An
unreadable utilisation or reset drops that window only.

`limits::classify_response(status, headers, body)` and, for an `error` event,
`limits::classify_stream_error(detail, limits)` give a `limits::FailureKind`. It mirrors the
gateway seam's `FailureKind` by variant and `as_str` name, without `Cancelled`, which only the
adapter sees; the crate stays pure, so the binary converts by name rather than this crate
depending on it. The client class and outcome are the gateway core's mapping:

| Answer | Failure kind | Client class | `qbd` outcome |
|---|---|---|---|
| 401, 403, `authentication_error`, `permission_error` | `auth` | `auth` | `http_401` |
| 429 with unified status `rejected`, or a message about a usage limit (`usage limit`, `hit your limit`, `limit reached`) | `usage_limit{resets_at}` | `quota_exhausted` | `usage_limit` |
| other 429, `rate_limit_error` | `rate_limited{retry_after}` | `overloaded` | `http_429` |
| 402, `billing_error`, or a 400 whose message is about credit or billing (`credit balance`, `billing`), as an API key out of prepaid credit gets | `usage_limit` without reset | `quota_exhausted` | `usage_limit` |
| 529, `overloaded_error` | `overloaded{retry_after}` | `overloaded` | `error` |
| 404, `not_found_error` | `model_unavailable` | `unavailable` | `model_unavailable` |
| 400, 413 whose message says the prompt is too long (`prompt is too long`, `context length`, `context window`, `exceed context limit`, `too many tokens`) | `context_too_long` | `context_too_long` | `error` |
| other 400, 413, `invalid_request_error` | `bad_request` | `bad_request` | `error` |
| anything else (5xx, `api_error`, a body that is not JSON) | `unavailable` | `unavailable` | `error` |

`resets_at` of a usage limit is the unified reset, else the representative window's reset, else
the latest reset of a window at 1.0. The failure carries the windows of the headers and the
vendor's message, cut to 300 characters with control characters (line ends included) replaced
by spaces; it never carries a header value.

## OAuth token refresh

`qb gateway` refreshes the token of an `oauth_anthropic` login (`crates/qb/src/gateway/oauth.rs`)
when it expires within 60 s or the vendor answered 401, through the vendor's OAuth refresh grant:

- `POST` to the login's `token_url`, else to `https://platform.claude.com/v1/oauth/token` and,
  when that fails in transport or with a 5xx, to `https://console.anthropic.com/v1/oauth/token`;
  ureq with rustls, no proxy, no redirects, 10 s to connect and 30 s per request;
- `user-agent` `axios/1.7.9`, the vendor CLI's HTTP client (`identity::OAUTH_TOKEN_USER_AGENT`):
  the token endpoint throttles the CLI's own inference user agent;
- body `application/x-www-form-urlencoded`: `grant_type=refresh_token`, `refresh_token`, and
  `client_id` `9d1c250a-e61b-44d9-88ed-5944d1962f5e`, the vendor CLI's public OAuth client id
  (`identity::OAUTH_CLIENT_ID`; the endpoints are `identity::OAUTH_TOKEN_URLS`);
- a 2xx answer is JSON with `access_token` and `expires_in` (seconds), both required, and an
  optional rotated `refresh_token`; without one the old refresh token stays. The new
  `expires_at` is the gateway's clock plus `expires_in`.

| Answer | Result |
|---|---|
| 2xx with the required fields | the new tokens, written back to the credential file |
| 400, 401, or another non-5xx answer other than 429 with an `invalid_grant`-class error code ([openai.md](openai.md#serving-the-upstream)) | refused: the login is `auth_dead` until a new sign-in, the turn moves to the next login |
| transport failure or 5xx at every endpoint, 429, another status, a malformed 2xx | failed: the turn ends `unavailable`, retryable |

A refresh error names the endpoint, the status and the OAuth `error` code, never a body, header
or token.

## OAuth sign-in

`qb login` (`crates/qb/src/gateway/signin.rs`, [config.md](config.md#signing-in)) signs an
`oauth_anthropic` login in with the authorization code grant and PKCE (RFC 7636, S256), the
vendor CLI's flow for a host without a browser:

- the authorize URL is `https://claude.ai/oauth/authorize` (`identity::OAUTH_AUTHORIZE_URL`)
  with `code=true`, `client_id`, `response_type=code`, `redirect_uri`
  `https://console.anthropic.com/oauth/code/callback` (`identity::OAUTH_REDIRECT_URI`), `scope`
  `org:create_api_key user:profile user:inference` (`identity::OAUTH_SCOPES`), `code_challenge`,
  `code_challenge_method=S256` and `state`. The verifier and the state are each 32 bytes of the
  kernel's random source in unpadded base64url; the challenge is the unpadded base64url SHA-256
  of the verifier;
- the redirect page shows `code#state`, which the operator pastes; a `state` other than the one
  sent is refused before any request;
- `POST` to the endpoints of the refresh above, in the same order, with the same transport and
  `user-agent`; body `application/json`: `grant_type` `authorization_code`, `code`, `state`,
  `client_id`, `redirect_uri` and `code_verifier`;
- a 2xx answer needs `access_token`, `refresh_token` and `expires_in`; `expires_at` is the clock
  plus `expires_in`.

A 4xx answer is a refusal and a transport failure or 5xx at every endpoint, or a 2xx without the
required fields, a failure; neither writes a file. The error names the endpoint, the status and
the OAuth `error` code, never the code, the verifier or a token.

## The `/v1/messages` front

`qb gateway` serves `POST /v1/messages` on its unix socket to the peers of its C4 front, when its
config has a `[fronts.messages]` table ([config.md](config.md#gateway-config)), in
`crates/qb/src/gateway/messages.rs`; the answer itself is written by
`crates/qb/src/gateway/answer.rs`, shared with the OpenAI fronts. With `fronts.listen` it also
serves it on that loopback TCP address, where the request head must carry the local client token
in `x-api-key` or `Authorization: Bearer`; the token's SHA-256 is compared in constant time with
`fronts.token_sha256` before the body is read. A missing or wrong token is 401
`authentication_error`, any other method or path 404 `not_found_error`, both in the Messages
error format, except on the paths of the OpenAI fronts, which answer in theirs
([openai.md](openai.md#serving-the-fronts)). `model` is a client model name of `fronts.models`
or a route alias; `native_vendor` is `fronts.messages.vendor`. Other request headers are
ignored: `anthropic-version`, `anthropic-beta`, `x-api-key` on the unix socket and the SDK's own
leave the turn as it is. The decoded turn runs through the same core as a C4 turn, with the same
rotation, and the answer is:

- `stream: true`: `200` with `content-type: text/event-stream`, one chunk per canonical event
  from `front::SseEncoder`; an error after the first event is an SSE `error` event; once
  `message_start` went out, a stream silent for `fronts.ping_interval_s` gets a `ping` event,
  so client read timeouts outlast a slow vendor;
- `stream: false`: one `front::Assembler` body as `application/json` once the turn ended;
- an error before the first event, an error of a non-streaming turn and a rejected request:
  `front::error_response` as status, `retry-after`, `x-should-retry` and Messages error body;
  a request the gateway cannot read is `invalid_request_error` with 400, 411 or 413, another
  method than `POST` with 405, and without `[fronts.messages]` the endpoint answers 404.

A client closing its connection cancels the turn and shuts the upstream connection down.

`front::decode_request(body, request_id, native_vendor, route_of)`:

- `model` becomes the route alias through `route_of`; an unknown model is `bad_request`;
- `system` as a string or text blocks (joined by a blank line); `content` as a string or blocks;
- `text`, base64 `image`, `tool_use`, `tool_result` (string or text blocks, joined by newlines)
  map one to one; `thinking` and `redacted_thinking` become `thinking` of `native_vendor` with the
  block as JSON, except a `redacted_thinking` this front wrapped for another vendor (below);
- `output_config.effort`: `xhigh` reads as `high`; an unknown effort is `bad_request`;
- `metadata.user_id` of 1 to 128 bytes is the `session_key`; a longer one (SDK ids such as
  `user_<hex>_account_<uuid>_session_<uuid>` run to about 160 bytes) gives `qb-sk:` and 32 hex
  digits of a deterministic non-cryptographic hash (two FNV-1a passes) of the whole id;
- `cache` is `auto` when `cache_control` is set at the top level, on a `system` block, a tool, a
  message content block or a block inside a tool result, else absent; a `cache_control` key
  inside a tool schema or tool input is data and does not count;
- sampling parameters, `tool_choice`, `stop_sequences` and thinking budgets are ignored; unknown
  fields are ignored;
- a `system` message (Claude Code sends the turn's environment and reminders as one after the
  last user message) becomes a canonical `system` message in place; one without content, which
  only sets `output_config` for the turns after it, is dropped, since the request's own
  `output_config` is what the turn uses; a per-message `output_config` is ignored;
- every tool goes upstream loaded (`defer_loading` is not sent), so what a client's tool search
  says about loading needs no upstream support: a `tool_reference` block (in a `tool_result` or
  on its own) becomes the text ``Tool `<name>` is loaded.``, and a `tool_addition` or
  `tool_removal` of a system message that names a tool by `tool_reference` is dropped (a system
  message left without blocks with it);
- documents, URL or file images, images inside tool results, roles other than `user`,
  `assistant` and `system`, a system message with another block than text and tool changes by
  reference (an inline `tool_definition` needs a beta the upstream does not send), a system
  message with `clear_at` other than `never` (turn-scoped messages need a beta too), and a turn
  that fails `TurnRequest::validate` are `bad_request`.

`front::SseEncoder` writes canonical events as Messages SSE: `message_start` (deferred to the
first event after `route`, so it carries the input usage; on an Anthropic login that event is
the vendor's own `message_start`, relayed as it arrives, before any content), one `content_block_*` group per text
run, thinking block and tool call with indices from 0, then `message_delta` with the stop reason
and cumulative usage, and `message_stop`. A tool call is one `input_json_delta` with the whole
input. `route` writes nothing; an `error` writes an `error` event and ends the stream.
`SseEncoder::started()` tells the front whether bytes went out; before that an error is an HTTP
error answer. `front::Assembler` builds the same answer as one response body.

Thinking of `native_vendor` whose payload is an Anthropic block goes out as that block. Thinking
of another vendor goes out as `redacted_thinking` whose `data` is `qb-thinking:` followed by
`{"vendor": …, "opaque": …}`; the client echoes it back and the decoder restores the canonical
block, so a turn can switch vendors under a Messages client.

Such a block breaks a rollback: a client pointed back at the vendor directly, with a
`qb-thinking:` block in its history, sends a `redacted_thinking` whose `data` the vendor did not
issue, and the vendor rejects the request. Where a rollback to the direct vendor must stay
possible, build the encoder and assembler with `.foreign_thinking(ForeignThinking::Drop)`:
thinking of another vendor is then left out of the answer (that vendor's reasoning is lost to
later turns, as when the upstream request drops it). The default is `Keep`.

`front::error_response(error, now)`:

| Class | Status | Error type | `retry-after` |
|---|---|---|---|
| `quota_exhausted` | 429 | `rate_limit_error` | seconds to `resets_at` (at least 1), else `retry_after` |
| `overloaded` | 529 | `overloaded_error` | `retry_after` |
| `auth` | 502 | `api_error` | — |
| `bad_request` | 400 | `invalid_request_error` | — |
| `context_too_long` | 400 | `invalid_request_error`, message starting `prompt is too long` | — |
| `unavailable` | 502 | `api_error` | — |
| `cancelled` | 409 | `api_error` | — |
| `no_route` | 503 | `api_error` | — |

`cancelled` and `no_route` carry `x-should-retry: false`: retrying a cancelled turn or a route
without any usable login cannot help.

A `quota_exhausted` answer whose `retry-after` is more than 300 s also carries
`x-should-retry: false`, so SDK clients stop their automatic retries until the reset.

`auth` here is the vendor rejecting the gateway's own credential. To an SDK client a 401 means
its own key is wrong, and some clients then discard that key, so the front answers 502. A bad
local client token is the gateway's own check and stays 401 there.
