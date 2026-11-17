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
| `messages[].role` | `user`, `assistant` |
| `text` | `text`; an empty text block is dropped |
| `image` (`base64`) | `image` with a `base64` source |
| `image` (`path`) | the same, with the bytes from the caller's loader; a load failure is a `BuildError` |
| `tool_use{id,name,input}` | `tool_use` with the same id |
| `tool_result{id,content,is_error}` | `tool_result{tool_use_id,content,is_error}` |
| `thinking{vendor,opaque}` of the picked vendor | the block whose JSON `opaque` holds (`thinking` with `signature`, or `redacted_thinking`) |
| `thinking` of another vendor, or an `opaque` that is not such a block | dropped |
| `tools[]` | `tools[]{name,description,input_schema}` |
| `max_tokens` | `max_tokens` |
| `effort`, else the ladder candidate's effort | `output_config.effort`; a value other than `low`, `medium`, `high`, `xhigh`, `max` is dropped |
| — | `stream: true`; `thinking: {type: adaptive}` unless the target turns it off |

A message left without blocks is dropped. The model id comes from `qbd`'s pick.

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
`limits::classify_stream_error(detail, limits)`:

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
vendor's message, cut to 300 characters; it never carries a header value.

## The `/v1/messages` front

`front::decode_request(body, request_id, native_vendor, route_of)`:

- `model` becomes the route alias through `route_of`; an unknown model is `bad_request`;
- `system` as a string or text blocks (joined by a blank line); `content` as a string or blocks;
- `text`, base64 `image`, `tool_use`, `tool_result` (string or text blocks, joined by newlines)
  map one to one; `thinking` and `redacted_thinking` become `thinking` of `native_vendor` with the
  block as JSON, except a `redacted_thinking` this front wrapped for another vendor (below);
- `output_config.effort`: `xhigh` reads as `high`; an unknown effort is `bad_request`;
- `metadata.user_id` of 1 to 128 bytes is the `session_key`;
- `cache` is `auto` when `cache_control` is set at the top level, on a `system` block, a tool, a
  message content block or a block inside a tool result, else absent; a `cache_control` key
  inside a tool schema or tool input is data and does not count;
- sampling parameters, `tool_choice`, `stop_sequences` and thinking budgets are ignored; unknown
  fields are ignored;
- documents, URL or file images, images inside tool results, roles other than `user` and
  `assistant`, and a turn that fails `TurnRequest::validate` are `bad_request`.

`front::SseEncoder` writes canonical events as Messages SSE: `message_start` (deferred to the
first event after `route`, so it carries the input usage), one `content_block_*` group per text
run, thinking block and tool call with indices from 0, then `message_delta` with the stop reason
and cumulative usage, and `message_stop`. A tool call is one `input_json_delta` with the whole
input. `route` writes nothing; an `error` writes an `error` event and ends the stream.
`SseEncoder::started()` tells the front whether bytes went out; before that an error is an HTTP
error answer. `front::Assembler` builds the same answer as one response body.

Thinking of `native_vendor` whose payload is an Anthropic block goes out as that block. Thinking
of another vendor goes out as `redacted_thinking` whose `data` is `qb-thinking:` followed by
`{"vendor": …, "opaque": …}`; the client echoes it back and the decoder restores the canonical
block, so a turn can switch vendors under a Messages client.

`front::error_response(error, now)`:

| Class | Status | Error type | `retry-after` |
|---|---|---|---|
| `quota_exhausted` | 429 | `rate_limit_error` | seconds to `resets_at` (at least 1), else `retry_after` |
| `overloaded` | 529 | `overloaded_error` | `retry_after` |
| `auth` | 401 | `authentication_error` | — |
| `bad_request` | 400 | `invalid_request_error` | — |
| `context_too_long` | 400 | `invalid_request_error`, message starting `prompt is too long` | — |
| `unavailable` | 502 | `api_error` | — |
