# OpenAI Chat Completions and Responses translation

`crates/qb-openai` translates between the gateway's canonical C4 turns (`qb_proto::gateway`, see
[api.md](api.md)) and the two OpenAI APIs, in both directions:

- **upstream**: the gateway calls an OpenAI-family vendor through the Responses API, with an API
  key or a ChatGPT subscription login. A `TurnRequest` becomes a Responses request body and
  header set; the SSE answer becomes canonical content events; rate-limit headers and errors
  become quota windows and a vendor-neutral failure for `qbd`'s report;
- **client side**: the gateway's `/v1/chat/completions` and `/v1/responses` fronts. A request
  from an OpenAI SDK client becomes a `TurnRequest`; canonical events become SSE, a response body
  or an error answer in the client's format.

The crate is pure: no I/O, no clock, no secrets. The caller passes `now` and builds the
credential header values itself. Every parser is total: any bytes give a value or a typed error,
never a panic.

## The pivot

Every front decodes into the canonical `TurnRequest` and encodes canonical events; every
upstream adapter encodes the canonical request and decodes its vendor stream into canonical
events. So any front runs on any route: a Chat Completions client on a Claude subscription, a
Messages client on a ChatGPT login. What does not survive a crossing:

| Crossing | Lost or changed |
|---|---|
| Thinking into a Chat Completions client | Chat Completions has no reasoning field: thinking is not shown and does not come back in the next turn. A Claude route that needs its thinking blocks in a tool loop gets them only through the Messages or Responses front. |
| Thinking into a Responses client | Kept. Thinking of the route's own OpenAI-family vendor is its reasoning item; thinking of another vendor is a `reasoning` item whose `encrypted_content` wraps it (below) and comes back byte for byte. Its `summary` is empty. |
| Anthropic thinking to an OpenAI upstream, or reasoning to an Anthropic upstream | Dropped by the upstream adapter: a vendor cannot read another vendor's thinking. |
| `cache_control` breakpoints of a Messages client on an OpenAI upstream | Not sent: OpenAI caches prompts on its own; `session_key` becomes `prompt_cache_key`. |
| Any OpenAI front | `cache` is always `auto`, since OpenAI clients expect caching without asking; on an Anthropic API key that means cache writes at their price. |
| `tool_result.is_error` to an OpenAI upstream | Dropped: `function_call_output` has no error flag. |
| Usage | OpenAI reports no cache writes: `cache_write` reads as 0 upstream, and fronts fold it into `prompt_tokens`/`input_tokens`. The canonical usage has no reasoning count, so fronts write `reasoning_tokens: 0`. |
| `reasoning.summary`, `include`, `store` of a Responses client | Ignored: the upstream adapter always asks for summaries and encrypted reasoning and never stores. |
| `n` > 1, logprobs, audio, structured output (`response_format`, `text.format`), non-function tools, image URLs, files | Refused with a clear `400`. |
| `tool_choice`, `parallel_tool_calls`, sampling parameters, `stop` | Ignored, as on the Messages front. |

## Upstream request

`request::build(req, target)` returns the body; `AuthMode::url()` names the endpoint,
`AuthMode::headers(session)` returns every header except the secret and the account id,
`AuthMode::secret_header()` names the secret's header and value prefix, and
`AuthMode::account_header()` names the account id's header.

| Canonical | Responses |
|---|---|
| `system` | `instructions` (always present on a subscription login, which requires it) |
| `user` text and images | one `message` item of `input_text` and `input_image` (a base64 `data:` URL, detail `auto`) parts |
| `assistant` text | one assistant `message` item of `output_text` parts |
| `tool_use{id,name,input}` | `function_call{call_id: id, name, arguments: input as JSON}` |
| `tool_result{id,content}` | `function_call_output{call_id: id, output: content}` |
| `thinking` of the picked vendor whose `opaque` is a reasoning item | that `reasoning` item (`summary`, `encrypted_content`) |
| `thinking` of another vendor, or another `opaque`; empty text | dropped |
| `image` with `path` | `BuildError`: the gateway reads no file a client names |
| `tools[]` | `tools[]{type: function, name, description, parameters, strict: false}`, `tool_choice: auto`, `parallel_tool_calls: true` |
| `max_tokens` | `max_output_tokens`, at least 16, the vendor's minimum (API key only; the subscription endpoint refuses it) |
| `effort`, else the ladder candidate's effort | `reasoning.effort`: `low`, `medium`, `high`; `max` is `xhigh`; a candidate effort other than `none`, `minimal`, `low`, `medium`, `high`, `xhigh`, `max` is dropped |
| `session_key` | `prompt_cache_key`, and the subscription mode's `session_id` header when it is visible ASCII |
| — | `store: false`, `stream: true`; with `target.reasoning`, `reasoning.summary: auto` and `include: ["reasoning.encrypted_content"]` |

Item ids are never sent: with `store: false` the vendor keeps no item to refer to. Text and
images between tool items keep their order.

### Header modes

| Mode | Endpoint | Secret header | Other headers |
|---|---|---|---|
| `api_key` | `https://api.openai.com/v1/responses` | `authorization: Bearer <key>` | `content-type`, `accept: text/event-stream`, `user-agent: qb-gateway` |
| `chatgpt_oauth` | `https://chatgpt.com/backend-api/codex/responses` | `authorization: Bearer <access token>` | `chatgpt-account-id: <account id from the credential file>`, `openai-beta: responses=experimental`, `originator` and `user-agent` of the Codex CLI, `session_id`, `content-type`, `accept` |

All identity values are constants in `request::identity`, the one place to change them. Clients
of the gateway never see or send them.

## Upstream answer

`stream::Reader` takes response bytes in chunks of any size. Its SSE parser accepts `\n`,
`\r\n` and `\r` line ends split anywhere, ignores comments, `id` and `retry`, joins multi-line
`data`, and fails once one event exceeds its bound. The vendor repeats the request's
instructions and tools in every lifecycle event and the whole output in `response.completed`, so
the caller sizes the bound with `Reader::with_event_bound(vendor, limits,
stream::event_bound(request_bytes))`: the upstream body plus 1 MiB, the turn's memory allowance.
`Reader::new` uses 1 MiB alone.
Events are decoded by their `type`; unknown types (such as `codex.rate_limits`,
`response.content_part.*` or the reasoning summary events) are skipped.

| Responses event | Canonical event |
|---|---|
| `response.created`, `response.in_progress` | nothing; the stream has started |
| `response.output_item.added` | nothing; opens the item at `output_index` |
| `response.output_text.delta`, `response.refusal.delta` | `text_delta` per non-empty delta; a refusal makes the stop `refusal` |
| `response.function_call_arguments.delta` / `.done` | accumulated per item |
| `response.output_item.done` of a `function_call` | one `tool_call{id: call_id, name, input}`; the done item's arguments win over the accumulated ones; empty arguments are `{}` |
| `response.output_item.done` of a `reasoning` item with `encrypted_content` | one `thinking{vendor, opaque}`, `opaque` = `{"type":"reasoning","summary":[…],"encrypted_content":…}` (no id, no status) |
| `response.output_item.done` of a `message` that streamed no deltas | its text as `text_delta` |
| `response.completed` | `usage`, then `Progress::Finished(tool_use)` when the answer has tool calls, `refusal` after a refusal, else `end` |
| `response.incomplete` | `usage`, then `Finished(max_tokens)`, or `Finished(refusal)` for `content_filter` |
| `response.failed`, `error` | a classified `Failure` |

Usage: `input` = `input_tokens` − `cached_tokens`, `cache_read` = `cached_tokens`, `output` =
`output_tokens` (reasoning included), `cache_write` = 0.

Events out of order (a content event before `response.created`, a delta outside its item, an
item added twice, any known event after the end), arguments that are not a JSON object, a
function call without `call_id` or name, open items holding more than 768 KiB of arguments or
more than 64 open items, undecodable event data, and a stream that ends before
`response.completed` are `unavailable` failures. Events already returned stay delivered.

## Rate limits and failures

`limits::rate_limits(headers, now)` reads, case-insensitively:

| Header | Window |
|---|---|
| `x-codex-{primary,secondary}-used-percent` (percent), `-window-minutes`, `-reset-at` (Unix time) or `-reset-after-seconds` | the subscription window, named as `qb-vendors` names the Codex rollout windows: `five_hour` (300 min), `seven_day` (10080 min), else `window_<m>m` |
| `x-ratelimit-{limit,remaining,reset}-requests` | `requests`: used = (limit − remaining) / limit, reset = `now` + the duration (`1s`, `6m0s`, `20ms`), no length |
| `x-ratelimit-{limit,remaining,reset}-tokens` | `tokens`, the same way |
| `retry-after` (whole seconds), else `retry-after-ms` | `retry_after`, rounded up |

`requests` and `tokens` are short rate limits: they go to `qbd`'s report but never count as a
usage limit. An unreadable value drops only its own window.

`limits::classify_response(status, headers, body, now)` and, for `error` and `response.failed`,
`limits::classify_stream_error(code, message, limits)`. The error object is read from
`{"error": {…}}`, a top-level object, or `{"detail": "…"}`; `type` and `code` both count:

| Answer | Failure kind | Client class | `qbd` outcome |
|---|---|---|---|
| `usage_limit_reached` (ChatGPT plan), `insufficient_quota` (API key out of credit), `billing_hard_limit_reached`, `billing_not_active`; a 429 when a subscription window is at 100 %; a 400 or 429 whose message says `usage limit`, `hit your limit`, `exceeded your current quota` or `credit balance` | `usage_limit{resets_at}` | `quota_exhausted` | `usage_limit` |
| `usage_not_included`, `model_not_found`, 404; a 400 whose message says `model is not supported`, `does not exist`, `model not found` or `must be verified` (an organisation not verified for the model) | `model_unavailable` | `unavailable` | `model_unavailable` |
| `context_length_exceeded`; any answer whose message says `request too large` or `must be reduced` (a request over a per-minute token limit, which no login with that limit can serve); a 400, 413 or 422 whose message says `context length`, `context window`, `maximum context`, `too many tokens`, `prompt is too long` or `input is too long` | `context_too_long` | `context_too_long` | `error` |
| 401, 403 with a JSON body, `invalid_api_key`, `token_expired`, `account_deactivated` | `auth` | `auth` | `http_401` |
| other 429, `rate_limit_exceeded`, type `requests` or `tokens` | `rate_limited{retry_after}` | `overloaded` | `http_429` |
| 402 | `usage_limit` without reset | `quota_exhausted` | `usage_limit` |
| 503, 529, `server_is_overloaded`, `slow_down` | `overloaded{retry_after}` | `overloaded` | `error` |
| other 400, 413, 422, `invalid_request_error`, `invalid_prompt` | `bad_request` | `bad_request` | `error` |
| anything else (5xx, `server_error`, a 403 whose body is not JSON such as a bot wall, another body that is not JSON) | `unavailable` | `unavailable` | `error` |

`resets_at` of a usage limit is the body's `resets_at`, else `now` + `resets_in_seconds`, else
the latest reset of a subscription window at 100 %. `retry_after` is the header, else the
duration after `try again in` in the message (`1.8s`, `6m0s`, `5 minutes`). The failure carries the windows of the headers and
the vendor's message, cut to 300 characters with control characters as spaces; it never carries a
header value.

## The `/v1/chat/completions` front

`chat::decode_request(body, request_id, route_of, default_max_tokens)`:

- `model` becomes the route alias through `route_of`; an unknown model is `bad_request`;
- `system` and `developer` messages, wherever they stand, join into `system` (blank line between);
- `user` content as a string or `text` and `image_url` parts; an image must be a base64 `data:`
  URL of PNG, JPEG, GIF or WebP;
- `assistant` content (text and refusal parts joined, then the `refusal` field) is a text block, followed by one
  `tool_use` per `tool_calls[]` entry with its arguments parsed as a JSON object;
- each `tool` message is a `tool_result` for its `tool_call_id`, which an earlier assistant
  message must have made; consecutive messages of one role merge, so the results of one
  assistant turn (and a user message after them) form one user message;
- `tools[]` of type `function` become tools; without `parameters` the schema is an empty object;
- `max_completion_tokens`, else `max_tokens`, else `default_max_tokens`;
- `reasoning_effort`: `none` and `minimal` read as `low`, `xhigh` as `max`;
- `prompt_cache_key`, else `user`, is the `session_key`; longer than 128 bytes it becomes `qb-sk:`
  and 32 hex digits derived from all of it;
- `stream` and `stream_options.include_usage` are passed on in `FrontRequest`.

Refused with `bad_request`: `n` other than 1, `logprobs`/`top_logprobs`, `audio`, a modality
other than text, a `response_format` other than text, tools that are not functions, image URLs
that are not `data:` URLs, audio and file parts, the legacy `function` role, and a turn that fails
`TurnRequest::validate`.

`chat::SseEncoder` writes `data:` events of `chat.completion.chunk` objects with one `id`
(`chatcmpl-<id>`), `created` and `model` (as the client named it): a first chunk with role
`assistant` (deferred to the first text or tool call), one chunk per `text_delta`, one chunk per
tool call with its `index` from 0, its id, name and whole arguments, a last chunk with
`finish_reason` (`end` → `stop`, `tool_use` → `tool_calls`, `max_tokens` → `length`, `refusal` →
`content_filter`), a usage chunk with no choices when `include_usage`, and `data: [DONE]`.
`route`, `usage` and `thinking` write nothing. `chat::Assembler` builds the same answer as one
`chat.completion` body; its message `content` is `null` when the answer is tool calls only.

## The `/v1/responses` front

`responses::decode_request(body, request_id, native_vendor, route_of, default_max_tokens)`:

- `model` as on the Chat front; `instructions` and `system`/`developer` messages join into
  `system`;
- `input` as a string (one user message) or items: messages (with or without `type`) with
  `input_text`, `input_image` (base64 `data:` URL), `output_text` and `refusal` parts;
  `function_call` (arguments parsed as a JSON object) joins the assistant message before it,
  `function_call_output` (string or text parts) the user message after, and must answer an
  earlier `function_call`;
- a `reasoning` item becomes canonical `thinking`: of `native_vendor` with the item's reduced form
  as `opaque`, or, when its `encrypted_content` starts with `qb-thinking:`, the vendor and payload
  that prefix wraps; a reasoning item without encrypted content cannot be passed on and is
  dropped;
- `max_output_tokens`, else `default_max_tokens`; `reasoning.effort` as on the Chat front;
  `prompt_cache_key`, else `user`, as the session key;
- `store`, `include`, `reasoning.summary`, `tool_choice`, `parallel_tool_calls` and sampling
  parameters are ignored.

Refused with `bad_request`: `previous_response_id` and `conversation` (the gateway is stateless:
the message says to send the whole conversation in `input`), `item_reference` items,
`background: true`, a `text.format` other than text, tools that are not functions, item types
other than the above, `input_image` by `file_id`, file parts, a damaged `qb-thinking:` payload,
and a turn that fails `TurnRequest::validate`.

`responses::SseEncoder` writes named events with `sequence_number` from 0:

1. `response.created` and `response.in_progress` (status `in_progress`), deferred to the first
   event after `route`;
2. per text run, a `message` item `msg_<id>_<n>`: `output_item.added`, `content_part.added`,
   `output_text.delta` per `text_delta`, then `output_text.done`, `content_part.done` and
   `output_item.done` when the run ends;
3. per thinking, a `reasoning` item `rs_<id>_<n>`: `output_item.added`, the summary parts
   (`reasoning_summary_part.added`, `reasoning_summary_text.delta`, `.done`,
   `reasoning_summary_part.done`), `output_item.done` with `encrypted_content`;
4. per tool call, a `function_call` item `fc_<id>_<n>` with `call_id` = the canonical id:
   `output_item.added`, `function_call_arguments.delta` with the whole arguments,
   `function_call_arguments.done`, `output_item.done`;
5. `response.completed` with every item and the usage, or `response.incomplete` with
   `incomplete_details.reason` `max_output_tokens` (`max_tokens`) or `content_filter`
   (`refusal`).

`output_index` counts items from 0 in output order. Thinking of `native_vendor` whose payload is a
reasoning item goes out as that item. Thinking of another vendor goes out as a `reasoning` item
with an empty summary whose `encrypted_content` is `qb-thinking:` followed by
`{"vendor": …, "opaque": …}`; a stateless client sends output items back as input, and the
decoder restores the canonical block exactly, so a turn can switch vendors under a Responses
client. `ForeignThinking::Drop` leaves such items out instead, for clients that also talk to
OpenAI directly with the same history. `responses::Assembler` builds the same response object,
with the same items and ids, for `stream: false`.

## Errors

`front::error_response(error, now)` gives the status, the headers (`ErrorResponse::headers()`)
and the body `{"error": {"message", "type", "param", "code"}}`:

| Class | Status | `type` | `code` | Headers |
|---|---|---|---|---|
| `quota_exhausted` | 429 | `insufficient_quota` | `insufficient_quota` | `retry-after`: seconds to `resets_at` (at least 1), else `retry_after`; `x-should-retry: false` when that is over 300 s |
| `overloaded` | 503 | `server_error` | `server_is_overloaded` | `retry-after` when known |
| `unavailable` | 503 | `server_error` | `upstream_unavailable` | `retry-after` when known |
| `no_route` | 503 | `server_error` | `no_route` | `x-should-retry: false` |
| `auth` | 502 | `server_error` | `upstream_auth_failed` | — |
| `bad_request` | 400 | `invalid_request_error` | `null` | — |
| `context_too_long` | 400 | `invalid_request_error` | `context_length_exceeded` | — |
| `cancelled` | 409 | `server_error` | `cancelled` | — |

`quota_exhausted` uses `insufficient_quota` rather than `rate_limit_exceeded`: every login of the
route is spent until a reset, which is what OpenAI clients understand by that code, and they stop
hammering it; OpenAI SDKs still honour `retry-after` and `x-should-retry`. A vendor rejecting the
gateway's credential is `502`, not `401`: to an SDK a `401` means the client's own key is wrong.

`SseEncoder::started()` tells the front whether bytes went out; before that an error is an HTTP
error answer. After it the error is in the stream: on the Chat front one
`data: {"error": {…}}` event (the shape OpenAI SDKs raise) and no `[DONE]`; on the Responses
front an `error` event with `code` and `message`, then `response.failed` with the items so far
and `error{code, message}`.
