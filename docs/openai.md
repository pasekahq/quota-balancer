# OpenAI Chat Completions and Responses translation

`crates/qb-openai` translates between the gateway's canonical C4 turns (`qb_proto::gateway`, see
[api.md](api.md)) and the two OpenAI APIs, in both directions:

- **upstream**: the gateway calls an OpenAI-family vendor through the Responses API, with an API
  key or a ChatGPT subscription login, or an OpenAI-compatible vendor (OpenRouter and others)
  through the Chat Completions API with an API key. A `TurnRequest` becomes a request body and
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
| Thinking to a Chat Completions upstream, reasoning from it | Dropped, of every vendor: a Chat Completions request has no field to carry it, and the answer's reasoning deltas are not read. |
| `cache_control` breakpoints of a Messages client on an OpenAI upstream | Not sent: OpenAI caches prompts on its own; on the Responses upstream `session_key` becomes `prompt_cache_key`. |
| Any OpenAI front | `cache` is always `auto`, since OpenAI clients expect caching without asking; on an Anthropic API key that means cache writes at their price. |
| `tool_result.is_error` to an OpenAI upstream | Dropped: `function_call_output` and the Chat Completions `tool` message have no error flag. |
| Usage | OpenAI reports no cache writes: `cache_write` reads as 0 upstream, and fronts fold it into `prompt_tokens`/`input_tokens`. The canonical usage has no reasoning count, so fronts write `reasoning_tokens: 0`. |
| `reasoning.summary`, `include`, `store` of a Responses client | Ignored: the upstream adapter asks for summaries and encrypted reasoning of every model that reasons, and never stores. |
| `n` > 1, logprobs, audio, structured output (`response_format`, `text.format`), non-function tools of the Chat front, image URLs, files | Refused with a clear `400`. |
| Non-function tools of a Responses client (`custom`, `tool_search`, `web_search`, …) | Sent as declared to a Responses upstream; elsewhere a `custom` tool is a function of one string argument `input` with its grammar in the description, tools the vendor runs itself or that only extend the toolset (`web_search*`, `file_search`, `code_interpreter`, `image_generation`, `mcp`, `tool_search`, `namespace`) are left out, and any other type fails the attempt with `bad_request` naming the tool. |
| Mid-conversation `system`/`developer` messages | Kept in place: a `developer` item on the Responses upstream, a mid-conversation system message on the Messages upstream where the vendor accepts one; elsewhere joined into the system prompt. |
| `tool_choice` other than `auto` (`none` with tools, `required`, a named tool) | Refused with a clear `400`: the canonical turn always leaves the choice to the model, so honouring it is impossible and ignoring it would run tools the client forbade. `none` without tools is accepted. |
| `reasoning_effort` / `reasoning.effort` `none` | Read as `low`: the canonical effort has no "off", so the model still reasons a little. |
| `parallel_tool_calls`, sampling parameters, `stop` | Ignored, as on the Messages front. |

## Upstream request

`request::build(req, target)` returns the body; `AuthMode::url()` names the endpoint,
`AuthMode::headers(session)` returns every header except the secret and the account id,
`AuthMode::secret_header()` names the secret's header and value prefix, and
`AuthMode::account_header()` names the account id's header.

| Canonical | Responses |
|---|---|
| `system` | `instructions` (always present on a subscription login, which requires it) |
| a `system` message | a `developer` `message` item of `input_text` parts, in place |
| `user` text and images | one `message` item of `input_text` and `input_image` (a base64 `data:` URL, detail `auto`) parts |
| `assistant` text | one assistant `message` item of `output_text` parts |
| `tool_use{id,name,input}` | `function_call{call_id: id, name, arguments: input as JSON}` |
| `tool_use` of a declared `custom` tool | `custom_tool_call{call_id, name, input}`, `input` the call's string `input` argument |
| `tool_use` of the declared `tool_search` tool | `tool_search_call{call_id, execution: client, status: completed, arguments: input}` |
| `tool_result{id,content}` | `function_call_output{call_id: id, output: content}`, or `custom_tool_call_output` / `tool_search_output{tools: content parsed as a JSON array}` when it answers such a call |
| `thinking` of the picked vendor whose `opaque` is a reasoning item | that `reasoning` item (`summary`, `encrypted_content`) |
| `thinking` of another vendor, or another `opaque`; empty text | dropped |
| `image` with `path` | `BuildError`: the gateway reads no file a client names |
| `tools[]` | `tools[]{type: function, name, description, parameters, strict: false}`, or a tool's `native.spec` as is when its `native.api` is `openai_responses`; `tool_choice: auto`, `parallel_tool_calls: true` |
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
| `response.output_item.done` of a `custom_tool_call` | one `tool_call{id: call_id, name, input: {input: <its input>}}` |
| `response.output_item.done` of a `tool_search_call` with `execution: client` | one `tool_call{id: call_id, name: tool_search, input: arguments}`; a `server` one, and the calls of tools the vendor runs itself (`web_search_call`, …), are skipped |
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
| `usage_limit_reached` (ChatGPT plan), `insufficient_quota` (API key out of credit), `billing_hard_limit_reached`, `billing_not_active`; a 429, or a stream error with a rate code, when a subscription window is at 100 %; a 400 or 429 whose message says `usage limit`, `hit your limit`, `exceeded your current quota` or `credit balance` | `usage_limit{resets_at}` | `quota_exhausted` | `usage_limit` |
| `usage_not_included`, `model_not_found`, 404; a 400 whose message says `model is not supported`, `does not exist`, `model not found` or `must be verified` (an organisation not verified for the model) | `model_unavailable` | `unavailable` | `model_unavailable` |
| `context_length_exceeded`; any answer whose message says `request too large` or `must be reduced` (a request over a per-minute token limit, which no login with that limit can serve); a 400, 413 or 422 whose message says `context length`, `context window`, `maximum context`, `too many tokens`, `prompt is too long` or `input is too long` | `context_too_long` | `context_too_long` | `error` |
| 401, 403 with a JSON body, `invalid_api_key`, `token_expired`, `account_deactivated` | `auth` | `auth` | `http_401` |
| other 429, `rate_limit_exceeded`, type `requests` or `tokens` | `rate_limited{retry_after}` | `overloaded` | `http_429` |
| 402 | `usage_limit` without reset | `quota_exhausted` | `usage_limit` |
| 503, 529, `server_is_overloaded`, `slow_down` | `overloaded{retry_after}` | `overloaded` | `error` |
| other 400, 413, 422, `invalid_request_error`, `invalid_prompt` | `bad_request` | `bad_request` | `error` |
| anything else (5xx, `server_error`, a 403 whose body is not JSON such as a bot wall, another body that is not JSON) | `unavailable` | `unavailable` | `error` |

A usage limit also marks its limiting window, since `qbd` learns the reset only from the
reported windows: a subscription window already at 100 % is it; else the subscription window
whose reset is nearest to the limit's is reported at 1.0 with the limit's reset. An API key's
`insufficient_quota` names no window and no reset.

`resets_at` of a usage limit is the body's `resets_at`, else `now` + `resets_in_seconds`, else
the latest reset of a subscription window at 100 %. `retry_after` is the header, else the
duration after `try again in` in the message (`1.8s`, `6m0s`, `5 minutes`). The failure carries the windows of the headers and
the vendor's message, cut to 300 characters with control characters as spaces; it never carries a
header value.

## Chat Completions upstream

`chat_upstream` is the upstream half for Chat Completions vendors: OpenRouter and other
OpenAI-compatible API keys. It reads no rate-limit headers; the vendor-reported cost is a side
value of the reader.

### Chat Completions request

`chat_upstream::build(req, model)` returns the body; `chat_upstream::PATH` (`/chat/completions`)
is the path below the vendor's base URL.

| Canonical | Chat Completions |
|---|---|
| `system` and every `system` message | the first message, `{role: system, content}`, joined by a blank line (compatible vendors differ on later system messages); absent when empty |
| `user` message | one `tool` message per `tool_result{id,content}` (`tool_call_id: id`, `content`), then one `user` message of `text` and `image_url` parts (a base64 `data:` URL) |
| `assistant` message | one `assistant` message: its text joined as `content` (`null` without text), `tool_calls[]{id, type: function, function{name, arguments: input as JSON}}` with the canonical id unchanged |
| `thinking` of any vendor; empty text; images of an assistant message | dropped |
| `image` with `path` | `BuildError` |
| `tools[]` | `tools[]{type: function, function{name, description, parameters}}`, `tool_choice: auto`; a tool with `native` follows its `elsewhere` as on the Messages upstream (`omit` left out, `refuse` a `BuildError`) |
| `max_tokens` | `max_tokens` |
| (always) | `stream: true`, `stream_options.include_usage: true` |

`effort` and `session_key` are not sent.

| Header | Value |
|---|---|
| `authorization` | `Bearer <key>`: `chat_upstream::secret_header()` names the header and prefix, the caller appends the key |
| `content-type`, `accept`, `user-agent` | `application/json`, `text/event-stream`, `qb-gateway` |
| `http-referer`, `x-title` | the caller's values, when given (OpenRouter's app attribution); a value that is empty or not printable ASCII is an `InvalidHeader` error |

`chat_upstream::headers(referer, title)` returns every header except the secret.

### Chat Completions answer

`chat_upstream::Reader` takes response bytes in chunks of any size through the same SSE parser,
with the 1 MiB event bound; comments such as `: OPENROUTER PROCESSING` are skipped. Only choice
0 is read.

| Chunk | Canonical event |
|---|---|
| `delta.content` | `text_delta` per non-empty piece |
| `delta.refusal` | `text_delta` per non-empty piece; the turn's stop reason is `refusal` |
| `delta.tool_calls[]` | accumulated by `index`: `id` and `function.name` from the first piece that has them, `function.arguments` concatenated; a piece without `index` starts a call when it has an `id` other than the last call's, and else continues the last call |
| `finish_reason` | every accumulated call as one `tool_call{id, name, input}` in `index` order, calls without `index` last in arrival order (empty arguments are `{}`); the stop reason `stop` → `end`, `tool_calls` → `tool_use`, `length` → `max_tokens`, `content_filter` → `refusal`, any other → `end`; `end` with tool calls is `tool_use` |
| `usage` | the last one of the stream becomes the one `usage`, emitted at `[DONE]` or when the vendor closes the stream: `input` = `prompt_tokens` − `cached_tokens`, `cache_read` = `cached_tokens`, `output` = `completion_tokens`, `cache_write` = 0; `usage.cost` (USD) is `Reader::cost()` |
| `delta.reasoning`, `delta.reasoning_details`, other fields | nothing |
| `data: [DONE]` | `Progress::Finished` with the stop reason |
| `{"error": {...}}` | a classified `Failure` (below) |

A stream the vendor closes after a finish reason but without `[DONE]` ends with that reason.
`[DONE]` or the end of the stream before a finish reason, a `finish_reason` of `error`, a chunk
that does not decode, content after the finish reason, data after `[DONE]`, a tool call without
id or name, arguments that are not a JSON object, more than 64 tool calls or more than 768 KiB of
them, and an oversized event are `unavailable` failures. Events already returned stay delivered;
a failed stream emits no `usage`.

### Chat Completions failures

`limits::classify_chat_response(status, headers, body, now)` classifies by status; only a 429
and a 400, 413 or 422 with a JSON error body are refined by its `code`, `type` and message. The failure
carries no windows; its message is cut and cleaned as in the Responses failures and never
carries a header value.

| Answer | Failure kind |
|---|---|
| 401, 403 | `auth` |
| 402; a 429 whose code or type is `insufficient_quota` (the key's credit is spent) | `usage_limit` without reset |
| other 429 | `rate_limited{retry_after}`, from `retry-after` or `retry-after-ms` |
| 404; a 400, 413 or 422 whose code is `model_not_found` or whose message names an unknown model (`model not found`, `does not exist`, `is not a valid model`, …) | `model_unavailable` |
| a 400, 413 or 422 whose code is `context_length_exceeded` or whose message says `context length`, `maximum context`, `context window`, … | `context_too_long` |
| other 400, 413, 422 | `bad_request` |
| 503 | `overloaded{retry_after}` |
| other 5xx, any other status | `unavailable` |

An in-stream error chunk goes through `limits::classify_chat_stream_error`: a numeric `code` from
400 to 599 (OpenRouter's) classifies as that status; another code (`server_error`,
`rate_limit_exceeded`) classifies as a Responses stream error.

## Serving the upstream

`qb gateway` runs every login of `api = "openai"` through this crate's upstream half, in
`crates/qb/src/gateway/openai_upstream.rs`, over the transport it shares with the Anthropic
adapter (`crates/qb/src/gateway/vendor.rs`): one ureq agent with rustls per attempt, no proxy, no
redirects, a 10 s connect bound and a 600 s attempt bound; a cancel or a client that hangs up
shuts the agent down, and the attempt ends `cancelled`.

The credential's kind ([config.md](config.md#gateway-config)) picks the header mode: `api_key`
is the `api_key` mode; `chatgpt_oauth`, a ChatGPT login's access token and account id, is the
`chatgpt_oauth` mode with the account id in `chatgpt-account-id`. The secret's header value is
built in a zeroizing string and dropped once the request is sent.

The gateway refreshes a ChatGPT token (`crates/qb/src/gateway/oauth.rs`) when its `expires_at`
falls within 60 s, or once after a vendor 401 before the first event, and then retries the turn
on the same login; a second 401 or a refused refresh makes the login `auth_dead`, and the turn
moves to the next login. A file without `refresh_token` is used as it is and is unusable after
a 401. The refresh is the OAuth refresh grant:

- `POST` to the login's `token_url`, else to `identity::OAUTH_TOKEN_URL`
  (`https://auth.openai.com/oauth/token`); ureq with rustls, no proxy, no redirects, 10 s to
  connect and 30 s per request, `user-agent` `identity::CHATGPT_USER_AGENT`;
- body `application/x-www-form-urlencoded`: `grant_type=refresh_token`, `refresh_token`, and
  `client_id` `identity::OAUTH_CLIENT_ID`, the Codex CLI's public OAuth client id;
- a 2xx answer is JSON with a required `access_token`, an optional rotated `refresh_token`
  (without one the old refresh token stays) and an optional `id_token`. The new `expires_at` is
  the gateway's clock plus `expires_in` when present, else the `exp` claim of the `id_token`'s
  payload, else of the access token's, each read as base64url JSON without a signature check.

| Answer | Result |
|---|---|
| 2xx with `access_token` and an expiry | the new tokens, written back to the credential file with the unchanged `account_id` |
| 400, 401, or another non-5xx answer other than 429 whose error code (`"error": "<code>"` or `"error": {"code": "<code>"}`) is `invalid_grant`, `refresh_token_expired`, `refresh_token_reused` or `refresh_token_invalidated` | refused: the login is `auth_dead` until a new sign-in, the turn moves to the next login |
| 429, 5xx, transport failure, another status, a 2xx without `access_token` or expiry | failed: the turn ends `unavailable`, retryable |

A refresh error names the endpoint, the status and the error code, never a body value, header,
token or account id. These field names, the refusal shape and the use of the `id_token`'s `exp`
come from references, not from captured answers; the operator runbook
[openai-live-smoke.md](runbooks/openai-live-smoke.md) checks them against the vendor with a
forced refresh.

The endpoint is the login's `base_url` followed by `/responses`, else `AuthMode::url()`. The body
is `request::build` with `target.reasoning` on, unless the gateway config's `openai_models` sets
`reasoning = false` for the picked model ([config.md](config.md#gateway-config)): then the body
carries no `reasoning`, no effort and no `include`. The stream's event bound is
`stream::event_bound` of the body's size. A 200 streams through `stream::Reader` into the turn and
ends with the stop reason and the windows of `limits::rate_limits`, read with the gateway's clock;
any other status reads up to 64 KiB of the body and ends with `limits::classify_response`, whose
usage limit already carries its limiting window at 1.0.

Every login of `api = "chat_completions"`, an `api_key` login, runs through `chat_upstream` in
`crates/qb/src/gateway/chat_upstream.rs` over the same transport; any other credential is an
`auth` failure. The endpoint is the login's `base_url` followed by `chat_upstream::PATH`, the
headers are `chat_upstream::headers` of the login's `referer` and `title`, and the key goes in
`chat_upstream::secret_header()`. A 200 streams through `chat_upstream::Reader` into the turn
and ends with the stop reason, no windows and the reader's cost, which a failed stream carries
too, for the spend count of a capped login ([config.md](config.md#spend-caps)). Any other
status reads up to 64 KiB of the body and ends with `limits::classify_chat_response`. The
runbook [openai-live-smoke.md](runbooks/openai-live-smoke.md) checks the usage, the charge and
the 402 answer against OpenRouter with one short turn per key, and names what a short turn
cannot show: the `usage.cost` field and the in-stream error chunk.

## OAuth sign-in

`qb login` (`crates/qb/src/gateway/signin.rs`, [config.md](config.md#signing-in)) and the
gateway's `/v1/model/logins/{name}/oauth/*` endpoints
([config.md](config.md#signing-in-through-the-gateway)) sign a `chatgpt_oauth` login in with the Codex CLI's authorization code grant and PKCE (RFC 7636, S256),
without its local callback listener:

- the authorize URL is `identity::OAUTH_AUTHORIZE_URL` (`https://auth.openai.com/oauth/authorize`)
  with `response_type=code`, `client_id` `identity::OAUTH_CLIENT_ID`, `redirect_uri`
  `identity::OAUTH_REDIRECT_URI` (`http://localhost:1455/auth/callback`), `scope`
  `identity::OAUTH_SCOPES` (`openid profile email offline_access`), the Codex CLI's
  `identity::OAUTH_AUTHORIZE_EXTRA` (`id_token_add_organizations=true`, which puts the account
  claims into the `id_token`, `codex_cli_simplified_flow=true`, `originator`), `code_challenge`,
  `code_challenge_method=S256` and `state`. The verifier and the state are each 32 bytes of the
  kernel's random source in unpadded base64url; the challenge is the unpadded base64url SHA-256
  of the verifier;
- the vendor redirects the browser to the redirect URI with `code` and `state` in the query,
  which fails to load where no Codex CLI listens; the operator pastes that address. A `state`
  other than the one sent is refused before any request, and so is a redirect with `error`;
- `POST` to the login's `token_url`, else `identity::OAUTH_TOKEN_URL`, with the transport and
  `user-agent` of the refresh above; body `application/x-www-form-urlencoded`: `grant_type`
  `authorization_code`, `code`, `redirect_uri`, `client_id` and `code_verifier`;
- a 2xx answer needs `access_token`, `refresh_token` and an `id_token` whose payload carries
  `https://api.openai.com/auth`.`chatgpt_account_id`, the file's `account_id`; `expires_at`
  follows the refresh's rules.

A 4xx answer is a refusal and a transport failure, a 5xx or a 2xx without the required fields a
failure; neither writes a file. The error names the endpoint, the status and the error code,
never the code, the verifier, a token or the account id. These field names come from the Codex
CLI's flow, not from captured answers; [openai-live-smoke.md](runbooks/openai-live-smoke.md)
signs its ChatGPT login in this way.

## Serving the fronts

`qb gateway` serves `POST /v1/chat/completions` and `POST /v1/responses` on its unix socket to
the peers of its C4 front, when its config has a `[fronts.openai]` table
([config.md](config.md#gateway-config)), in `crates/qb/src/gateway/openai.rs`; the answer is
written by `crates/qb/src/gateway/answer.rs`, shared with the Messages front. With
`fronts.listen` it serves them, and `/v1/messages`, on that loopback TCP address too, to
requests whose head carries a client token of `[fronts]` in `Authorization: Bearer` (what OpenAI
SDKs send) or `x-api-key`; the token's SHA-256 is compared in constant time with
`fronts.token_sha256` and each named client's hash (its `token_sha256`, or that of its
`token_file` and the previous one within its grace) before the body is read. On these
two paths a missing or wrong token is 401 `invalid_request_error` with code `invalid_api_key`,
another method 404 `invalid_request_error` with code `unknown_url`, and a route outside the
named client's `routes` 403 `permission_error` with code `route_not_allowed`
([api.md](api.md#model-gateway-v1model)). An OpenAI SDK switches to the gateway with the
base URL `http://127.0.0.1:<port>/v1` and the client token as its API key.

`model` is a client model name of `fronts.models` or a route alias; any other model is a 400.
`native_vendor` of the Responses front is `fronts.openai.vendor`, and `default_max_tokens` of
both fronts is `fronts.openai.max_tokens`. Thinking of another vendor is kept
(`ForeignThinking::Keep`). The decoded turn runs through the same core as a C4 turn, with the
same pick, report and rotation: a login that hits its limit before the first event is replaced
within the turn, unseen by the client. The answer is:

- `stream: true`: `200` with `content-type: text/event-stream`, one chunk per canonical event
  from the front's `SseEncoder`; once the first event went out, a stream silent for
  `fronts.ping_interval_s` gets the comment `: keep-alive`, which SDKs skip, so client read
  timeouts outlast a slow vendor; an error after the first event is in the stream (below);
- `stream: false`: one `Assembler` body as `application/json` once the turn ended;
- an error before the first event, an error of a non-streaming turn and a rejected request:
  `front::error_response` as status, `retry-after`, `x-should-retry` and OpenAI error body, so
  `quota_exhausted` is a 429 with `retry-after`; a request the gateway cannot read is
  `invalid_request_error` with 400, 411 or 413, another method than `POST` on the unix socket
  405, and without `[fronts.openai]` both endpoints answer 404.

Ids: a Chat Completions answer is `chatcmpl-<hex seconds>_<n>`, a Responses answer
`resp_<hex seconds>_<n>`, unique within the gateway process; the turn's `request_id` is the
same string. Other request headers (`OpenAI-Organization`, `OpenAI-Project`, the SDK's own) are
ignored. A client closing its connection cancels the turn and shuts the upstream connection
down. A loopback connection beyond the gateway's connection cap gets 429 with `retry-after: 1`
in the Messages error format, as the main thread answers it before the request is read; OpenAI
SDKs retry it like any 429.

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
- `tool_choice` may be absent, `null` or `auto` (or `none` without tools), else it is refused;
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

- `model` as on the Chat front; `instructions` and the `system`/`developer` messages before the
  first other item join into `system`; a later one becomes a canonical `system` message in
  place (Codex sends one when the sandbox or approval mode changes mid-session);
- `input` as a string (one user message) or items: messages (with or without `type`) with
  `input_text`, `input_image` (base64 `data:` URL), `output_text` and `refusal` parts;
  `function_call` (arguments parsed as a JSON object) joins the assistant message before it,
  `function_call_output` (string or text parts) the user message after, and must answer an
  earlier `function_call`; `custom_tool_call` is a `tool_use` with `input: {input: <text>}` and
  `custom_tool_call_output` its result; a client `tool_search_call` is a `tool_use` of
  `tool_search` with its arguments and `tool_search_output` its result, the loaded tools as a
  JSON array; a `server` tool search and the calls of tools the vendor runs itself
  (`web_search_call`, `file_search_call`, `code_interpreter_call`, `image_generation_call`,
  `mcp_call`, `mcp_list_tools`) are dropped, since their results are already in the answer; a
  call's `namespace` (a tool a client tool search loaded inside a namespace) joins its name as
  `namespace/name` in the canonical form (`/` occurs in no tool name), and the Responses
  upstream and this front's encoder split it again;
- `tools`: a plain function tool becomes a canonical tool; every other tool, and a function
  with fields beyond `name`, `description`, `parameters` and `strict` (`defer_loading`), keeps
  its declaration in `native` (`api: openai_responses`) with the rule `elsewhere`: `function` for
  functions and `custom` (offered as a function of one string `input`, the `format` grammar
  appended to the description), `omit` for `web_search*`, `file_search`, `code_interpreter`,
  `image_generation`, `mcp`, `tool_search` (named `tool_search`) and `namespace` (a group of
  functions, such as the sub-agent tools Codex declares for a model it has no metadata for),
  `refuse` for any other type (`local_shell`, `shell`, `computer_use_preview`, …). A tool
  without a name takes its `server_label` or type, with `_2`, `_3`, … when taken; a second
  `tool_search` tool is refused. On another vendor a client `tool_search` and a `namespace` are
  left out, so tools the client keeps for its search (Codex's deferred MCP tools) and the
  functions of a namespace are not reachable there;
- a `reasoning` item becomes canonical `thinking`: of `native_vendor` with the item's reduced form
  as `opaque`, or, when its `encrypted_content` starts with `qb-thinking:`, the vendor and payload
  that prefix wraps; a reasoning item without encrypted content cannot be passed on and is
  dropped;
- `max_output_tokens`, else `default_max_tokens`; `reasoning.effort` as on the Chat front;
  `prompt_cache_key`, else `user`, as the session key;
- `tool_choice` as on the Chat front;
- `store`, `include`, `reasoning.summary`, `parallel_tool_calls` and sampling parameters are
  ignored.

Refused with `bad_request`: `previous_response_id` and `conversation` (the gateway is stateless:
the message says to send the whole conversation in `input`), `item_reference` items,
`background: true`, a `text.format` other than text, a tool without a type or a function
without a name, item types other than the above, `input_image` by `file_id`, file parts, a damaged `qb-thinking:` payload,
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
   `function_call_arguments.done`, `output_item.done`; a call of a tool the request declared as
   `custom` is instead a `custom_tool_call` item `ctc_<id>_<n>` (its `input` the call's string
   `input` argument) and one of its `tool_search` tool a `tool_search_call` item `tsc_<id>_<n>`
   (`execution: client`, `arguments` the call's input), each `output_item.added` then
   `output_item.done` (`SseEncoder::tools`, `Assembler::tools`);
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
| `quota_exhausted`, wait ≤ 300 s | 429 | `requests` | `rate_limit_exceeded` | `retry-after`: seconds to `resets_at` (at least 1), else `retry_after`, else 60 |
| `quota_exhausted`, wait > 300 s | 429 | `insufficient_quota` | `insufficient_quota` | the same `retry-after`; `x-should-retry: false` |
| `overloaded` | 429 | `requests` | `rate_limit_exceeded` | `retry-after` when known |
| `unavailable` | 503 | `server_error` | `upstream_unavailable` | `retry-after` when known |
| `no_route` | 503 | `server_error` | `no_route` | `x-should-retry: false` |
| `auth` | 502 | `server_error` | `upstream_auth_failed` | `x-should-retry: false` |
| `bad_request` | 400 | `invalid_request_error` | `null` | — |
| `context_too_long` | 400 | `invalid_request_error` | `context_length_exceeded` | — |
| `cancelled` | 409 | `server_error` | `cancelled` | `x-should-retry: false` |

`quota_exhausted` is every candidate of the route waiting in qbd. That is a spent window until a
reset, but also a full lease table or a short back-off after a 429, so the code follows the wait:
up to 300 s it is OpenAI's request rate limit, which clients retry; beyond it is
`insufficient_quota`, which clients read as spent until a reset, with `x-should-retry: false`.
Errors inside a stream are labelled the same way, measured from the encoder's `created` time.

A vendor rejecting the gateway's credential is `502`, not `401`: to an SDK a `401` means the
client's own key is wrong. `overloaded` is what the core makes of a vendor's rate limit or overload back-off, so it is a
429 here as on the C4 front, in the shape of OpenAI's own request rate limit.
`auth`, `cancelled` and `no_route` say `x-should-retry: false`, as OpenAI SDKs otherwise retry
502, 409 and 503 and a retry would only meet the same rejected credentials, cancelled turn or
empty route.

`SseEncoder::started()` tells the front whether bytes went out; before that an error is an HTTP
error answer. After it the error is in the stream: on the Chat front one
`data: {"error": {…}}` event (the shape OpenAI SDKs raise) and no `[DONE]`; on the Responses
front an `error` event with `code` and `message`, then `response.failed` with the items so far
and `error{code, message}`.

## Fixtures

The streams, answers and the request bodies `chat_sdk_request.json` and
`responses_sdk_request.json` in `crates/qb-openai/tests/fixtures/` are synthetic: they are written
by hand in the shape the OpenAI API, the ChatGPT backend and the OpenAI SDKs use, with neutral ids
and values, and none was captured from a vendor. The `client_sdk_http_*.json` requests are
recorded byte for byte from the OpenAI Python SDK 2.24.0 (`chat.completions.create` and
`responses.create`, each with and without `stream`, with a tool call and its result in the
history) against a loopback listener, with synthetic content, the base URL
`http://127.0.0.1:8080/v1` and the test client token. The operator runbook
[openai-live-smoke.md](runbooks/openai-live-smoke.md) checks the vendor shapes they assume
against live logins.
