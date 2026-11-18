# Config

`qbd` reads one TOML file at start-up:

```sh
qb daemon --config PATH
```

Without `--config` the path is `$QB_CONFIG`, else `/etc/qb/qbd.toml`. A missing, unreadable or
invalid file stops the daemon before it binds its socket: exit code 2 and one line on stderr
naming the file, the field path and the reason, for example

```
qb: /etc/qb/qbd.toml: roles[0].ladder[1].candidates[2].vendor: undeclared vendor `vendor-c`
```

The file holds no secrets: clients are identified by uid or by the SHA-256 of their bearer
token, never by the token itself. It must be readable by the daemon's user (with
`DynamicUser=yes` that means world-readable, mode 0644).

Working examples: [`deploy/examples/`](../deploy/examples).

## Rules for the whole file

- Unknown keys are rejected everywhere.
- Names (`name` of vendors, windows, logins, roles, clients) are non-empty and unique within
  their list; windows are unique per vendor.
- Every reference (`vendor`, `window`, `role`) names something declared in the same file.
- Times are seconds, sizes are bytes, fractions are `0.0..=1.0`.

## `[[vendors]]`

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Vendor id, e.g. `vendor-a`. |
| `windows` | array of tables | Quota windows every login of this vendor has, at most 4. |

Each window:

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Window name as clients report it, e.g. `five_hour`, `seven_day`. |
| `length_s` | integer > 0 | Window length. |
| `t_burn_s` | integer ≤ `length_s` | `T_burn`: inside this time before a reset, the role reserves of the window are dropped. |

## `[[logins]]`

At most 32.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Login name used in `report` and `/v1/state`, e.g. `login-1`. |
| `vendor` | string | Declared vendor. |

## `[[roles]]`

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Role used in `pick` requests, e.g. `worker`. |
| `ladder` | array of tables | Steps, one per difficulty. |
| `reserves` | array of tables | Optional reserves `R(role, difficulty, window)`. |

Each ladder step:

| Key | Type | Meaning |
|---|---|---|
| `difficulty` | integer 0..=255 | Unique within the role. |
| `candidates` | array of tables | 1 to 8 candidates in preference order. |

Each candidate:

| Key | Type | Meaning |
|---|---|---|
| `vendor` | string | Declared vendor. |
| `model` | string | Model name passed to the vendor CLI. |
| `effort` | string | Optional reasoning effort. |
| `tier` | integer 0..=255 | Lower tiers are preferred. |
| `cost_per_minute` | float `0.0..=1.0` | Optional fraction of the vendor's shortest window one minute of work uses; default `leases.cost_per_minute`. |

Each reserve:

| Key | Type | Meaning |
|---|---|---|
| `difficulty` | integer | A ladder step of the same role. |
| `window` | string | A window name declared by some vendor; it constrains only candidates whose vendor declares it. |
| `fraction` | float `0.0..=1.0` | Part of the window this role keeps free at this difficulty. |

A `(difficulty, window)` pair appears at most once per role.

## `[[clients]]`

Optional. Each client needs `uid`, `bearer_sha256` or both.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Client name in leases and the journal. |
| `uid` | integer | Local peer uid (`SO_PEERCRED`); unique. |
| `bearer_sha256` | string | SHA-256 of the bearer token as 64 hex characters; unique. Plaintext tokens are rejected. |
| `role` | string | Declared role; a client listed in `[probe] agents` may omit it. |

Compute the hash with `printf %s "$TOKEN" | sha256sum`. How a request is matched to a client is
described in [api.md](api.md#callers).

## `[journal]`

Required.

| Key | Type | Meaning |
|---|---|---|
| `mode` | `"path"` or `"off"` | `off` writes nothing to disk and takes no other key. |
| `path` | string | With `mode = "path"`: absolute path of the journal file; the previous one is `<path>.1`. Under systemd it lives in the unit's `StateDirectory`, `/var/lib/qb`. |
| `rotate_bytes` | integer > 0 | With `mode = "path"`: rotation size, default 1048576. |

The journal's format, rotation and replay are described in [journal.md](journal.md).

## `[snapshot]`

Optional.

| Key | Type | Meaning |
|---|---|---|
| `ttl_s` | integer > 0 | Age after which a window snapshot is stale, default 300. A stale snapshot is still used; `pick` answers with `stale: true`. |

## `[leases]`

Optional. Every `run` holds a lease that reserves the task's cost; see [api.md](api.md).

| Key | Type | Meaning |
|---|---|---|
| `ttl_s` | integer > 0 | A lease expires this long after its pick plus `expected_minutes`, default 3600. |
| `cost_per_minute` | float `0.0..=1.0` | Cost rate of candidates without their own and of pins, default 0.002. |

## `[outcomes]`

Optional. How long the marks of report outcomes last.

| Key | Type | Meaning |
|---|---|---|
| `rate_limit_backoff_s` | integer > 0 | A login stays `rate_limited` this long after `http_429`, default 60. |
| `model_unavailable_s` | integer > 0 | A model stays dead on a login this long after `model_unavailable`, default 86400. |

## `[probe]`

Optional. Lazy probes: an agent fetches a login's usage endpoint when a `pick` needs its data;
the protocol is in [api.md](api.md#agents-and-probes).

| Key | Type | Meaning |
|---|---|---|
| `enabled` | bool | Hand out probe jobs, default `false`. Off, agents may wait but never get a job. |
| `agents` | array of strings | Declared client names that may act as agents, default none. |
| `backoff_initial_s` | integer > 0 | Back-off after a login's first failed probe, default 30. |
| `backoff_max_s` | integer ≥ `backoff_initial_s` | Ceiling of the doubling back-off, default 3600. |

## `[limits]`

Optional. A token bucket per client; see [api.md](api.md#callers).

| Key | Type | Meaning |
|---|---|---|
| `rate_per_s` | float > 0 | Refill rate in requests per second, default 5.0. |
| `burst` | integer > 0 | Bucket size, default 20. |

## `[hooks]`

Optional. Commands run when a login becomes `auth_dead` and when it leaves it; when and how
they run is in [design.md](design.md#hooks).

| Key | Type | Meaning |
|---|---|---|
| `on_dead` | array of strings | Absolute program path, then its arguments; run when a login becomes `auth_dead`. Not empty. |
| `on_recover` | array of strings | The same, run when a login leaves `auth_dead`. |

The program is exec'd without a shell and gets the event in its environment: `QB_EVENT`
(`dead` or `recover`), `QB_LOGIN` and `QB_VENDOR`. It must be executable by the daemon's user.
For example, with

```toml
[hooks]
on_dead = ["/usr/local/libexec/qb-hook"]
on_recover = ["/usr/local/libexec/qb-hook"]
```

and `/usr/local/libexec/qb-hook`

```sh
#!/bin/sh
logger -t qb-hook -p user.warning "login $QB_LOGIN of $QB_VENDOR: $QB_EVENT"
```

## Agent config

`qb agent` reads its own TOML file, given with `qb agent --config PATH`, under the same rules
for the whole file and with the same exit code 2 and one-line errors. It lists the logins this
agent holds credentials for, 1 to 32:

```toml
[[logins]]
name = "login-1"
kind = "claude"
credentials = ".claude/.credentials.json"
```

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Login name as declared in the daemon's config. |
| `kind` | `"claude"` or `"codex"` | Usage endpoint and response format: Claude `oauth/usage` or Codex `wham/usage` (see [vendors.md](vendors.md)). |
| `credentials` | string | Non-empty path of the vendor CLI's credential file; a relative path starts at the agent's working directory. The agent can read only the directories of these files, resolved at start (see [design.md](design.md#roles-and-privilege-separation)). |

The agent connects as a client of the daemon, so it needs a `[[clients]]` entry listed in
`[probe] agents` there, and `--bearer-file` or `$QB_BEARER_FILE` when it connects by bearer.

## Gateway config

`qb gateway --config PATH` reads its own TOML file, under the same rules for the whole file and
with the same exit code 2 and one-line errors naming the field path and line. Decisions behind
it: [ADR 0001](adr/0001-model-gateway.md); its API: [api.md](api.md#model-gateway-v1model).
Example: [`deploy/examples/gateway.toml`](../deploy/examples/gateway.toml), with its `qbd` side in
[`deploy/examples/qbd.toml`](../deploy/examples/qbd.toml); [Examples](#examples) takes the login
and route shapes out of them one at a time.

Top-level keys come before the tables (`[[clients]]`, `[[logins]]`, `[[routes]]`,
`[openai_models]`, `[prices]`, `[fronts]`):

| Key | Type | Meaning |
|---|---|---|
| `socket` | string | Required. Absolute path of the gateway's unix socket; a stale socket file is replaced. |
| `socket_mode` | integer | `0o600` (default): only the gateway's user may connect; `0o660`: its group too. |
| `qbd_socket` | string | Absolute path of `qbd`'s socket, default `/run/qb/qb.sock`. |
| `qbd_bearer_file` | string | Absolute path of a file with the gateway's bearer token for `qbd`; without it `qbd` identifies the gateway by uid. |
| `max_turns` | integer 1..=16 | Turns running at once, default 4; a further turn gets 429. |
| `max_request_bytes` | integer | Largest body of `POST /v1/model/turn` and of a `POST` to an HTTP front, default 8388608, at most 33554432; other requests take at most 64 KiB. |
| `max_attempts` | integer 1..=16 | Attempts per turn, default 4: picks whose login the gateway tries. |
| `spend_file` | string | Absolute path of the file that counts the spend of the logins with a `spend_cap`; required when one has it ([Spend caps](#spend-caps)). |

`[[clients]]`, optional: callers besides the gateway's own uid. Such a caller must also reach
the socket file: `socket_mode = 0o660` with the caller in the gateway user's group, and a
directory it may traverse. The shipped unit's `RuntimeDirectoryMode=0700` keeps everyone else
out of the runtime directory; with clients, set `RuntimeDirectoryMode=0750` and a shared group,
or put the socket in a directory outside it.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Caller name in the log. |
| `uid` | integer | Peer uid (`SO_PEERCRED`); unique. |

`[[logins]]`, 1 to 32: the logins this gateway holds credentials for.

| Key | Type | Meaning |
|---|---|---|
| `name` | string | Login name as declared in `qbd`'s `[[logins]]`. |
| `kind` | `"oauth_anthropic"`, `"chatgpt_oauth"` or `"api_key"` | Credential type; it selects the adapter's auth mode and must match the file's `type`. |
| `api` | `"anthropic"`, `"openai"` or `"chat_completions"` | The vendor API family the login speaks; it selects the adapter. `"anthropic"` (the default) for an `oauth_anthropic` login, `"openai"` (the default) for a `chatgpt_oauth` login; required for an `api_key` login. `"chat_completions"` is the Chat Completions API of OpenRouter or another OpenAI-compatible vendor, only for an `api_key` login. |
| `base_url` | string | Base URL of the vendor API, default the family's public endpoint: `https://api.anthropic.com` for `anthropic`, below which the gateway calls `/v1/messages`; for `openai` the URL below which it calls `/responses`, `https://api.openai.com/v1` for a key and `https://chatgpt.com/backend-api/codex` for a ChatGPT login. Required for `chat_completions`: the URL below which the gateway calls `/chat/completions`, e.g. `https://openrouter.ai/api/v1`. `https://` on port 443, or `http://` with a loopback host (`localhost`, `127.0.0.0/8`, `::1`); an optional path, no user, query or fragment. |
| `referer` | string | Only for a `chat_completions` login: sent as `http-referer`, OpenRouter's app attribution. Non-empty printable ASCII. |
| `title` | string | Only for a `chat_completions` login: sent as `x-title`, OpenRouter's app name. Non-empty printable ASCII. |
| `token_url` | string | Only for an `oauth_anthropic` or `chatgpt_oauth` login: the full URL of the OAuth token endpoint its refreshes and `qb login` sign-ins go to, instead of the vendor's endpoints ([anthropic.md](anthropic.md#oauth-token-refresh), [openai.md](openai.md#serving-the-upstream)). Same rules as `base_url`. |
| `credentials` | string | Absolute path of the credential file. |
| `spend_cap` | number > 0 | Only for an `api_key` login: USD it may spend per UTC calendar month ([Spend caps](#spend-caps)). |

The sandbox lets the gateway connect to TCP port 443 only, on every host: a loopback `http`
`base_url` or `token_url` must name port 443 too (`http://127.0.0.1:443`), or its requests fail
`unavailable`. Other ports work only where the sandbox is not enforced.

Every login `qbd` can pick for a route of this gateway needs an entry here: a pick of a login
without one fails the turn as a configuration error. Give the gateway's logins their own `qbd`
vendor and role to keep them apart from logins used elsewhere.

A credential file is the gateway's own copy, never a vendor CLI's file (two refreshers would race
for one rotating refresh token); `qb login` makes one from a new sign-in of an OAuth login
([Signing in](#signing-in)), `qb login import` from an existing credential
([Importing credentials](#importing-credentials)). It is JSON, a regular file owned by the
gateway's user with mode 0600; anything else is refused:

```json
{"type": "oauth_anthropic", "access_token": "...", "refresh_token": "...", "expires_at": 1800000000}
{"type": "chatgpt_oauth", "access_token": "...", "account_id": "...", "refresh_token": "...", "expires_at": 1800000000}
{"type": "api_key", "key": "..."}
```

An OAuth token (`oauth_anthropic`, `chatgpt_oauth`) expiring within 60 s, or rejected by the
vendor, is refreshed and the file replaced atomically (temporary 0600 file in the same
directory, fsync, rename, fsync of the directory); one refresh per file runs at a time, and a
token another attempt already replaced is not refreshed again. A `chatgpt_oauth` file holds the
access token of a ChatGPT subscription login and its account id
([openai.md](openai.md#serving-the-upstream)), which a refresh keeps; `refresh_token` and
`expires_at` are optional. Without `refresh_token` the token is used as it is, and a token the
vendor rejects makes the login unusable: the attempt is reported to `qbd` as `http_401` and the
turn moves to the next login. A field of another type (`key` in an OAuth file, `account_id` in
an `oauth_anthropic` or `api_key` file, an OAuth field in an `api_key` file) or any other field
is refused, and the error names the field, never a value. The gateway may create, write and
remove files in the credential files' directories and the directory of `spend_file`, and
nowhere else.

`[[routes]]`, 1 to 64: aliases clients name in `route`, each mapped to a `qbd` pick target: a
ladder step, a pin, or a chain of pins.

| Key | Type | Meaning |
|---|---|---|
| `alias` | string | `^[a-z][a-z0-9_-]{0,63}$`, unique. |
| `role` | string | `qbd` role of the pick. |
| `difficulty` | integer 0..=255 | Ladder step of the role, with `qbd`'s fallback to neighbouring steps, tiers and reserves. |
| `vendor`, `model` | string | Instead of `difficulty`: a pin of one vendor and model, without ladder or role reserve. |
| `effort` | string | Reasoning effort of a pin. |
| `chain` | array of tables | Instead of `difficulty`, `vendor`, `model` and `effort`: 1 to 8 steps `{ vendor, model, effort }`, each a pin (`vendor` and `model` required), which a turn tries in order ([api.md](api.md#attempts-and-rotation)). |
| `expected_minutes` | integer | Expected length of a turn, for the lease's cost. |

A chain across vendors: [Examples](#a-route-chaining-subscription-key-and-openrouter).

`qbd` needs a `[[clients]]` entry for the gateway (by uid, or by bearer with
`qbd_bearer_file`) whose `role` is one the routes name.

`[openai_models]`, optional: settings of models of the `openai` API family, keyed by model id as
`qbd` picks it, at most 256. An entry applies to every route and login of `api = "openai"` that
runs the model, pinned or picked from a ladder; a model without one keeps the defaults.

```toml
[openai_models."model-plain"]
reasoning = false
```

| Key | Type | Meaning |
|---|---|---|
| `reasoning` | boolean | Required. `false`: the model's Responses requests carry no `reasoning`, no effort (of the request or the pick) and no `include`, for a model that refuses the parameter ([openai.md](openai.md#serving-the-upstream)). `true` is the default. |

`[prices]`, optional: USD per million tokens of a model id as `qbd` picks it, at most 256. A
price is all four keys, each a number ≥ 0; it prices a turn of a capped login whose vendor
reports no cost.

```toml
[prices."model-large"]
input = 3.0
output = 15.0
cache_read = 0.3
cache_write = 3.75
```

| Key | Type | Meaning |
|---|---|---|
| `input` | number | Input tokens not read from cache. |
| `output` | number | Output tokens. |
| `cache_read` | number | Input tokens read from the prompt cache. |
| `cache_write` | number | Input tokens written to the prompt cache. |

### Spend caps

An `api_key` login with a `spend_cap` has its spend counted in USD per UTC calendar month. Each
adapter call on it, finished or failed, adds its cost: the cost the vendor reports (OpenRouter's
`usage.cost`), else the call's last `usage` at the model's `[prices]` entry, also when the turn
ended in an error after content. A call with neither counts nothing, and the gateway logs one
warning per such model and run. The counts live in `spend_file`, which the gateway alone writes
(temporary 0600 file in the same directory, fsync, rename); they survive a restart and a reload
and start from zero at each month's start. A file that is not a spend file stops the start.

A login whose count reached its cap is not called: the gateway checks before each adapter call,
whatever `qbd` picked, and the turn moves on as after a usage limit before the first event, to
another login or the next chain step, else ends `quota_exhausted` with `resets_at` at the next
month's start. The gateway reports the count to `qbd` as the login's window `spend`
(`utilization` = spent / cap, `resets_at` = the next month's start) after every call on the
login, so `qbd` stops picking it and `GET /v1/model/routes` shows the route `exhausted` with that
reset. `qbd` keeps only windows its vendor declares, so give the capped API-key logins a `qbd`
vendor of their own that declares `spend`, and no uncapped login:

```toml
[[vendors]]
name = "vendor-d"
windows = [{ name = "spend", length_s = 2678400, t_burn_s = 0 }]
```

On a vendor that also serves uncapped logins, `spend` would be their longest window and never
observed: a usage limit on one of them would mark it exhausted until that window's reset, up to
31 days, and its snapshot would stay stale.

`qb --socket <gateway socket> spend` prints each capped login's `spent_usd`, `cap_usd` and
`period_end`; `qb --socket <gateway socket> spend reset <login>` sets its count to zero
([api.md](api.md#get-v1modelspend-and-post-v1modelspendreset)). A reset, or a cap raised by a
reload, makes the login run again: the gateway reports the new `spend` window to `qbd` at once.

`[fronts]`, optional: the HTTP fronts, `POST /v1/messages`
([anthropic.md](anthropic.md#the-v1messages-front)), `POST /v1/chat/completions` and
`POST /v1/responses` ([openai.md](openai.md#serving-the-fronts)). Its keys are shared by all of
them; each front is served when its sub-table is present, and at least one must be. A front
without its sub-table answers 404.

| Key | Type | Meaning |
|---|---|---|
| `models` | table of strings | Client `model` names, each mapped to a route alias, at most 256; for example `{ "claude-sonnet-4-5-20250929" = "chat", "gpt-5" = "chat" }`. A `model` equal to an alias needs no entry; a key may not be an alias, and a value must be one. Any other `model` is answered 400 `invalid_request_error`. |
| `listen` | string | A loopback TCP address, `127.0.0.1:<port>` or `[::1]:<port>`, that serves the HTTP fronts besides the unix socket, for clients that only speak HTTP over TCP; any other address, or port 0, is a config error. Needs `token_sha256`. |
| `token_sha256` | string | With `listen`, and only with it: SHA-256 of the local client token as 64 hex characters. Plaintext tokens are rejected. |
| `ping_interval_s` | integer 1..=30 | Seconds a started stream may stay silent before the front writes an SSE keep-alive, default 10. |

`[fronts.messages]`: the `POST /v1/messages` front.

| Key | Type | Meaning |
|---|---|---|
| `vendor` | string | Required. The `qbd` vendor whose logins speak the Anthropic API: its thinking blocks reach clients as Anthropic blocks, and the thinking blocks clients send back count as its own. |

`[fronts.openai]`: the `POST /v1/chat/completions` and `POST /v1/responses` fronts.

| Key | Type | Meaning |
|---|---|---|
| `vendor` | string | Required. The `qbd` vendor whose logins speak the OpenAI API: its thinking reaches Responses clients as their reasoning items, and the reasoning items clients send back count as its own. |
| `max_tokens` | integer ≥ 1 | Required. The output bound of a request that names none (`max_completion_tokens`, `max_tokens`, `max_output_tokens`). |

Every request on `listen` carries the local client token in `x-api-key` or
`Authorization: Bearer`, so a client switches to the gateway with its base URL and API key: an
Anthropic SDK with `http://127.0.0.1:<port>`, an OpenAI SDK with `http://127.0.0.1:<port>/v1`. Generate the token and its hash with:

```sh
TOKEN="qb-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf %s "$TOKEN" | sha256sum
```

The token must not start with `sk-ant-`, `eyJ` or `cc-`: some Anthropic clients take a key of
that shape for a subscription OAuth token and send it with another identity. The `qb-` prefix
above avoids that. Anyone on the host who knows the token can spend the gateway's logins, so
keep it as private as a vendor key.

Switching a Hermes agent to the Messages front, and back: [runbooks/hermes-secretary-cutover.md](runbooks/hermes-secretary-cutover.md).

### Examples

Each shape below is a part of [`deploy/examples/gateway.toml`](../deploy/examples/gateway.toml)
and the lines of [`deploy/examples/qbd.toml`](../deploy/examples/qbd.toml) it needs; the two files
together are one working installation. Every route of that gateway runs on the `qbd` role
`gateway`, which `qbd.toml` declares with a ladder and grants to the gateway's uid:

```toml
# qbd.toml
[[clients]]
name = "gateway"
uid = 1003
role = "gateway"
```

#### An OpenAI API key

A key of the `openai` API family, capped at 50 USD a month. Its vendor reports no cost, so the
models it runs need a `[prices]` entry, and the cap needs `spend_file`:

```toml
# gateway.toml
spend_file = "/var/lib/qb-gateway/spend.json"

[[logins]]
name = "key-2"
kind = "api_key"
api = "openai"
spend_cap = 50.0
credentials = "/var/lib/qb-gateway/credentials/key-2.json"

[prices."model-large"]
input = 2.0
output = 8.0
cache_read = 0.5
cache_write = 0.0
```

```toml
# qbd.toml: a vendor of its own with the spend window and no uncapped login
[[vendors]]
name = "vendor-c"
windows = [{ name = "spend", length_s = 2678400, t_burn_s = 0 }]

[[logins]]
name = "key-2"
vendor = "vendor-c"
```

Without `spend_cap`, the key needs neither `spend_file` nor a price, and its vendor declares
`windows = []`, as `vendor-e` does for the Anthropic key `key-1`. The credential file comes from
an env file ([Importing credentials](#importing-credentials)):

```sh
qb login import --config /etc/qb/gateway.toml --from env --source /path/to/vendor.env \
  --var VENDOR_KEY key-2
```

#### A ChatGPT subscription login

The `openai` API family over the ChatGPT backend. Its vendor is the one the OpenAI fronts name:

```toml
# gateway.toml
[[logins]]
name = "login-3"
kind = "chatgpt_oauth"
credentials = "/var/lib/qb-gateway/credentials/login-3.json"

[fronts.openai]
vendor = "vendor-b"
max_tokens = 8192
```

```toml
# qbd.toml
[[vendors]]
name = "vendor-b"
windows = [{ name = "five_hour", length_s = 18000, t_burn_s = 1800 }]

[[logins]]
name = "login-3"
vendor = "vendor-b"
```

Fill its credential file with a sign-in of its own ([Signing in](#signing-in)), or import the
Codex CLI's ([Importing credentials](#importing-credentials)):

```sh
qb login --config /etc/qb/gateway.toml login-3
qb login import --config /etc/qb/gateway.toml --from codex --source /path/to/codex/auth.json login-3
```

#### An OpenRouter-style key

A key of an OpenAI-compatible vendor over Chat Completions, with OpenRouter's app attribution and
a cap of 20 USD a month. OpenRouter reports each call's cost, so it needs no price:

```toml
# gateway.toml
[[logins]]
name = "key-3"
kind = "api_key"
api = "chat_completions"
base_url = "https://openrouter.ai/api/v1"
referer = "https://app.example.com"
title = "example-app"
spend_cap = 20.0
credentials = "/var/lib/qb-gateway/credentials/key-3.json"
```

```toml
# qbd.toml
[[vendors]]
name = "vendor-d"
windows = [{ name = "spend", length_s = 2678400, t_burn_s = 0 }]

[[logins]]
name = "key-3"
vendor = "vendor-d"
```

Its model ids are the vendor's own, such as `vendor-x/model-large`. The credential file comes
from `qb login import --from env`, as for the OpenAI key.

#### A route chaining subscription, key and OpenRouter

The route `chat` tries the Anthropic subscription logins first, then the OpenAI key, then the
OpenRouter-style key; a turn moves to the next step only before the client has seen an event:

```toml
# gateway.toml
[[logins]]
name = "login-1"
kind = "oauth_anthropic"
credentials = "/var/lib/qb-gateway/credentials/login-1.json"

[[logins]]
name = "login-2"
kind = "oauth_anthropic"
credentials = "/var/lib/qb-gateway/credentials/login-2.json"

[[routes]]
alias = "chat"
role = "gateway"
chain = [
  { vendor = "vendor-a", model = "model-large" },
  { vendor = "vendor-c", model = "model-large", effort = "medium" },
  { vendor = "vendor-d", model = "vendor-x/model-large" },
]
expected_minutes = 2
```

```toml
# qbd.toml: vendor-c and vendor-d with their keys as above
[[vendors]]
name = "vendor-a"
windows = [
  { name = "five_hour", length_s = 18000, t_burn_s = 1800 },
  { name = "seven_day", length_s = 604800, t_burn_s = 43200 },
]

[[logins]]
name = "login-1"
vendor = "vendor-a"

[[logins]]
name = "login-2"
vendor = "vendor-a"
```

Each step's vendor serves only logins of this gateway, or a pick of another login fails the turn.
`[fronts.messages] vendor = "vendor-a"` gives the Anthropic logins' thinking blocks to
`/v1/messages` clients.

### Importing credentials

`qb login import` copies a credential another client already holds into a login's credential
file, as the gateway's user. An OAuth login is better signed in on its own with `qb login`
([Signing in](#signing-in)), which gives the gateway a refresh token no other client holds:

```sh
qb login import --config /etc/qb/gateway.toml --from hermes --source /path/to/hermes/auth.json \
  --provider anthropic --entry work login-1
qb login import --config /etc/qb/gateway.toml --from env --source /path/to/vendor.env \
  --var VENDOR_KEY key-1
```

It reads the source and the gateway config only, makes no network call and leaves the source as
it was; it confines itself before reading the source
([design.md](design.md#roles-and-privilege-separation)). It writes the login's `credentials` file in the format above, atomically with mode 0600,
and refuses a file that exists unless `--force` is given. It refuses a source whose credential
type differs from the login's `kind`. No output and no error carries a value: an error names
the file, the field and the problem. A refused import exits 1, a usage error 2.

| `--from` | Source file | Type | Fields |
|---|---|---|---|
| `hermes` | Hermes `auth.json`, the entry of `credential_pool.<provider>` named by `--entry` (its `id`, else its one `label`); `--entry` may be left out when the provider has one entry | `--provider anthropic`: `oauth_anthropic` when the entry's `auth_type` is `oauth` or its access token starts with `sk-ant-oat`, else `api_key`; `--provider openai-codex`: `chatgpt_oauth` | `access_token` → `access_token` (`key` for `api_key`); `refresh_token` → `refresh_token`; `expires_at_ms` (ms) or else `expires_at` (ISO 8601 with a time zone) → `expires_at` in Unix seconds; `chatgpt_account_id` claim of the access token (a JWT) → `account_id` |
| `claude-code` | Claude Code's `.credentials.json` | `oauth_anthropic` | `claudeAiOauth.accessToken` → `access_token`; `claudeAiOauth.refreshToken` → `refresh_token`; `claudeAiOauth.expiresAt` (ms) → `expires_at` in Unix seconds |
| `codex` | The Codex CLI's `auth.json` | `chatgpt_oauth` | `tokens.access_token` → `access_token`; `tokens.refresh_token` → `refresh_token`; `tokens.account_id`, else the `chatgpt_account_id` claim of `tokens.id_token` → `account_id`; no `expires_at`, so the gateway refreshes after the vendor rejects the token |
| `env` | An env file of `NAME=value` lines; `export ` and one pair of quotes around the value are dropped, the last line of the name counts | `api_key` | the value of `--var NAME` → `key` |

A refresh token is single-use: each refresh returns a new one and invalidates the old. When the
imported credential has one, the source client and the gateway share it, and the first refresh
by either leaves the other with a dead token. The command still writes the file, then prints one
warning naming the source client, recommending a dedicated sign-in of the login (`qb login`,
[Signing in](#signing-in)) or no further use of the source client with that account.

### Signing in

`qb login` signs an `oauth_anthropic` or `chatgpt_oauth` login in from scratch with OAuth PKCE,
as the gateway's user, on a host without a browser:

```sh
qb login --config /etc/qb/gateway.toml login-1
```

1. It prints what to do on stderr and one authorize URL on stdout. The URL carries the vendor's
   public client id, redirect URI and scopes, a fresh S256 code challenge and a random `state`;
   the verifier never leaves the process.
2. Open the URL in a browser on any device and sign in with the account of the login.
3. Paste one line on stdin:
   - `oauth_anthropic`: the vendor's page shows a code of the form `code#state`; paste it whole.
   - `chatgpt_oauth`: the browser is sent to `http://localhost:1455/auth/callback?code=...`,
     which fails to load where no Codex CLI listens; paste the full address from the address
     bar.
4. A `state` other than the one sent is refused before any request. The code and the verifier
   go to the login's `token_url`, else the vendor's token endpoint
   ([anthropic.md](anthropic.md#oauth-sign-in), [openai.md](openai.md#oauth-sign-in)), and the
   answer's tokens are written to the login's `credentials` file in the format above,
   atomically with mode 0600: the access token, the refresh token and `expires_at`, and for
   `chatgpt_oauth` the `account_id` from the `chatgpt_account_id` claim of the answer's
   `id_token`. One line on stdout names the file, the type and the login.

The refresh token is the gateway's own: no other client holds it, so no other client's refresh
invalidates it, as one can after `qb login import`.

It refuses an `api_key` login (`qb login import --from env` writes one) and a file that exists
unless `--force` is given, before it prints the URL. A vendor refusal names the status and the
OAuth error code; a refused or failed sign-in writes nothing and is started again. No output and
no error carries the code, the verifier, a token or the account id. It confines itself before it
reads stdin ([design.md](design.md#roles-and-privilege-separation)): like the gateway, it
connects to TCP port 443 only, so a loopback `token_url` must name port 443. A refused sign-in
exits 1, a usage error 2.

### Reload

SIGHUP, `systemctl --user reload qb-gateway` or `qb --socket <gateway socket> reload`
([api.md](api.md#post-v1modelreload)) makes the running gateway read its config file again. The
new file goes through the same parsing and validation as at startup. A valid file that changes
no restart-only key becomes the config of every turn admitted from then on: routes and their
chains, logins and their credential files, `token_url`, `spend_cap`, `max_turns`,
`max_request_bytes`, `max_attempts`, `[openai_models]`, `[prices]`, `[[clients]]`, and `[fronts]`
but `listen`, so the fronts'
`models`, the client token and the fronts served. The gateway logs
`gateway: reloaded <file>: <n> routes, <m> logins`.

A turn already admitted finishes on the config of its admission, its retries and chain steps
included; its stream is not cut. Refresh locks of the credential files carry over.

These keys need a restart: `socket`, `socket_mode`, `fronts.listen` (the listeners exist before
the sandbox), `qbd_socket` and `qbd_bearer_file` (the token is read once at startup),
`spend_file` (the sandbox opens its directory once), and a
login whose `credentials` lies in a directory no login of the startup config uses (the sandbox
opens the credential directories once). A file that cannot be read, does not validate or
changes one of them is refused: the running config stays, the gateway logs one line
`gateway: reload refused: <file>: <field>: <reason>` with the line where the file has one, and
`qb reload` exits 1 with the same reason. The sandbox lets the gateway read the files of its
config file's directory, so an editor may replace the file by rename.
