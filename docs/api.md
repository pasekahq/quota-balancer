# API `/v1`

JSON over HTTP/1.1 on a unix socket (or a forwarded one). One request per connection;
`Content-Length` is required for `POST`; bodies ≤ 64 KiB, headers ≤ 8 KiB. Times are Unix
seconds, utilisation is `0.0..=1.0`, enums are `snake_case`. Requests reject unknown fields;
responses may gain optional fields, which clients ignore. Types are defined in `crates/qb-proto`; example payloads are in `crates/qb-proto/tests/fixtures/`.

| Endpoint | Request | Response |
|---|---|---|
| `POST /v1/pick` | `PickRequest` | 200 `PickResponse` |
| `POST /v1/report` | `ReportRequest` | 200 `ReportResponse`, 403 another client's lease, 404 unknown lease/login/model |
| `GET /v1/state` | — | 200 `StateResponse` |
| `GET /v1/why/{lease_id}` | — | 200 `WhyResponse`, 404 unknown or ended lease |
| `GET /v1/health` | — | 200 `HealthResponse` |
| `GET /v1/roles` | — | 200 `RolesResponse` |
| `POST /v1/agent/next` | `AgentNextRequest` | 200 `AgentJob`, 400 unknown login, 403 not an agent, 429 too many waiting |
| `POST /v1/agent/result` | `AgentResultRequest` | 200 `ReportResponse`, 403 another client's probe, 404 unknown or expired probe |
| `GET /v1/admin/roles` | — | 200 `AdminRoles` with an `ETag`, 403 not an admin client, 500 a config file cannot be read or does not validate |
| `PUT /v1/admin/roles` | `AdminRolesPut`, `If-Match` | 200 `AdminRolesWritten`, 400 body or roles refused, 403 not an admin client, 404 no `roles_file`, 412 stale `If-Match`, 428 no `If-Match`, 500 a file cannot be read or written |
| `POST /v1/admin/reload` | — | 200 `AdminReloadAnswer`, 400 reload refused, 403 not an admin client |

Errors: `{"error": <code>, "message": "..."}` with codes `bad_request` (400), `unauthorized`
(401), `forbidden` (403), `not_found` (404), `method_not_allowed` (405), `length_required`
(411), `precondition_failed` (412), `payload_too_large` (413), `precondition_required` (428),
`too_many_requests` (429), `internal` (500).

## Callers

Before routing, every request is identified and then charged to its caller's token bucket:

1. With `Authorization: Bearer <token>`, the token's SHA-256 is compared in constant time with
   every `bearer_sha256` of `[[clients]]` (see [config.md](config.md)); the matching client is
   the caller. A token that matches none is 401 `unauthorized`, whatever the peer's uid.
2. Without a bearer, the peer's uid from `SO_PEERCRED` names the client with that `uid`; a uid no
   client declares is 401.
3. With no `[[clients]]` declared, every peer without a bearer is the caller `uid:<uid>`; the
   socket's file mode is the boundary.
4. The caller takes one token from its own bucket: `[limits] burst` tokens, refilled at
   `rate_per_s` on a monotonic clock. An empty bucket is 429 `too_many_requests`. A 401 takes
   no token. Without declared clients at most 64 uids keep a bucket; once all 64 are taken, a
   new uid replaces the fullest bucket.

`GET /v1/health` answers a peer that is not identified, without a bucket. The caller's name goes
into the leases it picks and the journal. A report by `lease_id` of a lease another client holds
is 403 `forbidden` and changes nothing; a report by `login` is open to every caller.

## `POST /v1/pick`

```json
{"role": "worker", "difficulty": 2, "expected_minutes": 30, "run_id": "run-0001"}
{"role": "reviewer", "pin": {"vendor": "vendor-b", "model": "model-large", "effort": "high"},
 "avoid_vendor": "vendor-a"}
```

Exactly one of `difficulty` / `pin`. Optional: `resume_of`, `avoid_vendor`, `need` (capabilities),
`expected_minutes`, `run_id`, `on_behalf_of`. `on_behalf_of` names the end client a relaying
caller such as `qb gateway` picks for: 1 to 128 bytes, else 400 `bad_request`. It is kept on the
lease and in the journal; no decision, rate limit or report check reads it.

```json
{"decision": "run", "reason": "spend_before_reset", "lease_id": "l-17", "vendor": "vendor-a",
 "model": "model-large", "effort": "high", "login": "login-1", "tier": 1, "stale": false,
 "quota_snapshot_at": 1800000000}
{"decision": "wait", "reason": "all_exhausted", "retry_after": 1800003600, "stale": true}
{"decision": "dead", "reason": "no_candidates", "stale": false}
```

`reason`: for `run` `spend_before_reset` (requested step), `neighbour_step` (a neighbouring
step, nothing being admissible on the requested one) or `pinned`; for `wait` `all_exhausted`
(every candidate is blocked until a known time) or `leases_full` (a candidate is admissible but
256 leases are live); for `dead` `no_candidates` (unknown role, no step for the difficulty, no
login for any candidate), `no_reset_known` (some candidate is blocked by a window without a
known reset, none by a known time) or `all_dead` (every candidate's login is `auth_dead` or its
model is dead on that login). `tier` is absent for a pin. `stale` is true when a window behind
the answer is older than the snapshot TTL or was never reported; `quota_snapshot_at` is the
oldest report behind a `run`, absent while one of its windows was never reported.

A candidate is admissible when its login is not `auth_dead`, `exhausted` or `rate_limited`, its
model is not dead on the login, and every window keeps `left = 1 − used − reserved − cost` above
0 and at least the role's reserve (dropped inside `T_burn`). `retry_after` is the earliest time
some rejected candidate gets all its blocks back: a window short of quota at its reset, a window
held only by its reserve when `T_burn` starts (`resets_at − t_burn_s + 1`), a window held by
reservations at the login's first lease expiry, a mark at its end. Dead logins and dead models
never set `retry_after`; for `leases_full` it is the first lease expiry.

Every `run` holds a lease until a report releases it or it expires at `now + leases.ttl_s +
60 · expected_minutes`. The lease reserves its cost in every window of the login:
`expected_minutes · cost_per_minute` of the vendor's shortest window, scaled by
`shortest length / window length` for longer windows; without `expected_minutes` it costs 0.
`cost_per_minute` is the candidate's own, else `leases.cost_per_minute` (see
[config.md](config.md)); a pin uses the rate of the role's candidate with the same vendor and
model, if any.

## `POST /v1/report`

```json
{"lease_id": "l-17", "outcome": "ok",
 "windows": [{"name": "five_hour", "utilization": 0.15, "resets_at": 1800018000}]}
{"login": "login-1", "outcome": "usage_limit", "release": true}
```

A report by `lease_id` acts on the lease's login and model (`model` is ignored); a report by
`login` names the model in `model`. `release: true` frees a lease report's lease and its
reservation after the outcome applies; a login report holds no lease and ignores it.

Each entry of `windows` overwrites that window of the login's snapshot (`source = stream`,
`observed_at` = server time). Names the login's vendor does not declare are ignored, and
`length_s` is informational: the configured length counts. Then the outcome applies:

| `outcome` | Effect |
|---|---|
| `ok` | With at least one declared window, `unknown`, `auth_stale` and `auth_dead` become `ok`. |
| `usage_limit`, `rejected` | `exhausted` until the earliest reset of a window at ≥ 0.99 used, else the reset of the vendor's longest window, else one longest-window length from now. |
| `http_401` | `auth_stale`; a 401 on an `auth_stale` login makes it `auth_dead`, which only an `ok` with a declared window clears, such as a report of a session run after re-login. An `auth_stale` login stays pickable. |
| `http_429` | `rate_limited` for `outcomes.rate_limit_backoff_s`. |
| `model_unavailable` | The model is dead on the login for `outcomes.model_unavailable_s`; other models and logins are unaffected. |
| `error` | Nothing. |

Marks end by time only: an `ok` report does not lift `exhausted` or `rate_limited`. Nothing is
applied when the report answers an error: 400 for a `utilization` outside `0.0..=1.0` or a
`model_unavailable` login report without `model`, 404 for an unknown lease or login or a
`model_unavailable` model no ladder declares.

Response: `{"accepted": true, "login_status": "exhausted"}` with `login_status` one of `ok`,
`rate_limited`, `exhausted`, `auth_stale`, `auth_dead`, `unknown`; with several marks the first
of `auth_dead`, `exhausted`, `rate_limited`, `auth_stale` shows.

## `GET /v1/state`

Logins with their status, `dead_until` (end of an `exhausted` or `rate_limited` mark, the later
of the two) and windows (`used`, `reserved`, `resets_at`, `observed_at`, `source` =
`stream|probe|assumed`, `stale`), and live leases (`lease_id`, `login`, `model`, `client`,
`run_id`, `on_behalf_of`, `expires_at`; `run_id` and `on_behalf_of` absent when the pick had
none). `client` is the caller that took the lease, `on_behalf_of` the end client it named. See
`state_response.json`. `reserved` is the sum of the live leases' costs in that window. A window
never reported shows `used = 0`, `observed_at = 0`, `source = assumed`, `stale = true`; once its
`resets_at` has passed it shows `used = 0`, `source = assumed` and no `resets_at`.

## `GET /v1/why/{lease_id}`

Why a live lease was granted, and its login now. See `why_response.json`.

```json
{"lease_id": "l-257", "login": "login-1", "model": "model-small", "client": "client-a",
 "run_id": "run-0001", "expires_at": 1800005400,
 "cost": [{"name": "five_hour", "cost": 0.06}, {"name": "seven_day", "cost": 0.0018}],
 "reason": "spend_before_reset", "login_state": {"login": "login-1", "...": "..."}}
```

The lease fields are those of `GET /v1/state`; `cost` is the fraction the lease reserves in
each window of the login's vendor, in declaration order. `reason` is the `reason` the pick
answered (`spend_before_reset`, `neighbour_step` or `pinned`); it survives a restart and is
absent for a lease replayed from a journal line that does not keep it. `login_state` is the
login's entry of `GET /v1/state` at the same time. A lease id that names no live lease, because
it never existed, was released or expired, is 404 `not_found`. Every caller may ask about every
lease; the request takes a token like any other.

## `GET /v1/health`

`{"status": "ok", "api_version": "v1", "version": "0.0.1", "uptime_s": 12}`

## `GET /v1/roles`

The roles `qbd` runs, as it took them at its start or its last reload (SIGHUP or
`POST /v1/admin/reload`), in the shape of `roles` of `GET /v1/admin/roles`, without its file and
hash: a roles file changed on disk shows only after a reload accepted it. Every identified caller
may read it. See `roles_response.json`:

```json
{"roles": [{"name": "worker",
            "ladder": [{"difficulty": 1, "candidates": [
                         {"vendor": "vendor-a", "model": "model-small", "tier": 1}]}],
            "reserves": []}]}
```

## Agents and probes

`qb agent` connects to the daemon like any client and waits for probe jobs; the daemon never
opens a connection. Only clients listed in `[probe] agents` (see [config.md](config.md)) may
call these endpoints; another caller gets 403 `forbidden` from `next`.

`POST /v1/agent/next` names the logins this agent can probe:

```json
{"logins": ["login-1", "login-2"]}
```

An empty list or a login the config does not declare is 400. The daemon then parks the
connection: it stays open with no server timeout while other clients are served, until one of
the listed logins is due and the daemon answers

```json
{"probe_id": "p-7", "login": "login-1"}
```

Each agent client parks at most one connection and at most 4 are parked in total; a further
`next` is 429 `too_many_requests`. A parked connection the agent closes is dropped.

A login is due when a `pick` considered it as a candidate while one of its windows was stale or
never reported, nothing has reported a window of it since, it is not `auth_dead`, it has no
probe in flight and it is not backing off. With `[probe] enabled = false` no login is ever due.
A job is in flight until its result arrives or 30 seconds pass; a timeout counts as a failed
probe. There is at most one probe in flight per login.

`POST /v1/agent/result` answers the job:

```json
{"probe_id": "p-7", "outcome": "ok",
 "windows": [{"name": "five_hour", "utilization": 0.06, "resets_at": 1800018000}]}
{"probe_id": "p-8", "outcome": "http_429", "retry_after_s": 120}
```

| `outcome` | Effect |
|---|---|
| `ok` | The windows apply as a report's do, with `source = probe` in `GET /v1/state`: names the login's vendor does not declare are ignored, `unknown`, `auth_stale` and `auth_dead` become `ok` when a declared window is among them. The back-off ends. |
| `http_401` | As a report `http_401`: `auth_stale`, then `auth_dead`. It also counts as a failed probe. |
| `http_429` | A failed probe that waits at least `retry_after_s`. |
| `error` | A failed probe. |

After a failed probe the login is not due for a back-off that starts at
`[probe] backoff_initial_s`, doubles with each further failure up to `backoff_max_s` and resets
on `ok`; a 429 waits the longer of `retry_after_s` and that back-off. A login backing off is
probed again only if a `pick` wants it in the meantime. Job timeouts and back-off ends are
deadlines of the daemon's loop, which sleeps without a timeout when nothing is pending.

The response is `{"accepted": true, "login_status": ...}` as for a report. A `probe_id` that is
unknown, already answered or timed out is 404 `not_found`; a probe handed to another client is
403 `forbidden`; a `utilization` outside `0.0..=1.0` is 400. None of them changes anything.

## Admin `/v1/admin/*`

Only a caller identified as a `[[clients]]` entry with `admin = true` ([config.md](config.md))
reaches these endpoints; any other identified caller gets 403 `forbidden` and the request
changes nothing. With no `[[clients]]` declared every caller is `uid:<uid>` and nobody is an
admin. `admin` is read only from the config file, so the admin API cannot grant it. Each call,
refused or not, logs one line naming its caller and status:

```
qbd: admin POST /v1/admin/reload by client-a: 200
```

The line of a `PUT /v1/admin/roles` also names the roles file's hash before and after and the
backup, or that nothing was written (`after` equals `before` then, unless a failed write replaced
the file):

```
qbd: admin PUT /v1/admin/roles by client-a: 200, roles sha256 5f1d… -> 7c2e…, backup /var/lib/qb/roles.toml.bak-1800000360
qbd: admin PUT /v1/admin/roles by client-a: 412, roles sha256 5f1d… -> 5f1d…, nothing written
```

### `GET /v1/admin/roles`

The roles of the config file and its `roles_file` as they are on disk, which may differ from the
running roles until a reload. Both files go through the same parsing and validation as at
startup. `source` is `roles_file` when the config names one, else `config`; `file` is the path of
the file that holds the roles and `sha256` the hex SHA-256 of its bytes, also sent as the strong
`ETag: "<sha256>"`. `roles` lists the roles in file order; `effort` and `cost_per_minute` are
absent when the file has none. See `admin_roles_file.json`:

```json
{"source": "roles_file", "file": "/etc/qb/roles.toml", "sha256": "5f1d…",
 "roles": [{"name": "worker",
            "ladder": [{"difficulty": 1, "candidates": [
                         {"vendor": "vendor-a", "model": "model-small", "tier": 1},
                         {"vendor": "vendor-b", "model": "model-medium", "effort": "low",
                          "tier": 2, "cost_per_minute": 0.004}]}],
            "reserves": [{"difficulty": 1, "window": "five_hour", "fraction": 0.2}]}]}
```

A file that cannot be read or does not validate is 500 `internal` with the message
`cannot read the roles: <file>: <field>: <reason>`, never a partial answer.

### `PUT /v1/admin/roles`

Replaces the `roles_file` ([config.md](config.md#roles)) with the roles of the body and makes
them the running roles. The body is `AdminRolesPut`, the `roles` of `GET` in the same shape,
unknown fields refused at every level; `If-Match` carries the hash `GET` answered, quoted as in
the `ETag` or bare. See `admin_roles_put.json`:

```json
{"roles": [{"name": "worker",
            "ladder": [{"difficulty": 1, "candidates": [
                         {"vendor": "vendor-a", "model": "model-small", "tier": 1}]}],
            "reserves": [{"difficulty": 1, "window": "five_hour", "fraction": 0.2}]}]}
```

A config without `roles_file` is 404 `not_found` and nothing is written. `qbd` reads the roles
file again: no `If-Match` is 428 `precondition_required`, one that is not the file's current hash
412 `precondition_failed`, so an edit by hand since the `GET` is detected. A body that does not
decode is 400 `bad_request`.

The roles are rendered as the whole file: one `[[roles]]` table per role in body order, each
followed by its `[[roles.ladder]]` and `[[roles.reserves]]` tables, keys in the order of the
`GET` shape, strings as escaped TOML basic strings, `fraction` and `cost_per_minute` as floats
that parse back to the same number. Comments and the layout of the old file are not kept. An
empty `roles` or `ladder` renders no table. The candidate goes through the parser and validation
of startup together with the config file on disk, and must change nothing a reload refuses
([config.md](config.md#reloading-roles-and-clients)); otherwise the answer is 400 `bad_request`
with the message `roles refused: <file>: <field>: <reason>`, the line being the candidate's, for
example ``roles[0].ladder[0].candidates[0].vendor: undeclared vendor `vendor-z` (line 7)``,
``roles[1].name: duplicate name `worker` (line 11)``, ``missing field `roles` (line 1)`` for an
empty `roles`, or ``clients[0].role: undeclared role `worker` (line 22)`` of the config file for
a body that drops a role a client names.

On success the old file is copied to `<roles_file>.bak-<unix s>`, `-<n>` appended when a backup
of that second exists, with mode 0600; the candidate is written atomically with mode 0600
(temporary file in the same directory, fsync, rename, fsync of the directory) and installed by
the reload of `POST /v1/admin/reload`, logging `qbd: reloaded …`: live leases, login states,
windows and marks stay, and the next `pick` follows the new ladders. The answer is
`AdminRolesWritten` with the hash of the file now on disk:

```json
{"sha256": "7c2e…", "backup": "/var/lib/qb/roles.toml.bak-1800000360"}
```

A candidate equal to the file byte for byte is not written: the answer is 200 with the file's
hash and no `backup`, no backup is made and nothing is reloaded. A file that cannot be read or
written is 500 `internal`. On every refusal the file, its backups and the running roles stay as
they were, with one exception: a write that fails after the rename replaced the file, or a reload
that refuses the written file, is 500 `internal` with the message `<file> was replaced but not
installed: <error>; the old file is kept as <backup>`. The running roles stay, the file on disk
is the candidate and the backup is kept, so a reload installs the candidate and the backup
restores the old file. `qbd` removes the new backup only when a failed write left the file
unchanged, and no other backup.

### `POST /v1/admin/reload`

Runs the reload SIGHUP runs ([config.md](config.md#reloading-roles-and-clients)); the body is
ignored. A config that is taken answers `{"roles": 2, "clients": 3}`, the counts of the new
config, and logs the same `qbd: reloaded …` line as SIGHUP. A refused one is 400 `bad_request`
with the message `reload refused: <file>: <field>: <reason>`, naming the line where the file has
one, and nothing changes.

## Model gateway `/v1/model/*`

`qb gateway` serves this part of the contract on its own unix socket, not on `qbd`'s. Decisions
and limits: [ADR 0001](adr/0001-model-gateway.md); machine-readable form:
[`openapi-gateway.json`](openapi-gateway.json); config: [config.md](config.md#gateway-config).
Types are in `crates/qb-proto/src/gateway.rs`, examples in
`crates/qb-proto/tests/fixtures/gateway_*`.

| Endpoint | Request | Response |
|---|---|---|
| `POST /v1/model/turn` | `TurnRequest` | 200 chunked NDJSON of `StreamEvent`; a rejection is an `Error` with 400, 401, 411, 413 or 429 |
| `GET /v1/model/routes` | — | 200 `RoutesAnswer` |
| `GET /v1/model/ladder?route=<alias>` or `?role=<role>` | — | 200 `LadderAnswer`, 400 a bad query or a pin or chain route, 401 no client token (loopback), 403 a route or role outside a named client's `routes` or the unnamed client token (loopback), 404 an unknown route or role, a role `qbd` does not run or a step it lacks, 503 `qbd` is unreachable |
| `POST /v1/model/cancel` | `CancelRequest` | 200 `CancelAnswer`, 403 another caller's turn, 404 no such running turn |
| `POST /v1/model/reload` | — | 200 `ReloadAnswer`, 400 refused, 403 a caller other than the gateway's own uid |
| `GET /v1/model/spend` | — | 200 `SpendAnswer`, 403 a caller other than the gateway's own uid |
| `POST /v1/model/spend/reset` | `SpendReset` | 200 `LoginSpend`, 400 a login without `spend_cap`, 403 a caller other than the gateway's own uid, 500 the spend file could not be written |
| `GET /v1/model/audit` | — | 200 `AuditAnswer`, 400 a bad query, 403 a caller other than the gateway's own uid, 404 no `audit_file` |
| `GET /v1/model/usage` | — | 200 `UsageAnswer`, 400 a bad query or more than 10 000 rows, 403 a caller other than the gateway's own uid, 404 no `[usage]` |
| `POST /v1/model/clients/{name}/rotate` | — | 200 `ClientRotateAnswer`, 403 a caller other than the gateway's own uid, 404 no such named client, 409 a client with `token_sha256`, 500 a file could not be written |
| `GET /v1/model/config/routes` | — | 200 `ConfigRoutes` with an `ETag`, 403 a caller other than the gateway's own uid, 500 the config file cannot be read or does not validate |
| `PUT /v1/model/config/routes` | `ConfigRoutesPut` with `If-Match` | 200 `ConfigRoutesWritten`, 400 a body or candidate file that does not validate, 403 a caller other than the gateway's own uid, 412 `If-Match` is not the file's hash, 428 no `If-Match`, 500 a file could not be read or written |
| `POST /v1/model/logins/{name}/key` | `LoginKey` | 200 `LoginKeyAnswer`, 400 a body or key that does not validate, 403 a caller other than the gateway's own uid, 404 no such login, 409 a login that is not `api_key`, 413 a body over 8 KiB, 500 a file could not be read or written |
| `POST /v1/model/logins/{name}/oauth/start` | — | 200 `LoginOauthStarted`, 400 a request with a body, 403 a caller other than the gateway's own uid, 404 no such login, 409 an `api_key` login, 500 the random source failed |
| `POST /v1/model/logins/{name}/oauth/code` | `LoginOauthCode` | 200 `LoginOauthSigned`, 400 a body that does not validate or a paste without a code or with another state, 403 a caller other than the gateway's own uid, 404 no such login, 409 an `api_key` login, no live sign-in or a login changed since the start, 413 a body over 8 KiB, 502 the token endpoint refused the code or could not be asked, 500 a file could not be read or written |
| `GET /v1/admin/roles` | — | 200 `AdminRoles` with an `ETag`, as `qbd` answers it; 403 a caller other than the gateway's own uid; `qbd`'s refusal; 503 `qbd` is unreachable |
| `PUT /v1/admin/roles` | `AdminRolesPut` with `If-Match` | 200 `AdminRolesWritten`, as `qbd` answers it; 403 a caller other than the gateway's own uid; `qbd`'s refusal; 503 `qbd` is unreachable |
| `POST /v1/admin/reload` | — | 200 `AdminReloadAnswer`, as `qbd` answers it; 403 a caller other than the gateway's own uid; `qbd`'s refusal; 503 `qbd` is unreachable |
| `GET /v1/health` | — | 200 `HealthResponse`, as `qbd` answers it |
| `POST /v1/messages` | Anthropic Messages request | Messages SSE or one Messages body; errors in the Messages error format ([anthropic.md](anthropic.md#the-v1messages-front)) |
| `POST /v1/chat/completions` | OpenAI Chat Completions request | Chat Completions SSE or one `chat.completion` body; errors in the OpenAI error format ([openai.md](openai.md#serving-the-fronts)) |
| `POST /v1/responses` | OpenAI Responses request | Responses SSE or one `response` object; errors in the OpenAI error format ([openai.md](openai.md#serving-the-fronts)) |

Framing is `qbd`'s: HTTP/1.1, one request per connection, head ≤ 8 KiB, `Content-Length`
required, chunked request bodies refused. The body of `POST /v1/model/turn` and of a `POST` to
an HTTP front (`/v1/messages`, `/v1/chat/completions`, `/v1/responses`) may be up to the config's
`max_request_bytes` (default 8 MiB), that of a `POST` to `/v1/model/logins/{name}/key` or
`/v1/model/logins/{name}/oauth/code` up to 8 KiB, every other body up to 64 KiB; a request whose head and body have not arrived within 10 s is dropped
without an answer. `/v1/model/*` requests reject unknown fields. Every non-200 answer of the
gateway has the body `Error` below, whose `class` is authoritative and whose status is
informative, except the answers of an HTTP front to a caller it serves, which use the error
format of that front's API.

**Callers.** The peer's uid from `SO_PEERCRED` must be the gateway's own uid or the `uid` of a
`[[clients]]` entry of the gateway config; any other peer gets 401 `auth` before its request
is read. The socket file is
0600, or 0660 with `socket_mode = 0o660`. The optional loopback listener (`fronts.listen`)
serves only the HTTP fronts and `GET /v1/model/ladder`, to requests with a client token of
`[fronts]` ([config.md](config.md#gateway-config), [openai.md](openai.md#serving-the-fronts)): the unnamed
`fronts.token_sha256`, whose turns run as the caller `client-token`, or a named
`[[fronts.clients]]` entry, whose turns run as its `name`; a named client's token is the one
its `token_sha256` hashes or the one in its `token_file`, and after a rotation also the previous
one within its grace. A named client with `routes` that asks
for a model resolving (through `fronts.models` or as an alias) to a route outside that list gets
403 in its front's error format before any pick: Messages `permission_error`, OpenAI
`permission_error` with code `route_not_allowed`, the message
``client `<name>` may not use route `<alias>` ``. The ladder read is for named clients only
([`GET /v1/model/ladder`](#get-v1modelladder)); every other path of the listener is 404 in the
Messages or OpenAI error format.

**Connections.** The gateway serves at most `max_turns` + 2 connections at once; one more gets
429 `overloaded` with `retry_after: 1` before its request is read. A loopback peer counts against
that cap only once its head showed a client token (429 in its front's format when the cap is
full then); before that it holds one of 4 slots of its own, also answered 429 when full, and must
send its head within 2 s or is dropped without an answer. Peers without a token never hold the
slots of the unix socket's clients. Each refused loopback request logs one warning line with
its reason (`token`, `path` or `busy`), method and path, or with the reason `route`, the client
name and the route alias; never a header value.

### `POST /v1/model/turn`

```json
{"route": "chat", "system": "You are terse.",
 "messages": [{"role": "user", "content": [{"type": "text", "text": "Hi"}]}],
 "max_tokens": 1024, "effort": "medium", "session_key": "session-1", "cache": "auto",
 "request_id": "turn-0001"}
```

Required: `route` (an alias of the gateway config, `^[a-z][a-z0-9_-]{0,63}$`), `messages` (at
least one, each with at least one block), `max_tokens` (≥ 1) and `request_id`
(`^[A-Za-z0-9_-]{1,64}$`, unique among running turns). Optional: `system`, `tools`
(`{name, description, input_schema}`, names unique, and optional `native`, below), `effort`
(`low|medium|high|max`), `session_key` (1 to 128 bytes), `cache` (`auto`).

The effort an attempt sends is the request's `effort`, else the picked candidate's (on a pinned
route the pin's, on a chain route the step's). On a route with `client_effort = "ignore"`
([config.md](config.md#gateway-config)) it is the pick's only, or none when the pick has none;
the request's `effort` is still validated. The HTTP fronts' `output_config.effort`,
`reasoning.effort` and `reasoning_effort` are the request's `effort` here.

A message has `role` (`user|assistant|system`) and `content`, a list of blocks, each one flat
object with `type`. At least one message is `user` or `assistant`. A `system` message holds
`text` blocks only: an instruction from that point
of the conversation on (Anthropic's mid-conversation system message, OpenAI's `developer`
message). An upstream keeps it in place where its vendor accepts one there and otherwise adds
its text to the system prompt ([anthropic.md](anthropic.md), [openai.md](openai.md)).

A tool's `native` is `{api, spec, elsewhere}`: the declaration `spec` as a client sent it in the
vendor API `api` (`openai_responses`) when it is not a plain function tool there. An upstream of
that API sends `spec` as is; another follows `elsewhere`: `function` offers the tool as a function
of `name`, `description` and `input_schema`, `omit` leaves it out, `refuse` fails the attempt with
`bad_request`.

Block types:

| `type` | Fields |
|---|---|
| `text` | `text` |
| `image` | `media_type` (`image/png|jpeg|gif|webp`) and `base64`; `path` is part of the shape but refused: the gateway reads no file a client names |
| `tool_use` | `id`, `name`, `input` (object) |
| `tool_result` | `id`, `content`, optional `is_error` |
| `thinking` | `vendor`, `opaque`, echoed back as received |

A block may carry only its own fields. The gateway drops `thinking` blocks whose `vendor` is not
the vendor it picks for an attempt, and passes tool-call ids through unchanged.

Before the turn starts the request is checked; a failure is answered at once: 400
`bad_request` (invalid JSON, unknown field, broken rule, unknown route alias, an image by
`path`, a `request_id` already running), 413 over `max_request_bytes`, 429 `overloaded` with
`retry_after: 1` when `max_turns` turns run already.

An admitted turn is answered `200` with `Transfer-Encoding: chunked` and
`Content-Type: application/x-ndjson`, one event per line. The response head goes out together
with the first event:

```json
{"type":"route","route":{"vendor":"vendor-a","model":"model-large","login_label":"login-1","lease":"l-17"}}
{"type":"thinking","thinking":{"vendor":"vendor-a","opaque":"..."}}
{"type":"text_delta","text":"Hello"}
{"type":"tool_call","tool_call":{"id":"call_02","name":"read","input":{"path":"notes.md"}}}
{"type":"usage","usage":{"input":120,"output":48,"cache_read":2048,"cache_write":0}}
{"type":"stop","reason":"tool_use"}
```

`route` comes with the first content event of the attempt that answers; `usage` replaces any
earlier one; `stop.reason` is `end`, `tool_use`, `max_tokens` or `refusal`. A stream ends with
exactly one `stop` or `error`; one that ends without either was cut by a transport failure.

#### Attempts and rotation

Each attempt is one `POST /v1/pick` to `qbd` with the route's target (`role` and `difficulty`,
or `role` and a `pin` of `vendor`, `model` and `effort`, on a chain route the current step's
pin), `run_id` = `session_key` or else
`request_id`, `on_behalf_of` = the turn's caller name (`uid:<n>`, a `[[clients]]` name,
`client-token` or a `[[fronts.clients]]` name), `resume_of` = `session_key` when given,
`expected_minutes` of the route, and
`avoid_vendor` after a vendor failure on a ladder or pin route. A `wait` caused by `resume_of` is asked again once
without it. `qbd` accepts `resume_of` but does not use it yet, so `session_key` only names the
run: turns of one session are not kept on one login for the prompt cache. The picked login's credential entry gives the credential kind, which selects the
vendor adapter. After the attempt the gateway reports to `qbd` with the lease,
`release: true`, the windows the vendor showed, and the outcome:

| Attempt ended with | `qbd` outcome | before any event reached the client |
|---|---|---|
| a stream, finished or not | `ok` | — |
| usage limit | `usage_limit` | next pick; the login is not tried again in this turn |
| 429 without usage limit | `http_429` | as above |
| 401 | `http_401` | an OAuth login first refreshes its token and retries once on the same lease; then as above, and the login is dead (below) |
| model unavailable to the login | `model_unavailable` | as above |
| unreadable or invalid credential file, or a refresh token the vendor refused | `http_401` | as above, and the login is dead (below) |
| overload, 5xx, transport failure | `error` | one more pick with `avoid_vendor`; if it finds nothing, this failure ends the turn. On a chain route: the next step |
| invalid request, context too long | `error` | the turn ends |
| no call: the login reached its `spend_cap` | `error`, with the `spend` window at 1.0 | as after a usage limit |

Once an event has reached the client the gateway never retries: a failure ends the stream
with an `error` event. A turn is bounded by `max_attempts` attempts (default 4), picks whose
login is tried. A 401 that the
one refresh did not cure, or an unusable credential file, does not pass by itself: after the
lease report the gateway also sends `POST /v1/report {"login", "outcome": "http_401"}`, which
makes the login `auth_dead` in `qbd`, so the next pick of the same turn skips it. A login that
failed in a turn is never called again in that turn: when a pick still returns it, the lease is
released with `error`, and on a ladder or pin route the turn ends with the last failure's class,
as it does when the pick after a failure answers `dead`. So a key login that answers 401 gets
one call per turn, an OAuth login two (before and after its one refresh).

A chain route walks its steps in order, starting with the first. Until an event has reached
the client, the turn moves to the next step without an adapter call when `qbd` answers the
step's pick with `wait` or `dead`, with a login that already failed in the turn, or with a login
the gateway config has no credential entry or adapter for, and after a vendor failure of the
step; after a login failure it picks the same step again, so another login of that vendor may
run. When no step is left the turn ends with `error`: `tried` lists
every attempt, and the class is `quota_exhausted` with the nearest `resets_at` of the steps
when every step was spent (a usage limit) or waiting, else the class of the last step's end.

Across vendors, on a chain step or a re-pick with `avoid_vendor`, a turn keeps these guarantees:

- Thinking of another vendor than the picked one is dropped from the request before every
  adapter call; the picked vendor's own thinking goes back to it.
- Tool ids pass unchanged in both directions: a `tool_use` or `tool_result` id reaches every
  vendor as the client sent it, and a vendor's tool call id reaches the client as the vendor
  sent it. The one exception: Anthropic accepts a tool id only when it matches
  `^[a-zA-Z0-9_-]+$`, so its adapter sends any other id (some Chat Completions providers issue
  ids like `functions.read:0`) as `qbx_` and the lowercase hex of its bytes, the same in the
  `tool_use` and its `tool_result`. Anthropic answers with ids of its own, so a client never
  sees the rewritten form.
- A fallback happens only before the first event reached the client; after it a failure ends
  the turn with `error`, `tried` lists every attempt of the turn, and no later step is called.
- A login that failed in the turn is not picked again in it (above).

#### Errors

```json
{"type":"error","error":{"class":"quota_exhausted","retryable":true,"resets_at":1800018000,
 "tried":[{"vendor":"vendor-a","model":"model-large","login_label":"login-1","class":"quota_exhausted"}]}}
```

`Error` has `class`, `retryable` and optionally `retry_after` (seconds), `resets_at` (Unix
time), `tried` (the attempts of the turn in order, each with `vendor`, `model`, `login_label`
and `class`) and `message` (never a credential).

A login's 429 with a `retry-after` before the first event moves the turn to the next login, and
qbd hears only the outcome. When the turn then ends with a retryable error that has no
`retry_after` of its own, it carries the soonest such wait as `retry_after` (seconds left, at
least 1), and its `resets_at`, if any, is no earlier than the end of that wait.

| `class` | When | `retryable` |
|---|---|---|
| `quota_exhausted` | `qbd` answered `wait`: every candidate waits for a reset or back-off; `resets_at` is the `wait`'s `retry_after`, the nearest time one becomes usable. On a chain route: every step was spent or waiting, `resets_at` the nearest of them | true |
| `no_route` | `qbd` answered `dead`; on a ladder or pin route only before an attempt of the turn failed | false |
| `auth` | the last login's credential was rejected or unusable; or, as a 401 answer, the caller is not allowed | false |
| `overloaded` | the vendor asked to back off (`retry_after`), a 429 of the last login, or the gateway's caps | true |
| `unavailable` | the vendor failed, `qbd` is unreachable, a token refresh could not reach the vendor, or the picked login has no credential entry or adapter (on a chain route only when it is the last step) | true, false for a configuration error |
| `bad_request` | the vendor or the gateway refused the request | false |
| `context_too_long` | the conversation does not fit the model | false |
| `cancelled` | `POST /v1/model/cancel` stopped the turn | false |

### `GET /v1/model/routes`

```json
{"routes": [{"alias": "chat", "state": "ready"},
            {"alias": "fast", "state": "exhausted", "vendor": "vendor-b", "model": "model-b",
             "resets_at": 1800018000}]}
```

Aliases sorted, each with the state of the logins it can run on in `qbd`'s `GET /v1/state`: the
gateway's logins of the pinned vendor, or every login of the gateway for a ladder route. A login
waits when its status is `exhausted` or `rate_limited`, until its `dead_until`, or when its
status is `ok`, `unknown` or `auth_stale` but a window of it is at `used` ≥ 1.0 with a
`resets_at`, until the latest such reset, since `qbd` does not pick it before (a capped login's
`spend` window, [config.md](config.md#spend-caps)). The route is `ready` when one login is
`ok`, `unknown` or `auth_stale` and does not wait; else `exhausted` when one waits, with
`resets_at` the earliest end of the waits; else `unavailable` (all `auth_dead`, none, or `qbd`
unreachable). `vendor` and `model` are a pinned route's. A chain route applies the same rule to
the logins of each step's vendor: it is `ready` with the `vendor` and `model` of its first
step that is `ready`; else `exhausted` with the earliest `resets_at` over its `exhausted`
steps when one is, else `unavailable`, without `vendor` and `model`. It takes no lease.

### `GET /v1/model/ladder`

The ladder steps a caller's ladder routes run on, read from `qbd` without a pick or a lease, for
a client that wants to know which model and effort a step runs before it starts work. The query
names exactly one of:

- `route=<alias>`: a ladder route (one with `difficulty`); the answer holds its role's step of
  that difficulty. A pin or chain route is 400 `bad_request`, an alias no route has 404.
- `role=<role>`: every step of that `qbd` role that at least one ladder route the caller may use
  names; a role no ladder route names is 404.

Neither, both, or another parameter is 400. The roles are those `qbd` runs (`GET /v1/roles`), so
a role or a route's step `qbd` does not run is 404; the states come from `qbd`'s
`GET /v1/state`. Either read failing is 503 `unavailable`. See `gateway_ladder_answer.json`:

```json
{"role": "worker",
 "steps": [
  {"difficulty": 1, "routes": ["worker-1"], "candidates": [
   {"vendor": "vendor-a", "api": "anthropic", "model": "model-small", "tier": 1, "state": "ready"},
   {"vendor": "vendor-b", "api": "chat_completions", "model": "model-medium", "effort": "low",
    "tier": 2, "state": "exhausted", "resets_at": 1800018000}]}]}
```

`steps` are sorted by `difficulty`, each with `routes`, the sorted ladder route aliases of the
caller that name it, and its `candidates` in ladder order. A candidate's `api` is the API family
(`anthropic`, `openai`, `chat_completions`) of the gateway's first login, in config order, that
`qbd` puts on its vendor, absent when the gateway holds none; `effort` is absent when the ladder
has none. `state` and `resets_at` follow the rule of `GET /v1/model/routes` over the gateway's
logins of the candidate's vendor: `ready`, `exhausted` with the earliest end of the waits, or
`unavailable`.

On the unix socket every caller reads every route. On the loopback listener only a named
`[[fronts.clients]]` token may, within its `routes`: a route outside them, or a role none of them
names, is 403 `auth` with the message ``client `<name>` may not use route `<alias>` `` or
``client `<name>` may not use a route of role `<role>` ``, before `qbd` is asked; the unnamed
`fronts.token_sha256` is 403 `auth`, a request without a client token 401 `auth`. Every error of
this endpoint is an `Error` on both listeners, and every 403 logs one warning line naming the
client.

### `POST /v1/model/cancel`

`{"request_id": "turn-0001"}` stops that running turn of this caller: the adapter's read is
interrupted, the lease is released, the stream ends with an `error` of class `cancelled`, and
the answer `{"cancelled": true}` comes once the turn has ended (at most 5 s). 404 when no turn
with that id runs, 403 when another caller started it. A client that closes its stream cancels
its turn the same way, without an event.

### `POST /v1/model/reload`

The gateway reads its config file again, as SIGHUP makes it do; `qb --socket <gateway socket>
reload` sends it. Only the gateway's own uid may: any other caller gets 403 `auth`. The body is
ignored. A new config that parses and validates and changes no restart-only field serves every
later turn, and the answer is `{"routes": 3, "logins": 2}`, its counts. Otherwise the answer is
400 `bad_request` with the message `reload refused: <file>: <field>: <reason>`, naming the line
where the file has one, and the running config stays. What a reload changes:
[config.md](config.md#reload).

### `GET /v1/model/spend` and `POST /v1/model/spend/reset`

The month's spend of the logins with a `spend_cap` ([config.md](config.md#spend-caps)). Only the
gateway's own uid may call them: any other caller gets 403 `auth`. `qb --socket <gateway socket>
spend` sends the `GET`, which answers each capped login of the current config in config order:

```json
{"logins": [{"login": "key-1", "spent_usd": 12.5, "cap_usd": 50.0, "period_end": 1800000000}]}
```

`period_end` is the next UTC month's start, when the count starts again from zero. `qb --socket
<gateway socket> spend reset <login>` sends `{"login": "key-1"}`: the login's count becomes zero,
the gateway reports its `spend` window to `qbd` so the login runs again, and the answer is the
login's entry as above. A login without a `spend_cap` in the current config is 400
`bad_request`; a spend file that cannot be written is 500 `unavailable`, with the count zero
until the next restart.

### `GET /v1/model/audit`

With the top-level config key `audit_file` ([config.md](config.md#gateway-config)) the gateway
appends one JSON line per admin action to that file, creating it with mode 0600, in one
`write` per line. A line is an `AuditEntry`:

```json
{"at": 1800000000, "actor": "uid:1000", "action": "reload", "object": "/etc/qb/gateway.toml",
 "result": "ok", "config_sha256_before": "5f0e…", "config_sha256_after": "a1b2…"}
```

| Field | Meaning |
|---|---|
| `at` | Unix time of the action |
| `actor` | `uid:<n>` for a unix socket caller, `signal` for a SIGHUP reload |
| `action` | `reload`, `spend_reset`, `client_rotate`, `config_routes` (a `PUT /v1/model/config/routes` with `routes`, or whose body does not parse), `config_spend_caps` (one with `spend_caps` only), `login_key` (a `POST /v1/model/logins/{name}/key`), `login_oauth_start` (a `POST /v1/model/logins/{name}/oauth/start`), `login_oauth_code` (a `POST /v1/model/logins/{name}/oauth/code`), `admin_roles` (a `PUT /v1/admin/roles`) or `admin_reload` (a `POST /v1/admin/reload`) |
| `object` | the config file of a reload or a config edit, the login of a spend reset, a key replacement or a sign-in, the client of a rotation, `qbd_socket` of a request to `qbd`'s admin API; absent when a refused request named none |
| `result` | `ok` when the action answered 200, else `refused` |
| `reason` | with `refused`: the refusal's message, such as the reload's `<file>: <field>: <reason>` |
| `config_sha256_before`, `config_sha256_after` | a reload's hex SHA-256 of the config file serving before and after it, a config edit's of the file on disk before and after it; equal when it was refused, unless the edit replaced the file but could not install it. An `admin_roles` that went through: the `If-Match` it sent and the `sha256` `qbd` answered, the hashes of `qbd`'s roles file before and after it; absent on a refused one |
| `backup` | a config edit that wrote the file, or that replaced the file but could not install it: path of the copy of the file it replaced; a key replacement or a sign-in's code that went through or failed after replacing the file: path of the copy of the credential file it replaced, absent when there was none; an `admin_roles` that went through: the `backup` `qbd` answered, absent when it wrote nothing |
| `token_sha256_prefix` | a rotation that went through: the first 12 hex characters of the new token's SHA-256 |
| `key_sha256_prefix` | a key replacement that went through: the first 12 hex characters of the new key's SHA-256 |

Every reload, by `POST /v1/model/reload` or SIGHUP, and every `POST /v1/model/spend/reset`,
`POST /v1/model/clients/{name}/rotate` and `PUT /v1/model/config/routes` that reaches its handler
is recorded, refusals included: another uid's 403, a missing or stale `If-Match`, a body that does
not parse, a config that does not validate, an unknown client. Every request to
`/v1/model/logins/{name}/key`, `/v1/model/logins/{name}/oauth/start` and
`/v1/model/logins/{name}/oauth/code` of a caller of the gateway is recorded, also one whose body
was too large or did not arrive and one with another method. Every `PUT /v1/admin/roles` and
`POST /v1/admin/reload` of a caller of the gateway is recorded, another uid's 403, `qbd`'s
refusals and an unreachable `qbd` included; `GET /v1/admin/roles` is not. A peer that is not a caller of the gateway gets its 401
before any handler and leaves no line. No field holds a token, key or credential content. A
line that cannot be appended is logged at error priority with the path; the action's answer
stays as it was. The gateway neither rotates nor trims the file.

`GET /v1/model/audit?since=<unix s>&limit=<n>` reads the lines back, only for the gateway's own
uid (any other caller gets 403 `auth`); the loopback listener does not serve it. It answers the
first `limit` entries (default 100, 1 to 1000) with `at` ≥ `since` (default 0), oldest first,
and in `skipped` the number of lines of the file that do not parse as an entry or are longer than
64 KiB, which are left out:

```json
{"entries": [{"at": 1800000120, "actor": "uid:1000", "action": "spend_reset",
              "object": "key-1", "result": "ok"}],
 "skipped": 0}
```

A missing file answers no entries. Another query parameter, one given twice or a value out of
range is 400 `bad_request`; without `audit_file` the answer is 404 `bad_request`.

### `POST /v1/model/clients/{name}/rotate`

Writes a fresh token to the `token_file` of the `[[fronts.clients]]` entry `name`, the name as
the config has it ([config.md](config.md#client-token-rotation)). Only the gateway's own uid may:
any other caller gets 403 `auth`; the loopback listener answers 404. The body is ignored. The
gateway takes 32 bytes from the kernel's random source, writes them base64url-encoded to the
file atomically with mode 0600, and accepts the new token from the next loopback connection.
The previous token stays accepted until `grace_until`, the time of the rotation plus
`fronts.rotate_grace_s`, across reloads and restarts. The answer never holds the token:

```json
{"client": "client-a", "token_sha256_prefix": "5d35a058cf51", "grace_until": 1800003600}
```

`token_sha256_prefix` is the first 12 hex characters of the new token's SHA-256. An unknown
name is 404 `bad_request`, a client with `token_sha256` 409 `bad_request`. A file that cannot be
written is 500 `unavailable`: the token file and the accepted tokens stay as they were.

### `POST /v1/model/logins/{name}/key`

Writes a new key to the credential file of the `[[logins]]` entry `name` of the running config,
an `api_key` login ([config.md](config.md#replacing-a-key)). Only the gateway's own uid may: any
other caller gets 403 `auth`; the loopback listener answers 404. The body, at most 8 KiB, holds
the key and nothing else, unknown fields refused:

```json
{"key": "synthetic-key-0002"}
```

The key must be 1 to 4096 bytes of visible ASCII: no whitespace, control character or other
byte. The gateway holds its reload lock for the request, so reloads, config edits and client
token rotations wait. It copies the credential file, when there is one, to
`<file>.bak-<unix s>`, `-<n>` appended when a backup of that second exists, with mode 0600 and
never over a file, then writes `{"type": "api_key", "key": "<key>"}` atomically with mode 0600
(temporary file in the same directory, fsync, rename, fsync of the directory). The login's next
attempt reads the new file; turns need no reload or restart. The request body, the key and the
file's bytes are zeroized after use. The answer never holds the key:

```json
{"login": "key-1", "backup": "/etc/qb/credentials/key-1.json.bak-1800000480",
 "key_sha256_prefix": "5bcc977b51d5"}
```

`backup` is `null` when the login had no credential file. `key_sha256_prefix` is the first 12
hex characters of the new key's SHA-256; the audit line and the log line show it too.

An unknown login is 404 `bad_request`, a login of another `kind` 409 `bad_request`, a body that
is not JSON 400 `bad_request` naming the line and column, a body of another shape 400
`bad_request` ``the body must be one object with the string `key` only``, a key that breaks a rule
400 `bad_request` naming the rule, a body over 8 KiB 413 `bad_request`; no message quotes the key
or the body. A file that cannot be read or a backup that cannot be written is 500 `unavailable`
and the old file stays in force. A write that fails before the rename is 500 `unavailable` with
`cannot write <file>: <error>; the old file stays`, the new backup removed; one that fails after
the rename replaced the file is 500 `unavailable` with `<file> was replaced but the write failed:
<error>; the old file is kept as <backup>`, the backup kept and the new key in force. The gateway
removes no other backup.

### `POST /v1/model/logins/{name}/oauth/start` and `.../oauth/code`

Sign the `oauth_anthropic` or `chatgpt_oauth` entry `name` of the running config in again with
PKCE ([config.md](config.md#signing-in-through-the-gateway)), the steps of `qb login` in two
requests. Only the gateway's own uid may: any other caller gets 403 `auth`; the loopback listener
answers 404.

`POST .../oauth/start` takes no body. The gateway draws a verifier and a state from the kernel's
random source and answers the vendor's authorize URL with the verifier's S256 challenge and the
state, what to paste back and when the sign-in expires, 600 s later:

```json
{"login": "login-1", "url": "https://vendor-a.example/oauth/authorize?...&code_challenge=...&code_challenge_method=S256&state=...",
 "paste": "code_state", "expires_at": 1800000600}
```

`paste` is `code_state` for an `oauth_anthropic` login, the `code#state` the vendor's page shows
after the sign-in, and `redirect_url` for a `chatgpt_oauth` login, the full address of the
localhost page the browser then fails to load. The verifier and the state stay in the gateway's
memory, zeroized when the sign-in ends; the state leaves the gateway only inside the URL. A login
has at most one pending sign-in: a new start replaces it. An unknown login is 404 `bad_request`,
an `api_key` login 409 `bad_request`, a request with a body 400 `bad_request`.

`POST .../oauth/code` takes what the operator pasted, at most 8 KiB, unknown fields refused;
surrounding whitespace is ignored:

```json
{"pasted": "synthetic-code-0001#c3ludGhldGljLXN0YXRlLTAwMDEtcGFkZGluZy1wYWRkaW5n"}
```

Without a pending sign-in of the login, or after its `expires_at`, the answer is 409
`bad_request`. A paste whose state is not the one sent, or that holds no code, is 400
`bad_request` and the sign-in stays pending. Otherwise the gateway takes the sign-in and
exchanges the code at the login's `token_url`, else the vendor's token endpoints, as `qb login`
does; the sign-in is gone whatever the exchange's outcome. A token endpoint that refuses the code
is 502 `auth`, one that cannot be asked or whose answer lacks a token or the account 502
`unavailable`; the message names the endpoint, the status and the OAuth error code, never a value.
A login whose `kind` or `credentials` a reload changed since the start is 409 `bad_request`.

The gateway then holds its reload lock and the login's refresh lock and writes the new tokens as
`POST /v1/model/logins/{name}/key` writes a key: the old file, when there is one, copied to
`<file>.bak-<unix s>` with mode 0600, the new file in the format of
[config.md](config.md#gateway-config) written atomically with mode 0600, the same 500 answers when a file
cannot be read or written. The exchange itself runs outside the reload lock. The login's next
attempt sends the new token; turns need no reload or restart:

```json
{"login": "login-1", "backup": "/etc/qb/credentials/login-1.json.bak-1800000300"}
```

`backup` is `null` when the login had no credential file. The request body, the code, the
verifier, the state and the tokens are zeroized after use; no answer, log line, audit line or
usage line holds the code, the verifier, the state, a token or the account id.

### `GET` and `PUT /v1/model/config/routes`

The `[[routes]]` items and the `api_key` logins' `spend_cap`s of the gateway's config file
([config.md](config.md#gateway-config)), read and edited as JSON. Only the gateway's own uid may
call them: any other caller gets 403 `auth`; the loopback listener answers 404. Both read the
file as it is on disk, which may differ from the running config until a reload.

`GET` answers the file's hex SHA-256, its items in file order, each key as the file has it and a
chain as an array of steps, and `spend_caps`: every `api_key` login by name with its `spend_cap`
in USD, `null` for one without; logins of other kinds are not listed. The same hash goes out as
the strong `ETag: "<sha256>"`:

```json
{"sha256": "a1b2…",
 "routes": [{"alias": "chat", "role": "gateway", "difficulty": 1, "expected_minutes": 10,
             "client_effort": "ignore"},
            {"alias": "pinned", "role": "gateway", "vendor": "vendor-b", "model": "model-b"},
            {"alias": "chain", "role": "gateway",
             "chain": [{"vendor": "vendor-a", "model": "model-a"},
                       {"vendor": "vendor-c", "model": "model-c", "effort": "low"}]}],
 "spend_caps": {"key-1": 25.0, "key-2": null}}
```

A file that cannot be read or does not validate is 500 `unavailable`.

`PUT` takes `routes`, `spend_caps` or both, unknown fields refused, a body with neither 400
`bad_request`, and `If-Match` with the hash `GET` answered, quoted as in the `ETag` or bare:

```json
{"routes": [{"alias": "chat", "role": "gateway", "difficulty": 1}],
 "spend_caps": {"key-1": 40.5, "key-2": null}}
```

The gateway holds its reload lock for the whole request, so reloads and client token rotations
wait, and reads the file again: no `If-Match` is 428 `bad_request`, one that is not the file's
current hash 412 `bad_request`, so an edit by hand since the `GET` is detected.

`routes`, items of the `GET` shape, replace the file's items: the gateway renders them as
`[[routes]]` tables, TOML basic strings escaped, puts them where the first old item starts and
removes the other old items. An item spans from its `[[routes]]` header to the end of the line of
its last value, its `[[routes.chain]]` tables included: every byte outside the old items stays,
comments and other tables included, and comments inside them go. A file whose `routes` are an
inline array, or with a table outside `routes` between an item and its `[[routes.chain]]`, cannot
be edited this way: 400 `bad_request`, nothing written.

`spend_caps` maps login names to a USD amount or `null`; logins not named keep theirs. An amount
replaces the value of the login's `spend_cap` in place, or adds the line `spend_cap = <amount>`
after the line of the login's last value; `null` removes the `spend_cap` line, its comment
included. Amounts are written as TOML floats that parse back to the same number. A login the
file does not have as a `[[logins]]` table, or whose `kind` is not `api_key`, is 400
`bad_request` naming it. Every other byte stays.

With both, the routes are replaced first and the caps set in the result; the request is one
edit. The candidate file must pass what a reload checks ([config.md](config.md#reload)), so a cap
without a top-level `spend_file` or of 0 is refused; otherwise the answer is 400 `bad_request`
with the message `routes refused: <file>: <field>: <reason>` (`spend_caps refused: …` for a body
of `spend_caps` only), the line being the candidate's, for example
``routes[1].alias: duplicate `chat` `` or ``logins[0].spend_cap: needs a top-level `spend_file`
to count in``. Integers of the body are not range-checked before that, so the parser names a
`difficulty` out of range. On success the old file is copied to `<config>.bak-<unix s>`, `-<n>`
appended when a backup of that second exists, with mode 0600; the candidate is written
atomically with mode 0600 (temporary file in the same directory, fsync, rename, fsync of the
directory) and becomes the running config as a reload makes it, logging
`gateway: reloaded <file>: …`, so `GET /v1/model/spend` and `qbd`'s `spend` windows follow the
new caps at once. The answer is

```json
{"sha256": "5f0e…", "backup": "/etc/qb/gateway.toml.bak-1800000360"}
```

with the hash of the file now on disk. A candidate equal to the file byte for byte is not
written: the answer is 200 with the file's hash and no `backup`, no backup is made and the
running config is not reloaded; the audit records it as `ok` without a `backup`. A file that
cannot be read or written is 500 `unavailable`. On every refusal the file, its backups and the
running config stay as they were, with one exception: a write that fails after the rename
replaced the file is 500 `unavailable` with the message `<file> was replaced but not installed:
<error>; the old file is kept as <backup>`. The running config stays, the file on disk is the
candidate and the backup is kept, so a reload installs the candidate and the backup restores the
old file. The gateway removes the new backup only when a failed write left the file unchanged,
and no other backup.

### `qbd`'s admin API: `GET`/`PUT /v1/admin/roles` and `POST /v1/admin/reload`

The gateway forwards these three requests to `qbd`'s admin API ([Admin
`/v1/admin/*`](#admin-v1admin)) on `qbd_socket`, as `qbd` defines them. Only the gateway's own
uid may send them: any other caller gets 403 `auth` with the message `only the gateway's own uid
may call qbd's admin API` and nothing is sent to `qbd`; the loopback listener answers 404.
Another method is 405 `bad_request`.

The gateway asks `qbd` as itself, by its uid or with the bearer of `qbd_bearer_file`, so `qbd`
serves it only when the gateway's `[[clients]]` entry in `qbd`'s config has `admin = true`. A
`PUT` goes with the caller's `If-Match` and body unchanged, a `POST` with its body; `GET` sends
none. A 200 of `qbd` is answered with `qbd`'s body unchanged and, on `GET`, `qbd`'s `ETag`. Any
other answer of `qbd` becomes an `Error` with `qbd`'s status and `qbd`'s message, of the class
`auth` for `qbd`'s 401 and 403, `overloaded` for its 429, `unavailable` for its 500 and
`bad_request` for every other code, such as 412 for a stale `If-Match` or 428 for none. `qbd`'s
403 has the message ``qbd refused the gateway as an admin client: not an admin client; the
gateway's `[[clients]]` entry in qbd's config needs `admin = true` ``, which the gateway's own 403
never has. An answer of `qbd` without an error body is `unavailable` with its status. A `qbd`
that cannot be reached, or stops answering for 5 s, is 503 `unavailable` with the message
`qbd is unreachable: <error>`.

With `audit_file`, each `PUT` and `POST` is recorded as `admin_roles` or `admin_reload` on
[`GET /v1/model/audit`](#get-v1modelaudit).

### Usage ledger

With the `[usage]` table ([config.md](config.md#gateway-config)) the gateway appends one JSON
line per adapter attempt to `usage.file`, creating it with mode 0600, in one `write` per line, as
the attempt ends. An attempt is a pick whose login's adapter was called: each chain step and each
move to another login within a turn has its own line, whether the attempt finished, failed or
was cancelled; a 401 retried after a token refresh stays one attempt. A pick that never reaches
an adapter (a login at its spend cap, a credential that does not load, a step `qbd` cannot run)
leaves no line. A line is a `UsageLine`:

```json
{"at": 1800000004, "duration_ms": 3870, "request_id": "turn-1", "client": "client-a",
 "route": "chat", "step": 1, "login": "login-2", "model": "model-b", "outcome": "ok",
 "stop": "tool_use", "input": 1200, "output": 340, "cache_read": 8000, "cache_write": 0,
 "usd": 0.00564, "usd_source": "prices", "tools": ["read_file", "search"]}
```

| Field | Meaning |
|---|---|
| `at` | Unix time the attempt ended |
| `duration_ms` | milliseconds from the attempt's credential load to its end, a refresh's retry included |
| `request_id` | the turn's `request_id` |
| `client` | the turn's caller: `uid:<n>` for the gateway's own uid, a `[[clients]]` name, `client-token` or a `[[fronts.clients]]` name |
| `route` | the turn's route alias |
| `step` | index of the chain step the attempt ran on; 0 on a route without a chain |
| `login`, `model` | the login and model `qbd` picked |
| `outcome` | the outcome reported to `qbd` for the attempt (`ok`, `usage_limit`, `http_401`, `http_429`, `model_unavailable`, `error`); a failure after the stream started reports `ok` |
| `stop` | the vendor's stop reason, when the attempt finished and was not cancelled |
| `error` | otherwise the failure class, `cancelled` for a cancelled attempt |
| `input`, `output`, `cache_read`, `cache_write` | the attempt's last `usage`; 0 when the vendor reported none |
| `usd`, `usd_source` | USD of the attempt: the cost the vendor reported (`vendor`), else its usage at the model's `[prices]` entry (`prices`); both absent when there is neither |
| `tools` | the sorted unique names of the attempt's tool calls, each cut to 64 bytes, at most 64 |

No field holds prompt or answer text, thinking, tool arguments or results, headers or
credentials. A line that cannot be appended is logged at error priority with the path; the turn
goes on as it was. Before a line would take the file past `rotate_bytes`, the file is renamed to
`<file>.<unix s>` and rotated files older than `keep_days` are removed
([config.md](config.md#gateway-config)), so a reader finds the whole ledger as `file` and the files
`<file>.<digits>` beside it, older stamps holding older lines.

### `GET /v1/model/usage`

`GET /v1/model/usage?from=<unix s>&to=<unix s>&group_by=<g>&bucket=<b>` sums the usage ledger,
only for the gateway's own uid (any other caller gets 403 `auth`); the loopback listener does not
serve it. The parameters are those of `UsageQuery`:

| Parameter | Meaning |
|---|---|
| `from` | required; lines with an earlier `at` are left out |
| `to` | default the time of the request; lines with `at` at or after it are left out; after `from` and at most 400 days later |
| `group_by` | `client`, `login`, `model`, `route` or `tool`; absent, every line is one group |
| `bucket` | `hour`, `day` or `month`, UTC; absent, the whole window is one bucket |

The answer is a `UsageAnswer`: the window and grouping it used, one row per bucket and group that
holds a line, ordered by `start`, then `group`, and in `skipped` the number of lines read that do
not parse as a `UsageLine` or are longer than 64 KiB, which are left out:

```json
{"from": 1800000000, "to": 1800172800, "group_by": "login", "bucket": "day",
 "rows": [{"start": 1799971200, "group": "login-1", "attempts": 12, "failed": 1,
           "input": 48000, "output": 9100, "cache_read": 310000, "cache_write": 0,
           "usd": 0.913, "unpriced": 2, "duration_ms": 61250}],
 "skipped": 0}
```

| Row field | Meaning |
|---|---|
| `start` | start of the row's UTC hour, day or calendar month, which can lie before `from`; `from` without `bucket` |
| `group` | the row's client, login, model, route or tool name; absent without `group_by` |
| `attempts` | lines counted |
| `failed` | lines whose `outcome` is not `ok` |
| `input`, `output`, `cache_read`, `cache_write` | sums of the lines' token counts |
| `usd` | sum of the lines' `usd`, priced lines only |
| `unpriced` | lines without `usd` |
| `duration_ms` | sum of the lines' `duration_ms` |

With `group_by=tool` a line counts once under each of its `tools` and lines without tools are
left out, so the rows' sums overlap and do not add up to the window's totals. Sums saturate at
the largest value of their type.

The gateway reads `usage.file` and the rotated files `<file>.<stamp>` whose stamp is at or after
`from`; a rotated file holds only lines with `at` at or before its stamp, so one stamped before
`from` has none in the window. A missing file counts as empty. An answer of more than 10 000 rows is 400 `bad_request`,
asking for a narrower window or a coarser bucket; no answer is cut short. An unknown parameter,
one given twice, a missing `from` or an invalid value is 400 `bad_request` naming the parameter;
without `[usage]` the answer is 404 `bad_request`.
