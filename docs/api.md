# API `/v1`

JSON over HTTP/1.1 on a unix socket (or a forwarded one). One request per connection;
`Content-Length` is required for `POST`; bodies ≤ 64 KiB, headers ≤ 8 KiB. Times are Unix
seconds, utilisation is `0.0..=1.0`, enums are `snake_case`. Requests reject unknown fields.
Types are defined in `crates/qb-proto`; example payloads are in `crates/qb-proto/tests/fixtures/`.

| Endpoint | Request | Response |
|---|---|---|
| `POST /v1/pick` | `PickRequest` | 200 `PickResponse` |
| `POST /v1/report` | `ReportRequest` | 200 `ReportResponse`, 403 another client's lease, 404 unknown lease/login/model |
| `GET /v1/state` | — | 200 `StateResponse` |
| `GET /v1/why/{lease_id}` | — | 200 `WhyResponse`, 404 unknown or ended lease |
| `GET /v1/health` | — | 200 `HealthResponse` |
| `POST /v1/agent/next` | `AgentNextRequest` | 200 `AgentJob`, 400 unknown login, 403 not an agent, 429 too many waiting |
| `POST /v1/agent/result` | `AgentResultRequest` | 200 `ReportResponse`, 403 another client's probe, 404 unknown or expired probe |

Errors: `{"error": <code>, "message": "..."}` with codes `bad_request` (400), `unauthorized`
(401), `forbidden` (403), `not_found` (404), `method_not_allowed` (405), `length_required`
(411), `payload_too_large` (413), `too_many_requests` (429), `internal` (500).

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
`expected_minutes`, `run_id`.

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
| `ok` | With at least one declared window, `unknown` and `auth_stale` become `ok`. |
| `usage_limit`, `rejected` | `exhausted` until the earliest reset of a window at ≥ 0.99 used, else the reset of the vendor's longest window, else one longest-window length from now. |
| `http_401` | `auth_stale`; a 401 on an `auth_stale` login makes it `auth_dead`, which no report clears (re-login and restart `qbd`). An `auth_stale` login stays pickable. |
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
`run_id`, `expires_at`). See `state_response.json`. `reserved` is the sum of the live leases'
costs in that window. A window never reported shows `used = 0`, `observed_at = 0`,
`source = assumed`, `stale = true`; once its `resets_at` has passed it shows `used = 0`,
`source = assumed` and no `resets_at`.

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
| `ok` | The windows apply as a report's do, with `source = probe` in `GET /v1/state`: names the login's vendor does not declare are ignored, `unknown` and `auth_stale` become `ok` when a declared window is among them. The back-off ends. |
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
