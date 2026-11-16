# API `/v1`

JSON over HTTP/1.1 on a unix socket (or a forwarded one). One request per connection;
`Content-Length` is required for `POST`; bodies ≤ 64 KiB, headers ≤ 8 KiB. Times are Unix
seconds, utilisation is `0.0..=1.0`, enums are `snake_case`. Requests reject unknown fields.
Types are defined in `crates/qb-proto`; example payloads are in `crates/qb-proto/tests/fixtures/`.

| Endpoint | Request | Response |
|---|---|---|
| `POST /v1/pick` | `PickRequest` | 200 `PickResponse` |
| `POST /v1/report` | `ReportRequest` | 200 `ReportResponse`, 404 unknown lease/login/model |
| `GET /v1/state` | — | 200 `StateResponse` |
| `GET /v1/health` | — | 200 `HealthResponse` |

Errors: `{"error": <code>, "message": "..."}` with codes `bad_request` (400), `unauthorized`
(401), `forbidden` (403), `not_found` (404), `method_not_allowed` (405), `length_required`
(411), `payload_too_large` (413), `too_many_requests` (429), `internal` (500).

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

## `GET /v1/health`

`{"status": "ok", "api_version": "v1", "version": "0.0.1", "uptime_s": 12}`
