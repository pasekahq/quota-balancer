# API `/v1`

JSON over HTTP/1.1 on a unix socket (or a forwarded one). One request per connection;
`Content-Length` is required for `POST`; bodies ≤ 64 KiB, headers ≤ 8 KiB. Times are Unix
seconds, utilisation is `0.0..=1.0`, enums are `snake_case`. Requests reject unknown fields.
Types are defined in `crates/qb-proto`; example payloads are in `crates/qb-proto/tests/fixtures/`.

| Endpoint | Request | Response |
|---|---|---|
| `POST /v1/pick` | `PickRequest` | 200 `PickResponse` |
| `POST /v1/report` | `ReportRequest` | 200 `ReportResponse`, 404 unknown lease/login |
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
step, nothing being admissible on the requested one) or `pinned`; for `wait` `all_exhausted`;
for `dead` `no_candidates` (unknown role, no step for the difficulty, no login for any
candidate) or `no_reset_known` (every candidate is blocked by a window without a known reset).
`tier` is absent for a pin. `stale` is true when a window behind the answer is older than the
snapshot TTL or was never reported; `quota_snapshot_at` is the oldest report behind a `run`,
absent while one of its windows was never reported. Leases are not issued: a `run` carries no
`lease_id`, and a report naming one answers 404.

## `POST /v1/report`

```json
{"lease_id": "l-17", "outcome": "ok",
 "windows": [{"name": "five_hour", "utilization": 0.15, "resets_at": 1800018000}]}
{"login": "login-1", "outcome": "usage_limit", "release": true}
```

Each entry of `windows` overwrites that window of the login's snapshot (`source = stream`,
`observed_at` = server time). Names the login's vendor does not declare are ignored, and
`length_s` is informational: the configured length counts. A `utilization` outside
`0.0..=1.0` answers 400 and applies nothing.

`outcome`: `ok`, `usage_limit`, `rejected`, `http_401`, `http_429`, `model_unavailable`,
`error`. Response: `{"accepted": true, "login_status": "exhausted"}` with `login_status` one of
`ok`, `rate_limited`, `exhausted`, `auth_stale`, `auth_dead`, `unknown`.

## `GET /v1/state`

Logins with their windows (`used`, `reserved`, `resets_at`, `observed_at`, `source` =
`stream|probe|assumed`, `stale`) and live leases. See `state_response.json`. A window never
reported shows `used = 0`, `observed_at = 0`, `source = assumed`, `stale = true`; once its
`resets_at` has passed it shows `used = 0`, `source = assumed` and no `resets_at`. `reserved` is
0 while no leases are issued.

## `GET /v1/health`

`{"status": "ok", "api_version": "v1", "version": "0.0.1", "uptime_s": 12}`
