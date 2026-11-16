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
| `role` | string | Declared role. |

Compute the hash with `printf %s "$TOKEN" | sha256sum`.

## `[journal]`

Required.

| Key | Type | Meaning |
|---|---|---|
| `mode` | `"path"` or `"off"` | `off` writes nothing to disk and takes no other key. |
| `path` | string | With `mode = "path"`: absolute path of the journal file. |
| `rotate_bytes` | integer > 0 | With `mode = "path"`: rotation size, default 1048576. |

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

Optional. Back-off of the agent's vendor probes.

| Key | Type | Meaning |
|---|---|---|
| `backoff_initial_s` | integer > 0 | First back-off, default 30. |
| `backoff_max_s` | integer ≥ `backoff_initial_s` | Ceiling, default 3600. |

## `[limits]`

Optional. A token bucket per client.

| Key | Type | Meaning |
|---|---|---|
| `rate_per_s` | float > 0 | Refill rate in requests per second, default 5.0. |
| `burst` | integer > 0 | Bucket size, default 20. |
