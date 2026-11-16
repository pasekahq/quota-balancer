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
