# Vendor quota sources

`crates/qb-vendors` turns the quota data that vendor CLIs and usage endpoints already emit into
`WindowReport`s for `POST /v1/report` (see [api.md](api.md)). The parsers are pure: no I/O, no
clock; a source with relative times takes `now` from the caller. They are total: any byte string
returns a value. The formats are undocumented, so unknown fields are ignored.

## Sources

| Function | Input | Windows |
|---|---|---|
| `claude::stream_line(line)` | one stream-json line | `rate_limit_info.unifiedWindows.<name>`: `utilization` (fraction), `resetsAt` (Unix time) |
| `claude::statusline(input)` | statusline input JSON | `rate_limits.<name>`: `used_percentage` (percent), `resets_at` (Unix time) |
| `claude::usage(body)` | `oauth/usage` response | top-level `<name>`: `utilization` (percent), `resets_at` (RFC 3339) |
| `codex::rollout_line(line, now)` | one session rollout JSONL line | `payload.rate_limits` or else `payload.info.rate_limits`, keys `primary`, `secondary`: `used_percent`, `window_minutes`, `resets_at` (Unix time) or `resets_in_seconds` |
| `codex::usage(body, now)` | `wham/usage` response | `rate_limit.primary_window`, `rate_limit.secondary_window`: `used_percent`, `limit_window_seconds`, `reset_at` (Unix time) or `reset_after_seconds` |

`stream_line` returns `Ok(None)` for a line whose `type` is not `rate_limit_event`, and otherwise
an `Event` with the windows and `rate_limit_info.status` passed through as a string (`allowed`,
`allowed_warning`, `rejected` or any other value). `statusline` and `rollout_line` return
`Ok(None)` when the input carries no rate limits (absent or `null`). The usage parsers return the
windows they find, possibly none.

## Usage endpoints

`qb agent` fetches the usage endpoint of a login's `kind` (see [config.md](config.md)) with the
vendor CLI's own credential file, read right before the request:

| Kind | Request | Headers | Credential fields |
|---|---|---|---|
| `claude` | `GET https://api.anthropic.com/api/oauth/usage` | `Authorization: Bearer <token>`, `anthropic-beta: oauth-2025-04-20` | `claudeAiOauth.accessToken` of `.claude/.credentials.json` |
| `codex` | `GET https://chatgpt.com/backend-api/wham/usage` | `Authorization: Bearer <token>`, `ChatGPT-Account-Id: <account>` when the file has one | `tokens.access_token`, optional `tokens.account_id`, of `.codex/auth.json` |

- The connect timeout and the limit on the whole request are 10 s each. Redirects are not
  followed and no proxy is used; the response body is read up to 1 MiB.
- 200 goes to `claude::usage` or `codex::usage`; 401 and 429 become the probe outcomes
  `http_401` and `http_429`; any other status, a transport error or an unreadable body is
  `error`.
- `Retry-After` counts only as whole seconds (`120`). An HTTP-date or any other value is absent,
  and the daemon's back-off applies.
- A missing or unreadable file, a file that is not JSON, and a field that is missing, empty, not
  a string or not visible ASCII make the probe `error`. The log line names the file and the
  field and never quotes the file.

## Errors

| Error | When |
|---|---|
| `NotJson` | The input is not exactly one JSON value (including truncated lines, `NaN`, trailing data). |
| `WrongType(path)` | The top level (`$`) is not an object, or a container on the source's path has the wrong type: `rate_limit_info`, `rate_limit_info.status`, `rate_limit_info.unifiedWindows`, `rate_limits`, `payload`, `payload.info`, `payload.rate_limits`, `payload.info.rate_limits`, `rate_limit`. |
| `Missing(path)` | A `rate_limit_event` without `rate_limit_info` or its `status`. |

A single window that cannot be read is dropped; the other windows of the input still count.

## Normalisation

- Names: Claude windows keep the source's key and are taken only for `five_hour`,
  `seven_day` and `seven_day_<model>` (for example `seven_day_opus`); other keys are ignored.
  The daemon keeps only windows the login's vendor declares, so a `seven_day_*` key that is not
  a model's window never reaches state unless a config declares it.
  Codex windows are named by length: 300 min is `five_hour`, 10080 min is `seven_day`, any other
  length is `window_<minutes>m`. Claude windows are returned sorted by name, Codex windows in
  `primary`, `secondary` order. Two readable Codex windows of the same length would share a
  name: the first in that order is kept and the later one is dropped.
- Length: `length_s` is always set: 18000 for `five_hour`, 604800 for `seven_day*`, and the
  stated length for Codex. A Codex length of 0, one that is not a whole number of minutes, or
  one that does not fit `u32` seconds drops the window.
- Utilisation: Percent sources are divided by 100; the result is clamped to at most 1.0. A
  missing, non-number, negative or non-finite value drops the window.
- Absolute resets: A numeric Unix time is read in seconds, or in milliseconds when it is at
  or above 10^11; fractions are rounded down. A value that is still at or above 10^11 s (year
  5138) after that, negative, or not a number drops the window. RFC 3339 strings are parsed by
  hand: `YYYY-MM-DDTHH:MM:SS`, optional fractional seconds (rounded down), and a `Z` or `±hh:mm`
  offset; `T` may be `t` or a space, `Z` may be `z`. Impossible dates (30 February, month 13),
  a missing offset and times before 1970 are unreadable and drop the window.
- Relative resets: `resets_in_seconds` counts from the rollout line's `timestamp` (RFC 3339),
  or from `now` when the line has no readable `timestamp`; `reset_after_seconds` counts from
  `now`. An absolute field wins when both are present. A negative, non-number or overflowing
  value drops the window.
- No reset: An absent or `null` reset field gives a window without `resets_at`.
