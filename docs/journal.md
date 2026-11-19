# Journal

With `[journal] mode = "path"` (see [config.md](config.md)) `qbd` appends one line per state
change to the journal file and replays it on start, so live leases and dead-until marks survive
a restart. Quota window snapshots are a cache and are not journaled. With `mode = "off"` the
daemon opens and creates no file.

## Lines

Each line is one JSON object terminated by `\n`: `at`, the Unix time the change happened, and
exactly one record key. Unknown keys are rejected.

| Record | Written when | Example |
|---|---|---|
| `lease` | a `pick` grants a run | `{"at":1800000000,"lease":{"id":257,"login":"login-1","model":"model-small","client":"uid:1001","run_id":"run-1","on_behalf_of":"client-a","cost":[0.06,0.0018],"expires_at":1800005400,"reason":"spend_before_reset"}}` |
| `release` | a report releases a lease | `{"at":1800000600,"release":257}` |
| `marks` | a report or a probe result changes a login's marks | `{"at":1800000600,"marks":{"login":"login-1","exhausted_until":1800018000}}` |
| `issued` | a rotation starts a new file | `{"at":1800000600,"issued":12}` |

- `lease`: `id` is the number in the wire id `l-<id>`; `run_id` and `on_behalf_of` are omitted
  when the pick had none, and a line without them replays as a lease without them; `cost` is the reserved fraction of each window of the login's vendor, in declaration
  order; `reason` is the pick's `reason` (see [api.md](api.md)). A line without `reason`
  replays as a lease whose reason is unknown; a `reason` that is not a pick reason does not
  decode.
- `marks`: all marks of the login after the change. `auth` is `ok`, `stale` or `dead` and is
  omitted when `ok`; `exhausted_until` and `rate_limited_until` are omitted when unset;
  `model_dead` maps a model to the end of its dead mark and is omitted when empty. A missing
  mark is a cleared mark.
- `issued`: how many leases were issued so far; ids issued after a restart are higher.

Lease expiries and the ends of marks are not written: they follow from the recorded times.

## Rotation

Once the file reaches `rotate_bytes` after an append, it is renamed to `<path>.1` (replacing the
previous `.1`) and a new file starts with the live state at that moment: one `issued` line, one
`lease` line per live lease and one `marks` line per login with any mark. Each file stays below
`rotate_bytes` plus one line, unless the live state alone is larger.

When an append fails (the write, or creating or writing the header of a new file), the daemon
writes nothing more into that file. Each later change retries a restart: the file, if any, is
renamed to `<path>.1` and a new file starts with the live state, which already holds that
change. A line torn by the failed write therefore ends `<path>.1`, where replay skips it.

## Replay

On start, before the socket accepts, `qbd` reads `<path>.1`, then `path`; a missing file is
empty. Every line is applied in order at its `at`: deadlines due by then apply first, a `lease`
replaces any lease in the slot its id names, `marks` replace the login's marks. After the last
line the deadlines due at the current time apply, so leases and marks that ended while the
daemon was down are gone.

- A final line without its `\n` was torn by a crash: it is skipped with a warning and cut from
  the file before the next append.
- A line naming a login the config no longer declares, or a lease whose `cost` does not match
  the vendor's windows, is skipped with a warning. Models no ladder declares are dropped from
  `model_dead`.
- Any other line that does not decode stops start-up with exit code 2 and one line naming the
  file, the line number and the reason, for example
  `qb: /var/lib/qb/journal: line 7: expected value at line 1 column 1`. Move the file away to
  start without it.

`qb simulate --config PATH <journal>` runs the same replay against a config without a daemon,
with the same warnings and exit code 2, and prints the resulting state as `GET /v1/state` JSON
at `--at T` (default: the time of the last record). With `--pick JSON` it then prints the
`PickResponse` that config gives for that `PickRequest` at that time, picked as the client
`simulate`. It opens both files read-only and creates no file.
