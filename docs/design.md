# Design

## Problem

An orchestrator runs coding agents on several subscriptions (vendors × logins). Each login has
rolling quota windows (for example 5 hours and 7 days). Picking by a fixed order wastes quota
that resets unused and runs into exhausted logins at the worst moment. `qb` answers one
question before every run — *where should this task run now?* — and keeps short leases so
concurrent workers do not oversubscribe the same window.

## Non-goals

- Proxying model traffic or failing over mid-request. Clients talk to vendors directly.
- Storing, refreshing or sharing credentials. Pooling accounts between people.
- Telemetry of any kind.

## Where quota numbers come from (cheapest first)

| Source | Cost | Freshness |
|---|---|---|
| **Stream**: clients report the rate-limit data that unmodified vendor CLIs already print (stream-json events, statusline input, session rollouts) via `POST /v1/report` | 0 requests | exactly when a login is in use |
| **Lazy probe** (optional, off by default): when `pick` needs a login whose data is older than its TTL, the agent makes one request to the vendor's usage endpoint; singleflight per login, exponential back-off, `Retry-After` honoured | 1 request | on demand |
| **Inference**: after `resets_at` a window is assumed empty (`source = assumed`) | 0 | coarse |

When nobody asks, `qb` makes no network requests at all.

## Roles and privilege separation

```
 clients (orchestrators, qb CLI)          qbd  (DynamicUser, PrivateNetwork=yes)
  local uid ──unix socket──────────────▶   policy, leases, journal
  remote ──ssh -L forwarded socket──────▶   no vendor secrets, no outbound sockets
            + bearer token                   ▲ "probe login X"
 qb agent (credential owner, user unit) ─────┘ reply: window numbers only
  landlock: read-only credential dirs, TCP 443 only; non-dumpable; zeroize
```

- **`qbd`** owns all state in one thread. It receives its listening socket from systemd, so it
  can run with `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`. It cannot open an
  outbound connection even if compromised. Alerts go out through a configured hook, not from
  the daemon.
- **`qb agent`** is the only component that ever touches a credential: it reads the vendor CLI's
  own credential file right before one GET, keeps the token for at most a second, then
  zeroizes it. It never writes or refreshes credentials. On 401 it reports `auth_stale`; the
  vendor CLI refreshes its own token on next use.
- **Clients** send no secrets: only outcome classes and window numbers.

## Transport

One contract — JSON over HTTP/1.1 under `/v1` — on two carriers:

- **Local**: unix stream socket, mode 0660, group-restricted; the peer is identified by
  `SO_PEERCRED` and mapped to a client name in config. `curl --unix-socket` works.
- **Remote**: the same socket forwarded with `ssh -L`, plus a mandatory bearer token (the server
  keeps only its SHA-256 and compares in constant time).

Rejected for now: abstract sockets (no file permissions), D-Bus (broker in the path),
io_uring (attack surface, no benefit at ~1 rps), HTTP/2 and gRPC (nothing to multiplex).
Varlink on the same socket and read-only shared memory for status bars are possible later.

## Policy core

Vendors, windows, logins, ladders, reserves and clients come from the config file described in
[config.md](config.md).

State, all in one thread, no locks, no allocation on the hot path:

- `logins[≤32]`, each with `windows[≤4]` of `{used, resets_at, len, observed_at, source}`;
  a window never observed, or past its `resets_at`, counts as `used = 0`, `source = assumed`,
  and one older than the snapshot TTL is `stale` (pick still uses it and says so);
- dead-until marks per login (`exhausted`, `rate_limited`) and per (login, model), and the
  login's auth state (`auth_stale`, `auth_dead`);
- `leases[≤256]` with per-login, per-window reserved sums updated in O(1); a lease id names its
  slot, so lookup is O(1) too;
- precomputed ladders `difficulty × role → [candidate ≤ 8]`;
- a deadline heap (lease expiry, dead-until, resets, TTLs) with lazy deletion: an entry counts
  only while the state still holds its time, and the heap is compacted when it outgrows twice
  the number of live deadlines. `pick` and `report` apply due deadlines first, so correctness
  does not depend on wake-ups; the loop sleeps in `poll()` until the earliest deadline, so an
  idle daemon wakes up zero times per second;
- learned cost per (model, effort) as an EWMA of "% of window per minute".

`pick` for k ≤ 8 candidates and W ≤ 4 windows:

1. Candidates from the pin or the ladder, each expanded to the logins of its vendor;
   `resume_of` keeps the session's login. A pin takes the logins of the pinned vendor (or the
   one named login) and no role reserve.
2. Drop dead logins/models, the avoided vendor, and candidates missing a required capability;
   `auth_stale` logins stay, the vendor CLI refreshes its token on next use.
3. Admissible if for every window of the login's vendor `left = 1 − used − reserved − cost`
   is above 0 and `left ≥ reserve(role, difficulty, w)`, where the reserve is dropped when the
   window resets within `T_burn(w)`; a reserve naming a window the vendor does not declare
   constrains nothing. A task must also fit into the short window.
4. Score by spend-before-reset urgency `left / max(resets_at − now, 1h) × len` on the
   vendor's longest window (an unknown reset counts as `len` away); choose lexicographically
   by (tier ascending, urgency descending, candidate order, login index).
5. Nothing admissible on the step → the nearest lower step, then the nearest higher one;
   nothing at all → `wait` with `retry_after` = the earliest time some rejected candidate gets
   all its blocks back (reset, `T_burn` start, lease expiry, end of a mark), or `dead` when
   there is no candidate or none can recover by a known time (and the `on_dead` hook).
6. Create the lease (a full table answers `wait`), append one journal line, answer.

`report` is O(1): limit/rejected → exhausted until reset; 401 → `auth_stale`, repeated →
`auth_dead`; 429 → short back-off; model unavailable → per-(login, model) dead mark; stream
windows overwrite the snapshot and reset its TTL. The exact rules are in [api.md](api.md).

## Disk

Only the journal, written with `O_APPEND` and no fsync (~150 bytes per pick, rotated at 1 MiB ×
2): leases and dead-until marks, replayed on start. Quota snapshots are a cache and are not
persisted. `journal = off` writes nothing.

## Cold start

systemd holds the socket while `qbd` restarts, so clients queue instead of failing. Start-up is
exec + config parse + journal replay (milliseconds). All snapshots start stale; the first `pick`
for a cold login may wait for one probe (≤ 1.5 s) or answer with `stale: true`.

## Budgets

| Resource | Target |
|---|---|
| daemon RSS idle / after 10⁴ picks | ≲ 2 MiB / ≤ 4 MiB (`MemoryMax=16M`) |
| agent RSS idle / during probe | ≲ 2 MiB / ≲ 6 MiB |
| binary | static musl, ≤ 2.5 MiB with TLS |
| dependencies | ≤ 12 direct, ≲ 50 total |
| CPU | 0 wake-ups/s idle; pick ≤ 50 µs server-side |
| disk | ≤ ~150 B per pick, or 0 with `journal = off` |
| network | 0 idle; ≤ 1 small HTTPS GET per login per TTL, only on demand |

## Why Rust, and why synchronous

At ~1 request per second, the language barely matters for throughput. Rust gives one static
binary, convenient landlock/seccomp, no GC, and memory safety next to credential handling. An
async stack would add ~100 crates and megabytes of binary for nothing at this load; if
thousands of clients ever appear, `mio` fits under the same core.
