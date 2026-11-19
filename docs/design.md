# Design

## Problem

An orchestrator runs coding agents on several subscriptions (vendors × logins). Each login has
rolling quota windows (for example 5 hours and 7 days). Picking by a fixed order wastes quota
that resets unused and runs into exhausted logins at the worst moment. `qb` answers one
question before every run — *where should this task run now?* — and keeps short leases so
concurrent workers do not oversubscribe the same window. Clients that should not hold vendor
credentials themselves can send model requests through the optional gateway, which asks `qbd`
the same question before each request.

## Non-goals

- Model traffic or credentials in `qbd`. Only the optional `qb gateway` carries model traffic
  and stores and refreshes tokens, for its own credential owner; other clients talk to vendors
  directly.
- Failing over after an answer has started streaming. The gateway moves to another login only
  before the client has seen any event ([ADR 0001](adr/0001-model-gateway.md#rotation-boundary)).
- Sharing credentials or pooling accounts between people.
- Telemetry of any kind.

## Where quota numbers come from (cheapest first)

| Source | Cost | Freshness |
|---|---|---|
| **Stream**: clients report the rate-limit data that unmodified vendor CLIs already print (stream-json events, statusline input, session rollouts) via `POST /v1/report` | 0 requests | exactly when a login is in use |
| **Lazy probe** (optional, off by default): when `pick` needs a login whose data is older than its TTL, the agent makes one request to the vendor's usage endpoint; singleflight per login, exponential back-off, `Retry-After` honoured | 1 request | on demand |
| **Inference**: after `resets_at` a window is assumed empty (`source = assumed`) | 0 | coarse |

When nobody asks, `qb` makes no network requests at all.

How each vendor's stream and usage-endpoint data becomes window reports is in
[vendors.md](vendors.md).

## Roles and privilege separation

```
 clients (orchestrators, qb CLI)          qbd  (DynamicUser, PrivateNetwork=yes)
  local uid ──unix socket──────────────▶   policy, leases, journal
  remote ──ssh -L forwarded socket──────▶   no vendor secrets, no outbound sockets
            + bearer token                   ▲ ▲ "probe login X"
 qb agent (credential owner, user unit) ─────┘ │ reply: window numbers only
  landlock: read-only credential dirs, TCP 443 only; non-dumpable; zeroize
                                               │ pick / report, as a client
 qb gateway (credential owner, user unit) ─────┘
  own unix socket (+ optional loopback port), model traffic to vendors over HTTPS
  landlock: read-write credential dirs, TCP 443 only, bind only the loopback port;
  non-dumpable; zeroize
```

- **`qbd`** owns all state in one thread. It receives its listening socket from systemd, so it
  can run with `PrivateNetwork=yes` and `RestrictAddressFamilies=AF_UNIX`. It cannot open an
  outbound connection even if compromised. Alerts go out through a configured hook, not from
  the daemon.
- **`qb agent`** touches credentials only to probe: it reads the vendor CLI's own credential
  file right before one GET, keeps the token for at most a second, then zeroizes it (the
  copies the HTTP client makes are listed in `SECURITY.md`). It never
  writes or refreshes credentials. Before its first connection to `qbd` it makes itself
  non-dumpable and restricts itself with landlock to reading the credential directories,
  `/etc/resolv.conf` and `/etc/hosts`, and to TCP connections to port 443; a kernel that cannot
  enforce part of this gets one warning in the log. DNS over TCP (port 53) is not allowed, so a
  truncated UDP answer fails the probe as `error`. Host names resolve on the probe's own thread,
  bounded by the system resolver's timeouts rather than the probe's, since `TasksMax=4` leaves
  no room for a resolver thread per probe. On 401 it reports `auth_stale`; the vendor
  CLI refreshes its own token on next use.
- `qb gateway` (optional) carries model traffic for its own credential owner and is the only
  long-running component that writes credentials. It serves its own unix socket, identifies peers by
  `SO_PEERCRED`, and for each request picks a login from `qbd` as an ordinary client, calls the
  vendor with that login's token or API key, rotates to another login before the first event
  when one fails, and reports the outcome and the windows it saw. It refreshes OAuth tokens on
  demand and replaces the credential file atomically (0600, rename in the same directory).
  It rotates the token of a named loopback client with a `token_file` the same way, and replaces
  the `[[routes]]` and the logins' `spend_cap`s of its config file, the key of an `api_key`
  login and the tokens of an OAuth login it signs in again with PKCE atomically with a 0600
  backup, on its own uid's request.
  Before serving it makes itself non-dumpable and restricts itself with landlock to its config's
  and credential directories and the directories of its spend, audit, usage, client token and
  grace files (read-write), the resolver files, TCP connections to port 443 and a
  bind on the optional loopback port; gaps on older kernels are logged as for the agent, and a
  fully applied sandbox gets one info line at startup (`sandbox: non-dumpable; landlock V4: …`).
  Decisions and limits: [ADR 0001](adr/0001-model-gateway.md).
- `qb login import` is run by the operator as the gateway's user to write a login's credential
  file from a credential another client holds ([config.md](config.md#importing-credentials)).
  It makes itself non-dumpable before it reads the gateway config, then restricts itself with
  landlock before it opens the source: it may read the files of the config's and the source's
  directories, and read, write, create and remove regular files in the directory of the login's
  credential file; no other file and no TCP. Gaps on older kernels get one warning, as for the
  gateway. It zeroizes the secrets it read and writes the file atomically (0600, rename in the
  same directory).
- `qb login` is run by the operator as the gateway's user to sign an OAuth login in from
  scratch with PKCE ([config.md](config.md#signing-in)): it prints an authorize URL, reads the
  pasted code from stdin, exchanges it at the vendor's token endpoint and writes the login's
  credential file. It makes itself non-dumpable before it reads the gateway config, then
  restricts itself with landlock before it reads stdin: it may read the files of the config's
  directory and the resolver files, read, write, create and remove regular files in the
  directory of the login's credential file, and connect over TCP to port 443 only. Gaps on
  older kernels get one warning, as for the gateway. It zeroizes the code, the verifier and the
  tokens and writes the file atomically (0600, rename in the same directory).
- **Clients** of `qbd` send no secrets: only outcome classes and window numbers.

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
   `auth_stale` logins stay: the token is refreshed on next use, by the vendor CLI or, for its
   own logins, by `qb gateway`.
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
   there is no candidate or none can recover by a known time. A `dead` answer runs no hook;
   `on_dead` runs once per login, when that login becomes `auth_dead` (see [Hooks](#hooks)).
6. Create the lease (a full table answers `wait`), append one journal line, answer.

`report` is O(1): limit/rejected → exhausted until reset; 401 → `auth_stale`, repeated →
`auth_dead`, both cleared by an `ok` with an observed window; 429 → short back-off; model unavailable → per-(login, model) dead mark; stream
windows overwrite the snapshot and reset its TTL. The exact rules are in [api.md](api.md).

## Hooks

`[hooks]` in the config ([config.md](config.md#hooks)) names commands `qbd` runs on a login's
`auth_dead` edges: `on_dead` when a report or probe result makes the login `auth_dead`,
`on_recover` when one clears it. The edge is decided where a request changes the login's marks,
so a repeated dead state, journal replay at start and marks that end by time run nothing.

A hook is exec'd without a shell, with stdin and stdout on `/dev/null` and stderr inherited, so
its output lands in `qbd`'s log. The loop never waits for it: finished hooks are reaped on the
next loop pass, and a non-zero exit or a failed spawn is logged and changes nothing else. At
most 2 run at once (`TasksMax=4` counts the daemon); an event beyond that is dropped with a
warning naming the event and login. A hook still running 60 s after its spawn gets `SIGKILL`
on the next loop pass, or when the next event needs its slot, and the kill is logged; no timer
wakes an idle loop for it, and processes the hook started itself are not tracked.

Hooks run inside `qbd`'s sandbox: its `DynamicUser`, no network, a read-only system. An alert
has to leave through something the sandbox allows, such as the journal via `logger` or a line
on stderr.

## Disk

Only the journal, written with `O_APPEND` and no fsync (~150 bytes per pick, rotated at 1 MiB ×
2): leases and dead-until marks, replayed on start. Quota snapshots are a cache and are not
persisted. `journal = off` writes nothing. Line format, rotation and replay:
[journal.md](journal.md).

## Cold start

systemd holds the socket while `qbd` restarts, so clients queue instead of failing. Start-up is
exec + config parse + journal replay (milliseconds). All snapshots start stale. A `pick` never
waits for a probe: it answers from what it has with `stale: true`, and the probe it triggers
refreshes the login for later picks.

## Budgets

| Resource | Target |
|---|---|
| daemon RSS idle / after 10⁴ picks | ≲ 2 MiB / ≤ 4 MiB (`MemoryMax=16M`) |
| agent RSS idle / during probe | ≲ 2 MiB / ≲ 6 MiB |
| gateway RSS idle / per turn in flight | ≤ 4 MiB / ≲ 1 MiB plus twice the request body |
| binary | static musl, ≤ 4 MiB with TLS, the gateway and both of its fronts (owner decision) |
| dependencies | ≤ 12 direct, ≲ 50 total |
| CPU | 0 wake-ups/s idle (daemon, agent and gateway); pick ≤ 50 µs server-side, p99 ≤ 1 ms over UDS from connect to response; gateway p99 ≤ 5 ms from a request to its upstream request |
| disk | ≤ ~150 B per pick, or 0 with `journal = off`; the gateway writes only refreshed credential files |
| network | 0 idle; agent ≤ 1 small HTTPS GET per login per TTL, only on demand; gateway one HTTPS request per attempt, one per token refresh and one per sign-in code its own uid sends |

CI enforces the binary budget, the daemon's RSS, latency, wake-up and `journal = off` budgets and
the gateway's RSS, latency and wake-up budgets in the `budgets` job. `ci/budgets.sh` checks the
size and static linking of the musl release binary. The acceptance lane,
`crates/qb/tests/acceptance.rs`, runs that binary as the daemon and as `qb gateway`:

- the three policy scenarios of the roadmap, with reports and picks over the socket;
- 10⁴ picks, each released by a report, one connection per request, journal on: it prints the
  latency distribution from connect to full response and fails on p99 > 1 ms or a daemon
  `VmHWM` above 4096 kB;
- the same picks with `journal = off`: it fails unless the daemon's `write_bytes` is 0;
- an idle daemon with a parked agent and hooks: it fails on any context switch over 10 s;
- an agent's probe back-off after a failed probe;
- `qb gateway` with its default caps and loopback listener, a daemon, and a scripted vendor on
  loopback port 443, the only port the gateway's sandbox connects to: it fails on an idle
  gateway `VmHWM` above 4096 kB, on a `VmHWM` above 4096 kB + 1 MiB + twice the request body
  after 20 turns of a 1 MiB body, on any context switch of an idle gateway over 10 s, and on a
  p99 above 5 ms from the client's connect to the vendor holding the upstream request over 300
  turns.

These tests are timing-bound and `#[ignore]`d, so `cargo test --workspace` skips them. The binary
comes from `QB_ACCEPTANCE_BIN`, an absolute path, or else the cargo-built one. The gateway cases
bind port 443, so the lane needs `net.ipv4.ip_unprivileged_port_start` at most 443. On a shared
host the timings measure the neighbours, so run the lane locally only on an idle machine:

```sh
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443
QB_ACCEPTANCE_BIN="$PWD/target/x86_64-unknown-linux-musl/release/qb" \
  cargo test --release --locked -p qb --test acceptance -- --ignored --test-threads=1 --nocapture
```

## Why Rust, and why synchronous

At ~1 request per second, the language barely matters for throughput. Rust gives one static
binary, convenient landlock/seccomp, no GC, and memory safety next to credential handling. An
async stack would add ~100 crates and megabytes of binary for nothing at this load; if
thousands of clients ever appear, `mio` fits under the same core. The gateway's long streams run
one blocking thread per turn, at most 16 at once, under the same rule.
