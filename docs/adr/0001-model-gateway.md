# ADR 0001: Model gateway

Status: Accepted

## Context

`qbd` decides where a run goes; clients then talk to the vendor with their own CLI and
credentials. An agent loop that has no vendor adapter of its own needs one local endpoint that
carries its model requests: it picks a login through `qbd`, holds that login's credential,
refreshes OAuth tokens, moves to another login when one runs out, and reports what it observed
back to `qbd`. The logins are the credential owner's subscription OAuth logins and API keys.

What stays fixed:

- `qbd` is single-threaded, answers one request per connection with bodies ≤ 64 KiB, holds no
  secrets and has no network (`PrivateNetwork=yes`).
- The stack is synchronous: no tokio, hyper or any async runtime (AGENTS.md rule 4, `deny.toml`).
- One static binary within its size budget.
- `qb agent` already shows how a credential-holding role hardens itself
  (`crates/qb/src/sandbox.rs`).

## Decision

### Role, socket and peers

`qb gateway --config PATH` is a role of the `qb` binary. It runs as the credential owner under a
systemd user unit, `qb-gateway.service`, installed for that user like `qb-agent.service`.

- It binds its own unix socket at the path its config names; there is no default path in code.
  The socket file is created with mode 0600, or 0660 when the config says so, and a stale
  socket file is replaced at start.
- Each peer on the socket is identified by `SO_PEERCRED`, as in `qbd`. A peer whose uid is the
  gateway's own or listed in the gateway config is a client; any other uid gets 401.
- Optionally it also listens on a loopback TCP address (`127.0.0.1:<port>` or `[::1]:<port>`)
  for the Messages front only. A non-loopback address is a config error. TCP carries no peer
  uid, so every request there needs the local client token (`x-api-key` or
  `Authorization: Bearer`); the config holds its SHA-256 and the gateway compares in constant
  time, as `qbd` compares bearers.
- Both listeners speak HTTP/1.1, one request per connection, with `qbd`'s framing limits on the
  request head. A request body needs `Content-Length`; chunked request bodies are rejected.
  Streamed responses use `Transfer-Encoding: chunked`.

### Sandbox

At start the gateway reads its config, creates its listeners, clears its dumpable flag
(`PR_SET_DUMPABLE`), and only then restricts itself with landlock (target ABI V4; the ruleset
handles every file and network right of that ABI):

- read and write beneath the directory of each configured credential file: read files and
  directories, write and truncate files, create regular files, remove files. The directory,
  not the file, because a refresh replaces the file by a rename inside that directory. No
  `REFER` right: renames never cross directories.
- read-only `/etc/resolv.conf` and `/etc/hosts`, the files the musl resolver reads.
- TCP connect to port 443 only.
- TCP bind only on the configured port of the Messages front, and no bind right without it.
  The listener exists before the restriction; handling the bind right keeps any other port
  from being bound later.

Connecting to `qbd`'s socket by path is not a right landlock controls on these ABIs, so the
gateway reaches `qbd` after restricting itself, as `qb agent` does. Nothing else is readable:
the gateway never opens a file a client names, so image content arrives inline in requests.

On a kernel that cannot enforce part of this (no landlock, or an ABI below V4 without the TCP
port rules) the gateway starts, logs one warning per unenforced part, and is left with the
unit's hardening. Failing to clear the dumpable flag stops the start. The unit adds what a user
unit can enforce: `NoNewPrivileges`, `SystemCallFilter=@system-service` plus the landlock
calls, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute`,
`UMask=0077`, `MemoryMax` and `TasksMax` from the caps below.

Secrets:

- A credential file is read into a zeroizing buffer right before each upstream attempt. The
  header value is built at its final size in a zeroizing string, as `qb agent` builds its
  bearer, and dropped once the request is sent. Copies inside the HTTP client's buffers are
  out of reach; the agent accepts the same limit.
- An OAuth refresh writes the new token set to a temporary file created 0600 in the same
  directory, syncs it, renames it over the credential file and syncs the directory. One
  refresh per login runs at a time; a turn waiting on it re-reads the file afterwards. Before
  refreshing, the gateway re-reads the file and uses its token if another writer already
  replaced the one that failed.
- The gateway's credential files are its own. A vendor CLI that refreshes the same login from
  the same file would race it for a rotating refresh token, so the gateway's config points at
  a copy that only the gateway writes.
- Tokens never appear in logs, error messages, stream events or `qbd` reports. The gateway
  writes no file but credential files and logs no request or response content.

### `qbd` stays as it is

`qbd` keeps its contract, sandbox and budgets: no secrets, no network, no new endpoint. The
gateway is an ordinary client of `qbd`'s socket with a `[[clients]]` entry (by uid, or by
bearer on a forwarded socket) and uses `POST /v1/pick`, `POST /v1/report` and `GET /v1/state`.
The logins it holds are `qbd` `[[logins]]` under the same names, so the windows it observes reach
`qbd` the way stream reports from any client do. When `qbd` is unreachable the turn fails with
a retryable error: the gateway has no policy of its own and never calls a vendor without a
lease.

### Routes, picks and credentials

A route alias is a name in the gateway config mapped to one `qbd` pick target:

- `role` and `difficulty`: the role's ladder in `qbd`'s config, with `qbd`'s fallback to
  neighbouring steps, tiers and reserves; or
- `role` and `pin` (`vendor`, `model`, optional `effort`): one exact model, no ladder and no
  role reserve.

The alias table lives in the gateway config; ladders and reserves stay in `qbd`'s config.
`GET /v1/model/routes` lists the aliases with the state of their logins from `GET /v1/state`.

Each attempt of a turn is one `POST /v1/pick` with the route's target, `run_id` set to the
request's `session_key` or else its `request_id`, `resume_of` set to the `session_key` when the
request has one, `expected_minutes` from the route, and `avoid_vendor` when re-picking after a
vendor failure. Stickiness serves the prompt cache and must not block a turn: a `wait` answer to
a pick with `resume_of` is retried once without it.

The gateway config has one credential entry per login it holds: the `qbd` login name, the kind
(`oauth_anthropic` or `api_key` in G1) and the file. The `login` of a `run` answer selects the
entry by exact name; the kind selects the adapter and its auth mode; the answer's `model` is the
vendor model id; its `effort` becomes the adapter's reasoning parameter. A `run` naming a login
without an entry is a configuration error: the gateway reports `error` with `release: true`,
logs the login name and fails the turn without retry. Every login of a vendor that one of the
gateway's routes can reach therefore needs a credential in this gateway; a separate `qbd`
vendor keeps the gateway's logins apart from logins used elsewhere.

After each attempt the gateway sends `POST /v1/report` with the lease, `release: true`, the
windows read from the vendor's rate-limit headers and limit errors
(`anthropic-ratelimit-unified-*` for Anthropic), and the outcome:

| Attempt ended with | Outcome |
|---|---|
| a stream that started, finished or not | `ok` |
| usage limit reached or request rejected for quota | `usage_limit` |
| 429 without a usage limit | `http_429` |
| 401 after the one refresh and retry | `http_401` |
| model unknown or unavailable to the login | `model_unavailable` |
| 5xx, overload, network, TLS or timeout | `error` |

### Concurrency and streaming

There is no async runtime: the gateway uses std threads and blocking I/O.

- The main thread polls the listeners only and sleeps without a timeout when idle. Each
  accepted connection gets its own thread with a fixed small stack, which reads the request
  under a deadline, serves it and closes the connection.
- At most `max_turns` turns run at once (config, default 4, at most 16); a turn beyond the cap
  is answered 429 before any pick. Two more threads are reserved for routes, cancel and health,
  so cancel is served while turns are at the cap; anything beyond is answered 429 by the main
  thread.
- A request body is at most `max_request_bytes` (config, default 8 MiB, at most 32 MiB), read
  whole, parsed into the canonical request and translated into the upstream body; the client's
  body is dropped before the upstream call, so a turn peaks at about twice its body.
- The upstream answer is read as server-sent events by the gateway's own line parser with a
  bounded event size. Each event is translated and written as one chunk and flushed: one NDJSON
  line on the C4 front, one SSE event on the Messages front. Only a non-streaming Messages
  request is assembled in memory, from the same events.
- Each attempt is bounded by the route's turn timeout through ureq's global timeout.
- Cancel: turns in flight are registered by `request_id` with a cancel flag and a clone of the
  upstream TCP stream, which the gateway's ureq agent records through a small connector of the
  gateway's own. `POST /v1/model/cancel` sets the flag and shuts the stream down; the turn's
  blocked read returns at once, and the turn ends with an `error` event of class `cancelled`.
  Cancel answers 404 for an unknown `request_id` and 403 when the caller is not the peer that
  started the turn. A client that closes its connection cancels its turn too: the next write
  fails and the turn ends the same way. The Messages front has no cancel request; closing the
  connection is its cancel.

### Rotation boundary

The response head and the first event go out together, and only once an upstream stream has
started (HTTP 200 and its first event read) or the turn has a final error. Until then the client
has seen nothing and the gateway may retry within the turn:

- After a login-scoped failure (`usage_limit`, `http_429`, `http_401`, `model_unavailable`) it
  reports and picks again; `qbd`'s new mark steers the pick to another login or candidate. The
  failed login is not retried in this turn, except the single retry after a 401 and a refresh.
- After a vendor-scoped transient failure (5xx, overload, connect or TLS failure, timeout before
  the first event) it reports `error` and picks once more with `avoid_vendor` set to that vendor.
- Attempts per turn are bounded by `max_attempts` (config, default 4) and the turn timeout.

The gateway never retries a request the vendor rejected as invalid (400, too long, refusal), and
never retries after the first event: a failure there ends the stream with an `error` event, and
the client decides whether to send the turn again. Two upstream answers are never spliced into
one stream.

A turn that ends without a stream ends with one `error` event: `quota_exhausted` with
`retryable: true` and `resets_at` from the `retry_after` of a `wait` answer; `no_route` with
`retryable: false` for a `dead` answer; otherwise the last attempt's class. Its `tried` lists
every attempt with vendor, model, login and outcome. On the Messages front the same error is an
HTTP error response in the Messages error format, 429 with `retry-after` for
`quota_exhausted`.

### One core, two fronts

A single core runs a turn: pick, credential read and refresh, the vendor identity, the upstream
call, rotation, report and canonical events. For OAuth Anthropic logins the adapter adds the
identity the subscription endpoint expects from the vendor's CLI (system prompt prefix, beta
headers, user agent); clients never see or send it. Thinking blocks produced by another vendor
are dropped by the core.

- The C4 front, `POST /v1/model/turn`, `GET /v1/model/routes` and `POST /v1/model/cancel` on the
  unix socket, maps C4 requests to the canonical form and writes NDJSON events.
- The Messages front, `POST /v1/messages` on the unix socket and on the optional loopback port,
  maps an Anthropic Messages request to the canonical form, takes its `model` as a route alias,
  and writes Messages SSE events or one JSON body for `stream: false`.

Neither front has pick, report, rotation or credential logic of its own.

### Dependencies

G1 reuses `ureq` with rustls (ring) for upstream HTTPS and token refresh, `landlock`, `zeroize`,
`serde` and `serde_json` for C4, Messages and SSE payloads, `httparse` and the existing framing
for the server side, and `rustix` for `SO_PEERCRED`, `poll()` and the dumpable flag. G1 adds no
crate: the SSE parser, the chunked writer and the atomic file replace are small code of its own.
The connector uses ureq's `unversioned` transport interface, which may change in a minor
release; `Cargo.lock` pins ureq, and an upgrade is checked by compiling. A G2 vendor type crate
needs its own reason and measured cost under AGENTS.md rule 4.

### Budgets

| Resource | Target |
|---|---|
| binary | the same static binary within the existing ≤ 4 MiB (2.5 MiB until 2026-11-17); the gateway links no TLS or HTTP crate the agent does not already link |
| gateway RSS | idle ≤ 4 MiB; per turn in flight ≲ 1 MiB plus twice its request body |
| unit memory | `MemoryMax` ≥ `max_turns` × (2 × `max_request_bytes` + 1 MiB) + 4 MiB, 96 MiB for the defaults |
| CPU | 0 wake-ups/s idle: no timers, refresh only on demand; p99 ≤ 5 ms from a turn's request to its upstream request, without refresh and TLS handshake |
| network | 0 idle; one HTTPS request per attempt and one per refresh |

The card that delivers the gateway enforces the binary limit through `ci/budgets.sh` as today,
adds the RSS and idle wake-up checks to the acceptance lane, and gives `qb-gateway.service` its
exposure threshold in the `systemd-units` job.

### Terms of service

The OAuth mode presents the gateway to the vendor's subscription endpoint as the vendor's own
CLI. The key mode uses the vendor's public API with an API key and is the fallback when a vendor
does not allow subscription logins in other clients; switching is a change of credential kind
and `qbd` ladder, invisible to clients. The rules for users are in the README's
[Terms of service](../../README.md#terms-of-service).

## Consequences

- `qb` carries model traffic when the gateway runs, and the gateway holds, reads and refreshes
  tokens. README, `docs/design.md` and AGENTS.md rules 3 and 6 name it as the second component
  allowed outbound connections and credential access, and the only one that writes credentials.
- `qbd`'s guarantees hold unchanged; a deployment without the gateway is what it was.
- A compromised gateway has its owner's credentials and outbound port 443; landlock bounds files
  and ports, not destinations.
- Concurrency is bounded by threads, at most 16 turns per gateway; more owners run more
  gateways against one `qbd`.
- Clients need one protocol, C4 or the Messages API, and no vendor knowledge.
- Windows observed by the gateway and by other clients of the same logins land in one `qbd`
  model.

## Rejected alternatives

- Model traffic through `qbd`: secrets and network would enter the daemon, and long streams
  would break its single-threaded, one-request-per-connection loop and its sandbox.
- Carrying traffic in `qb agent`: the agent reads credentials read-only for one probe and talks
  only to `qbd`; a server and credential writes would widen the smallest privileged component.
  A separate role keeps the agent as it is; both may share sandbox and credential code.
- An async runtime: denied by `deny.toml`, about a hundred crates and megabytes of binary for a
  handful of concurrent turns.
- One `poll()` loop driving every turn over non-blocking TLS: needs an HTTP client state machine
  of its own over rustls for no gain at 16 turns.
- Retrying after the first event: the client would get duplicated or contradictory output and
  tool call ids from two answers.
- One pipeline per front: rotation, reporting and credential handling would drift apart.
- Sharing the vendor CLI's credential file: two refreshers of one rotating refresh token.
- Stickiness through `pin.login`: a pin skips role reserves; `resume_of` keeps them.
