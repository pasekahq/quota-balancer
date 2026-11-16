# Roadmap

## 0.0.x — skeleton (done)

- Cargo workspace (`qb-core`, `qb-proto`, `qb`), size-first release profile.
- `/v1/pick`, `/v1/report`, `/v1/state`, `/v1/health` with typed requests/responses, fixtures and
  contract tests over a real unix socket. `pick` answers `dead/no_candidates` until the policy lands.
- HTTP/1.1 framing with hard limits, `SO_PEERCRED` peer identity, systemd socket activation.
- Multicall binary: `qbd` / `qb daemon`, `qb agent` (connectivity only), CLI.
- systemd templates with hardening (`qbd.service` exposure 0.2).
- CI: fmt, clippy `-D warnings`, tests, MSRV, cargo-deny, gitleaks, size/RSS budgets, unit exposure.

## S1 — working balancer on one host

Order matters; each item lands as its own PR with tests.

1. **Config** (TOML): vendors, logins, windows, roles, ladders `difficulty → [{vendor, model,
   effort, tier}]`, reserves `R(role, difficulty, window)`, `T_burn`, TTLs, clients (`uid →
   name`, bearer `sha256`, role), journal mode, limits. Validation with clear errors;
   `deploy/examples/*.toml` with neutral names.
2. **`qb-core` policy**: fixed-size tables (≤ 32 logins × ≤ 4 windows, ≤ 256 leases),
   admissibility (`left = 1 − used − reserved − cost ≥ reserve`, reserve dropped inside
   `T_burn`), spend-before-reset urgency, lexicographic choice, ladder fallback, `wait` with
   `retry_after`, `dead`; leases with O(1) reserve accounting; report classes
   (`usage_limit`/`rejected` → exhausted until reset, 401 → `auth_stale` → `auth_dead`,
   429 → back-off, `model_unavailable` → per-model dead bit); deadline heap. Table and
   property tests, including: "vendor A dead → vendor B", "30 % left and reset in 6 h → spend it
   first", "everything dead → `dead`".
3. **`qb-vendors`**: parsers for quota data that vendor CLIs already emit (stream-json rate-limit
   events, statusline rate limits, session rollout rate limits) and for usage-endpoint responses.
   Synthetic fixtures only.
4. **Daemon**: `poll()` loop that sleeps until the next deadline (zero wake-ups when idle),
   append-only journal with rotation and replay on start, `journal=off`, per-client token bucket,
   bearer auth, singleflight probe requests to agents.
5. **CLI**: `pick/report/state/why`, `report --from-stream-json <file>`, `simulate <journal>`.
6. **Agent**: reverse connection to the daemon, lazy probe (TTL, back-off, `Retry-After`) via
   `ureq` + rustls (ring), landlock (read-only credential dirs, TCP 443 only), `zeroize`,
   non-dumpable; probe **off by default**.
7. **Service hardening check**: `systemd-analyze security` in CI for all units; `on_dead` /
   `on_recover` hooks (exec).
8. **Acceptance**: the three scenarios above end-to-end through the daemon; RSS ≤ 4 MiB after
   10⁴ picks; binary ≤ 2.5 MiB; pick p99 ≤ 1 ms over UDS; 0 wake-ups/s idle; `write_bytes = 0`
   with `journal=off`; no network interfaces but `lo` under `PrivateNetwork`.

Also in S1: `clients/python/qb_client.py` — a single-file stdlib client (~60 lines) for
Python orchestrators, with a fallback to local logic when the daemon is unreachable.

## S2 — several hosts

Remote clients through an ssh-forwarded unix socket with bearer tokens; agents on other hosts
registering their logins; client integrations.

## 0.1 — public release

History scanned with gitleaks, docs reviewed for anything environment-specific, release
workflow (static musl builds for x86_64 and aarch64, `SHA256SUMS`, build provenance), then the
repository goes public under `Apache-2.0 OR MIT`.

## Later (S3+)

TCP + mTLS transport, varlink on the same socket, read-only shared-memory state for status
bars, `.deb` packages.
