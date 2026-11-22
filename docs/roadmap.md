# Roadmap

## 0.0.x — skeleton (done)

- Cargo workspace (`qb-core`, `qb-proto`, `qb`), size-first release profile.
- `/v1/pick`, `/v1/report`, `/v1/state`, `/v1/health` with typed requests/responses, fixtures and
  contract tests over a real unix socket.
- HTTP/1.1 framing with hard limits, `SO_PEERCRED` peer identity, systemd socket activation.
- Multicall binary: `qbd` / `qb daemon`, `qb agent` (the credential owner that answers the
  daemon's probe jobs), CLI.
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
   10⁴ picks; binary ≤ 4 MiB; pick p99 ≤ 1 ms over UDS; 0 wake-ups/s idle; `write_bytes = 0`
   with `journal=off`; no network interfaces but `lo` under `PrivateNetwork`.

Also in S1: `clients/python/qb_client.py` — a single-file stdlib client (~60 lines) for
Python orchestrators, with a fallback to local logic when the daemon is unreachable.

## G1: model gateway, contract and Anthropic (done)

The optional `qb gateway` role as decided in [ADR 0001](adr/0001-model-gateway.md).

1. ADR and the positioning of README, design, rules and roadmap.
2. Gateway contract: `POST /v1/model/turn` streaming NDJSON events, `GET /v1/model/routes`,
   `POST /v1/model/cancel`, in `docs/api.md` and an OpenAPI document, with fixtures and contract
   tests over a unix socket.
3. Credential store: 0600 files from the gateway's config, kinds `oauth_anthropic` and
   `api_key`, OAuth refresh with an atomic replace; a test that no secret reaches a log.
4. Anthropic Messages adapter: canonical request and SSE stream to gateway events, automatic
   prompt caching, signed thinking; OAuth mode with the vendor CLI's identity and beta headers,
   and key mode; tests on recorded synthetic streams.
5. Pick and report around each request: route alias to a `qbd` pick, windows reported from
   rate-limit headers and errors, rotation to the next login within the turn on `usage_limit`,
   and `quota_exhausted` with the nearest `resets_at` when every candidate is spent.
6. Messages-compatible front: `POST /v1/messages` on the same core, on the unix socket and
   optionally on a loopback port with a local client token.
7. Operation: gateway budgets in `ci/budgets.sh` and the acceptance lane, a hardened systemd
   user unit with its exposure threshold in CI, a manual smoke test on one OAuth login.

## G2: model gateway, OpenAI and Codex, keys, OpenRouter, chains (done)

The live check of the subscription logins runs per [runbooks/openai-live-smoke.md](runbooks/openai-live-smoke.md).

1. OpenAI Responses upstream: ChatGPT subscription logins (`chatgpt_oauth`, access token and
   account id) and OpenAI API keys, rotated like Anthropic logins.
2. OpenAI fronts: `POST /v1/chat/completions` and `POST /v1/responses` on the same core, on the
   unix socket and the loopback port, so OpenAI SDK clients run on any login.
3. Chat Completions adapter for OpenRouter and other API keys.
4. Cross-vendor fallback: foreign thinking blocks dropped, tool call ids stable across
   vendors, end-to-end test of a chain that falls from one vendor to the next.
5. Chains across vendors in the route config, and a config reload (`qb reload` or `SIGHUP`)
   that does not cut streams in flight.
6. Spend cap per API key, from the cost of reported usage.
7. Login import and login: `qb login import` from existing credential files by path,
   without printing values; `qb login` with PKCE for Anthropic and OpenAI.
8. CI and budgets green, `docs/config.md` with neutral examples.

## S2 — several hosts

Remote clients through an ssh-forwarded unix socket with bearer tokens; agents on other hosts
registering their logins; client integrations.

## 0.1 — public release (done)

History scanned with gitleaks, docs reviewed for anything environment-specific, release
workflow (static musl builds for x86_64 and aarch64, `SHA256SUMS`, build provenance; see
[release.md](release.md)), then the repository is public at `pasekahq/quota-balancer` under
`AGPL-3.0-only`.

## Later (S3+)

TCP + mTLS transport, varlink on the same socket, read-only shared-memory state for status
bars, `.deb` packages.
