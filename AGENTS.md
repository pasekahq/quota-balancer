# AGENTS.md — rules for coding agents in this repository

Read this before changing anything. `README.md` is for humans; this file is for you.

## What this is

`qb` is a pre-flight quota scheduler for coding-agent subscriptions: one static Rust binary with
the roles `qbd` daemon, `qb agent`, `qb` CLI and the optional `qb gateway` (model traffic for its
credential owner, decided in `docs/adr/0001-model-gateway.md`; the Anthropic adapter is linked)
and a JSON `/v1` API over HTTP/1.1 on a unix socket. Design: `docs/design.md`. Contract: `docs/api.md`. Plan:
`docs/roadmap.md`. Decisions: `docs/adr/`.

## Layout

| Path | What |
|---|---|
| `crates/qb-core` | Pure policy: state, `pick`, `report`, leases. **No I/O, no clock, no `unsafe`.** The caller passes `now`. |
| `crates/qb-proto` | Wire types of `/v1`. Every message is declared here exactly once. Fixtures in `tests/fixtures/`. |
| `crates/qb-vendors` | Pure, total parsers of vendor quota data (stream-json, statusline, rollouts, usage endpoints) into `qb-proto` window reports. Rules in `docs/vendors.md`; fixtures in `tests/fixtures/`. |
| `crates/qb-anthropic` | Pure translation between canonical C4 turns and the Anthropic Messages API, both directions: request body and header modes, SSE parser and event translator, rate-limit headers and error classification, and the `/v1/messages` front's decoder and encoders. Rules in `docs/anthropic.md`; fixtures in `tests/fixtures/`. |
| `crates/qb-openai` | Pure translation between canonical C4 turns and the OpenAI Chat Completions and Responses APIs, both directions: Responses request body and header modes (API key, ChatGPT login), SSE parser and event translator, rate-limit headers and error classification, and the `/v1/chat/completions` and `/v1/responses` fronts' decoders and encoders. Rules in `docs/openai.md`; fixtures in `tests/fixtures/`. |
| `crates/qb` | The binary: `http.rs` (framing), `server.rs` (`poll()` loop), `api.rs` (routing), `journal.rs` (journal lines, rotation, replay), `client.rs`, `listen.rs` (systemd socket activation), `agent.rs` (probe loop, HTTPS fetcher), `sandbox.rs` (agent and gateway hardening), `gateway/` (`qb gateway`: `config.rs`, `creds.rs` credential files and refresh, `upstream.rs` the adapter seam, `anthropic.rs` the Anthropic adapter over ureq, `oauth.rs` the OAuth token refresher, `core.rs` pick/report/rotation, `front.rs` the unix socket, the loopback listener and the C4 front, `answer.rs` the HTTP fronts' SSE or body answer, `messages.rs` the `/v1/messages` front, `openai.rs` the `/v1/chat/completions` and `/v1/responses` fronts), `main.rs` (CLI). |
| `deploy/systemd/` | Unit templates with hardening. |
| `ci/budgets.sh` | Binary size and static-link checks; the other budgets are the acceptance lane (`docs/design.md`, "Budgets"). |
| `clients/python/` | `qb_client.py`: single-file stdlib client (Python ≥ 3.9) to copy in; `contract.rs` drives it through `contract_driver.py`, so `cargo test` needs `python3`. |
| `ci/broad_check.py` | Stdlib-only driver for fmt + clippy + test (`python3 -m ci.broad_check`); external harnesses call this. |

## Commands (all must pass before you push)

If `cargo` is not on `PATH`, use `$HOME/.cargo/bin/cargo`.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
CC_x86_64_unknown_linux_musl=gcc cargo build --release --locked --target x86_64-unknown-linux-musl && ci/budgets.sh
```

ring's build script compiles C for the musl target; `CC_x86_64_unknown_linux_musl` names the
compiler when `x86_64-linux-musl-gcc` is not installed.

Optional locally, always in CI: `cargo deny check`, `gitleaks git .`, and the exposure of every
service unit within its own threshold (the `systemd-units` job; a new unit needs a case there):

```sh
for unit in deploy/systemd/*.service; do
  case "${unit##*/}" in
    qbd.service) threshold=15 ;;
    qb-agent.service) threshold=69 ;;
    qb-gateway.service) threshold=62 ;;
    *) echo "no exposure threshold for $unit"; continue ;;
  esac
  systemd-analyze security --offline=yes --threshold="$threshold" --no-pager "$unit"
done
```

Release builds are CPU-heavy (fat LTO). Run one cargo build at a time on shared hosts, under
`nice`, and do not start parallel builds of other projects.

## Hard rules

1. **No secrets anywhere in the repo**: no tokens, cookies, real account ids, e-mails or
   credential files, not even in tests. Fixtures are synthetic or anonymised (`login-1`,
   `vendor-a`). gitleaks scans the full history in CI.
2. **Nothing environment-specific in code or docs**: no host names, IPs, user names, home paths
   or names of the orchestrators that use `qb`. Everything deployment-specific goes through
   config; examples live in `deploy/examples/` with neutral names.
3. **No telemetry, no phone-home, no update checks.** Two components may connect outbound, both
   only over TCP 443 to vendor endpoints: the agent's vendor probes, off by default, and
   `qb gateway`'s model requests and OAuth token refreshes for the credentials in its config.
4. **Stay synchronous and small.** No tokio/hyper/axum/reqwest/chrono/openssl (enforced by
   `deny.toml`). A new dependency needs a reason in the PR description; keep direct
   dependencies ≤ 12 and the tree ≲ 50 crates (`cargo tree`).
5. **Budgets are part of the contract**: binary ≤ 4 MiB, daemon RSS ≤ 4 MiB after 10⁴ picks,
   `qbd.service` exposure ≤ 1.5. Do not raise a limit to make CI green; fix the cause or ask.
6. **The daemon never holds vendor credentials** and never opens outbound sockets. Only two
   components touch credential files, both as the credential owner, non-dumpable, under
   landlock and with `zeroize` after use: `qb agent` reads them read-only for the duration of
   one request; `qb gateway` reads them for each upstream request and is the only component
   that writes them, and only to store refreshed OAuth tokens (0600, temporary file renamed in
   the same directory). Neither puts a secret into a log, an error, a response or a report.
7. **`unsafe`** is forbidden in `qb-core` and `qb-proto` and denied in `qb`; the single
   exception (`listen.rs`, fd ownership from systemd) carries a `SAFETY:` comment. New
   exceptions need the same and a test.
8. **Wire compatibility**: `/v1` only grows. New response fields are optional; request types
   keep `deny_unknown_fields`. Change a type in `qb-proto` → update `docs/api.md` and add or
   adjust a fixture.

## Conventions

- Rust edition 2024, MSRV 1.85 (`rust-version` in `Cargo.toml`; CI checks it).
- Errors are values: no `unwrap()` outside tests; `expect()` only for real invariants.
- Logs go to stderr via `qb::log` (journald priority prefixes), no logging framework.
- Times are Unix seconds (`u64`), fractions are `0.0..=1.0`.
- Policy logic gets table tests in `qb-core`; transport behaviour gets contract tests in
  `crates/qb/tests/contract.rs` over a real socket.
- Commits: imperative mood, one logical change; PRs must have green CI before merge.
- Docs are in English. Keep README for humans (what, why, how to run); put agent-only rules here.
