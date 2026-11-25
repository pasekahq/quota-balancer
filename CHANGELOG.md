# Changelog

All notable changes to `qb` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
break the CLI, the config files or `/v1`; the wire contract in [docs/api.md](docs/api.md) only
grows within a minor version.

The release workflow publishes the section of a version as its release notes; how a release is
made and verified is in [docs/release.md](docs/release.md).

## [Unreleased]

### Added

- **`qb login reset --quota`**: `POST /v1/admin/logins/reset` takes an optional `quota`, which
  also clears the `exhausted`, `rate_limited` and dead-model marks and the window readings of the
  logins, so a login paid up or topped up before its windows reset works again without a
  restart or a renamed login. Admin clients of `qbd` only, journaled and logged.

## [0.2.0] - 2026-11-24

Anthropic Message Batches through the gateway, credential marks that follow a replaced
credential, and fixes before the first pilot.

### Added

- **Message Batches** for `api_key` Anthropic logins: `POST /v1/model/batches` submits a batch on
  a route, `GET /v1/model/batches/{batch_id}` reads its status, `.../results` streams its results
  and `.../cancel` cancels it, each for the caller that created it, with a `[batches]` store in
  the gateway config. A batch reserves its cost under the login's `spend_cap` before its create
  and settles it from its complete results. `qb batch submit|status|results|cancel` drives them
  from the CLI.
- **`qb login reset`** and credential fingerprints: `POST /v1/report` takes an optional
  `credential` fingerprint, and an `auth_stale` or `auth_dead` mark clears once the gateway
  announces another credential for the login, so a replaced key or sign-in no longer stays dead.

### Changed

- The examples, `docs/config.md` and the runbooks identify `qbd`'s clients by `bearer_sha256`:
  the shipped `qbd.service` runs with `PrivateUsers=yes`, which shows every caller's uid as the
  overflow uid, so a client by `uid` matched nobody. The gateway example sets
  `qbd_bearer_file`, `qb-agent.service` sets `QB_BEARER_FILE`.
- The installation check of the shipped examples follows the documented client rule, and finds a
  route whose `logins` cannot serve its pin, chain steps or ladder.

### Fixed

- A token refresh that failed in transport, with a 5xx or with a 429 no longer ends the turn: the login
  is left for the rest of the turn without a mark in `qbd`, and the turn moves to the next login;
  it ends `unavailable`, retryable, only when none is left.
- A tool call cut by the output token limit (`max_tokens` on Anthropic, `length` on Chat
  Completions, an incomplete Responses answer) is dropped and the turn ends with `max_tokens`,
  instead of failing as `unavailable`, being retried on another login and paid twice.
- A 401 is reported with the fingerprint of the credential the attempt sent, so a key replaced
  while a request was in flight is not marked dead.
- `GET /v1/model/usage` totals saturate at the `u64` limits and survive a rotation between
  listing and reading the ledger.
- The key and sign-in paste bodies of `/v1/model/logins/{name}/*` are decoded without
  unzeroized copies of the secret.

## [0.1.0] - 2026-11-22

The first tagged release: static musl binaries for x86_64 and aarch64, `SHA256SUMS` and build
provenance attestations.

### Added

- **`qbd`, the pre-flight scheduler.** `POST /v1/pick` chooses a vendor, model and login from a
  role's ladder by spend-before-reset urgency, per-role reserves and a lease that holds the
  expected cost; `POST /v1/report` takes quota windows and outcomes (`usage_limit`, `rejected`,
  429 back-off, `auth_stale`, `model_unavailable`); `GET /v1/state`, `/v1/why/{lease_id}`,
  `/v1/health` and `/v1/roles`. A pick may be limited to an allow-list of logins. HTTP/1.1 on a
  unix socket with `SO_PEERCRED` peer identity, bearer tokens for forwarded sockets, a token
  bucket per client and systemd socket activation.
- **State and journal.** State in RAM, an append-only journal with rotation and replay at start,
  or no journal at all; `qb simulate` replays a journal against a config without a daemon.
- **Reloads and admin API.** `SIGHUP` reloads roles and clients; roles may live in a separate
  `roles_file`; admin clients read and replace it through `GET`/`PUT /v1/admin/roles` and
  reload through `POST /v1/admin/reload`.
- **`qb agent`.** Runs as the credential owner and answers the daemon's probe jobs from vendor
  usage endpoints, non-dumpable, under landlock and with `zeroize`; probes are off by default.
- **Vendor parsers** (`qb-vendors`) for the quota data vendor CLIs already emit: stream-json
  rate-limit events, statusline rate limits, session rollouts and usage endpoint responses;
  `qb report --from-stream-json` posts the windows of a log.
- **`qb gateway`, the optional model gateway** for its own credential owner
  ([ADR 0001](docs/adr/0001-model-gateway.md)): `POST /v1/model/turn` streaming NDJSON events,
  `GET /v1/model/routes` and `/v1/model/ladder`, `POST /v1/model/cancel` and `/v1/model/reload`.
  Every turn is a `qbd` pick with windows reported from rate-limit headers and errors, and
  rotates to the next login or vendor of a chain on `usage_limit`.
- **Upstreams**: the Anthropic Messages API (OAuth subscription login or API key, automatic
  prompt caching, signed thinking), the OpenAI Responses API (ChatGPT subscription login or API
  key) and Chat Completions for OpenAI-compatible API keys such as OpenRouter; cross-vendor
  fallback with stable tool call ids.
- **Fronts**: `POST /v1/messages`, `POST /v1/chat/completions` and `POST /v1/responses` on the
  gateway's unix socket and an optional loopback port, for SDK clients and vendor CLIs.
- **Gateway operation**: named loopback client tokens with route limits and rotation with a
  grace period, a content-free usage ledger and `GET /v1/model/usage`, an append-only admin
  audit file and `GET /v1/model/audit`, monthly spend caps per API key login, `GET`/`PUT
  /v1/model/config/routes`, replacement of an API key and OAuth sign-in through
  `/v1/model/logins/{name}/*`, and `qbd`'s admin API forwarded for the gateway's own uid.
- **Logins**: `qb login import` copies an existing credential file into the gateway's store;
  `qb login` signs a login in with PKCE. Credential files are 0600 and replaced atomically.
- **Operation**: hardened systemd units (`qbd.socket` and `qbd.service`, `qb-agent.service`,
  `qb-gateway.service`) with their exposure checked in CI, `on_dead`/`on_recover` hooks,
  neutral examples in `deploy/examples/`, runbooks in `docs/runbooks/`, and a single-file
  stdlib Python client in `clients/python/`.
- **Budgets** checked in CI: a static binary of at most 4 MiB, daemon and gateway peak RSS of at
  most 4 MiB, pick p99 of at most 1 ms, no idle wake-ups.
- **Release**: a release workflow that builds static binaries for `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl`, publishes them bare and as tarballs with `SHA256SUMS`, and
  attests their build provenance. `qb --version` prints the git revision it was built from,
  e.g. `qb 0.1.0 (0123456789ab)`.

[Unreleased]: https://github.com/pasekahq/quota-balancer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/pasekahq/quota-balancer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/pasekahq/quota-balancer/releases/tag/v0.1.0
