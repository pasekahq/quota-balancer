# Changelog

All notable changes to `qb` are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a minor version may
break the CLI, the config files or `/v1`; the wire contract in [docs/api.md](docs/api.md) only
grows within a minor version.

The release workflow publishes the section of a version as its release notes; how a release is
made and verified is in [docs/release.md](docs/release.md).

## [Unreleased]

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

[Unreleased]: https://github.com/pasekahq/quota-balancer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pasekahq/quota-balancer/releases/tag/v0.1.0
