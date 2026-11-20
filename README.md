# quota-balancer (`qb`)

A small pre-flight scheduler for people who run coding agents on their own subscriptions.

Before your orchestrator starts an agent, it asks `qb` *where* to run it: which vendor, model and
login has quota left, which window resets soonest and should be spent first, and which
candidates are dead until a reset. `qb` answers in microseconds over a local unix socket and
holds a short lease so that parallel workers do not all pile onto the same last 2 % of a window.

With `qbd` and `qb agent` alone, your agents talk to their vendors directly, with their own CLIs
and credentials, and `qbd` never sees model traffic or a token. An agent loop without vendor
adapters of its own can instead send its model requests through the optional `qb gateway` role:
it runs as the owner of the logins, holds their OAuth tokens and API keys, refreshes the tokens,
picks and rotates logins through `qbd` and streams the answers back. It carries model traffic
only for its own credential owner. The decision is [ADR 0001](docs/adr/0001-model-gateway.md);
the gateway serves logins of the Anthropic Messages API, by OAuth token or API key, and of the
OpenAI Responses API, by ChatGPT subscription login or API key.

> **Status: pre-alpha skeleton (0.0.x).** The API contract, transport, CLI and service templates
> are in place, and the agent probes the vendors' usage endpoints; the scheduling policy and
> vendor adapters are being built.
> See [docs/roadmap.md](docs/roadmap.md). Not ready for use.

## Why

Agent orchestrators that juggle several subscriptions usually pick by a fixed order and find
out a login is exhausted only when a run fails. The quota numbers are already there: the vendor
CLIs print them into the streams your orchestrator reads anyway. `qb` collects those numbers,
keeps a tiny model of every window, and turns them into a decision:

- **spend-before-reset**: quota that will reset unused soon is spent first;
- **reserves per role**: keep headroom for reviews or urgent work;
- **dead vs. rate-limited**: a 429 back-off is not the same as an exhausted week;
- **fail fast**: a run that starts on a limit is reported and re-picked within seconds.

## Design in one screen

```
 orchestrator / CLI ──HTTP/1.1 over unix socket──▶ qbd   (policy, leases, journal)
   (reports windows seen in vendor streams)          no vendor secrets, no network
                                                      ▲ ▲ "probe login X" (optional)
 qb agent (runs as the credential owner) ─────────────┘ │ answers with numbers only
                                                        │ pick / report
 agent loop ──unix socket──▶ qb gateway (optional) ─────┘
   (one model API)           runs as the credential owner,
                             holds and refreshes its tokens ──HTTPS──▶ vendor APIs
```

- **One static binary, four roles**: `qbd` (daemon), `qb agent`, `qb gateway` (optional), `qb`
  CLI.
- **Synchronous and minimal**: no async runtime; `httparse` + `serde_json` + `rustix`.
- **State in RAM** plus an append-only journal (or none); `qbd` writes nothing else to disk but
  the `roles_file` an admin's `PUT /v1/admin/roles` replaces.
- **Hardened by default**: the daemon runs with `DynamicUser`, `PrivateNetwork`, a syscall
  filter and a 16 MB memory cap; `systemd-analyze security` rates the template 0.2 ("SAFE").
- **No telemetry.** `qb` makes no network connections except, optionally, the agent's
  probe to the vendor endpoints you configure and the gateway's requests to the vendors of its
  own credentials.

More in [docs/design.md](docs/design.md); the wire contract is in [docs/api.md](docs/api.md), the
daemon's config file in [docs/config.md](docs/config.md).

## Budgets

These are enforced in CI on every change (`ci/budgets.sh` and the acceptance lane, see
[docs/design.md](docs/design.md#budgets)):

| Budget | Limit |
|---|---|
| static musl binary | ≤ 4 MiB |
| daemon peak RSS after 10 000 picks | ≤ 4 MiB |
| pick latency over the unix socket, p99 | ≤ 1 ms |
| idle daemon wake-ups | 0 |
| disk writes with `journal = off`, no admin `PUT /v1/admin/roles` | 0 bytes |
| `qbd.service` exposure (`systemd-analyze security`) | ≤ 1.5 |

## Build

Requires Rust 1.85 or newer (`rustup` recommended).

```sh
cargo build --release
cargo test --workspace

# fully static binary, as shipped
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Try it

```sh
qb --socket /tmp/qb.sock daemon --config deploy/examples/minimal.toml &
qb --socket /tmp/qb.sock health
qb --socket /tmp/qb.sock pick --role worker --difficulty 1
curl --unix-socket /tmp/qb.sock http://qb/v1/state
```

`state` lists the logins from the config with their quota windows. Until a client reports
windows (`POST /v1/report`, see [docs/api.md](docs/api.md)) every window counts as unused, so
`pick` answers `run` on `login-1` with `"stale": true`.

More commands (`qb --help` lists every option):

```sh
qb why l-257                      # the lease, the reason it was granted, its login now
qb report --login login-1 --from-stream-json run.jsonl   # a Claude stream-json log, - = stdin
qb simulate --config new.toml /var/lib/qb/journal --pick '{"role":"worker","difficulty":1}'
qb --bearer-file token state                              # or QB_BEARER_FILE=token
```

- `report --from-stream-json` posts the windows of the log's last `rate_limit_event` with the
  outcome `rejected` if that event was rejected, else `ok`. It reads one line at a time, skips
  lines it cannot parse and lines over 1 MiB, and exits 1 without posting when the log has no
  such event.
- `simulate` replays a journal against a config without a daemon and writes nothing; see
  [docs/journal.md](docs/journal.md).
- `--bearer-file` sends the file's token, trailing whitespace trimmed, as
  `Authorization: Bearer`, for a socket forwarded from another host. The token is never taken
  from the command line; an empty file is a usage error.

## Install as a service

Templates live in [`deploy/systemd/`](deploy/systemd): `qbd.socket` + `qbd.service` (system
units, socket activation) and `qb-agent.service` (a user unit for the credential owner). Copy
the binary to `/usr/local/bin/qb`, write `/etc/qb/qbd.toml` (start from
[`deploy/examples/qbd.toml`](deploy/examples/qbd.toml)), create a `qb-clients` group for the
users allowed to talk to the daemon, then `systemctl enable --now qbd.socket`. The agent reads
`~/.config/qb/agent.toml` of its user (start from
[`deploy/examples/agent.toml`](deploy/examples/agent.toml)); probes stay off until
`[probe] enabled = true` in the daemon's config.
The gateway runs as `qb-gateway.service`, a user unit of the credential owner reading
`~/.config/qb/gateway.toml` (start from [`deploy/examples/gateway.toml`](deploy/examples/gateway.toml));
[docs/runbooks/hermes-secretary-cutover.md](docs/runbooks/hermes-secretary-cutover.md) installs it
next to a Hermes agent and switches that agent's Anthropic provider to it.

## Terms of service

Use `qb` only with your own subscriptions and keys, for your own work. It does not share, relay
or pool accounts between people, and it must not be used to do so: a gateway serves the one
person who owns its credentials, and its sockets are not for other people's clients.

The gateway's OAuth mode uses a subscription login through a client that is not the vendor's
own: it presents itself to the subscription endpoint as the vendor's CLI. A vendor's terms may
allow subscription logins only in its own clients, and may restrict or close an account used
otherwise. Read the terms of every vendor whose logins you put into the gateway. Where they
forbid it, use the key mode: an API key on the vendor's public API, which the gateway serves
through the same routes, so its clients do not change. Vendor terms change; read them again
when they do.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
