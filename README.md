# quota-balancer (`qb`)

A small pre-flight scheduler for people who run coding agents on their own subscriptions.

Before your orchestrator starts an agent, it asks `qb` *where* to run it: which vendor, model and
login has quota left, which window resets soonest and should be spent first, and which
candidates are dead until a reset. `qb` answers in microseconds over a local unix socket and
holds a short lease so that parallel workers do not all pile onto the same last 2 % of a window.

`qb` is **not a proxy**. Your agents talk to their vendors directly, with their own CLIs and their
own credentials. `qb` never sees model traffic and never stores or refreshes anyone's tokens.

> **Status: pre-alpha skeleton (0.0.x).** The API contract, transport, CLI and service templates
> are in place; the scheduling policy, vendor adapters and the agent's probe are being built.
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
                                                      ▲ "probe login X" (optional)
 qb agent (runs as the credential owner) ─────────────┘ answers with numbers only
```

- **One static binary, three roles**: `qbd` (daemon), `qb agent`, `qb` CLI.
- **Synchronous and minimal**: no async runtime; `httparse` + `serde_json` + `rustix`.
- **State in RAM** plus an append-only journal (or no disk writes at all).
- **Hardened by default**: the daemon runs with `DynamicUser`, `PrivateNetwork`, a syscall
  filter and a 16 MB memory cap; `systemd-analyze security` rates the template 0.2 ("SAFE").
- **No telemetry.** `qb` makes no network connections except, optionally, the agent's
  probe to the vendor endpoints you configure.

More in [docs/design.md](docs/design.md); the wire contract is in [docs/api.md](docs/api.md).

## Budgets

These are enforced in CI on every change (`ci/budgets.sh`):

| Budget | Limit | Current skeleton |
|---|---|---|
| static musl binary | ≤ 2.5 MiB | ~0.5 MiB |
| daemon peak RSS after 10 000 requests | ≤ 4 MiB | ~0.6 MiB |
| `qbd.service` exposure (`systemd-analyze security`) | ≤ 1.5 | 0.2 |

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
qb --socket /tmp/qb.sock daemon &
qb --socket /tmp/qb.sock health
qb --socket /tmp/qb.sock pick --role worker --difficulty 1
curl --unix-socket /tmp/qb.sock http://qb/v1/state
```

With no logins configured, `pick` answers `{"decision":"dead","reason":"no_candidates"}`.

## Install as a service

Templates live in [`deploy/systemd/`](deploy/systemd): `qbd.socket` + `qbd.service` (system
units, socket activation) and `qb-agent.service` (a user unit for the credential owner). Copy
the binary to `/usr/local/bin/qb`, create a `qb-clients` group for the users allowed to talk to
the daemon, then `systemctl enable --now qbd.socket`.

## Terms of service

Use `qb` only with your own subscriptions, for your own work. It does not share, relay or pool
accounts between people, and it must not be used to do so. Vendor terms change; read them.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.
