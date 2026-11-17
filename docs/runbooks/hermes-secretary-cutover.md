# Runbook: cut a Hermes agent over to `qb gateway`

This runbook installs `qb gateway` next to a running Hermes agent on the same host, points the
Hermes profile's Anthropic provider at the gateway's loopback port, verifies one turn and rolls
back. The gateway serves the Messages API described in
[anthropic.md](../anthropic.md#the-v1messages-front); its config is in
[config.md](../config.md#gateway-config).

Placeholders:

| Placeholder | Meaning |
|---|---|
| `<host>` | The host Hermes runs on. |
| `<user>`, `<uid>` | The user who runs Hermes and owns the gateway's credentials; the gateway runs as a user unit of this user. |
| `<hermes-profile-dir>` | The Hermes profile directory (its `HERMES_HOME`), holding `config.yaml`, `.env`, `auth.json` and `logs/`. |
| `<restart-hermes>` | The operator's command that restarts this Hermes profile, for example `systemctl --user restart <hermes-unit>`. |
| `<port>` | A free loopback TCP port for the gateway's Messages front. |
| `<gateway-vendor>`, `<gateway-role>` | The `qbd` vendor and role of the gateway's logins, used by nothing else. |
| `<login-1>` | A `qbd` login name of the gateway; repeat its entries for each further login. |
| `<credentials-dir>` | An absolute directory owned by `<user>`, mode 0700, holding only the gateway's credential files. |
| `<model-a>`, `<model-b>` | The Anthropic model names the profile sends (prerequisite 4). |

## Prerequisites

1. `qb` builds for `x86_64-unknown-linux-musl` from this repository, and the operator has a shell
   as `<user>` on `<host>` and root for the `qbd` steps.
2. The vendor terms allow the gateway's credential mode for each login ([README](../../README.md#terms-of-service)).
3. The Hermes profile matches the shape this runbook switches. Read, do not change:
   - `<hermes-profile-dir>/config.yaml` has `model.provider: anthropic` and no `model.base_url`
     (or an empty one). Hermes lets an Anthropic host in `model.base_url` override the base URL
     of every credential, which would send the client token past the gateway, and it ignores a
     loopback URL there.
   - Neither `<hermes-profile-dir>/.env` nor the environment of the Hermes service sets
     `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN`.
     `ANTHROPIC_TOKEN` and `CLAUDE_CODE_OAUTH_TOKEN` rank before `ANTHROPIC_API_KEY` in Hermes'
     credential pool and keep its OAuth credentials in the pool.
   - `HERMES_HOME=<hermes-profile-dir> hermes auth list anthropic` lists no `manual` entry. Hermes
     always selects entries added by `hermes auth add` first, and they keep the vendor's base URL.
     Entries from `claude_code` and `hermes_pkce` are fine: Hermes drops them from the pool while
     `ANTHROPIC_API_KEY` is the only Anthropic variable set, and seeds them again from their files
     once it is gone.

   If any check fails, stop: the two-line switch and its rollback do not hold for this profile.
4. Write down every Anthropic model name the profile sends: `model.default` and each model of
   provider `anthropic` elsewhere in `config.yaml` (auxiliary tasks, compression, fallback).
   Hermes sends them without an `anthropic/` prefix and with dots turned into hyphens
   (`claude-x-4.6` is sent as `claude-x-4-6`); map that form.
5. For each gateway login, a credential that no other program uses: an OAuth sign-in whose
   refresh token nothing else refreshes (two refreshers race for one rotating token, so never
   the token of a vendor CLI or of the Hermes profile itself), or an API key.
6. A baseline: send the agent one message that makes it call a tool, through its usual channel,
   and note the time to the answer. The same message is the verification turn.
7. `<user>`'s service manager outlives logins: `loginctl show-user <user> -p Linger` prints
   `Linger=yes`.

## Install

### Binary

On a build machine, from this repository:

```sh
CC_x86_64_unknown_linux_musl=gcc cargo build --release --locked --target x86_64-unknown-linux-musl
```

Copy `target/x86_64-unknown-linux-musl/release/qb` to `<host>` and install it where the units
expect it:

```sh
sudo install -m 0755 qb /usr/local/bin/qb      # qbd.service
install -D -m 0755 qb ~/.local/bin/qb          # qb-gateway.service, as <user>
```

### qbd, if absent

`systemctl status qbd.socket` shows whether `qbd` runs. If it does not, install it as in the
[README](../../README.md#install-as-a-service): copy `deploy/systemd/qbd.socket` and
`qbd.service` to `/etc/systemd/system/`, create the group `qb-clients`, and start from
[`deploy/examples/qbd.toml`](../../deploy/examples/qbd.toml) for `/etc/qb/qbd.toml`.

In either case add the gateway's vendor, logins, role and client to `/etc/qb/qbd.toml`:

```toml
[[vendors]]
name = "<gateway-vendor>"
windows = [
  { name = "five_hour", length_s = 18000, t_burn_s = 1800 },
  { name = "seven_day", length_s = 604800, t_burn_s = 43200 },
]

[[logins]]
name = "<login-1>"
vendor = "<gateway-vendor>"

[[roles]]
name = "<gateway-role>"

[[roles.ladder]]
difficulty = 1
candidates = [
  { vendor = "<gateway-vendor>", model = "<model-a>", tier = 1 },
  { vendor = "<gateway-vendor>", model = "<model-b>", tier = 1 },
]

[[clients]]
name = "gateway"
uid = <uid>
role = "<gateway-role>"
```

A `uid` is unique among clients: if `<uid>` is a `qbd` client already, identify the gateway by
bearer instead (`bearer_sha256` here, `qbd_bearer_file` in the gateway config). Then:

```sh
sudo usermod -aG qb-clients <user>
sudo systemctl enable --now qbd.socket      # first install
sudo systemctl restart qbd.service          # config change of a running qbd
qb state                                    # as <user>, in a new login: lists <login-1>
```

The gateway reaches `/run/qb/qb.sock` through the group `qb-clients`, which `<user>`'s service
manager has only when it started after the `usermod`. `systemd-run --user --wait --pipe id -G`
prints the manager's groups. Without the group, the manager needs a restart, which also restarts
every user unit of `<user>`, Hermes included: do it only with the owner's permission, before the
switch.

### Gateway credentials

As `<user>`, one file per login, mode 0600, in the format of
[config.md](../config.md#gateway-config):

```sh
install -d -m 0700 <credentials-dir>
umask 077
"${EDITOR:-vi}" <credentials-dir>/<login-1>.json
```

```json
{"type": "oauth_anthropic", "access_token": "...", "refresh_token": "...", "expires_at": 1800000000}
```

`expires_at` is Unix seconds; divide a millisecond value by 1000. An API key login is
`{"type": "api_key", "key": "..."}` with `kind = "api_key"` and `api = "anthropic"` in the
gateway config.

### Client token generation

```sh
umask 077
TOKEN="qb-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf %s "$TOKEN" | sha256sum | cut -d' ' -f1
```

The hash goes into `token_sha256`; the token goes only into the Hermes profile's `.env` in the
switch step, so keep this shell open until then. The `qb-` prefix keeps Hermes from taking the
token for an Anthropic OAuth token, which it would send with another identity.

### Gateway config

`~/.config/qb/gateway.toml` of `<user>`, one route per model name, pinned to the same model:

```toml
socket = "/run/user/<uid>/qb-gateway/gateway.sock"
qbd_socket = "/run/qb/qb.sock"
max_turns = 2
max_attempts = 4

[[logins]]
name = "<login-1>"
kind = "oauth_anthropic"
credentials = "<credentials-dir>/<login-1>.json"

[[routes]]
alias = "model-a"
role = "<gateway-role>"
vendor = "<gateway-vendor>"
model = "<model-a>"
expected_minutes = 2

[[routes]]
alias = "model-b"
role = "<gateway-role>"
vendor = "<gateway-vendor>"
model = "<model-b>"
expected_minutes = 2

[messages]
vendor = "<gateway-vendor>"
models = { "<model-a>" = "model-a", "<model-b>" = "model-b" }
listen = "127.0.0.1:<port>"
token_sha256 = "<the hash printed above>"
ping_interval_s = 10
```

`max_turns = 2` stays below the shipped unit's `TasksMax=8`: the gateway runs its main thread,
up to `max_turns` + 2 connection threads and, while a turn connects upstream, one DNS resolver
thread per turn. At `max_turns = 4` concurrent resolves exceed the limit and the turn whose
thread cannot start fails. Raise `max_turns` only together with `TasksMax`. A request beyond the
cap gets a 429 with `retry-after: 1`, which Hermes retries.

Every route pins `<gateway-vendor>`, the vendor of `[messages]`, so Hermes' history holds only
Anthropic blocks and stays valid after a rollback to direct Anthropic.

### Gateway unit

```sh
install -D -m 0644 deploy/systemd/qb-gateway.service ~/.config/systemd/user/qb-gateway.service
systemctl --user daemon-reload
systemctl --user enable --now qb-gateway.service
journalctl --user -u qb-gateway -n 20
qb --socket /run/user/<uid>/qb-gateway/gateway.sock health
```

A config error ends the process with exit code 2 and one line naming the field. Then check the
loopback front before Hermes uses it, from the shell that holds `$TOKEN`:

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:<port>/v1/messages \
  -H 'content-type: application/json' -d '{}'                      # 401: the token is checked
curl -sS http://127.0.0.1:<port>/v1/messages \
  -H @<(printf 'x-api-key: %s\n' "$TOKEN") \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -d '{"model": "<model-a>", "max_tokens": 32, "messages": [{"role": "user", "content": "Say ok."}]}'
```

The second call answers a Messages JSON body. The header file keeps the token off the process
list.

## Switch

1. Append two lines to `<hermes-profile-dir>/.env`, with the token from the shell above:

   ```sh
   printf 'ANTHROPIC_BASE_URL=http://127.0.0.1:<port>\nANTHROPIC_API_KEY=%s\n' "$TOKEN" \
     >> <hermes-profile-dir>/.env
   ```

   Hermes loads the profile `.env` over its process environment. With `ANTHROPIC_API_KEY` set and
   no `ANTHROPIC_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN`, it takes the API-key path: it seeds one pool
   entry `env:ANTHROPIC_API_KEY` whose base URL is `ANTHROPIC_BASE_URL`, and drops the
   `claude_code` and `hermes_pkce` OAuth entries, so a rotation after a 401 or 429 has no OAuth
   credential to move to. A base URL outside `anthropic.com` makes Hermes send the key as
   `x-api-key`, which the gateway checks.

2. Check the pool before the restart:

   ```sh
   HERMES_HOME=<hermes-profile-dir> hermes auth list anthropic
   ```

   It lists exactly one credential, `ANTHROPIC_API_KEY` of type `api_key` from
   `env:ANTHROPIC_API_KEY`, marked current. Any other row is a credential Hermes may send instead
   of the client token: roll back (delete the two lines) and stop.

3. Restart Hermes with `<restart-hermes>`.

## Verify one turn

Send the baseline message through the agent's usual channel. The turn passes when all of these
hold:

- The client's answer arrives and the tool call ran, as in the baseline.
- The gateway logged the turn, one line per Messages request, each naming the login `qbd` picked
  for the request's route:

  ```sh
  journalctl --user -u qb-gateway --since '-10 min'
  ```

  ```
  gateway: turn msg_<hex>_<n> of client-token: tool_use on <login-1>
  gateway: turn msg_<hex>_<n> of client-token: end on <login-1>
  ```

  `client-token` is the caller on the loopback port. No `warn` line `gateway: turn ... on
  <login-1>: ...` for these turns.
- `qb state` shows that login's windows updated by the turn: `source` is `stream`,
  `observed_at` is within the last minutes, and no lease of the gateway is left live.
  (`curl --unix-socket /run/qb/qb.sock http://qb/v1/state` answers the same.)
- No 401 on the loopback port: the gateway logs no refusal, so read Hermes' side, where none of
  `401`, `authentication_error` or `invalid x-api-key` appears:

  ```sh
  HERMES_HOME=<hermes-profile-dir> hermes logs errors --since 15m
  ```

A fallback provider in `config.yaml` can answer a turn the gateway failed, so the answer alone
does not prove the route: the gateway line and the `qb state` update do.

## Rollback

1. Delete the two lines from `<hermes-profile-dir>/.env`:

   ```sh
   sed -i -e '/^ANTHROPIC_BASE_URL=http:\/\/127\.0\.0\.1:<port>$/d' \
     -e '/^ANTHROPIC_API_KEY=qb-/d' <hermes-profile-dir>/.env
   ```

2. Restart Hermes with `<restart-hermes>`.
3. `HERMES_HOME=<hermes-profile-dir> hermes auth list anthropic` lists the profile's OAuth
   entries again, and the next turn adds no `of client-token` line to the gateway log.

Leave the gateway running. Stopping or restarting `qb-gateway.service`, or `qbd`, needs the
owner's permission; the gateway holds no state Hermes depends on once Hermes no longer calls it.

## Rollback criteria

Roll back at once on any of these during the verification turn or the first hours after it:

- Any 401 from the loopback port in Hermes' errors log.
- Any 5xx or 529 answer from the gateway (`api_error`, `overloaded_error`), or a gateway `warn`
  line for a turn, or a gateway login `auth_dead` in `qb state`.
- A turn that lacks a tool call or the thinking the same message produces directly.
- Time to the answer well above direct use: more than twice the baseline for the same message.
- A quota error (429 `rate_limit_error`) while `qb state` shows a gateway login with status `ok`
  and every window below 0.9 `used`.
- `hermes auth list anthropic` showing any credential besides `env:ANTHROPIC_API_KEY`.
