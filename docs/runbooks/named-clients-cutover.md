# Runbook: move loopback consumers to named clients

This runbook moves the consumers of one gateway's loopback listener from the unnamed client token
`fronts.token_sha256`, whose turns run as `client-token`, to named clients with token files of
their own ([config.md](../config.md#gateway-config), `[[fronts.clients]]`), one consumer at a
time, with every consumer served throughout. Each step has its verification and its rollback.
The consumers covered are a Hermes agent profile switched to the gateway by
[hermes-secretary-cutover.md](hermes-secretary-cutover.md) and the agent heads of an
orchestrator that share one family of routes; repeat a consumer's steps for any further one.

Placeholders:

| Placeholder | Meaning |
|---|---|
| `<user>`, `<uid>` | The user the gateway runs as, a user unit of this user, and its uid. |
| `<gateway-config>` | The gateway's config file, `~/.config/qb/gateway.toml` of `<user>` with the shipped unit. |
| `<gateway-socket>` | The gateway's `socket`, for example `/run/user/<uid>/qb-gateway/gateway.sock`. |
| `<port>` | The port of `fronts.listen`. |
| `<front-path>` | The path a consumer posts to: `/v1/messages`, `/v1/chat/completions` or `/v1/responses`. |
| `<state-dir>` | An absolute directory owned by `<user>`, mode 0700, holding `fronts.grace_file` and the client token files. |
| `<backup-dir>` | An absolute directory owned by `<user>`, mode 0700, for the copies this runbook keeps for its rollbacks. |
| `<login-1>` | A login of the gateway, as in the Hermes cutover runbook. |
| `<hermes-profile-dir>`, `<restart-hermes>` | The Hermes profile directory and the command that restarts it, as in the Hermes cutover runbook. Hermes reads its token from the environment: the line `ANTHROPIC_API_KEY=` of `<hermes-profile-dir>/.env`, loaded when it starts. |
| `<hermes-client>`, `<hermes-routes>` | The named client of the Hermes profile and its route aliases, for example `model-a` and `model-b` of the Hermes cutover runbook. |
| `<heads-client>`, `<heads-routes>` | The named client of the orchestrator's heads and the route aliases of their family. |
| `<heads-token-setting>` | The orchestrator's setting that gives a head its token: a path the head reads the token from when it starts, or an environment variable the orchestrator sets from that file when it starts a head. |
| `<restart-heads>` | The operator's command that makes the orchestrator start its heads again, or start new heads only with the changed setting. |
| `<window-s>` | The agreed number of seconds without `client-token` usage before the unnamed token goes; at least the longest run of a head. |
| `<outside-model>` | A client model name that resolves to a route outside a client's `routes`. |

Every command runs as `<user>` on the gateway's host.

## Prerequisites

1. The gateway runs a `qb` built from a revision of this repository with named clients:
   `[[fronts.clients]]` with `token_file`, `fronts.grace_file`, `rotate_grace_s` and
   `POST /v1/model/clients/{name}/rotate`. `qb --version` does not tell revisions apart; note the
   revision the binary was built from. Install a newer binary as in the Hermes cutover runbook's
   [Binary](hermes-secretary-cutover.md#binary) step; it takes effect at the restart of
   prerequisite 3.
2. Admin access to the gateway as its own uid: `qb --socket <gateway-socket> reload`,
   `GET /v1/model/audit`, `GET /v1/model/usage` and the rotation answer only to `<uid>`, any
   other caller gets 403.
3. `<gateway-config>` sets `audit_file`, `[usage]` and `fronts.grace_file`, and the gateway
   started with them. They are restart-only: a reload that adds or changes one is refused, and
   a token file is accepted by a reload only in a directory the gateway opened at its start.
   Add the missing ones in one edit and restart once, before the first step:

   ```sh
   install -d -m 0700 <backup-dir> <state-dir> <state-dir>/audit <state-dir>/usage
   cp -p <gateway-config> <backup-dir>/gateway.toml.pre-restart
   "${EDITOR:-vi}" <gateway-config>
   ```

   ```toml
   audit_file = "<state-dir>/audit/audit.jsonl"

   [usage]
   file = "<state-dir>/usage/usage.jsonl"
   keep_days = 90

   [fronts]
   grace_file = "<state-dir>/grace.json"
   # rotate_grace_s: at least the longest run of a head, at most 604800
   ```

   `audit_file` is a top-level key and goes before the tables; `grace_file` and `rotate_grace_s`
   join the existing `[fronts]` table. When the running gateway already has named clients,
   `qb --socket <gateway-socket> reload` checks the edited file first: it must exit 1 with
   `reload refused: <file>: <field>: changed; it takes effect only on a restart`, naming
   `audit_file`, `usage` or `fronts.grace_file`. Any other refusal would also stop the restarted
   gateway with exit code 2: fix the file first. The restart ends the turns running at that
   moment, so it needs the owner's permission and a quiet moment:

   ```sh
   systemctl --user restart qb-gateway
   journalctl --user -u qb-gateway -n 20
   curl -sS --unix-socket <gateway-socket> 'http://qb/v1/model/audit?since=0'
   ```

   The audit answers `{"entries": [], "skipped": 0}` or older entries, not a 404. Rollback: copy
   `<backup-dir>/gateway.toml.pre-restart` back to `<gateway-config>` and restart again.
4. For each consumer, how it reads its token and how it is restarted: `<restart-hermes>` for
   Hermes, `<heads-token-setting>` and `<restart-heads>` for the heads. A consumer runs as
   `<user>`, so it can read a 0600 token file of `<user>`; a head that runs as another user gets
   the token from a process that does, for example its orchestrator.
5. A copy of the unnamed token, for the rollbacks and the final 401 check, taken from where a
   consumer reads it, whose hash is `fronts.token_sha256`:

   ```sh
   umask 077
   sed -n 's/^ANTHROPIC_API_KEY=//p' <hermes-profile-dir>/.env > <backup-dir>/legacy.token
   tr -d '\n' < <backup-dir>/legacy.token | sha256sum
   grep '^token_sha256' <gateway-config>
   ```

   The two hashes are equal.

A check of a token that spends no quota, in the shell used for the steps below: a token the
listener accepts gets 400 for the empty body, any other token 401. The header file keeps the
token off the process list.

```sh
probe() {  # probe <token file> [<body>]: the listener's status for the token in the file
  local body='{}'
  [ $# -gt 1 ] && body=$2
  curl -sS -o /dev/null -w '%{http_code}\n' "http://127.0.0.1:<port><front-path>" \
    -H @<(printf 'x-api-key: %s\n' "$(cat "$1")") \
    -H 'content-type: application/json' -d "$body"
}
probe <backup-dir>/legacy.token                    # 400
```

## 1. Add the named clients beside the unnamed token

1. One token file per consumer in `<state-dir>`, mode 0600, owned by `<user>`:

   ```sh
   umask 077
   for client in <hermes-client> <heads-client>; do
     printf '%s\n' "qb-$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
       > <state-dir>/"$client".token
   done
   ls -l <state-dir>
   ```

   The gateway cuts one trailing newline. A consumer reads the token without it: Hermes from
   its `.env` line written in step 2, a head from the file or the variable of
   `<heads-token-setting>`.

2. Back up the config and add one `[[fronts.clients]]` entry per consumer after `[fronts]` and
   its sub-tables, keeping `fronts.token_sha256`:

   ```sh
   cp -p <gateway-config> <backup-dir>/gateway.toml.pre-clients
   "${EDITOR:-vi}" <gateway-config>
   ```

   ```toml
   [[fronts.clients]]
   name = "<hermes-client>"
   token_file = "<state-dir>/<hermes-client>.token"
   routes = <hermes-routes>

   [[fronts.clients]]
   name = "<heads-client>"
   token_file = "<state-dir>/<heads-client>.token"
   routes = <heads-routes>
   ```

   `routes` is a TOML array of aliases, `["model-a", "model-b"]`; leave it out for a consumer
   that may run on every route. A name is neither `client-token` nor a `[[clients]]` name.

3. Reload:

   ```sh
   t0=$(date +%s)
   qb --socket <gateway-socket> reload
   ```

Verify:

- `qb reload` prints `{"routes": <n>, "logins": <m>}` and the journal has
  `gateway: reloaded <gateway-config>: <n> routes, <m> logins`.
- The audit has the reload, `"action": "reload"`, `"result": "ok"`, with `config_sha256_before`
  and `config_sha256_after` different:

  ```sh
  curl -sS --unix-socket <gateway-socket> "http://qb/v1/model/audit?since=$t0"
  ```

- The new tokens and the unnamed one are accepted, and `routes` holds:

  ```sh
  probe <state-dir>/<hermes-client>.token          # 400
  probe <state-dir>/<heads-client>.token           # 400
  probe <backup-dir>/legacy.token                  # 400
  probe <state-dir>/<hermes-client>.token \
    '{"model": "<outside-model>", "max_tokens": 1, "messages": [{"role": "user", "content": "x"}]}'
                                                   # 403
  ```

  On `/v1/responses` the last body is `{"model": "<outside-model>", "input": "x"}`. The 403
  comes before any pick and logs
  ``gateway: loopback refused client `<hermes-client>` route `<alias>`: route``.
- The consumers' next turns still log `gateway: turn ... of client-token: ...`.

Rollback: copy `<backup-dir>/gateway.toml.pre-clients` back to `<gateway-config>` and reload;
the reload answers its counts and the probes of the named tokens answer 401. The token files may
stay until the next attempt.

## 2. Switch one consumer at a time

Switch one consumer, verify it, and only then the next one.

### Hermes

1. Back up `.env` and replace the value of its `ANTHROPIC_API_KEY` line with the token file's:

   ```sh
   env_file=<hermes-profile-dir>/.env
   cp -p "$env_file" <backup-dir>/hermes.env.pre-switch
   umask 077
   awk -v f=<state-dir>/<hermes-client>.token \
     'BEGIN { getline t < f } /^ANTHROPIC_API_KEY=/ { print "ANTHROPIC_API_KEY=" t; next } { print }' \
     "$env_file" > "$env_file.new" && mv "$env_file.new" "$env_file"
   HERMES_HOME=<hermes-profile-dir> hermes auth list anthropic
   ```

   `awk` takes the token from the file, so it stays off the process list. The pool lists exactly
   one credential, `env:ANTHROPIC_API_KEY`, as before; any other row: roll back.

2. `t1=$(date +%s)`, then restart Hermes with `<restart-hermes>`.

### Heads

1. Note the current value of `<heads-token-setting>` in `<backup-dir>`, then point it at
   `<state-dir>/<heads-client>.token`.
2. `t1=$(date +%s)`, then `<restart-heads>`. Heads started before it keep the unnamed token
   until they end; both tokens are accepted meanwhile.

### Verify

Send the consumer's verification turn through its usual channel (for Hermes, the baseline
message of the Hermes cutover runbook; for the heads, one head's ordinary task). The turn passes
when:

- Its answer arrives as before, and the gateway logs it under the client's name:

  ```sh
  journalctl --user -u qb-gateway --since '-10 min' | grep 'gateway: turn'
  ```

  ```
  gateway: turn msg_<hex>_<n> of <hermes-client>: end on <login-1>
  ```

- The usage ledger has a row for the client's name since the switch, and new `client-token`
  rows only from consumers not yet switched or heads started before it:

  ```sh
  curl -sS --unix-socket <gateway-socket> "http://qb/v1/model/usage?from=$t1&group_by=client"
  ```

- No `gateway: loopback refused ...: token` or `...: route` line in the journal since `$t1`.

Rollback: restore the consumer's token setting (`cp -p <backup-dir>/hermes.env.pre-switch
<hermes-profile-dir>/.env`, or the noted value of `<heads-token-setting>`) and restart it; its
next turn logs `of client-token` again.

## 3. Remove the unnamed token

Start once every consumer shows its own name in the usage rows and `client-token` has had no
usage for `<window-s>`:

```sh
from=$(( $(date +%s) - <window-s> ))
curl -sS --unix-socket <gateway-socket> "http://qb/v1/model/usage?from=$from&group_by=client"
journalctl --user -u qb-gateway --since "@$from" | grep -c 'of client-token:'
```

The usage answer has no row with `"group": "client-token"` and the count is 0. Then:

```sh
cp -p <gateway-config> <backup-dir>/gateway.toml.pre-removal
"${EDITOR:-vi}" <gateway-config>                   # delete token_sha256 of [fronts]
t2=$(date +%s)
qb --socket <gateway-socket> reload
```

Delete only the `token_sha256` line of `[fronts]`, not one of a `[[fronts.clients]]` entry.

Verify:

- The reload answers its counts and the audit since `$t2` has a `reload` with `"result": "ok"`.
- The unnamed token is refused and the named ones are not:

  ```sh
  probe <backup-dir>/legacy.token                  # 401
  probe <state-dir>/<hermes-client>.token          # 400
  probe <state-dir>/<heads-client>.token           # 400
  ```

  The 401 logs `gateway: loopback refused POST <front-path>: token`.
- Each consumer's next turn logs its own name.

Rollback: copy `<backup-dir>/gateway.toml.pre-removal` back to `<gateway-config>` and reload;
`probe <backup-dir>/legacy.token` answers 400 again.

Once no rollback is wanted, remove the copies of the unnamed token:

```sh
shred -u <backup-dir>/legacy.token <backup-dir>/hermes.env.pre-switch
```

and the noted value of `<heads-token-setting>` when it holds the token itself.

## 4. Rotate a client token (optional)

Rotate one client at a time. A rotation writes a new token to the client's `token_file`; the
previous one stays accepted until `grace_until`, the rotation plus `rotate_grace_s`
([config.md](../config.md#client-token-rotation)).

```sh
cp -p <state-dir>/<hermes-client>.token <backup-dir>/<hermes-client>.token.pre-rotate
curl -sS --unix-socket <gateway-socket> -d '' http://qb/v1/model/clients/<hermes-client>/rotate
```

The answer is `{"client": "<hermes-client>", "token_sha256_prefix": "<12 hex>", "grace_until":
<unix s>}`; it never holds the token.

The consumer must pick up the new file content before `grace_until`:

- Hermes reads the token only when it starts. The gateway writes 43 base64url characters
  without the `qb-` prefix; when they start with `sk-ant-`, `eyJ` or `cc-`, rotate again, since
  Hermes would take such a key for an OAuth token. Then rewrite the `.env` line with the `awk`
  command of step 2 and restart Hermes with `<restart-hermes>`.
- A head reads the token when it starts: heads started after the rotation take the new one,
  heads running past `grace_until` get 401. Keep `rotate_grace_s` above the longest run of a
  head, or `<restart-heads>` within the grace.

Verify:

- The file holds the new token: `tr -d '\n' < <state-dir>/<hermes-client>.token | sha256sum |
  cut -c1-12` prints `token_sha256_prefix`, and the audit has `"action": "client_rotate"`,
  `"result": "ok"` with the same `token_sha256_prefix`.
- `probe <state-dir>/<hermes-client>.token` answers 400; so does
  `probe <backup-dir>/<hermes-client>.token.pre-rotate` until `grace_until`, and 401 after it.
- After the consumer's restart its next turn logs its name, and no
  `gateway: loopback refused ...: token` line follows.

Rollback, before `grace_until`: put the previous token back and reload, so it stays the client's
token after the grace:

```sh
cp -p <backup-dir>/<hermes-client>.token.pre-rotate <state-dir>/<hermes-client>.token.new
mv <state-dir>/<hermes-client>.token.new <state-dir>/<hermes-client>.token
qb --socket <gateway-socket> reload
```

A consumer already on the new token goes back to the previous one as in its rotation step. Once
the rotation holds, `shred -u` the `.pre-rotate` copy.

## Failure signs

- 401 from the listener after a switch: the consumer sends a token the gateway does not hold. The
  journal has `gateway: loopback refused POST <front-path>: token`. The consumer read an old
  value (not restarted, or its `.env` line or setting not changed), its previous token's grace
  ended after a rotation, the reload that added its client was refused, or the unnamed token was
  removed while it still sent it. Roll the consumer back, or the removal, as in its step. The
  listener's token check: [anthropic.md](../anthropic.md#the-v1messages-front),
  [openai.md](../openai.md#serving-the-fronts); grace:
  [config.md](../config.md#client-token-rotation).
- 403 `permission_error` (OpenAI code `route_not_allowed`): the consumer asked for a model that
  resolves to a route outside its `routes`, logged as
  ``gateway: loopback refused client `<name>` route `<alias>`: route``. Add the alias to the
  client's `routes` and reload, or change the consumer's model
  ([api.md](../api.md#model-gateway-v1model)).
- A refused reload: `qb reload` exits 1 with `reload refused: <file>: <field>: <reason>`, the
  journal has `gateway: reload refused: ...` and the audit a `reload` with `"result":
  "refused"` and its `reason`. The running config and its tokens stay. `<field>` names the
  cause: a `fronts.clients[<i>].token_file` that cannot be read, is empty, holds another
  client's token or lies outside the directories the sandbox opened, or a restart-only key that
  changed ([config.md](../config.md#reload), [api.md](../api.md#post-v1modelreload)).
