# Runbook: give the heads the `hive-heads` ladder

This runbook takes an installed `qbd` and `qb gateway` to the ladder of an orchestrator's agent
heads: `qbd`'s roles moved to a `roles_file` in its state directory, the role `hive-heads` with
steps 1 to 5 holding the values of the orchestrator's current ladder, the gateway routes
`hive-step-1` to `hive-step-5` on that role, and the heads' named client allowed on them. Each
step has its verification and its rollback; roll back in reverse step order. The shapes it adds
are those of [`deploy/examples/qbd.toml`](../../deploy/examples/qbd.toml) and
[`deploy/examples/gateway.toml`](../../deploy/examples/gateway.toml)
([config.md](../config.md#ladder-routes-that-send-the-candidates-effort)).

Placeholders:

| Placeholder | Meaning |
|---|---|
| `<host>` | The host `qbd` and the gateway run on. |
| `<user>`, `<uid>` | The user the gateway runs as, a user unit of this user, and its uid. `<user>` is in the group `qb-clients`, so it reaches `qbd`'s socket. |
| `<gateway-client>` | The name of the gateway's `[[clients]]` entry in `<qbd-config>`, by the `bearer_sha256` of the gateway's `qbd_bearer_file`: the client `qbd` identifies the gateway as. |
| `<qbd-socket>` | `qbd`'s socket, `/run/qb/qb.sock` with the shipped `qbd.socket`. |
| `<gateway-socket>` | The gateway's `socket`, for example `/run/user/<uid>/qb-gateway/gateway.sock`. |
| `<port>` | The port of the gateway's `fronts.listen`. |
| `<qbd-config>` | `qbd`'s config file, `/etc/qb/qbd.toml` with the shipped unit. |
| `<roles-file>` | The roles file, `/var/lib/qb/roles.toml`: `/var/lib/qb` is the state directory of the shipped unit (`DynamicUser=yes`, `StateDirectory=qb`), which `qbd`'s user owns and may write. |
| `<gateway-config>` | The gateway's config file, `~/.config/qb/gateway.toml` of `<user>` with the shipped unit. |
| `<credentials-dir>` | The directory of the gateway's credential files, opened by the gateway at its start. |
| `<backup-dir>` | An absolute directory owned by `<user>`, mode 0700, for the copies this runbook keeps for its rollbacks. |
| `<sub-vendor>`, `<sub-login>` | The `qbd` vendor and login of the Anthropic subscription the heads use, tier 1. |
| `<key-vendor>`, `<key-login>` | The `qbd` vendor and login of the heads' Anthropic API key, tier 3. The vendor serves this login only. |
| `<openai-vendor>`, `<openai-login>` | The `qbd` vendor and login of the OpenAI subscription (a ChatGPT login), tier 1. |
| `<key-env-file>`, `<key-var>` | A file of `NAME=value` lines, mode 0600, owned by `<user>`, that holds the heads' API key in the variable `<key-var>`; the owner provides it. |
| `<key-cap>` | Optional: the USD the heads' key may spend per calendar month, a `spend_cap`. |
| `<heads-client>` | The gateway's named client of the heads, a `[[fronts.clients]]` entry. |
| `<heads-token-file>` | The `token_file` of `<heads-client>`. |
| `<heads-token-setting>` | The orchestrator's setting that gives a head its token, as in [named-clients-cutover.md](named-clients-cutover.md). |
| `<second-sub-login>` | A second Anthropic subscription login of the gateway, which `<sub-vendor>` may serve too. It stays out of every `hive-heads` list. |
| `<other-logins>` | The logins the gateway's other consumers run on. They stay out of every `hive-heads` list. |
| `<ladder-file>` | The orchestrator's file that holds its current ladder. |

Commands marked `root` run with `sudo` on `<host>`; every other command runs as `<user>` on
`<host>`.

## The ladder

The role `hive-heads` has these steps. Each step has three candidates in this order: the
Anthropic subscription and the heads' API key with the same model and effort, then the OpenAI
subscription.

| Step | `<sub-vendor>`, tier 1 | `<key-vendor>`, tier 3 | `<openai-vendor>`, tier 1 |
|---|---|---|---|
| 5 | `opus-5-5`, `high` | `opus-5-5`, `high` | `gpt-5.6-terra`, `high` |
| 4 | `opus-5-5`, `high` | `opus-5-5`, `high` | `gpt-5.6-terra`, `high` |
| 3 | `opus-5-5`, `medium` | `opus-5-5`, `medium` | `gpt-5.6-terra`, `medium` |
| 2 | `sonnet-5-5`, `high` | `sonnet-5-5`, `high` | `gpt-5.6-terra`, `medium` |
| 1 | `sonnet-5-5`, `medium` | `sonnet-5-5`, `medium` | `gpt-6-luna`, `medium` |

The OpenAI column reads the orchestrator's OpenAI list, `gpt-5.6-terra` with high, high, medium,
medium and `gpt-6-luna` with medium, as steps 5, 4, 3, 2 and 1. Prerequisite 6 checks that
reading and the model ids.

## Prerequisites

1. `qbd` and the gateway run a `qb` built from a revision of this repository whose
   `docs/config.md` lists `roles_file`, `admin` of `[[clients]]`, and `client_effort` and
   `logins` among the `[[routes]]` keys. `qb --version` does not tell revisions apart; note the
   revision the binary was built from. Install a newer binary as in the Hermes cutover runbook's
   [Binary](hermes-secretary-cutover.md#binary) step; `qbd` takes it at the restart of step 2,
   the gateway at its next restart, which needs the owner's permission. A running binary with
   these features answers 200 to the first two reads and 400 to the third, a ladder read
   without its query:

   ```sh
   curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket <qbd-socket> http://qb/v1/roles
   curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket <gateway-socket> \
     http://qb/v1/model/config/routes
   curl -sS -o /dev/null -w '%{http_code}\n' --unix-socket <gateway-socket> \
     http://qb/v1/model/ladder
   ```

   An older `qbd` answers 404 to the first, a gateway without `GET /v1/model/ladder` 404 to the
   third. A gateway without `client_effort` or route `logins`
   answers 200 to the second but refuses the `PUT` of step 5 with 400 naming the unknown field,
   and writes nothing.
2. A root shell on `<host>`, a shell as `<user>`, and `jq` on `<host>`.
3. `<qbd-config>` has `<gateway-client>` with `bearer_sha256`, the gateway config has
   `qbd_bearer_file`, and the gateway logs its turns as in the Hermes cutover runbook. A client
   by `uid` matches nobody under the shipped `qbd.service`, whose `PrivateUsers=yes` shows every
   caller as the overflow uid ([config.md](../config.md#clients)).
4. The subscription logins `<sub-login>` and `<openai-login>` are logins of the gateway with
   credential files in `<credentials-dir>` (the Hermes cutover runbook's
   [Gateway credentials](hermes-secretary-cutover.md#gateway-credentials) step, or a sign-in as
   in [config.md](../config.md#signing-in)), and `<key-env-file>` holds the heads' key.
5. The gateway serves `fronts.listen` with `fronts.grace_file`, as the
   [named-clients cutover runbook](named-clients-cutover.md#prerequisites) sets up, so step 6 can
   give the heads their named client.
6. The values of [The ladder](#the-ladder) match `<ladder-file>`: each step's Anthropic model and
   effort, and the OpenAI list read as steps 5 to 1 as above. The model ids are the ids each
   vendor's API takes, as `qbd` passes them unchanged to the gateway, which sends them to the
   vendor; correct the table, and the bodies of step 4, before applying.
7. The owner's permission for the restarts of `qbd` in steps 2 and 3 and a quiet moment for
   them. With the edits of both steps done first, one restart serves both.

## 1. Back up the configs and the running roles

```sh
install -d -m 0700 <backup-dir>
sudo cp -p <qbd-config> <backup-dir>/qbd.toml.pre-ladder                       # root
cp -p <gateway-config> <backup-dir>/gateway.toml.pre-ladder
curl -sS --unix-socket <qbd-socket> http://qb/v1/roles > <backup-dir>/roles.before.json
curl -sS --unix-socket <gateway-socket> http://qb/v1/model/config/routes \
  > <backup-dir>/routes.before.json
```

Verify:

- `cmp <qbd-config> <backup-dir>/qbd.toml.pre-ladder` and
  `cmp <gateway-config> <backup-dir>/gateway.toml.pre-ladder` print nothing.
- `jq -r '.roles[].name' <backup-dir>/roles.before.json` lists the roles `qbd` runs, without
  `hive-heads`; `jq -r '.routes[].alias' <backup-dir>/routes.before.json` lists the gateway's
  routes, without `hive-step-1` to `hive-step-5`. A role or route of those names already there
  stops the runbook: reconcile it with the owner first.

Rollback: nothing changed; the copies may stay.

## 2. Move the roles to the roles file

1. Write the roles file in `<backup-dir>`: every `[[roles]]`, `[[roles.ladder]]` and
   `[[roles.reserves]]` table of `<qbd-config>` with its keys, in their order, and nothing else.

   ```sh
   "${EDITOR:-vi}" <backup-dir>/roles.toml
   ```

2. Install it in the state directory, owned by the directory's owner, `qbd`'s user, mode 0600,
   so `qbd` can read it and replace it on a `PUT /v1/admin/roles`:

   ```sh
   owner=$(sudo stat -L -c %u:%g /var/lib/qb)                                  # root
   sudo install -m 0600 -o "${owner%:*}" -g "${owner#*:}" \
     <backup-dir>/roles.toml <roles-file>                                       # root
   sudo ls -ln <roles-file>                                                     # root
   ```

3. Edit `<qbd-config>`: delete those tables and add the top-level key, before the first table:

   ```sh
   sudo "${EDITOR:-vi}" <qbd-config>                                            # root
   ```

   ```toml
   roles_file = "<roles-file>"
   ```

   The file keeps mode 0644.

4. Check the edit with a reload, which validates both files and refuses the change of
   `roles_file`, then restart:

   ```sh
   sudo systemctl kill --kill-whom=main -s HUP qbd.service                     # root
   sudo journalctl -u qbd -n 5                                                  # root
   sudo systemctl restart qbd.service                                           # root
   sudo journalctl -u qbd -n 20                                                 # root
   ```

   The reload must log
   `qbd: reload refused: <qbd-config>: roles_file: changed; it takes effect only on a restart`.
   Any other refusal names the fault, which would also stop the restarted `qbd` with exit code 2:
   fix the file first.

Verify:

- After the restart the journal has `qbd: using the socket passed by systemd` and no line
  `qb: <qbd-config>: ...` or `qb: <roles-file>: ...`.
- The running roles are unchanged:

  ```sh
  curl -sS --unix-socket <qbd-socket> http://qb/v1/roles > <backup-dir>/roles.migrated.json
  cmp <backup-dir>/roles.before.json <backup-dir>/roles.migrated.json
  ```

  `cmp` prints nothing.

Rollback: copy the old config back and restart; the roles file may stay, nothing reads it:

```sh
sudo cp <backup-dir>/qbd.toml.pre-ladder <qbd-config>                           # root
sudo systemctl restart qbd.service                                              # root
```

## 3. Declare the candidates

The three candidates need their vendors and logins in `<qbd-config>` and their logins in
`<gateway-config>`. Add only what is missing; the subscription vendors and logins are usually
there already.

1. `<qbd-config>`, root:

   ```sh
   sudo cp -p <qbd-config> <backup-dir>/qbd.toml.pre-candidates                 # root
   sudo "${EDITOR:-vi}" <qbd-config>                                            # root
   ```

   ```toml
   [[vendors]]
   name = "<key-vendor>"
   windows = [{ name = "spend", length_s = 2678400, t_burn_s = 0 }]

   [[logins]]
   name = "<key-login>"
   vendor = "<key-vendor>"
   ```

   With `<key-cap>` the vendor declares the window `spend`, which the gateway reports for a
   capped login ([config.md](../config.md#spend-caps)); without a cap it is `windows = []`.
   `<sub-vendor>` with `<sub-login>` and `<openai-vendor>` with `<openai-login>` take the same
   shape, with the windows of their subscriptions as in the Hermes cutover runbook.

   For the admin API through the gateway, used by step 4, add `admin = true` to the entry of
   `<gateway-client>`. Whoever holds the gateway's `qbd_bearer_file` then is an admin on
   `<qbd-socket>` as well: `qbd` identifies the caller by that token.

   `[[vendors]]` and `[[logins]]` are restart-only in `qbd`: a reload refuses them, so the new
   vendor and login need a restart. `admin` alone is taken by a reload. Check the file with a
   reload first, as in step 2:

   ```sh
   sudo systemctl kill --kill-whom=main -s HUP qbd.service                     # root
   sudo journalctl -u qbd -n 5                                                  # root
   ```

   With a new vendor or login it logs
   `qbd: reload refused: <qbd-config>: vendors: changed; it takes effect only on a restart` (or
   `logins:`); restart then with `sudo systemctl restart qbd.service`. With only `admin` it logs
   `qbd: reloaded <qbd-config>: <n> roles, <m> clients`. Any other refusal: fix the file.

2. `<gateway-config>`, as `<user>`: the key's login, then its credential file from
   `<key-env-file>` ([config.md](../config.md#importing-credentials)), then a reload:

   ```sh
   cp -p <gateway-config> <backup-dir>/gateway.toml.pre-candidates
   "${EDITOR:-vi}" <gateway-config>
   ```

   ```toml
   [[logins]]
   name = "<key-login>"
   kind = "api_key"
   api = "anthropic"
   credentials = "<credentials-dir>/<key-login>.json"
   spend_cap = <key-cap>
   ```

   `spend_cap` needs a top-level `spend_file`, which is restart-only in the gateway; leave the
   line out without a cap. `<sub-login>` and `<openai-login>` need entries of their kinds
   (`oauth_anthropic`, `chatgpt_oauth`) if missing.

   With `<key-cap>`, add a price for every Anthropic model of the ladder the key serves, unless
   the file has one. The Anthropic API reports no USD cost, so the gateway counts a call on a
   capped login only at the model's `[prices]` entry; without one the cap counts nothing
   ([config.md](../config.md#spend-caps)). Fill in the USD per million tokens from the vendor's
   price list:

   ```toml
   [prices."opus-5-5"]
   input = <opus-input-usd>
   output = <opus-output-usd>
   cache_read = <opus-cache-read-usd>
   cache_write = <opus-cache-write-usd>

   [prices."sonnet-5-5"]
   input = <sonnet-input-usd>
   output = <sonnet-output-usd>
   cache_read = <sonnet-cache-read-usd>
   cache_write = <sonnet-cache-write-usd>
   ```

   ```sh
   qb login import --config <gateway-config> --from env --source <key-env-file> \
     --var <key-var> <key-login>
   qb --socket <gateway-socket> reload
   ```

   The import prints no value and writes `<credentials-dir>/<key-login>.json` with mode 0600.

Verify:

- `qb state` lists `<key-login>` (and every candidate login added), status `ok` or `unknown`.
- With `admin = true`, the admin read through the gateway answers the roles file, and its roles
  are the running ones:

  ```sh
  curl -sS --unix-socket <gateway-socket> http://qb/v1/admin/roles > <backup-dir>/roles.admin.json
  jq '{source, file}' <backup-dir>/roles.admin.json
  diff <(jq -S .roles <backup-dir>/roles.admin.json) <(jq -S .roles <backup-dir>/roles.migrated.json)
  ```

  `jq` prints `"source": "roles_file"` and `"file": "<roles-file>"`, `diff` nothing. The journal
  of `qbd` has `qbd: admin GET /v1/admin/roles by <gateway-client>: 200`.
- `qb --socket <gateway-socket> reload` prints `{"routes": <n>, "logins": <m>}` with `<m>` one
  more per login added, and the gateway's journal has
  `gateway: reloaded <gateway-config>: <n> routes, <m> logins`.
- With `<key-cap>`, `qb --socket <gateway-socket> spend` lists `<key-login>` with that
  `cap_usd`. After the first turn on `<key-login>`, which the routes of step 5 make possible, a
  priced call counts: `spent_usd` is above 0, the usage rows of `<key-login>` have `usd` above 0
  and `unpriced` 0, and the journal has no line
  ``gateway: model `<model>` has no price and its vendor reports no cost; ...``:

  ```sh
  qb --socket <gateway-socket> spend
  curl -sS --unix-socket <gateway-socket> "http://qb/v1/model/usage?from=$(date -d '-1 day' +%s)&group_by=login"
  journalctl --user -u qb-gateway --since '-1 day' | grep 'has no price'
  ```

Rollback: copy both configs back, restart `qbd` (or reload it when only `admin` changed),
reload the gateway and remove the key's credential file:

```sh
sudo cp <backup-dir>/qbd.toml.pre-candidates <qbd-config>                       # root
sudo systemctl restart qbd.service                                              # root
cp <backup-dir>/gateway.toml.pre-candidates <gateway-config>
qb --socket <gateway-socket> reload
shred -u <credentials-dir>/<key-login>.json
```

## 4. Add the role `hive-heads`

The role's body, the values of [The ladder](#the-ladder), in `<backup-dir>/hive-heads.json`:

```json
{"name": "hive-heads",
 "ladder": [
  {"difficulty": 1, "candidates": [
   {"vendor": "<sub-vendor>", "model": "sonnet-5-5", "effort": "medium", "tier": 1},
   {"vendor": "<key-vendor>", "model": "sonnet-5-5", "effort": "medium", "tier": 3},
   {"vendor": "<openai-vendor>", "model": "gpt-6-luna", "effort": "medium", "tier": 1}]},
  {"difficulty": 2, "candidates": [
   {"vendor": "<sub-vendor>", "model": "sonnet-5-5", "effort": "high", "tier": 1},
   {"vendor": "<key-vendor>", "model": "sonnet-5-5", "effort": "high", "tier": 3},
   {"vendor": "<openai-vendor>", "model": "gpt-5.6-terra", "effort": "medium", "tier": 1}]},
  {"difficulty": 3, "candidates": [
   {"vendor": "<sub-vendor>", "model": "opus-5-5", "effort": "medium", "tier": 1},
   {"vendor": "<key-vendor>", "model": "opus-5-5", "effort": "medium", "tier": 3},
   {"vendor": "<openai-vendor>", "model": "gpt-5.6-terra", "effort": "medium", "tier": 1}]},
  {"difficulty": 4, "candidates": [
   {"vendor": "<sub-vendor>", "model": "opus-5-5", "effort": "high", "tier": 1},
   {"vendor": "<key-vendor>", "model": "opus-5-5", "effort": "high", "tier": 3},
   {"vendor": "<openai-vendor>", "model": "gpt-5.6-terra", "effort": "high", "tier": 1}]},
  {"difficulty": 5, "candidates": [
   {"vendor": "<sub-vendor>", "model": "opus-5-5", "effort": "high", "tier": 1},
   {"vendor": "<key-vendor>", "model": "opus-5-5", "effort": "high", "tier": 3},
   {"vendor": "<openai-vendor>", "model": "gpt-5.6-terra", "effort": "high", "tier": 1}]}],
 "reserves": []}
```

Through the admin API (with `admin = true` from step 3): read the roles and their hash, append
the role, and replace the roles with `If-Match`:

```sh
curl -sS --unix-socket <gateway-socket> http://qb/v1/admin/roles > <backup-dir>/roles.pre-hive.json
jq --slurpfile add <backup-dir>/hive-heads.json '{roles: (.roles + $add)}' \
  <backup-dir>/roles.pre-hive.json > <backup-dir>/roles.put.json
t0=$(date +%s)
curl -sS --unix-socket <gateway-socket> -X PUT http://qb/v1/admin/roles \
  -H "If-Match: \"$(jq -r .sha256 <backup-dir>/roles.pre-hive.json)\"" \
  -H 'content-type: application/json' --data-binary @<backup-dir>/roles.put.json
```

Without the admin API, as root: append the role as TOML to `<roles-file>` in the shape of
`hive-heads` in [`deploy/examples/qbd.toml`](../../deploy/examples/qbd.toml), with the values of
the table, and reload. `tee -a` writes in place, so the file keeps its owner and mode:

```sh
sudo cp -p <roles-file> <backup-dir>/roles.toml.pre-hive                        # root
"${EDITOR:-vi}" <backup-dir>/hive-heads.toml
sudo tee -a <roles-file> < <backup-dir>/hive-heads.toml > /dev/null             # root
sudo systemctl kill --kill-whom=main -s HUP qbd.service                         # root
```

Verify:

- The `PUT` answers `{"sha256": "<new>", "backup": "<roles-file>.bak-<unix s>"}`. `qbd`'s journal
  has `qbd: admin PUT /v1/admin/roles by <gateway-client>: 200, roles sha256 <old> -> <new>,
  backup <roles-file>.bak-<unix s>` and, for both ways,
  `qbd: reloaded <qbd-config>: <n> roles, <m> clients` with `<n>` one more than before.
- The running roles are the old ones plus `hive-heads` with the values of the table:

  ```sh
  curl -sS --unix-socket <qbd-socket> http://qb/v1/roles > <backup-dir>/roles.hive.json
  diff <(jq -S '[.roles[] | select(.name != "hive-heads")]' <backup-dir>/roles.hive.json) \
       <(jq -S .roles <backup-dir>/roles.before.json)
  jq -r '.roles[] | select(.name == "hive-heads") | .ladder[] | .difficulty as $d
         | .candidates[] | "\($d) \(.vendor) \(.model) \(.effort) \(.tier)"' \
    <backup-dir>/roles.hive.json
  ```

  `diff` prints nothing; `jq` prints 15 lines, three per step, matching the table.
- `GET /v1/admin/roles` answers `"source": "roles_file"` with the new `sha256`.
- With the gateway's `audit_file`,
  `curl -sS --unix-socket <gateway-socket> "http://qb/v1/model/audit?since=$t0"` has an
  `admin_roles` entry with `"result": "ok"`.

Rollback: put the old roles back the same way, with the hash now on disk:

```sh
jq '{roles}' <backup-dir>/roles.pre-hive.json > <backup-dir>/roles.rollback.json
curl -sS --unix-socket <gateway-socket> -X PUT http://qb/v1/admin/roles \
  -H "If-Match: \"$(curl -sS --unix-socket <gateway-socket> http://qb/v1/admin/roles | jq -r .sha256)\"" \
  -H 'content-type: application/json' --data-binary @<backup-dir>/roles.rollback.json
```

or, as root, copy `<roles-file>.bak-<unix s>` (or `<backup-dir>/roles.toml.pre-hive`) over
`<roles-file>` with `sudo cp` and send the SIGHUP. `GET /v1/roles` then equals
`<backup-dir>/roles.before.json` again.

## 5. Add the routes `hive-step-1` to `hive-step-5`

Each route is one step of `hive-heads`, sends the picked candidate's effort whatever the client
asks for, and runs only on the three candidates' logins, so `<second-sub-login>` and
`<other-logins>` stay out:

```sh
jq -n '[range(1; 6) | {alias: "hive-step-\(.)", role: "hive-heads", difficulty: .,
        client_effort: "ignore", logins: ["<sub-login>", "<key-login>", "<openai-login>"]}]' \
  > <backup-dir>/hive-routes.json
curl -sS --unix-socket <gateway-socket> http://qb/v1/model/config/routes \
  > <backup-dir>/routes.pre-hive.json
jq --slurpfile add <backup-dir>/hive-routes.json '{routes: (.routes + $add[0])}' \
  <backup-dir>/routes.pre-hive.json > <backup-dir>/routes.put.json
curl -sS --unix-socket <gateway-socket> -X PUT http://qb/v1/model/config/routes \
  -H "If-Match: \"$(jq -r .sha256 <backup-dir>/routes.pre-hive.json)\"" \
  -H 'content-type: application/json' --data-binary @<backup-dir>/routes.put.json
```

The body has no `spend_caps`, so every cap stays. A config whose `routes` are an inline array is
refused with 400 and nothing is written; turn it into `[[routes]]` tables by hand first
([api.md](../api.md#get-and-put-v1modelconfigroutes)).

Verify:

- The `PUT` answers `{"sha256": "<new>", "backup": "<gateway-config>.bak-<unix s>"}` and the
  gateway's journal has `gateway: reloaded <gateway-config>: <n> routes, <m> logins` with `<n>`
  five more than before.
- The file holds the five routes, each with exactly the three logins:

  ```sh
  curl -sS --unix-socket <gateway-socket> http://qb/v1/model/config/routes \
    | jq -c '.routes[] | select(.role == "hive-heads")'
  ```

  It prints five lines, `hive-step-1` to `hive-step-5`, `difficulty` 1 to 5, each with
  `"client_effort":"ignore"` and `"logins":["<sub-login>","<key-login>","<openai-login>"]`; no
  line names `<second-sub-login>` or one of `<other-logins>`.
- `curl -sS --unix-socket <gateway-socket> http://qb/v1/model/routes` lists the five aliases,
  each `ready`, or `exhausted` with a `resets_at` while all three logins wait.

Rollback: put the old routes back with the hash now on disk; this removes the five routes and
leaves every other byte:

```sh
jq '{routes}' <backup-dir>/routes.pre-hive.json > <backup-dir>/routes.rollback.json
curl -sS --unix-socket <gateway-socket> -X PUT http://qb/v1/model/config/routes \
  -H "If-Match: \"$(curl -sS --unix-socket <gateway-socket> http://qb/v1/model/config/routes | jq -r .sha256)\"" \
  -H 'content-type: application/json' --data-binary @<backup-dir>/routes.rollback.json
```

## 6. Let the heads' named client use the routes

`<heads-client>` gets `routes = ["hive-step-1", "hive-step-2", "hive-step-3", "hive-step-4",
"hive-step-5"]`. While heads still run on other routes of the gateway, keep those aliases in the
list beside the five until the orchestrator stops using them.

- Without `<heads-client>`: add it as in step 1 of the
  [named-clients cutover runbook](named-clients-cutover.md#1-add-the-named-clients-beside-the-unnamed-token),
  with these `routes`, and switch the heads' `<heads-token-setting>` to `<heads-token-file>` as
  in its step 2.
- With `<heads-client>`: edit its `routes` and reload.

  ```sh
  cp -p <gateway-config> <backup-dir>/gateway.toml.pre-client-routes
  "${EDITOR:-vi}" <gateway-config>
  qb --socket <gateway-socket> reload
  ```

A token check that spends no quota, as in the named-clients cutover runbook, keeps the token off
the process list:

```sh
ladder() {  # ladder <query>: the loopback ladder read as <heads-client>
  curl -sS -w '\n%{http_code}\n' "http://127.0.0.1:<port>/v1/model/ladder?$1" \
    -H @<(printf 'x-api-key: %s\n' "$(cat <heads-token-file>)")
}
```

Verify:

- `qb --socket <gateway-socket> reload` prints its counts and the journal has
  `gateway: reloaded <gateway-config>: <n> routes, <m> logins`.
- `ladder route=hive-step-1` ends with `200`; a route outside the list ends with `403` and the
  journal has a warning line naming `<heads-client>`.

Rollback: copy `<backup-dir>/gateway.toml.pre-client-routes` back to `<gateway-config>` and
reload; `ladder route=hive-step-1` ends with `403` again. For a client added in this step, the
named-clients runbook's step 1 rollback.

## 7. Read the heads' ladder

```sh
ladder role=hive-heads
```

The answer ends with `200` and holds:

- `"role": "hive-heads"` and five `steps`, `difficulty` 1 to 5 in that order.
- Step `N` with `"routes": ["hive-step-N"]` and three `candidates` in this order:
  `<sub-vendor>` with `"api": "anthropic"`, `"tier": 1`; `<key-vendor>` with
  `"api": "anthropic"`, `"tier": 3`; `<openai-vendor>` with `"api": "openai"`, `"tier": 1`.
  Each candidate's `model` and `effort` are those of row `N` of [The ladder](#the-ladder).
- Each candidate's `state` is `ready`, or `exhausted` with a `resets_at` while its login waits.

For step 3:

```json
{"difficulty": 3, "routes": ["hive-step-3"], "candidates": [
 {"vendor": "<sub-vendor>", "api": "anthropic", "model": "opus-5-5", "effort": "medium",
  "tier": 1, "state": "ready"},
 {"vendor": "<key-vendor>", "api": "anthropic", "model": "opus-5-5", "effort": "medium",
  "tier": 3, "state": "ready"},
 {"vendor": "<openai-vendor>", "api": "openai", "model": "gpt-5.6-terra", "effort": "medium",
  "tier": 1, "state": "ready"}]}
```

A candidate without `api`, or with `"state": "unavailable"`, has no gateway login among the
routes' `logins`, or its login is `auth_dead`: check its login in steps 3 and 5 and in
`qb state`. A 404 means `qbd` does not run `hive-heads` (step 4), a 403 that `<heads-client>`'s
`routes` lack the five aliases (step 6).

Rollback: this step changes nothing.

Not done by this runbook: none of its steps has been applied to an installation, and switching
the orchestrator to ask `qb` for the model of a step is a separate change.
