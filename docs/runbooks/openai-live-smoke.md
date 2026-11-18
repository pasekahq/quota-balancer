# Runbook: live smoke of the OpenAI-family logins of `qb gateway`

This runbook checks the gateway's three OpenAI-family login shapes against the real vendors, one
short turn each: a ChatGPT subscription login (`chatgpt_oauth`), an OpenAI API key (`api_key`,
`api = "openai"`) and an OpenRouter key (`api_key`, `api = "chat_completions"`). It also forces
one token refresh of the ChatGPT login. The code encodes several vendor shapes from references
and synthetic fixtures only; [the list below](#assumptions-the-run-confirms-or-refutes) names
them and how the run settles each. The protocols are in [openai.md](../openai.md#serving-the-upstream),
the config in [config.md](../config.md#gateway-config).

The run uses its own `qbd` and gateway in the foreground, on sockets in a scratch directory, so
it touches no running `qbd`, gateway or client.

Placeholders:

| Placeholder | Meaning |
|---|---|
| `<host>` | The host the smoke runs on. |
| `<user>`, `<uid>` | The operator account that runs both processes and owns the credential files. |
| `<smoke-dir>` | An absolute directory owned by `<user>`, mode 0700: configs, sockets, turn output. |
| `<credentials-dir>` | An absolute directory owned by `<user>`, mode 0700, holding only this run's credential files. |
| `<backup-dir>` | An absolute directory owned by `<user>`, mode 0700, outside `<credentials-dir>`. |
| `<smoke-role>` | The `qbd` role of the gateway in this run. |
| `<chatgpt-vendor>`, `<openai-vendor>`, `<openrouter-vendor>` | `qbd` vendor names, one per part. |
| `<chatgpt-login>`, `<openai-key-login>`, `<openrouter-login>` | `qbd` login names, one per part; each credential file is `<credentials-dir>/<login>.json`. |
| `<chatgpt-model>`, `<openai-model>`, `<openrouter-model>` | The model each part asks for: a model the ChatGPT plan serves to Codex, an OpenAI API model, an OpenRouter model id. |
| `<openrouter-base-url>` | OpenRouter's API base URL, below which the gateway calls `/chat/completions`. |
| `<token-url>` | The ChatGPT token endpoint, `identity::OAUTH_TOKEN_URL` in `crates/qb-openai/src/request.rs`. |
| `<codex-client-id>` | The Codex CLI's public OAuth client id, `identity::OAUTH_CLIENT_ID` in the same file. |
| `<weekly-reset>` | The time the ChatGPT login's weekly window resets next, as the owner reads it in Codex's `/status`. |

## Prerequisites

1. The gate. Each part runs only when its gate is open; a closed gate skips that part, not the
   others:
   - the subscription part (setup of `<chatgpt-login>`, its turn and the forced refresh) runs
     only after `<weekly-reset>` has passed, so the turns land in a fresh weekly window and the
     owner's own use is not cut short;
   - the OpenAI key part and the OpenRouter part each run only on an explicit command of the
     product owner naming that part, with at most one short turn per key. The optional 402
     check is one more key and needs its own command.
2. `qb` built for `x86_64-unknown-linux-musl` from this repository and installed as `qb` on
   `<user>`'s `PATH` on `<host>`; `python3` and `curl` on `<host>`.
3. The vendor terms allow each credential mode ([README](../../README.md#terms-of-service)).
4. For the subscription part: a browser on any device, to sign the ChatGPT account in once with
   `qb login`, the dedicated sign-in of the ChatGPT login. That sign-in belongs to the gateway
   alone: no other client holds its refresh token, which the refresh in this run rotates.
5. For each key part: a key made for this run, so it can be revoked afterwards.

## Setup

Create the directories and keep the credential files out of the process list and the shell
history:

```sh
install -d -m 0700 <smoke-dir> <credentials-dir> <backup-dir>
umask 077
```

### `qbd`

`<smoke-dir>/qbd.toml`. A part whose gate is closed keeps its vendor and drops its
`[[logins]]` entry, so a turn on its route finds no login and calls no vendor:

```toml
[journal]
mode = "off"

[[vendors]]
name = "<chatgpt-vendor>"
windows = [
  { name = "five_hour", length_s = 18000, t_burn_s = 1800 },
  { name = "seven_day", length_s = 604800, t_burn_s = 43200 },
]

[[vendors]]
name = "<openai-vendor>"
windows = []

[[vendors]]
name = "<openrouter-vendor>"
windows = []

[[logins]]
name = "<chatgpt-login>"
vendor = "<chatgpt-vendor>"

[[logins]]
name = "<openai-key-login>"
vendor = "<openai-vendor>"

[[logins]]
name = "<openrouter-login>"
vendor = "<openrouter-vendor>"

[[roles]]
name = "<smoke-role>"

[[roles.ladder]]
difficulty = 1
candidates = [{ vendor = "<chatgpt-vendor>", model = "<chatgpt-model>", tier = 1 }]

[[clients]]
name = "gateway"
uid = <uid>
role = "<smoke-role>"
```

The ChatGPT windows carry the names the gateway gives the `x-codex-*` windows of 300 and 10080
minutes ([openai.md](../openai.md#rate-limits-and-failures)); `qbd` ignores window names its vendor
does not declare.

In a terminal of its own:

```sh
qb --socket <smoke-dir>/qbd.sock daemon --config <smoke-dir>/qbd.toml
```

Expected: no output and no exit. `qb --socket <smoke-dir>/qbd.sock state` lists the logins with
status `unknown`.

### Credential files

`<chatgpt-login>` is signed in with `qb login` once the gateway config exists
([Gateway](#gateway)).

`<openai-key-login>` and `<openrouter-login>`, once their part is commanded, each
`{"type": "api_key", "key": "..."}`:

```sh
"${EDITOR:-vi}" <credentials-dir>/<openai-key-login>.json
"${EDITOR:-vi}" <credentials-dir>/<openrouter-login>.json
ls -l <credentials-dir>                    # every file -rw-------, owned by <user>
```

### Gateway

`<smoke-dir>/gateway.toml`. A part whose gate is closed drops its `[[logins]]` entry here too.
`max_attempts = 1` keeps a failed turn from trying again:

```toml
socket = "<smoke-dir>/gateway.sock"
qbd_socket = "<smoke-dir>/qbd.sock"
max_attempts = 1

[[logins]]
name = "<chatgpt-login>"
kind = "chatgpt_oauth"
credentials = "<credentials-dir>/<chatgpt-login>.json"

[[logins]]
name = "<openai-key-login>"
kind = "api_key"
api = "openai"
credentials = "<credentials-dir>/<openai-key-login>.json"

[[logins]]
name = "<openrouter-login>"
kind = "api_key"
api = "chat_completions"
base_url = "<openrouter-base-url>"
credentials = "<credentials-dir>/<openrouter-login>.json"

[[routes]]
alias = "smoke-chatgpt"
role = "<smoke-role>"
vendor = "<chatgpt-vendor>"
model = "<chatgpt-model>"
expected_minutes = 1

[[routes]]
alias = "smoke-openai"
role = "<smoke-role>"
vendor = "<openai-vendor>"
model = "<openai-model>"
expected_minutes = 1

[[routes]]
alias = "smoke-openrouter"
role = "<smoke-role>"
vendor = "<openrouter-vendor>"
model = "<openrouter-model>"
expected_minutes = 1
```

If `<openai-model>` or `<chatgpt-model>` is a model that refuses the `reasoning` parameter, add
its entry, or the vendor answers 400:

```toml
[openai_models."<openai-model>"]
reasoning = false
```

Sign `<chatgpt-login>` in, once its part runs ([config.md](../config.md#signing-in)):

```sh
qb login --config <smoke-dir>/gateway.toml <chatgpt-login>
```

Open the URL it prints in a browser on any device and sign in to the ChatGPT account. The
browser then fails to load a `http://localhost:1455/auth/callback?...` page: paste that page's
full address into `qb login`. Expected on stdout, after the URL:

```text
<credentials-dir>/<chatgpt-login>.json: wrote the `chatgpt_oauth` credential of login `<chatgpt-login>`
```

and `ls -l <credentials-dir>` shows the file `-rw-------`. The gateway's file is the only holder
of the refresh token.

In a second terminal of its own:

```sh
qb gateway --config <smoke-dir>/gateway.toml 2>&1 | tee <smoke-dir>/gateway.log
```

Expected: no line naming a config field (a config error exits with code 2 and one such line),
and `qb --socket <smoke-dir>/gateway.sock health` answers. A sandbox gap is logged as a `warn`
line and does not stop the run.

After a change to either config, stop that process with Ctrl-C and start it again.

## Run one turn per login

Each turn is one `POST /v1/model/turn` on the gateway's socket ([api.md](../api.md#post-v1modelturn));
its NDJSON answer is kept for reading. `<route>` and `<id>` per part:

| Part | `<route>` | `<id>` |
|---|---|---|
| ChatGPT subscription | `smoke-chatgpt` | `smoke-chatgpt-1` |
| OpenAI key | `smoke-openai` | `smoke-openai-1` |
| OpenRouter key | `smoke-openrouter` | `smoke-openrouter-1` |

```sh
date +%s > <smoke-dir>/<id>.start
curl -sS -N --unix-socket <smoke-dir>/gateway.sock http://gateway/v1/model/turn \
  -H 'content-type: application/json' \
  -d '{"route": "<route>", "max_tokens": 512, "effort": "low", "request_id": "<id>",
       "messages": [{"role": "user", "content": [{"type": "text", "text": "Say ok."}]}]}' \
  | tee <smoke-dir>/<id>.ndjson
```

Run each part's turn once. Do not repeat a key part's turn after a failure: record the failure
and stop that part.

## Read the result

For each turn, all of these hold:

1. The answer's first line is the route event naming the part's vendor, model and login:

   ```json
   {"type":"route","route":{"vendor":"<chatgpt-vendor>","model":"<chatgpt-model>","login_label":"<chatgpt-login>","lease":"l-1"}}
   ```

   then content (`thinking` may come first on a reasoning model, then `text_delta`), one
   `usage` event and a `stop` event, last:

   ```json
   {"type":"usage","usage":{"input":12,"output":40,"cache_read":0,"cache_write":0}}
   {"type":"stop","reason":"end"}
   ```

   `input` and `output` are above 0; `stop.reason` is `end` (`max_tokens` passes too, as long
   as `usage` came). An `error` event instead fails the part: its `class` and `message` are the
   gateway's reading of the vendor's answer.
2. `<smoke-dir>/gateway.log` has the turn's line and no `warn` line for it:

   ```
   <6>gateway: turn <id> of uid:<uid>: end on <login>
   ```

3. `qb --socket <smoke-dir>/qbd.sock state` lists no live lease.
4. For the ChatGPT turn, the same `state` shows `<chatgpt-login>` with status `ok` and both
   windows reported by the turn:

   ```json
   {"login": "<chatgpt-login>", "vendor": "<chatgpt-vendor>", "status": "ok", "windows": [
     {"name": "five_hour", "used": 0.01, "source": "stream", "observed_at": 1800000000, ...},
     {"name": "seven_day", "used": 0.0, "source": "stream", "observed_at": 1800000000, ...}]}
   ```

   `observed_at` is at or after `<smoke-dir>/smoke-chatgpt-1.start`, and `used` matches what
   the owner's Codex `/status` shows for the account, as a fraction. The key logins have no
   declared windows and stay without them.
5. For the OpenRouter turn, the key's spend before and after it. Read it right before the turn
   and again a minute after, from OpenRouter's current-key endpoint; the header file keeps the
   key off the process list:

   ```sh
   key=<credentials-dir>/<openrouter-login>.json
   curl -sS <openrouter-base-url>/key \
     -H @<(python3 -c 'import json,sys; print("authorization: Bearer " + json.load(open(sys.argv[1]))["key"])' "$key") \
     | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["usage"])'
   ```

   The difference is the turn's cost in USD; on a free model it is 0. The gateway reads the
   stream's `usage.cost` but passes it nowhere, so this is the only cost the run sees.

## Forced refresh of the ChatGPT login

Subscription part only, after its turn passed.

1. Keep the file as it is and record its account id and refresh token as hashes only:

   ```sh
   f=<credentials-dir>/<chatgpt-login>.json
   cp -p "$f" <backup-dir>/<chatgpt-login>.json
   python3 - "$f" <<'EOF' > <smoke-dir>/refresh.before
   import hashlib, json, sys
   c = json.load(open(sys.argv[1]))
   for k in ("account_id", "refresh_token", "access_token"):
       print(k, hashlib.sha256(c[k].encode()).hexdigest()[:16])
   EOF
   ```

2. Set `expires_at` in the past, writing a 0600 file in the same directory and renaming it over
   the old one:

   ```sh
   python3 - "$f" <<'EOF'
   import json, os, sys
   c = json.load(open(sys.argv[1]))
   c["expires_at"] = 1
   tmp = sys.argv[1] + ".smoke"
   with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
       json.dump(c, out)
   os.rename(tmp, sys.argv[1])
   EOF
   ```

3. Run one turn as above with `<route>` `smoke-chatgpt` and `<id>` `smoke-chatgpt-2`. The turn
   passes as in [Read the result](#read-the-result).
4. The file was rewritten by the gateway:

   ```sh
   stat -c '%a %U %Y' "$f"            # 600 <user> <a time after smoke-chatgpt-2.start>
   python3 - "$f" <<'EOF' > <smoke-dir>/refresh.after
   import hashlib, json, sys
   c = json.load(open(sys.argv[1]))
   for k in ("account_id", "refresh_token", "access_token"):
       print(k, hashlib.sha256(c[k].encode()).hexdigest()[:16])
   EOF
   diff <smoke-dir>/refresh.before <smoke-dir>/refresh.after
   ```

   Expected: mode 600; `diff` shows `refresh_token` and `access_token` changed and
   `account_id` unchanged. An unchanged `refresh_token` means the answer carried none and the
   gateway kept the old one.
5. Record the expiry the gateway stored next to the new access token's own `exp`:

   ```sh
   python3 - "$f" <<'EOF'
   import base64, json, sys, time
   c = json.load(open(sys.argv[1]))
   p = c["access_token"].split(".")[1]
   exp = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))["exp"]
   print("now", int(time.time()), "expires_at", c["expires_at"], "access_exp", exp)
   EOF
   ```

The refresh rotated the refresh token. Any other client that held the old one, such as a Codex
CLI `auth.json` the file was copied from, now holds a spent token: its next refresh is refused
and it needs a new sign-in. The backup in `<backup-dir>` holds that spent token too and is no
way back.

## Refusal shape of the token endpoint

One request with a refresh token that was never issued; it holds no secret and spends nothing:

```sh
curl -sS -w '\nHTTP %{http_code}\n' -X POST <token-url> \
  -H 'content-type: application/x-www-form-urlencoded' -H 'accept: application/json' \
  --data 'grant_type=refresh_token&refresh_token=qb-smoke-not-a-token&client_id=<codex-client-id>'
```

Record the status and the body's `error`.

## Optional: the 402 of an OpenRouter key without credit

Only on its own product owner command. A second OpenRouter key whose credit limit is used up
(OpenRouter lets the key's owner set a credit limit per key). Put it into
`<credentials-dir>/<openrouter-login>.json` in place of the first key, run one turn with
`<route>` `smoke-openrouter` and `<id>` `smoke-openrouter-402`, then put the first key back or
delete the file.

Expected: an `error` event of class `quota_exhausted`, the log line
`<6>gateway: turn smoke-openrouter-402 on <openrouter-login>: usage_limit: ...` and
`<openrouter-login>` `exhausted` in `state`.

## Assumptions the run confirms or refutes

| Assumption in the code | Confirmed when | Refuted when |
|---|---|---|
| The ChatGPT sign-in takes the Codex CLI's authorize parameters, its form-encoded `grant_type=authorization_code` exchange answers `access_token`, `refresh_token` and an `id_token` with the `chatgpt_account_id` claim (`signin.rs`, [openai.md](../openai.md#oauth-sign-in)). | `qb login` prints the line naming `<chatgpt-login>.json` and the turn of the ChatGPT part passes. | The authorize page shows an error instead of the sign-in, or `qb login` exits 1 with `the token endpoint refused the code: <token-url>: HTTP <status> <code>` or `the token answer has no ...`. |
| The ChatGPT refresh is a form-encoded `grant_type=refresh_token` with the Codex client id, and its 2xx answer has `access_token`, an optional rotated `refresh_token` and an optional `id_token` (`oauth.rs`, [openai.md](../openai.md#serving-the-upstream)). | The forced refresh's turn passes and step 4 shows a new access token, the same account id and mode 600. | The turn fails with a log line `gateway: <credentials-dir>/<chatgpt-login>.json: refresh failed: <token-url>: ...`: `HTTP 400 <code>` or `HTTP 401` means the grant or client id is refused (the login turns `auth_dead` in this run's `qbd` only); `answer has no access_token` or `malformed answer` means other field names. |
| The token endpoint refuses a spent refresh token with 400 or 401, or with another non-5xx status other than 429 whose `error` (a string, or an object with `code`) is `invalid_grant`, `refresh_token_expired`, `refresh_token_reused` or `refresh_token_invalidated`. | The refusal request answers 400 or 401, or another such status with one of those codes in either form. | Any other answer: 429 or 5xx (the gateway would retry a spent token and never mark the login), or another status with a code outside the list or in a third shape. |
| Without `expires_in`, the `id_token`'s `exp` is a usable expiry for the access token. | Step 5 shows `expires_at` at most `access_exp` and at least a few minutes after `now`: the gateway refreshes before the token lapses and not on every turn. `expires_at` equal to `access_exp` means both JWTs carry the same `exp` or the access token's was used. | `expires_at` above `access_exp`: the gateway would send an expired token until a 401 forces the refresh. `expires_at` within about 60 s of `now`: every turn refreshes and rotates the token. The gateway does not log which source it took; an `expires_at` of `now` plus a round lifetime suggests `expires_in` was present and the `id_token` was not needed. |
| The ChatGPT backend sends `x-codex-primary-*` and `x-codex-secondary-*` window headers that reach `qbd` as `five_hour` and `seven_day`. | Step 4 of [Read the result](#read-the-result): both windows with `source` `stream`, a fresh `observed_at` and `used` in line with Codex `/status`. | A window stays `source` `assumed` with `observed_at` 0: the headers are missing, renamed, or name another window length, which the gateway calls `window_<m>m` and `qbd` ignores. |
| OpenRouter streams a final `usage` with `prompt_tokens`, `completion_tokens` and `usage.cost` in USD ([openai.md](../openai.md#chat-completions-answer)). | The OpenRouter turn ends with a `usage` event with `input` and `output` above 0, and the key's spend rose by a plausible cost. The field name `usage.cost` itself is not visible through the gateway: the run confirms the usage and that OpenRouter charges the turn, not the name. | No `usage` event, or the spend rose while `usage` stayed absent. |
| An OpenRouter error inside a started stream is `{"error": {...}}` with a numeric `code` ([openai.md](../openai.md#chat-completions-failures)). | Not provoked: a short turn on a healthy key gets no in-stream error. If one happens, its log line names a kind other than `unavailable` with a decode message. | A log line `unavailable` whose message says the chunk does not decode, during a stream that had started. |
| OpenRouter answers a key without credit with 402, read as a usage limit without reset. | The optional 402 check gives `usage_limit` and `exhausted`. | The check gives another kind, such as `bad_request` or `auth`, or another status. |

## Rollback

1. Stop the gateway and `qbd` with Ctrl-C in their terminals.
2. Revoke each key made for this run in its vendor's console.
3. Delete the credential files and the backup, which hold tokens and keys:

   ```sh
   rm -r <credentials-dir> <backup-dir>
   ```

   The ChatGPT sign-in stays valid at the vendor until its refresh token expires or the owner
   signs out of the account's other sessions.
4. Keep `<smoke-dir>` with the turn outputs and `gateway.log` for the report; they hold no
   secret. Delete it afterwards.

Nothing else changed: the production `qbd`, gateways and clients never saw this run.
