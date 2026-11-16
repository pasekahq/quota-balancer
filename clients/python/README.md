# Python client

`qb_client.py` is a single file with no dependencies beyond the standard library (Python 3.9+).
Copy it into your orchestrator; there is no package to install.

```python
from qb_client import Client, QbError

def local_pick(request):
    # Your orchestrator's own choice when qbd is down, for example a fixed order.
    return {"decision": "run", "vendor": "vendor-a", "model": "model-small", "login": "login-1"}

qb = Client()  # $QB_SOCKET, else /run/qb/qb.sock; timeout 2 s
choice = qb.pick({"role": "worker", "difficulty": 2, "expected_minutes": 30}, local_pick)
if choice["decision"] == "run" and "lease_id" in choice:
    qb.report({"lease_id": choice["lease_id"], "outcome": "ok", "release": True})
```

`pick` returns the daemon's `PickResponse` (see [docs/api.md](../../docs/api.md)). Only when
`qbd` is unreachable does it call your fallback and return its dict with `"fallback": True`
added. Unreachable means: the socket file is missing, nothing listens on it, the connect or the
read times out, or the connection is reset or closed before a status line arrives. The client
never invents a decision itself.

An HTTP error from a reachable daemon (4xx or 5xx) is not a fallback case: the request or the
config is wrong, and the call raises `QbError` with `status`, `error` and `message`.

`report` is best effort: it returns the `ReportResponse`, or `None` when `qbd` is unreachable,
and raises `QbError` on an HTTP error. `state()` and `health()` return the parsed responses and
raise when the daemon is unreachable.

## Bearer tokens

`Client(bearer=...)` sends `Authorization: Bearer <token>`; without it the daemon identifies
you by your uid. The client never reads a token from disk. Your orchestrator loads it from
wherever it keeps secrets and passes the string in.

The client has no logging, retries or threads, and makes no connection other than to the
socket you name.
