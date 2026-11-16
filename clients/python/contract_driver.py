"""Contract-test driver for qb_client, not part of the client: one call, one JSON line out.

argv: SOCKET BEARER TIMEOUT OP [REQUEST], with BEARER "" for none and OP one of pick, report,
state, health. Prints {"result": ...} or {"qb_error": {"status", "error", "message"}}.
"""

import json
import os
import sys

# Run under `python3 -I`, which leaves the script's directory off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from qb_client import Client, QbError  # noqa: E402


def local_pick(request: dict) -> dict:
    return {"decision": "run", "login": "local-login", "role": request["role"]}


def main(argv: list) -> None:
    socket_path, bearer, timeout, op, *request = argv
    client = Client(socket_path, bearer or None, float(timeout))
    calls = {
        "pick": lambda: client.pick(json.loads(request[0]), local_pick),
        "report": lambda: client.report(json.loads(request[0])),
        "state": client.state,
        "health": client.health,
    }
    try:
        out = {"result": calls[op]()}
    except QbError as e:
        out = {"qb_error": {"status": e.status, "error": e.error, "message": e.message}}
    print(json.dumps(out))


if __name__ == "__main__":
    main(sys.argv[1:])
