"""Stdlib-only client for the qbd /v1 API over a unix socket, one request per connection.

pick() answers fallback(request) plus {"fallback": True} only when qbd is unreachable; an HTTP
error status from a reachable qbd raises QbError. report() is best effort and answers None then.
"""

from __future__ import annotations

import http.client
import json
import os
import socket
from typing import Callable, Optional

DEFAULT_SOCKET = "/run/qb/qb.sock"

# Raised before a status line arrives: no socket, nobody listening, connect or read timeout,
# reset or close by the peer. AF_UNIX connect reports a full backlog as EAGAIN, not a timeout.
UNREACHABLE = (FileNotFoundError, ConnectionError, BlockingIOError, socket.timeout)


class QbError(Exception):
    """An HTTP error status from a reachable qbd: the request or the config is wrong."""

    def __init__(self, status: int, error: str, message: str) -> None:
        super().__init__(f"qbd answered {status} {error}: {message}")
        self.status, self.error, self.message = status, error, message


class _UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("qb", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Client:
    def __init__(self, socket_path: Optional[str] = None, bearer: Optional[str] = None,
                 timeout: float = 2.0) -> None:
        self.socket_path = socket_path or os.environ.get("QB_SOCKET") or DEFAULT_SOCKET
        self.bearer, self.timeout = bearer, timeout

    def pick(self, request: dict, fallback: Callable[[dict], dict]) -> dict:
        try:
            conn, resp = self._send("POST", "/v1/pick", request)
        except UNREACHABLE:
            return {**fallback(request), "fallback": True}
        return self._finish(conn, resp)

    def report(self, request: dict) -> Optional[dict]:
        try:
            conn, resp = self._send("POST", "/v1/report", request)
        except UNREACHABLE:
            return None
        return self._finish(conn, resp)

    def state(self) -> dict:
        return self._finish(*self._send("GET", "/v1/state", None))

    def health(self) -> dict:
        return self._finish(*self._send("GET", "/v1/health", None))

    def _send(self, method: str, path: str, body: Optional[dict]):
        conn = _UnixConnection(self.socket_path, self.timeout)
        headers = {} if body is None else {"Content-Type": "application/json"}
        if self.bearer:
            headers["Authorization"] = "Bearer " + self.bearer
        try:
            conn.request(method, path, None if body is None else json.dumps(body).encode(), headers)
            return conn, conn.getresponse()
        except BaseException:
            conn.close()
            raise

    @staticmethod
    def _finish(conn: _UnixConnection, resp: http.client.HTTPResponse) -> dict:
        try:
            payload = json.loads(resp.read())
        finally:
            conn.close()
        if resp.status >= 400:
            raise QbError(resp.status, payload["error"], payload["message"])
        return payload
