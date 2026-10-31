"""A tiny local web door for AIs that have no MCP and no shell
(OpenAI-style function calling, Ollama wrappers, scripts).

Same broker underneath, so the same rules: the AI never gets the key, the
host is fixed by the recipe, writes ask the person on the real terminal.

Safety of the door itself:
- listens on 127.0.0.1 only
- every request needs the secret token (random, kept in an owner-only file)
- the Host header must be exactly us (blocks DNS-rebinding tricks)
- any request with an Origin header is refused (blocks web pages)
- no CORS headers are ever sent; bodies are size-limited
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import broker

MAX_REQUEST = 300_000

TOOLS = [
    {"type": "function", "function": {
        "name": "call_api",
        "description": ("Call a connected service's API without seeing its "
                        "key. Host and credential are added for you."),
        "parameters": {"type": "object", "properties": {
            "service": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]},
            "path": {"type": "string", "description": "like /user"},
            "query": {"type": "object"},
            "body": {"type": "object"}},
            "required": ["service", "method", "path"]}}},
    {"type": "function", "function": {
        "name": "list_services",
        "description": "Services that have a saved connection recipe.",
        "parameters": {"type": "object", "properties": {}}}},
]


def load_or_make_token(path: str) -> str:
    try:
        with open(path, encoding="ascii") as f:
            tok = f.read().strip()
        if len(tok) >= 40:
            return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(32)
    folder = os.path.dirname(path) or "."
    os.makedirs(folder, mode=0o700, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(tok + "\n")
    return tok


def local_only(headers, port: int) -> bool:
    """Host must be exactly us (no DNS rebinding) and no web page (Origin)."""
    host = (headers.get("Host") or "").lower()
    return (host in (f"127.0.0.1:{port}", f"localhost:{port}")
            and headers.get("Origin") is None)


class DoorServer(ThreadingHTTPServer):
    """On Windows, SO_REUSEADDR lets another program bind the very same port
    and take the door's connections; ask for the port exclusively instead."""
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if os.name == "nt" and exclusive is not None:
            self.socket.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        super().server_bind()


def make_server(catalog: dict, get_values, token: str, policy, audit=None,
                port: int = 0, call_fn=None) -> ThreadingHTTPServer:
    call_fn = call_fn or broker.call

    class Handler(BaseHTTPRequestHandler):
        server_version = "oathkey"
        sys_version = ""
        timeout = 15                       # a stalled client cannot hold a thread forever

        def log_message(self, *a):          # never log request lines
            pass

        def _send(self, code: int, obj) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _guard(self) -> bool:
            if not local_only(self.headers, self.server.server_address[1]):
                self._send(403, {"error": "forbidden"})
                return False
            given = (self.headers.get("Authorization") or "")
            want = "Bearer " + token
            if not hmac.compare_digest(given.encode(), want.encode()):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self._guard():
                return
            if self.path == "/tools":
                return self._send(200, TOOLS)
            if self.path == "/services":
                return self._send(200, [
                    {"service": r["service"], "display": r["display"]}
                    for r in catalog.values()])
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            if self.path != "/call":
                return self._send(404, {"error": "not found"})
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return self._send(415, {"error": "send application/json"})
            try:
                n = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                n = -1
            if n < 0 or n > MAX_REQUEST:
                return self._send(413, {"error": "request too large"})
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
                recipe = catalog.get(req["service"])
                if not recipe:
                    return self._send(404, {"error": "unknown service"})
                values = get_values(recipe)
                out = call_fn(recipe, values, req["method"], req["path"],
                              req.get("query"), req.get("body"),
                              policy=policy, audit=audit)
                return self._send(200, out)
            except broker.BrokerError as e:
                return self._send(403 if e.code == 5 else 502, {"error": str(e)})
            except (ValueError, KeyError, TypeError):
                return self._send(400, {"error": "bad request"})
            except Exception:
                return self._send(500, {"error": "internal error"})

    srv = DoorServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


def serve_forever(srv) -> None:
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def start_background(srv) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
