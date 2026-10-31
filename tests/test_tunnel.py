import json
import os
import queue
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import mcp as mcp_mod
from stuntkey import validate as validate_mod


class Handler(BaseHTTPRequestHandler):
    # class-level knobs set by each test
    mode = "ok"          # ok | unauthorized | flaky
    seen_auth = None

    def do_GET(self):
        Handler.seen_auth = self.headers.get("Authorization")
        if Handler.mode == "ok":
            self.send_response(200)
        elif Handler.mode == "unauthorized":
            self.send_response(401)
        else:
            self.send_response(500)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


def run_server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def spec(srv, auth=None):
    return {"method": "GET",
            "url": f"http://127.0.0.1:{srv.server_port}/me",
            "auth": auth or {"type": "bearer"},
            "expect": [200]}


class TestValidateHTTP(unittest.TestCase):
    def test_bearer_ok(self):
        srv = run_server()
        try:
            Handler.mode = "ok"
            self.assertTrue(validate_mod.validate_key(spec(srv), "k123"))
            self.assertEqual(Handler.seen_auth, "Bearer k123")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_401_is_rejection_not_crash(self):
        srv = run_server()
        try:
            Handler.mode = "unauthorized"
            self.assertFalse(validate_mod.validate_key(spec(srv), "bad"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_header_auth(self):
        srv = run_server()
        try:
            Handler.mode = "ok"
            s = spec(srv, {"type": "header", "header": "X-API-Key"})
            # header-auth servers usually still send Authorization-less;
            # our impl puts the key in the named header instead.
            self.assertTrue(validate_mod.validate_key(s, "k123"))
            self.assertIsNone(Handler.seen_auth)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_basic_auth(self):
        srv = run_server()
        try:
            Handler.mode = "ok"
            self.assertTrue(validate_mod.validate_key(
                spec(srv, {"type": "basic"}), "k123"))
            self.assertTrue(Handler.seen_auth.startswith("Basic "))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_unreachable_raises(self):
        srv = run_server()
        port = srv.server_port
        srv.shutdown()
        srv.server_close()
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod.validate_key(spec(srv, ), "k",
                                       timeout=1.0)


CATALOG = {"acme": {"service": "acme", "display": "Acme",
                    "key_url": "https://acme.test/keys",
                    "env_var": "ACME_KEY", "steps": ["Click new key"],
                    "scopes": [], "docs": "",
                    "validate": {"method": "GET",
                                 "url": "https://acme.test/me",
                                 "auth": {"type": "bearer"},
                                 "expect": [200]}}}


class TestMCP(unittest.TestCase):
    def test_initialize(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1,
                            "method": "initialize", "params": {}}, CATALOG)
        self.assertEqual(r["result"]["serverInfo"]["name"], "stuntkey")

    def test_tools_list(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 2,
                            "method": "tools/list"}, CATALOG)
        names = {t["name"] for t in r["result"]["tools"]}
        self.assertEqual(names, {"list_services", "get_recipe", "find_public_apis", "get_public_api", "request_connect", "needs_keys", "capture_key", "call_api"})

    def test_list_services(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                            "params": {"name": "list_services",
                                       "arguments": {}}}, CATALOG)
        services = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(services[0]["service"], "acme")

    def test_get_recipe(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                            "params": {"name": "get_recipe",
                                       "arguments": {"service": "acme"}}},
                           CATALOG)
        text = r["result"]["content"][0]["text"]
        self.assertIn("https://acme.test/keys", text)
        self.assertIn("stuntkey connect acme", text)

    def test_get_recipe_unknown(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                            "params": {"name": "get_recipe",
                                       "arguments": {"service": "nope"}}},
                           CATALOG)
        self.assertTrue(r["result"]["isError"])

    def test_unknown_method(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 6,
                            "method": "nope"}, CATALOG)
        self.assertIn("error", r)

    def test_notification_returns_none(self):
        self.assertIsNone(mcp_mod.handle(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}, CATALOG))

    def test_stdio_smoke(self):
        """Full stdio round-trip through a real subprocess: the repo root
        as cwd (wherever it is checked out), bytes on the wire, and a
        reader thread with a timeout instead of a blocking readline."""
        proc = subprocess.Popen(
            [sys.executable, "-m", "stuntkey", "mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            cwd=_isolation.REPO, env=dict(os.environ))
        lines: "queue.Queue[bytes]" = queue.Queue()

        def pump():
            for ln in iter(proc.stdout.readline, b""):
                lines.put(ln)

        threading.Thread(target=pump, daemon=True).start()

        def rpc(method, params=None, rid=1):
            proc.stdin.write((json.dumps(
                {"jsonrpc": "2.0", "id": rid, "method": method,
                 "params": params or {}}) + "\n").encode("utf-8"))
            proc.stdin.flush()
            return json.loads(lines.get(timeout=20).decode("utf-8"))
        try:
            init = rpc("initialize")
            self.assertEqual(init["result"]["serverInfo"]["name"],
                             "stuntkey")
            tools = rpc("tools/list", rid=2)
            self.assertEqual(len(tools["result"]["tools"]), 8)
            call = rpc("tools/call",
                       {"name": "list_services", "arguments": {}}, rid=3)
            services = json.loads(call["result"]["content"][0]["text"])
            self.assertTrue(any(s["service"] == "github" for s in services))
        finally:
            proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=5)
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
