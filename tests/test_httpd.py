import http.client
import json
import os
import stat
import tempfile
import unittest

from stuntkey import broker, httpd, recipes

KEY = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"   # built at run time
CATALOG = recipes.load_recipes()
TOKEN = "t" * 43


def fake_call(recipe, values, method, path, query=None, body=None, **kw):
    if method == "POST":
        raise broker.BrokerError("writes are not allowed", 5)
    return {"status": 200, "headers": {}, "body": json.dumps({"ok": path}),
            "truncated": False}


class Door(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = httpd.make_server(CATALOG, lambda r: {"GITHUB_TOKEN": KEY},
                                    TOKEN, broker.Policy(), call_fn=fake_call)
        cls.port = cls.srv.server_address[1]
        httpd.start_background(cls.srv)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def req(self, method, path, body=None, headers=None, host=None):
        h = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
             "Host": host or f"127.0.0.1:{self.port}"}
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in h.items():
            c.putheader(k, v)
        data = json.dumps(body).encode() if body is not None else b""
        c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())

    def test_works_with_token(self):
        s, b, _ = self.req("POST", "/call", {"service": "github", "method": "GET", "path": "/user"})
        self.assertEqual(s, 200)
        self.assertEqual(json.loads(b)["status"], 200)

    def test_tools_listing(self):
        s, b, _ = self.req("GET", "/tools")
        self.assertEqual(s, 200)
        self.assertEqual({t["function"]["name"] for t in json.loads(b)},
                         {"call_api", "list_services"})

    def test_no_or_wrong_token(self):
        self.assertEqual(self.req("GET", "/tools", headers={"Authorization": None})[0], 401)
        self.assertEqual(self.req("GET", "/tools", headers={"Authorization": "Bearer nope"})[0], 401)

    def test_dns_rebinding_host_refused(self):
        self.assertEqual(self.req("GET", "/tools", host="evil.com")[0], 403)
        self.assertEqual(self.req("GET", "/tools", host=f"evil.com:{self.port}")[0], 403)
        self.assertEqual(self.req("GET", "/tools", host="127.0.0.1")[0], 403)

    def test_browser_origin_refused(self):
        s, _, _ = self.req("POST", "/call", {"service": "github", "method": "GET",
                                             "path": "/user"},
                           headers={"Origin": "https://evil.com"})
        self.assertEqual(s, 403)

    def test_no_cors_headers(self):
        _, _, h = self.req("GET", "/tools")
        self.assertFalse([k for k in h if k.lower().startswith("access-control")])

    def test_policy_refusal_is_403_and_has_no_key(self):
        s, b, _ = self.req("POST", "/call", {"service": "github", "method": "POST", "path": "/gists"})
        self.assertEqual(s, 403)
        self.assertNotIn(KEY.encode(), b)

    def test_bad_input(self):
        self.assertEqual(self.req("POST", "/call", {"method": "GET"})[0], 400)
        self.assertEqual(self.req("POST", "/call", {"service": "nope", "method": "GET",
                                                    "path": "/x"})[0], 404)
        self.assertEqual(self.req("POST", "/call", {}, headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.req("POST", "/call", {}, headers={"Content-Length": "9999999"})[0] in (413, 400), True)

    def test_unknown_path(self):
        self.assertEqual(self.req("GET", "/etc/passwd")[0], 404)

    def test_binds_loopback_only(self):
        self.assertEqual(self.srv.server_address[0], "127.0.0.1")


class TokenFile(unittest.TestCase):
    def test_created_private_and_stable(self):
        p = os.path.join(tempfile.mkdtemp(), "sub", "http.token")
        t1 = httpd.load_or_make_token(p)
        self.assertGreaterEqual(len(t1), 40)
        self.assertEqual(httpd.load_or_make_token(p), t1)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
