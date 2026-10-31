import base64
import json
import os
import tempfile
import unittest

from stuntkey import broker, recipes

KEY = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # built at run time
RECIPE = recipes.load_recipes()["github"]
VALUES = {"GITHUB_TOKEN": KEY}
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))]


def fake(status=200, body=b"{}", ctype="application/json", seen=None, extra=None):
    def send(req, ip, timeout):
        if seen is not None:
            seen.append((req, ip))
        h = {"content-type": ctype}
        h.update(extra or {})
        return status, h, body
    return send


def go(path="/user", method="GET", **kw):
    kw.setdefault("send", fake())
    kw.setdefault("resolver", PUBLIC)
    return broker.call(RECIPE, VALUES, method, path, **kw)


class PathAndHost(unittest.TestCase):
    def test_hostile_paths_refused(self):
        for bad in ("user", "//evil.com/x", "/a/../../etc", "/a/./b", "/x\\y",
                    "/x y", "/x\r\nHost: evil", "/%2e%2e/x", "http://evil.com/",
                    "@evil.com/x", "", None, "/x?y=1"):
            with self.assertRaises(broker.BrokerError, msg=repr(bad)):
                go(bad)

    def test_host_always_from_recipe(self):
        seen = []
        go("/user", send=fake(seen=seen))
        req, _ = seen[0]
        self.assertEqual(req.host, "api.github.com")
        self.assertTrue(req.full_url.startswith("https://api.github.com/user"))

    def test_credential_added_by_broker_only(self):
        seen = []
        go("/user", send=fake(seen=seen))
        self.assertEqual(seen[0][0].get_header("Authorization"), f"Bearer {KEY}")

    def test_query_param_cannot_smuggle_credential(self):
        r = dict(RECIPE, validate=dict(RECIPE["validate"],
                 auth={"type": "query", "param": "api_key"}))
        with self.assertRaises(broker.BrokerError):
            broker.call(r, VALUES, "GET", "/x", query={"api_key": "mine"},
                        send=fake(), resolver=PUBLIC)


class Addresses(unittest.TestCase):
    def test_non_public_refused(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                   "100.64.0.1", "::1", "fe80::1", "fc00::1",
                   "::ffff:127.0.0.1", "0.0.0.0"):
            self.assertFalse(broker.is_public_ip(ip), ip)
        self.assertTrue(broker.is_public_ip("140.82.112.5"))

    def test_name_that_also_points_inside_refused(self):
        mixed = lambda h, p, **k: [(2, 1, 6, "", ("140.82.112.5", p)),
                                   (2, 1, 6, "", ("10.0.0.1", p))]
        with self.assertRaises(broker.BrokerError):
            go(resolver=mixed)

    def test_connects_to_checked_ip(self):
        seen = []
        go(send=fake(seen=seen))
        self.assertEqual(seen[0][1], "140.82.112.5")


class Permissions(unittest.TestCase):
    def test_writes_refused_by_default(self):
        with self.assertRaises(broker.BrokerError):
            go("/gists", "POST", body={"a": 1})

    def test_write_with_approval(self):
        asked = []
        p = broker.Policy(approve=lambda s: asked.append(s) or True)
        self.assertEqual(go("/gists", "POST", body={"a": 1}, policy=p)["status"], 200)
        self.assertIn("POST", asked[0])

    def test_write_denied_by_person(self):
        with self.assertRaises(broker.BrokerError):
            go("/gists", "POST", body={}, policy=broker.Policy(approve=lambda s: False))

    def test_get_with_body_refused(self):
        with self.assertRaises(broker.BrokerError):
            go("/user", body={"x": 1})

    def test_call_limit(self):
        p = broker.Policy(max_calls=2)
        go(policy=p)
        go(policy=p)
        with self.assertRaises(broker.BrokerError):
            go(policy=p)

    def test_rate_limit(self):
        p = broker.Policy(max_per_minute=1)
        go(policy=p)
        with self.assertRaises(broker.BrokerError):
            go(policy=p)


class Scrubbing(unittest.TestCase):
    def test_echoed_key_is_hidden_in_many_forms(self):
        raw = KEY.encode()
        body = json.dumps({"raw": KEY, "b64": base64.b64encode(raw).decode(),
                           "hex": raw.hex()}).encode()
        out = go(send=fake(body=body, extra={"location": "https://x/?t=" + KEY}))
        self.assertNotIn(KEY, out["body"])
        self.assertNotIn(raw.hex(), out["body"])
        self.assertNotIn(base64.b64encode(raw).decode(), out["body"])
        self.assertNotIn(KEY, json.dumps(out["headers"]))

    def test_binary_is_opaque(self):
        out = go(send=fake(body=KEY.encode(), ctype="application/octet-stream"))
        self.assertNotIn(KEY, out["body"])
        self.assertIn("binary", out["body"])

    def test_network_error_has_no_key(self):
        def boom(req, ip, t):
            raise broker.BrokerError("network error talking to the API", 7)
        with self.assertRaises(broker.BrokerError) as c:
            go(send=boom)
        self.assertNotIn(KEY, str(c.exception))


class Audit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = broker.AuditLog(os.path.join(self.dir, "audit.log"))

    def test_chain_verifies_and_hides_query(self):
        go("/user", query={"secretq": "SHOULDNOTAPPEAR"}, audit=self.log)
        go("/repos/a/b", audit=self.log)
        ok, n = self.log.verify()
        self.assertTrue(ok)
        self.assertEqual(n, 2)
        text = open(self.log.path).read()
        self.assertNotIn("SHOULDNOTAPPEAR", text)
        self.assertNotIn(KEY, text)

    def test_tamper_detected(self):
        for _ in range(3):
            go(audit=self.log)
        lines = open(self.log.path).read().splitlines()
        lines[1] = lines[1].replace('"status": 200', '"status": 500')
        open(self.log.path, "w").write("\n".join(lines) + "\n")
        self.assertFalse(self.log.verify()[0])

    def test_removed_line_detected(self):
        for _ in range(3):
            go(audit=self.log)
        lines = open(self.log.path).read().splitlines()
        open(self.log.path, "w").write("\n".join([lines[0], lines[2]]) + "\n")
        self.assertFalse(self.log.verify()[0])


if __name__ == "__main__":
    unittest.main()
