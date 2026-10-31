"""0.6.1: doctor-recipes never visits private addresses; per-service time limit; pinned actions."""
import os
import re
import unittest

import _isolation  # noqa: F401
from stuntkey import doctor

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Private(unittest.TestCase):
    def test_literal_private_addresses(self):
        for url in ("http://127.0.0.1/x", "https://localhost/", "https://10.0.0.5/", "https://192.168.1.1/",
                    "https://169.254.169.254/latest/meta-data", "https://[::1]/", "https://[::ffff:127.0.0.1]/",
                    "https://printer.local/", "https://db.internal/", "https://0.0.0.0/"):
            self.assertIsNotNone(doctor.private_host_reason(url), url)
        self.assertIsNone(doctor.private_host_reason("https://platform.openai.com/api-keys"))
        self.assertIsNone(doctor.private_host_reason("https://8.8.8.8/"))

    def test_redirect_to_private_is_not_followed(self):
        seen = []

        def fetch(url, timeout):
            seen.append(url)
            if url == "https://vendor.example/a":
                return 302, "https://169.254.169.254/latest/meta-data", None
            return 200, None, None
        r = doctor.check_url("https://vendor.example/a", fetch)
        self.assertEqual(seen, ["https://vendor.example/a"])
        self.assertNotEqual(r["verdict"], doctor.OK)
        self.assertIn("not visited", r["detail"])

    def test_name_that_resolves_private_is_refused(self):
        resolver = lambda host, port, type=None: [(2, 1, 6, "", ("10.1.2.3", 0))]
        self.assertTrue(doctor.resolves_private("evil.example", resolver))
        resolver2 = lambda host, port, type=None: [(2, 1, 6, "", ("93.184.216.34", 0))]
        self.assertFalse(doctor.resolves_private("fine.example", resolver2))

    def test_real_fetch_refuses_a_private_name_without_connecting(self):
        orig = doctor.resolves_private
        doctor.resolves_private = lambda host, resolver=None: True
        try:
            status, loc, problem = doctor.fetch("https://anything.example/")
        finally:
            doctor.resolves_private = orig
        self.assertIsNone(status)
        self.assertIn("private", problem)

    def test_redirect_to_http_still_rot(self):
        r = doctor.check_url("https://v.example/", lambda u, t: (301, "http://v.example/", None))
        self.assertEqual(r["verdict"], doctor.ROT)


class Budget(unittest.TestCase):
    def test_slow_service_is_cut_short(self):
        clock = [0.0]
        def now():
            return clock[0]
        def fetch(url, timeout):
            clock[0] += 100.0
            return 200, None, None
        cat = {"x": {"key_url": "https://a.example/1", "docs": "https://a.example/2",
                     "validate": {"url": "https://a.example/3", "auth": {"type": "bearer"}}}}
        rows = doctor.run(cat, fetch, now=now, budget=90.0)
        self.assertEqual([r["verdict"] for r in rows], [doctor.OK, doctor.WARN, doctor.WARN])
        self.assertIn("skipped", rows[1]["detail"])


class Workflow(unittest.TestCase):
    def test_actions_pinned_by_sha_and_scope_kept(self):
        with open(os.path.join(REPO, ".github", "workflows", "recipes.yml")) as f:
            text = f.read()
        for m in re.finditer(r"uses:\s*(\S+)", text):
            self.assertRegex(m.group(1), r"@[0-9a-f]{40}$")
        self.assertEqual(text.count("issues: write"), 1)
        self.assertIn("timeout-minutes", text)


class UserRecipeToLocalhost(unittest.TestCase):
    REC = {"display": "Mine", "service": "mine", "env_var": "MINE_KEY", "key_url": "http://localhost:8000/keys",
           "steps": ["go"], "scopes": [], "validate": {"method": "GET", "url": "http://localhost:8000/me",
           "auth": {"type": "bearer"}, "expect": [200]}}

    def test_private_validate_url_needs_a_typed_yes(self):
        import io
        from stuntkey import connect
        asked, out = [], io.StringIO()
        code = connect.connect(dict(self.REC, _builtin=False), browser_open=lambda u: None,
                               prompt=lambda t: self.fail("asked for a key before confirming"),
                               out=out, confirm_in=lambda t: asked.append(t) or "no",
                               validate_fn=lambda *a: self.fail("sent"), store_fn=lambda a, b: "ok")
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), 1)
        self.assertIn("THIS computer", out.getvalue())

    def test_typed_yes_goes_on(self):
        import io
        from stuntkey import connect
        code = connect.connect(dict(self.REC, _builtin=False), browser_open=lambda u: None,
                               prompt=lambda t: "abcdefghij1234567890", out=io.StringIO(),
                               confirm_in=lambda t: "yes", validate_fn=lambda *a: True,
                               store_fn=lambda a, b: "ok")
        self.assertEqual(code, 0)
