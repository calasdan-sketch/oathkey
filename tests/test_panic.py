"""`stuntkey panic`: revoke (fake vendor), re-issue, find the old key, ledger;
never over MCP / serve; the revoke recipe schema; the status reminder."""
import argparse
import copy
import io
import json
import os
import subprocess
import unittest

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import broker, httpd, ledger, mcp, panic, recipes

CATALOG = recipes.load_recipes(recipes.RECIPES_DIR)
OLD = "github_pat_" + "OLDoldOLD1234567890abcdefXYZ"   # built at run time
VOLD = "vcp_" + "OldVercelToken1234567890"
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.6", port))]
PRIVATE = lambda host, port, **k: [(2, 1, 6, "", ("10.0.0.5", port))]


def args(service, dry=False):
    return argparse.Namespace(service=service, dry_run=dry, no_browser=True, env_file=None)


class FakeVendor:
    """Stands in for broker._real_send: records the request, answers `status`."""

    def __init__(self, status):
        self.status, self.seen = status, []

    def __call__(self, req, ip, timeout):
        self.seen.append((req.get_method(), req.full_url, dict(req.header_items()),
                          req.data, ip))
        return self.status, {}, b'{"echo": "' + OLD.encode() + b'"}'


class Run:
    def __init__(self, tmp, service="github", old=OLD, status=202, answers=(True, True),
                 reissue=0, resolver=PUBLIC):
        self.tmp = tmp
        self.out = io.StringIO()
        self.vendor = FakeVendor(status)
        self.answers = list(answers)
        self.asked, self.opened, self.connected = [], [], []
        self.index = os.path.join(tmp, "index.json")
        orig = ledger.path
        ledger.path = lambda: self.index
        try:
            self.code = panic.cmd_panic(
                args(service), CATALOG, env_file=os.path.join(tmp, ".env"), root=tmp,
                connect_fn=lambda r: (self.connected.append(r["service"]), reissue)[1],
                out=self.out, ask=self._ask, open_page=self.opened.append,
                read_values=lambda r: {r["env_var"]: old} if old else {},
                send=self.vendor, resolver=resolver, home=tmp,
                git=lambda root, matcher: {"findings": []})
        finally:
            ledger.path = orig
        self.text = self.out.getvalue()
        self.events = [e["step"] + ":" + e["result"] for e in
                       json.load(open(self.index))["projects"][os.path.realpath(tmp)]
                       [service]["events"]] if os.path.exists(self.index) else []

    def _ask(self, q):
        self.asked.append(q)
        return self.answers.pop(0) if self.answers else False


class Revoke(unittest.TestCase):
    def setUp(self):
        self.tmp = _isolation.mktemp()

    def test_github_revokes_through_the_official_api_without_auth(self):
        r = Run(self.tmp)
        self.assertEqual(r.code, 0, r.text)
        method, url, headers, data, ip = r.vendor.seen[0]
        self.assertEqual((method, url), ("POST", "https://api.github.com/credentials/revoke"))
        self.assertNotIn("Authorization", headers)      # GitHub: authenticated = 403
        self.assertEqual(json.loads(data), {"credentials": [OLD]})
        self.assertEqual(ip, "140.82.112.6")
        self.assertEqual(r.connected, ["github"])
        self.assertEqual(r.events, ["panic:started", "revoke:api 202", "reissue:ok",
                                    "scan:0 found"])
        self.assertNotIn(OLD, r.text)

    def test_vercel_deletes_the_current_token(self):
        r = Run(self.tmp, "vercel", VOLD, status=200)
        self.assertEqual(r.code, 0, r.text)
        method, url, headers, data, _ = r.vendor.seen[0]
        self.assertEqual((method, url), ("DELETE", "https://api.vercel.com/v3/user/tokens/current"))
        self.assertEqual(headers["Authorization"], "Bearer " + VOLD)
        self.assertIsNone(data)

    def test_a_failed_revoke_stops_before_anything_is_replaced(self):
        r = Run(self.tmp, status=422)
        self.assertEqual(r.code, 1)
        self.assertIn("revoke failed", r.text)
        self.assertIn("STOPPED", r.text)
        self.assertEqual(r.connected, [])               # old key left in place
        self.assertIn("revoke:failed", r.events)
        self.assertNotIn(OLD, r.text)

    def test_a_private_address_is_refused(self):
        r = Run(self.tmp, resolver=PRIVATE)
        self.assertEqual((r.code, r.vendor.seen, r.connected), (1, [], []))

    def test_saying_no_changes_nothing(self):
        r = Run(self.tmp, answers=(False,))
        self.assertEqual((r.code, r.vendor.seen, r.connected), (1, [], []))
        self.assertEqual(r.events, ["panic:declined"])

    def test_dry_run_asks_and_sends_nothing(self):
        out = io.StringIO()
        code = panic.cmd_panic(args("github", dry=True), CATALOG, connect_fn=None,
                               env_file=".env", root=self.tmp, out=out,
                               ask=lambda q: self.fail("asked"),
                               read_values=lambda r: {"GITHUB_TOKEN": OLD},
                               send=lambda *a: self.fail("sent"))
        self.assertEqual(code, 0)
        self.assertIn("api.github.com", out.getvalue())
        self.assertNotIn(OLD, out.getvalue())

    def test_no_api_opens_the_page_and_waits_for_the_person(self):
        r = Run(self.tmp, "openai", "sk-" + "x" * 30, answers=(True, False))
        self.assertEqual(r.opened, ["https://platform.openai.com/api-keys"])
        self.assertEqual((r.code, r.vendor.seen, r.connected), (1, [], []))
        r = Run(_isolation.mktemp(), "openai", "sk-" + "x" * 30, answers=(True, True))
        self.assertEqual((r.code, r.connected), (0, ["openai"]))
        self.assertIn("revoke:confirmed by person", r.events)

    def test_a_failed_reissue_says_so(self):
        r = Run(self.tmp, reissue=1)
        self.assertEqual(r.code, 1)
        self.assertIn("reissue:failed", r.events)


class FindOld(unittest.TestCase):
    def test_finds_the_old_key_in_files_mcp_configs_and_git_masked(self):
        tmp = _isolation.mktemp()
        with open(os.path.join(tmp, ".env"), "w") as f:
            f.write(f"GITHUB_TOKEN={OLD}\nOTHER=github_pat_{'n' * 30}\n")
        with open(os.path.join(tmp, ".mcp.json"), "w") as f:
            json.dump({"mcpServers": {"x": {"env": {"T": OLD}}}}, f)
        git = lambda *a, **k: subprocess.run(["git", "-C", tmp, *a], capture_output=True, **k)
        git("init", "-q")
        with open(os.path.join(tmp, "old.py"), "w") as f:
            f.write(f'T = "{OLD}"\n')
        git("add", "old.py")
        git("-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "x")
        os.remove(os.path.join(tmp, "old.py"))
        found = panic.find_old([panic.fingerprint(OLD)], tmp, home=tmp)
        where = sorted((f["where"], os.path.basename(f["file"])) for f in found)
        self.assertIn(("file", ".env"), where)
        self.assertIn(("file", ".mcp.json"), where)
        if git("--version").returncode == 0:
            self.assertIn(("git", "old.py"), where)
        self.assertEqual(sum(1 for f in found if f["file"].endswith(".env")), 1)
        self.assertNotIn(OLD, json.dumps(found))


class NeverForAgents(unittest.TestCase):
    def test_mcp_tools_and_serve_routes_have_no_panic_or_revoke(self):
        names = [t["name"] for t in mcp._tool_defs()] + \
                [json.dumps(t) for t in httpd.TOOLS]
        for n in names:
            self.assertNotRegex(n.lower(), "panic|revoke")
        src = open(httpd.__file__, encoding="utf-8").read()
        self.assertNotIn("panic", src)
        self.assertNotIn("panic", open(mcp.__file__, encoding="utf-8").read())


class Schema(unittest.TestCase):
    def check(self, revoke):
        r = copy.deepcopy({k: v for k, v in CATALOG["vercel"].items()
                           if not k.startswith("_")})
        r["revoke"] = revoke
        return recipes.validate_recipe(r)

    def test_good_and_bad_revoke_fields(self):
        api = {"method": "DELETE", "url": "https://api.vercel.com/v3/user/tokens/current",
               "auth": {"type": "bearer"}, "expect": [200]}
        self.check({"api": api})
        self.check({"page": "https://vercel.com/account/tokens", "steps": ["a"]})
        for bad in ({}, {"steps": ["a"]}, {"page": "http://x.com"},
                    {"api": dict(api, url="https://evil.example/x")},
                    {"api": dict(api, url="http://api.vercel.com/x")},
                    {"api": dict(api, method="GET")},
                    {"api": dict(api, expect=[401])},
                    {"api": dict(api, auth={"type": "json_list"})},
                    {"api": dict(api, headers={"X": "a\r\nb"})}):
            with self.assertRaises(recipes.RecipeError, msg=bad):
                self.check(bad)


class StatusReminder(unittest.TestCase):
    def test_old_key_hint_mentions_rotate_and_panic(self):
        import datetime
        from stuntkey import projectcmds
        tmp = _isolation.mktemp()
        index = os.path.join(tmp, "i.json")
        then = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        ledger.record(tmp, "github", "env", index_path=index, now=then)
        with open(os.path.join(tmp, ".env"), "w") as f:
            f.write(f"GITHUB_TOKEN={OLD}\n")
        rows = projectcmds.status_rows({"services": [{"service": "github"}]}, tmp, CATALOG,
                                       os.path.join(tmp, ".env"), 90, False,
                                       index_path=index, now=then + datetime.timedelta(days=120))
        self.assertIn("stuntkey rotate github", rows[0]["hint"])
        self.assertIn("stuntkey panic github", rows[0]["hint"])


if __name__ == "__main__":
    unittest.main()
