"""0.6.0: doctor-recipes. No test here touches the network."""
import io
import json
import os
import re
import socket
import ssl
import unittest
import urllib.error
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import doctor
from stuntkey import recipes as recipes_mod

CAT = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)


def fake(table):
    """fetch_fn answering from {url: (status, location, problem)}."""
    calls = []

    def fetch(url, timeout=15):
        calls.append(url)
        return table.get(url, (200, None, None))
    fetch.calls = calls
    return fetch


class TestJudging(unittest.TestCase):
    def one(self, status, location=None, problem=None, url="https://a.test/x"):
        return doctor.check_url(url, fake({url: (status, location, problem)}))

    def test_200_is_ok(self):
        self.assertEqual(self.one(200)["verdict"], "ok")

    def test_404_and_410_are_rot(self):
        for s in (404, 410):
            self.assertEqual(self.one(s)["verdict"], "ROT", s)

    def test_a_problem_is_rot(self):
        r = self.one(None, problem="name does not resolve")
        self.assertEqual((r["verdict"], r["detail"]), ("ROT", "name does not resolve"))

    def test_401_from_a_test_server_means_alive(self):
        self.assertEqual(self.one(401)["verdict"], "ok")

    def test_405_and_400_mean_alive(self):
        self.assertEqual(self.one(405)["verdict"], "ok")
        self.assertEqual(self.one(400)["verdict"], "ok")

    def test_403_429_and_5xx_are_only_warnings(self):
        for s in (403, 429, 500, 503):
            self.assertEqual(self.one(s)["verdict"], "warn", s)

    def test_a_redirect_is_followed_and_reported_as_moved(self):
        t = {"https://a.test/x": (301, "/new", None), "https://a.test/new": (200, None, None)}
        r = doctor.check_url("https://a.test/x", fake(t))
        self.assertEqual((r["verdict"], r["final"], r["hops"]), ("moved", "https://a.test/new", 1))

    def test_redirect_to_a_gone_page_is_rot(self):
        t = {"https://a.test/x": (302, "https://b.test/y", None), "https://b.test/y": (404, None, None)}
        self.assertEqual(doctor.check_url("https://a.test/x", fake(t))["verdict"], "ROT")

    def test_redirect_to_itself_is_rot(self):
        t = {"https://a.test/x": (302, "/x", None)}
        r = doctor.check_url("https://a.test/x", fake(t))
        self.assertEqual(r["verdict"], "ROT")

    def test_redirect_to_plain_http_is_rot(self):
        t = {"https://a.test/x": (302, "http://a.test/y", None)}
        r = doctor.check_url("https://a.test/x", fake(t))
        self.assertEqual(r["verdict"], "ROT")
        self.assertIn("HTTPS", r["detail"])

    def test_relative_location_is_resolved(self):
        t = {"https://a.test/d/x": (302, "../y", None)}
        r = doctor.check_url("https://a.test/d/x", fake(t))
        self.assertEqual(r["final"], "https://a.test/y")

    def test_a_very_long_chain_of_new_addresses_is_a_warning_not_rot(self):
        t = {f"https://a.test/{i}": (302, f"/{i + 1}", None) for i in range(40)}
        r = doctor.check_url("https://a.test/0", fake(t))
        self.assertEqual(r["verdict"], "warn")
        self.assertIn("sign-in", r["detail"])

    def test_a_loop_through_two_addresses_is_rot(self):
        t = {"https://a.test/a": (302, "/b", None), "https://a.test/b": (302, "/a", None)}
        self.assertEqual(doctor.check_url("https://a.test/a", fake(t))["detail"], "redirect loop")

    def test_a_redirect_to_a_sign_in_page_is_ok(self):
        t = {"https://a.test/keys": (302, "https://a.test/login?next=/keys", None)}
        r = doctor.check_url("https://a.test/keys", fake(t))
        self.assertEqual(r["verdict"], "ok")
        self.assertIn("sign-in", r["detail"])

    def test_google_sign_in_counts(self):
        t = {"https://a.test/k": (302, "https://accounts.google.com/v3/signin/identifier", None)}
        self.assertEqual(doctor.check_url("https://a.test/k", fake(t))["verdict"], "ok")

    def test_a_redirect_to_a_different_page_is_moved(self):
        t = {"https://a.test/old": (301, "https://a.test/docs/new", None)}
        self.assertEqual(doctor.check_url("https://a.test/old", fake(t))["verdict"], "moved")


class TestFetchErrors(unittest.TestCase):
    """doctor.fetch turns network failures into short sentences."""

    def fetch_with(self, exc):
        opener = mock.Mock()
        opener.open.side_effect = exc
        with mock.patch.object(doctor.urllib.request, "build_opener", return_value=opener):
            return doctor.fetch("https://a.test/")

    def test_dns(self):
        self.assertEqual(self.fetch_with(urllib.error.URLError(socket.gaierror(-2)))[2], "name does not resolve")

    def test_tls(self):
        self.assertEqual(self.fetch_with(urllib.error.URLError(ssl.SSLError("bad")))[2], "TLS certificate problem")

    def test_timeout(self):
        self.assertEqual(self.fetch_with(urllib.error.URLError(socket.timeout()))[2], "timed out")

    def test_refused(self):
        self.assertEqual(self.fetch_with(urllib.error.URLError(ConnectionRefusedError()))[2], "connection refused")

    def test_other_os_error(self):
        self.assertIn("could not connect", self.fetch_with(OSError("x"))[2])

    def test_head_then_get_when_head_is_refused(self):
        methods = []

        def opener_open(req, timeout=None):
            methods.append(req.get_method())
            if req.get_method() == "HEAD":
                raise urllib.error.HTTPError(req.full_url, 405, "no", {}, None)
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.status = 200
            resp.headers = {}
            return resp
        opener = mock.Mock()
        opener.open.side_effect = opener_open
        with mock.patch.object(doctor.urllib.request, "build_opener", return_value=opener):
            status, _, problem = doctor.fetch("https://a.test/")
        self.assertEqual((status, problem, methods), (200, None, ["HEAD", "GET"]))

    def test_no_credentials_are_ever_attached(self):
        seen = {}

        def opener_open(req, timeout=None):
            seen.update(req.headers)
            resp = mock.MagicMock()
            resp.__enter__.return_value = resp
            resp.status = 200
            resp.headers = {}
            return resp
        opener = mock.Mock()
        opener.open.side_effect = opener_open
        with mock.patch.object(doctor.urllib.request, "build_opener", return_value=opener):
            doctor.fetch("https://a.test/")
        self.assertEqual(set(k.lower() for k in seen), {"user-agent"})


class TestAddresses(unittest.TestCase):
    def test_every_recipe_lists_its_key_page_and_check_server(self):
        for slug, r in CAT.items():
            kinds = [w for w, _ in doctor.addresses(r)]
            self.assertIn("key page", kinds, slug)
            self.assertIn("check server", kinds if "check server" in kinds else ["check server"], slug)

    def test_the_query_string_is_never_visited(self):
        urls = [u for _, u in doctor.addresses(CAT["openweather"])]
        self.assertTrue(all("?" not in u for u in urls))

    def test_oauth_recipes_visit_the_token_server(self):
        kinds = [w for w, _ in doctor.addresses(CAT["paypal"])]
        self.assertIn("token server", kinds)

    def test_token_only_recipes_skip_the_unused_check_url(self):
        self.assertNotIn("check server", [w for w, _ in doctor.addresses(CAT["ebay"])])

    def test_all_addresses_are_https(self):
        for slug, r in CAT.items():
            for _, url in doctor.addresses(r):
                self.assertTrue(url.startswith("https://"), (slug, url))

    def test_no_address_contains_anything_key_like(self):
        for slug, r in CAT.items():
            for _, url in doctor.addresses(r):
                self.assertNotRegex(url, r"(?i)api[_-]?key=|token=|appid=")


class TestRunAndRender(unittest.TestCase):
    def test_shared_addresses_are_fetched_once(self):
        f = fake({})
        doctor.run({"a": CAT["stripe"], "b": dict(CAT["stripe"], service="b")}, f)
        self.assertEqual(len(f.calls), len(set(f.calls)))

    def test_only_filters(self):
        rows = doctor.run(CAT, fake({}), only=["stripe"])
        self.assertEqual({r["service"] for r in rows}, {"stripe"})

    def test_exit_code_is_1_only_for_rot(self):
        ok = doctor.run({"stripe": CAT["stripe"]}, fake({}))
        self.assertEqual(doctor.exit_code(ok), 0)
        bad = doctor.run({"stripe": CAT["stripe"]}, fake({CAT["stripe"]["key_url"]: (404, None, None)}))
        self.assertEqual(doctor.exit_code(bad), 1)
        warn = doctor.run({"stripe": CAT["stripe"]}, fake({CAT["stripe"]["key_url"]: (503, None, None)}))
        self.assertEqual(doctor.exit_code(warn), 0)

    def test_render_has_a_table_and_a_count(self):
        bad = doctor.run({"stripe": CAT["stripe"]}, fake({CAT["stripe"]["key_url"]: (404, None, None)}))
        text = doctor.render(bad)
        self.assertIn("ROT", text)
        self.assertRegex(text, r"\d+ addresses: \d+ ok, \d+ moved, \d+ to look at, 1 rotted")
        self.assertIn("was https://dashboard.stripe.com/apikeys", text)

    def test_unknown_service_is_exit_2(self):
        args = mock.Mock(service=["nope"], json=False, timeout=1)
        out = io.StringIO()
        self.assertEqual(doctor.cmd_doctor(args, CAT, out, fake({})), 2)

    def test_json_output_is_parseable_and_has_no_secret_fields(self):
        args = mock.Mock(service=["stripe"], json=True, timeout=1)
        out = io.StringIO()
        code = doctor.cmd_doctor(args, CAT, out, fake({}))
        data = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertFalse(data["rotted"])
        self.assertTrue(all("key" not in r for r in data["rows"]))

    def test_cli_command_exists_and_uses_the_network_function(self):
        out = io.StringIO()
        with mock.patch.object(doctor, "fetch", fake({})), \
                mock.patch("sys.stdout", out):
            code = cli_mod.main(["doctor-recipes", "stripe"])
        self.assertEqual(code, 0)
        self.assertIn("stripe", out.getvalue())

    def test_cli_exit_1_on_rot(self):
        out = io.StringIO()
        with mock.patch.object(doctor, "fetch", fake({CAT["stripe"]["docs"]: (404, None, None)})), \
                mock.patch("sys.stdout", out):
            self.assertEqual(cli_mod.main(["doctor-recipes", "stripe"]), 1)


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        path = os.path.join(_isolation.REPO, ".github", "workflows", "recipes.yml")
        if not os.path.exists(path):
            self.skipTest("the sdist has no .github")
        with open(path, encoding="utf-8") as f:
            self.text = f.read()

    def test_weekly_schedule(self):
        self.assertRegex(self.text, r'cron: "\d+ \d+ \* \* 1"')

    def test_top_level_permissions_are_read_only(self):
        top = self.text.split("jobs:")[0]
        self.assertRegex(top, r"permissions:\s*\n\s+contents: read\s*\n")
        self.assertNotIn("issues: write", top)

    def test_issues_write_only_in_the_job(self):
        self.assertEqual(self.text.count("issues: write"), 1)
        self.assertGreater(self.text.index("issues: write"), self.text.index("jobs:"))

    def test_one_issue_is_opened_or_edited(self):
        self.assertIn("gh issue edit", self.text)
        self.assertIn("gh issue create", self.text)
        self.assertIn("GH_TOKEN: ${{ github.token }}", self.text)

    def test_no_secrets_used(self):
        self.assertNotIn("secrets.", self.text)

    def test_contributing_and_pr_template_demand_docs_and_a_fake_key(self):
        for name, needles in (("CONTRIBUTING.md", ("Cite the vendor's docs", "FAKE key")),
                              (os.path.join(".github", "PULL_REQUEST_TEMPLATE.md"), ("docs page", "FAKE key"))):
            path = os.path.join(_isolation.REPO, name)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as f:
                text = f.read()
            for n in needles:
                self.assertIn(n, text, (name, n))


if __name__ == "__main__":
    unittest.main()
