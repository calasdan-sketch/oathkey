"""Public APIs directory tests: parse, search, CLI find, MCP tools.

No network in tests: parsing uses a fixture markdown sample, and the MCP
handler gets entries injected via pa_loader.
"""

import io
import json
import unittest

from contextlib import redirect_stdout

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)

from stuntkey import cli as cli_mod
from stuntkey import mcp as mcp_mod
from stuntkey import publicapis as pa_mod

FIXTURE_MD = """# Public APIs

### Weather
API | Description | Auth | HTTPS | CORS
|:---|:---|:---|:---|:---|
| [7Timer!](http://www.7timer.info/doc.php) | Weather forecast | No | Yes | Yes |
| [Weatherstack](https://weatherstack.com/) | Real-time weather | `apiKey` | Yes | Yes |

### Animals
API | Description | Auth | HTTPS | CORS
|:---|:---|:---|:---|:---|
| [Cat Facts](https://catfact.ninja/) | Random cat facts | No | Yes | Yes |
"""

ENTRIES = pa_mod.parse(FIXTURE_MD)


class TestParse(unittest.TestCase):
    def test_count(self):
        self.assertEqual(len(ENTRIES), 3)

    def test_fields(self):
        e = ENTRIES[0]
        self.assertEqual(e["name"], "7Timer!")
        self.assertEqual(e["category"], "Weather")
        self.assertEqual(e["auth"], "No")
        self.assertIn("7timer", e["url"])

    def test_backticked_auth(self):
        e = [x for x in ENTRIES if x["name"] == "Weatherstack"][0]
        self.assertEqual(e["auth"], "apiKey")

    def test_ignores_non_rows(self):
        self.assertEqual(pa_mod.parse("# nothing\n\nplain text\n"), [])


class TestSearch(unittest.TestCase):
    def test_keyword(self):
        hits = pa_mod.search(ENTRIES, "weather")
        self.assertEqual(len(hits), 2)

    def test_multi_word(self):
        hits = pa_mod.search(ENTRIES, "cat facts")
        self.assertEqual(hits[0]["name"], "Cat Facts")

    def test_auth_filter(self):
        hits = pa_mod.search(ENTRIES, "weather", auth="apiKey")
        self.assertEqual([h["name"] for h in hits], ["Weatherstack"])

    def test_category_filter(self):
        hits = pa_mod.search(ENTRIES, "facts", category="animals")
        self.assertEqual(len(hits), 1)

    def test_limit(self):
        hits = pa_mod.search(ENTRIES, "a", limit=1)
        self.assertEqual(len(hits), 1)

    def test_no_match(self):
        self.assertEqual(pa_mod.search(ENTRIES, "zzz-nope"), [])

    def test_find_by_name(self):
        self.assertEqual(pa_mod.find_by_name(ENTRIES, "cat facts")["name"],
                         "Cat Facts")
        self.assertIsNone(pa_mod.find_by_name(ENTRIES, "nope"))


class TestFindCLI(unittest.TestCase):
    def test_find(self):
        # monkeypatch fetch to avoid network
        orig = pa_mod.fetch
        pa_mod.fetch = lambda refresh=False: FIXTURE_MD
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_mod.main(["find", "weather"])
            out = buf.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("Weatherstack", out)
            self.assertIn("7Timer!", out)
        finally:
            pa_mod.fetch = orig

    def test_find_auth_filter(self):
        orig = pa_mod.fetch
        pa_mod.fetch = lambda refresh=False: FIXTURE_MD
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_mod.main(["find", "weather", "--auth", "No"])
            out = buf.getvalue()
            self.assertEqual(code, 0)
            self.assertIn("7Timer!", out)
            self.assertNotIn("Weatherstack", out)
        finally:
            pa_mod.fetch = orig

    def test_find_no_match(self):
        orig = pa_mod.fetch
        pa_mod.fetch = lambda refresh=False: FIXTURE_MD
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli_mod.main(["find", "zzz-nope"])
            self.assertEqual(code, 0)
            self.assertIn("no public APIs match", buf.getvalue())
        finally:
            pa_mod.fetch = orig


def _call(name, args):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}}
    resp = mcp_mod.handle(req, {}, pa_loader=lambda: ENTRIES)
    return json.loads(resp["result"]["content"][0]["text"])


class TestMCPTools(unittest.TestCase):
    def test_find_public_apis(self):
        hits = _call("find_public_apis", {"query": "weather"})
        self.assertEqual(len(hits), 2)
        self.assertTrue(all("url" in h for h in hits))

    def test_find_with_auth(self):
        hits = _call("find_public_apis",
                     {"query": "weather", "auth": "apiKey"})
        self.assertEqual([h["name"] for h in hits], ["Weatherstack"])

    def test_get_no_auth(self):
        d = _call("get_public_api", {"name": "Cat Facts"})
        self.assertEqual(d["name"], "Cat Facts")
        self.assertIn("No key needed", d["wiring"])

    def test_get_apikey(self):
        d = _call("get_public_api", {"name": "Weatherstack"})
        self.assertIn("stuntkey add", d["wiring"])
        self.assertIn("stuntkey connect", d["wiring"])

    def test_get_missing(self):
        resp = mcp_mod.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "get_public_api",
                       "arguments": {"name": "nope"}}},
            {}, pa_loader=lambda: ENTRIES)
        self.assertTrue(resp["result"].get("isError"))

    def test_offline_graceful(self):
        def boom():
            raise ConnectionError("down")
        resp = mcp_mod.handle(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "find_public_apis",
                       "arguments": {"query": "x"}}},
            {}, pa_loader=boom)
        self.assertTrue(resp["result"].get("isError"))


if __name__ == "__main__":
    unittest.main()
