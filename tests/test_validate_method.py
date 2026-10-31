"""A validation call only reads: GET or HEAD, nothing else.

Panel finding (SEA-5): validate.method was unrestricted, so a user recipe
(one somebody sent you, say) could make `stuntkey connect` send DELETE -
or POST, PUT - with the real key to an endpoint on the key's own domain,
where the cross-domain prompt never fires. All 29 shipped recipes use GET.
"""

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import recipes as recipes_mod
from stuntkey import validate as validate_mod


def recipe(method="GET", **over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"],
         "validate": {"method": method, "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


class Recorder(BaseHTTPRequestHandler):
    seen = []

    def _answer(self):
        Recorder.seen.append((self.command, self.headers.get("Authorization")))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD = do_DELETE = do_POST = do_PUT = do_PATCH = _answer

    def log_message(self, *a):
        pass


class LocalServer:
    """A fake API on 127.0.0.1 that records every request it gets."""

    def __enter__(self):
        Recorder.seen = []
        self.srv = HTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/me"
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()

    def spec(self, method):
        return {"method": method, "url": self.url, "auth": {"type": "bearer"},
                "expect": [200]}


class TestRecipesMayOnlyRead(unittest.TestCase):
    def test_get_and_head_are_accepted_in_any_case(self):
        for method in ("GET", "get", "Get", "HEAD", "head"):
            with self.subTest(method=method):
                recipes_mod.validate_recipe(recipe(method))

    def test_anything_that_writes_is_refused(self):
        for method in ("DELETE", "POST", "PUT", "PATCH", "OPTIONS", "TRACE",
                       "CONNECT", "PROPFIND", "", " GET", "GET ", "GET,DELETE",
                       None, 5, ["GET"]):
            with self.subTest(method=method):
                with self.assertRaises(recipes_mod.RecipeError) as cm:
                    recipes_mod.validate_recipe(recipe(method))
                text = str(cm.exception)
                self.assertIn("GET or HEAD", text)
                self.assertIn("validate.method", text)
                self.assertTrue(text.isprintable(), ascii(text))

    def test_every_shipped_recipe_reads(self):
        shipped = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        self.assertTrue(shipped)
        for slug, data in shipped.items():
            if slug == "aws":       # STS GetCallerIdentity: documented as a POST, read-only
                self.assertEqual(data["validate"]["method"], "POST")
                continue
            self.assertIn(data["validate"]["method"].upper(), ("GET", "HEAD"), slug)

    def test_a_recipe_file_that_asks_for_delete_is_skipped_with_a_warning(self):
        import io
        import json
        from contextlib import redirect_stderr
        directory = _isolation.mktemp()
        with open(os.path.join(directory, "evil.json"), "w", encoding="utf-8") as f:
            json.dump(recipe("DELETE", service="evil"), f)
        with open(os.path.join(directory, "good.json"), "w", encoding="utf-8") as f:
            json.dump(recipe("GET", service="good"), f)
        err = io.StringIO()
        with redirect_stderr(err):
            loaded = recipes_mod.load_recipes(directory)
        self.assertEqual(sorted(loaded), ["good"])
        self.assertIn("GET or HEAD", err.getvalue())


class TestTheCallItselfIsAlsoGuarded(unittest.TestCase):
    """For a recipe that never went through the loader."""

    def test_a_write_method_is_never_sent(self):
        for method in ("DELETE", "POST", "PUT", "PATCH"):
            with self.subTest(method=method), LocalServer() as server:
                with self.assertRaises(validate_mod.ValidationError) as cm:
                    validate_mod.validate_key(server.spec(method), "k-123")
                self.assertIn("GET or HEAD", str(cm.exception))
                self.assertEqual(Recorder.seen, [])

    def test_get_and_head_still_work_end_to_end(self):
        for method in ("GET", "get", "HEAD"):
            with self.subTest(method=method), LocalServer() as server:
                self.assertTrue(validate_mod.validate_key(
                    server.spec(method), "k-123"))
                self.assertEqual(Recorder.seen, [(method.upper(), "Bearer k-123")])


class TestReadmeSaysSo(unittest.TestCase):
    def test_the_recipe_rules_mention_get_or_head(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        self.assertTrue("`GET` or `HEAD`" in flat,
                        "the README does not say a validation call is GET or HEAD")


if __name__ == "__main__":
    unittest.main()
