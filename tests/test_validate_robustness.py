"""A key that cannot travel in an HTTP header, and the origin test on redirects.

Panel finding (SEA-8):
- a key with a character outside Latin-1 (a curly quote copied along with it,
  an emoji) made `connect` end in a traceback (UnicodeEncodeError) after the
  paste; one with a line break made http.client raise "Invalid header value
  b'Bearer <the key>'", a message that holds the key. Now such a key is
  refused right after the paste, before any request, with a sentence that
  never repeats it - and `connect` lets the person paste again.
- dropping the scheme test from should_strip_auth survived every test: the
  credential must not follow a redirect from https to http even when host and
  port stay the same.
"""

import io
import os
import threading
import traceback
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import connect as connect_mod
from stuntkey import validate as validate_mod

CURLY = chr(0x2019)
EMOJI = chr(0x1F331)
GOOD = "sk-test-THIS-IS-A-FAKE-KEY-999"


class Recorder(BaseHTTPRequestHandler):
    seen = []

    def do_GET(self):
        Recorder.seen.append(self.headers.get("Authorization")
                             or self.headers.get("x-api-key"))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class LocalServer:
    """A fake API on 127.0.0.1 that records the credential of every request."""

    def __enter__(self):
        Recorder.seen = []
        self.srv = HTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=self.srv.serve_forever,
                         kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/me"
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()

    def spec(self, auth_type="bearer"):
        auth = {"type": auth_type}
        if auth_type == "header":
            auth["header"] = "x-api-key"
        if auth_type == "basic":
            auth["username"] = "api"
        return {"method": "GET", "url": self.url, "auth": auth, "expect": [200]}


class TestAKeyAHeaderCannotCarry(unittest.TestCase):
    BAD = {
        "a curly quote": "sk-" + CURLY + "test",
        "an emoji": "sk-" + EMOJI,
        "a line feed": "sk-test-0000\nX",
        "a carriage return": "sk-test\rX",
        "a NUL": "sk-\x00test",
        "an escape": "sk-\x1b[2Jtest",
        "a tab": "sk-\ttest",
    }

    def test_nothing_is_sent_and_the_message_never_holds_the_key(self):
        for auth_type in ("bearer", "header"):
            for label, key in self.BAD.items():
                with self.subTest(auth=auth_type, key=label), LocalServer() as srv:
                    with self.assertRaises(validate_mod.UnsendableKey) as cm:
                        validate_mod.validate_key(srv.spec(auth_type), key)
                    self.assertIsInstance(cm.exception, validate_mod.ValidationError)
                    self.assertEqual(Recorder.seen, [], "something was sent")
                    text = str(cm.exception)
                    self.assertTrue(text.isprintable(), ascii(text))
                    self.assertNotIn(key, text)
                    self.assertNotIn(key.strip(), text)
                    self.assertNotIn("Invalid header value", text)

    def test_the_reason_names_what_is_wrong(self):
        with LocalServer() as srv:
            with self.assertRaises(validate_mod.UnsendableKey) as cm:
                validate_mod.validate_key(srv.spec(), "sk-" + CURLY + "test")
            self.assertIn("Latin-1", str(cm.exception))
            with self.assertRaises(validate_mod.UnsendableKey) as cm:
                validate_mod.validate_key(srv.spec(), "sk-test\nX")
            self.assertIn("not printable", str(cm.exception))

    def test_basic_auth_carries_any_printable_key_but_still_not_a_line_break(self):
        with LocalServer() as srv:
            self.assertTrue(validate_mod.validate_key(srv.spec("basic"),
                                                      "sk-" + CURLY + "test"))
            self.assertEqual(len(Recorder.seen), 1)
            with self.assertRaises(validate_mod.UnsendableKey):
                validate_mod.validate_key(srv.spec("basic"), "sk-test\nX")
            self.assertEqual(len(Recorder.seen), 1)

    def test_ordinary_keys_still_validate(self):
        for key in (GOOD, "sk-ant-api03-abc_DEF-123", "caf" + chr(0xE9) + "-key",
                    "a" * 400):
            with self.subTest(key=key[:12]), LocalServer() as srv:
                self.assertTrue(validate_mod.validate_key(srv.spec(), key))
                self.assertEqual(len(Recorder.seen), 1)

    def test_a_value_error_from_the_http_stack_never_echoes_its_text(self):
        # the safety net: whatever else http.client may refuse to put in a header
        secret = "sk-SECRET-IN-THE-MESSAGE"

        def refuse(self, req, *a, **k):
            raise ValueError(f"Invalid header value b'Bearer {secret}'")

        with LocalServer() as srv, \
                mock.patch.object(urllib.request.OpenerDirector, "open", refuse):
            with self.assertRaises(validate_mod.ValidationError) as cm:
                validate_mod.validate_key(srv.spec(), secret)
            self.assertNotIn(secret, str(cm.exception))
            self.assertNotIn("Invalid header value", str(cm.exception))
            self.assertNotIn(secret, repr(cm.exception))
            # nor in the traceback of an uncaught one: the original error is
            # not chained to it
            shown = "".join(traceback.format_exception(
                type(cm.exception), cm.exception, cm.exception.__traceback__))
            self.assertNotIn(secret, shown)
            self.assertNotIn("Invalid header value", shown)


class TestConnectLetsYouPasteAgain(unittest.TestCase):
    def run_connect(self, keys):
        recipe = {"service": "acme", "display": "Acme", "env_var": "ACME_API_KEY",
                  "key_url": "https://acme.test/keys", "steps": ["Click"],
                  "validate": None}
        out = io.StringIO()
        pasted = iter(keys)
        with LocalServer() as srv:
            recipe["validate"] = srv.spec()
            recipe["validate"]["url"] = srv.url
            env = os.path.join(_isolation.mktemp(), ".env")
            code = connect_mod.connect(
                recipe, env_file=env, browser_open=lambda _u: None,
                prompt=lambda _t: next(pasted), out=out,
                confirm_in=lambda _t: "yes")
            seen = list(Recorder.seen)
        return code, out.getvalue(), seen, env

    def test_a_curly_quote_is_caught_before_anything_is_sent(self):
        code, text, seen, env = self.run_connect(["sk-" + CURLY + "test", GOOD])
        self.assertEqual(code, 0, text)
        self.assertEqual(seen, [f"Bearer {GOOD}"])         # the bad one never left
        self.assertIn("Latin-1", text)
        self.assertIn("Nothing was sent", text)
        self.assertNotIn("Traceback", text)
        self.assertNotIn("sk-" + CURLY, text)
        self.assertNotIn("couldn't reach", text)

    def test_three_bad_pastes_give_up_cleanly(self):
        code, text, seen, env = self.run_connect(["sk-" + EMOJI] * 3)
        self.assertEqual(code, 1)
        self.assertEqual(seen, [])
        self.assertIn("giving up", text)
        self.assertFalse(os.path.exists(env))

    def test_a_key_that_is_fine_for_the_env_file_but_not_for_a_header(self):
        # printable, so the .env check passes it; only the header cannot
        code, text, seen, env = self.run_connect(["sk-" + CURLY + "test"] * 3)
        self.assertEqual(code, 1)
        self.assertEqual(seen, [])


class TestTheSchemeCountsAsPartOfTheOrigin(unittest.TestCase):
    def test_should_strip_auth(self):
        strip = validate_mod.should_strip_auth
        # a change of scheme alone - same host, and the SAME port
        self.assertTrue(strip("https://acme.test:8080/a", "http://acme.test:8080/a"))
        self.assertTrue(strip("https://acme.test/a", "http://acme.test:443/a"))
        self.assertTrue(strip("http://acme.test:443/a", "https://acme.test/a"))
        self.assertTrue(strip("https://acme.test/a", "http://acme.test/a"))     # 443 -> 80
        # host and port
        self.assertTrue(strip("https://acme.test/a", "https://evil.test/a"))
        self.assertTrue(strip("https://acme.test/a", "https://acme.test:8443/a"))
        self.assertTrue(strip("https://acme.test:8443/a", "https://acme.test/a"))
        # the same origin, however it is spelled
        self.assertFalse(strip("https://acme.test/a", "https://acme.test/b?x=1"))
        self.assertFalse(strip("https://acme.test/a", "https://ACME.test:443/a"))
        self.assertFalse(strip("https://acme.test:8080/a", "https://acme.test:8080/b"))

    def test_the_handler_drops_the_header_on_a_scheme_change_alone(self):
        handler = validate_mod._CredentialScrubbingRedirectHandler("Authorization")
        req = urllib.request.Request("https://acme.test:8080/a",
                                     headers={"Authorization": "Bearer KKK"})
        new = handler.redirect_request(req, None, 302, "Found", {},
                                       "http://acme.test:8080/a")
        self.assertIsNotNone(new)
        self.assertEqual([n for n in list(new.headers) + list(new.unredirected_hdrs)
                          if n.lower() == "authorization"], [])
        self.assertEqual(handler.stripped_to, "http://acme.test:8080/a")

    def test_the_handler_keeps_it_inside_one_origin(self):
        handler = validate_mod._CredentialScrubbingRedirectHandler("Authorization")
        req = urllib.request.Request("https://acme.test/a",
                                     headers={"Authorization": "Bearer KKK"})
        new = handler.redirect_request(req, None, 302, "Found", {},
                                       "https://acme.test/b")
        self.assertEqual(new.get_header("Authorization"), "Bearer KKK")
        self.assertIsNone(handler.stripped_to)


class TestReadmeSaysSo(unittest.TestCase):
    def test_a_key_a_header_cannot_carry(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("cannot carry", "before any request"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
