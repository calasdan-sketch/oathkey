"""Cases found by the red-team review. Keys are built at run time."""
import base64
import json
import os
import tempfile
import threading
import unittest
from urllib.parse import quote

from stuntkey import approve, broker, clients, gitscan as scan, recipes

KEY = "wJalr" + "XUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"      # has / and +
RECIPE = recipes.load_recipes()["github"]
VALUES = {"GITHUB_TOKEN": KEY}
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))]


def go(body, ctype="application/json", extra=None, **kw):
    def send(req, ip, t):
        h = {"content-type": ctype}
        h.update(extra or {})
        return 200, h, body if isinstance(body, bytes) else body.encode()
    return broker.call(RECIPE, VALUES, "GET", "/user", send=send, resolver=PUBLIC, **kw)


class Disguises(unittest.TestCase):
    def check(self, text):
        out = go(text)["body"]
        self.assertNotIn(KEY, out)
        self.assertNotIn(KEY.replace("/", "\\/"), out)
        self.assertNotIn(quote(KEY, safe="").replace("%2F", "%2f").replace("%2B", "%2b"), out)
        self.assertNotIn("K7MDENG", out)
        return out

    def test_php_escaped_slash(self):
        self.check(json.dumps({"k": KEY}).replace("/", "\\/"))

    def test_lowercase_percent(self):
        self.check("k=" + quote(KEY, safe="").replace("%2F", "%2f").replace("%2B", "%2b"))

    def test_double_percent(self):
        self.check("k=" + quote(quote(KEY, safe=""), safe=""))

    def test_whitespace_split(self):
        self.check("k=" + KEY[:10] + "\n  " + KEY[10:])

    def test_html_entities(self):
        self.check("k=" + KEY.replace("+", "&#43;").replace("/", "&#47;"))

    def test_unicode_escapes(self):
        self.check("k=" + "".join("\\u%04x" % ord(c) for c in KEY))

    def test_mime_wrapped_base64(self):
        b = base64.b64encode(KEY.encode()).decode()
        self.check("\n".join(b[i:i + 20] for i in range(0, len(b), 20)))

    def test_key_straddling_clip_line(self):
        pad = "x" * (broker.MAX_BODY_OUT - 10)
        out = go(pad + KEY)["body"]
        self.assertNotIn(KEY[:8], out[-40:])

    def test_compressed_not_shown(self):
        out = go(b"\x1f\x8b\x08junk", extra={"content-encoding": "gzip"})
        self.assertIn("compressed", out["body"])


class Paths(unittest.TestCase):
    def test_more_hostile_paths(self):
        for bad in ("/a/..;/admin", "/%252e%252e/x", "/a//b", "/a%00b", "/a%2fb",
                    "/a/%2E%2e/x", "/x;jsessionid=1"):
            with self.assertRaises(broker.BrokerError, msg=bad):
                broker.check_path(bad)

    def test_method_override_query_refused(self):
        for k in ("method", "_method", "X-HTTP-Method-Override", "$httpMethod"):
            with self.assertRaises(broker.BrokerError, msg=k):
                broker.build_url(RECIPE, "/user", {k: "DELETE"})

    def test_credential_param_case_insensitive(self):
        r = dict(RECIPE, validate=dict(RECIPE["validate"],
                 auth={"type": "query", "param": "api_key"}))
        with self.assertRaises(broker.BrokerError):
            broker.build_url(r, "/x", {"API_KEY": "mine"})


class PolicyThreads(unittest.TestCase):
    def test_max_calls_is_exact_under_concurrency(self):
        p = broker.Policy(max_calls=10, max_per_minute=1000)
        ok = []

        def worker():
            try:
                p.count()
                ok.append(1)
            except broker.BrokerError:
                pass
        ts = [threading.Thread(target=worker) for _ in range(60)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(ok), 10)

    def test_three_refusals_stop_the_prompts(self):
        asked = []
        p = broker.Policy(approve=lambda s: asked.append(s) or False)
        for _ in range(3):
            self.assertFalse(p.ask("x"))
        with self.assertRaises(broker.BrokerError):
            p.ask("x")
        self.assertEqual(len(asked), 3)

    def test_flood_is_counted_before_prompting(self):
        asked = []
        p = broker.Policy(max_calls=2, approve=lambda s: asked.append(s) or True)
        for _ in range(2):
            broker.call(RECIPE, VALUES, "GET", "/user", policy=p,
                        send=lambda r, i, t: (200, {"content-type": "application/json"}, b"{}"),
                        resolver=PUBLIC)
        with self.assertRaises(broker.BrokerError):
            broker.call(RECIPE, VALUES, "POST", "/gists", body={}, policy=p,
                        send=lambda *a: (200, {}, b""), resolver=PUBLIC)
        self.assertEqual(len(asked), 1)         # only the first-use prompt


class Approval(unittest.TestCase):
    def test_summary_shows_query_and_body(self):
        s = broker.describe(RECIPE, "POST", "api.github.com",
                            "https://api.github.com/gists?force=true", b'{"files":1}')
        self.assertIn("'force'='true'", s)
        self.assertIn("11 bytes", s)

    def test_no_dialog_and_no_console_means_no(self):
        orig_d, orig_c = approve.dialog, approve.console
        approve.dialog = lambda s: None
        approve.console = lambda s: False
        try:
            self.assertFalse(approve.ask_person("x"))
        finally:
            approve.dialog, approve.console = orig_d, orig_c

    def test_dialog_answer_used(self):
        orig = approve.dialog
        approve.dialog = lambda s: True
        try:
            self.assertTrue(approve.ask_person("x"))
        finally:
            approve.dialog = orig

    def test_long_text_is_cut_with_a_note(self):
        self.assertIn("more characters", approve._safe("a" * 2000))


class AuditRobust(unittest.TestCase):
    def test_unwritable_log_stops_the_call(self):
        d = tempfile.mkdtemp()

        class Bad(broker.AuditLog):
            def ready(self):
                raise broker.BrokerError("cannot write log", 5)
        sent = []
        with self.assertRaises(broker.BrokerError):
            broker.call(RECIPE, VALUES, "GET", "/user",
                        audit=Bad(os.path.join(d, "a.log")),
                        send=lambda *a: sent.append(1) or (200, {}, b""),
                        resolver=PUBLIC)
        self.assertEqual(sent, [])

    def test_junk_line_does_not_reset_chain_head(self):
        log = broker.AuditLog(os.path.join(tempfile.mkdtemp(), "a.log"))
        log.write({"a": 1})
        head = log._last_hash()
        open(log.path, "ab").write(b"junk\n")
        self.assertEqual(log._last_hash(), head)

    def test_concurrent_writers_keep_chain(self):
        log = broker.AuditLog(os.path.join(tempfile.mkdtemp(), "a.log"))
        ts = [threading.Thread(target=lambda: log.write({"x": 1})) for _ in range(20)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(log.verify(), (True, 20))


class Entries(unittest.TestCase):
    def test_python_started_without_current_folder_on_path(self):
        flags = clients.server_entry()["args"]
        self.assertIn(flags[0], ("-P", "-I"))

    @unittest.skipIf(os.name == "nt", "mkfifo is posix")
    def test_fifo_is_not_opened(self):
        d = tempfile.mkdtemp()
        os.mkfifo(os.path.join(d, ".env"))
        self.assertEqual(scan.scan([d], include_home=False)["findings"], [])


if __name__ == "__main__":
    unittest.main()
