"""Test-rigour seat: the safety claims nothing else measures.

Each class names the published claim it checks. These are written to MEASURE
the product, not to agree with it: where one fails, the product (or the claim)
is wrong, and the test is left failing on purpose.

What the rest of the suite already covers well, and this file deliberately
does not repeat: route policy, the day cap across processes, STOP/resume as a
pair, the token meter (tests/test_wave1_broker.py), in-place edits and removed
lines in the chain (tests/test_broker.py), path and method-override hardening
(tests/test_hardening.py).

The gap this file fills is that the cap and kill-switch tests assert only that
a BrokerError was RAISED. Every one of those refusals says "so no call was
made" to the person reading it. Nothing measured that. These do.
"""
import json
import os
import unittest

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import broker, caps, recipes

CATALOG = recipes.load_recipes()
KEY = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # built at run time
RECIPE = CATALOG["github"]
VALUES = {"GITHUB_TOKEN": KEY}
PUBLIC = lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))]


class Spy:
    """A sender that records whether the request ever left the broker."""

    def __init__(self):
        self.sent = []

    def __call__(self, req, ip, timeout):
        self.sent.append(getattr(req, "full_url", "?"))
        return 200, {"content-type": "application/json"}, b"{}"


def new_log(name="audit.log"):
    return broker.AuditLog(os.path.join(_isolation.mktemp(), name))


def entries(log):
    with open(log.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---- claim: "per-key spend caps with a kill switch ... so no call was made" ------

class ARefusalReallyMeansNothingWentOut(unittest.TestCase):
    """tests/test_wave1_broker.py proves these refusals raise. It never checks
    that the HTTP request was not made, which is the only thing the person is
    actually promised. A cap that charges you and then complains is not a cap."""

    def setUp(self):
        self.home = _isolation.mktemp()
        self.spy = Spy()

    def attempt(self):
        pol = broker.Policy(home=self.home, project_dir=self.home)
        with self.assertRaises(broker.BrokerError) as caught:
            broker.call(RECIPE, VALUES, "GET", "/user", policy=pol,
                        send=self.spy, resolver=PUBLIC)
        return caught.exception

    def set_caps(self, **limits):
        with open(caps.caps_path(self.home), "w", encoding="utf-8") as f:
            json.dump({"github": limits}, f)

    def test_a_session_cap_refusal_sends_no_request(self):
        self.set_caps(calls_session=0)
        self.assertIn("cap", str(self.attempt()))
        self.assertEqual(self.spy.sent, [], "the cap was reported as reached "
                                            "AFTER the request was sent")

    def test_a_day_cap_refusal_sends_no_request(self):
        self.set_caps(calls_day=0)
        self.assertIn("cap", str(self.attempt()))
        self.assertEqual(self.spy.sent, [])

    def test_the_stop_switch_sends_no_request(self):
        caps.cmd_stop(self.home)
        self.assertIn("stuntkey stop", str(self.attempt()))
        self.assertEqual(self.spy.sent, [], "`stuntkey stop` did not stop the "
                                            "request from going out")

    def test_a_damaged_caps_file_sends_no_request(self):
        with open(caps.caps_path(self.home), "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIn("caps.json", str(self.attempt()))
        self.assertEqual(self.spy.sent, [])

    def test_a_damaged_usage_record_sends_no_request(self):
        self.set_caps(calls_day=5)
        with open(caps.usage_path(self.home, "github"), "w", encoding="utf-8") as f:
            f.write("}{")
        self.assertIn("usage", str(self.attempt()))
        self.assertEqual(self.spy.sent, [])

    def test_a_stop_marker_that_is_not_a_plain_file_still_stops(self):
        """`stop` is a kill switch, so its presence must be enough. A folder
        (or a dangling link, which is the same lexists() question) must not be
        read as 'not stopped'."""
        os.makedirs(caps.stop_path(self.home))
        self.assertIn("stuntkey stop", str(self.attempt()))
        self.assertEqual(self.spy.sent, [])


# ---- claim: "every call goes to a hash-chained append-only log" -----------------

class TheChainCatchesTheRestOfTheAttacks(unittest.TestCase):
    """test_broker.py covers an edited line and a removed middle line. These are
    the attacks it does not: cutting the tail off (what the .head anchor exists
    for), replacing the log with a shorter chain that is internally perfect, and
    whether a log that was caught once can be made to look healthy again."""

    def _log(self, n=4):
        log = new_log()
        for i in range(n):
            log.write({"service": "t", "method": "GET", "host": "h",
                       "path": "/p", "status": 200, "bytes": 1,
                       "result": "ok", "ms": 1, "i": i})
        return log

    def test_cutting_the_last_entries_off_is_detected(self):
        log = self._log()
        self.assertEqual(log.verify(), (True, 4))
        with open(log.path, "rb") as f:
            lines = f.read().splitlines()
        with open(log.path, "wb") as f:                 # drop the last two
            f.write(b"\n".join(lines[:2]) + b"\n")
        self.assertFalse(log.verify()[0],
                         "the last two entries were cut off and verify() said "
                         "the log was clean")

    def test_a_rebuilt_shorter_chain_that_is_internally_valid_is_detected(self):
        """The interesting forgery: do not edit the log, delete it and write a
        fresh, perfectly-hashed one entry long. Only the anchor can catch this."""
        log = self._log(5)
        os.remove(log.path)
        broker.AuditLog(log.path).write({"service": "t", "result": "ok",
                                         "note": "forged"})
        ok, _n = broker.AuditLog(log.path).verify()
        self.assertFalse(ok, "a forged 1-entry chain replaced 5 real entries "
                             "and verified as clean")

    def test_once_a_problem_is_found_the_log_never_verifies_again(self):
        log = self._log(3)
        with open(log.path, "rb") as f:
            lines = f.read().splitlines()
        with open(log.path, "wb") as f:
            f.write(b"\n".join(lines[1:]) + b"\n")      # drop the first entry
        self.assertFalse(log.verify()[0])
        log.write({"service": "t", "result": "ok"})     # later, honest writes
        log.write({"service": "t", "result": "ok"})
        self.assertFalse(log.verify()[0],
                         "later writes healed a log that had been tampered with")
        self.assertIsNotNone(log.broken_reason())

    def test_the_problem_is_recorded_in_the_log_itself(self):
        log = self._log(2)
        with open(log.path, "ab") as f:
            f.write(b'{"service": "x", "hash": "00", "prev": "00"}\n')
        log.write({"service": "t", "result": "ok"})
        self.assertIn("LOG-PROBLEM-FOUND", [e.get("result") for e in entries(log)],
                      "the log was found damaged and did not say so in itself")


# ---- claim: "the key never appears in the audit log" ----------------------------

class TheLogMustNotHoldTheKey(unittest.TestCase):
    """broker.py's docstring: the log records "never the query string, body or
    headers". The path IS recorded, and it is recorded unscrubbed."""

    def test_a_key_in_the_path_is_not_written_to_the_log(self):
        log = new_log()
        broker.call(RECIPE, VALUES, "GET", "/user/" + KEY, policy=broker.Policy(),
                    audit=log, send=Spy(), resolver=PUBLIC)
        with open(log.path, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn(KEY, text,
                         "the key reached the audit log in plain text through "
                         "the request path: _log() scrubs the query string and "
                         "the body but passes the path through untouched")

    def test_a_key_in_the_query_string_is_not_written_to_the_log(self):
        log = new_log()
        broker.call(RECIPE, VALUES, "GET", "/user", query={"t": KEY},
                    policy=broker.Policy(), audit=log, send=Spy(),
                    resolver=PUBLIC)
        with open(log.path, encoding="utf-8") as f:
            self.assertNotIn(KEY, f.read())


# ---- claim: "the broker picks the host (from the recipe, never from the AI)" ----

class TheAICannotChooseWhoIsCalled(unittest.TestCase):
    def test_no_path_can_change_the_host(self):
        for path in ("/@evil.com/x", "/..@evil.com", "/x:443@evil.com",
                     "/evil.com", "/x%40evil.com"):
            try:
                host, url = broker.build_url(RECIPE, path, None)
            except broker.BrokerError:
                continue                        # refused outright is fine too
            self.assertEqual(host, "api.github.com", path)
            self.assertTrue(url.startswith("https://api.github.com/"), url)

    def test_a_recipe_aimed_at_this_machine_is_refused_end_to_end(self):
        loopback = dict(RECIPE, service="loop",
                        validate=dict(RECIPE["validate"],
                                      url="https://127.0.0.1/v1/x"))
        spy = Spy()
        with self.assertRaises(broker.BrokerError) as caught:
            broker.call(loopback, VALUES, "GET", "/v1/x",
                        policy=broker.Policy(), send=spy)
        self.assertIn("private or internal", str(caught.exception))
        self.assertEqual(spy.sent, [])

    def test_a_recipe_with_no_https_host_is_refused(self):
        for url in ("http://evil.com/v1", "file:///etc/passwd", "", "ftp://x/"):
            with self.assertRaises(broker.BrokerError, msg=url):
                broker.allowed_host({"service": "x", "validate": {"url": url}})


# ---- claim: "the key never appears in an error message" -------------------------

class NoRefusalCarriesTheKey(unittest.TestCase):
    """test_broker.test_network_error_has_no_key proves this for one path by
    raising a clean BrokerError itself: the test supplies the very message it
    then checks. This sweeps every refusal the broker can actually produce."""

    HOSTILE = (
        ("GET", "/a/../../etc", None, None),
        ("GET", "/user", {"_method": "DELETE"}, None),
        ("GET", "/a//b", None, None),
        ("GET", "/x%00", None, None),
        ("GET", "/x;jsessionid=1", None, None),
        ("TRACE", "/user", None, None),
        ("CONNECT", "/user", None, None),
        ("GET", "/user", None, {"a": 1}),
        ("POST", "/gists", None, {"a": 1}),
        ("POST", "/gists", None, {"a": "z" * 500}),
        ("GET", "/user", {"q": "z" * 500}, None),
        ("GET", "/user", {str(i): i for i in range(60)}, None),
    )

    def test_no_refusal_message_anywhere_carries_the_key(self):
        for method, path, query, body in self.HOSTILE:
            with self.subTest(method=method, path=path[:24]):
                try:
                    broker.call(RECIPE, VALUES, method, path, query=query,
                                body=body, policy=broker.Policy(),
                                send=Spy(), resolver=PUBLIC)
                except broker.BrokerError as e:
                    self.assertNotIn(KEY, str(e))
                    self.assertNotIn(KEY[4:], str(e))

    def test_a_failed_sign_in_does_not_echo_the_client_secret(self):
        """The oauth2 branch calls validate._fetch_token directly and has to
        scrub the failure itself. Drive it with a failure that really does
        contain the secret, the way a chatty token endpoint would."""
        from stuntkey import validate as _v
        recipe = {"service": "oa",
                  "fields": [{"name": "id", "env_var": "OA_ID"},
                             {"name": "secret", "env_var": "OA_SECRET"}],
                  "validate": {"url": "https://api.github.com/v1/x",
                               "auth": {"type": "oauth2_client_credentials",
                                        "token_url": "https://api.github.com/token"}}}
        values = {"OA_ID": "client-id-1234", "OA_SECRET": KEY}

        def chatty(spec, creds, timeout, no_proxy=False):
            raise _v.ValidationError(f"bad client_secret={KEY}")

        original = _v._fetch_token
        _v._fetch_token = chatty
        try:
            with self.assertRaises(broker.BrokerError) as caught:
                broker.call(recipe, values, "GET", "/v1/x",
                            policy=broker.Policy(), send=Spy(), resolver=PUBLIC)
        finally:
            _v._fetch_token = original
        self.assertNotIn(KEY, str(caught.exception))


# ---- claim: "append-only ... change or remove any line and verify() says so" ----

@unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
class ALinkedLogIsNotALog(unittest.TestCase):
    """ledger.py refuses to read its index through a symlink
    (`if os.path.islink(index_path)`). AuditLog applies no such rule: it opens
    its path with O_CREAT|O_APPEND, which follows a link. An agent that can
    write one file in ~/.stuntkey can therefore point the log somewhere
    harmless before it does anything, and verify() still reports a clean log.

    Skipped on a Windows without the symlink privilege; it runs on CI's Linux
    and macOS jobs.
    """

    def setUp(self):
        d = _isolation.mktemp()
        self.target = os.path.join(d, "elsewhere.log")
        self.link = os.path.join(d, "audit.log")
        try:
            os.symlink(self.target, self.link)
        except (OSError, NotImplementedError) as e:
            self.skipTest(f"symbolic links are not available here ({e})")

    def test_the_log_refuses_to_write_through_a_symlink(self):
        log = broker.AuditLog(self.link)
        with self.assertRaises(broker.BrokerError,
                               msg="the log was written through a symlink, so "
                                   "an agent can redirect it and verify() "
                                   "still calls the log clean"):
            log.ready()
            log.write({"service": "t", "result": "ok"})


if __name__ == "__main__":
    unittest.main()
