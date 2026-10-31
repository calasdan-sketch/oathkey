"""0.7.0: agent-driven key capture (capture_key) with a fake clipboard and a fake vendor.

Nothing here touches the network or a real clipboard, and every key-like
value is assembled from pieces.
"""

import io
import json
import os
import threading
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import agent as agent_mod
from stuntkey import consent as consent_mod
from stuntkey import allowcmd
from stuntkey import capture as capture_mod
from stuntkey import clipboard as clip_mod
from stuntkey import hook as hook_mod
from stuntkey import mcp as mcp_mod
from stuntkey import recipes as recipes_mod
from stuntkey import validate as validate_mod

CATALOG = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
GH_KEY = "gh" + "p_" + "Qw3Er5Ty7Ui9Op1As3Df5Gh7Jk9Lz1Xc3Vb5"
GH_KEY2 = "gh" + "p_" + "Zx9Cv7Bn5Mq3We1Rt9Yu7Io5Pa3Sd1Fg9Hj7"
OTHER = "zz" + "-" + "Pq8Wo7Ei6Ru5Ty4Ui3Op2Al1Sk9Dj8Fh7Gg6"


class FakeClipboard:
    def __init__(self, value=""):
        self.value = value
        self.clears = 0
        self.reads = 0
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            self.reads += 1
            return self.value

    def clear(self):
        with self.lock:
            self.value = ""
            self.clears += 1

    def copy(self, value):                      # the vendor's Copy button
        with self.lock:
            self.value = value

    def backend(self):
        return self.get, self.clear


class MemorySecret:
    """A secret store that lives in memory (no keychain, no DPAPI, no file)."""
    kind = "memory"
    advisory = False

    def __init__(self):
        self.secret = None

    def load(self):
        return self.secret

    def save(self, secret):
        self.secret = secret


TERMINAL = ("stored", "failed", "timeout", "cancelled")


def until(mgr, states=TERMINAL, limit=20.0):
    """Ask for the status until it is one of `states` (a condition with a
    deadline, never a fixed sleep)."""
    end = time.monotonic() + limit
    out = mgr.status(0)
    while out.get("state") not in states and time.monotonic() < end:
        out = mgr.status(0.2)
    return out


def wait_for(condition, limit=20.0):
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.005)
    return condition()


class Vendor:
    def __init__(self, answer=None, error=None):
        self.answer = validate_mod.Result("valid") if answer is None else answer
        self.error = error
        self.seen = []

    def __call__(self, spec, key, timeout=10.0):
        self.seen.append(key)
        if self.error:
            raise self.error
        return self.answer


class Base(unittest.TestCase):
    def setUp(self):
        self.proj = _isolation.mktemp()
        self.consent = os.path.join(_isolation.mktemp(), "consent.json")
        self.clip = FakeClipboard()
        self.vendor = Vendor()
        self.history = None
        self.recorded = []
        self.secret = MemorySecret()
        self.mgrs = []

    def manager(self, **kw):
        defaults = dict(backend=self.clip.backend, validate_fn=self.vendor,
                        history_fn=lambda: self.history, poll=0.002,
                        consent_file=self.consent, secret_store=self.secret,
                        timeout_limits=(0.05, 180), clear_wait=0.05,
                        window_available=lambda: False, env_problem=lambda: None,
                        record_fn=lambda *a, **k: self.recorded.append(a))
        defaults.update(kw)
        mgr = capture_mod.Manager(**defaults)
        self.mgrs.append(mgr)
        self.addCleanup(mgr.cancel)
        return mgr

    def allow(self, service="github", history_ok=False):
        consent_mod.grant(self.proj, service, history_ok, self.consent, None, self.secret)

    def session_grant(self, mgr, service="github", project=None):
        """What a 'yes' in the permission window leaves in the server's memory."""
        root = os.path.realpath(project or self.proj)
        mgr._session[(consent_mod.project_key(root), service)] = {
            "project": root, "service": service, "clipboard_history_ok": False, "via": "window"}

    def start(self, mgr, service="github", **kw):
        return mgr.start(service, CATALOG[service], self.proj, **kw)

    def env_text(self):
        try:
            with open(os.path.join(self.proj, ".env"), encoding="utf-8") as f:
                return f.read()
        except OSError:
            return ""

    def assertNoKey(self, *things):
        text = json.dumps(things, default=str)
        for secret in (GH_KEY, GH_KEY2, OTHER):
            self.assertNotIn(secret, text)
            self.assertNotIn(secret[:12], text)


class TestConsent(Base):
    def test_without_the_persons_yes_nothing_is_armed_or_read(self):
        mgr = self.manager()
        out = self.start(mgr)
        self.assertEqual(out["state"], "consent_needed")
        self.assertIn("stuntkey allow-agent github", out["message"])
        self.assertEqual(self.clip.reads, 0)

    def test_a_grant_is_for_one_project_and_one_service(self):
        self.allow("github")
        mgr = self.manager()
        other = _isolation.mktemp()
        self.assertEqual(mgr.start("github", CATALOG["github"], other)["state"], "consent_needed")
        self.assertEqual(self.start(mgr, "stripe")["state"], "consent_needed")

    def test_revoke_takes_it_back(self):
        self.allow()
        self.assertEqual(consent_mod.revoke(self.proj, "github", self.consent, self.secret), 1)
        self.assertEqual(self.start(self.manager())["state"], "consent_needed")

    def test_the_grant_is_not_kept_in_the_project(self):
        self.allow()
        self.assertFalse(os.path.exists(os.path.join(self.proj, "stuntkey.json")))
        self.assertTrue(os.path.exists(self.consent))

    def test_a_recipe_of_your_own_is_refused(self):
        self.allow()
        mine = dict(CATALOG["github"], _builtin=False)
        out = self.manager().start("github", mine, self.proj)
        self.assertEqual(out["state"], "refused")
        self.assertEqual(self.clip.reads, 0)


class TestCapture(Base):
    def test_the_whole_flow_stores_and_empties_and_never_shows_the_key(self):
        self.allow()
        mgr = self.manager()
        armed = self.start(mgr)
        self.assertEqual(armed["state"], "waiting")
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "stored", done)
        self.assertEqual(done["env_vars"], ["GITHUB_TOKEN"])
        self.assertIn("GITHUB_TOKEN=" + GH_KEY, self.env_text())
        self.assertEqual(self.clip.value, "")
        self.assertGreaterEqual(self.clip.clears, 1)
        self.assertEqual(self.vendor.seen, [GH_KEY])
        self.assertIn("key_length", done)
        self.assertNoKey(armed, done)
        self.assertEqual(len(self.recorded), 1)

    def test_what_was_on_the_clipboard_before_is_ignored_and_wiped(self):
        self.allow()
        self.clip.copy(GH_KEY)                  # an old copy of a real-looking key
        mgr = self.manager()
        self.start(mgr, timeout=0.3)
        done = until(mgr)
        self.assertEqual(done["state"], "timeout")
        self.assertEqual(self.vendor.seen, [])
        self.assertEqual(self.env_text(), "")
        self.assertEqual(self.clip.value, "")   # wiped, not left lying around

    def test_copying_the_same_key_again_after_the_wipe_counts(self):
        self.allow()
        self.clip.copy(GH_KEY)
        mgr = self.manager()
        self.start(mgr, timeout=20)
        self.clip.copy(GH_KEY)                  # the Copy button, same text
        self.assertEqual(until(mgr)["state"], "stored")

    def test_a_key_of_another_service_is_rejected(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=20)
        self.clip.copy(OTHER)
        self.assertTrue(wait_for(lambda: mgr.status(0).get("ignored_clipboard_changes", 0) >= 1))
        mid = mgr.status(0)
        self.assertEqual(mid["state"], "waiting")
        self.assertEqual(self.vendor.seen, [])
        self.clip.copy(GH_KEY)
        self.assertEqual(until(mgr)["state"], "stored")
        self.assertNotIn(OTHER, self.env_text())

    def test_timeout_saves_nothing(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=0.2)
        done = until(mgr)
        self.assertEqual(done["state"], "timeout")
        self.assertIn("2FA", done["message"])
        self.assertEqual(self.env_text(), "")

    def test_the_vendor_rejecting_it_stores_nothing_and_empties_the_clipboard(self):
        self.allow()
        self.vendor.answer = validate_mod.Result("invalid")
        mgr = self.manager()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "failed")
        self.assertEqual(self.env_text(), "")
        self.assertEqual(self.clip.value, "")
        self.assertNoKey(done)

    def test_a_vendor_error_that_echoes_the_key_is_scrubbed(self):
        self.allow()
        self.vendor.error = validate_mod.ValidationError("boom " + GH_KEY + " boom")
        mgr = self.manager()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "failed")
        self.assertNoKey(done)
        self.assertEqual(self.env_text(), "")

    def test_a_limited_key_is_kept_with_the_note(self):
        self.allow()
        self.vendor.answer = validate_mod.Result("limited", "this kind of token may not read the profile")
        mgr = self.manager()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "stored")
        self.assertIn("may not read", done["vendor_note"])

    def test_a_store_failure_keeps_nothing_and_says_so_without_the_key(self):
        self.allow()

        def broken(recipe, env_file, store):
            def store_fn(var, key):
                raise OSError(13, "Permission denied (" + key + ")")
            return store_fn
        mgr = self.manager(store_factory=broken)
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "failed")
        self.assertIn("NOT be saved", done["message"])
        self.assertNoKey(done)

    def test_two_value_recipes_collect_each_in_order(self):
        recipe = {"service": "duo", "display": "Duo", "key_url": "https://duo.test/keys",
                  "env_var": "DUO_ID", "steps": ["x"], "_builtin": True,
                  "fields": [{"name": "app", "env_var": "DUO_ID", "label": "App ID",
                              "accept": "^gh" + "p_"},
                             {"name": "secret", "env_var": "DUO_SECRET", "label": "Secret",
                              "accept": "^zz" + "-"}],
                  "validate": {"method": "GET", "url": "https://duo.test/me",
                               "auth": {"type": "basic"}, "expect": [200]}}
        consent_mod.grant(self.proj, "duo", False, self.consent, None, self.secret)
        mgr = self.manager()
        out = mgr.start("duo", recipe, self.proj, timeout=20)
        self.assertEqual(out["state"], "waiting")
        self.clip.copy(GH_KEY)
        self.assertTrue(wait_for(lambda: self.clip.value == ""))      # the first one was taken
        self.assertEqual(mgr.status(0)["state"], "waiting")
        self.clip.copy(OTHER)
        done = until(mgr)
        self.assertEqual(done["state"], "stored", done)
        text = self.env_text()
        self.assertIn("DUO_ID=" + GH_KEY, text)
        self.assertIn("DUO_SECRET=" + OTHER, text)
        self.assertEqual(self.vendor.seen, [{"app": GH_KEY, "secret": OTHER}])

    def test_an_existing_key_is_not_replaced_unless_asked(self):
        self.allow()
        with open(os.path.join(self.proj, ".env"), "w") as f:
            f.write("GITHUB_TOKEN=already-there-12345\n")
        mgr = self.manager()
        self.assertEqual(self.start(mgr)["state"], "already_stored")
        # replacing needs the person's yes in a window; none here -> refused
        self.assertEqual(self.start(mgr, replace=True)["state"], "refused")
        asked = []
        mgr2 = self.manager(window_available=lambda: True,
                            ask_person=lambda title, text: asked.append(text) or True)
        self.session_grant(mgr2)
        self.assertEqual(self.start(mgr2, replace=True)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr2.status(0)["state"] != "consent_pending"))
        self.assertEqual(mgr2.status(0)["state"], "replace_granted")
        self.assertIn("REPLACE", asked[0])
        self.assertEqual(self.start(mgr2, replace=True)["state"], "waiting")


class TestLimits(Base):
    def test_only_one_capture_at_a_time_and_cancel_frees_it(self):
        self.allow()
        mgr = self.manager()
        self.assertEqual(self.start(mgr, timeout=30)["state"], "waiting")
        self.assertEqual(self.start(mgr)["state"], "busy")
        self.assertEqual(mgr.cancel()["state"], "cancelled")
        self.assertEqual(self.start(mgr, timeout=30)["state"], "waiting")
        mgr.cancel()

    def test_starts_are_rate_limited(self):
        self.allow()
        mgr = self.manager(starts_per_hour=2)
        for _ in range(2):
            self.assertEqual(self.start(mgr, timeout=30)["state"], "waiting")
            mgr.cancel()
        out = self.start(mgr)
        self.assertEqual(out["state"], "refused")
        self.assertIn("Too many", out["message"])

    def test_the_time_limit_is_clamped(self):
        self.allow()
        mgr = self.manager(timeout_limits=(10, 180))
        self.assertEqual(self.start(mgr, timeout=99999)["timeout_seconds"], 180)
        mgr.cancel()
        self.assertEqual(self.start(mgr, timeout=1)["timeout_seconds"], 10)
        mgr.cancel()

    def test_status_with_nothing_started_is_idle(self):
        self.assertEqual(self.manager().status(0)["state"], "idle")


class TestClipboardHistoryAndAvailability(Base):
    def test_history_on_refuses_without_the_acceptance_and_reads_nothing(self):
        self.allow()
        self.history = "Windows clipboard history is ON."
        out = self.start(self.manager())
        self.assertEqual(out["state"], "refused")
        self.assertTrue(out["clipboard_history"])
        self.assertIn("allow-agent github --allow-clipboard-history", out["message"])
        self.assertEqual(self.clip.reads, 0)

    def test_history_on_with_the_acceptance_goes_ahead_and_says_so(self):
        self.allow(history_ok=True)
        self.history = "Windows clipboard history is ON."
        mgr = self.manager()
        out = self.start(mgr)
        self.assertEqual(out["state"], "waiting")
        self.assertIn("history", out["clipboard_history_warning"])
        mgr.cancel()

    def test_no_clipboard_means_unavailable_with_the_fallback(self):
        self.allow()

        def none():
            raise clip_mod.Unavailable("no tool")
        out = self.start(self.manager(backend=none))
        self.assertEqual(out["state"], "unavailable")
        self.assertIn("stuntkey connect github", out["message"])


class TestThroughMcp(Base):
    def call(self, args):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "capture_key", "arguments": args}},
                           CATALOG, cwd=self.proj)
        return r["result"]["content"][0]["text"], r["result"]

    def setUp(self):
        super().setUp()
        self.mgr = self.manager()
        capture_mod.set_manager(self.mgr)
        self.addCleanup(capture_mod.set_manager, None)

    def test_the_tool_is_listed(self):
        r = mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, CATALOG)
        self.assertIn("capture_key", {t["name"] for t in r["result"]["tools"]})

    def test_start_then_status_never_carries_the_key(self):
        self.allow()
        text, _ = self.call({"service": "github"})
        start = json.loads(text)
        self.assertEqual(start["state"], "waiting")
        self.assertIn("rules", start)
        self.assertIn("browser", start)
        self.clip.copy(GH_KEY)
        text2, _ = self.call({"action": "status", "wait_seconds": 5})
        if json.loads(text2)["state"] != "stored":
            self.assertTrue(wait_for(lambda: self.mgr.status(0)["state"] == "stored"))
            text2, _ = self.call({"action": "status", "wait_seconds": 0})
        self.assertEqual(json.loads(text2)["state"], "stored")
        self.assertNoKey(text, text2)
        self.assertNotIn(GH_KEY, text + text2)

    def test_consent_needed_through_the_tool(self):
        text, _ = self.call({"service": "github"})
        self.assertEqual(json.loads(text)["state"], "consent_needed")

    def test_unknown_service_and_bad_action(self):
        text, result = self.call({"service": "nope-nope"})
        self.assertTrue(result.get("isError"))
        text, result = self.call({"service": "github", "action": "explode"})
        self.assertTrue(result.get("isError"))

    def test_request_connect_carries_browser_steps_and_rules(self):
        r = agent_mod.request_connect("github", CATALOG, cwd=self.proj)
        self.assertIn("capture_key", r["instructions"])
        self.assertTrue(r["browser"]["steps"])
        self.assertTrue(any("Never enter a password" in x for x in r["rules"]))
        self.assertTrue(any("Never look at the key" in x for x in r["rules"]))
        self.assertTrue(any("short expiry" in x for x in r["rules"]))
        self.assertIn("stuntkey connect github", r["instructions"])     # the fallback


class TestAllowAgentCommand(Base):
    def run_cmd(self, **opts):
        args = type("A", (), dict(service="github", revoke=False, list=False,
                                   allow_clipboard_history=False, **opts))()
        return args

    def go(self, args, answer="yes", terminal=True):
        out = io.StringIO()
        code = allowcmd.cmd_allow_agent(args, CATALOG, ask=lambda p: answer,
                                        terminal=lambda: terminal, out=out,
                                        consent_file=self.consent, cwd=self.proj, store=self.secret)
        return code, out.getvalue()

    def test_without_a_terminal_nothing_is_granted(self):
        code, text = self.go(self.run_cmd(), terminal=False)
        self.assertEqual(code, 2)
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_anything_but_yes_grants_nothing(self):
        for answer in ("", "y", "ok"):
            code, _ = self.go(self.run_cmd(), answer=answer)
            self.assertEqual(code, 1)
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_yes_grants_and_list_and_revoke_work(self):
        code, text = self.go(self.run_cmd())
        self.assertEqual(code, 0)
        self.assertIn("EMPTIES", text)
        self.assertIsNotNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))
        listing = self.go(type("A", (), dict(service=None, revoke=False, list=True,
                                             allow_clipboard_history=False))())[1]
        self.assertIn("github", listing)
        code, text = self.go(type("A", (), dict(service="github", revoke=True, list=False,
                                                allow_clipboard_history=False))())
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_history_acceptance_is_recorded(self):
        args = type("A", (), dict(service="github", revoke=False, list=False,
                                   allow_clipboard_history=True))()
        self.go(args)
        self.assertTrue(consent_mod.consent_for(self.proj, "github", self.consent, self.secret)["clipboard_history_ok"])

    def test_only_builtin_services(self):
        args = type("A", (), dict(service="not-a-service", revoke=False, list=False,
                                   allow_clipboard_history=False))()
        self.assertEqual(self.go(args)[0], 2)


class TestHookRefusesAnAgentGrantingItself(unittest.TestCase):
    def denied(self, command):
        status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse",
                                                 "tool_name": "Bash",
                                                 "tool_input": {"command": command}}))
        return bool(out)

    def test_allow_agent_is_refused(self):
        for cmd in ("stuntkey allow-agent github",
                    "stuntkey allow-agent github --allow-clipboard-history",
                    "python -m stuntkey allow-agent github",
                    "cd /x && stuntkey.exe allow-agent github"):
            self.assertTrue(self.denied(cmd), cmd)

    def test_the_consent_file_cannot_be_read_or_edited(self):
        self.assertTrue(self.denied("cat ~/.stuntkey/agent-consent.json"))

    def test_ordinary_commands_stay_allowed(self):
        self.assertFalse(self.denied("stuntkey list"))


if __name__ == "__main__":
    unittest.main()
