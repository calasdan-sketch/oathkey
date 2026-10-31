"""0.7.1: the panel's findings, as tests. Fake clipboard, fake vendor, fake
window, fake secret store; every key-like value is built from pieces and every
wait is a condition with a deadline (no fixed sleeps)."""

import base64
import contextlib
import io
import json
import logging
import ntpath
import os
import stat
import sys
import threading
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
import test_v070_capture as base
from stuntkey import capture as capture_mod
from stuntkey import clipboard as clip_mod
from stuntkey import consent as consent_mod
from stuntkey import hook as hook_mod
from stuntkey import manifest as manifest_mod
from stuntkey import safeprompt
from stuntkey import store as store_mod
from stuntkey import validate as validate_mod

GH_KEY, OTHER, CATALOG = base.GH_KEY, base.OTHER, base.CATALOG
until, wait_for = base.until, base.wait_for


class TestSlowVendor(base.Base):
    def test_status_shows_validating_while_the_vendor_thinks_then_stored(self):
        self.allow()
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)

        def slow(spec, key, timeout=10.0):
            entered.set()
            gate.wait(20)
            return validate_mod.Result("valid")
        mgr = self.manager(validate_fn=slow)
        self.start(mgr, timeout=30)
        self.clip.copy(GH_KEY)
        self.assertTrue(entered.wait(20))
        mid = mgr.status(0)
        self.assertEqual(mid["state"], "validating")
        self.assertNotIn("stored", mid)
        gate.set()
        done = until(mgr)
        self.assertEqual(done["state"], "stored")
        self.assertIn("GITHUB_TOKEN=" + GH_KEY, self.env_text())

    def test_cancel_while_validating_stores_nothing(self):
        self.allow()
        gate, entered = threading.Event(), threading.Event()
        self.addCleanup(gate.set)

        def slow(spec, key, timeout=10.0):
            entered.set()
            gate.wait(20)
            return validate_mod.Result("valid")
        mgr = self.manager(validate_fn=slow)
        self.start(mgr, timeout=30)
        self.clip.copy(GH_KEY)
        self.assertTrue(entered.wait(20))
        threading.Timer(0.05, gate.set).start()
        out = mgr.cancel()
        self.assertIn(out["state"], ("cancelled", "validating"))
        self.assertEqual(until(mgr)["state"], "cancelled")
        self.assertEqual(self.env_text(), "")


class TestNothingLeaks(base.Base):
    """The key must reach no stdout, stderr, log record, ledger argument or result."""

    def run_scenario(self, validate_fn=None, copy=GH_KEY, timeout=30, store_factory=None):
        self.allow()
        out, err = io.StringIO(), io.StringIO()
        records = []

        class Catch(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage() + " " + repr(record.args))
        handler = Catch(level=logging.DEBUG)
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        results = []
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                kw = {}
                if validate_fn:
                    kw["validate_fn"] = validate_fn
                if store_factory:
                    kw["store_factory"] = store_factory
                mgr = self.manager(**kw)
                results.append(self.start(mgr, timeout=timeout))
                if copy is not None:
                    self.clip.copy(copy)
                    results.append(until(mgr))
                else:
                    results.append(until(mgr))
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        everything = json.dumps([results, out.getvalue(), err.getvalue(), records,
                                 [list(a) for a in self.recorded]], default=str)
        return results, everything

    def assertClean(self, text):
        for secret in (GH_KEY, base.GH_KEY2, OTHER):
            self.assertNotIn(secret, text)
            self.assertNotIn(base64.b64encode(secret.encode()).decode(), text)

    def test_stored(self):
        results, text = self.run_scenario()
        self.assertEqual(results[-1]["state"], "stored")
        self.assertClean(text)

    def test_the_vendor_says_no(self):
        results, text = self.run_scenario(lambda s, k, timeout=10.0: validate_mod.Result("invalid"))
        self.assertEqual(results[-1]["state"], "failed")
        self.assertClean(text)

    def test_the_vendor_error_holds_the_key_plain(self):
        def boom(spec, key, timeout=10.0):
            raise RuntimeError("server said no to " + key)
        results, text = self.run_scenario(boom)
        self.assertEqual(results[-1]["state"], "failed")
        self.assertClean(text)

    def test_the_vendor_error_holds_the_key_base64_or_urlencoded(self):
        def boom(spec, key, timeout=10.0):
            raise RuntimeError("basic " + base64.b64encode(key.encode()).decode()
                               + " / " + base64.urlsafe_b64encode(key.encode()).decode()
                               + " / token=" + key)
        results, text = self.run_scenario(boom)
        self.assertEqual(results[-1]["state"], "failed")
        self.assertClean(text)

    def test_the_store_error_holds_the_key(self):
        def broken(recipe, env_file, store):
            def store_fn(var, key):
                raise OSError(5, "no space (" + key + ")")
            return store_fn
        results, text = self.run_scenario(store_factory=broken)
        self.assertEqual(results[-1]["state"], "failed")
        self.assertClean(text)

    def test_timeout(self):
        results, text = self.run_scenario(copy=None, timeout=0.05)
        self.assertEqual(results[-1]["state"], "timeout")
        self.assertClean(text)

    def test_something_else_copied_is_never_echoed(self):
        results, text = self.run_scenario(copy=OTHER, timeout=0.1)
        self.assertEqual(results[-1]["state"], "timeout")
        self.assertClean(text)


class TestTheClipboardIsReallyEmptied(base.Base):
    def test_a_clear_that_silently_fails_is_not_reported_as_emptied(self):
        self.allow()

        class Stuck(base.FakeClipboard):
            def clear(self):                    # looks like it worked, did nothing
                with self.lock:
                    self.clears += 1
        self.clip = Stuck()
        mgr = self.manager(backend=self.clip.backend)
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["state"], "stored")
        self.assertIn("could NOT be emptied", done["clipboard_warning"])
        self.assertNotIn("The clipboard was emptied", done["message"])
        self.assertNoKey(done)

    def test_clear_verified_reports_the_truth(self):

        self.assertFalse(clip_mod.clear_verified(lambda: "still here", lambda: None, wait=0.02,
                                                 poll=0.001))
        self.assertTrue(clip_mod.clear_verified(lambda: "", lambda: None, wait=0.02))


class TestStaleAndLateCopies(base.Base):
    def test_a_copy_after_cancel_stores_nothing(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=30)
        self.assertEqual(mgr.cancel()["state"], "cancelled")
        self.clip.copy(GH_KEY)
        self.assertEqual(mgr.status(0)["state"], "cancelled")
        self.assertEqual(self.env_text(), "")
        self.assertEqual(self.vendor.seen, [])

    def test_a_copy_after_the_timeout_stores_nothing(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=0.05)
        self.assertEqual(until(mgr)["state"], "timeout")
        self.clip.copy(GH_KEY)
        self.assertEqual(mgr.status(0)["state"], "timeout")
        self.assertEqual(self.env_text(), "")
        self.assertEqual(self.vendor.seen, [])

    def test_a_copy_right_after_start_counts(self):
        self.allow()
        mgr = self.manager()
        self.start(mgr, timeout=30)
        self.clip.copy(GH_KEY)                 # no pause at all
        self.assertEqual(until(mgr)["state"], "stored")

    def test_the_same_value_twice_is_taken_once(self):
        self.allow()
        recipe = base_two_value()
        consent_mod.grant(self.proj, "duo", False, self.consent, None, self.secret)
        mgr = self.manager()
        mgr.start("duo", recipe, self.proj, timeout=30)
        self.clip.copy(GH_KEY)
        self.assertTrue(wait_for(lambda: self.clip.value == ""))
        self.clip.copy(GH_KEY)                 # the first value again: not the second field
        self.assertTrue(wait_for(lambda: mgr.status(0).get("state") == "waiting"
                                 and self.clip.value == GH_KEY))
        self.assertEqual(self.vendor.seen, [])
        self.assertEqual(self.env_text(), "")
        self.clip.copy(OTHER)
        self.assertEqual(until(mgr)["state"], "stored")


def base_two_value():
    return {"service": "duo", "display": "Duo", "key_url": "https://duo.test/keys",
            "env_var": "DUO_ID", "steps": ["x"], "_builtin": True,
            "fields": [{"name": "app", "env_var": "DUO_ID", "label": "App ID", "accept": "^gh" + "p_"},
                       {"name": "secret", "env_var": "DUO_SECRET", "label": "Secret",
                        "accept": "^zz" + "-"}],
            "validate": {"method": "GET", "url": "https://duo.test/me",
                         "auth": {"type": "basic"}, "expect": [200]}}


class TestMutationSurvivors(base.Base):
    def test_values_that_cannot_be_stored_safely(self):
        for bad in ("a\nb", "a'b", "a\\b", "a${b", "a\tb"):
            self.assertIsNotNone(store_mod.unsafe_reason(bad), repr(bad))
        for fine in ("a=b", "a#b", 'a"b'):
            self.assertIsNone(store_mod.unsafe_reason(fine), repr(fine))

    def test_the_key_shape_gate_refuses_whitespace_and_links(self):
        for bad in ("gh" + "p_abc def", "gh" + "p_abc\ndef", "https://x.test/" + "a" * 30, ""):
            self.assertFalse(clip_mod.looks_like(bad, "^gh" + "p_"), repr(bad))
        self.assertTrue(clip_mod.looks_like(GH_KEY, "^gh" + "p_"))

    def test_the_keychain_store_never_asks_the_person_anything(self):
        seen = {}

        def fake(recipe, env_file, out=None, interactive=None):
            seen["interactive"] = interactive
            return lambda var, key: "ok"
        from stuntkey import cli as cli_mod
        with mock.patch.object(cli_mod, "keychain_store", fake):
            capture_mod._default_store(CATALOG["github"], "x.env", "keychain")
        self.assertFalse(seen["interactive"]())

    def test_the_account_name_comes_from_the_vendor_not_the_clipboard(self):
        self.allow()
        result = validate_mod.Result("valid")
        result.identity = "octo-" + "cat"
        self.vendor.answer = result
        mgr = self.manager()
        self.start(mgr)
        self.clip.copy(GH_KEY)
        done = until(mgr)
        self.assertEqual(done["account"], "octo-cat")


class TestConsentIntegrity(base.Base):
    def read(self):
        with open(self.consent, encoding="utf-8") as f:
            return json.load(f)

    def write(self, text):
        with open(self.consent, "w", encoding="utf-8") as f:
            f.write(text)

    def test_every_corruption_fails_closed(self):
        self.allow()
        data = self.read()
        variants = {
            "empty": "", "garbage": "{{{", "list": "[]", "null": "null",
            "no mac": json.dumps({k: v for k, v in data.items() if k != "mac"}),
            "bad mac": json.dumps(dict(data, mac="0" * 64)),
            "old version": json.dumps(dict(data, version=1)),
            "grants not a list": json.dumps(dict(data, grants="x")),
            "deep": "[" * 100000,
        }
        for name, text in variants.items():
            self.write(text)
            self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret), name)
            out = self.start(self.manager())
            self.assertEqual(out["state"], "consent_needed", name)

    def test_an_edited_grant_is_forged(self):
        self.allow("github")
        data = self.read()
        data["grants"].append(dict(data["grants"][0], service="stripe"))     # hand-added
        self.write(json.dumps(data))
        grants, problem = consent_mod.read_grants(self.consent, self.secret)
        self.assertEqual((grants, problem), ([], "forged"))
        self.assertEqual(self.start(self.manager(), "stripe")["state"], "consent_needed")

    def test_a_lost_secret_means_no_consent(self):
        self.allow()
        self.secret.secret = None
        self.assertEqual(consent_mod.read_grants(self.consent, self.secret)[1], "no secret")
        self.assertEqual(self.start(self.manager())["state"], "consent_needed")

    def test_another_secret_means_no_consent(self):
        self.allow()
        other = base.MemorySecret()
        other.secret = b"x" * 32
        self.assertEqual(consent_mod.read_grants(self.consent, other)[1], "forged")

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_the_files_are_private(self):
        self.allow()
        self.assertEqual(stat.S_IMODE(os.stat(self.consent).st_mode), 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_the_advisory_secret_file_is_private(self):
        path = os.path.join(_isolation.mktemp(), "secret")
        consent_mod.FileSecret(path).save(b"s" * 32)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(consent_mod.FileSecret(path).load(), b"s" * 32)

    def test_a_corrupt_file_is_replaced_and_no_old_copy_is_left(self):
        self.write("{{{ old")
        with open(self.consent + ".bak", "w") as f:
            f.write("an old copy")
        self.allow()
        self.assertFalse(os.path.exists(self.consent + ".bak"))
        self.assertIsNotNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_consent_found_from_a_subdirectory(self):
        self.allow()
        sub = os.path.join(self.proj, "src", "deep")
        os.makedirs(sub)
        os.makedirs(os.path.join(self.proj, ".git"))      # the project's top
        out = self.manager().start("github", CATALOG["github"], sub, timeout=30)
        self.assertEqual(out["state"], "waiting")
        self.assertEqual(manifest_mod.project_root(sub), os.path.realpath(self.proj))

    def test_a_project_key_ignores_case_and_slashes_on_windows(self):
        with mock.patch.object(consent_mod.os, "path", ntpath):
            a = consent_mod.project_key("C:\\Proj")
            b = consent_mod.project_key("c:/proj")
            c = consent_mod.project_key("C:\\Proj2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)


class TestTheWindowRoute(base.Base):
    def window_manager(self, answer):
        asked = []

        def ask(title, text):
            asked.append((title, text))
            return answer
        mgr = self.manager(window_available=lambda: True, ask_person=ask)
        return mgr, asked

    def test_yes_in_the_window_records_the_consent_then_capture_starts(self):
        mgr, asked = self.window_manager(True)
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_granted"))
        # the window's yes lives in this server's memory only - nothing on disk
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))
        self.assertFalse(os.path.exists(self.consent))
        self.assertEqual(self.start(mgr, timeout=30)["state"], "waiting")
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.clip.reads, 1)    # only the snapshot, once armed

    def test_no_reads_the_clipboard_never_and_is_not_asked_again_at_once(self):
        mgr, asked = self.window_manager(False)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_denied"))
        self.assertEqual(self.start(mgr)["state"], "consent_denied")
        self.assertEqual(len(asked), 1)
        self.assertEqual(self.clip.reads, 0)
        self.assertIsNone(consent_mod.consent_for(self.proj, "github", self.consent, self.secret))

    def test_a_window_that_crashes_is_not_a_no_and_can_be_asked_again(self):
        def broken(title, text):
            raise RuntimeError("no display")
        mgr = self.manager(window_available=lambda: True, ask_person=broken)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_needed"))
        self.assertEqual(self.start(mgr)["state"], "consent_pending")

    def test_the_window_text_is_plain_and_names_project_and_service(self):
        mgr, asked = self.window_manager(False)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: asked))
        title, text = asked[0]
        self.assertIn("GitHub", text)
        self.assertIn(os.path.basename(os.path.realpath(self.proj)), text)
        self.assertNotIn(os.path.realpath(self.proj), text)         # the last folder name only
        self.assertNotIn(GH_KEY, text)

    def test_windows_are_rate_limited(self):
        mgr, asked = self.window_manager(False)
        clock = [1000.0]
        mgr.now = lambda: clock[0]
        for _ in range(capture_mod.DIALOGS_PER_HOUR):
            mgr.start("github", CATALOG["github"], self.proj)
            self.assertTrue(wait_for(lambda: mgr._job.done.is_set()))
            clock[0] += 700                         # past the 10-minute memory of a no
        out = mgr.start("github", CATALOG["github"], self.proj)
        self.assertEqual(out["state"], "refused")

    def test_a_terminal_only_grant_is_labelled_weaker(self):
        out = self.start(self.manager())
        self.assertIn("weaker", out["message"])


class TestHookVariants(unittest.TestCase):
    def denied(self, command, tool="Bash"):
        status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse",
                                                 "tool_name": tool,
                                                 "tool_input": {"command": command}}))
        return bool(out)

    def test_these_are_refused(self):
        for cmd in (
                "Get-Content .env", "gc .env", "type .env", "cat .env", "cat ./sub/.env.local",
                "c''at .env", 'cat ".e""nv"', "cat .e^nv", "cat $HOME/proj/.env",
                "cd sub && cat ../.env", "cat \"$PWD\"/.env",
                "python -m stuntkey allow-agent github", "py -m stuntkey allow-agent github",
                "stuntkey 'allow-agent' github", "stuntkey allow-\"agent\" github",
                "stuntkey.exe allow^-agent github", "stuntkey allow-agent $X",
                "pbpaste", "wl-paste", "xclip -o", "xclip -selection clipboard -o",
                "xsel -o", "xsel --output", "Get-Clipboard", "powershell -c Get-Clipboard",
                "pwsh -c \"[Windows.Forms.Clipboard]::GetText()\"",
                "python -c 'import pyperclip; pyperclip.paste()'",
                "cat ~/.stuntkey/agent-consent.json", "type %USERPROFILE%\\.stuntkey\\agent-consent.json",
        ):
            self.assertTrue(self.denied(cmd), cmd)

    def test_powershell_tool_and_other_tools_too(self):
        self.assertTrue(self.denied("Get-Clipboard", tool="PowerShell"))
        self.assertTrue(self.denied("Get-Content .env", tool="PowerShell"))

    def test_these_stay_allowed(self):
        for cmd in ("ls", "git status", "stuntkey list", "stuntkey connect github",
                    "cat README.md", "echo 'hello there'", "xclip -i file.txt",
                    "python -m pytest", "type notes.txt", "cat .env.example"):
            self.assertFalse(self.denied(cmd), cmd)


class TestWindowsPromptDrain(unittest.TestCase):
    def test_the_windows_drain_reads_until_the_keyboard_buffer_is_empty(self):
        pending = list("rest of a paste")
        taken = []
        fake = types.SimpleNamespace(kbhit=lambda: bool(pending),
                                     getwch=lambda: taken.append(pending.pop(0)) or "x")
        with mock.patch.dict(sys.modules, {"msvcrt": fake, "termios": None}):
            safeprompt._drain_input()
        self.assertEqual(pending, [])
        self.assertEqual(len(taken), len("rest of a paste"))

    def test_a_drain_that_fails_does_not_break_the_prompt(self):
        def boom():
            raise OSError("no console")
        fake = types.SimpleNamespace(kbhit=boom, getwch=boom)
        with mock.patch.dict(sys.modules, {"msvcrt": fake, "termios": None}):
            safeprompt._drain_input()


class TestEnvFileParity(unittest.TestCase):
    NAMES = [".env", ".env.local", ".env.production", ".env.development.local", "prod.env",
             "app.env", ".ENV", ".Env.Local", ".envrc", ".envfoo", ".env.example", ".env.sample",
             ".env.template", "env", "my.environment", ".env.", ".env.bak", ".env~", ".env.swp",
             "config/.env", "a/b/.env.test", "x.env.json", "x.env.md", ".env.yml"]

    def test_every_name_the_writer_accepts_is_protected_by_the_hook(self):
        accepted = [n for n in self.NAMES if manifest_mod.env_file_problem(n) is None]
        self.assertIn(".env", accepted)
        for name in accepted:
            last = name.split("/")[-1]
            self.assertTrue(hook_mod.is_env_name(last), name)
            status, out = hook_mod.check(json.dumps({
                "hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": "/proj/" + name}}))
            self.assertTrue(out, name)

    def test_public_folders_are_refused(self):
        for name in ("public/.env", "dist/.env", "www/x/.env", "static/.env.local"):
            self.assertIsNotNone(manifest_mod.env_file_problem(name), name)


if __name__ == "__main__":
    unittest.main()
