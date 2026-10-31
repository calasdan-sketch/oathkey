"""0.7.5: the real program name in the windows, who made the tool, a dead
stored key, and a closed window that is never recorded as a No."""

import io
import os
import unittest

import _isolation  # noqa: F401
import test_v070_capture as base
import test_v072_round2 as r2
from stuntkey import aboutcmd
from stuntkey import cli as cli_mod
from stuntkey import dialog as dialog_mod
from stuntkey import mcp as mcp_mod
from stuntkey import validate as validate_mod

CATALOG, GH_KEY = base.CATALOG, base.GH_KEY
wait_for, until = base.wait_for, base.until
Window = r2.Window


class TestClientLabel(unittest.TestCase):
    def tearDown(self):
        dialog_mod.set_client(None)

    def test_known_names_are_friendly(self):
        for raw, want in (("claude-code", "Claude Code"), ("claude-ai", "Claude"),
                          ("cursor", "Cursor"), ("codex", "Codex"), ("gemini-cli", "Gemini CLI"),
                          ("windsurf", "Windsurf"), ("cline", "Cline"), ("zed", "Zed"),
                          ("Claude-Code", "Claude Code"), ("cursor-vscode", "Cursor")):
            self.assertEqual(dialog_mod.client_label(raw)[0], want, raw)
            self.assertEqual(dialog_mod.client_label(raw)[1], want, raw)

    def test_absent_gives_a_neutral_name(self):
        for raw in (None, "", "   ", 5):
            self.assertEqual(dialog_mod.client_label(raw),
                             ("An AI program", "the AI program"), raw)

    def test_an_unknown_name_is_cleaned_and_cut(self):
        subject, obj = dialog_mod.client_label('my-agent <b>"x"</b>`$\\&' + "z" * 60 + "а")
        self.assertLessEqual(len(subject), 30)
        self.assertTrue(subject.isascii() and subject.isprintable())
        for bad in '<>&"`$\\':
            self.assertNotIn(bad, subject)
        self.assertTrue(subject.startswith("my-agent"))

    def test_initialize_remembers_the_name_for_the_windows(self):
        mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "clientInfo": {"name": "claude-code", "version": "1"}}},
            CATALOG)
        self.assertEqual(dialog_mod.current_client(), "claude-code")
        root = os.path.join(os.sep, "x", "my-shop")
        self.assertIn('Claude Code wants to connect GitHub for "my-shop".',
                      dialog_mod.consent_window("GitHub", root)[1])

    def test_a_bad_client_info_is_ignored(self):
        for info in (None, "str", 5, {"name": 7}, {}):
            mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"clientInfo": info}}, CATALOG)
            self.assertEqual(dialog_mod.client_label(dialog_mod.current_client())[0], "An AI program")


class TestWho(unittest.TestCase):
    def test_the_first_line_names_the_maker_and_the_window_is_five_lines(self):
        for fn in (dialog_mod.consent_window, dialog_mod.replace_window):
            title, text = fn("GitHub", "/a/proj")
            lines = text.splitlines()
            self.assertEqual(len(lines), 5)
            self.assertIn("Calas Automations", lines[0])
            self.assertIn("installed on this computer", lines[0])
            self.assertIn("free", lines[0])


class TestAbout(unittest.TestCase):
    def test_it_says_how_to_check(self):
        out = io.StringIO()
        self.assertEqual(aboutcmd.cmd_about(out), 0)
        text = out.getvalue()
        for needle in ("Calas Automations", "pip show stuntkey",
                       "https://pypi.org/project/stuntkey/",
                       "https://github.com/calasdan-sketch/stuntkey", "reports about"):
            self.assertIn(needle, text)

    def test_the_command_exists(self):
        out = io.StringIO()
        from contextlib import redirect_stdout
        with redirect_stdout(out):
            code = cli_mod.main(["about"])
        self.assertEqual(code, 0)
        self.assertIn("pip show stuntkey", out.getvalue())


class TestClosedWindowIsNotRecorded(base.Base):
    def test_a_soft_no_is_told_but_not_remembered(self):
        answers = iter([dialog_mod.SOFT_NO, True])
        asked = []

        def ask(t, x):
            asked.append(x)
            return next(answers)
        mgr = self.manager(window_available=lambda: True, ask_person=ask)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_denied"))
        out = mgr.status(0)
        self.assertIn("cannot tell", out["message"])
        # no 10-minute lock: the very next start asks again
        self.assertEqual(self.start(mgr)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_granted"))
        self.assertEqual(len(asked), 2)

    def test_a_real_no_is_still_remembered(self):
        asked = []

        def ask(t, x):
            asked.append(x)
            return False
        mgr = self.manager(window_available=lambda: True, ask_person=ask)
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_denied"))
        self.start(mgr)
        self.assertNotEqual(len(asked), 2)
        self.assertEqual(len(asked), 1)

    def test_expired_is_not_remembered_either(self):
        answers = iter([dialog_mod.EXPIRED, True])
        mgr = self.manager(window_available=lambda: True, ask_person=lambda t, x: next(answers))
        self.start(mgr)
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_expired"))
        self.assertEqual(self.start(mgr)["state"], "consent_pending")


class TestDeadStoredKey(base.Base):
    OLD = "gh" + "p_" + "Old0Old1Old2Old3Old4Old5Old6Old7Old8Old9"

    def put_old(self):
        with open(os.path.join(self.proj, ".env"), "w") as f:
            f.write("GITHUB_TOKEN=" + self.OLD + "\n")

    def setUp(self):
        super().setUp()
        self.put_old()

    def test_a_dead_key_skips_the_replace_question(self):
        self.vendor.answer = validate_mod.Result("invalid")
        w = Window(True)
        mgr = self.manager(window_available=lambda: True, ask_person=w)
        self.session_grant(mgr)
        out = self.start(mgr, replace=True)
        self.assertEqual(out["state"], "waiting")
        self.assertEqual(w.asked, [])
        self.assertIn("no longer works", out["stored_key_note"])
        self.assertEqual(self.vendor.seen, [self.OLD])          # tested with the vendor
        self.assertNoKey(out)
        self.assertNotIn(self.OLD, str(out))

    def test_a_dead_key_without_consent_asks_the_normal_question(self):
        self.vendor.answer = validate_mod.Result("invalid")
        w = Window(True)
        mgr = self.manager(window_available=lambda: True, ask_person=w)
        self.assertEqual(self.start(mgr, replace=True)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "consent_granted"))
        self.assertEqual(len(w.asked), 1)
        text = w.asked[0][1]
        self.assertIn("wants to connect", text)
        self.assertNotIn("REPLACE", text)
        msg = mgr.status(0)["message"]
        self.assertIn("no longer works", msg)
        self.assertIn("replace=true", msg)
        self.assertNotIn(self.OLD, text + msg)

    def test_a_working_key_keeps_the_replace_window(self):
        w = Window(True)
        mgr = self.manager(window_available=lambda: True, ask_person=w)
        self.session_grant(mgr)
        self.assertEqual(self.start(mgr, replace=True)["state"], "consent_pending")
        self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "replace_granted"))
        self.assertIn("REPLACE", w.asked[0][1])

    def test_a_key_that_cannot_be_tested_keeps_the_replace_window(self):
        for vendor in (base.Vendor(error=OSError("offline")),
                       base.Vendor(answer=validate_mod.Result("unknown"))):
            w = Window(True)
            mgr = self.manager(window_available=lambda: True, ask_person=w, validate_fn=vendor)
            self.session_grant(mgr)
            self.assertEqual(self.start(mgr, replace=True)["state"], "consent_pending")
            self.assertTrue(wait_for(lambda: mgr.status(0)["state"] == "replace_granted"))
            self.assertIn("REPLACE", w.asked[0][1])

    def test_without_replace_a_stored_key_is_not_tested_or_touched(self):
        self.vendor.answer = validate_mod.Result("invalid")
        mgr = self.manager(window_available=lambda: True, ask_person=Window(True))
        self.session_grant(mgr)
        self.assertEqual(self.start(mgr)["state"], "already_stored")
        self.assertEqual(self.vendor.seen, [])


if __name__ == "__main__":
    unittest.main()
