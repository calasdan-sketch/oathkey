"""0.9.0: oathkey became stuntkey. Every path an 0.8 user's data takes over."""
import argparse
import io
import json
import os
import types
import unittest
from unittest import mock

import _isolation
from stuntkey import (clients, consent, hook, keychain, manifest, migrate, policy,
                      scrub)

SECRET = "sk-test-" + "q7w8e9r0" * 4


def _fake_keychain(test, box):
    """keychain._dispatch over a dict {(prefix, service, var): key}."""
    def dispatch(op, backend, service, account, key, run, ctypes_mod,
                 prefix=keychain.TARGET_PREFIX):
        k = (prefix, service, account)
        if op == "store":
            box[k] = key
            return None
        if op == "read":
            return box.get(k)
        return None if box.pop(k, None) is not None else ""
    fp = os.path.join(_isolation.mktemp(), "fp.json")
    for p in (mock.patch.object(keychain, "_dispatch", dispatch),
              mock.patch.object(scrub, "fingerprint_path", lambda: fp),
              mock.patch.object(migrate, "had_oathkey", lambda: True)):
        p.start()
        test.addCleanup(p.stop)


class TheFolderIsCopied(unittest.TestCase):
    def setUp(self):
        self.base = _isolation.mktemp()
        self.old = os.path.join(self.base, ".oathkey")
        os.makedirs(os.path.join(self.old, "recipes"))
        with open(os.path.join(self.old, "caps.json"), "w") as f:
            f.write('{"openai": {"calls_day": 5}}')
        with open(os.path.join(self.old, "recipes", "mine.json"), "w") as f:
            f.write("{}")
        os.makedirs(os.path.join(self.old, "pyz", "abc"))

    def test_copied_once_and_the_old_folder_stays(self):
        err = io.StringIO()
        self.assertTrue(migrate.copy_home(self.base, err=err))
        new = os.path.join(self.base, ".stuntkey")
        with open(os.path.join(new, "caps.json")) as f:
            self.assertIn("calls_day", f.read())
        self.assertTrue(os.path.isfile(os.path.join(new, "recipes", "mine.json")))
        self.assertFalse(os.path.exists(os.path.join(new, "pyz")))   # unpacked code only
        self.assertTrue(os.path.isfile(os.path.join(self.old, "caps.json")))
        self.assertIn("copied your settings", err.getvalue())
        err2 = io.StringIO()
        self.assertFalse(migrate.copy_home(self.base, err=err2))
        self.assertEqual(err2.getvalue(), "")                       # said once
        self.assertEqual([n for n in os.listdir(self.base) if "migrate" in n], [])

    def test_an_existing_new_folder_is_never_overwritten(self):
        new = os.path.join(self.base, ".stuntkey")
        os.makedirs(new)
        self.assertFalse(migrate.copy_home(self.base, err=io.StringIO()))
        self.assertEqual(os.listdir(new), [])


class KeychainFallback(unittest.TestCase):
    def setUp(self):
        self.box = {("oathkey", "openai", "OPENAI_API_KEY"): SECRET}
        _fake_keychain(self, self.box)

    def test_read_falls_back_to_the_old_name(self):
        self.assertEqual(keychain.read("openai", "OPENAI_API_KEY", "fake"), SECRET)
        self.assertIsNone(keychain.read_current("openai", "OPENAI_API_KEY", "fake"))

    def test_the_new_name_wins(self):
        self.box[("stuntkey", "openai", "OPENAI_API_KEY")] = "new-" + SECRET
        self.assertEqual(keychain.read("openai", "OPENAI_API_KEY", "fake"), "new-" + SECRET)

    def test_forget_removes_the_old_copy_too(self):
        self.assertTrue(keychain.delete("openai", "OPENAI_API_KEY", "fake"))
        self.assertIsNone(keychain.read("openai", "OPENAI_API_KEY", "fake"))

    def test_no_second_lookup_on_a_computer_that_never_ran_oathkey(self):
        with mock.patch.object(migrate, "had_oathkey", lambda: False):
            self.assertIsNone(keychain.read("openai", "OPENAI_API_KEY", "fake"))


class MigrateCommand(unittest.TestCase):
    CATALOG = {"openai": {"service": "openai", "env_var": "OPENAI_API_KEY"},
               "github": {"service": "github", "env_var": "GITHUB_TOKEN"}}

    def setUp(self):
        self.box = {("oathkey", "openai", "OPENAI_API_KEY"): SECRET}
        _fake_keychain(self, self.box)
        self.done = os.path.join(_isolation.mktemp(), migrate.DONE_FILE)
        p = mock.patch("stuntkey.remote.home_dir", lambda: os.path.dirname(self.done))
        p.start()
        self.addCleanup(p.stop)

    def run_it(self, **kw):
        out = io.StringIO()
        code = migrate.migrate_keychain(self.CATALOG, backend="fake", out=out, **kw)
        self.assertNotIn(SECRET, out.getvalue())
        return code, out.getvalue()

    def test_copies_checks_and_leaves_the_old_entry(self):
        code, text = self.run_it()
        self.assertEqual(code, 0)
        self.assertEqual(self.box[("stuntkey", "openai", "OPENAI_API_KEY")], SECRET)
        self.assertIn(("oathkey", "openai", "OPENAI_API_KEY"), self.box)
        self.assertIn("1 key(s) copied", text)
        self.assertIn("--remove-old", text)
        self.assertTrue(os.path.exists(self.done))
        with mock.patch.object(migrate, "had_oathkey", lambda: True):
            self.assertFalse(migrate.keychain_pending())

    def test_remove_old(self):
        code, _ = self.run_it(remove_old=True)
        self.assertEqual(code, 0)
        self.assertNotIn(("oathkey", "openai", "OPENAI_API_KEY"), self.box)
        self.assertEqual(self.box[("stuntkey", "openai", "OPENAI_API_KEY")], SECRET)

    def test_a_different_new_key_is_kept(self):
        self.box[("stuntkey", "openai", "OPENAI_API_KEY")] = "newer-" + SECRET
        code, text = self.run_it(remove_old=True)
        self.assertEqual(self.box[("stuntkey", "openai", "OPENAI_API_KEY")], "newer-" + SECRET)
        self.assertIn(("oathkey", "openai", "OPENAI_API_KEY"), self.box)  # never removed
        self.assertIn("kept it", text)

    def test_a_copy_that_does_not_read_back_is_a_problem_and_the_old_one_stays(self):
        with mock.patch.object(keychain, "store",
                               side_effect=keychain.KeychainError("reading the entry back failed")):
            code, text = self.run_it(remove_old=True)
        self.assertEqual(code, 1)
        self.assertIn(("oathkey", "openai", "OPENAI_API_KEY"), self.box)
        self.assertIn("not copied", text)
        self.assertFalse(os.path.exists(self.done))


class OldProjectFiles(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        os.makedirs(os.path.join(self.dir, ".git"))

    def test_an_old_manifest_is_used_with_a_note(self):
        old = os.path.join(self.dir, "oathkey.json")
        with open(old, "w") as f:
            f.write('{"version": 1, "services": []}')
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.assertEqual(os.path.realpath(manifest.find(self.dir)), os.path.realpath(old))
        self.assertIn("oathkey.json", err.getvalue())
        with open(os.path.join(self.dir, "stuntkey.json"), "w") as f:
            f.write('{"version": 1, "services": []}')
        self.assertTrue(manifest.find(self.dir).endswith("stuntkey.json"))

    def test_an_old_policy_file_is_used(self):
        with open(os.path.join(self.dir, "oathkey.policy"), "w") as f:
            f.write("{}")
        with mock.patch("sys.stderr", io.StringIO()):
            self.assertTrue(policy.project_file(self.dir).endswith("oathkey.policy"))
            self.assertTrue(policy.user_file(self.dir).endswith("oathkey.policy"))
        self.assertTrue(policy.project_file(_isolation.mktemp()).endswith("stuntkey.policy"))


OLD_HANDLER = {"type": "command", "command": "/x/bin/oathkey hook check",
               "timeout": 10, "statusMessage": "oathkey hook"}


def _deny_run(argv, **kw):
    out = {"hookSpecificOutput": {"permissionDecision": "deny"}}
    return types.SimpleNamespace(stdout=json.dumps(out).encode(), returncode=0)


class OldHook(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(_isolation.mktemp(), "settings.json")
        with open(self.path, "w") as f:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [OLD_HANDLER]}],
                                 "PostToolUse": [{"matcher": "Bash", "hooks": [OLD_HANDLER]}]}}, f)

    def install(self, yes):
        args = argparse.Namespace(hook_cmd="install", settings=self.path, project=False,
                                  shell_form=False, fail_open=False, yes=yes)
        out = io.StringIO()
        code = hook.cmd_hook(args, out=out, err=io.StringIO(), run=_deny_run)
        with open(self.path) as f:
            return code, out.getvalue(), json.load(f)

    def test_found_and_flagged(self):
        self.assertEqual(len(hook.legacy_handlers(hook.load_settings(self.path))), 2)
        self.assertEqual(migrate.legacy_hooks([self.path]), [self.path])
        self.assertFalse(hook.is_legacy({"command": "/x/stuntkey hook check"}))
        self.assertFalse(hook.is_legacy({"command": "/x/oathkey-wt/stuntkey hook check",
                                         "statusMessage": hook.MARKER}))

    def test_not_replaced_without_an_answer(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            code, text, data = self.install(yes=False)
        self.assertEqual(code, 1)
        self.assertIn("old (oathkey 0.8)", text)
        self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"], [OLD_HANDLER])

    def test_replaced_after_showing_the_change(self):
        code, text, data = self.install(yes=True)
        self.assertEqual(code, 0, text)
        self.assertIn("-    \"statusMessage\": \"oathkey hook\"", text)
        for event in ("PreToolUse", "PostToolUse"):
            handlers = [h for g in data["hooks"][event] for h in g["hooks"]]
            self.assertEqual(len(handlers), 1)
            self.assertEqual(handlers[0]["statusMessage"], hook.MARKER)
        self.assertEqual(migrate.legacy_hooks([self.path]), [])

    def test_uninstall_takes_the_old_one_out(self):
        args = argparse.Namespace(hook_cmd="uninstall", settings=self.path, project=False)
        hook.cmd_hook(args, out=io.StringIO(), err=io.StringIO())
        with open(self.path) as f:
            self.assertNotIn("hooks", json.load(f))


class OldMcpEntry(unittest.TestCase):
    def test_install_replaces_it_after_showing_the_diff(self):
        folder = _isolation.mktemp()
        path = os.path.join(folder, "mcp.json")
        with open(path, "w") as f:
            json.dump({"mcpServers": {"oathkey": {"command": "py", "args": ["-m", "oathkey", "mcp"]},
                                      "other": {"command": "x"}}}, f)
        tg = {"cursor": (path, "mcpServers")}
        self.assertEqual(migrate.legacy_mcp(tg), ["cursor"])
        lines = []
        with mock.patch.object(clients, "targets", lambda **kw: tg):
            clients.run(["cursor"], yes=False, ask=lambda q: "y", out=lines.append)
        text = "\n".join(lines)
        self.assertIn("replace the old 'oathkey' entry", text)
        self.assertIn('-  "oathkey": {', text)
        with open(path) as f:
            servers = json.load(f)["mcpServers"]
        self.assertEqual(sorted(servers), ["other", "stuntkey"])
        self.assertEqual(migrate.legacy_mcp(tg), [])


class OldAgentRulesBlock(unittest.TestCase):
    def test_replaced_on_install_and_removed_on_uninstall(self):
        folder = _isolation.mktemp()
        path = os.path.join(folder, "CLAUDE.md")
        with open(path, "w", newline="") as f:
            f.write("# Mine\n\n<!-- oathkey:begin (old) -->\n## API keys (oathkey)\n"
                    "<!-- oathkey:end -->\n")
        hook.add_agent_rules(folder)
        with open(path) as f:
            text = f.read()
        self.assertNotIn("oathkey:begin", text)
        self.assertIn(hook.RULES_END, text)
        self.assertTrue(text.startswith("# Mine"))
        with open(path, "a") as f:
            f.write("<!-- oathkey:begin -->\nx\n<!-- oathkey:end -->\n")
        hook.remove_agent_rules(folder)
        with open(path) as f:
            self.assertEqual(f.read(), "# Mine\n")


class TheHookStillGuardsTheOldName(unittest.TestCase):
    def denied(self, cmd):
        _status, out = hook.check(json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}))
        return bool(out) and json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_old_folder_and_old_command(self):
        for cmd in ("cat ~/.oathkey/consent.key", "ls ~/.oath*/*", "cat ~/.stuntkey/caps.json",
                    "ls ~/.stunt*/*", "oathkey run github -- env", "stuntkey run github -- env",
                    "python -m oathkey call github GET /user"):
            self.assertTrue(self.denied(cmd), cmd)
        self.assertFalse(self.denied("stuntkey doctor"))


class TheConsentSecretSurvives(unittest.TestCase):
    def test_the_old_keychain_label_is_read_when_ours_is_missing(self):
        asked = []

        def run(argv, **kw):
            asked.append(argv)
            hit = consent.LEGACY_LABEL in argv
            return types.SimpleNamespace(returncode=0 if hit else 44,
                                         stdout=(b"ab" * 16) if hit else b"")
        secret = consent.CommandSecret("keychain", run=run, find=lambda n: "/usr/bin/" + n)
        self.assertEqual(secret.load(), bytes.fromhex("ab" * 16))
        self.assertIn(consent.LABEL, asked[0])


@unittest.skipUnless(os.path.isdir(os.path.join(_isolation.REPO, "shim-oathkey")),
                     "the shims are not in the sdist")
class TheOldCommandForwards(unittest.TestCase):
    def test_oathkey_says_so_and_runs_stuntkey(self):
        import subprocess
        import sys
        code = ("import sys; sys.path.insert(0, 'shim-oathkey'); sys.argv = ['oathkey', '--version']; "
                "import oathkey; sys.exit(oathkey.main())")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           cwd=_isolation.REPO, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("oathkey is now stuntkey", r.stderr)
        self.assertRegex(r.stdout, r"^stuntkey \d")

    def test_the_safeeasyapi_shim_points_at_stuntkey(self):
        import sys
        sys.path.insert(0, os.path.join(_isolation.REPO, "shim"))
        try:
            import safeeasyapi
        finally:
            sys.path.pop(0)
        self.assertIn("pipx install stuntkey", safeeasyapi.MESSAGE)


if __name__ == "__main__":
    unittest.main()
