"""0.5.2: the hook also refuses Edit, Write, MultiEdit and NotebookEdit on a
real .env file, with an opt-out, and old installs are upgraded in place."""

import json
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod

from test_hook import Settings, call, denied

OLD_MATCHER = "Read|Grep|Bash|PowerShell|Monitor"


class TestWritesRefused(unittest.TestCase):
    def test_write_edit_multiedit_on_env(self):
        for tool, extra in (("Write", {"content": "K=1"}),
                            ("Edit", {"old_string": "a", "new_string": "b"}),
                            ("MultiEdit", {"edits": []})):
            self.assertTrue(denied(call(tool, file_path="/app/.env", **extra)), tool)

    def test_notebook_edit_uses_notebook_path(self):
        self.assertTrue(denied(call("NotebookEdit", notebook_path="/app/prod.env", new_source="x")))

    def test_other_env_names(self):
        for name in (".env.local", "prod.env", ".envrc", ".env.production"):
            self.assertTrue(denied(call("Write", file_path="/app/" + name, content="x")), name)

    def test_templates_and_ordinary_files_are_writable(self):
        for name in (".env.example", ".env.sample", ".env.template", ".env.dist",
                     "main.py", "environment.py"):
            self.assertFalse(denied(call("Write", file_path="/app/" + name, content="x")), name)
        self.assertFalse(denied(call("NotebookEdit", notebook_path="/a/nb.ipynb")))

    def test_message_is_plain(self):
        _, out = hook_mod.check(call("Write", file_path="/app/.env", content="K=1"))
        reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Claude can't write to '.env' - your keys stay out of the chat. "
                      "Call the stuntkey tool `capture_key`", reason)
        self.assertIn("stuntkey connect <service>", reason)

    def test_reads_keep_the_read_message(self):
        _, out = hook_mod.check(call("Read", file_path="/app/.env"))
        self.assertNotIn("can't write", out)


class TestOptOut(unittest.TestCase):
    def test_env_var_allows_writes_only(self):
        with mock.patch.dict("os.environ", {hook_mod.ALLOW_WRITE_VAR: "1"}):
            self.assertFalse(denied(call("Write", file_path="/app/.env", content="x")))
            self.assertFalse(denied(call("Edit", file_path="/app/.env")))
            self.assertTrue(denied(call("Read", file_path="/app/.env")))
            self.assertTrue(denied(call("Bash", command="cat .env")))

    def test_other_values_do_not_count(self):
        for value in ("0", "", "true"):
            with mock.patch.dict("os.environ", {hook_mod.ALLOW_WRITE_VAR: value}):
                self.assertTrue(denied(call("Write", file_path="/app/.env")), value)


class TestUpgrade(Settings):
    def old_group(self):
        return {"matcher": OLD_MATCHER, "hooks": [
            {"type": "command", "command": "/opt/bin/stuntkey hook check",
             "statusMessage": hook_mod.MARKER}]}

    def test_install_upgrades_our_matcher_and_leaves_foreign_hooks(self):
        foreign = {"matcher": "Write", "hooks": [{"type": "command", "command": "/x/fmt.sh"}]}
        foreign2 = {"matcher": OLD_MATCHER, "hooks": [{"type": "command", "command": "/x/audit.sh"}]}
        self.put({"hooks": {"PreToolUse": [foreign, self.old_group(), foreign2]}})
        code, out, _ = self.hook("install")
        self.assertEqual(code, 0)
        self.assertIn("Updated", out)
        groups = self.get()["hooks"]["PreToolUse"]
        self.assertEqual(groups[0], foreign)
        self.assertEqual(groups[2], foreign2)
        self.assertEqual(groups[1]["matcher"], hook_mod.MATCHER)
        self.assertEqual(len(groups), 3)

    def test_status_says_outdated(self):
        self.put({"hooks": {"PreToolUse": [self.old_group()]}})
        _, out, _ = self.hook("status")
        self.assertIn("OUTDATED", out)
        self.assertIn("hook install", out)

    def test_status_is_quiet_after_upgrade(self):
        self.put({"hooks": {"PreToolUse": [self.old_group()]}})
        self.hook("install")
        _, out, _ = self.hook("status")
        self.assertNotIn("OUTDATED", out)

    def test_fresh_install_matcher_covers_write_tools(self):
        self.hook("install")
        matcher = self.get()["hooks"]["PreToolUse"][0]["matcher"]
        for tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
            self.assertIn(tool, matcher.split("|"))

    def test_second_install_changes_nothing(self):
        self.hook("install")
        self.assertIn("Already installed", self.hook("install")[1])
