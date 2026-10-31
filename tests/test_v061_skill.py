"""0.6.1: the skill ships in the package and installs safely."""
import io
import os
import tempfile
import unittest

import _isolation  # noqa: F401
from stuntkey import skillcmd


class Args:
    def __init__(self, project=False, yes=False):
        self.project, self.yes = project, yes


class Skill(unittest.TestCase):
    def test_packaged_file_exists(self):
        text = skillcmd.skill_text()
        self.assertTrue(text.startswith("---"))
        self.assertIn("request_connect", text)
        self.assertNotIn("run <service> -- <command>`, or", text)

    def test_install_into_home_and_again(self):
        with tempfile.TemporaryDirectory() as home:
            out = io.StringIO()
            self.assertEqual(skillcmd.cmd_skill(Args(), out, home=home), 0)
            target = os.path.join(home, ".claude", "skills", "stuntkey", "SKILL.md")
            self.assertTrue(os.path.isfile(target))
            out2 = io.StringIO()
            self.assertEqual(skillcmd.cmd_skill(Args(), out2, home=home), 0)
            self.assertIn("up to date", out2.getvalue())

    def test_project_install(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(skillcmd.cmd_skill(Args(project=True), io.StringIO(), cwd=d), 0)
            self.assertTrue(os.path.isfile(os.path.join(d, ".claude", "skills", "stuntkey", "SKILL.md")))

    def test_different_file_is_not_replaced_without_asking(self):
        with tempfile.TemporaryDirectory() as home:
            target = os.path.join(home, ".claude", "skills", "stuntkey", "SKILL.md")
            os.makedirs(os.path.dirname(target))
            with open(target, "w") as f:
                f.write("mine")
            self.assertEqual(skillcmd.cmd_skill(Args(), io.StringIO(), home=home, interactive=lambda: False), 1)
            self.assertEqual(skillcmd.cmd_skill(Args(), io.StringIO(), home=home, interactive=lambda: True,
                                                ask=lambda p: "n"), 1)
            with open(target) as f:
                self.assertEqual(f.read(), "mine")
            self.assertEqual(skillcmd.cmd_skill(Args(), io.StringIO(), home=home, interactive=lambda: True,
                                                ask=lambda p: "y"), 0)
            self.assertEqual(skillcmd.cmd_skill(Args(yes=True), io.StringIO(), home=home), 0)

    def test_links_are_refused(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlink")
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as other:
            os.makedirs(os.path.join(home, ".claude"))
            os.symlink(other, os.path.join(home, ".claude", "skills"))
            out = io.StringIO()
            self.assertEqual(skillcmd.cmd_skill(Args(), out, home=home), 1)
            self.assertIn("link", out.getvalue())
            self.assertEqual(os.listdir(other), [])
