"""The front-page README must match the program: no drift, no old names."""
import argparse
import os
import re
import unittest

from stuntkey import cli

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


def _subcommands():
    parser = None
    orig = argparse.ArgumentParser.parse_args

    def grab(self, *a, **k):
        nonlocal parser
        parser = self
        raise SystemExit(0)
    argparse.ArgumentParser.parse_args = grab
    try:
        try:
            cli._main(["list"])
        except SystemExit:
            pass
    finally:
        argparse.ArgumentParser.parse_args = orig
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    raise AssertionError("no subcommands found")


class FrontPageTests(unittest.TestCase):
    def test_every_command_in_the_readme_exists(self):
        real = _subcommands()
        named = set(re.findall(r"`stuntkey ([a-z][a-z-]+)", _read("README.md")))
        named -= {"is"}
        self.assertTrue(named, "README names no commands")
        self.assertEqual(sorted(named - real), [], "README names commands that do not exist")

    def test_the_headline_commands_are_documented(self):
        text = _read("README.md")
        for cmd in ("get", "call", "selftest", "doctor", "scan", "install", "audit",
                    "serve", "mcp", "run", "list"):
            self.assertTrue(f"stuntkey {cmd}" in text.replace("`", "") or f"`{cmd}`" in text
                            or f"`{cmd} " in text, cmd)

    def test_it_points_at_security_and_the_guide(self):
        text = _read("README.md")
        self.assertIn("SECURITY.md", text)
        self.assertIn("docs/guide.md", text)
        self.assertTrue(os.path.exists(os.path.join(REPO, "docs", "guide.md")))

    def test_it_does_not_hard_code_the_number_of_attacks(self):
        self.assertIsNone(re.search(r"\b\d+ attacks\b", _read("README.md")))

    def test_no_old_product_name_anywhere(self):
        old = "safe" + "easy" + "api"
        for folder in ("stuntkey", "tests", "docs"):
            for name in os.listdir(os.path.join(REPO, folder)):
                path = os.path.join(REPO, folder, name)
                if os.path.isfile(path) and name.endswith((".py", ".md", ".json")):
                    self.assertNotIn(old, _read(folder, name).lower(), path)
        for name in ("README.md", "SECURITY.md", "pyproject.toml"):
            text = "\n".join(line for line in _read(name).splitlines()
                             if not line.startswith(("Coming from", "- Formerly")))  # the migration lines
            self.assertNotIn(old, text.lower(), name)

    def test_version_matches_pyproject(self):
        from stuntkey import __version__
        m = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"), re.M)
        self.assertEqual(m.group(1), __version__)


if __name__ == "__main__":
    unittest.main()
