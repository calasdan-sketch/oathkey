"""The written docs must match the program (review group A, docs items)."""
import os
import re
import unittest

from stuntkey import mcp as mcp_mod

OLD = "safe" + "easy" + "api"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


class DocsMatch(unittest.TestCase):
    def test_service_count_is_the_real_one(self):
        n = len([f for f in os.listdir(os.path.join(REPO, "stuntkey", "recipes"))
                 if f.endswith(".json")])
        self.assertIn(f"{n} services are built in", _read("README.md"))
        guide = _read("docs", "guide.md")
        self.assertIn(f"{n} built in", guide)
        self.assertIn(f"Ships with {n} recipes", guide)
        self.assertEqual(re.findall(r"\b3[0-9] (?:services|recipes|built in)", guide).count(f"{n} built in"), 1)

    def test_skill_explains_call_api(self):
        skill = _read("stuntkey", "skill", "SKILL.md")
        self.assertIn("## Use the key", skill)
        for word in ("call_api", "query_json", "body_json", "ask the person first", "do not retry"):
            self.assertIn(word, skill)

    def test_guide_lists_all_eight_tools(self):
        guide = _read("docs", "guide.md")
        tools = [t["name"] for t in mcp_mod._tool_defs()]
        self.assertEqual(len(tools), 8)
        for name in tools:
            self.assertIn(f"`{name}`", guide, name)
            self.assertIn(name, mcp_mod.__doc__, name)
        self.assertNotIn("returns recipes; the interactive key paste", guide)

    def test_one_type_words_table(self):
        src = _read("stuntkey", "mcp.py")
        self.assertEqual(src.count("\n_TYPE_WORDS = "), 1)
        self.assertEqual(mcp_mod._TYPE_WORDS["boolean"], "true or false")

    def test_guide_heading_and_commands(self):
        guide = _read("docs", "guide.md")
        self.assertTrue(guide.lstrip().split("\n\n", 1)[1].startswith("# stuntkey\n"))
        for cmd in ("install", "uninstall", "start", "overview", "doctor", "trust-server"):
            self.assertRegex(guide, r"(?m)^stuntkey [^\n]*\b%s\b" % cmd)

    def test_readme_front_page(self):
        text = _read("README.md")
        self.assertIn("Let your AI use your API keys through stuntkey without holding them.", text)
        self.assertIn("Need pipx? https://pipx.pypa.io", text)
        self.assertIn("read-only", text)
        self.assertIn("unless you agree to the fallback", text)
        self.assertIn(OLD, text)        # the migration line
        # the one simple path: install, get a key, plug in, then doctor shows it connected
        order = [text.index(s) for s in ("pipx install stuntkey", "stuntkey get github",
                                          "stuntkey install", "stuntkey doctor")]
        self.assertEqual(order, sorted(order))

    def test_changelog_says_fresh_start(self):
        log = _read("CHANGELOG.md").split("## 0.7.5")[0]
        self.assertIn("fresh start", log)
        self.assertIn("Nothing is migrated", log)
        self.assertIn(f"remove any old `{OLD}`", log)

    def test_pyproject_summary_makes_no_security_claim(self):
        m = re.search(r'^description = "([^"]+)"', _read("pyproject.toml"), re.M)
        low = m.group(1).lower()
        for word in ("secure", "safe tunnel", "audited"):
            self.assertNotIn(word, low)


if __name__ == "__main__":
    unittest.main()
