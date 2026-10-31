"""0.6.1: the MCP guard blanks secrets, not ordinary words, and never member names."""
import json
import os
import tempfile
import unittest

import _isolation  # noqa: F401
from stuntkey import agent, recipes

CAT = recipes.load_recipes(recipes.RECIPES_DIR)
SECRET = "sk-proj-Zk3pQ9vL2mXw8RtY5uBn7HcD"


def env_dir(text):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, ".env"), "w") as f:
        f.write(text)
    return d


class Guard(unittest.TestCase):
    def test_ordinary_settings_are_not_blanked(self):
        d = env_dir(f"STATUS=present\nNODE_ENV=production\nPORT=8080\nMODE=missing\nOPENAI_API_KEY={SECRET}\n")
        text = json.dumps({"status": "present", "mode": "production-ready", "service": "openai", "note": "missing"})
        self.assertEqual(json.loads(agent.guard_text(text, CAT, d, environ={})), json.loads(text))

    def test_the_secret_value_is_blanked(self):
        d = env_dir(f"OPENAI_API_KEY={SECRET}\n")
        out = agent.guard_text(json.dumps({"x": "see " + SECRET}), CAT, d, environ={})
        self.assertNotIn(SECRET, out)
        self.assertIn("[REDACTED]", out)

    def test_member_names_survive_even_when_equal_to_a_value(self):
        d = env_dir("SOME_API_KEY=statusvalue123456\n")
        text = json.dumps({"statusvalue123456": 1, "status": "statusvalue123456"})
        out = json.loads(agent.guard_text(text, CAT, d, environ={}))
        self.assertIn("statusvalue123456", out)          # the member NAME is untouched
        self.assertEqual(out["status"], "[REDACTED]")

    def test_long_key_shaped_value_with_odd_name_is_blanked(self):
        d = env_dir(f"MY_THING={SECRET}\n")
        self.assertNotIn(SECRET, agent.guard_text(SECRET, CAT, d, environ={}))

    def test_still_valid_json(self):
        d = env_dir(f"OPENAI_API_KEY={SECRET}\n")
        json.loads(agent.guard_text(json.dumps({"a": [SECRET, {"b": SECRET}]}), CAT, d, environ={}))


class Limits(unittest.TestCase):
    def test_needs_keys_refuses_a_folder_outside_the_project(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            r = agent.needs_keys(b, CAT, cwd=a)
            self.assertTrue(r.get("isError"))
            os.makedirs(os.path.join(a, "sub"))
            self.assertFalse(agent.needs_keys("sub", CAT, cwd=a).get("isError"))

    def test_needs_keys_refuses_dotdot_escape(self):
        with tempfile.TemporaryDirectory() as a:
            cwd = os.path.join(a, "p")
            os.makedirs(cwd)
            self.assertTrue(agent.needs_keys("..", CAT, cwd=cwd).get("isError"))
            self.assertTrue(agent.needs_keys("/", CAT, cwd=cwd).get("isError"))

    def test_open_key_page_global_limit(self):
        agent._OPEN_TIMES.clear()
        agent._LAST_OPEN.clear()
        opened = []
        slugs = [s for s in sorted(CAT)][:6]
        res = [agent.request_connect(s, CAT, open_key_page=True, opener=opened.append,
                                     cwd=tempfile.gettempdir()).get("opened_key_page") for s in slugs]
        self.assertEqual(len(opened), 3)
        self.assertEqual(res.count(True), 3)
        agent._OPEN_TIMES.clear()
        agent._LAST_OPEN.clear()
