import io
import os
import unittest

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import connect as connect_mod
from stuntkey import store as store_mod
from stuntkey import validate as validate_mod

SECRET = "sk-test-THIS-IS-A-FAKE-KEY-999"


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


class TestStore(unittest.TestCase):
    def test_create_new_env(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        path, updated = store_mod.store_key("ACME_API_KEY", SECRET, env)
        self.assertEqual(path, env)
        self.assertFalse(updated)
        with open(env, encoding="utf-8") as f:
            self.assertIn(f"ACME_API_KEY={SECRET}", f.read())
        self.assert_owner_only(env)

    def assert_owner_only(self, path):
        # POSIX mode bits mean nothing on Windows (chmod only toggles the
        # read-only flag there); the ACL is handled separately.
        if os.name != "nt":
            self.assertEqual(store_mod.file_mode(path), 0o600)

    def test_update_in_place_preserves_rest(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with open(env, "w", encoding="utf-8") as f:
            f.write("OTHER=1\nACME_API_KEY=old\nTAIL=x\n")
        path, updated = store_mod.store_key("ACME_API_KEY", SECRET, env)
        self.assertTrue(updated)
        with open(env, encoding="utf-8") as f:
            content = f.read()
        self.assertIn(f"ACME_API_KEY={SECRET}", content)
        self.assertIn("OTHER=1", content)
        self.assertIn("TAIL=x", content)
        self.assertNotIn("ACME_API_KEY=old", content)
        self.assert_owner_only(env)


class TestConnect(unittest.TestCase):
    def _run(self, keys, validate_results, env_file):
        """keys: values returned by fake prompt. validate_results: bools."""
        prompts = list(keys)
        validations = list(validate_results)
        opened = []

        def fake_browser(url):
            opened.append(url)

        def fake_prompt(_):
            return prompts.pop(0)

        def fake_validate(spec, key):
            self.assertEqual(spec["url"], "https://acme.test/me")
            return validations.pop(0)

        out = io.StringIO()
        code = connect_mod.connect(
            recipe(), env_file=env_file, browser_open=fake_browser,
            prompt=fake_prompt, out=out, validate_fn=fake_validate)
        return code, out.getvalue(), opened

    def test_happy_path(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        code, output, opened = self._run([SECRET], [True], env)
        self.assertEqual(code, 0)
        self.assertEqual(opened, ["https://acme.test/keys"])
        with open(env, encoding="utf-8") as f:
            self.assertIn(f"ACME_API_KEY={SECRET}", f.read())
        # THE key must never appear in output.
        self.assertNotIn(SECRET, output)
        self.assertIn("never displayed, never logged", output)

    def test_rejected_then_accepted(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        code, output, _ = self._run(["bad-key", SECRET], [False, True], env)
        self.assertEqual(code, 0)
        self.assertIn("key rejected", output)
        with open(env, encoding="utf-8") as f:
            self.assertIn(SECRET, f.read())
        self.assertNotIn("bad-key", output)

    def test_three_strikes_gives_up(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        code, output, _ = self._run(["k1", "k2", "k3"],
                                    [False, False, False], env)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.isfile(env))
        self.assertIn("giving up", output)

    def test_validation_network_error_aborts(self):
        def boom(spec, key):
            raise validate_mod.ValidationError("dns down")
        out = io.StringIO()
        code = connect_mod.connect(
            recipe(), env_file=os.path.join(_isolation.mktemp(), ".env"),
            browser_open=lambda u: None, prompt=lambda _: SECRET,
            out=out, validate_fn=boom)
        self.assertEqual(code, 1)
        self.assertIn("couldn't reach the API", out.getvalue())
        self.assertNotIn(SECRET, out.getvalue())


if __name__ == "__main__":
    unittest.main()
