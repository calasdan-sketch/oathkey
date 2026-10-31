"""`stuntkey get <service>`: one command, keychain + copy-and-go by default."""
import unittest
from unittest import mock

from stuntkey import cli, clipboard, connect


class GetCommandTests(unittest.TestCase):
    def _run(self, argv):
        seen = {}

        def fake_connect(recipe, **kw):
            seen["recipe"] = recipe["service"]
            seen.update(kw)
            return 0
        fake_clip = (lambda: "", lambda: None)
        with mock.patch.object(connect, "connect", fake_connect), \
                mock.patch.object(clipboard, "backend", lambda: fake_clip), \
                mock.patch.object(cli.keychain_mod, "detect_backend", lambda: "test"), \
                mock.patch.object(cli, "keychain_store", lambda r, e: "STORE"):
            code = cli.main(argv)
        return code, seen

    def test_get_defaults_to_keychain_and_clipboard(self):
        code, seen = self._run(["get", "github"])
        self.assertEqual(code, 0)
        self.assertEqual(seen["recipe"], "github")
        self.assertEqual(seen["store_fn"], "STORE")
        self.assertIsNotNone(seen["clipboard"])

    def test_get_can_use_hidden_prompt(self):
        _, seen = self._run(["get", "github", "--no-clipboard"])
        self.assertIsNone(seen["clipboard"])

    def test_connect_keeps_old_defaults(self):
        _, seen = self._run(["connect", "github"])
        self.assertIsNone(seen["store_fn"])
        self.assertIsNone(seen["clipboard"])


if __name__ == "__main__":
    unittest.main()
