import os
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from oathkey import keychain, scrub


class KeychainKeepsFingerprints(unittest.TestCase):
    """Saving to or deleting from the keychain updates the hook's fingerprint
    file, so the PostToolUse scrubber knows a stored key without reading it."""

    def setUp(self):
        self.fp = os.path.join(tempfile.mkdtemp(), "fingerprints.json")
        self.box = {}

        def dispatch(action, backend, service, env_var, key, run, ctypes_mod):
            if action == "store":
                self.box[(service, env_var)] = key
            elif action == "read":
                return self.box.get((service, env_var))
            elif action == "delete":
                return None if self.box.pop((service, env_var), None) is not None else False
            return None

        patches = [mock.patch.object(keychain, "_dispatch", dispatch),
                   mock.patch.object(scrub, "fingerprint_path", lambda: self.fp)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_store_then_delete(self):
        key = "sk-test-" + "a1b2c3d4" * 4
        keychain.store("openai", "OPENAI_API_KEY", key, backend="fake")
        salt, fps = scrub.load_fingerprints(self.fp)
        self.assertTrue(fps, "a stored key is fingerprinted")
        with open(self.fp, encoding="utf-8") as f:
            self.assertNotIn(key, f.read(), "the file never holds the key")
        self.assertTrue(keychain.delete("openai", "OPENAI_API_KEY", backend="fake"))
        self.assertFalse(scrub.load_fingerprints(self.fp)[1], "a deleted key is forgotten")

    def test_fingerprint_failure_never_blocks_a_save(self):
        with mock.patch.object(scrub, "remember_key", side_effect=OSError("disk full")):
            self.assertEqual(keychain.store("openai", "OPENAI_API_KEY", "sk-test-" + "z" * 32, backend="fake"), "fake")


if __name__ == "__main__":
    unittest.main()
