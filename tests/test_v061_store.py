"""0.6.1: concurrent .env writes; no-follow lock."""
import os
import tempfile
import threading
import unittest

import _isolation  # noqa: F401
from stuntkey import store


class Parallel(unittest.TestCase):
    def test_twenty_writers_lose_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, ".env")
            errors = []

            def work(i):
                try:
                    store.store_key_result(f"KEY_{i}", f"value-{i}-abcdefghij", env)
                except Exception as e:     # pragma: no cover
                    errors.append(repr(e))
            ts = [threading.Thread(target=work, args=(i,)) for i in range(20)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.assertEqual(errors, [])
            values = store.load_env(env)
            self.assertEqual(len(values), 20)

    def test_lock_times_out_with_a_plain_error(self):
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, ".env")
            with store.file_lock(env):
                with self.assertRaises(store.EnvFileBusy):
                    with store.file_lock(env, timeout=0.2):
                        pass

    def test_forget_is_locked_too(self):
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, ".env")
            store.store_key_result("A_KEY", "abcdefghij1234", env)
            with store.file_lock(env):
                with self.assertRaises(store.EnvFileBusy):
                    store.LOCK_SECONDS, old = 0.2, store.LOCK_SECONDS
                    try:
                        store.remove_key("A_KEY", env)
                    finally:
                        store.LOCK_SECONDS = old
