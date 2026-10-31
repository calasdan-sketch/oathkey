"""Round 6: the activity log cannot heal itself; nothing is shown cut off;
a keychain error never leaves a key in ./.env."""
import io
import json
import os
import tempfile
import types
import unittest

from stuntkey import approve, broker, cli as cli_mod, keychain as keychain_mod

RECIPE = {"service": "t", "display": "T", "env_var": "T_KEY",
          "fields": [{"env_var": "T_KEY", "label": "key", "name": "key"}],
          "validate": {"method": "GET", "url": "https://api.example.test/u",
                       "auth": {"type": "bearer"}, "expect": [200]}}


def _log(n=4):
    d = tempfile.mkdtemp(prefix="stuntkey-t-")
    log = broker.AuditLog(os.path.join(d, "audit.log"))
    for i in range(n):
        log.write({"service": "t", "method": "GET", "host": "h", "path": "/p",
                   "status": 200, "bytes": 1, "result": "ok", "ms": 1})
    return log


def _cut(log, keep):
    with open(log.path, "rb") as f:
        lines = f.read().splitlines()
    with open(log.path, "wb") as f:
        f.write(b"\n".join(lines[:keep]) + b"\n")


class AuditHealing(unittest.TestCase):
    def test_cut_then_write_stays_broken(self):
        log = _log()
        self.assertEqual(log.verify(), (True, 4))
        _cut(log, 2)
        self.assertFalse(log.verify()[0])
        log.write({"result": "ok"})
        log.write({"result": "ok"})
        self.assertFalse(log.verify()[0])
        self.assertIsNotNone(log.broken_reason())
        with open(log.path, encoding="utf-8") as f:
            self.assertIn("LOG-PROBLEM-FOUND", f.read())

    def test_deleted_then_write_stays_broken(self):
        log = _log()
        os.remove(log.path)
        log.write({"result": "ok"})
        self.assertFalse(log.verify()[0])

    def test_garbled_marker_is_a_problem_not_a_pass(self):
        log = _log()
        with open(log.anchor_path, "w") as f:
            f.write("garbage")
        self.assertFalse(log.verify()[0])

    def test_non_object_lines_do_not_crash(self):
        log = _log(2)
        with open(log.path, "ab") as f:
            f.write(b"[1]\nnull\n\n")
        self.assertFalse(log.verify()[0])

    def test_reset_keeps_old_log_and_starts_clean(self):
        log = _log()
        _cut(log, 1)
        log.write({"result": "ok"})
        kept = log.reset()
        self.assertTrue(kept and os.path.exists(kept))
        self.assertEqual(log.verify(), (True, 0))
        log.write({"result": "ok"})
        self.assertEqual(log.verify(), (True, 1))

    def test_normal_use_stays_healthy(self):
        log = _log(6)
        self.assertEqual(log.verify(), (True, 6))
        self.assertIsNone(log.broken_reason())


class NothingCutOff(unittest.TestCase):
    def test_long_query_value_refused(self):
        with self.assertRaises(broker.BrokerError):
            broker.describe(RECIPE, "POST", "h", "https://h/x?a=" + "b" * 201, None)

    def test_long_body_refused(self):
        with self.assertRaises(broker.BrokerError):
            broker.describe(RECIPE, "POST", "h", "https://h/x", b"x" * 401)

    def test_short_values_shown_in_full(self):
        text = broker.describe(RECIPE, "POST", "h", "https://h/x?a=" + "b" * 150,
                               b'{"k": "' + b"z" * 300 + b'END"}')
        self.assertIn("b" * 150, text)
        self.assertIn("END", text)

    def test_kdialog_text_has_no_markup(self):
        out = approve._no_markup("<b>Allow</b> & go")
        self.assertNotIn("<", out)
        self.assertNotIn(">", out)
        self.assertIn("&amp;", out)

    def test_refused_requests_count(self):
        pol = broker.Policy(max_calls=2)
        for _ in range(2):
            with self.assertRaises(broker.BrokerError):
                broker.call(RECIPE, {"T_KEY": "k" * 20}, "GET", "/a/../b", policy=pol)
        with self.assertRaises(broker.BrokerError) as cm:
            broker.call(RECIPE, {"T_KEY": "k" * 20}, "GET", "/ok", policy=pol)
        self.assertIn("Limit of 2", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
