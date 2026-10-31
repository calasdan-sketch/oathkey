"""doctor reports on stuntkey itself; list has --json."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from stuntkey import cli
from stuntkey import gitscan as scan


class DoctorTests(unittest.TestCase):
    def test_reports_log_tools_and_selfcheck(self):
        names = {c["check"] for c in scan.doctor()["checks"]}
        self.assertTrue({"activity log", "AI tools", "self-attack test"} <= names)

    def test_broken_log_is_flagged(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "audit.log"), "w") as f:
            f.write('{"not": "a valid chain"}\n')
        with mock.patch("stuntkey.remote.home_dir", lambda: d):
            checks = {c["check"]: c for c in scan.doctor()["checks"]}
        self.assertFalse(checks["activity log"]["ok"])
        self.assertTrue(checks["activity log"]["fix"])

    def test_one_failing_check_does_not_hide_others(self):
        with mock.patch("stuntkey.clients.targets", side_effect=RuntimeError("x")):
            checks = {c["check"]: c for c in scan.doctor()["checks"]}
        self.assertFalse(checks["AI tools"]["ok"])
        self.assertIn("self-attack test", checks)


class ListJsonTests(unittest.TestCase):
    def test_list_json_is_valid(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["list", "--json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(any(r["service"] == "github" for r in data))
        self.assertTrue(all({"service", "display", "env_vars"} <= set(r) for r in data))


if __name__ == "__main__":
    unittest.main()