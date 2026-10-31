"""The MCP server survives a message it cannot take apart or write back.

Panel finding (SEA-3): `python -c "print('['*100000)" | stuntkey mcp`
ended in a traceback and exit status 1. json.loads raises RecursionError, not
ValueError, for text nested that deep, and serve() only expected ValueError.
The server must answer "Parse error" and carry on, like any other bad line.

Round-2 panel (SEA-2): `echo '{...initialize...}' | stuntkey mcp >&-` ended
in an AttributeError traceback. With standard output closed Python has no
sys.stdout (it is None), and the first reply was written to it; with standard
input closed the first request was read from it. Now the server says so in
one line, before it reads anything, and exits with status 2.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import mcp as mcp_mod

PING = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"})


def run_server(lines, **patches):
    """Feed `lines` (bytes, one message each) to serve() in-process; returns
    the parsed replies. Any exception out of serve() fails the test."""
    stdin = io.BytesIO(b"".join(line + b"\n" for line in lines))
    stdout = io.BytesIO()
    mcp_mod.serve({}, stdin=stdin, stdout=stdout)
    return [json.loads(row) for row in stdout.getvalue().splitlines()]


class TestTooDeepToParse(unittest.TestCase):
    def check(self, bomb):
        replies = run_server([bomb, PING.encode()])
        self.assertEqual(len(replies), 2, replies)
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.PARSE_ERROR)
        self.assertIsNone(replies[0]["id"])
        # and the server carried on
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})

    def test_a_hundred_thousand_open_brackets(self):
        self.check(b"[" * 100000)

    def test_a_hundred_thousand_open_objects(self):
        self.check(b'{"a":' * 100000)

    def test_deep_nesting_inside_a_request(self):
        self.check(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":'
                   + b"[" * 100000 + b"]" * 100000 + b"}")

    def test_it_does_not_depend_on_how_deep_this_python_can_parse(self):
        # Python 3.14 parsed 100000 levels on some machines (a limit that
        # follows the C stack): the answer is still "Parse error"
        deep = (b'{"jsonrpc":"2.0","id":1,"method":"ping","params":'
                + b"[" * 5000 + b"]" * 5000 + b"}")
        real_loads = json.loads

        def lenient(text, *a, **k):         # a parser that does not give up
            return {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []} \
                if len(text) > 5000 else real_loads(text, *a, **k)

        with mock.patch.object(mcp_mod.json, "loads", lenient):
            self.check(deep)

    def test_ordinary_nesting_and_brackets_in_strings_are_fine(self):
        self.assertFalse(mcp_mod._too_deep("[" * 150 + "]" * 150))
        self.assertTrue(mcp_mod._too_deep("[" * 201 + "]" * 201))
        self.assertFalse(mcp_mod._too_deep('{"a":"' + "[" * 1000 + '"}'))
        self.assertFalse(mcp_mod._too_deep('{"a":"\\"' + "[" * 1000 + '"}'))
        self.assertTrue(mcp_mod._too_deep('{"a":"x\\\\",' + '"b":' + "[" * 300 + "]" * 300 + "}"))

    def test_a_bomb_between_good_messages(self):
        replies = run_server([PING.encode(), b"[" * 100000, PING.encode()])
        self.assertEqual([r.get("id") for r in replies], [7, None, 7])


class TestAReplyThatCannotBeWritten(unittest.TestCase):
    """An `id` is echoed back, and it can be any JSON value. If echoing it is
    what fails, the server answers without it instead of dying."""

    def serve_with_reply(self, reply):
        replies = None
        with mock.patch.object(mcp_mod, "handle", lambda *a, **k: reply):
            replies = run_server([PING.encode()])
        return replies

    def test_a_reply_nested_too_deep_to_write(self):
        # 5000 levels: json.dumps may or may not manage that (it depends on
        # the Python version and platform); the answer must not depend on it
        deep = []
        for _ in range(5000):
            deep = [deep]
        replies = self.serve_with_reply(
            {"jsonrpc": "2.0", "id": deep, "result": {}})
        self.assertEqual(len(replies), 1)
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.INTERNAL_ERROR)
        self.assertIsNone(replies[0]["id"])

    def test_a_reply_nested_too_deep_even_when_dumps_copes(self):
        real = json.dumps
        with mock.patch.object(mcp_mod.json, "dumps", real):
            deep = []
            for _ in range(mcp_mod.MAX_JSON_DEPTH + 5):
                deep = [deep]
            replies = self.serve_with_reply(
                {"jsonrpc": "2.0", "id": deep, "result": {}})
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.INTERNAL_ERROR)

    def test_a_reply_that_refers_to_itself(self):
        loop = []
        loop.append(loop)
        replies = self.serve_with_reply(
            {"jsonrpc": "2.0", "id": loop, "result": {}})
        self.assertEqual(replies[0]["error"]["code"], mcp_mod.INTERNAL_ERROR)

    def test_the_server_carries_on_afterwards(self):
        calls = []

        def handle(request, *a, **k):
            calls.append(request.get("id"))
            if len(calls) == 1:
                loop = []
                loop.append(loop)
                return {"jsonrpc": "2.0", "id": loop, "result": {}}
            return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

        with mock.patch.object(mcp_mod, "handle", handle):
            replies = run_server([PING.encode(), PING.encode()])
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[1], {"jsonrpc": "2.0", "id": 7, "result": {}})


class TestTheRealCommand(unittest.TestCase):
    """The report's reproduction, with a real process and real pipes."""

    def test_the_reported_reproduction_ends_cleanly(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        env["PYTHONPATH"] = _isolation.REPO + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "stuntkey", "mcp"],
            input=b"[" * 100000 + b"\n" + PING.encode() + b"\n",
            capture_output=True, env=env, cwd=_isolation.mktemp(), timeout=120)
        self.assertEqual(proc.stderr.decode("utf-8", "replace"), "")
        self.assertEqual(proc.returncode, 0)
        rows = [json.loads(r) for r in proc.stdout.splitlines()]
        self.assertEqual([r.get("id") for r in rows], [None, 7])
        self.assertEqual(rows[0]["error"]["code"], mcp_mod.PARSE_ERROR)


INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {}}).encode() + b"\n"


class TestAClosedStandardStream(unittest.TestCase):
    def assertSaidSoOnce(self, code, err, which):
        self.assertEqual(code, 2, err)
        lines = err.strip().splitlines()
        self.assertEqual(len(lines), 1, err)
        self.assertTrue(lines[0].startswith("error: "), err)
        self.assertIn(f"standard {which} is closed", lines[0])
        self.assertNotIn("Traceback", err)
        self.assertNotIn("AttributeError", err)

    def main_with(self, *, stdin, stdout):
        """The command line's `mcp` with these as sys.stdin / sys.stdout (None
        is what Python has when the process was started with them closed)."""
        err = io.StringIO()
        with mock.patch.object(sys, "stdin", stdin), \
                mock.patch.object(sys, "stdout", stdout), \
                contextlib.redirect_stderr(err):
            code = cli_mod.main(["mcp"])
        return code, err.getvalue()

    def test_a_closed_standard_output_is_one_line_and_status_2(self):
        stdin = io.BytesIO(INITIALIZE)
        code, err = self.main_with(stdin=stdin, stdout=None)
        self.assertSaidSoOnce(code, err, "output")
        self.assertEqual(stdin.tell(), 0, "a request was read before the "
                                          "server knew it could answer")

    def test_a_closed_standard_input_is_one_line_and_status_2(self):
        stdout = io.BytesIO()
        code, err = self.main_with(stdin=None, stdout=stdout)
        self.assertSaidSoOnce(code, err, "input")
        self.assertEqual(stdout.getvalue(), b"")

    def test_both_closed_is_still_one_line(self):
        code, err = self.main_with(stdin=None, stdout=None)
        self.assertSaidSoOnce(code, err, "input")

    def test_the_library_call_says_the_same(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stdout", None), \
                contextlib.redirect_stderr(err):
            code = mcp_mod.serve({}, stdin=io.BytesIO(INITIALIZE))
        self.assertSaidSoOnce(code, err.getvalue(), "output")

    def test_streams_that_are_given_are_used_even_when_the_real_ones_are_gone(self):
        # a caller that passes its own streams does not need sys.stdin/stdout
        stdin, stdout = io.BytesIO(INITIALIZE), io.BytesIO()
        with mock.patch.object(sys, "stdin", None), \
                mock.patch.object(sys, "stdout", None):
            self.assertEqual(mcp_mod.serve({}, stdin=stdin, stdout=stdout), 0)
        self.assertEqual(json.loads(stdout.getvalue())["id"], 1)

    @unittest.skipIf(os.name == "nt", "there is no >&- or <&- on Windows; the "
                                      "tests above stand in for it")
    def test_in_a_real_process(self):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
        env["PYTHONPATH"] = _isolation.REPO + os.pathsep + env.get("PYTHONPATH", "")
        for redirect, which in ((">&-", "output"), ("<&-", "input"),
                                ("<&- >&-", "input")):
            with self.subTest(redirect):
                proc = subprocess.run(
                    ["sh", "-c", f'exec "$@" {redirect}', "sh", sys.executable,
                     "-m", "stuntkey", "mcp"],
                    input=None if "<" in redirect else INITIALIZE,
                    capture_output=True, env=env, cwd=_isolation.mktemp(),
                    timeout=60)
                self.assertEqual(proc.stdout, b"")
                self.assertSaidSoOnce(proc.returncode,
                                      proc.stderr.decode("utf-8", "replace"),
                                      which)

    def test_the_readme_says_so(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("standard input or standard output is closed",
                       "one `error:` line", "exit status 2"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
