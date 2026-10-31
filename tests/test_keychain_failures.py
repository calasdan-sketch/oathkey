"""A keychain tool that hangs or cannot be started must not lose the key.

Panel finding (SEA-4): a hung `secret-tool` raised subprocess.TimeoutExpired
after 30 seconds. `connect --store keychain` then died with a traceback AFTER
the key had been validated - the key was lost - and `forget` died before it
touched the .env file. Now the tool failing is a KeychainError like any other:
connect falls back to the .env file, forget finishes the .env file and says
the keychain did not answer.
"""

import functools
import io
import os
import stat
import subprocess
import sys
import time
import unittest
from contextlib import contextmanager, redirect_stderr
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod

FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def hung(argv, **kw):
    raise subprocess.TimeoutExpired(argv, kw.get("timeout", 30))


def not_runnable(argv, **kw):
    raise FileNotFoundError(2, "No such file or directory", argv[0])


@contextmanager
def keychain_whose_tool(run, backend=keychain_mod.LINUX):
    """The keychain module as it is on a machine where `backend` exists and
    its tool misbehaves like `run`. (store/read/delete take `run` as a
    default argument, bound when they were defined, so patching
    subprocess.run would not reach them.)"""
    real = {name: getattr(keychain_mod, name)
            for name in ("store", "read", "delete")}
    with mock.patch.object(keychain_mod, "detect_backend",
                           return_value=backend), \
            mock.patch.object(keychain_mod, "store",
                              functools.partial(real["store"], run=run)), \
            mock.patch.object(keychain_mod, "read",
                              functools.partial(real["read"], run=run)), \
            mock.patch.object(keychain_mod, "delete",
                              functools.partial(real["delete"], run=run)):
        yield


class TestTheToolFailing(unittest.TestCase):
    backends = (keychain_mod.MACOS, keychain_mod.LINUX)

    def test_store_read_and_delete_raise_a_keychain_error_on_a_timeout(self):
        for backend in self.backends:
            calls = {
                "store": lambda: keychain_mod.store(
                    "acme", "ACME_API_KEY", FAKE_KEY, backend, run=hung),
                "read": lambda: keychain_mod.read(
                    "acme", "ACME_API_KEY", backend, run=hung),
                "delete": lambda: keychain_mod.delete(
                    "acme", "ACME_API_KEY", backend, run=hung),
            }
            for name, call in calls.items():
                with self.subTest(backend=backend, call=name):
                    with self.assertRaises(keychain_mod.KeychainUnavailable) as cm:
                        call()
                    self.assertIsInstance(cm.exception, keychain_mod.KeychainError)
                    text = str(cm.exception)
                    self.assertIn("did not answer", text)
                    self.assertNotIn(FAKE_KEY, text)

    def test_a_tool_that_cannot_be_started_is_the_same_kind_of_error(self):
        for backend in self.backends:
            with self.subTest(backend=backend):
                with self.assertRaises(keychain_mod.KeychainUnavailable) as cm:
                    keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                       backend, run=not_runnable)
                self.assertIn("could not be run", str(cm.exception))
                self.assertNotIn(FAKE_KEY, str(cm.exception))

    def test_a_plain_refusal_is_still_an_ordinary_keychain_error(self):
        run = lambda argv, **kw: mock.Mock(returncode=1, stdout=b"", stderr=b"")  # noqa: E731
        with self.assertRaises(keychain_mod.KeychainError) as cm:
            keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                               keychain_mod.LINUX, run=run)
        self.assertNotIsInstance(cm.exception, keychain_mod.KeychainUnavailable)


@unittest.skipIf(os.name == "nt", "needs a POSIX shell script to stand in for "
                 "secret-tool")
class TestARealHungProcess(unittest.TestCase):
    def test_a_secret_tool_that_sleeps_is_given_up_on_and_killed(self):
        folder = _isolation.mktemp()
        pidfile = os.path.join(folder, "pid")
        tool = os.path.join(folder, "secret-tool")
        with open(tool, "w", newline="\n") as f:
            f.write(f"#!/bin/sh\necho $$ > '{pidfile}'\nexec sleep 60\n")
        os.chmod(tool, os.stat(tool).st_mode | stat.S_IXUSR)
        path = folder + os.pathsep + os.environ.get("PATH", "")
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"PATH": path}), \
                mock.patch.object(keychain_mod, "TOOL_TIMEOUT", 1):
            with self.assertRaises(keychain_mod.KeychainUnavailable):
                keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                   keychain_mod.LINUX)
        self.assertLess(time.monotonic() - started, 30)
        with open(pidfile) as f:
            pid = int(f.read())
        time.sleep(0.2)
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)         # the hung tool is gone, not left running


class TestConnectKeepsTheKey(unittest.TestCase):
    def test_a_hung_keychain_falls_back_to_the_env_file(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        shown = io.StringIO()
        with keychain_whose_tool(hung):
            store_fn = cli_mod.keychain_store(
                recipe(), env, out=shown, backend=keychain_mod.LINUX,
                ask=lambda _p: "y", interactive=lambda: True)
            code = connect_mod.connect(
                recipe(), env_file=env, browser_open=lambda _u: None,
                prompt=lambda _t: FAKE_KEY, out=shown,
                validate_fn=lambda *_: True, store_fn=store_fn)
        self.assertEqual(code, 0)
        text = shown.getvalue()
        self.assertIn("did not answer", text)
        self.assertIn("could not keep the key", text)
        self.assertNotIn(FAKE_KEY, text)
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)

    def test_a_tool_that_will_not_start_falls_back_too(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        shown = io.StringIO()
        with keychain_whose_tool(not_runnable, keychain_mod.MACOS):
            store_fn = cli_mod.keychain_store(
                recipe(), env, out=shown, backend=keychain_mod.MACOS,
                ask=lambda _p: "y", interactive=lambda: True)
            code = connect_mod.connect(
                recipe(), env_file=env, browser_open=lambda _u: None,
                prompt=lambda _t: FAKE_KEY, out=shown,
                validate_fn=lambda *_: True, store_fn=store_fn)
        self.assertEqual(code, 0)
        self.assertIn("could not be run", shown.getvalue())
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)


class TestForgetFinishesTheEnvFile(unittest.TestCase):
    def forget(self, env_text):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        if env_text is not None:
            with open(env, "w", encoding="utf-8", newline="") as f:
                f.write(env_text)
        out = io.StringIO()
        with keychain_whose_tool(hung):
            code = cli_mod._cmd_forget(recipe(), env, out=out)
        return code, out.getvalue(), env

    def test_the_env_line_is_removed_and_the_keychain_problem_is_reported(self):
        code, text, env = self.forget(
            "OTHER=1\nACME_API_KEY=sk-forget-me-7731\nTAIL=2\n")
        with open(env, encoding="utf-8") as f:
            self.assertEqual(f.read(), "OTHER=1\nTAIL=2\n")
        self.assertEqual(code, 1)           # not everything was forgotten
        self.assertIn("did not answer", text)
        self.assertIn("may still", text)
        self.assertIn("removed ACME_API_KEY from", text)
        self.assertNotIn("sk-forget-me-7731", text)

    def test_it_never_claims_nothing_was_stored_when_it_could_not_look(self):
        code, text, _env = self.forget("OTHER=1\n")
        self.assertEqual(code, 1)
        self.assertIn("did not answer", text)
        self.assertNotIn("nothing stored", text)

    def test_with_no_env_file_at_all(self):
        code, text, _env = self.forget(None)
        self.assertEqual(code, 1)
        self.assertIn("did not answer", text)


class TestRunSaysSo(unittest.TestCase):
    def test_a_hung_keychain_is_a_message_and_exit_1(self):
        err = io.StringIO()
        with mock.patch.object(recipes_mod, "load_recipes",
                               return_value={"acme": recipe()}), \
                keychain_whose_tool(hung), redirect_stderr(err):
            code = cli_mod.main(["run", "acme", "--", sys.executable, "-c", "pass"])
        self.assertEqual(code, 1)
        self.assertIn("did not answer", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


class TestReadmeSaysSo(unittest.TestCase):
    def test_the_keychain_section_describes_a_tool_that_does_not_answer(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("does not answer within 30 seconds",
                       "before putting the key in the plain-text `.env` file"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
