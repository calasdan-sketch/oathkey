"""`run` with a command that cannot start, a child a signal stopped, and Ctrl-C.

Panel finding (SEA-8): `stuntkey run <service> -- nosuchcmd` ended in a
FileNotFoundError traceback - after the key had been read from the keychain -
and Ctrl-C anywhere (the MCP server, `run`) ended in a KeyboardInterrupt
traceback. On Windows `npm` was "not found" because CreateProcess looks for
`npm.exe`, not for the `npm.cmd` shim.

Now: a command that cannot start is one line on stderr and the shell's exit
status (127 not found, 126 found but not runnable), reported before the
keychain is asked for the key; a child stopped by a signal gives 128 + the
signal; Ctrl-C is "interrupted." and 130.
"""

import io
import os
import signal
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod

FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"
POSIX = os.name == "posix"
ESC = chr(27)
# A python that gets SIGINT delivered as KeyboardInterrupt even when the test
# runner itself was started with SIGINT ignored (a background job): that
# setting is inherited, and then Ctrl-C would do nothing at all.
RUNNER = ("import signal, sys; "
          "signal.signal(signal.SIGINT, signal.default_int_handler); "
          "from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))")


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def make_file(directory, name, mode=0o755, text="#!/bin/sh\nexit 0\n"):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)
    return path


def run_cli(*args, read=FAKE_KEY, call=None):
    """cli.main(['run', 'acme', '--', *args]) with a keychain that answers.
    Returns (exit status, stderr, the read mock, the call mock)."""
    err = io.StringIO()
    with mock.patch.object(recipes_mod, "load_recipes",
                           return_value={"acme": recipe()}), \
            mock.patch.object(keychain_mod, "detect_backend",
                              return_value=keychain_mod.LINUX), \
            mock.patch.object(keychain_mod, "read",
                              return_value=read) as read_mock, \
            mock.patch.object(keychain_mod.subprocess, "call",
                              **(call or {"return_value": 0})) as call_mock, \
            redirect_stderr(err), redirect_stdout(io.StringIO()), \
            mock.patch.object(cli_mod, "_is_tty", return_value=True):
        code = cli_mod.main(["run", "--no-redact", "acme", "--", *args])
    return code, err.getvalue(), read_mock, call_mock


class TestLocateProgram(unittest.TestCase):
    def env_for(self, *dirs):
        return {"PATH": os.pathsep.join(dirs)}

    def locate(self, name, *dirs, **kw):
        return keychain_mod.locate_program(name, self.env_for(*dirs),
                                           on_windows=False, **kw)

    def refused(self, name, *dirs):
        with self.assertRaises(keychain_mod.CannotRun) as cm:
            self.locate(name, *dirs)
        return cm.exception

    @unittest.skipUnless(POSIX, "needs execute permission bits")
    def test_a_program_that_is_there_is_left_as_typed(self):
        d = _isolation.mktemp()
        make_file(d, "tool")
        self.assertEqual(self.locate("tool", d), "tool")
        path = os.path.join(d, "tool")
        self.assertEqual(self.locate(path), path)

    def test_a_name_that_is_nowhere_is_command_not_found(self):
        d = _isolation.mktemp()
        e = self.refused("nosuchcmd-xyz", d)
        self.assertEqual(e.code, 127)
        self.assertIn("command not found", str(e))
        self.assertIn("nosuchcmd-xyz", str(e))
        self.assertEqual(self.refused("nosuchcmd-xyz").code, 127)   # empty PATH
        self.assertEqual(self.refused("").code, 127)
        self.assertEqual(self.refused(os.path.join(d, "missing")).code, 127)

    @unittest.skipUnless(POSIX, "needs execute permission bits")
    def test_a_file_that_is_not_executable_is_126_not_not_found(self):
        d = _isolation.mktemp()
        make_file(d, "deploy.sh", mode=0o644)
        for name in ("deploy.sh", os.path.join(d, "deploy.sh")):
            with self.subTest(name=name):
                e = self.refused(name, d)
                self.assertEqual(e.code, 126)
                self.assertIn("not an executable file", str(e))

    @unittest.skipUnless(POSIX, "needs execute permission bits")
    def test_a_directory(self):
        d = _isolation.mktemp()
        os.mkdir(os.path.join(d, "docs"))
        e = self.refused(os.path.join(d, "docs"), d)
        self.assertEqual(e.code, 126)
        self.assertIn("directory", str(e))
        # a directory on the PATH is not a command, as in a shell
        self.assertEqual(self.refused("docs", d).code, 127)

    @unittest.skipUnless(POSIX, "needs execute permission bits")
    def test_the_first_runnable_match_on_the_path_wins(self):
        a, b = _isolation.mktemp(), _isolation.mktemp()
        make_file(a, "tool", mode=0o644)
        make_file(b, "tool")
        self.assertEqual(self.locate("tool", a, b), "tool")

    @unittest.skipUnless(POSIX and os.path.exists("/bin/sh"), "needs /bin/sh")
    def test_without_a_path_variable_the_default_path_is_searched(self):
        # what subprocess does too (os.get_exec_path)
        self.assertEqual(keychain_mod.locate_program("sh", {}, on_windows=False),
                         "sh")

    def test_the_text_is_safe_to_print(self):
        name = "bad" + ESC + "[8mcmd\nforged: line"
        e = self.refused(name)
        self.assertTrue(str(e).isprintable(), ascii(str(e)))
        self.assertIn("\\x1b", str(e))

    def test_windows_finds_a_batch_shim_the_way_the_shell_does(self):
        seen = []

        def fake_which(name, path=None):
            seen.append((name, path))
            return {"npm": "C:\\nodejs\\npm.CMD", "old": "C:\\x\\old.bat",
                    "node": "C:\\nodejs\\node.EXE"}.get(name)

        def locate(name, env=None):
            return keychain_mod.locate_program(
                name, {"Path": "C:\\nodejs"} if env is None else env,
                which=fake_which, on_windows=True)

        self.assertEqual(locate("npm"), "C:\\nodejs\\npm.CMD")
        self.assertEqual(locate("old"), "C:\\x\\old.bat")
        # an executable is left to CreateProcess, as before
        self.assertEqual(locate("node"), "node")
        # PATH is looked up whatever the case of its name, as Windows does
        self.assertEqual(seen[0], ("npm", "C:\\nodejs"))
        with self.assertRaises(keychain_mod.CannotRun) as cm:
            locate("nosuchcmd")
        self.assertEqual(cm.exception.code, 127)

    def test_posix_leaves_the_name_alone_whatever_which_says(self):
        def fake_which(name, path=None):
            return "/usr/bin/npm.cmd"

        self.assertEqual(keychain_mod.locate_program(
            "npm", {"PATH": "/usr/bin"}, which=fake_which, on_windows=False),
            "npm")


class TestRunWithKeyLaunch(unittest.TestCase):
    def run_with(self, call):
        return keychain_mod.run_with_key(
            recipe(), ["prog", "arg"], keychain_mod.LINUX, env={},
            read_fn=lambda *a: FAKE_KEY, call=call)

    def test_a_child_a_signal_stopped_gives_128_plus_the_signal(self):
        for status, want in ((-9, 137), (-2, 130), (-15, 143), (-11, 139),
                             (0, 0), (1, 1), (7, 7), (255, 255)):
            with self.subTest(status=status):
                self.assertEqual(self.run_with(lambda cmd, env=None: status),
                                 want)

    def test_a_program_the_system_will_not_start_is_126(self):
        for exc in (FileNotFoundError(2, "No such file or directory", "prog"),
                    PermissionError(13, "Permission denied", "prog"),
                    OSError(8, "Exec format error", "prog"),
                    OSError(7, "Argument list too long"),
                    OSError("no number, no text")):
            def boom(cmd, env=None, exc=exc):
                raise exc
            with self.subTest(exc=repr(exc)):
                with self.assertRaises(keychain_mod.CannotRun) as cm:
                    self.run_with(boom)
                self.assertEqual(cm.exception.code, 126)
                text = str(cm.exception)
                self.assertIn("cannot run prog", text)
                self.assertNotIn(FAKE_KEY, text)
                self.assertTrue(text.isprintable(), ascii(text))
                if exc.strerror:
                    self.assertIn(exc.strerror, text)

    def test_ctrl_c_goes_through_untouched(self):
        def interrupted(cmd, env=None):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_with(interrupted)


class TestRunOnTheCommandLine(unittest.TestCase):
    def test_a_command_that_does_not_exist(self):
        code, err, read, call = run_cli("nosuchcmd-xyz", "--flag")
        self.assertEqual(code, 127)
        self.assertIn("command not found: nosuchcmd-xyz", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn(FAKE_KEY, err)
        # the keychain is not even asked: a typo should not cost an unlock
        read.assert_not_called()
        call.assert_not_called()

    @unittest.skipUnless(POSIX, "needs execute permission bits")
    def test_a_file_that_is_not_executable(self):
        d = _isolation.mktemp()
        path = make_file(d, "deploy.sh", mode=0o644)
        code, err, read, call = run_cli(path)
        self.assertEqual(code, 126)
        self.assertIn("cannot run", err)
        self.assertIn("not an executable file", err)
        self.assertNotIn("Traceback", err)
        read.assert_not_called()
        call.assert_not_called()

    def test_the_name_is_made_printable(self):
        code, err, _read, _call = run_cli("evil" + ESC + "[8m")
        self.assertEqual(code, 127)
        self.assertNotIn(ESC, err)
        self.assertIn("\\x1b", err)

    def test_a_program_the_system_refuses_after_all(self):
        code, err, read, _call = run_cli(
            sys.executable, "-c", "pass",
            call={"side_effect": OSError(8, "Exec format error", "prog")})
        self.assertEqual(code, 126)
        self.assertIn("Exec format error", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn(FAKE_KEY, err)
        read.assert_called_once()

    def test_a_child_that_was_killed(self):
        code, err, _read, _call = run_cli(sys.executable, "-c", "pass",
                                          call={"return_value": -9})
        self.assertEqual(code, 137)
        self.assertEqual(err, "")

    def test_the_childs_own_status_still_comes_back(self):
        for status in (0, 1, 3, 42):
            with self.subTest(status=status):
                code, _err, _read, call = run_cli(
                    sys.executable, "-c", "pass", call={"return_value": status})
                self.assertEqual(code, status)
                self.assertEqual(call.call_args.args[0],
                                 [sys.executable, "-c", "pass"])

    def test_ctrl_c_while_the_child_runs(self):
        code, err, _read, _call = run_cli(sys.executable, "-c", "pass",
                                          call={"side_effect": KeyboardInterrupt})
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("KeyboardInterrupt", err)


class TestCtrlCAnywhere(unittest.TestCase):
    def test_main_turns_it_into_a_message_and_130(self):
        err = io.StringIO()
        with mock.patch.object(cli_mod, "_main", side_effect=KeyboardInterrupt), \
                redirect_stderr(err):
            code = cli_mod.main(["list"])
        self.assertEqual(code, 130)
        self.assertEqual(err.getvalue().strip(), "interrupted.")

    def test_a_closed_stderr_does_not_make_it_worse(self):
        class Gone(io.StringIO):
            def write(self, text):
                raise OSError(9, "Bad file descriptor")
        with mock.patch.object(cli_mod, "_main", side_effect=KeyboardInterrupt), \
                redirect_stderr(Gone()):
            self.assertEqual(cli_mod.main(["list"]), 130)

    def test_any_command_not_only_run_and_mcp(self):
        # (the key paste and the cross-domain question have their own
        # "cancelled."; this is Ctrl-C anywhere else, the API call say)
        err = io.StringIO()
        with mock.patch.object(recipes_mod, "load_recipes",
                               return_value={"acme": recipe()}), \
                mock.patch("stuntkey.connect.connect",
                           side_effect=KeyboardInterrupt), \
                redirect_stderr(err):
            code = cli_mod.main(["connect", "acme", "--no-browser"])
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err.getvalue())


def child_env(*, front=None):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    if front:
        env["PATH"] = front + os.pathsep + env.get("PATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class TestCtrlCWhileTheReadersStart(unittest.TestCase):
    """CI (Python 3.12 and 3.14): Ctrl-C landed while `run` was still starting
    its output readers; the first reader was left running and Python died with
    "could not acquire lock for <stdout> at interpreter shutdown" (SIGABRT, -6)
    instead of 130. Every reader that started must be finished before the
    interrupt leaves run_redacted, and the child must not be left behind."""

    def fake_proc(self):
        proc = mock.Mock()
        proc.stdout = io.BytesIO(b"started\n")
        proc.stderr = io.BytesIO(b"")
        proc.poll.return_value = None
        proc.wait.return_value = -2
        return proc

    def test_interrupt_while_starting_readers_joins_the_started_ones(self):
        import threading
        from stuntkey import runner
        proc = self.fake_proc()
        real_start = threading.Thread.start
        starts = []

        def start(thread):
            starts.append(thread)
            if len(starts) == 2:
                raise KeyboardInterrupt
            real_start(thread)

        out, err = io.BytesIO(), io.BytesIO()
        with mock.patch.object(threading.Thread, "start", start), \
                self.assertRaises(KeyboardInterrupt):
            runner.run_redacted(["x"], {}, ["secret"], popen=lambda *a, **k: proc,
                                stdout=out, stderr=err)
        self.assertEqual(len(starts), 2)
        self.assertFalse(starts[0].is_alive(), "a reader was left running")
        self.assertEqual(out.getvalue(), b"started\n")

    @unittest.skipUnless(POSIX, "needs a POSIX SIGINT")
    def test_a_real_ctrl_c_during_the_start_waits_until_the_readers_are_up(self):
        import threading
        from stuntkey import runner
        before = signal.signal(signal.SIGINT, signal.default_int_handler)
        self.addCleanup(signal.signal, signal.SIGINT, before)
        proc = self.fake_proc()
        real_start = threading.Thread.start
        starts = []

        def start(thread):
            starts.append(thread)
            if len(starts) == 2:
                os.kill(os.getpid(), signal.SIGINT)     # lands mid-start
            real_start(thread)

        with mock.patch.object(threading.Thread, "start", start), \
                self.assertRaises(KeyboardInterrupt):
            runner.run_redacted(["x"], {}, [], popen=lambda *a, **k: proc,
                                stdout=io.BytesIO(), stderr=io.BytesIO())
        self.assertEqual(len(starts), 2, "both readers must have been started")
        self.assertFalse(any(t.is_alive() for t in starts))
        # and the handler is back the way it was
        self.assertIs(signal.getsignal(signal.SIGINT), signal.default_int_handler)

    def test_a_reader_that_cannot_start_does_not_leave_the_child_running(self):
        import threading
        from stuntkey import runner
        proc = self.fake_proc()
        with mock.patch.object(threading.Thread, "start",
                               side_effect=RuntimeError("can't start new thread")), \
                self.assertRaises(RuntimeError):
            runner.run_redacted(["x"], {}, [], popen=lambda *a, **k: proc,
                                stdout=io.BytesIO(), stderr=io.BytesIO())
        proc.kill.assert_called_once()


class TestRealProcesses(unittest.TestCase):
    """The same, with real operating-system processes and a real SIGINT."""

    @classmethod
    def setUpClass(cls):
        cls.bin = _isolation.mktemp()
        # a stand-in for the Secret Service tool: answers `lookup` with a key
        make_file(cls.bin, "secret-tool",
                  text='#!/bin/sh\n[ "$1" = lookup ] && printf %s "' + FAKE_KEY
                  + '" && exit 0\nexit 1\n')

    def cli(self, *args, **kw):
        return subprocess.run(
            [sys.executable, "-c", RUNNER, *args], cwd=_isolation.REPO,
            env=child_env(front=self.bin), capture_output=True, text=True,
            timeout=60, **kw)

    run_on = unittest.skipUnless(sys.platform.startswith("linux"),
                                 "uses a stand-in secret-tool")

    @run_on
    def test_a_command_that_does_not_exist(self):
        p = self.cli("run", "github", "--", "nosuchcmd-xyz")
        self.assertEqual(p.returncode, 127, p.stderr)
        self.assertIn("command not found: nosuchcmd-xyz", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.stdout, "")

    @run_on
    def test_a_file_that_is_not_executable(self):
        d = _isolation.mktemp()
        path = make_file(d, "deploy.sh", mode=0o644)
        p = self.cli("run", "github", "--", path)
        self.assertEqual(p.returncode, 126, p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    @run_on
    def test_exit_statuses_and_the_key_reaches_the_child(self):
        for script, want in (("exit 7", 7), ("exit 0", 0), ("kill -9 $$", 137),
                             ("kill -15 $$", 143),
                             ('test "$GITHUB_TOKEN" = "' + FAKE_KEY + '"', 0)):
            with self.subTest(script=script):
                p = self.cli("run", "github", "--", "sh", "-c", script)
                self.assertEqual(p.returncode, want, p.stderr)
                self.assertNotIn("Traceback", p.stderr)
                self.assertNotIn(FAKE_KEY, p.stdout + p.stderr)

    @run_on
    def test_ctrl_c_while_the_command_runs(self):
        # as a terminal does it: SIGINT to the whole foreground process group
        proc = subprocess.Popen(
            [sys.executable, "-c", RUNNER, "run", "github", "--", "sh", "-c",
             "echo started; exec sleep 60"],
            cwd=_isolation.REPO, env=child_env(front=self.bin),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "started")
            os.killpg(proc.pid, signal.SIGINT)
            err = proc.stderr.read()
            proc.wait(timeout=20)
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 130, err)
        self.assertIn("interrupted", err)
        self.assertNotIn("Traceback", err)

    @unittest.skipUnless(POSIX, "needs a POSIX SIGINT")
    def test_ctrl_c_stops_the_mcp_server(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", RUNNER, "mcp"], cwd=_isolation.REPO,
            env=child_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        try:
            proc.stdin.write(b'{"jsonrpc":"2.0","id":1,"method":"initialize",'
                             b'"params":{}}\n')
            proc.stdin.flush()
            # the server has answered, so it is now waiting for the next line
            self.assertIn(b'"result"', proc.stdout.readline())
            proc.send_signal(signal.SIGINT)
            err = proc.stderr.read().decode("utf-8", "replace")
            proc.wait(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()
        self.assertEqual(proc.returncode, 130, err)
        self.assertIn("interrupted", err)
        self.assertNotIn("Traceback", err)


class TestReadmeSaysSo(unittest.TestCase):
    def test_the_run_paragraph(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("command not found", "exit status 127", "126",
                       "128 plus the signal number", "exit status 130",
                       "`PATHEXT`"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
