"""0.6.0: run (manifest / .env / keychain, redaction), export, clipboard history."""
import base64
import binascii
import io
import json
import os
import random
import stat
import subprocess
import tempfile
import sys
import unittest
import urllib.parse
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import clipboard as clipboard_mod
from stuntkey import export as export_mod
from stuntkey import keychain as keychain_mod
from stuntkey import recipes as recipes_mod
from stuntkey import redact, runner

CAT = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
KEY = "sk_live_CANARY9f8e7d6c5b4a3928"
POSIX = os.name == "posix"


def proj(text=None):
    d = _isolation.mktemp()
    if text is not None:
        with open(os.path.join(d, ".env"), "w") as f:
            f.write(text)
    return d


class cd:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, *a):
        os.chdir(self.old)


class TestRedactorVariants(unittest.TestCase):
    def test_raw(self):
        self.assertEqual(redact.Redactor([KEY]).text(f"a {KEY} b"), "a [REDACTED] b")

    def test_standard_and_urlsafe_base64_at_every_alignment(self):
        r = redact.Redactor([KEY])
        for pre in ("", "a", "ab", "abc", "user:"):
            for suf in ("", "x", "xy", ":pw"):
                raw = (pre + KEY + suf).encode()
                for enc in (base64.b64encode(raw), base64.urlsafe_b64encode(raw),
                            base64.b64encode(raw).rstrip(b"=")):
                    out = r.text(enc.decode())
                    self.assertNotEqual(out, enc.decode(), (pre, suf, enc))

    def test_many_random_keys_every_alignment(self):
        rng = random.Random(7)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for _ in range(60):
            key = "".join(rng.choice(alphabet) for _ in range(rng.randint(8, 48)))
            r = redact.Redactor([key])
            for pre in ("", "q", "qr"):
                enc = base64.b64encode((pre + key).encode()).decode()
                self.assertNotEqual(r.text(enc), enc, (key, pre))

    def test_hex_percent_json_forms(self):
        key = 'pa/ss+w"ord=12345'
        r = redact.Redactor([key])
        for form in (binascii.hexlify(key.encode()).decode(), binascii.hexlify(key.encode()).decode().upper(),
                     urllib.parse.quote(key, safe=""), urllib.parse.quote_plus(key), json.dumps(key)[1:-1]):
            self.assertEqual(r.text("x" + form + "y"), "x[REDACTED]y", form)

    def test_short_values_are_not_redacted(self):
        self.assertEqual(redact.Redactor(["abc"]).text("abc abc"), "abc abc")

    def test_two_values(self):
        self.assertEqual(redact.Redactor(["secret-one-1", "secret-two-2"]).text("secret-two-2 secret-one-1"),
                         "[REDACTED] [REDACTED]")

    def test_value_that_contains_another(self):
        out = redact.Redactor(["abcdefgh", "abcdefghijkl"]).text("abcdefghijkl")
        self.assertEqual(out, "[REDACTED]")

    def test_unrelated_text_untouched(self):
        self.assertEqual(redact.Redactor([KEY]).text("hello world"), "hello world")

    def test_reversed_value_is_caught_since_the_merge_with_scrub(self):
        self.assertEqual(redact.Redactor([KEY]).text(KEY[::-1]), "[REDACTED]")

    def test_honest_limit_partial_print_is_not_caught(self):
        self.assertIn(KEY[:10], redact.Redactor([KEY]).text(KEY[:10]))


class TestRedactorStreaming(unittest.TestCase):
    def stream(self, data, size):
        r = redact.Redactor([KEY])
        out = b""
        for i in range(0, len(data), size):
            out += r.feed(data[i:i + size])
        return out + r.flush()

    def test_split_across_chunks_every_size(self):
        data = f"start {KEY} middle {KEY}\nend".encode()
        for size in range(1, len(data) + 1):
            self.assertEqual(self.stream(data, size), b"start [REDACTED] middle [REDACTED]\nend", size)

    def test_ordinary_lines_are_not_held_back(self):
        r = redact.Redactor([KEY])
        self.assertEqual(r.feed(b"progress: 10%\n"), b"progress: 10%\n")

    def test_a_possible_start_is_held_then_released(self):
        r = redact.Redactor([KEY])
        first = r.feed(b"hi sk_live_")
        self.assertEqual(first, b"hi ")
        self.assertEqual(r.feed(b"nope\n"), b"sk_live_nope\n")

    def test_flush_releases_the_tail(self):
        r = redact.Redactor([KEY])
        r.feed(b"sk_live_CAN")
        self.assertEqual(r.flush(), b"sk_live_CAN")

    def test_no_values_is_passthrough(self):
        r = redact.Redactor([])
        self.assertEqual(r.feed(b"abc"), b"abc")

    def test_binary_safe(self):
        data = bytes(range(256)) + KEY.encode() + b"\xff\xfe"
        out = self.stream(data, 7)
        self.assertNotIn(KEY.encode(), out)
        self.assertTrue(out.endswith(b"\xff\xfe"))

    def test_hits_are_counted(self):
        r = redact.Redactor([KEY])
        r.feed(f"{KEY}{KEY}".encode())
        self.assertEqual(r.hits, 2)


@unittest.skipUnless(POSIX and os.path.exists("/bin/sh"), "needs sh")
class TestRunRedactedForReal(unittest.TestCase):
    def go(self, script, secrets=(KEY,), env=None):
        out, err = io.BytesIO(), io.BytesIO()
        child = dict(os.environ, **(env or {}))
        code = runner.run_redacted(["/bin/sh", "-c", script], child, list(secrets), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def test_stdout_and_stderr_are_scrubbed(self):
        code, out, err = self.go(f'echo "out {KEY}"; echo "err {KEY}" >&2')
        self.assertEqual((code, out, err), (0, b"out [REDACTED]\n", b"err [REDACTED]\n"))

    def test_printing_the_environment_is_scrubbed(self):
        code, out, _ = self.go("env", env={"STRIPE_SECRET_KEY": KEY})
        self.assertIn(b"STRIPE_SECRET_KEY=[REDACTED]", out)
        self.assertNotIn(KEY.encode(), out)

    def test_base64_of_the_env_is_scrubbed(self):
        code, out, _ = self.go('printf %s "$K" | base64', env={"K": KEY})
        self.assertNotIn(base64.b64encode(KEY.encode()), out)

    def test_exit_status_passes_through(self):
        self.assertEqual(self.go("exit 7")[0], 7)

    def test_signal_status(self):
        self.assertEqual(self.go("kill -9 $$")[0], 137)

    def test_large_output_is_not_deadlocked_or_lost(self):
        code, out, err = self.go("i=0; while [ $i -lt 20000 ]; do echo line-$i-xxxxxxxxxxxxxxxxxxxx; i=$((i+1)); done; echo done >&2")
        self.assertEqual(code, 0)
        self.assertEqual(out.count(b"\n"), 20000)
        self.assertEqual(err, b"done\n")

    def test_stdin_is_inherited(self):
        r, w = os.pipe()
        os.write(w, b"hello\n")
        os.close(w)
        out = io.BytesIO()
        with os.fdopen(r) as stdin_file:
            old = os.dup(0)
            os.dup2(stdin_file.fileno(), 0)
            try:
                code = runner.run_redacted(["/bin/sh", "-c", "read x; echo got-$x"], dict(os.environ), [KEY],
                                           stdout=out, stderr=io.BytesIO())
            finally:
                os.dup2(old, 0)
                os.close(old)
        self.assertEqual(out.getvalue(), b"got-hello\n")

    def test_the_key_is_not_in_the_childs_argv(self):
        code, out, _ = self.go('tr "\\0" " " < /proc/$$/cmdline 2>/dev/null || ps -o args= -p $$', env={"K": KEY})
        self.assertNotIn(KEY.encode(), out)


class TestRunSources(unittest.TestCase):
    def recipe(self):
        return CAT["groq"]

    def gather(self, env_text, kc=None, prefer="keychain", backend="fake"):
        d = proj(env_text)
        return keychain_mod.gather(self.recipe(), backend, lambda s, v, b: kc,
                                   os.path.join(d, ".env"), prefer)

    def test_keychain_first(self):
        self.assertEqual(self.gather("GROQ_API_KEY=fromfile\n", "fromkeychain"), {"GROQ_API_KEY": "fromkeychain"})

    def test_env_file_when_keychain_has_none(self):
        self.assertEqual(self.gather("GROQ_API_KEY=fromfile\n", None), {"GROQ_API_KEY": "fromfile"})

    def test_prefer_env(self):
        self.assertEqual(self.gather("GROQ_API_KEY=fromfile\n", "fromkeychain", "env"), {"GROQ_API_KEY": "fromfile"})

    def test_nowhere_is_a_keychain_error(self):
        with self.assertRaises(keychain_mod.KeychainError):
            self.gather("", None)

    def test_keychain_unavailable_but_file_has_it(self):
        def boom(s, v, b):
            raise keychain_mod.KeychainUnavailable("hung")
        d = proj("GROQ_API_KEY=fromfile\n")
        got = keychain_mod.gather(self.recipe(), "fake", boom, os.path.join(d, ".env"))
        self.assertEqual(got, {"GROQ_API_KEY": "fromfile"})

    def test_keychain_unavailable_and_no_file_value_raises_unavailable(self):
        def boom(s, v, b):
            raise keychain_mod.KeychainUnavailable("hung")
        with self.assertRaises(keychain_mod.KeychainUnavailable):
            keychain_mod.gather(self.recipe(), "fake", boom, os.path.join(proj(""), ".env"))

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_env_file_symlink_is_not_followed(self):
        d = proj()
        with open(os.path.join(d, "real"), "w") as f:
            f.write("GROQ_API_KEY=viaLink\n")
        try:
            os.symlink(os.path.join(d, "real"), os.path.join(d, ".env"))
        except OSError:
            self.skipTest("no symlink right")
        self.assertIsNone(runner.env_file_value(os.path.join(d, ".env"), "GROQ_API_KEY"))

    def test_empty_value_is_absent(self):
        d = proj("GROQ_API_KEY=\n")
        self.assertIsNone(runner.env_file_value(os.path.join(d, ".env"), "GROQ_API_KEY"))

    def test_two_part_credentials_gather_both(self):
        d = proj("TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nTWILIO_AUTH_TOKEN=tok123456\n")
        got = keychain_mod.gather(CAT["twilio"], None, lambda *a: None, os.path.join(d, ".env"))
        self.assertEqual(set(got), {"TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"})

    def test_execute_injects_into_the_child_env_only(self):
        seen = {}
        keychain_mod.execute(["x"], {"A_KEY": "v" * 10}, {"PATH": "p"},
                             call=lambda cmd, env: seen.update(env=env, cmd=cmd) or 0)
        self.assertEqual(seen["env"]["A_KEY"], "v" * 10)
        self.assertNotIn("A_KEY", os.environ)
        self.assertEqual(seen["cmd"], ["x"])

    def test_redact_flag_chooses_popen_and_passes_the_values(self):
        got = {}

        def fake_run(cmd, env, secrets, popen=None, **kw):
            got.update(secrets=secrets)
            return 3
        with mock.patch.object(runner, "run_redacted", fake_run):
            code = keychain_mod.execute(["x"], {"A_KEY": "v" * 10}, {}, redact=True)
        self.assertEqual((code, got["secrets"]), (3, ["v" * 10]))

    def test_no_redact_uses_the_plain_call(self):
        called = []
        keychain_mod.execute(["x"], {}, {}, call=lambda *a, **k: called.append(1) or 0, redact=False)
        self.assertEqual(called, [1])


@unittest.skipUnless(POSIX, "needs sh")
class TestRunCli(unittest.TestCase):
    def run_cli(self, d, *argv):
        out, err = io.StringIO(), io.StringIO()
        with cd(d), mock.patch.object(keychain_mod, "detect_backend", return_value=None), \
                mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = cli_mod.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_run_from_the_env_file_with_redaction_on_by_default(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        # stdout of the child goes to the real fd via .buffer, so use a real process
        p = subprocess.run([sys.executable, "-c",
                            "import sys; from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))",
                            "run", "groq", "--", "sh", "-c", 'echo "k=$GROQ_API_KEY"'],
                           cwd=d, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONPATH=_isolation.REPO), timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "k=[REDACTED]\n")

    def test_no_redact_is_refused_when_output_is_a_pipe(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        p = subprocess.run([sys.executable, "-c",
                            "import sys; from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))",
                            "run", "--no-redact", "groq", "--", "sh", "-c", 'echo "k=${GROQ_API_KEY%%_*}"'],
                           cwd=d, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONPATH=_isolation.REPO), timeout=60)
        # 0.6.1: with output going to a pipe, --no-redact is refused
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(KEY, p.stdout + p.stderr)
        self.assertEqual(p.stdout, "")

    def test_missing_key_message_names_both_places(self):
        d = proj("")
        code, _, err = self.run_cli(d, "run", "groq", "--", "true")
        self.assertEqual(code, 1)
        self.assertIn(".env", err)
        self.assertNotIn("Traceback", err)

    def test_nothing_anywhere(self):
        d = proj()
        code, _, err = self.run_cli(d, "run", "groq", "--", "true")
        self.assertEqual(code, 1)
        self.assertIn("no OS keychain", err)

    def test_all_injects_every_manifest_service(self):
        d = proj("GROQ_API_KEY=" + KEY + "\nTAVILY_API_KEY=" + KEY[::-1] + "\n")
        with open(os.path.join(d, "stuntkey.json"), "w") as f:
            json.dump({"version": 1, "services": [{"service": "groq"}, {"service": "tavily"}]}, f)
        p = subprocess.run([sys.executable, "-c",
                            "import sys; from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))",
                            "run", "--all", "sh", "--", "-c", 'echo "$GROQ_API_KEY $TAVILY_API_KEY"'],
                           cwd=d, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONPATH=_isolation.REPO), timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "[REDACTED] [REDACTED]\n")

    def test_all_without_a_manifest(self):
        code, _, err = self.run_cli(proj(), "run", "--all", "true")
        self.assertEqual(code, 1)
        self.assertIn("stuntkey.json", err)

    def test_a_manifest_env_file_is_used(self):
        d = proj()
        os.makedirs(os.path.join(d, "cfg"))
        with open(os.path.join(d, "cfg", ".env"), "w") as f:
            f.write(f"GROQ_API_KEY={KEY}\n")
        with open(os.path.join(d, "stuntkey.json"), "w") as f:
            json.dump({"version": 1, "env_file": "cfg/.env", "services": [{"service": "groq"}]}, f)
        p = subprocess.run([sys.executable, "-c",
                            "import sys; from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))",
                            "run", "groq", "--", "sh", "-c", 'test -n "$GROQ_API_KEY"'],
                           cwd=d, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONPATH=_isolation.REPO), timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)


# ------------------------------------------------------------------ export

class TestExportArgv(unittest.TestCase):
    def test_github_argv_has_names_only(self):
        argv = export_mod.build_argv("github", "/usr/bin/gh", "GROQ_API_KEY", "me/app", "prod")
        self.assertEqual(argv, ["/usr/bin/gh", "secret", "set", "GROQ_API_KEY", "--repo", "me/app", "--env", "prod"])

    def test_github_minimal(self):
        self.assertEqual(export_mod.build_argv("github", "gh", "X_Y"), ["gh", "secret", "set", "X_Y"])

    def test_vercel_argv(self):
        self.assertEqual(export_mod.build_argv("vercel", "vercel", "X_Y"),
                         ["vercel", "env", "add", "X_Y", "production", "--sensitive"])
        self.assertEqual(export_mod.build_argv("vercel", "vercel", "X_Y", environment="preview", overwrite=True),
                         ["vercel", "env", "add", "X_Y", "preview", "--sensitive", "--force"])

    def test_no_body_or_value_flag_exists(self):
        for target in ("github", "vercel"):
            argv = export_mod.build_argv(target, "x", "NAME_1")
            self.assertNotIn("--body", argv)
            self.assertNotIn("-b", argv)
            self.assertNotIn("--value", argv)

    def test_bad_repo_refused(self):
        for bad in ("--evil", "a b/c", "a/b/c/d", "a;b/c", "-x/y", ""):
            if not bad:
                continue
            with self.assertRaises(export_mod.ExportError):
                export_mod.build_argv("github", "gh", "N", bad)

    def test_bad_name_refused(self):
        for bad in ("--x", "a b", "a=b", "1A"):
            with self.assertRaises(export_mod.ExportError):
                export_mod.build_argv("github", "gh", bad)

    def test_vercel_environment_must_be_known(self):
        with self.assertRaises(export_mod.ExportError):
            export_mod.build_argv("vercel", "vercel", "N", environment="staging")

    def test_vercel_has_no_repo(self):
        with self.assertRaises(export_mod.ExportError):
            export_mod.build_argv("vercel", "vercel", "N", repo="a/b")

    def test_github_environment_name_checked(self):
        with self.assertRaises(export_mod.ExportError):
            export_mod.build_argv("github", "gh", "N", environment="--x y")

    def test_unknown_target(self):
        with self.assertRaises(export_mod.ExportError):
            export_mod.build_argv("heroku", "x", "N")


class A:
    def __init__(self, **kw):
        self.__dict__.update(dict(service="groq", to="github", repo="acme/widgets", environment=None,
                                  env_file=None, overwrite=False, yes=True), **kw)


class TestExportFlow(unittest.TestCase):
    def go(self, env_text, run, **kw):
        d = proj(env_text)
        out = io.StringIO()
        args = A(env_file=os.path.join(d, ".env"), **kw)
        code = export_mod.cmd_export(args, CAT, out=out, which=lambda n: "/fake/" + n, run=run,
                                     read_fn=lambda *a: None, backend="fake",
                                     interactive=lambda: True)
        return code, out.getvalue()

    def test_value_goes_on_stdin_and_never_in_argv_or_output(self):
        calls = []

        def run(argv, input=None, **kw):
            calls.append((argv, input))
            return subprocess.CompletedProcess(argv, 0, b"Set secret", b"")
        code, text = self.go(f"GROQ_API_KEY={KEY}\n", run)
        self.assertEqual(code, 0)
        argv, stdin = calls[0]
        self.assertEqual(stdin, KEY.encode())
        self.assertFalse(any(KEY in a for a in argv))
        self.assertNotIn(KEY, text)
        self.assertIn("sent to github", text)

    def test_stdin_is_exact_no_newline(self):
        calls = []
        self.go(f"GROQ_API_KEY={KEY}\n", lambda argv, input=None, **kw:
                calls.append(input) or subprocess.CompletedProcess(argv, 0, b"", b""))
        self.assertFalse(calls[0].endswith(b"\n"))

    def test_failure_note_has_the_value_scrubbed_and_exit_1(self):
        def run(argv, input=None, **kw):
            return subprocess.CompletedProcess(argv, 1, b"", f"HTTP 422: value {KEY} too long".encode())
        code, text = self.go(f"GROQ_API_KEY={KEY}\n", run)
        self.assertEqual(code, 1)
        self.assertNotIn(KEY, text)
        self.assertIn("[REDACTED]", text)

    def test_tool_missing(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        out = io.StringIO()
        code = export_mod.cmd_export(A(env_file=os.path.join(d, ".env")), CAT, out=out,
                                     which=lambda n: None, read_fn=lambda *a: None, backend="fake")
        self.assertEqual(code, 1)
        self.assertIn("not installed", out.getvalue())

    def test_no_stored_key(self):
        code, text = self.go("", lambda *a, **k: self.fail("must not run"))
        self.assertEqual(code, 1)
        self.assertIn("stuntkey connect groq", text)

    def test_asks_first_without_yes_and_declines_by_default(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        out = io.StringIO()
        code = export_mod.cmd_export(A(env_file=os.path.join(d, ".env"), yes=False), CAT, ask=lambda p: "",
                                     window=lambda *a: None, interactive=lambda: True, out=out, which=lambda n: "/f/" + n,
                                     run=lambda *a, **k: self.fail("must not run"),
                                     read_fn=lambda *a: None, backend="fake")
        self.assertEqual(code, 1)
        self.assertIn("cancelled", out.getvalue())

    def test_no_terminal_and_no_yes_sends_nothing(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        out = io.StringIO()
        code = export_mod.cmd_export(A(env_file=os.path.join(d, ".env"), yes=False),
                                     CAT, window=lambda *a: None, interactive=lambda: False, out=out, which=lambda n: "/f/" + n,
                                     run=lambda *a, **k: self.fail("must not run"),
                                     read_fn=lambda *a: None, backend="fake")
        self.assertEqual(code, 1)
        self.assertIn("--yes", out.getvalue())

    def test_yes_answer_sends(self):
        d = proj(f"GROQ_API_KEY={KEY}\n")
        calls = []
        code = export_mod.cmd_export(A(env_file=os.path.join(d, ".env"), yes=False), CAT, ask=lambda p: "y",
                                     window=lambda *a: None, interactive=lambda: True, out=io.StringIO(), which=lambda n: "/f/" + n,
                                     run=lambda argv, input=None, **k: calls.append(1) or subprocess.CompletedProcess(argv, 0, b"", b""),
                                     read_fn=lambda *a: None, backend="fake")
        self.assertEqual((code, calls), (0, [1]))

    def test_two_part_credential_sends_each_variable(self):
        names = []

        def run(argv, input=None, **kw):
            names.append(argv[3])
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        d = proj("TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nTWILIO_AUTH_TOKEN=tok1234567\n")
        code = export_mod.cmd_export(A(service="twilio", env_file=os.path.join(d, ".env")), CAT, out=io.StringIO(),
                                     which=lambda n: "/f/" + n, run=run, read_fn=lambda *a: None, backend="fake",
                                     interactive=lambda: True)
        self.assertEqual((code, sorted(names)), (0, ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]))

    def test_timeout_is_a_message(self):
        def run(argv, input=None, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        code, text = self.go(f"GROQ_API_KEY={KEY}\n", run)
        self.assertEqual(code, 1)
        self.assertIn("did not finish", text)

    def test_oserror_is_a_message_without_text_of_the_error(self):
        def run(argv, input=None, **kw):
            raise OSError(f"cannot run {KEY}")
        code, text = self.go(f"GROQ_API_KEY={KEY}\n", run)
        self.assertEqual(code, 1)
        self.assertNotIn(KEY, text)

    def test_vercel_target(self):
        calls = []
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, ".vercel"))
        with open(os.path.join(d, ".vercel", "project.json"), "w") as f:
            f.write('{"projectName": "shop"}')
        old = os.getcwd()
        os.chdir(d)
        try:
            self.go(f"GROQ_API_KEY={KEY}\n", lambda argv, input=None, **k:
                    calls.append(argv) or subprocess.CompletedProcess(argv, 0, b"", b""), to="vercel", environment="preview", repo=None)
        finally:
            os.chdir(old)
        self.assertEqual(calls[0][1:], ["env", "add", "GROQ_API_KEY", "preview", "--sensitive"])

    def test_unknown_service(self):
        out = io.StringIO()
        export_mod.cmd_export(A(service=KEY), CAT, out=out)
        self.assertNotIn(KEY, out.getvalue())


@unittest.skipUnless(POSIX, "uses a stand-in gh script")
class TestExportWithAFakeGh(unittest.TestCase):
    """A real subprocess: a fake `gh` records its argv and stdin to files."""

    def test_the_real_pipe(self):
        bindir = _isolation.mktemp()
        log = os.path.join(bindir, "log")
        gh = os.path.join(bindir, "gh")
        with open(gh, "w") as f:
            f.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{log}.argv"\ncat > "{log}.stdin"\nexit 0\n')
        os.chmod(gh, 0o755)
        d = proj(f"GROQ_API_KEY={KEY}\n")
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"], PYTHONPATH=_isolation.REPO)
        p = subprocess.run([sys.executable, "-c",
                            "import sys; from stuntkey import dialog; dialog.confirm = lambda *a, **k: True; "
                            "from stuntkey.cli import main; sys.exit(main(sys.argv[1:]))",
                            "export", "groq", "--to", "github", "--repo", "me/app", "--yes"],
                           cwd=d, capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        with open(log + ".argv") as f:
            argv = f.read().split()
        with open(log + ".stdin") as f:
            stdin = f.read()
        self.assertEqual(argv, ["secret", "set", "GROQ_API_KEY", "--repo", "me/app"])
        self.assertEqual(stdin, KEY)
        self.assertNotIn(KEY, p.stdout + p.stderr)


# ------------------------------------------------------ clipboard history

class TestClipboardHistory(unittest.TestCase):
    def test_not_windows_no_warning(self):
        self.assertIsNone(clipboard_mod.history_warning("linux", lambda: {"history": True}))
        self.assertIsNone(clipboard_mod.history_warning("darwin", lambda: {"history": True}))

    def test_windows_with_history_on_warns_and_says_it_cannot_clear(self):
        w = clipboard_mod.history_warning("win32", lambda: {"history": True, "cloud": False})
        self.assertIn("Win+V", w)
        self.assertIn("cannot remove it", w)
        self.assertNotIn("Cloud", w)

    def test_cloud_sync_is_mentioned(self):
        self.assertIn("Cloud sync", clipboard_mod.history_warning("win32", lambda: {"history": True, "cloud": True}))

    def test_windows_history_off(self):
        self.assertIsNone(clipboard_mod.history_warning("win32", lambda: {"history": False, "cloud": False}))

    def test_unreadable_setting_is_no_warning(self):
        def boom():
            raise OSError("no key")
        self.assertIsNone(clipboard_mod.history_warning("win32", boom))

    def test_connect_falls_back_to_the_hidden_prompt_when_history_is_on(self):
        seen = {}

        def fake_connect(recipe, **kw):
            seen.update(kw)
            return 0
        with mock.patch.object(clipboard_mod, "backend", return_value=(lambda: "", lambda: None)), \
                mock.patch.object(clipboard_mod, "history_warning", return_value="HISTORY IS ON"), \
                mock.patch.object(cli_mod.connect_mod, "connect", fake_connect), \
                mock.patch("sys.stdout", io.StringIO()) as out:
            cli_mod.connect_service(CAT["groq"], env_file=os.path.join(proj(), ".env"), no_browser=True, clipboard=True)
        self.assertIsNone(seen["clipboard"])
        self.assertIn("HISTORY IS ON", out.getvalue())

    def test_allow_flag_keeps_copy_and_go(self):
        seen = {}
        with mock.patch.object(clipboard_mod, "backend", return_value=("g", "c")), \
                mock.patch.object(clipboard_mod, "history_warning", return_value="HISTORY IS ON"), \
                mock.patch.object(cli_mod.connect_mod, "connect", lambda r, **kw: seen.update(kw) or 0), \
                mock.patch("sys.stdout", io.StringIO()):
            cli_mod.connect_service(CAT["groq"], env_file=os.path.join(proj(), ".env"), no_browser=True,
                                    clipboard=True, allow_history=True)
        self.assertEqual(seen["clipboard"], ("g", "c"))

    def test_no_warning_no_fallback(self):
        seen = {}
        with mock.patch.object(clipboard_mod, "backend", return_value=("g", "c")), \
                mock.patch.object(clipboard_mod, "history_warning", return_value=None), \
                mock.patch.object(cli_mod.connect_mod, "connect", lambda r, **kw: seen.update(kw) or 0), \
                mock.patch("sys.stdout", io.StringIO()):
            cli_mod.connect_service(CAT["groq"], env_file=os.path.join(proj(), ".env"), no_browser=True, clipboard=True)
        self.assertEqual(seen["clipboard"], ("g", "c"))

    def test_the_module_docstring_states_the_limit(self):
        self.assertIn("clipboard history", clipboard_mod.__doc__.lower())


if __name__ == "__main__":
    unittest.main()
