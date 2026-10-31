"""Round 9: programs by full path, lock-down before the key is written, a
.gitignore warning, user recipes that replace built-ins, copy-and-go that
refuses links, a folder named .env, and the keychain never silently
downgrading to a plain-text file."""

import io
import json
import os
import shutil
import subprocess
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import clipboard as clipboard_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import procs
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod

FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": [],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


def run_connect(rec, env, **kw):
    out = io.StringIO()
    code = connect_mod.connect(
        rec, env_file=env, browser_open=kw.pop("browser_open", lambda u: None),
        prompt=kw.pop("prompt", lambda t: FAKE_KEY), out=out,
        validate_fn=kw.pop("validate_fn", lambda *_: True), **kw)
    return code, out.getvalue()


class TestProgramsByFullPath(unittest.TestCase):
    def test_system32_tool_path(self):
        self.assertEqual(procs.system32_tool("icacls.exe", {"SystemRoot": "D:\\Win"}),
                         "D:\\Win\\System32\\icacls.exe")
        self.assertEqual(procs.system32_tool("icacls.exe", {}),
                         "C:\\Windows\\System32\\icacls.exe")

    def test_icacls_is_not_started_by_bare_name(self):
        calls = []
        with mock.patch.object(store_mod.subprocess, "run",
                               lambda argv, **kw: calls.append(argv) or
                               types.SimpleNamespace(returncode=0)), \
                mock.patch.dict(os.environ, {"USERNAME": "dan"}):
            store_mod._windows_owner_only("C:\\x\\.env")
        self.assertNotEqual(calls[0][0].lower(), "icacls")
        self.assertTrue(calls[0][0].lower().endswith("system32\\icacls.exe"))

    def test_a_program_in_the_current_folder_is_not_taken_on_windows(self):
        cwd, good = _isolation.mktemp(), _isolation.mktemp()
        for d in (cwd, good):
            with open(os.path.join(d, "gh.exe"), "w") as f:
                f.write("x")
        env = {"PATH": os.pathsep.join([cwd, good]), "PATHEXT": ".exe"}
        found = procs.find_program("gh", which=lambda n: os.path.join(cwd, "gh.exe"),
                                   on_windows=True, environ=env, cwd=cwd)
        self.assertEqual(found, os.path.join(good, "gh.exe"))
        only_here = {"PATH": cwd, "PATHEXT": ".exe"}
        self.assertIsNone(procs.find_program(
            "gh", which=lambda n: os.path.join(cwd, "gh.exe"), on_windows=True,
            environ=only_here, cwd=cwd))

    def test_a_normal_hit_is_returned_absolute(self):
        d = _isolation.mktemp()
        exe = os.path.join(d, "gh")
        found = procs.find_program("gh", which=lambda n: exe, on_windows=False)
        self.assertEqual(found, exe)
        self.assertIsNone(procs.find_program("gh", which=lambda n: None))

    def test_via_cli_runs_gh_by_its_full_path(self):
        calls, logins = [], []
        rec = recipe(cli_token={"login": ["gh", "auth", "login", "--web"],
                                "token": ["gh", "auth", "token"]})
        exe = os.path.abspath(os.path.join(_isolation.mktemp(), "gh"))
        out = io.StringIO()
        token = connect_mod._cli_token(
            rec, out,
            run=lambda argv, **kw: calls.append(argv) or types.SimpleNamespace(
                returncode=0, stdout=b"ghp_FAKE\n"),
            call=lambda argv: logins.append(argv) or 0, which=lambda n: exe)
        self.assertEqual(token, "ghp_FAKE")
        self.assertEqual(calls, [[exe, "auth", "token"]])
        self.assertEqual(logins, [[exe, "auth", "login", "--web"]])


class TestLockDownBeforeTheKeyIsWritten(unittest.TestCase):
    def test_the_empty_temp_file_is_locked_first_then_checked_after_rename(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        seen = []
        real = store_mod._lock_down

        def spy(path):
            seen.append((os.path.basename(path), os.path.getsize(path)))
            return real(path)

        with mock.patch.object(store_mod, "_lock_down", spy):
            store_mod.write_private(env, "ACME_API_KEY=" + FAKE_KEY + "\n")
        self.assertEqual(len(seen), 2, seen)
        self.assertTrue(seen[0][0].endswith(".tmp"))
        self.assertEqual(seen[0][1], 0, "the key was already in the file")
        self.assertEqual(seen[1][0], ".env")


class TestGitIgnoreWarning(unittest.TestCase):
    def test_warns_only_when_git_says_not_ignored(self):
        def run_rc(rc):
            return lambda argv, **kw: types.SimpleNamespace(returncode=rc)
        f = lambda n: "/usr/bin/git"  # noqa: E731
        self.assertTrue(store_mod.env_not_git_ignored("/p/.env", f, run_rc(1)))
        self.assertFalse(store_mod.env_not_git_ignored("/p/.env", f, run_rc(0)))
        self.assertFalse(store_mod.env_not_git_ignored("/p/.env", f, run_rc(128)))
        self.assertFalse(store_mod.env_not_git_ignored("/p/.env", lambda n: None, run_rc(1)))

        def boom(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 10)
        self.assertFalse(store_mod.env_not_git_ignored("/p/.env", f, boom))

    def test_the_success_line_carries_the_warning(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        with mock.patch.object(store_mod, "env_not_git_ignored", return_value=True):
            text = connect_mod.store_in_env_file(env)("ACME_API_KEY", FAKE_KEY)
        self.assertIn("NOT in .gitignore", text)
        self.assertNotIn(FAKE_KEY, text)
        with mock.patch.object(store_mod, "env_not_git_ignored", return_value=False):
            self.assertNotIn("gitignore", connect_mod.store_in_env_file(env)(
                "ACME_API_KEY", FAKE_KEY))

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_with_a_real_repository(self):
        repo = _isolation.mktemp()
        subprocess.run(["git", "init", "-q", repo], check=True)
        env = os.path.join(repo, ".env")
        self.assertTrue(store_mod.env_not_git_ignored(env))
        with open(os.path.join(repo, ".gitignore"), "w") as f:
            f.write(".env\n")
        self.assertFalse(store_mod.env_not_git_ignored(env))
        self.assertFalse(store_mod.env_not_git_ignored(
            os.path.join(_isolation.mktemp(), ".env")))     # not a repository


class TestUserRecipeReplacingABuiltin(unittest.TestCase):
    def setUp(self):
        self.user = recipes_mod.user_recipes_dir()
        os.makedirs(self.user, exist_ok=True)
        self.path = os.path.join(self.user, "openai.json")
        builtin = {k: v for k, v in recipes_mod.load_recipes()["openai"].items()
                   if not k.startswith("_")}
        mine = dict(builtin, display="My OpenAI")   # same server: allowed

        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(mine, f)
        self.addCleanup(lambda: os.path.exists(self.path) and os.remove(self.path))

    def test_load_marks_the_override(self):
        cat = recipes_mod.load_recipes()
        self.assertTrue(cat["openai"]["_overrides_builtin"])
        self.assertFalse(cat["stripe"]["_overrides_builtin"])

    def test_list_and_connect_say_so(self):
        cat = recipes_mod.load_recipes()
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli_mod._cmd_list(cat)
        lines = [ln for ln in out.getvalue().splitlines() if "openai" in ln]
        self.assertIn("(your recipe, replaces the built-in)", lines[0])
        self.assertNotIn("replaces", "".join(ln for ln in out.getvalue().splitlines()
                                             if "stripe" in ln))
        env = os.path.join(_isolation.mktemp(), ".env")
        code, text = run_connect(cat["openai"], env, confirm_in=lambda p: "yes")
        self.assertIn("(your recipe, replaces the built-in)", text.split("Connect")[0])
        self.assertEqual(code, 0)

    def test_a_plain_user_recipe_is_not_flagged(self):
        os.remove(self.path)
        extra = os.path.join(self.user, "brandnew.json")
        with open(extra, "w", encoding="utf-8") as f:
            json.dump(dict(recipe(), service="brandnew"), f)
        self.addCleanup(lambda: os.path.exists(extra) and os.remove(extra))
        self.assertFalse(recipes_mod.load_recipes()["brandnew"]["_overrides_builtin"])


class TestClipboardRefusesLinks(unittest.TestCase):
    def test_links_are_not_keys(self):
        for v in ("https://dashboard.example.com/keys", "http://x.test/abcdefgh",
                  "HTTPS://example.com/abcdef"):
            self.assertFalse(clipboard_mod.looks_like(v, None), v)
            self.assertFalse(clipboard_mod.looks_like(v, r"\S{8,}"), v)
        self.assertTrue(clipboard_mod.looks_like("sk-abcdefgh12345678", None))

    def test_a_copied_link_is_never_taken(self):
        values = ["", "https://platform.example.com/keys", "sk-realkey1234567890"]
        state = {"i": 0}

        def get():
            v = values[min(state["i"], len(values) - 1)]
            state["i"] += 1
            return v
        got = clipboard_mod.wait_for_key(None, set(), get, lambda: None,
                                         wait=5, poll=0, sleep=lambda s: None)
        self.assertEqual(got, "sk-realkey1234567890")

    def test_the_prompt_says_the_clipboard_is_emptied(self):
        env = os.path.join(_isolation.mktemp(), ".env")
        feed = iter(["", FAKE_KEY])
        clip = (lambda: next(feed, FAKE_KEY), lambda: None)
        code, text = run_connect(recipe(), env, clipboard=clip, confirm_in=lambda p: "")
        self.assertEqual(code, 0)
        self.assertIn("EMPTY", text)
        self.assertNotIn(FAKE_KEY, text)

    def test_built_in_recipes_carry_key_patterns(self):
        cat = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        samples = {"openai": "sk-proj-abcdefghijklmnop1234", "anthropic": "sk-ant-api03-abcdefghijklmnop",
                   "groq": "gsk_abcdefghijklmnop1234", "huggingface": "hf_abcdefghijklmnop1234",
                   "replicate": "r8_abcdefghijklmnopqrstuvwxyz0123456789A", "sendgrid": "SG.abcdefghijklmnop.qrstuvwxyz1234",
                   "tavily": "tvly-abcdefghijklmnop1234", "openrouter": "sk-or-v1-abcdefghijklmnop12"}
        for slug, sample in samples.items():
            field = recipes_mod.fields(cat[slug])[0]
            # scan's heuristic (detect) exists for all of these; the copy-and-go
            # gate (accept) only for the documented shapes (see test_recipe_split)
            self.assertTrue(field["detect"], slug)
            gate = field["accept"]       # None = generic key shape
            self.assertTrue(clipboard_mod.looks_like(sample, gate), slug)
            self.assertFalse(clipboard_mod.looks_like("https://example.com/" + sample, gate), slug)
            if gate:
                self.assertFalse(clipboard_mod.looks_like("justaword", gate), slug)


class TestFolderNamedEnv(unittest.TestCase):
    def test_refused_before_the_browser_opens(self):
        d = _isolation.mktemp()
        env = os.path.join(d, ".env")
        os.mkdir(env)
        with self.assertRaises(OSError):
            store_mod.check_env_file(env)
        opened = []
        code, text = run_connect(recipe(), env, browser_open=opened.append,
                                 prompt=lambda t: self.fail("asked for a key"))
        self.assertEqual(code, 1)
        self.assertEqual(opened, [])
        self.assertIn("is a folder", text)
        self.assertIn("Nothing was asked for", text)


class FakeKeychain:
    KeychainError = keychain_mod.KeychainError

    def __init__(self, fail=None, backend=keychain_mod.LINUX):
        self.fail, self.backend, self.stored = fail, backend, []

    def detect_backend(self):
        return self.backend

    def store(self, service, var, key, backend):
        if self.fail:
            raise keychain_mod.KeychainError(self.fail)
        self.stored.append((service, var))
        return backend

    label = staticmethod(keychain_mod.label)


class TestKeychainNeverSilentlyDowngrades(unittest.TestCase):
    def attempt(self, kc, ask, interactive):
        env = os.path.join(_isolation.mktemp(), ".env")
        out = io.StringIO()
        fn = cli_mod.keychain_store(recipe(), env, out=out, keychain=kc,
                                    ask=ask, interactive=interactive)
        code, text = run_connect(recipe(), env, store_fn=fn)
        return code, text + out.getvalue(), env

    def test_no_terminal_means_exit_1_and_nothing_saved(self):
        code, text, env = self.attempt(
            FakeKeychain("vault locked"),
            lambda p: self.fail("asked with no terminal"), lambda: False)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(env))
        self.assertIn("Nothing was saved", text)
        self.assertNotIn(FAKE_KEY, text)

    def test_no_keychain_at_all_is_the_same(self):
        code, text, env = self.attempt(FakeKeychain(backend=None),
                                       lambda p: "y", lambda: False)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(env))

    def test_default_answer_is_no(self):
        for answer in ("", "n", "no", "maybe"):
            code, text, env = self.attempt(FakeKeychain("vault locked"),
                                           lambda p, a=answer: a, lambda: True)
            self.assertEqual(code, 1, answer)
            self.assertFalse(os.path.exists(env), answer)
            self.assertIn("nothing was saved", text)

    def test_yes_saves_to_the_env_file(self):
        prompts = []
        code, text, env = self.attempt(
            FakeKeychain("vault locked"),
            lambda p: prompts.append(p) or "y", lambda: True)
        self.assertEqual(code, 0)
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], FAKE_KEY)
        self.assertIn("[y/N]", prompts[0])

    def test_a_working_keychain_asks_nothing(self):
        kc = FakeKeychain()
        code, text, env = self.attempt(kc, lambda p: self.fail("asked"), lambda: False)
        self.assertEqual(code, 0)
        self.assertEqual(kc.stored, [("acme", "ACME_API_KEY")])
        self.assertFalse(os.path.exists(env))


class TestKeychainReadBack(unittest.TestCase):
    def run_fn(self, back):
        def run(argv, **kw):
            if argv[1] == "lookup":
                return types.SimpleNamespace(returncode=0 if back is not None else 1,
                                             stdout=(back or "").encode(), stderr=b"")
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        return run

    def test_a_matching_read_back_is_fine(self):
        self.assertEqual(keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                            keychain_mod.LINUX, run=self.run_fn(FAKE_KEY)),
                         keychain_mod.LINUX)

    def test_a_mismatch_or_a_missing_entry_is_a_keychain_error(self):
        for back in ("something-else", None, ""):
            with self.assertRaises(keychain_mod.KeychainError) as cm:
                keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY,
                                   keychain_mod.LINUX, run=self.run_fn(back))
            self.assertNotIn(FAKE_KEY, str(cm.exception))

    def test_a_read_back_that_hangs_is_a_keychain_error_too(self):
        def run(argv, **kw):
            if argv[1] == "lookup":
                raise subprocess.TimeoutExpired(argv, 30)
            return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with self.assertRaises(keychain_mod.KeychainError):
            keychain_mod.store("acme", "ACME_API_KEY", FAKE_KEY, keychain_mod.LINUX, run=run)


class TestRepoHygiene(unittest.TestCase):
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_ci_and_release_workflows_parse(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML is not installed")
        for name in ("ci.yml", "release.yml"):
            path = os.path.join(self.ROOT, ".github", "workflows", name)
            if not os.path.exists(path):
                self.skipTest("not a source checkout")
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self.assertIn("jobs", data)

    def test_gitattributes_normalises_line_endings(self):
        path = os.path.join(self.ROOT, ".gitattributes")
        if not os.path.exists(path):
            self.skipTest("not a source checkout")
        with open(path, encoding="utf-8") as f:
            self.assertIn("* text=auto", f.read())


if __name__ == "__main__":
    unittest.main()
