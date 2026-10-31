"""0.6.1: hostile env_file; manifest search stops at the project; connect/export use the manifest."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import manifest

BAD = ("README.md", "stuntkey.json", "src/app.py", "C:/x/.env", "C:\\x\\.env", "\\\\host\\share\\.env",
       "/etc/.env", "~/.env", "./.env", "a/./.env", "a//.env", "../.env", ".git/config", ".git/.env",
       "a/.GIT/.env", "x/.envrc", "notes.txt", "nul.env", ".env/../../x", "a\\..\\.env", ".env\x00.md")
GOOD = (".env", ".env.local", "config/.env", "prod.env", "a/b/.env.development")


def man(**extra):
    return dict({"version": 1, "services": [{"service": "openai"}]}, **extra)


class EnvFileRules(unittest.TestCase):
    def test_bad_names_refused(self):
        for v in BAD:
            with self.assertRaises(manifest.ManifestError, msg=repr(v)):
                manifest.validate(man(env_file=v))

    def test_good_names_accepted(self):
        for v in GOOD:
            manifest.validate(man(env_file=v))

    def test_symlinked_folder_escape(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlink")
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as other:
            os.symlink(other, os.path.join(root, "cfg"))
            with self.assertRaises(manifest.ManifestError):
                manifest.env_file_in(root, man(env_file="cfg/.env"))
            self.assertTrue(manifest.env_file_in(root, man(env_file=".env")).endswith(".env"))


class FindStops(unittest.TestCase):
    def test_no_git_root_means_only_here(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "stuntkey.json"), "w") as f:
                json.dump(man(), f)
            sub = os.path.join(d, "a", "b")
            os.makedirs(sub)
            self.assertIsNone(manifest.find(sub))
            self.assertIsNotNone(manifest.find(d))

    def test_does_not_climb_above_git_root(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "stuntkey.json"), "w") as f:
                json.dump(man(), f)
            proj = os.path.join(d, "proj")
            os.makedirs(os.path.join(proj, ".git"))
            os.makedirs(os.path.join(proj, "src"))
            self.assertIsNone(manifest.find(os.path.join(proj, "src")))
            with open(os.path.join(proj, "stuntkey.json"), "w") as f:
                json.dump(man(), f)
            self.assertEqual(manifest.find(os.path.join(proj, "src")),
                             os.path.realpath(os.path.join(proj, "stuntkey.json")))


class ConnectUsesManifest(unittest.TestCase):
    def test_connect_default_env_file_comes_from_the_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "stuntkey.json"), "w") as f:
                json.dump(man(env_file="config/.env.local"), f)
            seen = {}

            def fake(recipe, env_file=".env", **kw):
                seen["env"] = env_file
                return 0
            old = os.getcwd()
            os.chdir(d)
            try:
                with mock.patch.object(cli_mod, "connect_service", fake):
                    self.assertEqual(cli_mod.main(["connect", "openai"]), 0)
                    self.assertEqual(os.path.basename(seen["env"]), ".env.local")
                    cli_mod.main(["connect", "openai", "--env-file", "x.env"])
                    self.assertEqual(seen["env"], "x.env")
            finally:
                os.chdir(old)

    def test_bad_manifest_env_file_stops_connect(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "stuntkey.json"), "w") as f:
                json.dump({"version": 1, "services": [], "env_file": "README.md"}, f)
            old = os.getcwd()
            os.chdir(d)
            err = io.StringIO()
            try:
                with redirect_stderr(err), redirect_stdout(io.StringIO()):
                    code = cli_mod.main(["connect", "openai"])
            finally:
                os.chdir(old)
            self.assertEqual(code, 1)

    def test_project_dir_option(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            try:
                with redirect_stdout(io.StringIO()) as out:
                    cli_mod.main(["--project-dir", d, "status"])
                self.assertEqual(os.path.realpath(os.getcwd()), os.path.realpath(d))
            finally:
                os.chdir(old)


class FifoDoesNotHang(unittest.TestCase):
    def test_fifo_named_py_is_skipped(self):
        import threading
        from stuntkey import detect
        if not hasattr(os, "mkfifo"):
            self.skipTest("no fifo")
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(os.path.join(d, "trap.py"))
            with open(os.path.join(d, "ok.py"), "w") as f:
                f.write("import os\nos.environ['OPENAI_API_KEY']\n")
            result = {}
            t = threading.Thread(target=lambda: result.update(r=detect.names_in_project(d)), daemon=True)
            t.start()
            t.join(5)
            self.assertFalse(t.is_alive(), "the walk hung on a named pipe")
            self.assertIn("OPENAI_API_KEY", result["r"][0])


class ExportNamesTheTarget(unittest.TestCase):
    KEY = "gsk_" + "Ab3dE6gH9jK2mN5pQ8sT1vW4"

    def args(self, d, **kw):
        base = dict(service="groq", to="github", repo=None, environment=None,
                    env_file=os.path.join(d, ".env"), overwrite=False, yes=False)
        base.update(kw)
        return type("A", (), base)()

    def run_export(self, d, args, ask="y", **kw):
        import subprocess
        from stuntkey import export
        with open(os.path.join(d, ".env"), "w") as f:
            f.write(f"GROQ_API_KEY={self.KEY}\n")
        out, calls, prompts = io.StringIO(), [], []

        def run(argv, input=None, **k):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        cat = __import__("stuntkey.recipes", fromlist=["x"]).load_recipes(
            __import__("stuntkey.recipes", fromlist=["x"]).RECIPES_DIR)
        code = export.cmd_export(args, cat, ask=lambda p: prompts.append(p) or ask,
                                 interactive=lambda: True, out=out, which=lambda n: "/f/" + n,
                                 window=lambda *a: None,      # no pop-up in tests
                                 run=run, read_fn=lambda *a: None, backend="fake")
        return code, out.getvalue(), calls, prompts

    def test_repo_from_the_git_remote_is_named_and_passed_explicitly(self):
        import subprocess
        from stuntkey import export
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "init", "-q", d], check=True)
            subprocess.run(["git", "-C", d, "remote", "add", "origin", "git@github.com:acme/widgets.git"], check=True)
            self.assertEqual(export.github_repo_here(d), "acme/widgets")
            old = os.getcwd()
            os.chdir(d)
            try:
                code, text, calls, prompts = self.run_export(d, self.args(d))
            finally:
                os.chdir(old)
        self.assertEqual(code, 0)
        self.assertIn("acme/widgets", text)
        self.assertIn("acme/widgets", prompts[0])
        self.assertEqual(calls[0][-2:], ["--repo", "acme/widgets"])

    def test_no_repo_known_stops(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                code, text, calls, _ = self.run_export(d, self.args(d))
            finally:
                os.chdir(old)
        self.assertEqual((code, calls), (1, []))
        self.assertIn("--repo OWNER/REPO", text)

    def test_vercel_names_the_linked_project(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".vercel"))
            with open(os.path.join(d, ".vercel", "project.json"), "w") as f:
                json.dump({"projectId": "prj_abc123", "orgId": "team_x", "projectName": "my-shop"}, f)
            old = os.getcwd()
            os.chdir(d)
            try:
                code, text, calls, prompts = self.run_export(d, self.args(d, to="vercel"))
                code2, text2, calls2, _ = self.run_export(d, self.args(d, to="vercel"), ask="n")
            finally:
                os.chdir(old)
        self.assertEqual(code, 0)
        self.assertIn("my-shop", prompts[0])
        self.assertEqual((code2, calls2), (1, []))

    def test_vercel_unlinked_folder_stops(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.getcwd()
            os.chdir(d)
            try:
                code, text, calls, _ = self.run_export(d, self.args(d, to="vercel"))
            finally:
                os.chdir(old)
        self.assertEqual((code, calls), (1, []))
        self.assertIn("vercel link", text)
