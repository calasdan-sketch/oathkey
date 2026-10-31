"""stuntkey.pyz, the npx shim, `start --simple` and the check after `install`."""
import json
import os
import shutil
import subprocess
import sys
import unittest

import _isolation
from stuntkey import clients, cmds, recipes as recipes_mod

REPO = _isolation.REPO
sys.path.insert(0, os.path.join(REPO, "scripts"))
import build_pyz  # noqa: E402


def _env(home):
    env = dict(os.environ)
    for var in ("HOME", "USERPROFILE"):
        env[var] = home
    return env


class Pyz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = _isolation.mktemp()
        cls.pyz, cls.win = build_pyz.build(cls.out)
        cls.home = _isolation.mktemp()

    def run_pyz(self, *argv):
        return subprocess.run([sys.executable, "-P" if sys.version_info >= (3, 11) else "-I",
                               self.pyz, *argv], capture_output=True, text=True,
                              env=_env(self.home), cwd=self.home, timeout=120)

    def test_the_recipes_load_from_the_pyz(self):
        r = self.run_pyz("list", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(json.loads(r.stdout)), len(recipes_mod.load_recipes(
            recipes_mod.RECIPES_DIR)))

    def test_the_skill_file_loads_from_the_pyz(self):
        r = self.run_pyz("skill", "install", "--project", "--yes")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(REPO, "stuntkey", "skill", "SKILL.md"), encoding="utf-8") as f:
            want = f.read()
        with open(os.path.join(self.home, ".claude", "skills", "stuntkey", "SKILL.md"),
                  encoding="utf-8") as f:
            self.assertEqual(f.read(), want)

    def test_mcp_entries_start_the_pyz_again(self):
        code = ("import stuntkey; stuntkey.PYZ = 'C:/x/stuntkey.pyz'; "
                "from stuntkey import clients; print(clients.server_entry(False)['args'])")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           cwd=REPO)
        self.assertIn("'C:/x/stuntkey.pyz', 'mcp'", r.stdout)
        self.assertEqual(clients.self_args(), ["-m", "stuntkey"])

    def test_hook_install_from_the_pyz_starts_the_pyz(self):
        settings = os.path.join(self.home, "hook-settings.json")
        r = self.run_pyz("hook", "install", "--settings", settings)
        # 0: the self-test ran the installed hook (through the .pyz) and it said no
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        with open(settings, encoding="utf-8") as f:
            text = json.dumps(json.load(f))
        self.assertIn(os.path.basename(self.pyz), text)
        self.assertNotIn('"-m", "stuntkey"', text)

    def test_hook_argv_uses_self_args(self):
        code = ("import stuntkey; stuntkey.PYZ = 'C:/x/stuntkey.pyz'; "
                "from stuntkey import hook; print(hook.hook_argv()[1:])")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           cwd=REPO)
        self.assertIn("['-I', 'C:/x/stuntkey.pyz', 'hook', 'check']", r.stdout, r.stderr)

    def test_the_windows_zip_has_the_launcher(self):
        import zipfile
        with zipfile.ZipFile(self.win) as z:
            self.assertEqual(sorted(z.namelist()), ["LICENSE", "stuntkey.cmd", "stuntkey.pyz"])


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class NpmShim(unittest.TestCase):
    def setUp(self):
        self.pkg = _isolation.mktemp()
        src = os.path.join(REPO, "packaging", "npm")
        shutil.copytree(os.path.join(src, "bin"), os.path.join(self.pkg, "bin"))
        self.js = os.path.join(self.pkg, "bin", "stuntkey.js")

    def test_runs_the_bundled_pyz(self):
        pyz, _ = build_pyz.build(self.pkg)
        self.assertTrue(os.path.exists(pyz))
        r = subprocess.run(["node", self.js, "--version"], capture_output=True, text=True,
                           env=_env(_isolation.mktemp()), timeout=120)
        from stuntkey import __version__
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(__version__, r.stdout)

    def test_says_plainly_when_python_is_missing(self):
        node = shutil.which("node")
        env = {"PATH": os.path.dirname(node)}
        if os.name != "nt":
            # node's own dir often holds python3 too (Homebrew /usr/local/bin
            # on macOS); give the shim a PATH with node and nothing else.
            only = _isolation.mktemp()
            os.symlink(os.path.realpath(node), os.path.join(only, "node"))
            env["PATH"] = only
        if os.name == "nt":
            env["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")
        r = subprocess.run([shutil.which("node"), self.js, "--version"], capture_output=True,
                           text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Install Python 3.10+ from python.org, then run again", r.stderr)


class StartSimple(unittest.TestCase):
    CATALOG = {"openai": {"service": "openai", "display": "OpenAI",
                          "env_var": "OPENAI_API_KEY"}}

    def go(self, answers, code=0):
        answers, said, ran = list(answers), [], []

        def run(argv):
            ran.append(argv)
            return code
        rc = cmds.cmd_start_simple(self.CATALOG, ask=lambda q: (said.append(q), answers.pop(0))[1],
                                   out=said.append, run=run)
        return rc, "\n".join(said), ran

    def test_happy_path(self):
        rc, text, ran = self.go(["4", "opnai", "openai", "example.com"])
        self.assertEqual(rc, 0)
        self.assertEqual(ran, [["get", "openai"], ["scan", "--bundle", "https://example.com"]])
        self.assertIn("Did you mean: openai", text)
        self.assertIn("never put it in a setting whose name starts with VITE_ or NEXT_PUBLIC_",
                      text.replace("Never", "never"))
        self.assertIn("OPENAI_API_KEY", text)
        self.assertIn("https://vercel.com/docs/environment-variables", text)
        self.assertIn("stuntkey export openai --to vercel", text)

    def test_enter_stops_and_a_failed_get_stops(self):
        self.assertEqual(self.go([""])[2], [])
        rc, _text, ran = self.go(["1", "openai"], code=1)
        self.assertEqual((rc, ran), (1, [["get", "openai"]]))


class InstallSaysWhatIsConnected(unittest.TestCase):
    def test_install_ends_with_the_connection_check(self):
        d = _isolation.mktemp()
        out = []
        answers = iter(["y", "n"])
        clients.run(["cursor", "claude-code"], False, ask=lambda q: next(answers),
                    out=out.append, home=d, cwd=d)
        self.assertIn("  Cursor: connected", out)
        self.assertIn("  Claude Code: not connected", out)


if __name__ == "__main__":
    unittest.main()
