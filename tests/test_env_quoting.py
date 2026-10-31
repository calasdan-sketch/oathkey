"""What a .env line holds, and what happens when something reads it.

The panel's finding (SEA-2): a value used to be written inside double
quotes, and a shell that sources the file runs `$(...)` and backticks inside
double quotes. A pasted "key" such as  a$(touch /tmp/x)b  became code that
runs the next time anybody ran `source .env`. Now a value is bare when it is
plain, single-quoted otherwise (a shell takes every character in single
quotes literally), and refused when it holds a character the .env readers do
not agree on - real API keys never do.

The shell tests run a real POSIX shell and are skipped where there is none
(Windows); the shlex tests cover the same quoting everywhere.
"""

import errno
import io
import os
import shlex
import shutil
import subprocess
import unittest

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import connect as connect_mod
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod

FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"

# Built from code points so no invisible character is typed into this file.
TAB, NL, CR, NUL, ESC, DEL = "\t", "\n", "\r", "\x00", "\x1b", "\x7f"
C1_NEL = chr(0x85)
NBSP = chr(0xA0)
ZERO_WIDTH_SPACE = chr(0x200B)
LINE_SEPARATOR = chr(0x2028)
BYTE_ORDER_MARK = chr(0xFEFF)
E_ACUTE = chr(0xE9)
CJK = chr(0x4E2D) + chr(0x6587)

POSIX_SHELLS = [] if os.name == "nt" else [
    s for s in ("sh", "bash") if shutil.which(s)]


def new_env_path():
    return os.path.join(_isolation.mktemp(), ".env")


def read_text(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8")


def source_with(shell, path, var="K"):
    """Source `path` in a real shell and return (what the variable holds,
    the exit status). The child gets no PYTHONUNBUFFERED (this sandbox sets
    it) and a throwaway HOME."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUNBUFFERED"}
    env["HOME"] = os.path.dirname(path)
    proc = subprocess.run(
        [shell, "-c", '. "$1" && printf %s "$' + var + '"', shell, path],
        capture_output=True, env=env, cwd=os.path.dirname(path), timeout=60)
    return proc.stdout.decode("utf-8"), proc.returncode


# Values a hostile recipe, a clipboard accident or an odd-but-real secret
# could hand over. {m} is replaced by a marker file in a temp directory: if
# the shell ever runs the payload, the file appears.
def tricky_values(marker):
    return [
        f"a$(touch {marker})b",
        f"a`touch {marker}`b",
        f"a;touch {marker};b",
        f"a&touch {marker}&b",
        f"a|touch {marker}",
        f"$(touch {marker})",
        "a$HOME",
        "$HOME",
        "pa$$word",
        "a$",
        "a$(",
        "a$ {HOME}",
        "a{HOME}b",
        "~",
        "~/x",
        "a:~b",
        "a b",
        " leading",
        "trailing ",
        "a  b",
        "a#b",
        "a #b",
        "#",
        'a"b',
        'a"b"c',
        "a>b",
        "a<b",
        "a*b?c[d]",
        "a!b",
        "50%",
        "(a)",
        "{a}",
        "x=y",
        "-n",
        "a" * 500,
        "caf" + E_ACUTE,
        CJK,
    ]


@unittest.skipUnless(POSIX_SHELLS, "needs a POSIX shell (sh or bash); the "
                     "shlex tests below cover the quoting on this platform")
class TestAShellThatSourcesTheFile(unittest.TestCase):
    """The finding itself, with the real thing: source the file."""

    def test_no_value_runs_anything_and_every_value_comes_back_exactly(self):
        for shell in POSIX_SHELLS:
            tmp = _isolation.mktemp()
            # forward slashes: a value may not contain a backslash, and a
            # POSIX shell on Windows (Git Bash) reads C:/x/marker
            marker = os.path.join(tmp, "marker").replace("\\", "/")
            for value in tricky_values(marker):
                with self.subTest(shell=shell, value=value[:40]):
                    env = os.path.join(tmp, ".env")
                    if os.path.exists(env):
                        os.remove(env)
                    store_mod.store_key("K", value, env)
                    got, rc = source_with(shell, env)
                    self.assertFalse(os.path.exists(marker),
                                     "sourcing the file ran the payload")
                    self.assertEqual(rc, 0)
                    self.assertEqual(got, value)

    def test_the_issue_reproduction_payload(self):
        # the exact value from the report, both forms of command substitution
        for shell in POSIX_SHELLS:
            tmp = _isolation.mktemp()
            marker = os.path.join(tmp, "PWNED").replace("\\", "/")
            for payload in (f"a$(touch {marker})b", f"a`touch {marker}`b"):
                env = os.path.join(tmp, ".env")
                if os.path.exists(env):
                    os.remove(env)
                store_mod.store_key("K", payload, env)
                got, _ = source_with(shell, env)
                self.assertFalse(os.path.exists(marker), shell)
                self.assertEqual(got, payload)

    def test_other_lines_of_the_file_are_untouched_and_still_work(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with open(env, "w", encoding="utf-8", newline="") as f:
            f.write("# comment\nOTHER=1\nK=old\nTAIL='x y'\n")
        store_mod.store_key("K", "ab#c d", env)
        self.assertEqual(read_text(env),
                         "# comment\nOTHER=1\nK='ab#c d'\nTAIL='x y'\n")
        for shell in POSIX_SHELLS:
            self.assertEqual(source_with(shell, env, "K"), ("ab#c d", 0))
            self.assertEqual(source_with(shell, env, "TAIL"), ("x y", 0))


class TestTheOnDiskForm(unittest.TestCase):
    def test_plain_values_stay_bare(self):
        for v in (FAKE_KEY, "sk_live_abc123", "a.b+c/d=e:f-g_h", "AIzaSy0",
                  "abc==", "=abc", "SG.abc-DEF_123.xyz", "0"):
            self.assertEqual(store_mod.quote_value(v), v)

    def test_a_tilde_is_never_bare(self):
        # a shell expands an unquoted ~ (alone, or after a colon) to $HOME
        self.assertEqual(store_mod.quote_value("~"), "'~'")
        self.assertEqual(store_mod.quote_value("a:~/b"), "'a:~/b'")

    def test_everything_else_is_single_quoted(self):
        for value, line in {
            "a b": "'a b'",
            "a#b": "'a#b'",
            'a"b': "'a\"b'",
            "a$b": "'a$b'",
            "a$(id)b": "'a$(id)b'",
            "a`id`b": "'a`id`b'",
            "a;b": "'a;b'",
            " x ": "' x '",
            "": "''",
            "caf" + E_ACUTE: "'caf" + E_ACUTE + "'",
        }.items():
            with self.subTest(value=value):
                self.assertEqual(store_mod.quote_value(value), line)

    def test_a_double_quoted_value_is_never_written(self):
        # inside double quotes a shell still expands $(...), `...` and $VAR
        env = new_env_path()
        for i, value in enumerate(tricky_values("/nonexistent/marker")):
            store_mod.store_key(f"V{i}", value, env)
        for line in read_text(env).splitlines():
            if line.strip():
                self.assertNotIn('="', line)

    def test_shlex_splits_the_line_back_into_the_value(self):
        # the same guarantee without needing a shell: one word, whole value
        env = new_env_path()
        for i, value in enumerate(tricky_values("/nonexistent/marker")):
            with self.subTest(value=value[:40]):
                if os.path.exists(env):
                    os.remove(env)
                store_mod.store_key("K", value, env)
                line = read_text(env).rstrip("\n")
                self.assertEqual(shlex.split(line, posix=True), ["K=" + value])

    def test_our_own_reader_gets_it_back(self):
        env = new_env_path()
        values = tricky_values("/nonexistent/marker")
        for i, value in enumerate(values):
            store_mod.store_key(f"V{i}", value, env)
        loaded = store_mod.load_env(env)
        for i, value in enumerate(values):
            self.assertEqual(loaded[f"V{i}"], value, repr(value[:40]))

    def test_the_old_double_quoted_form_is_still_read(self):
        # files written by 0.3.1 and earlier
        pv = store_mod.parse_value
        self.assertEqual(pv('"a b"'), "a b")
        self.assertEqual(pv('"a\\"b\\\\c"'), 'a"b\\c')
        env = new_env_path()
        with open(env, "w", encoding="utf-8", newline="") as f:
            f.write('K="ab#c d\\"e"\nJ=\'single\'\nI=bare\n')
        self.assertEqual(store_mod.load_env(env),
                         {"K": 'ab#c d"e', "J": "single", "I": "bare"})

    def test_rewriting_an_old_double_quoted_line_makes_it_safe(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        # a POSIX-style name, not a path under tmp: a Windows path has
        # backslashes, which a value may not contain
        marker = "/nonexistent/marker"
        with open(env, "w", encoding="utf-8", newline="") as f:
            f.write('K="old value"\nOTHER=1\n')
        store_mod.store_key("K", f"a$(touch {marker})b", env)
        self.assertEqual(read_text(env),
                         f"K='a$(touch {marker})b'\nOTHER=1\n")


# What cannot be written, and the words used for it. The value is never part
# of a message.
UNSTORABLE = [
    ("a single quote", "it's"),
    ("a single quote", "'"),
    ("a backslash", "back\\slash"),
    ("a backslash", "trailing\\"),
    ("a backslash", "double\\\\slash"),
    ("the characters ${", "a${HOME}b"),
    ("the characters ${", "${"),
    ("not printable", "tab" + TAB + "in"),
    ("not printable", "line" + NL + "break"),
    ("not printable", "trailing" + NL),
    ("not printable", "carriage" + CR + "return"),
    ("not printable", "nul" + NUL + "in"),
    ("not printable", "esc" + ESC + "[8min"),
    ("not printable", "del" + DEL + "in"),
    ("not printable", "nel" + C1_NEL + "in"),
    ("not printable", "ls" + LINE_SEPARATOR + "in"),
    ("not printable", "zero" + ZERO_WIDTH_SPACE + "width"),
    ("not printable", "nb" + NBSP + "sp"),
    ("not printable", BYTE_ORDER_MARK + "bom"),
    ("not printable", "lone" + chr(0xDC80) + "surrogate"),
]


class TestWhatIsRefused(unittest.TestCase):
    def test_each_unstorable_value_is_refused_with_a_reason(self):
        for words, value in UNSTORABLE:
            with self.subTest(value=repr(value)):
                reason = store_mod.unsafe_reason(value)
                self.assertIsNotNone(reason)
                self.assertIn(words, reason)
                with self.assertRaises(store_mod.UnsafeValue) as cm:
                    store_mod.quote_value(value)
                self.assertIn(words, cm.exception.strerror)

    def test_storable_values_have_no_reason(self):
        for value in tricky_values("/nonexistent/marker") + [FAKE_KEY, ""]:
            with self.subTest(value=value[:40]):
                self.assertIsNone(store_mod.unsafe_reason(value))

    def test_store_key_refuses_and_changes_nothing(self):
        for words, value in UNSTORABLE:
            with self.subTest(value=repr(value)):
                tmp = _isolation.mktemp()
                env = os.path.join(tmp, ".env")
                with self.assertRaises(store_mod.UnsafeValue) as cm:
                    store_mod.store_key_result("ACME_API_KEY", value, env)
                exc = cm.exception
                # an OSError, so every "could not save" handler copes
                self.assertIsInstance(exc, OSError)
                self.assertEqual(exc.errno, errno.EINVAL)
                self.assertEqual(exc.filename, env)
                self.assertIn(words, exc.strerror)
                # the value is never in what is shown (a one- or two-character
                # value such as "'" or "${" is part of the fixed wording)
                if len(value) > 6:
                    self.assertNotIn(value, str(exc))
                    self.assertNotIn(value, repr(exc))
                    self.assertNotIn(value, exc.strerror)
                # nothing written: no file, no leftover temp file
                self.assertEqual(os.listdir(tmp), [])

    def test_an_existing_file_is_left_exactly_as_it_was(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        before = b"A=1\r\nACME_API_KEY=old\r\n# caf\xe9\r\n"
        with open(env, "wb") as f:
            f.write(before)
        for _words, value in UNSTORABLE[:4]:
            with self.assertRaises(store_mod.UnsafeValue):
                store_mod.store_key("ACME_API_KEY", value, env)
        with open(env, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(os.listdir(tmp), [".env"])

    def test_the_message_says_why_and_how_to_go_on(self):
        exc = None
        try:
            store_mod.store_key("ACME_API_KEY", "it's", new_env_path())
        except store_mod.UnsafeValue as e:
            exc = e
        self.assertIn("single quote", exc.strerror)
        self.assertIn("real API keys do not", exc.strerror)


def recipe(**over):
    r = {"service": "acme", "display": "Acme",
         "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
         "steps": ["Click 'New key'"], "scopes": ["read"],
         "validate": {"method": "GET", "url": "https://acme.test/me",
                      "auth": {"type": "bearer"}, "expect": [200]}}
    r.update(over)
    return r


class TestConnectSaysSoBeforeSendingTheKey(unittest.TestCase):
    """The key is checked for storability right after the paste - before it
    is sent to the API - so a refusal costs nothing but a second paste."""

    def run_connect(self, keys, store_fn=None):
        prompts, seen, out = list(keys), [], io.StringIO()

        def prompt(_text):
            return prompts.pop(0)

        def validate(_spec, key):
            seen.append(key)
            return True

        env = new_env_path()
        code = connect_mod.connect(
            recipe(), env_file=env, browser_open=lambda _url: None,
            prompt=prompt, out=out, validate_fn=validate,
            confirm_in=lambda _: "yes", store_fn=store_fn)
        return code, seen, out.getvalue(), env

    def test_an_unstorable_key_is_never_sent_to_the_api(self):
        bad = "pasted'with-a-quote-7731"
        code, seen, text, env = self.run_connect([bad, bad, bad])
        self.assertEqual(code, 1)
        self.assertEqual(seen, [])
        self.assertFalse(os.path.exists(env))
        self.assertIn("single quote", text)
        self.assertIn("Nothing was sent", text)
        self.assertIn("giving up", text)
        self.assertNotIn(bad, text)

    def test_a_second_paste_can_succeed(self):
        code, seen, text, env = self.run_connect(["'" + FAKE_KEY + "'", FAKE_KEY])
        self.assertEqual(code, 0)
        self.assertEqual(seen, [FAKE_KEY])      # only the good one was sent
        self.assertIn("single quote", text)
        self.assertEqual(read_text(env), f"ACME_API_KEY={FAKE_KEY}\n")
        self.assertNotIn(FAKE_KEY, text)

    def test_every_kind_gets_its_own_words(self):
        for words, value in UNSTORABLE:
            if value != value.strip():
                continue    # connect() strips what was pasted before looking
            with self.subTest(value=repr(value)):
                code, seen, text, _env = self.run_connect([value, value, value])
                self.assertEqual((code, seen), (1, []))
                self.assertIn(words, text)
                if len(value) > 6:      # "'" or "${" occur in the fixed text
                    self.assertNotIn(value, text)

    def test_a_key_headed_for_the_keychain_is_not_held_to_the_env_rule(self):
        stored = []

        def keychain(env_var, key):
            stored.append((env_var, key))
            return "stored in the keychain"

        code, seen, _text, env = self.run_connect(["quote'd-key-7731"], store_fn=keychain)
        self.assertEqual((code, seen), (0, ["quote'd-key-7731"]))
        self.assertEqual(stored, [("ACME_API_KEY", "quote'd-key-7731")])
        self.assertFalse(os.path.exists(env))

    def test_a_fallback_to_the_env_file_still_ends_cleanly(self):
        # `--store keychain` on a machine without one saves to .env after the
        # key was validated; an unstorable key must end in the usual
        # "could NOT be saved" line, not a traceback
        env = new_env_path()
        store = connect_mod.store_in_env_file(env)
        out = io.StringIO()
        code = connect_mod.connect(
            recipe(), env_file=env, browser_open=lambda _u: None,
            prompt=lambda _t: "quote'd-key-7731", out=out,
            validate_fn=lambda *_: True,
            confirm_in=lambda _: "yes", store_fn=store)
        text = out.getvalue()
        self.assertEqual(code, 1)
        self.assertIn("could NOT be saved", text)
        self.assertIn("single quote", text)
        # a path is not the problem here, so it must not be offered as the cure
        self.assertNotIn("Fix the path", text)
        self.assertNotIn("quote'd-key-7731", text)
        self.assertFalse(os.path.exists(env))


class TestANameMayNotEndInANewline(unittest.TestCase):
    """`$` also matches in front of a final newline, so a recipe's
    env_var of  NAME + newline  passed the pattern and was written as the
    bare line  NAME  followed by  =<key>  - and a shell that sources the file
    runs a bare line as a command. The patterns now end at the end of the
    text."""

    def test_an_env_var_with_a_final_newline_is_not_a_valid_recipe(self):
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(recipe(env_var="REBOOT_ME" + NL))

    def test_a_slug_with_a_final_newline_is_not_valid(self):
        with self.assertRaises(recipes_mod.RecipeError):
            recipes_mod.validate_recipe(recipe(service="acme" + NL))
        self.assertIsNone(recipes_mod.SLUG_RE.match("acme" + NL))

    def test_the_store_refuses_it_too_and_writes_nothing(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        with self.assertRaises(ValueError):
            store_mod.store_key("REBOOT_ME" + NL, FAKE_KEY, env)
        self.assertEqual(os.listdir(tmp), [])

    def test_ordinary_names_still_pass(self):
        for name in ("ACME_API_KEY", "_x", "a1", "OPENAI_API_KEY"):
            self.assertTrue(recipes_mod.ENV_VAR_RE.match(name), name)
        for slug in ("github", "my-api", "a_b", "x" * 64):
            self.assertTrue(recipes_mod.SLUG_RE.match(slug), slug)
        self.assertIsNone(recipes_mod.SLUG_RE.match("x" * 65))
        recipes_mod.validate_recipe(recipe())


class TestReadmeTellsTheTruth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            cls.text = f.read()
        cls.flat = " ".join(cls.text.split())

    def test_the_false_claim_about_every_reader_is_gone(self):
        for claim in ("so Node dotenv, python-dotenv, docker compose and a shell "
                      "`source` all read the whole key back", "written double-quoted"):
            self.assertFalse(claim in self.flat,
                             f"the README still says: {claim!r}")

    def test_it_says_what_is_written_and_what_is_refused(self):
        for phrase in ("single-quoted", "takes every character inside single "
                       "quotes literally", "single quote, a backslash, `${`",
                       "refused"):
            self.assertTrue(phrase in self.flat,
                            f"the README does not say: {phrase!r}")

    def test_it_says_which_readers_were_checked_and_how(self):
        for phrase in ("python-dotenv 1.2.3", "Node dotenv 17.4.2",
                       "docker compose", "checked by hand"):
            self.assertTrue(phrase in self.flat,
                            f"the README does not say: {phrase!r}")

    def test_it_tells_people_with_an_old_file_what_to_do(self):
        for phrase in ("0.3.1 and earlier", "stuntkey rotate"):
            self.assertTrue(phrase in self.flat,
                            f"the README does not say: {phrase!r}")

    def test_no_hard_coded_test_count(self):
        import re
        self.assertIsNone(re.search(r"\b\d{2,4} tests\b", self.text))


if __name__ == "__main__":
    unittest.main()
