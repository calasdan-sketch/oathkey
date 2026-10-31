"""A quoted value that runs over several lines belongs to its variable.

Panel finding (SEA-7): editing the .env file line by line, a line INSIDE
another variable's multi-line value that looked like `ACME_API_KEY=...` was
taken for an assignment. `connect` rewrote it (so the real variable was never
set and the other value was corrupted) and `forget` cut it out of the middle of
the other value. python-dotenv, Node dotenv and a shell all read such a line
as part of the value.

How the reader sees it (checked by hand with python-dotenv 1.2.3, Node dotenv
17.4.2 and bash): the value starts with a quote right after `=`, ends at the
first unescaped quote of the same kind that is followed by nothing but an
optional comment, and everything in between is the value. A quote that is never
closed, or is followed by other text, makes a one-line value.
"""

import io
import os
import types
import unittest

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import cli as cli_mod
from stuntkey import keychain as keychain_mod
from stuntkey import store as store_mod

KEY = "sk-forget-me-7731"
NO_KEYCHAIN = types.SimpleNamespace(detect_backend=lambda: None,
                                    label=keychain_mod.label,
                                    delete=lambda *a: False)
RECIPE = {"service": "acme", "display": "Acme", "env_var": "ACME_API_KEY",
          "key_url": "https://acme.test/keys", "steps": ["x"],
          "validate": {"method": "GET", "url": "https://acme.test/me",
                       "auth": {"type": "bearer"}, "expect": [200]}}

INSIDE = ('BIG="first\n'
          'ACME_API_KEY=not-the-key\n'
          'last"\n'
          'OTHER=1\n')


def env_with(text):
    path = os.path.join(_isolation.mktemp(), ".env")
    with open(path, "wb") as f:
        f.write(text.encode("utf-8"))
    return path


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8")


def forget(env):
    out = io.StringIO()
    code = cli_mod._cmd_forget(RECIPE, env, out=out, keychain=NO_KEYCHAIN)
    return code, out.getvalue()


class TestLinesInsideAnotherValueAreNotAssignments(unittest.TestCase):
    def test_connect_adds_the_variable_instead_of_rewriting_the_inside_line(self):
        env = env_with(INSIDE)
        stored = store_mod.store_key_result("ACME_API_KEY", KEY, env)
        self.assertFalse(stored.updated)
        self.assertEqual(stored.duplicates, 0)
        text = read(env)
        self.assertTrue(text.startswith(INSIDE), text)      # BIG is untouched
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], KEY)
        self.assertEqual(text.count("ACME_API_KEY="), 2)    # theirs + ours

    def test_forget_leaves_the_other_value_alone(self):
        env = env_with(INSIDE)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)
        self.assertEqual(read(env), INSIDE)
        code, text = forget(env)
        self.assertEqual(code, 0)
        self.assertIn("nothing stored", text)
        self.assertEqual(read(env), INSIDE)

    def test_the_real_assignment_after_the_value_is_the_one_that_counts(self):
        env = env_with(INSIDE + "ACME_API_KEY=real\n")
        stored = store_mod.store_key_result("ACME_API_KEY", KEY, env)
        self.assertTrue(stored.updated)
        self.assertEqual(stored.duplicates, 0)              # the inside line is no duplicate
        self.assertEqual(read(env), INSIDE + f"ACME_API_KEY={KEY}\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1)
        self.assertEqual(read(env), INSIDE)

    def test_the_real_assignment_before_the_value_too(self):
        env = env_with("ACME_API_KEY=real\n" + INSIDE)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1)
        self.assertEqual(read(env), INSIDE)

    def test_forget_counts_only_real_assignments(self):
        env = env_with("ACME_API_KEY=a\n" + INSIDE + "ACME_API_KEY=b\n")
        code, text = forget(env)
        self.assertEqual(code, 0, text)
        self.assertIn("appeared twice", text)
        self.assertEqual(read(env), INSIDE)

    def test_single_quotes_and_export(self):
        for text in ("export BIG='first\nACME_API_KEY=x\nlast'\nOTHER=1\n",
                     "BIG='first\nACME_API_KEY=x\nlast'\nOTHER=1\n",
                     'export BIG="first\nACME_API_KEY=x\nlast"\nOTHER=1\n',
                     'BIG= "first\nACME_API_KEY=x\nlast"\nOTHER=1\n'):
            with self.subTest(text=text):
                env = env_with(text)
                self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)
                self.assertEqual(read(env), text)

    def test_an_escaped_quote_does_not_end_the_value(self):
        text = 'BIG="say \\"hi\\"\nACME_API_KEY=x\nend"\nOTHER=1\n'
        env = env_with(text)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)
        self.assertEqual(read(env), text)

    def test_a_comment_after_the_closing_quote(self):
        text = 'BIG="a\nACME_API_KEY=x\nb" # note\nOTHER=1\n'
        env = env_with(text)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)
        self.assertEqual(read(env), text)

    def test_a_value_that_runs_over_many_lines(self):
        pem = "\n".join(["-----BEGIN KEY-----"] + ["MIIB" + "x" * 60] * 30
                        + ["ACME_API_KEY=also-inside", "-----END KEY-----"])
        text = f"BIG='{pem}'\nOTHER=1\n"
        env = env_with(text)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)
        self.assertEqual(read(env), text)

    def test_a_windows_file_comes_back_byte_for_byte(self):
        text = INSIDE.replace("\n", "\r\n")
        env = env_with(text + "ACME_API_KEY=real\r\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1)
        self.assertEqual(read(env), text)
        env = env_with(text)
        store_mod.store_key_result("ACME_API_KEY", KEY, env)
        out = read(env)
        self.assertTrue(out.startswith(text))
        self.assertTrue(out.endswith(f"ACME_API_KEY={KEY}\r\n"), out)

    def test_read_env_does_not_list_the_inside_line(self):
        env = env_with(INSIDE)
        lines, index = store_mod.read_env(env)
        self.assertEqual(index, {"BIG": 0, "OTHER": 3})
        self.assertEqual(lines[1], "ACME_API_KEY=not-the-key")   # still a line of the file
        self.assertNotIn("ACME_API_KEY", store_mod.load_env(env))


class TestWhereAQuoteDoesNotOpenAValue(unittest.TestCase):
    """Everything here is a one-line value, as the readers take it."""

    def assertOneLine(self, text):
        env = env_with(text)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1, text)
        self.assertNotIn("ACME_API_KEY", read(env))

    def test_a_quote_that_is_never_closed(self):
        self.assertOneLine('BIG="oops\nACME_API_KEY=real\nOTHER=1\n')
        self.assertOneLine("BIG='oops\nACME_API_KEY=real\nOTHER=1\n")

    def test_a_quote_closed_only_by_a_line_with_other_text_after_it(self):
        # Node dotenv reads BIG as `"first`, ACME_API_KEY as `real`
        self.assertOneLine('BIG="first\nACME_API_KEY=real\nOTHER="x"\n')

    def test_a_quote_in_the_middle_of_a_value_or_in_a_comment(self):
        self.assertOneLine('K=abc"def\nACME_API_KEY=real\nZ="x\n')
        self.assertOneLine('# a "comment\nACME_API_KEY=real\nZ="x\n')
        self.assertOneLine('\n"\nACME_API_KEY=real\nZ=1\n')

    def test_a_value_closed_on_its_own_line(self):
        self.assertOneLine('K="done" # "\nACME_API_KEY=real\nZ="x\n')
        self.assertOneLine("K='done'\nACME_API_KEY=real\nZ='x\n")
        # a later line with a stray quote at its end does not reopen it
        self.assertOneLine('K="done"\nACME_API_KEY=real\nZ=abc"\n')
        self.assertOneLine("K='done'\nACME_API_KEY=real\nZ=abc'\n")

    def test_the_other_kind_of_quote_does_not_close_it(self):
        env = env_with("BIG=\"a ' b\nACME_API_KEY=x\nc ' d\"\nOTHER=1\n")
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 0)


class TestTheVariableItselfRunsOverSeveralLines(unittest.TestCase):
    TEXT = 'BEFORE=1\nACME_API_KEY="line1\nline2"\nOTHER=1\n'

    def test_forget_takes_every_line_of_it(self):
        env = env_with(self.TEXT)
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1)
        self.assertEqual(read(env), "BEFORE=1\nOTHER=1\n")

    def test_connect_replaces_all_of_it_with_the_new_line(self):
        env = env_with(self.TEXT)
        stored = store_mod.store_key_result("ACME_API_KEY", KEY, env)
        self.assertTrue(stored.updated)
        self.assertEqual(stored.duplicates, 0)
        self.assertEqual(read(env), f"BEFORE=1\nACME_API_KEY={KEY}\nOTHER=1\n")

    def test_the_value_reads_back_whole(self):
        env = env_with(self.TEXT)
        self.assertEqual(store_mod.load_env(env)["ACME_API_KEY"], "line1\nline2")

    def test_at_the_end_of_the_file_and_in_a_windows_file(self):
        env = env_with('ACME_API_KEY="a\nb"')
        self.assertEqual(store_mod.remove_key("ACME_API_KEY", env), 1)
        self.assertEqual(read(env), "")
        env = env_with('X=1\r\nACME_API_KEY="a\r\nb"\r\nY=2\r\n')
        store_mod.store_key_result("ACME_API_KEY", KEY, env)
        self.assertEqual(read(env), f"X=1\r\nACME_API_KEY={KEY}\r\nY=2\r\n")


class TestMixedLineEndings(unittest.TestCase):
    def test_the_new_line_takes_the_ending_of_the_last_line_it_replaces(self):
        env = env_with('ACME_API_KEY="a\nb"\r\nY=2\r\n')
        store_mod.store_key_result("ACME_API_KEY", KEY, env)
        self.assertEqual(read(env), f"ACME_API_KEY={KEY}\r\nY=2\r\n")


class TestReadmeSaysSo(unittest.TestCase):
    def test_the_env_paragraph(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("runs over several lines",):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
