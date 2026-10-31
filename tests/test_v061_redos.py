"""0.6.1: no recipe pattern (built-in or user) can be made to run for long."""
import re
import time
import unittest

import _isolation  # noqa: F401
from stuntkey import clipboard, recipes

CAT = recipes.load_recipes(recipes.RECIPES_DIR)
BIG = 1_000_000


def adversarial(prefix=""):
    return [prefix + "a" * BIG, prefix + "A1" * (BIG // 2), prefix + "-" * BIG,
            (prefix + "-") * (BIG // (len(prefix) + 1)), prefix + "a" * BIG + "!", " ".join([prefix + "x"] * (BIG // 8)),
            ("sk-" + prefix) * (BIG // 8), "0" * BIG, "\n".join([prefix + "k=" + "a" * 50] * (BIG // 60))]


class BuiltIns(unittest.TestCase):
    def test_every_pattern_is_fast_on_a_megabyte(self):
        worst = 0.0
        for slug, rec in CAT.items():
            for f in recipes.fields(rec):
                for key in ("accept", "detect"):
                    pat = f[key]
                    if not pat:
                        continue
                    rx = re.compile(pat)
                    for text in adversarial(pat[:4].strip("^(")):
                        t = time.perf_counter()
                        rx.search(text)
                        dt = time.perf_counter() - t
                        worst = max(worst, dt)
                        self.assertLess(dt, 5.0, f"{slug} {key} took {dt:.1f}s")
        self.assertLess(worst, 5.0)

    def test_looks_like_is_fast_on_a_megabyte(self):
        for text in adversarial():
            for pat in (None, "^sk-[A-Za-z0-9]{20,}", "^[a-z]+$"):
                t = time.perf_counter()
                clipboard.looks_like(text, pat)
                self.assertLess(time.perf_counter() - t, 1.0)

    def test_no_builtin_pattern_is_risky(self):
        for slug, rec in CAT.items():
            for f in recipes.fields(rec):
                for key in ("accept", "detect"):
                    if f[key]:
                        self.assertIsNone(recipes.regex_risk(f[key]), f"{slug} {key}")


class UserPatterns(unittest.TestCase):
    def recipe(self, pat, key="accept"):
        return {"display": "X", "service": "x", "env_var": "X_KEY", "key_url": "https://example.com/k",
                "steps": ["s"], "scopes": [], "validate": {"method": "GET", "url": "https://example.com/m",
                "auth": {"type": "bearer"}, "expect": [200]},
                "fields": [{"name": "key", "env_var": "X_KEY", key: pat}]}

    def test_catastrophic_patterns_are_refused(self):
        for pat in ("(a+)+$", "(a*)*b", "(a|aa)*b", "(.*a){9}", "(x+x+)+y", "^(([a-z])+.)+[A-Z]([a-z])+$",
                    "(a)\\1", "a{100000}", "(\\w+\\s?)*$"):
            with self.assertRaises(recipes.RecipeError, msg=pat):
                recipes.validate_recipe(self.recipe(pat))
            with self.assertRaises(recipes.RecipeError, msg=pat):
                recipes.validate_recipe(self.recipe(pat, "detect"))

    def test_a_plain_gate_is_accepted(self):
        recipes.validate_recipe(self.recipe("^sk-[A-Za-z0-9_-]{20,}"))

    def test_refused_pattern_would_really_be_slow(self):
        # the point of the rule: this one takes seconds on 28 characters
        rx = re.compile("(a+)+$")
        t = time.perf_counter()
        rx.search("a" * 24 + "!")
        self.assertGreater(time.perf_counter() - t, 0.2)
