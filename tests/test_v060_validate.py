"""0.6.0: verdicts - valid / limited / invalid - and the recipe fields behind them."""
import os
import unittest

import _isolation  # noqa: F401
from _stub import Stub
from stuntkey import recipes as recipes_mod
from stuntkey import validate as validate_mod

KEY = "fake-key-0123456789abcdef"


def spec(base, **over):
    s = {"method": "GET", "url": base + "/me", "auth": {"type": "bearer"},
         "expect": [200]}
    s.update(over)
    return s


class TestVerdicts(unittest.TestCase):
    def check(self, routes, **over):
        with Stub(routes) as stub:
            return validate_mod.validate_key(spec(stub.base, **over), KEY), stub

    def test_expected_status_is_valid(self):
        r, _ = self.check({("GET", "/me"): (200, "{}")})
        self.assertEqual(r.status, "valid")
        self.assertTrue(r)
        self.assertIsNone(r.note)

    def test_rejected_status_is_invalid_and_falsy(self):
        r, _ = self.check({("GET", "/me"): (401, "{}")})
        self.assertEqual(r.status, "invalid")
        self.assertFalse(r)

    def test_limited_status_is_truthy_and_carries_the_recipe_note(self):
        r, _ = self.check({("GET", "/me"): (403, "{}")},
                          limited=[{"status": 403, "meaning": "lacks permission X"}])
        self.assertEqual(r.status, "limited")
        self.assertTrue(r)
        self.assertEqual(r.note, "lacks permission X")

    def test_limited_beats_the_default_reject_list(self):
        # 403 is in the default reject list; a recipe that says 403 means "limited" wins
        r, _ = self.check({("GET", "/me"): (403, "")},
                          limited=[{"status": 403, "meaning": "m"}], reject=[401, 403])
        self.assertEqual(r.status, "limited")

    def test_without_a_limited_entry_403_is_still_dead(self):
        r, _ = self.check({("GET", "/me"): (403, "")})
        self.assertFalse(r)

    def test_body_rule_turns_a_401_into_limited(self):
        r, _ = self.check({("GET", "/me"): (401, '{"name":"restricted_api_key"}')},
                          body_rules=[{"status": 401, "body_contains": "restricted_api_key",
                                       "result": "limited", "meaning": "sending only"}])
        self.assertEqual((r.status, r.note), ("limited", "sending only"))

    def test_body_rule_is_case_insensitive(self):
        r, _ = self.check({("GET", "/me"): (401, "RESTRICTED_API_KEY")},
                          body_rules=[{"status": 401, "body_contains": "restricted_api_key",
                                       "result": "limited", "meaning": "m"}])
        self.assertEqual(r.status, "limited")

    def test_body_rule_that_does_not_match_leaves_401_dead(self):
        r, _ = self.check({("GET", "/me"): (401, '{"name":"invalid_api_key"}')},
                          body_rules=[{"status": 401, "body_contains": "restricted_api_key",
                                       "result": "limited", "meaning": "m"}])
        self.assertEqual(r.status, "invalid")

    def test_body_rule_for_another_status_is_ignored(self):
        r, _ = self.check({("GET", "/me"): (403, "restricted_api_key")},
                          body_rules=[{"status": 401, "body_contains": "restricted_api_key",
                                       "result": "limited", "meaning": "m"}])
        self.assertFalse(r)

    def test_body_rule_can_say_valid(self):
        r, _ = self.check({("GET", "/me"): (400, "quota")},
                          body_rules=[{"status": 400, "body_contains": "quota", "result": "valid"}])
        self.assertEqual(r.status, "valid")

    def test_unexpected_status_is_an_error_not_a_verdict(self):
        with Stub({("GET", "/me"): (500, "")}) as stub:
            with self.assertRaises(validate_mod.ValidationError):
                validate_mod.validate_key(spec(stub.base), KEY)

    def test_result_never_holds_the_vendors_answer(self):
        r, _ = self.check({("GET", "/me"): (401, "SECRETY restricted_api_key SECRETY")},
                          body_rules=[{"status": 401, "body_contains": "restricted_api_key",
                                       "result": "limited", "meaning": "fine"}])
        self.assertNotIn("SECRETY", repr((r.status, r.note)))

    def test_bool_equality_keeps_old_callers_working(self):
        self.assertTrue(validate_mod.Result("valid") == True)   # noqa: E712
        self.assertTrue(validate_mod.Result("invalid") == False)  # noqa: E712

    def test_a_body_is_read_only_when_a_rule_needs_it(self):
        # no body_rules: nothing of a 401 answer is read (the old promise)
        from unittest import mock
        with Stub({("GET", "/me"): (401, "x" * 100)}) as stub:
            with mock.patch.object(validate_mod, "_verdict", wraps=validate_mod._verdict) as v:
                validate_mod.validate_key(spec(stub.base), KEY)
            self.assertEqual(v.call_args.kwargs["body"], b"")

    def test_the_key_reaches_the_stub_in_the_header_only(self):
        _, stub = self.check({("GET", "/me"): (200, "{}")})
        self.assertEqual(stub.seen[0]["headers"]["authorization"], f"Bearer {KEY}")
        self.assertNotIn(KEY, stub.seen[0]["path"])


class TestSchema(unittest.TestCase):
    def base(self, **v):
        r = {"service": "acme", "display": "Acme", "key_url": "https://a.test/k",
             "env_var": "ACME_KEY", "steps": ["x"],
             "validate": {"method": "GET", "url": "https://a.test/me",
                          "auth": {"type": "bearer"}, "expect": [200]}}
        r["validate"].update(v)
        return r

    def bad(self, data, text=None):
        with self.assertRaises(recipes_mod.RecipeError) as cm:
            recipes_mod.validate_recipe(data)
        if text:
            self.assertIn(text, str(cm.exception))

    def test_limited_must_be_status_and_meaning(self):
        self.bad(self.base(limited=[{"status": 403}]), "limited")
        self.bad(self.base(limited="403"), "limited")
        self.bad(self.base(limited=[{"status": 99, "meaning": "x"}]), "limited")

    def test_limited_cannot_repeat_an_expected_status(self):
        self.bad(self.base(limited=[{"status": 200, "meaning": "x"}]), "repeats")

    def test_body_rules_shape(self):
        self.bad(self.base(body_rules=[{"status": 401, "body_contains": "", "result": "valid"}]), "body_rules")
        self.bad(self.base(body_rules=[{"status": 401, "body_contains": "x", "result": "maybe"}]), "body_rules")
        self.bad(self.base(body_rules=[{"status": 401, "body_contains": "x" * 101, "result": "valid"}]), "body_rules")

    def test_good_rules_load(self):
        recipes_mod.validate_recipe(self.base(
            limited=[{"status": 403, "meaning": "m"}],
            body_rules=[{"status": 401, "body_contains": "x", "result": "limited", "meaning": "m"}]))

    def test_least_privilege_shape(self):
        d = self.base()
        d["least_privilege"] = {"summary": ""}
        self.bad(d, "least_privilege")
        d["least_privilege"] = {"summary": "ok", "url": "http://x.test"}
        self.bad(d, "https")
        d["least_privilege"] = {"summary": "ok", "extra": 1}
        self.bad(d, "least_privilege")
        d["least_privilege"] = {"summary": "ok", "url": "https://x.test/y"}
        recipes_mod.validate_recipe(d)

    def test_unverified_shape(self):
        d = self.base()
        d["unverified"] = "validate.url"
        self.bad(d, "unverified")
        d["unverified"] = ["validate.url"]
        recipes_mod.validate_recipe(d)

    def test_accept_and_detect_must_compile(self):
        d = self.base()
        d["fields"] = [{"name": "key", "env_var": "ACME_KEY", "accept": "("}]
        self.bad(d, "accept")
        d["fields"] = [{"name": "key", "env_var": "ACME_KEY", "detect": "["}]
        self.bad(d, "detect")

    def test_detect_confidence_values(self):
        d = self.base()
        d["fields"] = [{"name": "key", "env_var": "ACME_KEY", "detect": "x{4}", "detect_confidence": "sure"}]
        self.bad(d, "detect_confidence")

    def test_post_is_refused_for_everyone_but_the_sts_call(self):
        self.bad(self.base(method="POST"), "GET or HEAD")
        d = self.base(method="POST", body="Action=Other")
        d["validate"]["auth"] = {"type": "aws_sigv4", "region": "us-east-1", "service": "sts"}
        d["fields"] = [{"name": "access_key_id", "env_var": "ACME_KEY"}, {"name": "secret_access_key", "env_var": "ACME_SECRET"}]
        self.bad(d, "GET or HEAD")

    def test_the_sts_post_is_allowed_exactly(self):
        d = self.base(method="POST", body=recipes_mod.STS_BODY)
        d["validate"]["auth"] = {"type": "aws_sigv4", "region": "us-east-1", "service": "sts"}
        d["fields"] = [{"name": "access_key_id", "env_var": "ACME_KEY"}, {"name": "secret_access_key", "env_var": "ACME_SECRET"}]
        recipes_mod.validate_recipe(d)


class TestFieldsAcceptVersusDetect(unittest.TestCase):
    def test_legacy_pattern_fills_both(self):
        f = recipes_mod.fields({"env_var": "X", "fields": [{"name": "key", "env_var": "X", "pattern": "^a+$"}]})[0]
        self.assertEqual((f["accept"], f["detect"], f["detect_confidence"]), ("^a+$", "^a+$", "known"))

    def test_detect_only_is_a_guess_and_has_no_gate(self):
        f = recipes_mod.fields({"env_var": "X", "fields": [{"name": "key", "env_var": "X", "detect": "gsk_x+"}]})[0]
        self.assertIsNone(f["accept"])
        self.assertEqual(f["detect_confidence"], "guess")

    def test_accept_only_is_also_what_scan_looks_for_as_known(self):
        f = recipes_mod.fields({"env_var": "X", "fields": [{"name": "key", "env_var": "X", "accept": "^sk-"}]})[0]
        self.assertEqual((f["accept"], f["detect"], f["detect_confidence"]), ("^sk-", "^sk-", "known"))

    def test_no_fields_has_neither(self):
        f = recipes_mod.fields({"env_var": "X"})[0]
        self.assertEqual((f["accept"], f["detect"]), (None, None))


if __name__ == "__main__":
    unittest.main()
