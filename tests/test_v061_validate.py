"""0.6.1: key never in an error; redaction case variants; clock skew; limited 403."""
import unittest
import unittest.mock

import _isolation  # noqa: F401
from _stub import Stub
from stuntkey import redact as redact_mod
from stuntkey import validate as validate_mod

CANARY = "CANARYkey0123456789abcdef"


class TestRedirectNeverEchoesKey(unittest.TestCase):
    def test_query_auth_redirect_hides_query(self):
        with Stub() as stub:
            stub.routes[("GET", "/w")] = (301, "", {"Location": stub.base + "/other?appid=" + CANARY + "#frag"})
            spec = {"method": "GET", "url": stub.base + "/w", "auth": {"type": "query", "param": "appid"}, "expect": [200]}
            with self.assertRaises(validate_mod.ValidationError) as cm:
                validate_mod.validate_key(spec, CANARY)
            msg = str(cm.exception)
            self.assertNotIn(CANARY, msg)
            self.assertNotIn("appid", msg)
            self.assertIn("/other", msg)

    def test_safe_url_drops_query_and_fragment(self):
        self.assertEqual(validate_mod.safe_url("https://a.example/p/q?k=SECRET#f"), "https://a.example/p/q")

    def test_error_text_is_scrubbed_of_the_key(self):
        def boom(*a, **k):
            raise validate_mod.ValidationError("oops " + CANARY)
        orig = validate_mod._validate_key
        validate_mod._validate_key = boom
        try:
            with self.assertRaises(validate_mod.ValidationError) as cm:
                validate_mod.validate_key({}, CANARY)
        finally:
            validate_mod._validate_key = orig
        self.assertNotIn(CANARY, str(cm.exception))


class TestRedactCase(unittest.TestCase):
    def test_upper_and_lower_variants(self):
        r = redact_mod.Redactor([CANARY])
        for form in (CANARY.upper(), CANARY.lower()):
            self.assertNotIn(form.encode(), r.feed(("x " + form + "\n").encode()) + r.flush())


class TestClockSkew(unittest.TestCase):
    def aws(self, base):
        import copy
        from stuntkey import recipes
        spec = copy.deepcopy(recipes.load_recipes(recipes.RECIPES_DIR)["aws"]["validate"])
        spec["url"] = base + "/"
        spec["trusted_hosts"] = ["127.0.0.1"]
        return spec

    KEYS = {"access_key_id": "AKIA" + "A" * 16, "secret_access_key": "s" * 40}

    def date(self, minutes_ago):
        import datetime
        import email.utils
        t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=minutes_ago)
        return email.utils.format_datetime(t, usegmt=True)

    def test_skewed_clock_is_reported_not_called_dead(self):
        import datetime
        later = lambda: datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=20)
        with Stub({("POST", "/"): (403, "<Error>SignatureDoesNotMatch</Error>", {})}) as stub, \
                unittest.mock.patch.object(validate_mod, "_utcnow", later):
            with self.assertRaises(validate_mod.ClockSkew) as cm:
                validate_mod.validate_key(self.aws(stub.base), self.KEYS)
        self.assertIn("clock", str(cm.exception))
        self.assertNotIn(self.KEYS["secret_access_key"], str(cm.exception))

    def test_correct_clock_403_is_a_dead_key(self):
        with Stub({("POST", "/"): (403, "<Error/>", {"Date": self.date(0)})}) as stub:
            r = validate_mod.validate_key(self.aws(stub.base), self.KEYS)
        self.assertFalse(r)

    def test_connect_stops_without_using_up_tries(self):
        import io
        from stuntkey import connect
        asked = []
        def v(spec, key):
            raise validate_mod.ClockSkew(20, True)
        out = io.StringIO()
        rec = {"display": "X", "service": "x", "env_var": "X_KEY", "key_url": "https://example.com/k",
               "steps": ["go"], "scopes": [], "validate": {"method": "GET", "url": "https://example.com/m",
               "auth": {"type": "bearer"}, "expect": [200]}}
        code = connect.connect(rec, browser_open=lambda u: None,
                               prompt=lambda t: asked.append(1) or "abcdefghij1234567890",
                               out=out, validate_fn=v, store_fn=lambda a, b: "ok")
        self.assertEqual(code, 1)
        self.assertEqual(len(asked), 1)
        self.assertIn("clock", out.getvalue())


class TestOpenAILimited(unittest.TestCase):
    def spec(self, base):
        import copy
        from stuntkey import recipes
        s = copy.deepcopy(recipes.load_recipes(recipes.RECIPES_DIR)["openai"]["validate"])
        s["url"] = base + "/v1/models"
        return s

    def test_403_is_a_real_key_with_limits_and_401_is_dead(self):
        with Stub({("GET", "/v1/models"): (403, "{}", {})}) as stub:
            r = validate_mod.validate_key(self.spec(stub.base), "sk-test-0123456789abcdef")
        self.assertTrue(r)
        self.assertEqual(r.status, "limited")
        with Stub({("GET", "/v1/models"): (401, "{}", {})}) as stub:
            self.assertFalse(validate_mod.validate_key(self.spec(stub.base), "sk-test-0123456789abcdef"))
