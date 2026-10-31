"""Whose sub-domain is it? Hosting platforms and country registries.

Panel finding (SEA-6): connect asks for a typed "yes" when the validation URL
is on a different owner than the key page, and "owner" is the registrable
domain. The 100-entry suffix list missed a.run.app / evil.run.app, x.com.gr /
y.com.gr, a.blogspot.com / b.blogspot.com and a.myshopify.com /
b.myshopify.com, so each pair counted as ONE owner and the prompt never came,
although the key would go to somebody else's site.

The list is a compact snapshot, not the full Public Suffix List; the tests
below pin what it must get right and the README says what it does not.
"""

import io
import os
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import connect as connect_mod
from stuntkey import recipes as recipes_mod

rd = connect_mod.registrable_domain
same = connect_mod.same_owner
FAKE_KEY = "sk-test-THIS-IS-A-FAKE-KEY-999"


def url(host):
    return f"https://{host}/x"


def recipe(key_host, validate_host):
    return {"service": "acme", "display": "Acme",
            "key_url": url(key_host) + "/keys", "env_var": "ACME_API_KEY",
            "steps": ["Click 'New key'"], "scopes": ["read"],
            "validate": {"method": "GET", "url": url(validate_host),
                         "auth": {"type": "bearer"}, "expect": [200]}}


# Two hosts that belong to two different parties.
DIFFERENT = (
    # the panel's own examples
    ("a.run.app", "evil.run.app"),
    ("svc-1.a.run.app", "svc-2.a.run.app"),
    ("x.com.gr", "y.com.gr"),
    ("a.blogspot.com", "b.blogspot.com"),
    ("a.myshopify.com", "b.myshopify.com"),
    # the same kind of thing elsewhere
    ("bucket1.s3.amazonaws.com", "bucket2.s3.amazonaws.com"),
    ("bucket1.s3.us-west-2.amazonaws.com", "bucket2.s3.us-west-2.amazonaws.com"),
    ("abc123.execute-api.us-east-1.amazonaws.com",
     "def456.execute-api.us-east-1.amazonaws.com"),
    ("ec2-1-1-1-1.us-west-2.compute.amazonaws.com",
     "ec2-2-2-2-2.us-west-2.compute.amazonaws.com"),
    ("one.uc.r.appspot.com", "two.uc.r.appspot.com"),
    ("acct1.blob.core.windows.net", "acct2.blob.core.windows.net"),
    ("a.cloudfunctions.net", "b.cloudfunctions.net"),
    ("a.web.app", "b.web.app"),
    ("a.pages.dev", "b.pages.dev"),
    ("a.workers.dev", "b.workers.dev"),
    ("a.vercel.app", "b.vercel.app"),
    ("a.netlify.app", "b.netlify.app"),
    ("a.herokuapp.com", "b.herokuapp.com"),
    ("a.github.io", "b.github.io"),
    ("a.gitlab.io", "b.gitlab.io"),
    ("a.wordpress.com", "b.wordpress.com"),
    ("a.githubusercontent.com", "b.githubusercontent.com"),
    ("a.azurestaticapps.net", "b.azurestaticapps.net"),
    ("a.ngrok-free.app", "b.ngrok-free.app"),
    ("a.ondigitalocean.app", "b.ondigitalocean.app"),
    ("a.hf.space", "b.hf.space"),
    ("a.streamlit.app", "b.streamlit.app"),
    # country registries, by the rule and by name
    ("a.co.uk", "b.co.uk"),
    ("a.com.au", "b.com.au"),
    ("a.co.jp", "b.co.jp"),
    ("a.go.kr", "b.go.kr"),
    ("a.gob.mx", "b.gob.mx"),
    ("a.nom.es", "b.nom.es"),
    ("a.ac.th", "b.ac.th"),
    ("a.me.uk", "b.me.uk"),
    ("a.sch.uk", "b.sch.uk"),
)

# Hosts of ONE party: no prompt.
SAME = (
    ("api.stripe.com", "dashboard.stripe.com"),
    ("api.stripe.com", "stripe.com"),
    ("console.example.co.uk", "api.example.co.uk"),
    ("api.example.com.gr", "www.example.com.gr"),
    ("api.example.com.au", "www.example.com.au"),
    ("api.example.co.jp", "www.example.co.jp"),
    ("api.example.go.kr", "www.example.go.kr"),
    ("api.example.gob.mx", "www.example.gob.mx"),
    ("api.a.blogspot.com", "www.a.blogspot.com"),
    ("api.a.myshopify.com", "admin.a.myshopify.com"),
    ("api.evil.github.io", "www.evil.github.io"),
    ("api.acme.io", "dashboard.acme.io"),
    ("api.tavily.ai", "app.tavily.ai"),
    ("api.acme.co", "dashboard.acme.co"),
    ("api.acme.dev", "www.acme.dev"),
)

# host -> the registrable domain (the owner's name) it has to resolve to.
REGISTRABLE = (
    ("api.stripe.com", "stripe.com"),
    ("a.b.c.example.org", "example.org"),
    ("api.example.co.uk", "example.co.uk"),
    ("x.com.gr", "x.com.gr"),
    ("api.x.com.gr", "x.com.gr"),
    ("a.b.ne.jp", "b.ne.jp"),
    ("a.b.or.jp", "b.or.jp"),
    ("a.b.plc.uk", "b.plc.uk"),
    ("a.b.ltd.uk", "b.ltd.uk"),
    ("a.b.mil.br", "b.mil.br"),
    ("a.b.edu.sg", "b.edu.sg"),
    ("a.b.gov.in", "b.gov.in"),
    ("a.b.me.uk", "b.me.uk"),
    ("www.a.blogspot.com", "a.blogspot.com"),
    ("shop.a.myshopify.com", "a.myshopify.com"),
    ("x.evil.github.io", "evil.github.io"),
    ("svc.a.run.app", "svc.a.run.app"),
    ("a.run.app", "a.run.app"),
    ("bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com"),
    ("bucket.s3.us-west-2.amazonaws.com", "bucket.s3.us-west-2.amazonaws.com"),
    ("one.uc.r.appspot.com", "one.uc.r.appspot.com"),
    ("acct.blob.core.windows.net", "acct.blob.core.windows.net"),
)


class TestThePanelsExamples(unittest.TestCase):
    def test_tenants_of_one_platform_are_different_owners(self):
        for a, b in DIFFERENT:
            with self.subTest(a=a, b=b):
                self.assertFalse(same(url(a), url(b)), (a, b))
                self.assertFalse(same(url(b), url(a)), (b, a))

    def test_one_partys_own_hosts_are_one_owner(self):
        for a, b in SAME:
            with self.subTest(a=a, b=b):
                self.assertTrue(same(url(a), url(b)), (a, b))
                self.assertTrue(same(url(b), url(a)), (b, a))

    def test_the_name_an_owner_resolves_to(self):
        for host, expected in REGISTRABLE:
            with self.subTest(host=host):
                self.assertEqual(rd(host), expected)


class TestWhatTheOldListKnewIsStillKnown(unittest.TestCase):
    OLD = ("co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.nz",
           "co.za", "co.in", "co.kr", "com.cn", "com.tw", "com.hk", "com.sg",
           "com.mx", "com.tr", "co.id", "co.il", "com.pl", "co.th", "com.my",
           "com.ph", "com.vn", "com.ua", "com.ru", "co.ke", "com.ng", "com.eg",
           "com.sa", "com.pk", "com.bd", "com.pe", "com.co", "com.ar",
           "web.id", "idv.tw", "firm.in", "in.th", "web.za",
           "github.io", "gitlab.io", "herokuapp.com", "vercel.app",
           "netlify.app", "pages.dev", "workers.dev", "web.app",
           "firebaseapp.com", "appspot.com", "azurewebsites.net",
           "cloudfront.net", "onrender.com", "fly.dev",
           "railway.app", "ngrok.io", "ngrok.app", "ngrok-free.app",
           "trycloudflare.com", "repl.co", "replit.app", "glitch.me",
           "surge.sh", "now.sh", "deno.dev", "supabase.co")

    def test_the_next_label_is_still_the_owner(self):
        for suffix in self.OLD:
            with self.subTest(suffix=suffix):
                self.assertEqual(rd("api.acme." + suffix), "acme." + suffix)
                self.assertFalse(same(url("a." + suffix), url("b." + suffix)))
                self.assertTrue(same(url("api.acme." + suffix),
                                     url("www.acme." + suffix)))


class TestOrdinaryNamesAreUntouched(unittest.TestCase):
    def test_addresses_localhost_and_single_labels(self):
        for host in ("127.0.0.1", "10.0.0.5", "1.2.3", "::1", "fe80::1",
                     "localhost", "intranet", ""):
            with self.subTest(host=host):
                self.assertEqual(rd(host), host)

    def test_two_different_ipv4_mapped_addresses_are_not_one_owner(self):
        # "::ffff:1.2.3.4" and "::ffff:5.6.3.4" both end in ".3.4" when cut
        # at the dots
        self.assertEqual(rd("::ffff:1.2.3.4"), "::ffff:1.2.3.4")
        self.assertFalse(same("https://[::ffff:1.2.3.4]/", "https://[::ffff:5.6.3.4]/"))

    def test_a_registry_or_platform_on_its_own_is_its_own_name(self):
        for host in ("co.uk", "com.gr", "github.io", "run.app",
                     "blob.core.windows.net", "s3.amazonaws.com"):
            with self.subTest(host=host):
                self.assertEqual(rd(host), host)

    def test_a_two_letter_code_is_not_a_registry_by_itself(self):
        # .io .ai .co .me .tv are ordinary, sold by the name
        for tld in ("io", "ai", "co", "me", "tv", "sh", "ly", "dev", "app"):
            with self.subTest(tld=tld):
                self.assertEqual(rd("api.acme." + tld), "acme." + tld)
                self.assertTrue(same(url("api.acme." + tld),
                                     url("dashboard.acme." + tld)))

    def test_the_rule_needs_a_two_letter_code_and_a_generic_label(self):
        # "com" under a three-letter TLD is not a registry ...
        self.assertEqual(rd("a.b.com.org"), "com.org")
        # ... and an everyday word under a country code is a name
        self.assertEqual(rd("api.stripe.de"), "stripe.de")
        self.assertEqual(rd("a.shop.fr"), "shop.fr")
        # ... and the generic word counts only right under the code
        self.assertEqual(rd("net.example.de"), "example.de")
        self.assertEqual(rd("www.co.acme.io"), "acme.io")
        # ... and the rule reads the LAST two labels, nothing in the middle
        self.assertEqual(rd("www.co.uk.example.com"), "example.com")
        self.assertEqual(rd("api.com.gr.acme.dev"), "acme.dev")

    def test_empty_labels_and_trailing_dots_behave_as_before(self):
        self.assertEqual(rd("a..b.example"), "b.example")
        self.assertEqual(rd("API.Stripe.COM."), "stripe.com")
        self.assertEqual(rd("WWW.Example.CO.UK."), "example.co.uk")


class TestEveryEntryDoesItsJob(unittest.TestCase):
    def test_public_suffixes(self):
        for entry in connect_mod.PUBLIC_SUFFIXES:
            with self.subTest(entry=entry):
                self.assertEqual(rd("api.tenant." + entry), "tenant." + entry)
                self.assertEqual(rd("tenant." + entry), "tenant." + entry)
                self.assertEqual(rd(entry), entry)

    def test_per_host_domains(self):
        for entry in connect_mod.PER_HOST_DOMAINS:
            with self.subTest(entry=entry):
                self.assertEqual(rd("api.tenant." + entry), "api.tenant." + entry)
                self.assertEqual(rd("tenant." + entry), "tenant." + entry)
                self.assertEqual(rd(entry), entry)

    def test_generic_second_level_labels(self):
        for label in connect_mod.GENERIC_SECOND_LEVEL:
            for code in ("uk", "jp", "gr", "mx", "io"):
                registry = f"{label}.{code}"
                with self.subTest(registry=registry):
                    self.assertEqual(rd("api.tenant." + registry), "tenant." + registry)
                    self.assertEqual(rd(registry), registry)


class TestTheLongestSuffixWins(unittest.TestCase):
    def test_a_platform_inside_a_platform(self):
        tables = frozenset({"example.net", "pages.example.net"})
        with mock.patch.object(connect_mod, "PUBLIC_SUFFIXES", tables):
            self.assertEqual(rd("x.example.net"), "x.example.net")
            self.assertEqual(rd("www.x.example.net"), "x.example.net")
            self.assertEqual(rd("x.pages.example.net"), "x.pages.example.net")
            self.assertEqual(rd("www.x.pages.example.net"), "x.pages.example.net")
            self.assertFalse(same(url("x.pages.example.net"),
                                  url("y.pages.example.net")))


class TestTheTablesAreTidy(unittest.TestCase):
    def test_entries_are_in_comparison_form(self):
        for name in ("PUBLIC_SUFFIXES", "PER_HOST_DOMAINS", "GENERIC_SECOND_LEVEL"):
            entries = getattr(connect_mod, name)
            self.assertTrue(entries, name)
            for entry in entries:
                with self.subTest(table=name, entry=entry):
                    self.assertEqual(entry, connect_mod._normalize_host(entry))
                    self.assertTrue(entry.isascii() and entry.strip() == entry)
                    self.assertNotIn("..", entry)
                    self.assertNotIn("*", entry)

    def test_a_suffix_is_listed_once(self):
        both = connect_mod.PUBLIC_SUFFIXES & connect_mod.PER_HOST_DOMAINS
        self.assertEqual(sorted(both), [])

    def test_public_suffixes_have_two_labels_or_more(self):
        for entry in connect_mod.PUBLIC_SUFFIXES:
            self.assertGreaterEqual(entry.count("."), 1, entry)


class TestTheTypedYesIsAskedFor(unittest.TestCase):
    """The panel's end-to-end symptom: no prompt, so the key went out."""

    def go(self, key_host, validate_host, answer):
        sent = []
        asked = []
        out = io.StringIO()

        def confirm(prompt):
            asked.append(prompt)
            return answer

        code = connect_mod.connect(
            recipe(key_host, validate_host),
            env_file=os.path.join(_isolation.mktemp(), ".env"),
            browser_open=lambda _u: None, prompt=lambda _t: FAKE_KEY, out=out,
            validate_fn=lambda spec, key: sent.append(key) or True,
            confirm_in=confirm)
        return code, out.getvalue(), asked, sent

    def test_two_tenants_of_one_platform_need_the_typed_yes(self):
        for key_host, validate_host in (("a.run.app", "evil.run.app"),
                                        ("x.com.gr", "y.com.gr"),
                                        ("a.blogspot.com", "b.blogspot.com"),
                                        ("a.myshopify.com", "b.myshopify.com")):
            with self.subTest(key_host=key_host, validate_host=validate_host):
                code, text, asked, sent = self.go(key_host, validate_host, "no")
                self.assertEqual(code, 1)
                self.assertEqual(len(asked), 1, "no typed confirmation was asked for")
                self.assertIn("DIFFERENT domain", text)
                self.assertIn(f"{validate_host} vs {key_host}", text)
                self.assertEqual(sent, [], "the key was sent")
                self.assertNotIn(FAKE_KEY, text)

    def test_and_after_the_yes_it_goes_through(self):
        code, text, asked, sent = self.go("a.run.app", "evil.run.app", "yes")
        self.assertEqual(code, 0)
        self.assertEqual(sent, [FAKE_KEY])

    def test_one_tenants_own_hosts_do_not_ask(self):
        for key_host, validate_host in (("console.example.com.gr", "api.example.com.gr"),
                                        ("a.blogspot.com", "api.a.blogspot.com")):
            with self.subTest(key_host=key_host):
                code, text, asked, sent = self.go(key_host, validate_host, "no")
                self.assertEqual(code, 0)
                self.assertEqual(asked, [])
                self.assertNotIn("DIFFERENT domain", text)

    def test_no_shipped_recipe_starts_asking(self):
        shipped = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
        self.assertTrue(shipped)
        for slug, data in shipped.items():
            with self.subTest(recipe=slug):
                v = data["validate"]
                host = connect_mod._host(v["url"])
                vouched = {connect_mod._normalize_host(h)
                           for h in v.get("trusted_hosts") or []}
                self.assertTrue(connect_mod.same_owner(v["url"], data["key_url"])
                                or host in vouched, slug)


class TestReadmeSaysWhatTheListIs(unittest.TestCase):
    def test_it_is_a_compact_snapshot_not_the_public_suffix_list(self):
        with open(os.path.join(_isolation.REPO, "docs", "guide.md"),
                  encoding="utf-8") as f:
            flat = " ".join(f.read().split())
        for phrase in ("compact snapshot", "not the full Public Suffix List",
                       "treated as an ordinary domain"):
            self.assertTrue(phrase in flat, f"the README does not say: {phrase!r}")


if __name__ == "__main__":
    unittest.main()
