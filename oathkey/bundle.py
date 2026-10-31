"""`oathkey scan --bundle`: secret keys shipped to the browser.

A web app built with Vite, Next.js, Create React App or Expo copies every
VITE_*, NEXT_PUBLIC_*, REACT_APP_* and EXPO_PUBLIC_* variable into the
JavaScript every visitor downloads. A secret key put there is public. This
looks in a built folder (dist/, build/, out/, .next/static) or, for your own
public site, in the page and its same-site scripts.

Defensive and careful, like the rest of the scan:
- It READS only: .js/.mjs/.cjs/.map/.html files, each at most 10 MB.
- A URL must be https, must resolve to public addresses only (the broker's
  own checks), is fetched from the address that was checked, never through a
  proxy, follows a redirect only within the same site, and loads at most
  MAX_SCRIPTS scripts from that same site (scheme, host and port), never a
  CDN or another site.
- Keys are shown masked (first 4 and last 2 characters), as everywhere.
"""

from __future__ import annotations

import dataclasses
import html.parser
import os
import re
import time
import urllib.parse

from . import broker as broker_mod
from . import scan as scan_mod

BUNDLE_DIRS = ("dist", "build", "out", os.path.join(".next", "static"))
SUFFIXES = (".js", ".mjs", ".cjs", ".map", ".html", ".htm")
PRUNE = frozenset({"node_modules", ".git"})
MAX_FILE = 10 * 1024 * 1024
MAX_FILES = 5000
MAX_SCRIPTS = 40
MAX_REDIRECTS = 3
MAX_TOTAL = 60 * 1024 * 1024        # bytes fetched from a site, all files together
FETCH_SECONDS = 15

PUBLIC_ENV_RE = re.compile(
    r"\b((?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]{2,64})[\"']?\s*[:=]\s*"
    r"[\"'`]([^\"'`\s\\]{16,400})[\"'`]")
# names that are public on purpose: a publishable key, an anon key, an id, an address
PUBLIC_BY_DESIGN = re.compile(
    r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|_URL$|_URI$|_ID$|_DSN$|_HOST$|_DOMAIN$"
    r"|_REGION$|_ENV$|_VERSION$|MEASUREMENT|_BUCKET$|_PROJECT$")
PUBLIC_VALUE = re.compile(r"(?:pk|rk)_(?:live|test)_|sb_publishable_|pk\.")

ADVICE = ("This key is in a file every visitor's browser downloads, so anyone can "
          "read it. Rotate it now, then move the call that uses it to your server "
          "(an API route or serverless function) and keep the key in the server's "
          "environment, not in a VITE_ / NEXT_PUBLIC_ / REACT_APP_ / EXPO_PUBLIC_ "
          "variable.")
GOOGLE_NOTE = (" If it is a Firebase or Google Maps browser key it is public by "
               "design: restrict it to your site's address in the Google Cloud console.")


def _public_env_findings(text: str, rel: str, have: set) -> list[scan_mod.Finding]:
    out = []
    for m in PUBLIC_ENV_RE.finditer(text):
        name, value = m.group(1), m.group(2)
        if (value in have or PUBLIC_BY_DESIGN.search(name) or PUBLIC_VALUE.match(value)
                or not scan_mod._secret_value_ok(value)):
            continue
        have.add(value)
        line = text.count("\n", 0, m.start(2)) + 1
        out.append(scan_mod.Finding(
            rel, line, m.start(2) - (text.rfind("\n", 0, m.start(2)) + 1) + 1,
            None, f"{name} (browser variable)", "public-env-variable", "guess",
            scan_mod.redact(value), can_validate=False,
            skip_reason="no service is known for this variable", _value=value))
    return out


def scan_text(text: str, rel: str, catalog: dict, rules, words) -> list[scan_mod.Finding]:
    budget = scan_mod.Budget(scan_mod.FILE_SECONDS)
    found = scan_mod.scan_text(text, rel, rules, catalog, words, budget)
    found += _public_env_findings(text, rel, {f._value for f in found})
    for f in found:
        f.fix = ADVICE + (GOOGLE_NOTE if f._value.startswith("AIza") else "")
    return found


def _walk(root: str, skipped: list) -> list[str]:
    tops = [os.path.join(root, d) for d in BUNDLE_DIRS if os.path.isdir(os.path.join(root, d))]
    files: list[str] = []
    for top in tops or [root]:
        for d, dirs, names in os.walk(top):
            dirs[:] = sorted(x for x in dirs if x not in PRUNE)
            for n in sorted(names):
                if n.lower().endswith(SUFFIXES):
                    if len(files) >= MAX_FILES:
                        skipped.append(scan_mod.Skipped(".", f"stopped after {MAX_FILES} files", True))
                        return files
                    files.append(os.path.join(d, n))
    return files


def scan_folder(target: str, catalog: dict) -> scan_mod.ScanResult:
    root = os.path.abspath(target)
    if not os.path.isdir(root):
        raise ValueError(f"{target} is not a folder (or an https:// address)")
    root_real = os.path.realpath(root)
    skipped: list = []
    files = _walk(root, skipped)
    rules, words = scan_mod.build_rules(catalog), scan_mod._name_tokens(catalog)
    findings, scanned = [], 0
    for path in files:
        rel = os.path.relpath(path, root).replace("\\", "/")
        text, why = scan_mod.read_text_safely(path, root_real, MAX_FILE)
        if text is None:
            skipped.append(scan_mod.Skipped(rel, why or "skipped",
                                            bool(why and why.startswith(("could not", "bigger")))))
            continue
        scanned += 1
        findings += scan_text(text, rel, catalog, rules, words)
    return scan_mod.ScanResult(root, scanned, findings, skipped, kind="bundle")


# ----------------------------------------------------------------------- URL

class _Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.found.append(a["src"])
        elif tag == "link" and a.get("href") and (
                "modulepreload" in a.get("rel", "").lower()
                or ("preload" in a.get("rel", "").lower() and a.get("as") == "script")):
            self.found.append(a["href"])


def _origin(url: str) -> tuple:
    p = urllib.parse.urlsplit(url)
    return p.scheme.lower(), (p.hostname or "").lower(), p.port or 443


def _real_get(url: str, ip: str, limit: int) -> tuple[int, str, bytes]:
    """(status, Location, body): one GET to the checked address, with the
    certificate checked for the real name (broker._Pinned), no proxy."""
    p = urllib.parse.urlsplit(url)
    conn = broker_mod._Pinned(p.hostname, ip=ip, port=p.port or 443, timeout=FETCH_SECONDS)
    try:
        conn.request("GET", (p.path or "/") + (f"?{p.query}" if p.query else ""),
                     headers={"User-Agent": "oathkey-bundle-check",
                              "Accept-Encoding": "identity"})
        resp = conn.getresponse()
        return resp.status, resp.getheader("Location") or "", resp.read(limit + 1)
    except OSError as e:
        raise ValueError(f"could not fetch {url}: {type(e).__name__}") from None
    finally:
        conn.close()


@dataclasses.dataclass
class _Site:
    origin: tuple
    ip: str
    get: object
    total: int = 0

    def fetch(self, url: str) -> tuple[str, bytes]:
        """(final url, body). Redirects are followed only within the site."""
        for _ in range(MAX_REDIRECTS + 1):
            status, location, body = self.get(url, self.ip, MAX_FILE)
            if status in (301, 302, 303, 307, 308) and location:
                nxt = urllib.parse.urljoin(url, location)
                if _origin(nxt) != self.origin:
                    raise ValueError("it redirects to another site, which is not followed")
                url = nxt
                continue
            if status != 200:
                raise ValueError(f"the server answered {status}")
            if len(body) > MAX_FILE:
                raise ValueError("bigger than 10 MB")
            self.total += len(body)
            if self.total > MAX_TOTAL:
                raise ValueError("more than 60 MB in total was fetched")
            return url, body
        raise ValueError("too many redirects")


def scan_url(url: str, catalog: dict, resolve=broker_mod.resolve_public,
             get=_real_get) -> scan_mod.ScanResult:
    try:
        p = urllib.parse.urlsplit(url)
        p.port
    except ValueError:
        raise ValueError("that is not a valid address") from None
    if p.scheme.lower() != "https" or not p.hostname:
        raise ValueError("--bundle takes a folder or an https:// address")
    if p.username or p.password:
        raise ValueError("the address may not hold a user name or password")
    try:
        ip = resolve(p.hostname, p.port or 443)
    except broker_mod.BrokerError as e:
        raise ValueError(f"{e} (only a public site can be checked)") from None
    site = _Site(_origin(url), ip, get)
    rules, words = scan_mod.build_rules(catalog), scan_mod._name_tokens(catalog)
    skipped: list = []
    final, body = site.fetch(url)
    page = body.decode("utf-8", "replace")
    findings = scan_text(page, final, catalog, rules, words)
    parser = _Scripts()
    try:
        parser.feed(page)
    except Exception:                   # a broken page: scan what was found
        pass
    scripts, other = [], 0
    for src in dict.fromkeys(urllib.parse.urljoin(final, s) for s in parser.found):
        if _origin(src) != site.origin:
            other += 1
        else:
            scripts.append(src)
    if other:
        skipped.append(scan_mod.Skipped(".", f"{other} script(s) on other sites (a CDN, "
                                             f"analytics) were not fetched"))
    if len(scripts) > MAX_SCRIPTS:
        skipped.append(scan_mod.Skipped(".", f"only the first {MAX_SCRIPTS} of "
                                             f"{len(scripts)} scripts were fetched", True))
    deadline = time.monotonic() + scan_mod.SCAN_SECONDS
    scanned = 1
    for src in scripts[:MAX_SCRIPTS]:
        if time.monotonic() > deadline:
            skipped.append(scan_mod.Skipped(".", "stopped: out of time", True))
            break
        try:
            got, data = site.fetch(src)
        except ValueError as e:
            skipped.append(scan_mod.Skipped(src, str(e), True))
            continue
        scanned += 1
        findings += scan_text(data.decode("utf-8", "replace"), got, catalog, rules, words)
    skipped.append(scan_mod.Skipped(".", "scripts a page loads later (code splitting) "
                                         "are not fetched: scan the build folder for those"))
    return scan_mod.ScanResult(final, scanned, findings, skipped, kind="bundle")


def scan_bundle(target: str, catalog: dict, **kw) -> scan_mod.ScanResult:
    if re.match(r"[A-Za-z][A-Za-z0-9+.-]*://", target):
        return scan_url(target, catalog, **kw)
    return scan_folder(target, catalog)
