"""Route rules: which methods and paths each key may be used for.

A file named `oathkey.policy` (JSON) in ~/.oathkey and, optionally, in the
project folder:

    {"openai": {"methods": ["GET", "POST"],
                "paths": ["/v1/chat/completions", "/v1/models"]}}

Once a service has a rule, anything the rule does not list is refused (deny
by default). Services without a rule keep the broker's normal rules. The
project file can only narrow the user file, never widen it: for a service
both name, a request must pass both.

An AI could edit these files, so a file is only obeyed after a person runs
`oathkey policy approve`, which stores its sha256. A file that changed since
then stops every brokered call until it is approved again (fail closed).
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.parse

from .broker import MAX_REVIEW, BrokerError

FILE = "oathkey.policy"
MAX_BYTES = 64_000


def user_file(home: str) -> str:
    return os.path.join(home, FILE)


def project_file(project_dir: str) -> str:
    return os.path.join(project_dir, FILE)


def _approved_path(home: str) -> str:
    return os.path.join(home, "policy.approved")


def _read(path: str):
    """The file's bytes, or None when there is no file."""
    if not os.path.lexists(path):
        return None
    if os.path.islink(path) or not os.path.isfile(path):
        raise BrokerError(f"{path} is not a plain file, so no call was made.", 5)
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError:
        raise BrokerError(f"{path} cannot be read, so no call was made.", 5) from None
    if len(raw) > MAX_BYTES:
        raise BrokerError(f"{path} is too big to be a policy file.", 5)
    return raw


def parse(raw: bytes, where: str = FILE) -> dict:
    """{service: (frozenset(methods), tuple(path prefixes))}."""
    bad = BrokerError(f"{where} is not a valid policy file (see `oathkey policy "
                      "show` for the format), so no call was made.", 5)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise bad from None
    if not isinstance(data, dict):
        raise bad
    rules = {}
    for service, rule in data.items():
        if not isinstance(rule, dict):
            raise bad
        methods, paths = rule.get("methods", []), rule.get("paths", [])
        if not (isinstance(methods, list) and isinstance(paths, list)
                and all(isinstance(m, str) for m in methods)
                and all(isinstance(p, str) and p.startswith("/") for p in paths)):
            raise bad
        rules[str(service)] = (frozenset(m.upper() for m in methods), tuple(paths))
    return rules


def _under(path: str, prefix: str) -> bool:
    """Prefix match on whole path segments: /v1/chat does not cover /v1/chatX."""
    if prefix.endswith("/"):
        return path.startswith(prefix)
    return path == prefix or path.startswith(prefix + "/")


def narrow(user: dict, project: dict) -> dict:
    """The rules that pass both files."""
    out = dict(user)
    for service, (pm, pp) in project.items():
        if service not in user:
            out[service] = (pm, pp)
            continue
        um, up = user[service]
        paths = {p for p in pp if any(_under(p, u) for u in up)}
        paths |= {u for u in up if any(_under(u, p) for p in pp)}
        out[service] = (um & pm, tuple(sorted(paths)))
    return out


def _approved(home: str) -> dict:
    try:
        with open(_approved_path(home), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _key(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def _checked(path: str, approved: dict):
    raw = _read(path)
    if raw is None:
        return {}
    if approved.get(_key(path)) != hashlib.sha256(raw).hexdigest():
        raise BrokerError(f"The policy file {path} is new or was changed and a "
                          "person has not approved it, so no call was made. "
                          "Run `oathkey policy approve` to review it.", 5)
    return parse(raw, path)


def load(home: str, project_dir: str) -> dict:
    approved = _approved(home)
    user = _checked(user_file(home), approved)
    proj = project_file(project_dir)
    if _key(proj) == _key(user_file(home)):
        return user
    return narrow(user, _checked(proj, approved))


def check(rules: dict, service: str, method: str, path: str) -> None:
    if service not in rules:
        return
    methods, prefixes = rules[service]
    plain = urllib.parse.unquote(path.split("?")[0])
    if method.upper() in methods and any(_under(plain, p) for p in prefixes):
        return
    raise BrokerError(f"Your oathkey policy does not allow {method.upper()} "
                      f"{path.split('?')[0][:80]} for '{service}', so it was not "
                      "sent. A person can change oathkey.policy and run "
                      "`oathkey policy approve`.", 5)


def approve(home: str, project_dir: str, ask) -> int:
    """Show each policy file to the person; store the sha256 of each one they
    accept. Returns how many files were approved."""
    from .store import write_private
    approved = _approved(home)
    n = 0
    for path in dict.fromkeys((user_file(home), project_file(project_dir))):
        raw = _read(path)
        if raw is None:
            continue
        parse(raw, path)                       # never approve a broken file
        text = f"Use this route policy ({path}):\n" + raw.decode("utf-8")
        if len(text) > MAX_REVIEW:              # never ask about a cut-off file
            raise BrokerError(f"{path} is too long to review safely in one "
                              "window; make it shorter.", 5)
        if not ask(text):
            continue
        approved[_key(path)] = hashlib.sha256(raw).hexdigest()
        n += 1
    write_private(_approved_path(home), json.dumps(approved, indent=2) + "\n")
    return n
