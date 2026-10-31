"""Is a key already stored? Answers yes/no - never returns a value.

Looks in the OS keychain and in the project's .env file. A link or a file
that is not plain UTF-8 text is not read (store.refuse_link): this module
only ever asks "is there a non-empty value for this name".
"""

from __future__ import annotations

import os

from . import keychain as keychain_mod
from . import store as store_mod


def env_names(env_file: str) -> set[str]:
    """Names in `env_file` that have a non-empty value. Missing, linked or
    unreadable files have none."""
    try:
        store_mod.refuse_link(env_file)
        if not os.path.isfile(env_file):
            return set()
        values = store_mod.load_env(env_file)
    except (OSError, ValueError):
        return set()
    return {k for k, v in values.items() if v.strip()}


def in_keychain(service: str, var: str, backend: str | None = None,
                read=keychain_mod.read) -> bool | None:
    """True/False, or None when no keychain is available or it would not
    answer."""
    backend = backend or keychain_mod.detect_backend()
    if backend is None:
        return None
    try:
        return bool(read(service, var, backend))
    except keychain_mod.KeychainError:
        return None


def locate(service: str, variables: list[str], env_file: str,
           check_keychain: bool = True, read=keychain_mod.read,
           backend: str | None = None) -> dict:
    """{"env": [names found in the file], "keychain": [names found] or None
    (not checked / unavailable), "complete": bool, "missing": [names]}."""
    in_env = env_names(env_file)
    env_found = [v for v in variables if v in in_env]
    kc_found = None
    if check_keychain:
        got = [in_keychain(service, v, backend, read) for v in variables]
        if any(g is not None for g in got):
            kc_found = [v for v, g in zip(variables, got) if g]
    have = set(env_found) | set(kc_found or [])
    missing = [v for v in variables if v not in have]
    return {"env": env_found, "keychain": kc_found, "complete": not missing,
            "missing": missing}
