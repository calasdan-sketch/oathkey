"""Protection profiles: given a simulated tool call, decide whether it is
blocked before it runs.

A profile is a callable ``(tool_payload) -> (blocked: bool, reason: str|None)``.
``none`` blocks nothing (the baseline). ``oathkey-hook`` runs OathKey's own
Claude Code PreToolUse hook decision function, if OathKey is importable.

Other tools are welcome: add a profile here (or register one at import time)
and send a PR. See README.md ("Adding a profile").
"""

from __future__ import annotations

import json
from typing import Callable

# (blocked, reason). reason is the profile's own words when it blocks.
Profile = Callable[[dict], "tuple[bool, str | None]"]


def _profile_none(_payload: dict) -> tuple[bool, str | None]:
    return False, None


def _load_oathkey_hook() -> Profile:
    """Wrap OathKey's PreToolUse hook. Raises ImportError if OathKey is not on
    the path, so the harness can mark the profile skipped rather than guess."""
    from oathkey import hook as hook_mod  # noqa: F401  (import-time check)

    def profile(payload: dict) -> tuple[bool, str | None]:
        stdin_text = json.dumps({"hook_event_name": "PreToolUse", **payload})
        status, out = hook_mod.check(stdin_text)
        if status == 0 and out.strip():
            try:
                decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
            except (ValueError, KeyError):
                return False, None
            if decision == "deny":
                reason = json.loads(out)["hookSpecificOutput"].get(
                    "permissionDecisionReason", "")
                return True, reason.split(".")[0] if reason else "denied"
        return False, None

    return profile


def get(name: str) -> Profile:
    """Return the profile by name, or raise. ``oathkey-hook`` raises ImportError
    when OathKey is not importable."""
    if name == "none":
        return _profile_none
    if name == "oathkey-hook":
        return _load_oathkey_hook()
    raise KeyError(name)


AVAILABLE = ("none", "oathkey-hook")
