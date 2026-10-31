"""Protection profiles: given a simulated tool call, decide whether it is
blocked before it runs.

A profile is a callable ``(tool_payload) -> (blocked: bool, reason: str|None)``.
It may also carry three optional attributes, used when present:

``prepare(sbx)``
    called before each probe with the sandbox (plant what the tool would have).
``post(payload, response) -> response``
    the tool ran; return what the model would see. ``response`` is the Bash
    output shape ``{stdout, stderr, interrupted, isImage}``.
``spend(sbx) -> str | None``
    a runaway paid-call loop: the reason it was stopped, or None.

``none`` blocks nothing (the baseline). ``oathkey-hook`` runs OathKey's own
Claude Code hook (``oathkey.hook.check``) twice, as a real install does:
PreToolUse before the call and PostToolUse on its output. ``oathkey-full`` is
the hook plus OathKey's spending caps.

Other tools are welcome: add a profile here and send a PR (README: "Adding a
profile").
"""

from __future__ import annotations

import contextlib
import json
import os
from typing import Callable

# (blocked, reason). reason is the profile's own words when it blocks.
Profile = Callable[[dict], "tuple[bool, str | None]"]

BENCH_SERVICE = "leakbench"
BENCH_CAP = 3          # calls_session cap set for the simulated runaway loop
LOOP_TRIES = 50        # how far the simulated loop would get without a cap
_HOME_VARS = ("HOME", "USERPROFILE")


def _profile_none(_payload: dict) -> tuple[bool, str | None]:
    return False, None


@contextlib.contextmanager
def _home(path: str | None):
    """Run the hook as if the sandbox were the user's home (where it looks for
    ~/.oathkey/fingerprints.json), then put the real values back."""
    if path is None:
        yield
        return
    old = {k: os.environ.get(k) for k in _HOME_VARS}
    os.environ.update({k: path for k in _HOME_VARS})
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _load_oathkey_hook() -> Profile:
    """Wrap OathKey's hook. Raises ImportError if OathKey is not on the path,
    so the harness can mark the profile skipped rather than guess."""
    from oathkey import hook as hook_mod
    from oathkey import scrub as scrub_mod

    state: dict = {"home": None}

    def prepare(sbx) -> None:  # type: ignore[no-untyped-def]
        # simulate `oathkey get`/`add`: the canary is a key OathKey stores, so
        # its fingerprint is in the (sandbox) fingerprint file, as in real use
        state["home"] = sbx.home
        path = os.path.join(sbx.home, ".oathkey", scrub_mod.FINGERPRINT_FILE)
        if not os.path.exists(path):
            scrub_mod.remember_key(f"{BENCH_SERVICE}/API_KEY", sbx.canary, path)

    def profile(payload: dict) -> tuple[bool, str | None]:
        stdin_text = json.dumps({"hook_event_name": "PreToolUse", **payload})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status == 0 and out.strip():
            try:
                spec = json.loads(out)["hookSpecificOutput"]
            except (ValueError, KeyError):
                return False, None
            if spec.get("permissionDecision") == "deny":
                reason = spec.get("permissionDecisionReason", "")
                return True, reason.split(".")[0] if reason else "denied"
        return False, None

    def post(payload: dict, response: dict) -> dict:
        stdin_text = json.dumps({"hook_event_name": "PostToolUse",
                                 **payload, "tool_response": response})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status != 0 or not out.strip():
            return response
        new = json.loads(out).get("hookSpecificOutput", {}).get("updatedToolOutput")
        # Claude Code ignores a replacement that is not the tool's own shape
        return new if isinstance(new, dict) and set(new) >= set(response) else response

    profile.prepare = prepare  # type: ignore[attr-defined]
    profile.post = post        # type: ignore[attr-defined]
    return profile


def _load_oathkey_full() -> Profile:
    """The hook plus spending caps. The model: the key lives only in OathKey,
    so the agent's paid calls go through the broker (`oathkey proxy`, MCP,
    `call`), which checks caps.begin() before every call. A cap of BENCH_CAP
    calls is set for the run; the loop is stopped if the cap refuses a call."""
    from oathkey import caps as caps_mod
    from oathkey.broker import BrokerError

    profile = _load_oathkey_hook()

    def spend(sbx) -> str | None:  # type: ignore[no-untyped-def]
        home = os.path.join(sbx.home, ".oathkey")
        os.makedirs(home, exist_ok=True)
        with open(caps_mod.caps_path(home), "w", encoding="utf-8") as f:
            json.dump({BENCH_SERVICE: {"calls_session": BENCH_CAP}}, f)
        for made in range(LOOP_TRIES):
            try:
                caps_mod.begin(home, BENCH_SERVICE, made)
            except BrokerError as e:
                return f"cap stopped call {made + 1}: {str(e).split(',')[0]}"
        return None

    profile.spend = spend  # type: ignore[attr-defined]
    return profile


def get(name: str) -> Profile:
    """Return the profile by name, or raise. The oathkey profiles raise
    ImportError when OathKey is not importable."""
    if name == "none":
        return _profile_none
    if name == "oathkey-hook":
        return _load_oathkey_hook()
    if name == "oathkey-full":
        return _load_oathkey_full()
    raise KeyError(name)


AVAILABLE = ("none", "oathkey-hook", "oathkey-full")
