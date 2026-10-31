"""A yes/no question in a window of the operating system, outside the agent's reach.

The person's permission for agent-driven key capture is asked here, by the
MCP server itself, not by anything the agent can type into. Windows: a system
MessageBox (with a timeout). macOS: osascript. Linux: zenity or kdialog,
found only in fixed system folders (safeexec.py) and run with a fixed
environment. With no graphical session (SSH, a container, a server) there is
no window: `confirm` returns None and the caller falls back to the terminal
command, which is weaker (an agent can fake a terminal) and is labelled so.

What this is, honestly: a real gate against an agent that works through files
and shell commands and cannot run code as the same user as this server. It is
NOT a gate against an agent that can run code as that user (it can drive the
same OS interfaces) or that controls the screen and presses the button itself.

Answers: True (Yes), False (the No button, provably), SOFT_NO (No or closed: cannot tell), EXPIRED (nobody
answered in time: not a refusal, ask again) and None (no window could be shown,
or the helper failed: also not a refusal).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time

from . import safeexec

# A window stays open at least five minutes: nobody should have it vanish while they
# are still working out what it is. The text of every window says so.
TIMEOUT_SECONDS = 330
EXPIRES_TEXT = "This window closes by itself in 5 minutes (same as No)."


class _Expired:
    """What confirm() returns when nobody answered in time: not a Yes, not a No."""

    def __repr__(self) -> str:
        return "EXPIRED"

    def __bool__(self) -> bool:
        return False


EXPIRED = _Expired()


class _SoftNo:
    """The window went away with a "no" or with the close box and we cannot tell
    which (kdialog, an old zenity, Esc on macOS). Treated as "not now" and never
    remembered as the person's refusal."""

    def __repr__(self) -> str:
        return "SOFT_NO"

    def __bool__(self) -> bool:
        return False


SOFT_NO = _SoftNo()

# ------------------------------------------------------------ who is asking
# The MCP client names itself in the `initialize` request (clientInfo.name). It is
# what the program REPORTS about itself - not proof - and it is only used to make
# the window say "Claude Code" instead of something vague.
FRIENDLY = (
    ("claude-code", "Claude Code"), ("claude-ai", "Claude"), ("claude-desktop", "Claude"),
    ("claude", "Claude"), ("cursor", "Cursor"), ("codex", "Codex"), ("gemini", "Gemini CLI"),
    ("windsurf", "Windsurf"), ("cline", "Cline"), ("zed", "Zed"),
    ("visual-studio-code", "VS Code"), ("vscode", "VS Code"), ("roo", "Roo Code"),
    ("continue", "Continue"), ("goose", "Goose"), ("opencode", "OpenCode"))
UNKNOWN_SUBJECT, UNKNOWN_OBJECT = "An AI program", "the AI program"
_CLIENT: list = [None]


def set_client(name) -> None:
    """Remember who connected (this server session). Anything but text clears it."""
    _CLIENT[0] = name if isinstance(name, str) else None


def current_client():
    return _CLIENT[0]


def client_label(name=None) -> tuple[str, str]:
    """(how to say it at the start of a sentence, how to say it mid-sentence)."""
    raw = current_client() if name is None else name
    if isinstance(raw, str):
        low = raw.strip().lower()
        for key, nice in FRIENDLY:
            if low == key or low.startswith(key + "-") or low.startswith(key + "_") \
                    or low.startswith(key + " ") or low.startswith(key + "/"):
                return nice, nice
        cleaned = re.sub(r"[^\x20-\x7e]", "", raw)
        cleaned = re.sub(r"[<>&\"`$\\]", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()[:30].strip()
        if re.search(r"[A-Za-z0-9]", cleaned):
            return cleaned, cleaned
    return UNKNOWN_SUBJECT, UNKNOWN_OBJECT


def available(platform: str | None = None, env=None, which=safeexec.find) -> bool:
    platform = platform or sys.platform
    env = os.environ if env is None else env
    # NOTE: this switch is read from the server's environment, which the MCP client's
    # config sets; an agent that can edit that config can set it (and so fall back to
    # the advisory terminal route). It is a convenience, not a lock.
    if env.get("STUNTKEY_NO_WINDOW") == "1":
        return False                    # the person turned windows off for this server
    if platform == "win32":
        return True
    if platform == "darwin":
        return bool(which("osascript")) and not env.get("SSH_CONNECTION")
    if env.get("SSH_CONNECTION") or not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        return False
    return bool(which("zenity") or which("kdialog"))


MAX_TITLE = 90
MAX_MESSAGE = 1600
MAX_PATH = 120


def plain(text: str, limit: int = MAX_MESSAGE) -> str:
    """Text that cannot mislead: ASCII only (a look-alike letter from another
    alphabet becomes '?'), no control characters except line breaks, cut to
    `limit` characters."""
    text = re.sub(r"[^\x20-\x7e\n]", "?", str(text))
    return text if len(text) <= limit else text[:limit - 3] + "..."


def short_path(path: str, limit: int = MAX_PATH) -> str:
    """The END of a path (where the project is), plain, at most `limit` long."""
    path = plain(path, 10_000)
    return path if len(path) <= limit else "..." + path[-(limit - 3):]


def why_unavailable(platform: str | None = None, env=None, explain=safeexec.explain) -> str | None:
    """When the only reason there is no window is that a helper program was
    REFUSED (not root-owned ...), say so; else None."""
    platform = platform or sys.platform
    names = ("osascript",) if platform == "darwin" else (
        () if platform == "win32" else ("zenity", "kdialog"))
    for name in names:
        why = explain(name)
        if why:
            return why
    return None


def markup_free(text: str) -> str:
    """No characters a rich-text widget could read as markup."""
    return re.sub(r"[<>&]", "?", text)


# ---------------------------------------------------------------- the words
# Short, everyday words; at most five short lines; the buttons are Yes and No
# (that is what the Windows box has, and the other platforms are made to match).

TITLE = "stuntkey (installed on this computer)"
FIRST = "stuntkey (free key-safe tool, made by Calas Automations, installed on this computer)"


def project_name(root: str) -> str:
    """Just the last folder's name, in plain ASCII."""
    name = re.split(r"[\\/]", str(root).rstrip("/\\"))[-1] or "this project"
    return plain(name, 40)


def consent_window(display: str, root: str, who: tuple[str, str] | None = None) -> tuple[str, str]:
    display, project = plain(display, 40), project_name(root)
    subject, obj = who or client_label()
    return TITLE, "\n".join((
        FIRST,
        f'{subject} wants to connect {display} for "{project}".',
        f"stuntkey will save the key safely; it is never shown to {obj}.",
        f"Did you ask {obj} to do this?",
        "No = nothing is stored or changed. " + EXPIRES_TEXT))


def replace_window(display: str, root: str, who: tuple[str, str] | None = None) -> tuple[str, str]:
    display, project = plain(display, 40), project_name(root)
    subject, obj = who or client_label()
    return TITLE, "\n".join((
        FIRST,
        f'{subject} wants to REPLACE your saved {display} key for "{project}".',
        f"The old key will be overwritten. It is never shown to {obj}.",
        f"Did you ask {obj} to do this?",
        "No = nothing is stored or changed. " + EXPIRES_TEXT))


def account_window(display: str, account: str | None, root: str) -> tuple[str, str]:
    display, project = plain(display, 40), project_name(root)
    who = plain(account, 60) if account else "(not reported)"
    return TITLE, "\n".join((
        f"{display} account: {who}",
        "Is this your account?",
        f'Yes = save the key for "{project}". No = nothing is stored.',
        EXPIRES_TEXT))


def _applescript_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _attract(user32, title: str, tries: int = 12, pause: float = 0.25) -> None:
    """Make sure the person notices the box: find it, bring it to the front and
    flash its taskbar button. Best effort - every failure is ignored."""
    import ctypes

    class FLASHWINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("hwnd", ctypes.c_void_p), ("dwFlags", ctypes.c_uint),
                    ("uCount", ctypes.c_uint), ("dwTimeout", ctypes.c_uint)]
    for _ in range(tries):
        time.sleep(pause)
        try:
            hwnd = user32.FindWindowW(None, title)
            if not hwnd:
                continue
            user32.SetForegroundWindow(hwnd)
            info = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 0x3 | 0xC, 6, 0)   # caption+taskbar, until foreground
            user32.FlashWindowEx(ctypes.byref(info))
            return
        except Exception:
            return


def _message_box(title: str, message: str, seconds: int = TIMEOUT_SECONDS) -> bool | None:
    """True / False, or None when nobody answered within `seconds`.
    MessageBoxTimeoutW (user32, long-standing but undocumented) closes the box
    itself; without it a watchdog thread posts WM_CLOSE to the box."""
    import ctypes
    import threading
    MB_YESNO, MB_ICONQUESTION, MB_DEFBUTTON2 = 0x4, 0x20, 0x100
    MB_SETFOREGROUND, MB_TOPMOST = 0x10000, 0x40000
    flags = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST
    user32 = ctypes.windll.user32
    try:
        user32.MessageBeep(MB_ICONQUESTION)          # the system "question" sound
    except Exception:
        pass
    threading.Thread(target=_attract, args=(user32, title), daemon=True).start()
    timeout_fn = getattr(user32, "MessageBoxTimeoutW", None)
    if timeout_fn is not None:
        answer = timeout_fn(None, message, title, flags, 0, int(seconds * 1000))
        return None if answer == 32000 else answer == 6        # 32000: timed out
    done = threading.Event()

    def watchdog():
        if not done.wait(seconds):
            WM_CLOSE = 0x10
            hwnd = user32.FindWindowW(None, title)
            if hwnd:
                user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
    timer = threading.Thread(target=watchdog, daemon=True)
    timer.start()
    started = time.monotonic()
    try:
        answer = user32.MessageBoxW(None, message, title, flags)
    finally:
        done.set()
    if answer == 6:
        return True
    # a box closed by the watchdog answers IDNO (7) after the full time
    return None if time.monotonic() - started >= seconds - 1 else False


def _launch_failed(code: int, err: bytes = b"") -> bool:
    """Not an answer: an odd exit status, or exit 1 WITH an error message (the
    display could not be opened, a flag is unknown ...). A real "No" is exit 1
    and silence."""
    return code not in (0, 1, 5) or (code == 1 and bool((err or b"").strip()))


def _no_or_failure(done):
    """SOFT_NO for exit 1 with empty stderr (a No button OR a closed window: the tool
    cannot say which); else None (a failure)."""
    if done.returncode == 1 and not (done.stderr or b"").strip():
        return SOFT_NO
    return None


def confirm(title: str, message: str, platform: str | None = None, env=None,
            which=safeexec.find, run=safeexec.run, message_box=_message_box) -> bool | None:
    """True for the Yes button; False ONLY when the No button was pressed and the
    tool can prove it (Windows, macOS, zenity with --switch); SOFT_NO when a No
    and a closed window cannot be told apart; EXPIRED when nobody answered in
    time; None when no window can be shown or the helper failed (crash, unsupported
    flag, odd exit status). A failure or a close is never the person's "no"."""
    platform = platform or sys.platform
    if not available(platform, env, which):
        return None
    title, message = plain(title, MAX_TITLE), plain(message)
    try:
        if platform == "win32":
            answer = message_box(title, message)
            return EXPIRED if answer is None else bool(answer)
        if platform == "darwin":
            script = (f'display dialog "{_applescript_text(message)}" with title '
                      f'"{_applescript_text(title)}" buttons {{"No", "Yes"}} '
                      f'default button "No" with icon caution '
                      f'giving up after {TIMEOUT_SECONDS}')
            done = run([which("osascript"), "-e", script], capture_output=True,
                       timeout=TIMEOUT_SECONDS + 10)
            out, err = done.stdout or b"", done.stderr or b""
            if b"gave up:true" in out:
                return EXPIRED
            if done.returncode == 0:
                if b"Yes" in out:
                    return True
                return False if b"No" in out else None      # the No BUTTON, pressed
            # Esc / Cmd-. is "User canceled" (-128): closed without choosing, not a "No"
            return SOFT_NO if (b"-128" in err or b"User canceled" in err) else None
        if which("zenity"):
            zen = which("zenity")
            limit = f"--timeout={TIMEOUT_SECONDS}"
            # Best: two extra buttons, so the label of the one pressed is printed - then
            # "No" (button) is told apart from the window being closed.
            done = run([zen, "--question", "--switch", "--extra-button", "Yes",
                        "--extra-button", "No", "--title", title, "--text", message,
                        "--no-markup", limit], capture_output=True, timeout=TIMEOUT_SECONDS + 10)
            if done.returncode == 5:
                return EXPIRED
            pressed = (done.stdout or b"").strip()
            if not _launch_failed(done.returncode, done.stderr):
                if pressed == b"Yes" or done.returncode == 0:
                    return True
                return False if pressed == b"No" else SOFT_NO      # nothing pressed: closed
            # an old zenity without --switch: the plain two-button form; a close then looks
            # like a No, so a silent exit 1 is only a SOFT_NO
            base = [zen, "--question", "--title", title, "--text", message,
                    "--ok-label", "Yes", "--cancel-label", "No"]
            done = run(base + ["--no-markup", "--default-cancel", limit], capture_output=True,
                       timeout=TIMEOUT_SECONDS + 10)
            if _launch_failed(done.returncode, done.stderr):
                # older still: without --no-markup / --default-cancel, markup characters removed
                again = list(base)
                again[again.index("--text") + 1] = markup_free(message)
                again.append(limit)
                done = run(again, capture_output=True, timeout=TIMEOUT_SECONDS + 10)
            if done.returncode == 5:            # zenity: timed out
                return EXPIRED
            if done.returncode == 0:
                return True
            return _no_or_failure(done)
        done = run([which("kdialog"), "--title", title, "--yesno", markup_free(message),
                    "--yes-label", "Yes", "--no-label", "No"], capture_output=True,
                   timeout=TIMEOUT_SECONDS + 10)
        if done.returncode == 0:
            return True
        return _no_or_failure(done)
    except subprocess.TimeoutExpired:
        return EXPIRED
    except Exception:
        return None
