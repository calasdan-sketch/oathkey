"""Run the helper programs (zenity, osascript, security, secret-tool, xclip ...) safely.

An agent that can put a program called `zenity` or `xclip` earlier on PATH
(or in a folder the person can write to) could answer a permission window or
read the clipboard for itself. So these helpers are looked up ONLY in fixed
system folders, only when the file is owned by root and neither it nor its
folder can be changed by anyone else, and they run with a minimal, fixed
environment (a fixed PATH, no LD_PRELOAD, no PYTHON*, no user PATH).

On Windows nothing here is used (the helpers are ctypes calls).
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess

SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/local/bin")
FIXED_PATH = "/usr/bin:/bin"
# what a desktop helper needs to find the person's screen and session bus
KEEP = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE", "LANG", "LC_ALL", "HOME")


def _trusted(path: str, statfn=os.stat) -> bool:
    """Owned by root (uid 0), not writable by group or others, in a folder
    that is also root-owned and not writable by group or others."""
    if os.name != "posix" and statfn is os.stat:
        return False
    try:
        for p in (path, os.path.dirname(path)):
            st = statfn(p)
            if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return False
        mode = statfn(path).st_mode
        return stat.S_ISREG(mode) and bool(mode & stat.S_IXUSR)
    except OSError:
        return False


def find(name: str, dirs=SYSTEM_DIRS, statfn=os.stat) -> str | None:
    """The absolute path of helper `name`, or None when it is missing or not
    trustworthy. Never consults PATH."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    for folder in dirs:
        path = os.path.join(folder, name)
        if _trusted(path, statfn):
            return path
    return None


def explain(name: str, dirs=SYSTEM_DIRS, statfn=os.stat, which=None) -> str | None:
    """None when a trusted `name` exists or none exists anywhere. When a copy
    is on the person's PATH but was refused, WHY (so the failure is visible
    instead of capture quietly not working). The rule is not relaxed: a tool
    that is not root-owned could be replaced by any program of the same user."""
    if find(name, dirs, statfn):
        return None
    try:
        found = (which or shutil.which)(name)
    except Exception:
        found = None
    if not found:
        return None
    return (f"found {name} at {found} but it is not a trusted install (it must be owned by "
            f"root, not writable by others, in {', '.join(dirs)}); capture needs a "
            f"root-owned {name} there - or use `stuntkey connect`.")


def env(source=None) -> dict:
    source = os.environ if source is None else source
    out = {"PATH": FIXED_PATH}
    for key in KEEP:
        if source.get(key):
            out[key] = source[key]
    return out


def run(argv, **kw):
    """subprocess.run with the fixed environment. argv[0] must be absolute."""
    if not os.path.isabs(argv[0]):
        raise OSError("helper programs are run by absolute path only")
    kw.setdefault("env", env())
    return subprocess.run(argv, **kw)
