"""Finding the programs stuntkey runs itself (icacls, git, gh).

On Windows a program named without a folder is looked for in the CURRENT
folder first, and stuntkey is run from project folders: a cloned
repository could ship its own `icacls.exe` or `gh.exe` and have it run with
the person's rights. So the programs stuntkey starts are named by their
full path: icacls by its fixed place in the Windows folder, the others by a
search of PATH that never looks in the current folder.
"""

from __future__ import annotations

import ntpath
import os
import shutil


def system32_tool(name: str, environ=None) -> str:
    """The full path of a program in the Windows System32 folder
    (``C:\\Windows\\System32\\icacls.exe``), never found by searching."""
    env = os.environ if environ is None else environ
    root = env.get("SystemRoot") or env.get("windir") or "C:\\Windows"
    return ntpath.join(root, "System32", name)


def _same_dir(a: str, b: str, on_windows: bool) -> bool:
    a, b = os.path.abspath(a), os.path.abspath(b)
    return os.path.normcase(a) == os.path.normcase(b) if on_windows else a == b


def find_program(name: str, which=shutil.which, on_windows: bool | None = None,
                 environ=None, cwd: str | None = None) -> str | None:
    """The absolute path of `name` on PATH, or None. On Windows a hit in the
    current folder is not accepted: PATH is searched again by hand, folder by
    folder, without it."""
    if on_windows is None:
        on_windows = os.name == "nt"
    env = os.environ if environ is None else environ
    here = os.getcwd() if cwd is None else cwd
    found = which(name)
    if found is None:
        return None
    found = os.path.abspath(found)
    if not on_windows or not _same_dir(os.path.dirname(found), here, True):
        return found
    # PATH may be spelled PATH, Path or path on Windows
    search = next((v for k, v in env.items() if k.upper() == "PATH"), "")
    exts = [e for e in (env.get("PATHEXT") or ".COM;.EXE;.BAT;.CMD").split(";") if e]
    names = [name] if os.path.splitext(name)[1] else [name + e for e in exts]
    for directory in search.split(os.pathsep):
        if not directory or _same_dir(directory, here, True):
            continue
        for candidate in names:
            path = os.path.join(directory, candidate)
            if os.path.isfile(path):
                return os.path.abspath(path)
    return None
