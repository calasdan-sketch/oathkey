"""Find the environment-variable NAMES a project uses, and match them to recipes.

Reads only source files and templates (`.env.example`, `.env.sample` ...).
It never opens a real `.env` file: it does not need to (the names are in the
template and in the code), and keys do not belong in anything this reads.
Only names are collected - the values in a template are dropped on the spot.
"""

from __future__ import annotations

import os
import re
import stat
import time

from . import hook as hook_mod
from . import recipes as recipes_mod
from . import scan as scan_mod

CODE_SUFFIXES = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php",
    ".java", ".kt", ".rs", ".cs", ".sh", ".bash", ".ps1", ".yml", ".yaml",
    ".toml", ".dockerfile", ".tf"})
MAX_FILES = 5000
MAX_FILE_BYTES = 512 * 1024
MAX_DEPTH = 8
NAME_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]{2,63})(?![A-Za-z0-9_])")
TEMPLATE_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _is_template(name: str) -> bool:
    return bool(hook_mod.ENV_NAME_RE.fullmatch(name)) and not hook_mod.is_env_name(name)


def _read_limited(path: str) -> str | None:
    """The file's text, or None for anything but a small plain file. It is
    opened without waiting and without following a link, and checked after
    opening, so a named pipe (or a device) called x.py cannot hang the walk."""
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow and os.path.islink(path):
        return None     # Windows has no O_NOFOLLOW: a link is turned away here
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | nofollow
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                return None
            data = f.read(MAX_FILE_BYTES)
    except OSError:
        return None
    if b"\x00" in data:
        return None
    return data.decode("utf-8", "replace")


MAX_DIRS = 20000
MAX_SECONDS = 10.0


def names_in_project(root: str) -> tuple[set[str], list[str]]:
    """({NAME, ...}, [files read]) for the folder `root`. Real .env files are
    never opened."""
    names: set[str] = set()
    read: list[str] = []
    count = 0
    root = os.path.abspath(root)
    started = time.monotonic()
    seen_dirs = 0
    for dirpath, dirs, files in os.walk(root):
        seen_dirs += 1
        if seen_dirs > MAX_DIRS or time.monotonic() - started > MAX_SECONDS:
            break
        depth = os.path.relpath(dirpath, root).count(os.sep)
        dirs[:] = sorted(d for d in dirs if d not in scan_mod.PRUNE_DIRS
                         and not os.path.islink(os.path.join(dirpath, d)))
        if depth >= MAX_DEPTH:
            dirs[:] = []
        for fname in sorted(files):
            full = os.path.join(dirpath, fname)
            template = _is_template(fname)
            suffix = os.path.splitext(fname)[1].lower()
            if hook_mod.is_env_name(fname) or not (template or suffix in CODE_SUFFIXES
                                                   or fname in ("Dockerfile",)):
                continue
            count += 1
            if count > MAX_FILES:
                return names, read
            text = _read_limited(full)
            if text is None:
                continue
            read.append(os.path.relpath(full, root))
            if template:
                for line in text.splitlines():
                    m = TEMPLATE_LINE_RE.match(line)
                    if m:
                        names.add(m.group(1))    # the value after "=" is dropped here
            else:
                names.update(NAME_RE.findall(text))
    return names, read


def match_recipes(names: set[str], catalog: dict) -> list[dict]:
    """[{service, env_vars}] for each recipe with at least one variable in
    `names`, in catalog (alphabetical) order. env_vars is the recipe's full
    list, so a two-part credential is asked for whole."""
    found = []
    for slug in sorted(catalog):
        recipe = catalog[slug]
        variables = recipes_mod.env_vars(recipe)
        if any(v in names for v in variables):
            found.append({"service": slug, "env_vars": variables})
    return found


def detect(root: str, catalog: dict) -> tuple[list[dict], list[str]]:
    names, read = names_in_project(root)
    return match_recipes(names, catalog), read
