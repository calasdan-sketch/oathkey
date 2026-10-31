"""`stuntkey export`: copy a stored key into GitHub or Vercel without typing it.

The key goes to the vendor's OWN command-line tool through its standard
INPUT (a pipe), the way both tools document for secrets:

  GitHub   gh secret set NAME [--repo OWNER/REPO] [--env ENVIRONMENT]
           (the docs: "reads from standard input if --body is not specified")
  Vercel   vercel env add NAME ENVIRONMENT --sensitive
           (the docs: a value can come from standard input)

So the key is never on a command line (where `ps` and shell history would
see it), never in a file this tool writes and never on screen. Only names
are in the argument list. This tool does not talk to GitHub or Vercel
itself: you must have `gh` / `vercel` installed and signed in.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys

from . import dialog as dialog_mod
from . import keychain as keychain_mod
from . import procs
from . import recipes as recipes_mod
from . import safeprompt
from . import redact as redact_mod

TARGETS = ("github", "vercel")
PROGRAMS = {"github": "gh", "vercel": "vercel"}
LABELS = {"github": "GitHub (gh secret set)", "vercel": "Vercel (vercel env add)"}
REPO_RE = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9.-]*/)?[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
ENV_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
VERCEL_ENVS = ("development", "preview", "production")
TIMEOUT = 90


class ExportError(Exception):
    """A plain sentence; never holds a key."""


def build_argv(target: str, exe: str, name: str, repo: str | None = None,
               environment: str | None = None, overwrite: bool = False) -> list[str]:
    """The command line: names only, never a value."""
    if not recipes_mod.ENV_VAR_RE.match(name):
        raise ExportError("not a valid variable name")
    if target == "github":
        argv = [exe, "secret", "set", name]
        if repo:
            if not REPO_RE.match(repo):
                raise ExportError("--repo must look like OWNER/REPO")
            argv += ["--repo", repo]
        if environment:
            if not ENV_NAME_RE.match(environment):
                raise ExportError("--environment is not a valid environment name")
            argv += ["--env", environment]
        return argv
    if target == "vercel":
        environment = environment or "production"
        if environment not in VERCEL_ENVS:
            raise ExportError("--environment for Vercel must be development, preview or production")
        if repo:
            raise ExportError("--repo is for GitHub; Vercel uses the project linked in this folder")
        argv = [exe, "env", "add", name, environment, "--sensitive"]
        if overwrite:
            argv.append("--force")
        return argv
    raise ExportError("unknown target")


GITHUB_REMOTE_RE = re.compile(
    r"github\.com[:/]+(?P<repo>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*?)(?:\.git)?/?\Z")


def github_repo_here(cwd: str | None = None, git_run=subprocess.run, find=procs.find_program) -> str | None:
    """OWNER/REPO from this folder's `origin` remote, or None."""
    git = find("git")
    if not git:
        return None
    try:
        done = git_run([git, "-C", cwd or ".", "remote", "get-url", "origin"],
                       capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    m = GITHUB_REMOTE_RE.search(done.stdout.decode("utf-8", "replace").strip())
    return m.group("repo") if m else None


def vercel_project_here(cwd: str | None = None) -> str | None:
    """The linked Vercel project (from .vercel/project.json): its name when the
    file has one, else its id."""
    path = os.path.join(cwd or ".", ".vercel", "project.json")
    try:
        if os.path.islink(path) or os.path.getsize(path) > 65536:
            return None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    for key in ("projectName", "name", "projectId"):
        value = data.get(key)
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value):
            return value
    return None


def send(argv: list[str], value: str, run=subprocess.run) -> tuple[bool, str]:
    """Run the vendor tool with `value` on its standard input. Returns
    (ok, note); the note is the tool's complaint with the value scrubbed
    out, cut short."""
    try:
        done = run(argv, input=value.encode("utf-8"), capture_output=True,
                   timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"{argv[0]} did not finish within {TIMEOUT} seconds"
    except OSError as e:
        return False, f"{argv[0]} could not be run ({type(e).__name__})"
    if done.returncode == 0:
        return True, ""
    scrub = redact_mod.Redactor([value])
    text = scrub.text(done.stderr.decode("utf-8", "replace") or done.stdout.decode("utf-8", "replace"))
    text = " ".join(recipes_mod.printable(text).split())[:300]
    return False, text or f"{argv[0]} exited with status {done.returncode}"


def cmd_export(args, catalog: dict, ask=None, interactive=None, out=None,
               which=None, run=subprocess.run, read_fn=None, backend=None,
               window=None) -> int:
    out = out or sys.stdout
    recipe = catalog.get(args.service)
    if recipe is None:
        out.write("unknown service. See `stuntkey list`.\n")
        return 1
    program = PROGRAMS[args.to]
    exe = procs.find_program(program, which or __import__("shutil").which)
    if not exe:
        out.write(f"  {program} is not installed (or not on PATH). Install it and sign in "
                  f"({program} auth login), then run this again.\n")
        return 1
    # Say WHICH repository / project the key is going to, from what this
    # folder says - not from whatever the vendor's tool would pick.
    repo = args.repo
    project = None
    if args.to == "github":
        repo = repo or github_repo_here()
        if not repo:
            out.write("  I could not tell which GitHub repository this is (no github.com "
                      "'origin' remote).\n  Say it: --repo OWNER/REPO\n")
            return 1
    else:
        project = vercel_project_here()
        if not project:
            out.write("  This folder is not linked to a Vercel project (no .vercel/project.json).\n"
                      "  Run `vercel link` here first, so I can tell you where the key will go.\n")
            return 1
    try:
        values = keychain_mod.gather(
            recipe, backend if backend is not None else keychain_mod.detect_backend(),
            read_fn, args.env_file, "keychain")
        argvs = {name: build_argv(args.to, exe, name, repo, args.environment,
                                  args.overwrite) for name in values}
    except ExportError as e:
        out.write(f"  {recipes_mod.printable(e)}\n")
        return 1
    except keychain_mod.KeychainError as e:
        out.write(f"  I could not find the stored key to export: "
                  f"{recipes_mod.printable(e)}. Run `stuntkey connect {args.service}` first.\n")
        return 1
    names = ", ".join(values)
    where = (f"repository {repo}" if args.to == "github" else f"project {project}")
    envname = args.environment or ("production" if args.to == "vercel" else None)
    target = f"{LABELS[args.to]}, {where}" + (f", environment {envname}" if envname else "")
    out.write(f"  About to send {names} to {target}.\n"
              f"  The value goes to `{program}` through a pipe - never on a command line, "
              f"never on screen.\n")
    if interactive is None:
        interactive = lambda: bool(sys.stdin and sys.stdin.isatty())
    at_terminal = interactive()
    if not (args.yes and at_terminal):
        # --yes counts only at a real terminal. Anywhere else (a script, an AI's
        # shell, a pipe) a person must answer in a window.
        answer = (window or dialog_mod.confirm)(
            "stuntkey - send a key?", f"Send {names} to {target}?\n\n"
            f"The value goes to `{program}` through a pipe, never on screen.")
        if answer is True:
            pass
        elif answer is not None:
            out.write("  cancelled - nothing was sent.\n")
            values.clear()
            return 1
        elif not at_terminal:
            out.write("  There is no window and no terminal to ask on, so nothing was "
                      "sent. (--yes only counts at a real terminal.)\n")
            values.clear()
            return 1
        elif not safeprompt.ask(
                f"  Send it to {where}? [y/N]: ", out, enter_means=False, reader=ask,
                if_key="That looked like a key. Do not paste it here. "
                       "Type y or n."):
            out.write("  cancelled - nothing was sent.\n")
            values.clear()
            return 1
    failed = 0
    for name, value in list(values.items()):
        ok, note = send(argvs[name], value, run)
        if ok:
            out.write(f"  ✓ {name} sent to {args.to}\n")
        else:
            failed += 1
            out.write(f"  ✗ {name}: {note}\n")
    values.clear()
    return 1 if failed else 0
