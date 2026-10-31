"""Coming from 0.8, when this tool was called oathkey.

- The folder: on the first run, ~/.oathkey is COPIED to ~/.stuntkey (only
  when ~/.stuntkey does not exist yet). The old folder is left as it was.
- Keychain entries: 0.8 saved keys as "oathkey:<service>". keychain.read()
  falls back to that name; `stuntkey migrate` copies them to the new name,
  reads each one back, and removes the old one only with --remove-old.
- Project files: an old oathkey.json / oathkey.policy is used when the new
  file is absent (manifest.py, policy.py), with a note.
- Hooks and MCP entries 0.8 wrote: `hook install` / `install` replace them
  (after showing the change), and `doctor` points them out.

Nothing here ever prints a key.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

LEGACY_DIR = ".oathkey"
NEW_DIR = ".stuntkey"
LEGACY_MCP_NAME = "oathkey"
DONE_FILE = "keychain-migrated"     # in ~/.stuntkey, written by a clean `migrate`
_noted: set = set()


def _homes() -> list[str]:
    from . import consent
    return list(dict.fromkeys((os.path.expanduser("~"), consent.home_dir())))


def copy_home(home: str | None = None, err=None) -> bool:
    """Copy ~/.oathkey to ~/.stuntkey when only the old one exists. True when
    a copy was made. Copied into a temporary folder first and renamed, so a
    half copy is never used; a second run racing this one just loses."""
    copied = False
    for base in ([home] if home else _homes()):
        old, new = os.path.join(base, LEGACY_DIR), os.path.join(base, NEW_DIR)
        if not os.path.isdir(old) or os.path.lexists(new):
            continue
        tmp = None
        try:
            tmp = tempfile.mkdtemp(prefix=".stuntkey-migrate-", dir=base)
            dest = os.path.join(tmp, NEW_DIR)
            # pyz/ only holds unpacked code: the .pyz unpacks itself again
            shutil.copytree(old, dest, symlinks=True,
                            ignore=shutil.ignore_patterns("pyz"))
            os.chmod(dest, 0o700)
            os.rename(dest, new)
            copied = True
            (err or sys.stderr).write(
                f"stuntkey: copied your settings from {old} to {new} (oathkey is now "
                f"stuntkey). The old folder was left as it was. Run `stuntkey doctor` "
                f"to see what else to move over.\n")
        except OSError as e:
            if not os.path.lexists(new):
                (err or sys.stderr).write(
                    f"stuntkey: could not copy {old} to {new} ({e.strerror or e}); "
                    f"nothing was changed.\n")
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
    return copied


def pick(folder: str, name: str, legacy: str, err=None) -> str:
    """`folder/name`, or `folder/legacy` when only the old 0.8 file is there
    (said once per file)."""
    path = os.path.join(folder, name)
    old = os.path.join(folder, legacy)
    if os.path.lexists(path) or not os.path.lexists(old):
        return path
    if old not in _noted:
        _noted.add(old)
        (err or sys.stderr).write(f"stuntkey: using the old {legacy} in {folder} "
                                  f"(rename it to {name} when you like).\n")
    return old


# ----------------------------------------------------------- the keychain

def _names(catalog: dict) -> list[tuple[str, str]]:
    """(service, env_var) of every key stuntkey could have saved: the recipes,
    and the names in the fingerprint file (keys saved under recipes since
    removed)."""
    from . import recipes as recipes_mod
    from . import scrub
    out = [(slug, var) for slug, r in catalog.items() for var in recipes_mod.env_vars(r)]
    try:
        for name in scrub._read_fingerprints(scrub.fingerprint_path()).get("keys", {}):
            service, _, var = str(name).partition("/")
            if service and var:
                out.append((service, var))
    except Exception:       # noqa: BLE001 - only a hint; the recipes are the list
        pass
    return list(dict.fromkeys(out))


def migrate_keychain(catalog: dict, remove_old: bool = False, backend=None,
                     out=None) -> int:
    """Copy each "oathkey:<service>" keychain entry to the new name. 0 when
    every one is copied (or none was there), 1 on a problem."""
    from . import keychain
    out = out or sys.stdout
    try:
        backend = backend or keychain.detect_backend()
    except keychain.KeychainError:
        backend = None
    if backend is None:
        out.write("  No OS keychain here, so there are no saved keys to move.\n")
        return 0
    copied = kept = problems = 0
    for service, var in _names(catalog):
        name = f"{service} ({var})"
        try:
            old = keychain.read_legacy(service, var, backend)
            if old is None:
                continue
            now = keychain.read_current(service, var, backend)
            if now is not None and now != old:
                out.write(f"  {name}: stuntkey already has a different key; kept it, "
                          f"the old one was left alone.\n")
                kept += 1
                continue
            if now is None:
                keychain.store(service, var, old, backend)   # reads it back
            if keychain.read_current(service, var, backend) != old:
                raise keychain.KeychainError("reading the copy back did not match")
            del old, now
            copied += 1
            if remove_old:
                keychain.delete_legacy(service, var, backend)
                out.write(f"  {name}: copied, checked, old entry removed.\n")
            else:
                out.write(f"  {name}: copied and checked.\n")
        except keychain.KeychainError as e:
            problems += 1
            out.write(f"  {name}: not copied ({e}). The old entry is still there.\n")
    out.write(f"\n  {copied} key(s) copied, {kept} kept as they were, "
              f"{problems} problem(s).\n")
    if copied and not remove_old:
        out.write("  The old entries are still in the keychain. When everything "
                  "works, `stuntkey migrate --remove-old` removes them.\n")
    if not problems:
        _mark_done()
    return 1 if problems else 0


def _mark_done() -> None:
    from .store import write_private
    from . import remote
    try:
        os.makedirs(remote.home_dir(), mode=0o700, exist_ok=True)
        write_private(os.path.join(remote.home_dir(), DONE_FILE), "1\n")
    except OSError:
        pass


def had_oathkey() -> bool:
    """Did oathkey 0.8 run on this computer (is there a ~/.oathkey)?"""
    return any(os.path.isdir(os.path.join(h, LEGACY_DIR)) for h in _homes())


def keychain_pending() -> bool:
    """Is there a 0.8 folder and has `stuntkey migrate` not run cleanly yet?
    (Decided without reading the keychain: that can ask for a password.)"""
    from . import remote
    return (had_oathkey()
            and not os.path.exists(os.path.join(remote.home_dir(), DONE_FILE)))


# ---------------------------------------------- old hooks and MCP entries

def legacy_mcp(tg: dict | None = None) -> list[str]:
    """The AI tools whose config still has 0.8's "oathkey" MCP entry."""
    import json
    from . import clients
    found = []
    for name, (path, key) in (clients.targets() if tg is None else tg).items():
        try:
            with open(path, encoding="utf-8-sig") as f:
                if LEGACY_MCP_NAME in json.load(f).get(key, {}):
                    found.append(name)
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    return found


def legacy_hooks(paths: list[str] | None = None) -> list[str]:
    """The Claude Code settings files that still hold 0.8's hook."""
    from . import hook
    paths = paths or [hook.user_settings_path(), hook.project_settings_path()]
    found = []
    for path in dict.fromkeys(paths):
        try:
            if hook.legacy_handlers(hook.load_settings(path)):
                found.append(path)
        except hook.SettingsError:
            continue
    return found


def doctor_checks(add) -> None:
    try:
        if keychain_pending():
            add("old oathkey keys", False, "may still be under their old keychain names",
                "Run `stuntkey migrate` (copies them, never prints them).")
        tools = legacy_mcp()
        if tools:
            add("old oathkey MCP entry", False, "in " + ", ".join(tools),
                "Run `stuntkey install` to replace it.")
        hooks = legacy_hooks()
        if hooks:
            add("old oathkey hook", False, "in " + ", ".join(hooks),
                "Run `stuntkey hook install` (add --project for a project's file) to replace it.")
    except Exception as e:                                   # noqa: BLE001
        add("oathkey migration", False, f"could not check ({type(e).__name__})", "")


def cmd_migrate(args, catalog: dict) -> int:
    print("  Copying keys saved by oathkey (0.8) to their stuntkey names. "
          "No key is shown.\n")
    return migrate_keychain(catalog, remove_old=args.remove_old)
