"""Start oathkey from oathkey.pyz (this file is the .pyz's own __main__.py).

oathkey reads its recipes and SKILL.md as plain files, which a zip cannot
give. So the first run unpacks the package once into
~/.oathkey/pyz/<first 16 hex of the .pyz's sha256>/ and runs it from there;
a changed .pyz gets a new folder. Unpacked into a temporary folder first and
renamed, so a half-unpacked copy is never used.
"""
import hashlib
import os
import shutil
import sys
import tempfile
import zipfile

if sys.version_info < (3, 10):
    sys.stderr.write("oathkey needs Python 3.10 or newer. Install Python 3.10+ "
                     "from python.org, then run again.\n")
    sys.exit(1)


def _unpacked(pyz: str) -> str:
    with open(pyz, "rb") as f:
        tag = hashlib.sha256(f.read()).hexdigest()[:16]
    base = os.path.join(os.path.expanduser("~"), ".oathkey", "pyz")
    dest = os.path.join(base, tag)
    if os.path.isfile(os.path.join(dest, "oathkey", "__init__.py")):
        return dest
    os.makedirs(base, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=base)
    with zipfile.ZipFile(pyz) as z:
        z.extractall(tmp, [n for n in z.namelist() if n.startswith("oathkey/")])
    try:
        os.rename(tmp, dest)
    except OSError:                       # another run unpacked it first
        shutil.rmtree(tmp, ignore_errors=True)
    return dest


def main() -> int:
    args = sys.argv[1:]
    if any(args[i:i + 2] == ["hook", "install"] for i in range(len(args))):
        # ponytail: the hook starts `python -I -m oathkey`, which a .pyz cannot
        # answer, so it would block every tool call. Teach hook.py the .pyz first.
        sys.stderr.write("The Claude Code hook needs oathkey installed with pip: "
                         "py -m pip install --user oathkey (or pipx install oathkey), "
                         "then run `oathkey hook install`.\n")
        return 2
    pyz = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _unpacked(pyz))
    import oathkey
    oathkey.PYZ = pyz                     # MCP entries and hooks start this file again
    from oathkey.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
