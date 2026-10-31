"""Start stuntkey from stuntkey.pyz (this file is the .pyz's own __main__.py).

stuntkey reads its recipes and SKILL.md as plain files, which a zip cannot
give. So the first run unpacks the package once into
~/.stuntkey/pyz/<first 16 hex of the .pyz's sha256>/ and runs it from there;
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
    sys.stderr.write("stuntkey needs Python 3.10 or newer. Install Python 3.10+ "
                     "from python.org, then run again.\n")
    sys.exit(1)


def _unpacked(pyz: str) -> str:
    with open(pyz, "rb") as f:
        tag = hashlib.sha256(f.read()).hexdigest()[:16]
    base = os.path.join(os.path.expanduser("~"), ".stuntkey", "pyz")
    dest = os.path.join(base, tag)
    if os.path.isfile(os.path.join(dest, "stuntkey", "__init__.py")):
        return dest
    os.makedirs(base, mode=0o700, exist_ok=True)
    tmp = tempfile.mkdtemp(dir=base)
    with zipfile.ZipFile(pyz) as z:
        z.extractall(tmp, [n for n in z.namelist() if n.startswith("stuntkey/")])
    try:
        os.rename(tmp, dest)
    except OSError:                       # another run unpacked it first
        shutil.rmtree(tmp, ignore_errors=True)
    return dest


def main() -> int:
    pyz = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _unpacked(pyz))
    import stuntkey
    stuntkey.PYZ = pyz                     # MCP entries and hooks start this file again
    from stuntkey.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
