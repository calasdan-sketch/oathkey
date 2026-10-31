"""Build the one-file stuntkey: dist/stuntkey.pyz, and the Windows portable zip
dist/stuntkey-<version>-windows.zip (stuntkey.pyz + stuntkey.cmd + LICENSE) that
the winget manifest in packaging/winget/ points at.

Standard library only. Run from anywhere:

    python scripts/build_pyz.py [OUT_DIR]        (default: dist/)

Then: python dist/stuntkey.pyz doctor  (any Python 3.10+).
"""
import os
import re
import shutil
import sys
import tempfile
import zipapp
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def version() -> str:
    with open(os.path.join(ROOT, "stuntkey", "__init__.py"), encoding="utf-8") as f:
        return re.search(r'__version__ = "([^"]+)"', f.read()).group(1)


def build(out_dir: str) -> tuple:
    os.makedirs(out_dir, exist_ok=True)
    pyz = os.path.join(out_dir, "stuntkey.pyz")
    stage = tempfile.mkdtemp(prefix="stuntkey-pyz-")
    try:
        shutil.copytree(os.path.join(ROOT, "stuntkey"), os.path.join(stage, "stuntkey"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]"))
        shutil.copy(os.path.join(ROOT, "scripts", "pyz_main.py"),
                    os.path.join(stage, "__main__.py"))
        zipapp.create_archive(stage, pyz, interpreter="/usr/bin/env python3",
                              compressed=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    win = os.path.join(out_dir, f"stuntkey-{version()}-windows.zip")
    with zipfile.ZipFile(win, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(pyz, "stuntkey.pyz")
        z.write(os.path.join(ROOT, "packaging", "winget", "stuntkey.cmd"), "stuntkey.cmd")
        z.write(os.path.join(ROOT, "LICENSE"), "LICENSE")
    return pyz, win


if __name__ == "__main__":
    for path in build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist")):
        print(path)
