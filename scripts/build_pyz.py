"""Build the one-file oathkey: dist/oathkey.pyz, and the Windows portable zip
dist/oathkey-<version>-windows.zip (oathkey.pyz + oathkey.cmd + LICENSE) that
the winget manifest in packaging/winget/ points at.

Standard library only. Run from anywhere:

    python scripts/build_pyz.py [OUT_DIR]        (default: dist/)

Then: python dist/oathkey.pyz doctor  (any Python 3.10+).
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
    with open(os.path.join(ROOT, "oathkey", "__init__.py"), encoding="utf-8") as f:
        return re.search(r'__version__ = "([^"]+)"', f.read()).group(1)


def build(out_dir: str) -> tuple:
    os.makedirs(out_dir, exist_ok=True)
    pyz = os.path.join(out_dir, "oathkey.pyz")
    stage = tempfile.mkdtemp(prefix="oathkey-pyz-")
    try:
        shutil.copytree(os.path.join(ROOT, "oathkey"), os.path.join(stage, "oathkey"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]"))
        shutil.copy(os.path.join(ROOT, "scripts", "pyz_main.py"),
                    os.path.join(stage, "__main__.py"))
        zipapp.create_archive(stage, pyz, interpreter="/usr/bin/env python3",
                              compressed=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    win = os.path.join(out_dir, f"oathkey-{version()}-windows.zip")
    with zipfile.ZipFile(win, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(pyz, "oathkey.pyz")
        z.write(os.path.join(ROOT, "packaging", "winget", "oathkey.cmd"), "oathkey.cmd")
        z.write(os.path.join(ROOT, "LICENSE"), "LICENSE")
    return pyz, win


if __name__ == "__main__":
    for path in build(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist")):
        print(path)
