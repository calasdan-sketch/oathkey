"""stuntkey uses only Python's own standard library - no outside code.

This is a promise we make to users, so a test enforces it: if any file in the
package imports something that is not in the standard library, this fails.
"""
import ast
import os
import sys
import unittest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stuntkey")


# stdlib modules newer than the oldest supported Python (3.10). Allowed only
# inside `try:` blocks that catch ImportError, so 3.10 still runs.
NEWER_STDLIB = {"tomllib"}


def _guarded(tree):
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
                isinstance(h.type, ast.Name) and h.type.id in ("ImportError", "ModuleNotFoundError")
                for h in node.handlers):
            ids.update(id(s) for s in node.body if isinstance(s, (ast.Import, ast.ImportFrom)))
    return ids


def _imports(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), path)
    guarded = _guarded(tree)
    for node in ast.walk(tree):
        if id(node) in guarded and all(
                (a.name if isinstance(node, ast.Import) else node.module or "").split(".")[0]
                in NEWER_STDLIB for a in node.names):
            continue
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0]


class StdlibOnlyTests(unittest.TestCase):
    def test_no_outside_imports(self):
        std = set(sys.stdlib_module_names) | {"stuntkey", "__future__"}
        bad = []
        for name in sorted(os.listdir(PKG)):
            if name.endswith(".py"):
                for mod in set(_imports(os.path.join(PKG, name))):
                    if mod not in std:
                        bad.append(f"{name}: {mod}")
        self.assertEqual(bad, [], "outside packages are imported: " + ", ".join(bad))

    def test_pyproject_lists_no_dependencies(self):
        root = os.path.dirname(PKG)
        with open(os.path.join(root, "pyproject.toml"), encoding="utf-8") as f:
            text = f.read()
        import re
        m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.S | re.M)
        if m:
            self.assertEqual(m.group(1).strip(), "", "pyproject lists dependencies")


if __name__ == "__main__":
    unittest.main()
