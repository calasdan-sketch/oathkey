"""stuntkey uses only Python's own standard library - no outside code.

This is a promise we make to users, so a test enforces it: if any file in the
package imports something that is not in the standard library, this fails.
"""
import ast
import os
import sys
import unittest

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "stuntkey")


def _imports(path):
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), path)
    for node in ast.walk(tree):
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
