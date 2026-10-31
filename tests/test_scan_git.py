import os
import shutil
import subprocess
import tempfile
import unittest

from stuntkey import gitscan as scan

KEY = "ghp_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"   # built at run time


def git(d, *a):
    subprocess.run(["git", "-C", d, "-c", "user.email=t@t", "-c", "user.name=t", *a],
                   check=True, capture_output=True)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class GitScan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        git(self.d, "init", "-q")

    def test_key_removed_but_still_in_history(self):
        p = os.path.join(self.d, "app.py")
        open(p, "w").write(f'TOKEN = "{KEY}"\n')
        git(self.d, "add", "-A")
        git(self.d, "commit", "-qm", "oops")
        open(p, "w").write("TOKEN = None\n")
        git(self.d, "commit", "-qam", "clean")
        res = scan.scan_git(self.d)
        self.assertEqual(len(res["findings"]), 1)
        f = res["findings"][0]
        self.assertEqual(f["file"], "app.py")
        self.assertNotIn(KEY, repr(res))          # masked
        self.assertNotIn(KEY, scan.format_git(res))

    def test_clean_repo(self):
        open(os.path.join(self.d, "a.txt"), "w").write("hello\n")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-qm", "x")
        self.assertEqual(scan.scan_git(self.d)["findings"], [])

    def test_staged_only(self):
        open(os.path.join(self.d, "a.txt"), "w").write("hello\n")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-qm", "x")
        open(os.path.join(self.d, "b.txt"), "w").write(f"k={KEY}\n")
        git(self.d, "add", "b.txt")
        res = scan.scan_git(self.d, staged=True)
        self.assertEqual(len(res["findings"]), 1)

    def test_not_a_repo_is_an_error_not_a_pass(self):
        res = scan.scan_git(tempfile.mkdtemp(), staged=True)
        self.assertTrue(res["error"])

    def test_hook_install_and_no_overwrite(self):
        path = scan.install_hook(self.d)
        text = open(path).read()
        self.assertIn("exit 1", text)
        self.assertIn("scan-git --staged", text)
        scan.install_hook(self.d)                  # re-install is fine
        open(path, "w").write("#!/bin/sh\necho mine\n")
        with self.assertRaises(OSError):
            scan.install_hook(self.d)
        self.assertIn("mine", open(path).read())


if __name__ == "__main__":
    unittest.main()
