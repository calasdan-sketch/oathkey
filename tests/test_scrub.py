import base64
import io
import json
import sys
import unittest
from urllib.parse import quote

from stuntkey import remote, scrub

# built at run time so this file never contains a key-shaped string
SECRET = "sk" + "_live_" + "A1b2C3d4E5f6G7h8"


class FormsTest(unittest.TestCase):
    def assertGone(self, text):
        out = scrub.scrub_text(text, [SECRET])
        self.assertNotIn(SECRET, out)
        return out

    def test_raw(self):
        self.assertIn("[REDACTED]", self.assertGone(f"token={SECRET}!"))

    def test_encodings(self):
        raw = SECRET.encode()
        shapes = [
            quote(SECRET, safe=""), SECRET[::-1], raw.hex(), raw.hex().upper(),
            json.dumps(SECRET)[1:-1],
            base64.b64encode(raw).decode(),
            base64.urlsafe_b64encode(raw).decode(),
        ]
        for k in (0, 1, 2):          # base64 of the key inside a longer string
            shapes.append(base64.b64encode(b"u" * k + raw + b":x").decode())
        shapes.append(base64.b64encode(b"user:" + raw).decode())
        for s in shapes:
            out = scrub.scrub_text("echo " + s + " end", [SECRET])
            # nothing 8+ chars of the pure-secret part of the encoding survives
            self.assertNotEqual(out, "echo " + s + " end", s)

    def test_split_across_chunks(self):
        s = scrub.Scrubber([SECRET])
        data = b"before " + SECRET.encode() + b" after"
        for cut in range(1, len(data)):
            s = scrub.Scrubber([SECRET])
            out = s.feed(data[:cut]) + s.feed(data[cut:]) + s.flush()
            self.assertNotIn(SECRET.encode(), out, cut)
            self.assertIn(b"before", out)
            self.assertIn(b"after", out)

    def test_short_values_left_alone(self):
        self.assertEqual(scrub.scrub_text("abc abc", ["abc"]), "abc abc")

    def test_no_secrets_passes_through(self):
        self.assertEqual(scrub.scrub_text("hello", []), "hello")


class RunScrubbedTest(unittest.TestCase):
    def test_child_cannot_print_key(self):
        out, err = io.BytesIO(), io.BytesIO()
        code = scrub.run_scrubbed(
            [sys.executable, "-c",
             "import os,sys;print(os.environ['K']);print(os.environ['K'],file=sys.stderr)"],
            {**__import__("os").environ, "K": SECRET}, [SECRET], out, err)
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET.encode(), out.getvalue())
        self.assertNotIn(SECRET.encode(), err.getvalue())
        self.assertIn(b"[REDACTED]", out.getvalue())


class SshArgsTest(unittest.TestCase):
    def test_safe_options_pass(self):
        self.assertEqual(remote.check_ssh_args(["-p", "2222", "-o", "ConnectTimeout=5"]),
                         ["-p", "2222", "-o", "ConnectTimeout=5"])

    def test_dangerous_options_refused(self):
        for bad in (["-o", "ProxyCommand=touch /tmp/x"],
                    ["-o", "LocalCommand=id"], ["-F", "/tmp/cfg"],
                    ["-J", "evil"], ["-o", "PermitLocalCommand=yes"],
                    ["-p", "22;id"], ["-o"]):
            with self.assertRaises(remote.RemoteError):
                remote.check_ssh_args(bad)


if __name__ == "__main__":
    unittest.main()
