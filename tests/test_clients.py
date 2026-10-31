import json
import os
import tempfile
import unittest

from stuntkey import clients


class Install(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = os.path.join(self.d, "cfg.json")

    def test_merge_keeps_other_servers_and_settings(self):
        json.dump({"theme": "dark", "mcpServers": {"other": {"command": "x"}}},
                  open(self.path, "w"))
        p = clients.plan(self.path, "mcpServers")
        self.assertEqual(p["others"], ["other"])
        clients.apply(p)
        got = json.load(open(self.path))
        self.assertEqual(got["theme"], "dark")
        self.assertEqual(got["mcpServers"]["other"], {"command": "x"})
        self.assertEqual(got["mcpServers"]["stuntkey"], clients.server_entry())
        self.assertTrue([f for f in os.listdir(self.d) if ".bak-" in f])

    def test_creates_missing_file_and_no_key_inside(self):
        p = clients.plan(os.path.join(self.d, "new", "mcp.json"), "servers")
        clients.apply(p)
        text = open(p["path"]).read()
        self.assertIn("stuntkey", text)
        for bad in ("token", "secret", "api_key", "sk-"):
            self.assertNotIn(bad, text.lower())

    def test_uses_absolute_python(self):
        self.assertTrue(os.path.isabs(clients.server_entry()["command"]))

    def test_idempotent(self):
        clients.apply(clients.plan(self.path, "mcpServers"))
        self.assertTrue(clients.plan(self.path, "mcpServers")["already"])

    def test_bad_json_not_touched(self):
        open(self.path, "w").write("{not json")
        with self.assertRaises(ValueError):
            clients.plan(self.path, "mcpServers")
        self.assertEqual(open(self.path).read(), "{not json")

    def test_wrong_shape_not_touched(self):
        json.dump({"mcpServers": []}, open(self.path, "w"))
        with self.assertRaises(ValueError):
            clients.plan(self.path, "mcpServers")

    def test_uninstall_keeps_other_servers(self):
        json.dump({"mcpServers": {"other": {"command": "x"}}}, open(self.path, "w"))
        clients.apply(clients.plan(self.path, "mcpServers"))
        tg = {"cursor": (self.path, "mcpServers")}
        orig = clients.targets
        clients.targets = lambda **kw: tg
        try:
            clients.remove(["cursor"], True, out=lambda *a: None)
        finally:
            clients.targets = orig
        got = json.load(open(self.path))
        self.assertEqual(list(got["mcpServers"]), ["other"])

    def test_asks_first(self):
        out = []
        clients.run(["cursor"], False, ask=lambda q: "n", out=out.append,
                    home=self.d, cwd=self.d)
        self.assertFalse(os.path.exists(os.path.join(self.d, ".cursor", "mcp.json")))
        clients.run(["cursor"], True, out=out.append, home=self.d, cwd=self.d)
        self.assertTrue(os.path.exists(os.path.join(self.d, ".cursor", "mcp.json")))


if __name__ == "__main__":
    unittest.main()
