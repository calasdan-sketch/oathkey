#!/usr/bin/env node
// npx stuntkey: find Python 3.10+ and run the stuntkey.pyz shipped in this
// package, or `python -m stuntkey` when it is not there. No dependencies.
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const pyz = path.join(__dirname, "..", "stuntkey.pyz");
const candidates = process.platform === "win32"
  ? [["py", "-3"], ["python"], ["python3"]]
  : [["python3"], ["python"]];
const probe = "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)";

function findPython() {
  for (const [cmd, ...pre] of candidates) {
    const r = spawnSync(cmd, [...pre, "-c", probe], { stdio: "ignore" });
    if (!r.error && r.status === 0) return [cmd, pre];
  }
  return null;
}

const found = findPython();
if (!found) {
  console.error("stuntkey needs Python. Install Python 3.10+ from python.org, then run again.");
  process.exit(1);
}
const [cmd, pre] = found;
const target = fs.existsSync(pyz) ? [pyz] : ["-m", "stuntkey"];
const r = spawnSync(cmd, [...pre, ...target, ...process.argv.slice(2)], { stdio: "inherit" });
if (r.error) {
  console.error(`stuntkey: could not start ${cmd}: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status === null ? 1 : r.status);
