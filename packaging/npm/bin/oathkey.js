#!/usr/bin/env node
// npx oathkey: find Python 3.10+ and run the oathkey.pyz shipped in this
// package, or `python -m oathkey` when it is not there. No dependencies.
"use strict";
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const pyz = path.join(__dirname, "..", "oathkey.pyz");
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
  console.error("oathkey needs Python. Install Python 3.10+ from python.org, then run again.");
  process.exit(1);
}
const [cmd, pre] = found;
const target = fs.existsSync(pyz) ? [pyz] : ["-m", "oathkey"];
const r = spawnSync(cmd, [...pre, ...target, ...process.argv.slice(2)], { stdio: "inherit" });
if (r.error) {
  console.error(`oathkey: could not start ${cmd}: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status === null ? 1 : r.status);
