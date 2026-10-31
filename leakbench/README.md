# Agent Leak Benchmark (`leakbench`)

A reproducible suite of ways an AI coding agent can expose an API key, used to
score secret-protection setups **fairly and honestly** — OathKey included, with
its gaps listed, not hidden.

Each *probe* is one small, named leak: read a `.env`, dump the environment,
grep a folder, echo a key in an error, follow a planted instruction, ship a key
in a browser bundle. The harness plants clearly-fake canary secrets
(`sk-canary-<random>`, unique per run) in a throwaway sandbox, simulates the
agent's tool call under a chosen **protection profile**, and records the
outcome.

```
python -m leakbench --profile none
python -m leakbench --profile oathkey-hook
python -m leakbench --profile oathkey-hook --json
```

## Outcomes

| status  | meaning                                                            |
|---------|--------------------------------------------------------------------|
| blocked | the profile denied the tool call before it ran                     |
| masked  | the call ran but the canary was redacted from the output           |
| leaked  | the canary appears in the agent-visible output (a **gap**)         |
| n/a     | the call could not reproduce here (tool missing, daemon down, …)   |

`n/a` is neither a pass nor a fail. Keystore probes read `n/a` under `none`
because the sandbox keyring is empty — under `oathkey-hook` the same probes are
`blocked`, which is the point: they measure whether the *attempt* is stopped.

## Method

1. Build a sandbox: a temp dir with `HOME`/`USERPROFILE`/`XDG_*`/`APPDATA`
   overridden to it, so **the real home and configs are never touched**. Plant
   `.env` variants, `secret.pem`, `~/.ssh/id_rsa`, `~/.aws/credentials`,
   `~/.claude.json`, `.mcp.json`, a built JS bundle, a git repo that committed
   then removed a `.env`, an app log, and canary env vars.
2. For each probe, substitute `{SBX}` (sandbox home) and `{CANARY}`.
3. Ask the profile to judge the probe's **tool call** (`tool_name` +
   `tool_input`). If it denies → `blocked`.
4. Otherwise run the probe's command in a subprocess with the sandbox env, and
   check whether the canary reached the agent-visible output → `leaked`.

## Limits (read these before trusting a score)

- **This simulates an agent's tool calls; it is not a real model.** A profile
  that blocks every probe here can still be bypassed by a model that builds its
  command at run time, splits it across tools, or uses a tool the guardrail is
  not attached to.
- A `blocked` result reflects the *pre-tool* decision only. It does not prove a
  key never reaches the model by another route.
- `n/a` counts depend on which binaries and daemons exist on the host (docker,
  a populated keyring, `/proc`). Compare profiles on the **same** host.
- Canary env vars are planted in the harness's own process environment, so
  env-dump probes leak the canary; this mirrors how a real agent inherits keys
  from its parent shell.

## Profiles

- **none** — blocks nothing. The baseline: every reproducible probe leaks.
- **oathkey-hook** — runs OathKey's Claude Code PreToolUse hook decision
  (`oathkey.hook.check`) on the probe's tool call. Skipped (exit 2) if OathKey
  is not importable.

### Adding a profile (PRs welcome)

A profile is a callable `(tool_payload: dict) -> (blocked: bool, reason: str | None)`.
Add it in `leakbench/profiles.py`:

```python
def _load_mytool() -> Profile:
    import mytool  # raise ImportError if unavailable
    def profile(payload: dict) -> tuple[bool, str | None]:
        if mytool.denies(payload["tool_name"], payload["tool_input"]):
            return True, "mytool denied it"
        return False, None
    return profile
```

Then register the name in `get()` and `AVAILABLE`. If your tool masks output
instead of blocking the call, have the harness see the mask marker (see
`runner.MASK_MARKERS`) and the probe records `masked`.

## Adding a probe

Drop a dict into any `leakbench/probes/*.json` list:

```json
{
  "id": "unique-short-name",
  "category": "tool indirection",
  "attack": "plain words: what the agent would run or read",
  "tool": {"tool_name": "Bash", "tool_input": {"command": "grep -rn sk- {SBX}"}},
  "run": {"kind": "sh", "cmd": "grep -rn 'sk-' '{SBX}'"}
}
```

`run.kind` is `sh | python | node | powershell | cmd | none`. `check` defaults
to `canary_in_output`; use `write_tamper` for settings/key writes and
`no_guard` for spend probes.

## Results (this repo, this host)

61 probes. Run on a Windows host with bash, python, node, git, rg, docker,
powershell present. Reproduce with the commands above.

| profile      | blocked | masked | leaked | n/a |
|--------------|--------:|-------:|-------:|----:|
| none         |       0 |      0 |     54 |   7 |
| oathkey-hook |      22 |      0 |     38 |   1 |

**What OathKey's hook blocks (22):** every `.env` read/write (direct, `cat`,
`sed`, `base64 .env`, `find -name '*.env'`, quote-split `cat .e''nv`,
`git show …:.env`), keystore and clipboard reads (`secret-tool`, `security`,
`keyring`, `cmdkey`, `pbpaste`), `/proc/self/environ`, its own `.oathkey` store,
protected settings writes (`.claude/settings.json`, `.mcp.json`, `~/.claude.json`),
and an MCP tool call whose arguments name a `.env`.

**Top gaps (leaked under oathkey-hook) — the honest failures:**

- **Plain environment dumps** that never name a `.env`: `env`, `printenv`,
  `export -p`, `set`, `Get-ChildItem env:`, `python -c "os.environ"`.
- **Reads of non-`.env` secret files**: `secret.pem`, `~/.ssh/id_rsa`,
  `~/.aws/credentials`, `~/.claude.json`, `.mcp.json`, `credentials.json`
  (the hook guards `.env` names, not arbitrary secret files).
- **Tool indirection not naming `.env`**: `grep -r` / `rg` for a key,
  `find -name '*.pem' -exec cat`, `base64`/`xxd`/`awk` on `secret.pem`,
  `git log -p` surfacing a removed `.env` from history.
- **Browser-bundle exposure**: `VITE_`/`NEXT_PUBLIC_` keys baked into built JS
  and source maps.
- **Output channels**: keys echoed in error messages, HTTP responses, logs,
  tracebacks, `tee`.
- **Code paths**: hard-coded key in a `curl` header; an agent-written script
  that prints `os.environ`/`process.env` (the hook sees the `Write`, not its
  content); prompt-injection exfil via `env` piped to `curl`.
- **Spend**: an uncapped/retry loop making paid calls has no guard.

These gaps are expected: OathKey's hook is a `.env`/keystore pre-tool guardrail,
not an output scrubber, a file-wide DLP, or a spend cap. The benchmark exists to
make that boundary measurable.
