# oathkey

**Let your AI use your API keys through oathkey without holding them.**

> **Beta: not independently security-reviewed yet. Use at your own risk; MIT, no warranty.**

- The key sits in your computer's own keychain. When your AI needs an API, it asks oathkey to make the call, and oathkey adds the key itself.
- Replies are cleaned of the key. Anything other than a read (GET) waits for your click. Every call is logged.
- Plain Python, no extra packages. No account, no server, no cloud.
- Not related to OATH/TOTP one-time codes.

![Recording of a terminal running oathkey --version, list, selftest and audit show. The output is real; the demo does not show saving a key.](https://raw.githubusercontent.com/calasdan-sketch/oathkey/main/docs/demo.svg)

## Start here (four steps)

Need pipx? https://pipx.pypa.io

```
pipx install oathkey
oathkey get github            # opens the key page; you click Copy; oathkey tests the key and saves it
oathkey install               # plug oathkey into Claude, Cursor or VS Code, then restart that app
oathkey doctor                # health check; "AI tools: plugged into ..." means it is connected
```

When a key page asks which permissions to give, pick read-only or the minimum it offers.

Now ask your AI: *"Who am I on GitHub?"* The AI asks oathkey for `GET /user`; oathkey makes the call with your key and hands back only the answer. The first time, a window asks you to allow GitHub reads for this session. To see what it did: `oathkey audit show`.

> No `pipx`? `pip install oathkey` works too. Latest unreleased code: `pipx install git+https://github.com/calasdan-sketch/oathkey`.
> Needs Python 3.10 or newer. On Linux the keychain needs `secret-tool` (package `libsecret-tools`). If your computer says `oathkey` is not found, close the window and open a new one, or run `python -m oathkey`.

## When your AI writes normal code

Asking oathkey to make a call works when the AI talks to oathkey (through MCP or `serve`). If instead your AI writes an ordinary program that uses a vendor's SDK (for example `openai.OpenAI()` reading `OPENAI_API_KEY`), run that program through the proxy:

```
oathkey proxy -- python app.py
```

The program gets `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GROQ_BASE_URL` and `TOGETHER_BASE_URL` pointing at a local oathkey address on this computer, and its `*_API_KEY` is a throwaway password for that address, not your key. oathkey adds the real key on the way out and scrubs it from the answers. If oathkey stops, the program's calls fail instead of going out on their own. `--print-env` prints the variables for a tool you start yourself. There is no certificate trickery: this works only for SDKs that let you change their base address (OpenAI, Anthropic, Groq, Together); other vendors stay on brokered calls.

For other programs, `oathkey run openai -- python app.py` puts the key in that one program's environment only and scrubs it from the program's output. That program does see the key, so use `run` yourself; do not hand it to an AI that can run shell commands.

## The permission windows

oathkey asks you, not the AI, before anything risky. The question appears in a window from your operating system (outside the AI app, so the AI cannot type the answer):

- **Windows:** a standard message box titled "oathkey - permission needed". No is the default button.
- **macOS:** a system dialog. **Linux:** a `zenity` or `kdialog` window, if one is installed in a system folder.
- **When it asks:** the first read of each service in an AI session (one yes covers that service's reads until the AI app restarts), and every write, change or delete (each one, showing the method, address, query and whole body).
- **No answer** in 2 minutes counts as no. Three refusals stop further requests for that session.
- **No window possible** (SSH, WSL or Linux without a desktop, a headless server): oathkey asks on the terminal instead and you type a 4-digit code shown only there. If there is no terminal either, or a window helper is installed but cannot open, the answer is no. On WSL a window works only if WSLg (or another display) and `zenity`/`kdialog` are set up.
- **Agent key capture** (`capture_key`, below) asks in its own window, which says it closes by itself after 5 minutes. With no window possible, it relies on a grant you made in the terminal with `oathkey allow-agent <service>`.

## Why not just put the key in a `.env` file?

AI coding tools read files in your project, and they paste what they read into a chat that someone else's computer sees. A key in a file, a chat or a config can leak in seconds. With oathkey the key stays in your computer's keychain and oathkey adds it to each request, so the AI does not receive it through oathkey. `oathkey get` will not leave a key in a file in your project folder unless you agree to the fallback (it asks first, and only when no keychain works).

## How it works

1. **You save a key once** (`oathkey get <service>`). It goes into the Windows, Mac or Linux keychain. oathkey tests it with a harmless call first.
2. **Your AI asks for an action**, not a key: "GET /user on GitHub". It can only name the service, the method, the path and the data.
3. **oathkey makes the call itself**, to the service's real address only, adds the key, and hands back the answer with the key scrubbed out.

`oathkey call` is you making the same brokered call by hand, with no AI involved.

## What oathkey does not do

It reduces risk; it does not remove it, and no independent security review has been done yet.

- **It does not stop an AI misusing a key it is allowed to use.** Once you allow GitHub reads, the AI can read whatever that key can read. Give each key only the permissions it needs, at the provider.
- **It does not protect against malware, or an AI that can run programs as you.** Anything running as your user can read your keychain, edit the log and click the windows. Run risky agents in a separate account or container.
- **It does not hide the data.** Replies from the API go to your AI, and so to the AI company. The key is scrubbed; the rest is not.
- **It does not protect `run`.** A program started with `run` holds the key and can print it.
- **It does not catch every disguise.** Scrubbing is best effort.
- **The clipboard.** `get` empties it right away, but other programs or clipboard-history tools may see the key while it is there.
- **A log that can't be rewritten.** The log shows accidents and casual edits. Someone running as you could rewrite it.
- **It sends no telemetry.** oathkey talks only to the services you call (and, for `find`, a public list on GitHub).

The threat model, with links to the code that does each job, is in [docs/THREAT_MODEL.md](https://github.com/calasdan-sketch/oathkey/blob/main/docs/THREAT_MODEL.md). More known limits (a GET can read other secrets through a vendor's own endpoints, and others) are under "Known limits" in [SECURITY.md](https://github.com/calasdan-sketch/oathkey/blob/main/SECURITY.md), which is also where to report a security problem privately.

## Check it yourself (don't trust us)

| Command | What it shows |
|---|---|
| `oathkey selftest` | Runs oathkey's rules against simulated attacks, using a made-up key and a pretend server: a server that echoes the key in disguise, tricky addresses, names that point inside your network, writes without permission, edits to the log. Prints how many it stopped (`--verbose` lists each) and exits with an error if any gets through. It does not test the live network layer, so treat it as a check of the rules, not a security audit. |
| `oathkey doctor` | One-paste health check: keychain, activity log, which AI tools it is plugged into, and a quick self-attack run. |
| `oathkey scan` | Finds API keys lying in your project files and AI-tool settings, including the MCP server configs of Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Codex, Gemini and Zed (`--no-mcp` skips those). It prints only a shortened form of each key. `--bundle dist/` or `--bundle https://your-app.com` shows secret keys your website ships to every visitor (`VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `EXPO_PUBLIC_` and known key formats). |
| `oathkey scan-git` | Looks through git history for keys; `--staged` checks only what is about to be committed, `--install-hook` blocks such commits. |
| `oathkey audit verify` | Checks the activity log was not edited, cut short or deleted. If it did not check out, `audit reset` starts a fresh log and keeps the old one. |

oathkey uses only Python's own standard library, and a test in the repository ([tests/test_stdlib_only.py](https://github.com/calasdan-sketch/oathkey/blob/main/tests/test_stdlib_only.py)) fails if that ever changes.

## Commands

**Start**

- `get <service>` - one command: opens the key page, takes the key when you click Copy (then empties the clipboard), tests it, saves it in the keychain. `--no-clipboard` uses hidden typing instead.
- `install` / `uninstall` - plug oathkey into (or remove it from) Claude Desktop, Cursor, Claude Code and VS Code.
- `doctor` - the health check above.
- `start` - a short guided tour: what is connected and what to do next.
- `list` - the services it knows.

**Daily**

- `call <service> <METHOD> <path>` - make one brokered call yourself (`--query name=value`, `--data '{...}'`, `--json`). Try `oathkey call github GET /user`.
- `overview` - what is connected and whether the activity log is intact. (`status` shows where each key lives and how old it is.)
- `audit show` - the last calls, with a warning if the log does not check out.
- `rotate <service>` - replace a stored key.
- `panic <service> [--dry-run]` - "I leaked a key": asks first, revokes it (GitHub and Vercel through their official API; others open the revoke page and wait for you), gets a new one with the `get` flow, then shows where the old key is still written (project, .env, MCP configs, git history). Terminal only - never offered to an agent.
- `caps set openai --calls-day 500 --tokens-day 200000 --calls-session 100` - a spending limit per key, counted across every program using it (`--clear` removes it; `caps show` lists them). The limit can be passed by one call already in flight.
- `stop` / `resume` - a kill switch: `stop` refuses every brokered and proxied call at once; `resume` (asks you first) lets them through again.
- `policy show` / `policy approve` - an `oathkey.policy` file lists the methods and paths each service may use. A project's file can only narrow your own. A new or changed file is obeyed only after you approve it.
- `forget <service>` - remove a stored key.

**Security**

- `selftest`, `doctor`, `scan`, `scan-git`, `hook` (stops Claude Code reading `.env` files and running oathkey commands that use a key; it blocks the call if it breaks, unless you install it with `hook install --fail-open`) as above.

**Advanced**

- `run <service> -- <command>` - run a program with the key in its environment (see "When your AI writes normal code"). For you, not for an AI with a shell.
- `serve` - a local web door for AI tools that cannot use MCP (OpenAI-style functions, Ollama, scripts).
- `mcp` - the MCP server your AI app starts for you. Besides brokered calls it has `capture_key`: your AI opens the key page, you click Copy, and oathkey takes the key from the clipboard without passing it to the AI. You allow this per service with `allow-agent <service>`.
- `init` / `setup` - write `oathkey.json` for a project, then connect every service it needs.
- `remote`, `trust-server`, `deploy` - use a key on your own server over ssh.
- `wrap <client> <server>` - move a key out of an MCP server's settings into the keychain; the server is then started through `oathkey run`. `--all --dry-run` previews every server, `--undo` restores the old settings, `--file` picks a config file.
- `proxy -- <command>` - see "When your AI writes normal code".
- `add` - make your own service recipe. `find` - look for free public APIs.

Coming from the old `safeeasyapi` name? 0.8.0 is a fresh start: nothing is migrated. Re-run `oathkey get <service>` and `oathkey install`, and remove any old `safeeasyapi` hook or MCP entry by hand.

Many commands accept `--json` (try `list`, `overview`, `selftest`, `doctor`, `audit`). Exit codes: 0 fine, 1 problem, 2 wrong usage, 3 service not found, 5 refused by policy, 7 network problem.

## Services

36 services are built in, from GitHub and Stripe to OpenAI and AWS. `oathkey list` shows them all.

Not listed? `oathkey add` makes a recipe in a minute. A recipe cannot send a built-in service's key to a different server. To share a recipe with everyone, see [CONTRIBUTING.md](https://github.com/calasdan-sketch/oathkey/blob/main/CONTRIBUTING.md).

The longer user guide (every flag, where keys are stored, two-value keys, testing) is in [docs/guide.md](https://github.com/calasdan-sketch/oathkey/blob/main/docs/guide.md).

## License

MIT, no warranty. See [LICENSE](https://github.com/calasdan-sketch/oathkey/blob/main/LICENSE).
