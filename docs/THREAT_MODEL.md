# oathkey threat model

**Beta: not independently security-reviewed yet. Use at your own risk; MIT, no warranty.**

This page says what oathkey protects, from whom, and where it stops. It is
written to be checked: each claim names the code that does the work. If the
code and this page disagree, the code wins and this page has a bug (please
report it, see [SECURITY.md](../SECURITY.md)).

## What is being protected

1. **Your API keys** (and two-value keys such as AWS id + secret). They live in
   the operating system's keychain ([keychain.py](../oathkey/keychain.py)), or,
   only if no keychain works and you agree, in an owner-only `.env` file
   ([store.py](../oathkey/store.py)).
2. **What a key can do.** Writes, deletes and spending through a key you saved.
3. **The record of what happened.** The activity log in `~/.oathkey/audit.log`
   ([broker.py](../oathkey/broker.py), `AuditLog`).
4. **Your permission.** The yes/no you give in a pop-up window
   ([approve.py](../oathkey/approve.py), [dialog.py](../oathkey/dialog.py)) and
   the per-project grants for agent key capture
   ([consent.py](../oathkey/consent.py)).

## Who we assume is attacking

| Attacker | What they can do | In scope? |
|---|---|---|
| **A prompt-injected AI agent** | Reads whatever a web page, issue or file told it to. Calls oathkey's MCP tools, the local web door (`serve`) or shell commands, with any arguments. | Yes. This is the main one. |
| **A malicious or careless MCP server / plugin** | Runs next to oathkey in the same AI app; sees the chat and can ask the agent to do things. | Partly. It is treated like a prompt-injected agent when it goes through the agent. Running as you, it is the next row. |
| **Same-user malware** (any program running as your user account, including an agent that can run arbitrary code) | Reads your keychain, files and memory, edits configs, drives the screen. | **No.** See "What oathkey does not stop". |
| **The network** (Wi-Fi, a hostile DNS answer, a proxy) | Sees and changes traffic, answers DNS. | Partly: HTTPS with certificate checks to the recipe's own host; proxies are ignored for brokered calls. A compromised vendor or certificate authority is out of scope. |
| **A web page in your browser** | Sends requests to `localhost`. | Yes, against `serve` only. |
| **A planted recipe** | A JSON file dropped in your recipes folder. | Yes, for built-in services. |

## What oathkey stops (when the agent only uses oathkey)

- **The agent never receives the key.** The agent names a service, a method, a
  path and a body; oathkey adds the key itself
  ([broker.py](../oathkey/broker.py), `call`). The MCP tools and `serve` have
  no way to return a stored key.
- **The key is scrubbed from replies.** Responses and `run` output are cleaned
  of the key, including encoded, escaped and split forms
  ([scrub.py](../oathkey/scrub.py), [redact.py](../oathkey/redact.py)). A reply
  that still looks like it holds a disguised key is withheld. This is best
  effort, not proof.
- **The key goes only to the service's real address.** The destination comes
  from the recipe, never from the agent. Private and internal addresses are
  refused, the connection is pinned to the address that was checked, redirects
  are not followed and proxies are ignored ([broker.py](../oathkey/broker.py),
  `resolve_public`, `_Pinned`). A user recipe cannot point a built-in service
  (or its key name) at another server ([recipes.py](../oathkey/recipes.py)).
- **Writes need your click.** Anything other than GET/HEAD asks you in a pop-up
  window, or on the terminal with a code shown only on screen; if neither can
  be shown the answer is no ([approve.py](../oathkey/approve.py)). Reads ask
  once per service per AI session ([broker.py](../oathkey/broker.py),
  `Policy`). Three refusals stop further requests in that session.
- **Padding tricks.** Long query values and bodies are refused instead of shown
  cut off in the approval window.
- **Credential minting through reads.** For AWS only plain look-ups pass; calls
  that create credentials are refused.
- **Casual log edits.** Each log entry carries the hash of the one before it;
  `oathkey audit verify` notices edits, deletions and a cut-off end.
- **Web pages against `serve`.** Loopback only, a secret token, an exact Host
  check, Origin refused, no CORS ([httpd.py](../oathkey/httpd.py)).
- **Claude Code reading `.env` files or running key-using oathkey commands.**
  The optional hook ([hook.py](../oathkey/hook.py)) refuses those tool calls.

`oathkey selftest` runs these rules against simulated attacks
([selftest.py](../oathkey/selftest.py)). It checks the rules, not the live
network layer.

## What oathkey does not stop

- **An agent misusing a key it is allowed to use.** If you approve reads for
  GitHub, the agent can read anything that key can read, and send what it read
  back to its vendor. Some APIs change things on a GET. A read can also return
  *other* secrets (a settings or tokens listing) that oathkey does not
  recognise. Limit each key at the provider: read-only, one project, an expiry.
- **A same-user process reading the keychain.** The OS keychain protects keys
  from other users and other machines, not from other programs running as you.
  Malware, or an agent that can run arbitrary code as you, can read the
  keychain, the `.env` fallback, the consent secret and the `serve` token, can
  rewrite the activity log so it verifies again, and can click the approval
  window by driving the screen. Run risky agents in a separate account,
  container or VM.
- **`run` and `remote` given to an agent with a shell.** They put the key in a
  program's environment; that program can print it. Scrubbing helps only with
  output that passes through oathkey.
- **Fail-open cases.** These are the places where something lets a call through
  instead of refusing it:
  - The Claude Code hook fails closed by default (if it breaks, the tool call is
    blocked). If you install it with `hook install --fail-open`, a hook error
    lets the call through.
  - The hook reads the text of a call. A command built at run time, a tool the
    hook is not attached to, or an AI app other than Claude Code gets past it.
  - Agent key capture (`capture_key`): with no window possible (SSH, a server,
    `OATHKEY_NO_WINDOW=1`) it falls back to the grant made with the terminal
    command `oathkey allow-agent`, which is weaker and labelled advisory in
    [consent.py](../oathkey/consent.py).
  - `OATHKEY_ENV_FILE` and `OATHKEY_NO_WINDOW` are read from the MCP server's
    environment, which the AI app's config sets. An agent that can edit that
    config can change them.
- **Telemetry and what the AI vendor sees.** oathkey itself sends no telemetry
  and has no account or server; it only connects to the services you call,
  their key-test addresses, and, for `find`, a public list on GitHub. But the
  *replies* from those services go to your AI app and so to the AI vendor. The
  key is scrubbed; the data is not.
- **The clipboard.** `oathkey get` empties the clipboard after taking the key,
  but clipboard-history tools and other programs may keep a copy. Use
  `--no-clipboard` if that matters.
- **Memory.** Python cannot reliably wipe a secret from memory.
- **A compromised vendor**, or one that logs your key itself.
- **The OAuth token fetch** is checked to be public and ignores proxies, but it
  is not pinned to the checked address (a DNS change in between is possible).

The full list of known limits is in [SECURITY.md](../SECURITY.md).

## Changing this page

Any change that adds a protection should add a selftest attack for it. Any
change that weakens one should add a line under "What oathkey does not stop".
