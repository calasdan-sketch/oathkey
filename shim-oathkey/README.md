# oathkey is now stuntkey

oathkey was renamed to stuntkey in 0.9.0. This package only installs `stuntkey`; the `oathkey` command still works, says it is now `stuntkey`, and passes the command on.

```
pipx install stuntkey
```

Your 0.8 data comes along: the first run copies `~/.oathkey` to `~/.stuntkey` (the old folder stays), `stuntkey migrate` copies your saved keychain keys to their new names, and `stuntkey install` / `stuntkey hook install` replace the old `oathkey` MCP and hook entries after showing the change. `stuntkey doctor` shows what is left.

Project: https://calasautomations.com/devtools/stuntkey/ (source: https://github.com/calasdan-sketch/stuntkey)
