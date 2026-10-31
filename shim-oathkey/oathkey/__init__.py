"""oathkey was renamed to stuntkey. This package passes every command on to it."""
import sys

__version__ = "0.9.0"

MESSAGE = ("oathkey is now stuntkey: running `stuntkey` for you. "
           "Use `stuntkey` from now on (https://calasautomations.com/devtools/stuntkey/).\n")


def main() -> int:
    # stderr: stdout may be the MCP protocol or a hook's answer
    sys.stderr.write(MESSAGE)
    from stuntkey.cli import main as stuntkey_main
    return stuntkey_main(sys.argv[1:])
