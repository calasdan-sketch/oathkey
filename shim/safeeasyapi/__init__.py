"""safeeasyapi was renamed to stuntkey. This package only points to it."""
import sys

__version__ = "0.9.0"

MESSAGE = (
    "safeeasyapi has been renamed to stuntkey.\n"
    "Nothing was moved for you: your old saved keys, settings and hook entries\n"
    "are not read by stuntkey. To switch:\n"
    "  1. pipx install stuntkey   (or: pip install stuntkey)\n"
    "  2. stuntkey get <service>  for each key you want to keep\n"
    "  3. stuntkey install        to plug it into your AI tools\n"
    "  4. remove the old 'safeeasyapi' hook and MCP entries from your AI tools' settings\n"
    "More: https://github.com/calasdan-sketch/stuntkey\n"
)


def main() -> int:
    sys.stderr.write(MESSAGE)
    return 1
