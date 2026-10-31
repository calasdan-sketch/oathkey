"""``python -m leakbench --profile none|oathkey-hook [--json]``."""

from __future__ import annotations

import argparse
import sys

from . import harness, profiles, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leakbench",
        description="Agent Leak Benchmark: score a secret-protection setup "
                    "against ways an AI coding agent can expose an API key.")
    parser.add_argument("--profile", default="none", choices=profiles.AVAILABLE,
                        help="protection profile to score (default: none)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    try:
        results = harness.run(args.profile)
    except ImportError:
        print(f"profile '{args.profile}' unavailable: OathKey is not importable "
              f"(install it or run from the repo).", file=sys.stderr)
        return 2

    out = (report.to_json(results, args.profile) if args.json
           else report.to_table(results, args.profile))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
