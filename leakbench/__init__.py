"""Agent Leak Benchmark: a reproducible suite of ways an AI coding agent can
expose an API key, used to score secret-protection setups fairly.

Each probe is one small, named way a key leaks (read a .env, dump the
environment, grep a folder, echo a key in an error, follow a planted
instruction). The harness plants clearly-fake canary secrets in a throwaway
sandbox, simulates the agent's tool call under a chosen "protection profile",
and records whether the canary was blocked, masked, leaked, or not applicable.

This simulates an agent's tool calls; it is NOT a real model. A profile that
blocks every probe here can still be bypassed by a model that builds its
command at run time. See README.md for method and limits.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
