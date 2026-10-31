"""Start a program with keys in its environment, optionally scrubbing its output.

The keys go into the CHILD's environment only: not onto its command line,
not into this process's own environment, not into any file. With redaction
on, the child's standard output and error come back through redact.Redactor
so a program that prints a key does not put it on your screen.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading

from . import redact as redact_mod
from . import store as store_mod


def env_file_value(path: str, var: str) -> str | None:
    """The value of `var` in a .env file, or None. A link, a missing file or a
    file that is not plain text gives None. For `run` only: never printed."""
    try:
        store_mod.refuse_link(path)
        if not os.path.isfile(path):
            return None
        value = store_mod.load_env(path).get(var)
    except (OSError, ValueError):
        return None
    return value if value else None


def _pump(src, dst, redactor: redact_mod.Redactor) -> None:
    try:
        while True:
            chunk = src.read1(redact_mod.CHUNK) if hasattr(src, "read1") else src.read(redact_mod.CHUNK)
            if not chunk:
                break
            out = redactor.feed(chunk)
            if out:
                dst.write(out)
                dst.flush()
        tail = redactor.flush()
        if tail:
            dst.write(tail)
            dst.flush()
    except (OSError, ValueError):
        pass        # our reader went away (closed pipe): keep draining quietly
    finally:
        try:
            src.close()
        except OSError:
            pass


class _interrupt_held_back:
    """While active, Ctrl-C (SIGINT) is noted instead of raised; `held` says
    whether it came. A no-op where the handler cannot be changed (not the main
    thread) or SIGINT is ignored or not a Python handler."""

    def __init__(self):
        self.held = False
        self._old = None

    def __bool__(self):
        return self.held

    def __enter__(self):
        try:
            old = signal.getsignal(signal.SIGINT)
            if callable(old):
                signal.signal(signal.SIGINT, self._note)
                self._old = old
        except (ValueError, OSError):
            self._old = None
        return self

    def _note(self, _signum, _frame):
        self.held = True

    def __exit__(self, *exc):
        if self._old is not None:
            try:
                signal.signal(signal.SIGINT, self._old)
            except (ValueError, OSError):
                pass
        return False


def _binary(stream):
    return getattr(stream, "buffer", stream)


def run_redacted(cmd: list[str], child_env: dict, secrets, popen=subprocess.Popen,
                 stdout=None, stderr=None) -> int:
    """Run `cmd`; its output is scrubbed of every value in `secrets`.
    Returns the child's status (128 + n for a signal). Standard input is the
    child's own (inherited), so it can still ask you things."""
    out = _binary(stdout if stdout is not None else sys.stdout)
    err = _binary(stderr if stderr is not None else sys.stderr)
    proc = popen(cmd, env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    threads = []
    try:
        # Ctrl-C must not land while the readers are being started: raised
        # inside Thread.start it can leave threading's own locks broken
        # ("release unlocked lock") or a reader running as Python exits, which
        # holds the lock of standard output and kills the interpreter with
        # "could not acquire lock ... at interpreter shutdown" (SIGABRT)
        # instead of leaving with 130. So it is held back until they are up.
        with _interrupt_held_back() as held:
            for src, dst in ((proc.stdout, out), (proc.stderr, err)):
                t = threading.Thread(target=_pump,
                                     args=(src, dst, redact_mod.Redactor(secrets)),
                                     daemon=True)
                t.start()
                threads.append(t)
        if held:
            raise KeyboardInterrupt
        status = proc.wait()
    except KeyboardInterrupt:
        # Ctrl-C reached the child too; give it a moment to finish, then say so
        try:
            status = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            status = proc.wait()
        raise
    except BaseException:
        # could not start a reader (no threads left): do not leave the child
        # running with nobody reading it
        proc.kill()
        proc.wait()
        raise
    finally:
        for t in threads:
            t.join(timeout=5)
        # a reader that never started leaves its pipe open
        for pipe in (proc.stdout, proc.stderr):
            try:
                if pipe is not None and not any(t.is_alive() for t in threads):
                    pipe.close()
            except (OSError, ValueError):
                pass
    return 128 - status if status < 0 else status
