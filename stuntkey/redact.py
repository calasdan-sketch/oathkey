"""Scrub exact key values (and common re-writings of them) out of output.

`stuntkey run` hands a key to a program through its environment. A
program that prints its own environment, or an error that quotes a request
header, would put the key on your screen - and in an AI agent's chat if it
is watching. With redaction ON (the default) the program's output goes
through this filter first.

What it catches: the exact value; its base64 forms (standard and URL-safe,
padded or not, at any of the three alignments it can take inside a longer
base64 string); hex (lower and upper case); percent-encoding; JSON string
escaping; UTF-16; its upper-case and lower-case forms; and the value with its
characters reversed. The filter itself lives in scrub.py (one implementation
for `stuntkey run`, the broker and the hook); this module keeps the old names.

What it CANNOT catch (honest limits):
  - a value the program changes: hashed, encrypted, truncated, split over
    several lines, or only part of it printed;
  - a value shorter than MIN_LENGTH (too many false hits);
  - anything the program writes to a file or sends over the network instead
    of printing it;
  - output a program only produces on a real terminal: with redaction on,
    the program's output is a pipe, not a terminal, so some programs drop
    colours or stop asking questions. Use --no-redact for those.
"""

from __future__ import annotations

from .scrub import MIN_LEN as MIN_LENGTH, REDACTED as MARK, Scrubber as Redactor, forms

CHUNK = 4096

__all__ = ["CHUNK", "MARK", "MIN_LENGTH", "Redactor", "variants"]


def variants(value: str) -> set[bytes]:
    """Every byte string worth hiding for `value`."""
    return set(forms(value))
