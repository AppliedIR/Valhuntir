"""Case text for the terminal.

Case records hold text written by the AI or read from evidence, and a terminal
acts on control characters in it: an ESC sequence can clear rows, move the
cursor or retitle the window. Every command that prints case records shows
them through this module. A single-line value has every control character
shown as "?"; a multi-line field keeps its line breaks. Machine output (JSON)
and files written are left as they are.
"""

from __future__ import annotations

import re

# C0 and C1 controls: escape sequences and line breaks
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Fields that hold multi-line text; every other value is one line
MULTI_LINE = frozenset({"observation", "interpretation", "description", "context"})


def one_line(text) -> str:
    """Text for one terminal line, its control characters shown as "?", so it
    can't move the cursor or hide another line."""
    return _CONTROL.sub("?", str(text))


def lines(text, indent: str) -> str:
    """Multi-line text: each line break stays a real one, indented under its
    field; every other control character is shown as "?"."""
    return f"\n{indent}".join(one_line(line) for line in str(text).split("\n"))


def display_safe(value, field: str = ""):
    """A copy of loaded case records to print from: every string by `one_line`,
    except a multi-line field's, which keeps its line breaks. Numbers, booleans
    and None are unchanged."""
    if isinstance(value, str):
        return lines(value, "") if field in MULTI_LINE else one_line(value)
    if isinstance(value, dict):
        return {
            (one_line(k) if isinstance(k, str) else k): display_safe(
                v, k if isinstance(k, str) else ""
            )
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [display_safe(v, field) for v in value]
    return value
