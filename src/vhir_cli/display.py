"""Case text for the terminal.

Case records hold text written by the AI or read from evidence, and a terminal
acts on control characters in it: an ESC sequence can clear rows, move the
cursor or retitle the window. Every command that prints case records shows
them through this module, and the print site decides: text printed within a
line (a header, a table cell, `tool(k=v)`) goes through `one_line`, which shows
every control character as "?"; only a block that indents its continuation
lines keeps line breaks, through `lines`. Machine output (JSON) and files
written are left as they are.
"""

from __future__ import annotations

import re
import unicodedata

# C0 and C1 controls: escape sequences and line breaks
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Format (bidi overrides, zero-width), surrogate, and line or paragraph
# separator characters: they reorder or break what the line shows
_UNSAFE_CATEGORIES = frozenset({"Cf", "Cs", "Zl", "Zp"})

# Fields `vhir approve` shows as indented blocks
MULTI_LINE = frozenset({"observation", "interpretation", "description", "context"})


def one_line(text) -> str:
    """Text for one terminal line, its control characters shown as "?", so it
    can't move the cursor or hide another line."""
    text = _CONTROL.sub("?", str(text).expandtabs())  # a TAB keeps its column
    if text.isascii():
        return text
    return "".join(
        "?" if unicodedata.category(ch) in _UNSAFE_CATEGORIES else ch for ch in text
    )


def lines(text, indent: str) -> str:
    """Multi-line text: each line break stays a real one, indented under its
    field; every other control character is shown as "?"."""
    return f"\n{indent}".join(one_line(line) for line in str(text).split("\n"))


def ioc_text(iocs, _depth: int = 0) -> str:
    """A finding's iocs as the examiner reads them: each value as written, a
    typed one followed by its type, never the list's Python or JSON form. A
    {type: [values]} form, or a dict with no value, reads `key: values`. None
    and empty items are left out; nesting past a few levels shows as "...".
    The print site still makes the text safe for its line."""
    if iocs is None:
        return ""
    if _depth > 8:
        return "..."
    if isinstance(iocs, dict):
        if "value" in iocs:
            value = ioc_text(iocs["value"], _depth + 1)
            kind = ioc_text(iocs.get("type"), _depth + 1)
            return f"{value} ({kind})".lstrip() if kind else value
        return "; ".join(f"{k}: {ioc_text(v, _depth + 1)}" for k, v in iocs.items())
    if isinstance(iocs, list):
        return ", ".join(t for t in (ioc_text(i, _depth + 1) for i in iocs) if t)
    return str(iocs)


def cited(value) -> list:
    """The audit ids a record cites, as a list: a list as it is, None as none,
    any other value as one id. Whatever the shape, it is shown, never a crash."""
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def cited_text(value) -> str:
    """The cited audit ids as one text, as every view shows them; the print
    site still makes it safe for its line."""
    return ", ".join(str(eid) for eid in cited(value))


def display_safe(value):
    """A copy of loaded case records to print inline from: every string, keys
    included, by `one_line`. Numbers, booleans and None are unchanged. A block
    that keeps line breaks reads its text from the records, through `lines`."""
    if isinstance(value, str):
        return one_line(value)
    if isinstance(value, dict):
        return {
            (one_line(k) if isinstance(k, str) else k): display_safe(v)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [display_safe(v) for v in value]
    return value
