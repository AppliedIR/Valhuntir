"""Refang defanged IOCs so they can be extracted from free text.

Analysts habitually neuter indicators before pasting them into notes, tickets
and chat so nobody clicks them by accident::

    hxxp://evil[.]com     185[.]220[.]101[.]45     bad(dot)example

Every IOC pattern in this package matches the live form only, so a defanged
indicator contributes nothing to a report even though it is the form an analyst
is most likely to have typed. Normalising the text once, before extraction, is
preferable to teaching each individual pattern about every notation.

The output is the live indicator, which is what downstream consumers
(blocklists, other responders) need. Refanging is a pure text transformation
with no external data, so it does not affect reproducibility.
"""

from __future__ import annotations

import re

# Dot substitutes. The lookarounds require a name character on both sides so
# that ordinary bracketed prose ("see note [.] here", a Markdown footnote) is
# left alone; every genuine defanged domain or IPv4 has labels on both sides.
_DOT_RE = re.compile(r"(?<=[\w-])[\[({](?:\.|dot)[\])}](?=[\w-])", re.IGNORECASE)

# Scheme separators: hxxp[://]evil.com, hxxp[:]//evil.com.
_SCHEME_SEP_RE = re.compile(r"\[://\]|\[:\]//")
_COLON_RE = re.compile(r"(?<=[\w])\[:\](?=[\w/])")

# hxxp / hXXps / HXXP -> http / https, preserving the surrounding case.
_HXXP_RE = re.compile(r"\b(h)(xx)(ps?)\b", re.IGNORECASE)

_REPLACEMENTS = (
    (_DOT_RE, "."),
    (_SCHEME_SEP_RE, "://"),
    (_COLON_RE, ":"),
)


def _unmask_scheme(match: re.Match[str]) -> str:
    """Turn a matched hxxp/hxxps back into http/https, keeping its case."""
    lead, masked, tail = match.group(1), match.group(2), match.group(3)
    return f"{lead}{'TT' if masked.isupper() else 'tt'}{tail}"


def refang(text: str) -> str:
    """Return ``text`` with common defanging notations undone.

    Handles ``[.]``, ``(.)``, ``{.}``, ``[dot]``, ``(dot)``, ``{dot}``,
    ``[:]``, ``[://]`` and ``hxxp``/``hxxps`` in any case.

    Deliberately conservative. Spaced forms (``evil . com``, ``evil dot com``)
    are not undone, because they are indistinguishable from ordinary prose.
    Backslash-escaped dots are not undone either: ``C:\\Users\\.ssh`` is a real
    Windows path on the kind of host this tool examines, not a defanged domain.
    """
    for pattern, replacement in _REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return _HXXP_RE.sub(_unmask_scheme, text)
