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
_HXXP_RE = re.compile(r"\b(h)(xx)(ps?)(?=://)", re.IGNORECASE)

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


# Writing a report's IOCs defanged (the reverse of refang): report-mcp holds
# the same regexes and functions (_defanged, _defang_iocs), and a parity test
# runs both.
_IPV4 = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
)
_URL = re.compile(r"(?i)(https?)://([^/\s:?#]+)(\S*)")
_DOMAIN = re.compile(
    r"(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]"
)
_NETWORK_TYPES = ("domain", "ipv4", "url")  # an IOC type naming one of these


def _defanged(text: str) -> str:
    """One IOC occurrence written defanged: http(s) -> hxxp(s), keeping its
    case, and every dot of the host -> [.]; a URL's path is left as it is."""
    m = _URL.fullmatch(text)
    if m:
        scheme = m.group(1)
        scheme = scheme[0] + ("XX" if scheme[1:3].isupper() else "xx") + scheme[3:]
        return f"{scheme}://{m.group(2).replace('.', '[.]')}{m.group(3)}"
    return text.replace(".", "[.]")


def defang_iocs(text: str, iocs: list[str]) -> str:
    """`text` with every whole occurrence of each IOC defanged. A whole
    occurrence is never part of a longer name or address: no name character
    or dot before it, and no name character, or dot and label, after it. A
    domain right after a single / or \\ is a path component, left as written
    (after two of them, mixed or not, or one right after a scheme's colon, it
    is a host). A defanged form no longer holds the live value, so it isn't
    defanged twice."""

    def one(m: re.Match, name: bool) -> str:
        s, i = m.string, m.start()
        if name and i and s[i - 1] in "/\\" and (i < 2 or s[i - 2] not in "/\\:"):
            return m.group(0)  # a path component, not a host
        return _defanged(m.group(0))

    for v in iocs:
        name = not (_URL.fullmatch(v) or _IPV4.fullmatch(v))
        whole = re.compile(r"(?<![\w.-])" + re.escape(v) + r"(?![\w-]|\.[\w-])", re.I)
        text = whole.sub(lambda m, name=name: one(m, name), text)
    return text


def network_ioc(value, typed: bool) -> str | None:
    """`value` live, if it is a URL, an IPv4 address, or (`typed`: its IOC type
    names a domain) a domain name; else None. An untyped name like a.exe could
    be a file."""
    v = re.sub(r"\[(\W)\]", r"\1", refang(str(value).strip()))
    base, _, prefix = v.partition("/")
    if prefix.isdigit() and len(prefix) <= 2 and _IPV4.fullmatch(base):
        v = base  # a range (a.b.c.d/nn): its base address
    if typed and v.endswith(".") and _DOMAIN.fullmatch(v[:-1]):
        v = v[:-1]  # the root dot
    if _URL.fullmatch(v) or _IPV4.fullmatch(v) or (typed and _DOMAIN.fullmatch(v)):
        return v
    return None


def structured_iocs(findings: list) -> list[tuple]:
    """Each value in the findings' `iocs` fields, with whether its IOC type
    names a domain, an IPv4 address or a URL (a plain value has no type)."""
    out = []
    for f in findings:
        field = f.get("iocs") if isinstance(f, dict) else None
        if isinstance(field, dict):
            for kind, values in field.items():
                typed = any(t in str(kind).lower() for t in _NETWORK_TYPES)
                out += [
                    (v, typed)
                    for v in (values if isinstance(values, list) else [values])
                ]
        elif isinstance(field, list):
            for ioc in field:
                if isinstance(ioc, dict):
                    kind = str(ioc.get("type", "")).lower()
                    out.append(
                        (ioc.get("value", ""), any(t in kind for t in _NETWORK_TYPES))
                    )
                else:
                    out.append((ioc, False))
    return out
