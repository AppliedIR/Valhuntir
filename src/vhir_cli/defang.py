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

import functools
import re

from vhir_cli import ioc_types

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


# Writing a report's IOCs defanged (the reverse of refang). report-mcp defangs
# its reports with defang_iocs from here and keeps its own copy of the three
# regexes to pick which values are network IOCs.
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


@functools.cache
def _fold_table() -> dict[int, str]:
    """str.translate table that, followed by lower(), sends every two
    characters re.I treats as equal to one character, one for one. lower()
    alone parts some (K and the Kelvin sign meet, but s and the long s do not)
    and writes U+0130 as two characters. Each character goes to the least of
    the lowercase forms sharing its uppercase; capital sigma is mapped too, so
    lower() never reads its neighbours to choose a final sigma."""

    def lower(c: str) -> str:
        s = c.lower()
        return s if len(s) == 1 else ("i" if c == "\u0130" else c)

    chars = [chr(n) for n in range(0x10000) if not 0xD800 <= n <= 0xDFFF]
    group: dict[str, set[str]] = {}
    for c in chars:
        group.setdefault(lower(c).upper(), set()).add(lower(c))
    least = {low: min(g) for g in group.values() for low in g}
    return {
        ord(c): least[lower(c)]
        for c in chars
        if least[lower(c)] != c.lower() or c == "\u03a3"
    }


def _folded(text: str) -> str:
    """`text` with each character folded alone, so a fold is as long as the
    text and a slice of it is the fold of that slice of the text."""
    return text.translate(_fold_table()).lower()


def defang_iocs(text: str, iocs: list[str]) -> str:
    """`text` with every whole occurrence of each IOC defanged. A whole
    occurrence is never part of a longer name or address: no name character
    or dot before it, and no name character, or dot and label, after it. A
    domain right after a single / or \\ is a path component, left as written
    (after two of them, mixed or not, or one right after a scheme's colon, it
    is a host). A defanged form no longer holds the live value, so it isn't
    defanged twice.

    IOCs are taken in order, each on the text the ones before it left. The
    regex for an IOC only runs where its fold occurs in the text's fold, and
    an IOC whose fold occurs nowhere is skipped: a match of it, case
    ignored, would have the same fold."""

    def one(m: re.Match, name: bool) -> str:
        s, i = m.string, m.start()
        if name and i and s[i - 1] in "/\\" and (i < 2 or s[i - 2] not in "/\\:"):
            return m.group(0)  # a path component, not a host
        return _defanged(m.group(0))

    folded = _folded(text)
    for v in iocs:
        key = _folded(v)
        at = folded.find(key) if v else -1
        if at < 0:
            continue
        name = not (_URL.fullmatch(v) or _IPV4.fullmatch(v))
        whole = re.compile(r"(?<![\w.-])" + re.escape(v) + r"(?![\w-]|\.[\w-])", re.I)
        parts, fparts, done = [], [], 0
        while at >= 0:
            # the whole text, so the lookarounds see past the IOC
            m = whole.match(text, at)
            if not m:
                at = folded.find(key, at + 1)
                continue
            new = one(m, name)
            if new != m.group(0):
                parts += (text[done:at], new)
                fparts += (folded[done:at], _folded(new))
                done = m.end()
            at = folded.find(key, m.end())
        if parts:
            text = "".join(parts) + text[done:]
            folded = "".join(fparts) + folded[done:]
    return text


def network_ioc(value, typed: bool) -> str | None:
    """`value` live, if it is a URL, an IPv4 address, or (`typed`: its IOC type
    names a domain) a domain name; else None. An untyped name like a.exe could
    be a file."""
    v = ioc_types.unbracket(refang(ioc_types.unbracket(str(value).strip())))
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
    names a domain, an IPv4 address or a URL (a plain value has no type), and
    the type forensic-mcp keys it under: a {"value", "type"} dict's own type,
    else none (it flattens a {type: values} form to plain values)."""
    out = []
    for f in findings:
        field = f.get("iocs") if isinstance(f, dict) else None
        if isinstance(field, dict):
            for kind, values in field.items():
                typed = any(t in str(kind).lower() for t in _NETWORK_TYPES)
                out += [
                    (v, typed, None)
                    for v in (values if isinstance(values, list) else [values])
                ]
        elif isinstance(field, list):
            for ioc in field:
                if isinstance(ioc, dict):
                    kind = str(ioc.get("type", "")).lower()
                    typed = any(t in kind for t in _NETWORK_TYPES)
                    out.append((ioc.get("value", ""), typed, ioc.get("type")))
                else:
                    out.append((ioc, False, None))
    return out
