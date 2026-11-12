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
from vhir_cli.display import IOC_DEPTH

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
# its reports with defang_iocs from here and picks which values are network
# IOCs with walk_iocs and select_network_ioc from here too.
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


def _network_type(t) -> bool:
    """A type is a network type when its key holds domain, ipv4 or url: the
    table id it folds to, else the type as lower-case text. Never raises."""
    key = ioc_types.canonical(t) or str(t).lower()
    return any(w in key for w in _NETWORK_TYPES)


def _absent(t) -> bool:
    return t is None or (isinstance(t, str) and t == "")


def _verdict(types) -> bool | None:
    """Whether a value is a network IOC, from its enclosing types, nearest
    first. Walk outward and stop at the first type that folds to a table id
    other than unknown: True when a network type was seen up to and including
    it, False when it stopped at a non-network one with none seen. None when
    no type folds and none is a network type (no type, or free text only)."""
    seen = False
    for t in types:
        if _absent(t):
            continue
        seen = seen or _network_type(t)
        if ioc_types.canonical(t) not in (None, "unknown"):
            return seen
    return True if seen else None


def _key(d: dict, name: str):
    """The key of `d` that is `name` in any letter case: `name` itself first."""
    if name in d:
        return name
    return next((k for k in d if isinstance(k, str) and k.lower() == name), None)


def _walk(node, depth: int, types: list, own, out: list) -> None:
    if node is None or depth > IOC_DEPTH:  # past it ioc_text shows "..."
        return
    if isinstance(node, dict):
        vk, tk = _key(node, "value"), _key(node, "type")
        t = node[tk] if tk is not None else None
        if vk is not None:  # shown as its value and type only
            _walk(node[vk], depth + 1, [t, *types], t, out)
            return
        for k, v in node.items():  # each key encloses its own subtree
            if k != tk:
                _walk(v, depth + 1, [k, t, *types], None, out)
        return
    if isinstance(node, list):
        for item in node:
            _walk(item, depth + 1, types, own, out)
        return
    nearest = next((t for t in types if not _absent(t)), None)
    out.append((node, _verdict(types), nearest, own))


def _walked(field) -> list[tuple]:
    out: list[tuple] = []
    _walk(field, 0, [], None, out)
    return out


def walk_iocs(field) -> list[tuple]:
    """Each value in an `iocs` field (or a list of IOC records), with whether
    it is a network IOC (True, False, or None when no type says) and its
    nearest type, for select_network_ioc. A value is walked exactly when
    display.ioc_text shows it: one level per dict or list, none past IOC_DEPTH. A
    dict with a `value` key (any case) holds that value, typed by its `type`;
    a dict without one holds each item, typed by its key, then by the dict's
    own `type` (whose own value isn't walked), then by what encloses it."""
    return [(v, verdict, nearest) for v, verdict, nearest, _ in _walked(field)]


def walk_records(records: list) -> list[tuple]:
    """walk_iocs over IOC records: each record's `value` (any case) typed by
    its `type`, a list-valued one walked as a finding's is. A record's `value`
    takes the place of a finding's `iocs` field: the count starts there, so
    the same nested shape reaches the same limit through both. A record with
    no value holds none."""
    out: list[tuple] = []
    for r in records:
        if isinstance(r, dict) and _key(r, "value") is not None:
            _walk(r, -1, [], None, out)  # the record one above, its value at 0
    return [(v, verdict, nearest) for v, verdict, nearest, _ in out]


_PORT = re.compile(r"[^:]+:\d{1,5}")  # a value ending in one :port


def select_network_ioc(value, type=None, *, network=...) -> str | None:
    """The string a report defangs for `value`, or None. `type` is the
    nearest type enclosing it and `network` the walk's verdict (walk_iocs);
    left out, the verdict is the walk over `type` alone. An IPv4 address with
    a port is its bare address when its nearest type is ipv4-addr, or none
    encloses it; any other type leaves it out, as before. Otherwise a value
    the walk says is network is picked as a typed one, and any other as an
    untyped one: a URL or an IPv4 address is picked whatever its type, as in
    0.6.6, and a name only when the walk says network."""
    if network is ...:
        network = _verdict([type])
    v = ioc_types.unbracket(refang(ioc_types.unbracket(str(value).strip())))
    if _PORT.fullmatch(v) and ioc_types.is_ipv4(v):
        if _absent(type) or ioc_types.canonical(type) == "ipv4-addr":
            return v.rpartition(":")[0]
        return None
    return network_ioc(value, network is True)


def structured_iocs(findings: list) -> list[tuple]:
    """Each value in the findings' `iocs` fields, with whether the walk says
    its IOC type names a domain, an IPv4 address or a URL (a plain value has
    no type), and the type forensic-mcp keys it under: a {"value", "type"}
    dict's own type, else none (it flattens a {type: values} form to plain
    values). Built on walk_iocs's walk."""
    out = []
    for f in findings:
        field = f.get("iocs") if isinstance(f, dict) else None
        out += [(v, verdict is True, own) for v, verdict, _, own in _walked(field)]
    return out
