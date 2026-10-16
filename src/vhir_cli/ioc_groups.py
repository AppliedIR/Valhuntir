"""The IOCs a set of findings names, grouped under one label each, as `vhir
review --iocs` and the reports list them.

Each value is listed once. Two values are the same IOC when they normalise to
the same text, as forensic-mcp compares IOCs when it records them: a hash
case-insensitively, a dotted name case-insensitively and without a trailing
dot, a path with a backslash case-insensitively. The first label a value gets
is kept, and it is shown as first written.

Every value in a finding's `iocs` is listed under its type's label. A value
with no type (a plain string, or a type that is empty or null) takes the type
of the case's IOC record with the same value; with no such record it is
labelled by the text pattern that matches all of it, else "Unknown". Values
the finding's text names but no finding's `iocs` holds are listed last, in one
group of their own.
"""

from __future__ import annotations

import re

from vhir_cli.defang import refang

# How a stored IOC type is labelled; any other type is shown as stored
LABELS = {
    "ipv4-addr": "IPv4",
    "ipv4": "IPv4",
    "ip": "IPv4",
    "ipv6-addr": "IPv6",
    "ipv6": "IPv6",
    "domain-name": "Domain",
    "domain": "Domain",
    "url": "URL",
    "email-addr": "Email",
    "email": "Email",
    "file:path": "File",
    "file-path": "File",
    "file": "File",
    "file:hash:sha256": "SHA256",
    "sha256": "SHA256",
    "file:hash:sha1": "SHA1",
    "sha1": "SHA1",
    "file:hash:md5": "MD5",
    "md5": "MD5",
    "unknown": "Unknown",
}
# The group of values found in a finding's text that no finding's iocs holds
TEXT_ONLY = "Found in text, not recorded"

_IPV4 = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
# The patterns a finding's text is searched with, in this order
PATTERNS = (
    ("IPv4", _IPV4),
    ("SHA256", r"\b[a-fA-F0-9]{64}\b"),
    ("SHA1", r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"),
    ("MD5", r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"),
    ("File", r"[A-Z]:\\(?:[^\s,;]+)"),
    (
        "Domain",
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk)\b",
    ),
)


def ioc_key(value: str) -> str:
    """The text two values are compared by (forensic-mcp's `_normalize_ioc`)."""
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return v.lower()
    if "." in v and not v.replace(".", "").isdigit():
        return v.lower().rstrip(".")
    if "\\" in v:
        return v.lower()
    return v


def text_iocs(text: str) -> list[tuple[str, str]]:
    """(label, value) for each IOC the text names, by the patterns in order.
    Defanged indicators are read live; a hash or domain is lowercased, and a
    0., 127. or 255. address is left out."""
    # Analysts habitually defang indicators in notes; every pattern matches
    # the live form only, so normalise before matching.
    text = refang(text)
    found = []
    for label, pattern in PATTERNS:
        for v in re.findall(pattern, text):
            if label == "IPv4":
                if not v.startswith(("0.", "127.", "255.")):
                    found.append((label, v))
            else:
                found.append((label, v if label == "File" else v.lower()))
    return found


def _no_type(t) -> bool:
    return t is None or (isinstance(t, str) and not t.strip())


def _label(t) -> str:
    if isinstance(t, str):
        return LABELS.get(t.strip().lower(), t)
    return str(t)


def _items(iocs):
    """(type, value) for each value a finding's iocs field holds: a list of
    strings and {"value", "type"} dicts, or a {type: values} dict."""
    if isinstance(iocs, dict):
        for t, values in iocs.items():
            for v in values if isinstance(values, list) else [values]:
                yield t, v
    elif isinstance(iocs, list):
        for i in iocs:
            if isinstance(i, str):
                yield None, i
            elif isinstance(i, dict):
                yield i.get("type"), i.get("value")


def ioc_groups(findings: list, records: list) -> dict[str, list[str]]:
    """label -> the values under it, sorted; the labels sorted, the values the
    text alone names last. `records` are the case's IOC records (iocs.json)."""
    record_type: dict[str, object] = {}
    for r in records or []:
        typed = isinstance(r, dict) and not _no_type(r.get("type"))
        if typed and r.get("value") is not None:
            record_type.setdefault(ioc_key(str(r["value"])), r["type"])
    findings = [f for f in findings or [] if isinstance(f, dict)]

    listed: dict[str, tuple[str, str]] = {}  # key -> (label, as first written)
    for f in findings:
        for t, value in _items(f.get("iocs")):
            if value is None:
                continue
            value = value if isinstance(value, str) else str(value)
            key = ioc_key(value)
            if not key or key in listed:
                continue
            if _no_type(t):
                t = record_type.get(key)
            if _no_type(t):
                v = value.strip()
                t = next((lb for lb, p in PATTERNS if re.fullmatch(p, v)), "Unknown")
            listed[key] = (_label(t), value)

    text_only: dict[str, str] = {}
    for f in findings:
        text = f"{f.get('observation', '')} {f.get('interpretation', '')}"
        for _, value in text_iocs(text):
            key = ioc_key(value)
            if key not in listed:
                text_only.setdefault(key, value)

    groups: dict[str, list[str]] = {}
    for label, value in listed.values():
        groups.setdefault(label, []).append(value)
    found_in_text = groups.pop(TEXT_ONLY, []) + list(text_only.values())
    out = {label: sorted(groups[label]) for label in sorted(groups)}
    if found_in_text:
        out[TEXT_ONLY] = sorted(found_in_text)
    return out
