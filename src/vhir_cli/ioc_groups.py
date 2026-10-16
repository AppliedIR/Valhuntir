"""The IOCs a case holds, grouped under one label each, as `vhir review
--iocs` and the reports list them.

The listing is the case's IOC records (iocs.json), each under its type's
label, as the Portal lists them. A record with no type (empty or null) is
labelled by the text pattern that matches all of its value, else "Unknown".

Then one group of its own, last: the values the findings name, in their
`iocs` or their text, that no IOC record of the case holds, whatever that
record's status. Each is listed once, as first written. Two values are the
same IOC when they key to the same text, as forensic-mcp keys an IOC when it
records it: refanged, an IPv4 address without its :port, then a hash
case-insensitively, a dotted name case-insensitively and without a trailing
dot, a path with a backslash case-insensitively.
"""

from __future__ import annotations

import re

from vhir_cli.case_io import _is_ipv4, _refang_ioc, normalize_ioc
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
# The values the findings name that no IOC record of the case holds
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


def ioc_key(value: str, type_=None) -> str:
    """The text two values are compared by: the key forensic-mcp records an
    IOC under (forensic_mcp/case/manager.py `_process_iocs`, as
    case_io.ioc_values copies it). The value is refanged, an IPv4 address
    loses its :port (typed "ipv4-addr", or untyped and read as IPv4), then
    normalised."""
    v = _refang_ioc(value.strip())
    if type_ == "ipv4-addr" if type_ else _is_ipv4(v):
        v = re.sub(r":\d{1,5}$", "", v)
    return normalize_ioc(v)


def _sentence_end(value: str) -> str:
    """The value without the punctuation the sentence around it ends with: a
    trailing . , ; : " or ', and a ) with no ( to close."""
    while value and (
        value[-1] in ".,;:\"'"
        or (value[-1] == ")" and value.count(")") > value.count("("))
    ):
        value = value[:-1]
    return value


def text_iocs(text: str) -> list[tuple[str, str]]:
    """(label, value) for each IOC the text names, by the patterns in order.
    Defanged indicators are read live; a hash or domain is lowercased, a path
    loses the punctuation that ends its sentence, and a 0., 127. or 255.
    address is left out."""
    # Analysts habitually defang indicators in notes; every pattern matches
    # the live form only, so normalise before matching.
    text = refang(text)
    found = []
    for label, pattern in PATTERNS:
        for v in re.findall(pattern, text):
            if label == "IPv4":
                if not v.startswith(("0.", "127.", "255.")):
                    found.append((label, v))
            elif label == "File":
                found.append((label, _sentence_end(v)))
            else:
                found.append((label, v.lower()))
    return found


def _no_type(t) -> bool:
    return t is None or (isinstance(t, str) and not t.strip())


def _label(t) -> str:
    if isinstance(t, str):
        return LABELS.get(t.strip().lower(), t)
    return str(t)


def _items(iocs):
    """(type, value) for each value a finding's iocs field holds: a list of
    values (text or numbers) and {"value", "type"} dicts, or a {type: values}
    dict. A value
    under a {type: values} key has no type: forensic-mcp flattens that form
    to plain values before it keys them."""
    if isinstance(iocs, dict):
        for values in iocs.values():
            for v in values if isinstance(values, list) else [values]:
                yield None, v
    elif isinstance(iocs, list):
        for i in iocs:
            if isinstance(i, dict):
                yield i.get("type"), i.get("value")
            elif not isinstance(i, (list, tuple)):  # a value, as text or a number
                yield None, i


def _value(v) -> str | None:
    """A stored value as text; None when there is none to list."""
    if v is None:
        return None
    v = v if isinstance(v, str) else str(v)
    return v if v.strip() else None


def record_status(record: dict) -> str:
    """A record's status as the Portal reads it: DRAFT when it has none."""
    return str(record.get("status") or "DRAFT").upper()


def record_groups(records: list) -> dict[str, list[str]]:
    """label -> the values of the IOC records, sorted; the labels sorted. Each
    record is listed under its type's label; a record with no type under the
    text pattern that matches all of its value, else "Unknown"."""
    groups: dict[str, list[str]] = {}
    for r in records or []:
        if not isinstance(r, dict) or (value := _value(r.get("value"))) is None:
            continue
        t = r.get("type")
        if _no_type(t):
            v = value.strip()
            t = next((lb for lb, p in PATTERNS if re.fullmatch(p, v)), "Unknown")
        groups.setdefault(_label(t), []).append(value)
    return {label: sorted(groups[label]) for label in sorted(groups)}


def not_recorded(findings: list, all_records: list) -> list[str]:
    """The values the findings name, in their `iocs` or their text, that match
    none of the case's IOC records (`all_records`, whatever their status),
    sorted; each once, as first written."""
    recorded = set()
    for r in all_records or []:
        if isinstance(r, dict) and (value := _value(r.get("value"))) is not None:
            t = r.get("type")
            recorded.add(ioc_key(value, None if _no_type(t) else t))
    found: dict[str, str] = {}
    findings = [f for f in findings or [] if isinstance(f, dict)]
    for f in findings:
        for t, value in _items(f.get("iocs")):
            if (value := _value(value)) is not None:
                key = ioc_key(value, None if _no_type(t) else t)
                if key and key not in recorded:
                    found.setdefault(key, value)
    for f in findings:
        text = f"{f.get('observation', '')} {f.get('interpretation', '')}"
        for _, value in text_iocs(text):
            key = ioc_key(value)
            if key and key not in recorded:
                found.setdefault(key, value)
    return sorted(found.values())


def ioc_groups(findings: list, records: list, all_records=None) -> dict[str, list[str]]:
    """label -> the values under it: `records` by type (`record_groups`), then
    the values the findings name that no record of the case (`all_records`,
    `records` when not given) holds, in the group TEXT_ONLY, last."""
    out = record_groups(records)
    rest = not_recorded(findings, records if all_records is None else all_records)
    found_in_text = out.pop(TEXT_ONLY, []) + rest
    if found_in_text:
        out[TEXT_ONLY] = sorted(found_in_text)
    return out
