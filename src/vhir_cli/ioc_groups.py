"""The IOCs a case holds, grouped under one label each, as `vhir review
--iocs` and the reports list them.

The listing is the case's IOC records (iocs.json), each under its type's
label, as the Portal lists them. A record with no type (empty or null) is
labelled by the text pattern that matches all of its value, else "Unknown".

Then one group of its own, last: the values the findings name, in their
`iocs` or their text, that no IOC record of the case holds, whatever that
record's status. Two values are the same IOC when ioc_types.same says so, as
forensic-mcp joins a citation to a record. Values that are the same IOC,
directly or through others, are listed once, as the one that sorts first.
"""

from __future__ import annotations

import re

from vhir_cli import ioc_types
from vhir_cli.defang import refang

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


def _items(iocs):
    """(type, value) for each value a finding's iocs field holds: a list of
    strings and {"value", "type"} dicts, or a {type: values} dict. A value
    under a {type: values} key has no type: forensic-mcp flattens that form
    to plain values before it keys them."""
    if isinstance(iocs, dict):
        for values in iocs.values():
            for v in values if isinstance(values, list) else [values]:
                yield None, v
    elif isinstance(iocs, list):
        for i in iocs:
            if isinstance(i, str):
                yield None, i
            elif isinstance(i, dict):
                yield i.get("type"), i.get("value")


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
        if ioc_types.untyped(t):
            v = value.strip()
            t = next((lb for lb, p in PATTERNS if re.fullmatch(p, v)), "Unknown")
        groups.setdefault(ioc_types.label(t), []).append(value)
    return {label: sorted(groups[label]) for label in sorted(groups)}


def not_recorded(findings: list, all_records: list) -> list[str]:
    """The values the findings name, in their `iocs` or their text, that are
    the same IOC as none of the case's IOC records (`all_records`, whatever
    their status), sorted. Values that are the same IOC, directly or through
    others, are listed once, as the one that sorts first."""
    recorded = set()
    for r in all_records or []:
        if isinstance(r, dict) and (value := _value(r.get("value"))) is not None:
            recorded |= ioc_types.keys(value, r.get("type"))
    cited = []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        text = f"{f.get('observation', '')} {f.get('interpretation', '')}"
        named = [*_items(f.get("iocs")), *((None, v) for _, v in text_iocs(text))]
        for t, value in named:
            if (value := _value(value)) is None or not ioc_types.ck(value, t):
                continue
            if not ioc_types.keys(value, t) & recorded:
                cited.append((value, t))
    return sorted(min(v for v, _ in g) for g in ioc_types.components(cited))


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
