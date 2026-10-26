"""A value the examiner rejected (its IOC record REJECTED and manually
reviewed) is no IOC of the report, so a saved report leaves it live, whichever
approved finding names it and however. A held, approved or cascade-rejected
record is still one when an approved finding names it or the record is
approved: the safe side. Values match as the report gathers them (refanged,
then case-folded). report-mcp's tests state the same rows against its copy,
and run them through both."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FINDING = "F-tester-001"  # the approved finding
SOURCES = {  # how it names the value: its iocs field, the record's value, type
    "a plain string": (["plain.example.net"], "plain.example.net", "domain-name"),
    "an explicit type": ([{"value": "typed.example.net", "type": "domain-name"}],
                         "typed.example.net", "domain-name"),
    "a domain key": ({"domain": ["keyed.example.net"]}, "keyed.example.net", "domain-name"),
    "a URL": (["http://url.example.net/p"], "http://url.example.net/p", "url"),
    "an IPv4 address": (["10.9.8.7"], "10.9.8.7", "ipv4-addr"),
}  # fmt: skip
STATUSES = {  # the record's status and manually_reviewed
    "held": ("DRAFT", False),
    "approved": ("APPROVED", True),
    "rejected by the examiner": ("REJECTED", True),
    "rejected by cascade": ("REJECTED", False),
}


def _record(value, kind, status, reviewed, cited=True) -> dict:
    return {"id": "IOC-tester-001", "value": value, "type": kind, "status": status,
            "manually_reviewed": reviewed,
            "source_findings": [FINDING if cited else "F-tester-009"]}  # fmt: skip


def _expected(name, cited, source, value) -> list[str]:
    if name == "rejected by the examiner":
        return []  # live, whatever cites it
    if source == "a plain string" and not cited and name != "approved":
        return []  # an untyped name in a finding's field could be a file
    return [value]


ROWS = [  # (id, the finding's iocs field, the case's IOC record, the IOCs gathered)
    (f"{name}, {'cited' if cited else 'not cited'}, {source}", field,
     _record(value, kind, *STATUSES[name], cited), _expected(name, cited, source, value))
    for name in STATUSES for cited in (True, False)
    for source, (field, value, kind) in SOURCES.items()
] + [
    ("rejected by the examiner, written in other letter case, defanged",
     [{"value": "Evil-C2[.]example.net", "type": "domain-name"}],
     _record("evil-c2.example.net", "domain-name", "REJECTED", True), []),
    ("rejected by the examiner, written defanged",
     ["hxxp://rej2[.]example[.]org/q"],
     _record("http://rej2.example.org/q", "url", "REJECTED", True), []),
    ("a rejected value drops no other",
     [{"value": "notrej.example.net", "type": "domain-name"}, "http://rej.example.net.au/"],
     _record("rej.example.net", "domain-name", "REJECTED", True),
     ["http://rej.example.net.au/", "notrej.example.net"]),
    ("manually reviewed as a string is no review",
     [{"value": "strrej.example.net", "type": "domain-name"}],
     _record("strrej.example.net", "domain-name", "REJECTED", "true"), ["strrej.example.net"]),
]  # fmt: skip


def gathered(report_iocs, case: Path, field, record) -> list[str]:
    """What `report_iocs` gathers from a case holding `record`, for a report of
    one approved finding whose iocs field is `field`."""
    case.mkdir(exist_ok=True)
    (case / "iocs.json").write_text(json.dumps([record]))
    view = {"findings": [{"id": FINDING, "status": "APPROVED", "iocs": field}],
            "iocs": [record] if record["status"] == "APPROVED" else []}  # fmt: skip
    return report_iocs(case, view)


@pytest.mark.parametrize(("field", "record", "expected"), [r[1:] for r in ROWS],
                         ids=[r[0] for r in ROWS])  # fmt: skip
def test_a_value_the_examiner_rejected_is_no_ioc_of_the_report(
    tmp_path, field, record, expected
):
    from vhir_cli.commands.report import _report_iocs

    assert gathered(_report_iocs, tmp_path / "case", field, record) == expected
