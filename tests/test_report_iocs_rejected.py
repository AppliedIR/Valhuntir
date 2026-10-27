"""A value the examiner rejected (its IOC record REJECTED and manually
reviewed, and the rejection signed in the approval ledger, which verify reads
as VALID) is no IOC of the report, so a saved report leaves it live, whichever
approved finding names it and however. A held, approved or cascade-rejected
record is still one when an approved finding names it or the record is
approved, and so is one set REJECTED by hand (no ledger line), one whose
latest line is a cascade's, or one changed after its rejection was signed: the
safe side. Values match as the report gathers them (refanged, then
case-folded). report-mcp's tests state the same rows against its copy,
and run them through both."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.ledger_verify import approved_view

FINDING = "F-tester-001"  # the approved finding
SOURCES = {  # how it names the value: its iocs field, the record's value, type
    "a plain string": (["plain.example.net"], "plain.example.net", "domain-name"),
    "an explicit type": ([{"value": "typed.example.net", "type": "domain-name"}],
                         "typed.example.net", "domain-name"),
    "a domain key": ({"domain": ["keyed.example.net"]}, "keyed.example.net", "domain-name"),
    "a URL": (["http://url.example.net/p"], "http://url.example.net/p", "url"),
    "an IPv4 address": (["10.9.8.7"], "10.9.8.7", "ipv4-addr"),
}  # fmt: skip
STATUSES = {  # the record's status and manually_reviewed, and its ledger line
    "held": ("DRAFT", False, None),
    "approved": ("APPROVED", True, None),
    "rejected by the examiner": ("REJECTED", True, "reject"),
    "rejected by cascade": ("REJECTED", False, None),
    "set REJECTED by hand": ("REJECTED", True, None),
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


ROWS = [  # (id, the finding's iocs field, the case's IOC record, its ledger line,
          #  the IOCs gathered)
    (f"{name}, {'cited' if cited else 'not cited'}, {source}", field,
     _record(value, kind, *STATUSES[name][:2], cited), STATUSES[name][2],
     _expected(name, cited, source, value))
    for name in STATUSES for cited in (True, False)
    for source, (field, value, kind) in SOURCES.items()
] + [
    ("rejected by the examiner, written in other letter case, defanged",
     [{"value": "Evil-C2[.]example.net", "type": "domain-name"}],
     _record("evil-c2.example.net", "domain-name", "REJECTED", True), "reject", []),
    ("rejected by the examiner, written defanged",
     ["hxxp://rej2[.]example[.]org/q"],
     _record("http://rej2.example.org/q", "url", "REJECTED", True), "reject", []),
    ("rejected by the examiner, its record written in upper case",
     [{"value": "evil-up.example.net", "type": "domain-name"}],
     _record("EVIL-UP.Example.NET", "domain-name", "REJECTED", True), "reject", []),
    ("a rejected value drops no other",
     [{"value": "notrej.example.net", "type": "domain-name"}, "http://rej.example.net.au/"],
     _record("rej.example.net", "domain-name", "REJECTED", True), "reject",
     ["http://rej.example.net.au/", "notrej.example.net"]),
    ("manually reviewed as a string is no review",
     [{"value": "strrej.example.net", "type": "domain-name"}],
     _record("strrej.example.net", "domain-name", "REJECTED", "true"), "reject",
     ["strrej.example.net"]),
    ("set REJECTED and reviewed by hand, no ledger line",
     [{"value": "c2.example.net", "type": "domain-name"}],
     _record("c2.example.net", "domain-name", "REJECTED", True), None, ["c2.example.net"]),
    ("set REJECTED by hand over a signed approval",
     [{"value": "c2a.example.net", "type": "domain-name"}],
     _record("c2a.example.net", "domain-name", "REJECTED", True), "approve",
     ["c2a.example.net"]),
    ("its latest line a cascade's, reviewed by hand",
     [{"value": "c2c.example.net", "type": "domain-name"}],
     _record("c2c.example.net", "domain-name", "REJECTED", True), "cascade",
     ["c2c.example.net"]),
    ("rejected by the examiner, its record changed after",
     [{"value": "c2e.example.net", "type": "domain-name"}],
     _record("c2e.example.net", "domain-name", "REJECTED", True), "reject, then edit",
     ["c2e.example.net"]),
]  # fmt: skip


def _sign(case: Path, record: dict, line: str) -> None:
    """The record's ledger line, as `vhir reject` (or approve) signs it: a
    direct decision, or one coupled from the finding (a cascade)."""
    decision = "approve" if line == "approve" else "reject"
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    signed = {**record, "status": "APPROVED" if decision == "approve" else "REJECTED"}
    bodies = ledger.prepare(
        case.name,
        [{"item_id": record["id"], "type": "ioc", "decision": decision,
          "status_after": signed["status"],
          "coupled_from": FINDING if line == "cascade" else None,
          "content_snapshot": signed_text(signed, "ioc")}],
        "tester", pub, "cli", "2026-10-08T10:00:00+00:00",
    )  # fmt: skip
    with ledger.case_lock(case.name) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


def gathered(report_iocs, case: Path, field, record, line=None) -> list[str]:
    """What `report_iocs` gathers from a case holding `record` (with `line`
    signed for it in the ledger, if any), for a report of one approved
    finding whose iocs field is `field`. Verify's verdicts are the real ones."""
    case.mkdir(exist_ok=True)
    if line:
        _sign(case, record, line)
    if line == "reject, then edit":
        record = {**record, "description": "changed after the rejection"}
    (case / "iocs.json").write_text(json.dumps([record]))
    view = {"findings": [{"id": FINDING, "status": "APPROVED", "iocs": field}],
            "iocs": [record] if record["status"] == "APPROVED" else [],
            "result": approved_view(case)["result"]}  # fmt: skip
    return report_iocs(case, view)


@pytest.mark.parametrize(("field", "record", "line", "expected"), [r[1:] for r in ROWS],
                         ids=[r[0] for r in ROWS])  # fmt: skip
def test_a_value_the_examiner_rejected_is_no_ioc_of_the_report(
    tmp_path, field, record, line, expected
):
    from vhir_cli.commands.report import _report_iocs

    assert gathered(_report_iocs, tmp_path / "case", field, record, line) == expected
