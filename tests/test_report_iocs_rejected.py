"""A value the examiner rejected (its IOC record REJECTED and manually
reviewed, and the rejection signed in the approval ledger, which verify reads
as VALID) is no IOC of the report, so a saved report leaves it live, whichever
approved finding names it and however. A held, approved or cascade-rejected
record is still one when an approved finding names it or the record is
approved, and so is one set REJECTED by hand (no ledger line), one whose
latest line is a cascade's, one changed after its rejection was signed, or any
in a case that fails verify, whatever verdict fails it: the safe side. Values match as the report gathers them (refanged, then
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


def _approved(value) -> dict:  # as `vhir approve` leaves it
    return {**_record(value, "domain-name", "APPROVED", True), "approved_by": "tester",
            "approved_at": "2026-10-08T10:00:00+00:00"}  # fmt: skip


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
    ("rejected by the examiner, its tags changed after",
     [{"value": "c2t.example.net", "type": "domain-name"}],
     _record("c2t.example.net", "domain-name", "REJECTED", True), "reject, then tag",
     ["c2t.example.net"]),
    ("a second reviewed REJECTED record with a signed rejection's id",
     [{"value": "c2d.example.net", "type": "domain-name"}],
     [_record("ok-d.example.net", "domain-name", "REJECTED", True),
      _record("c2d.example.net", "domain-name", "REJECTED", True)], "reject",
     ["ok-d.example.net", "c2d.example.net"]),
    ("a signed rejection in a case whose ledger fails elsewhere",
     [{"value": "c2f.example.net", "type": "domain-name"}],
     _record("c2f.example.net", "domain-name", "REJECTED", True),
     "reject, beside a line for a record the case lacks", ["c2f.example.net"]),
    ("a signed rejection in a case where another IOC changed after its approval",
     [{"value": "c2g.example.net", "type": "domain-name"}],
     [_record("c2g.example.net", "domain-name", "REJECTED", True),
      {**_approved("ok-g.example.net"), "id": "IOC-tester-002"}],
     "reject, beside an approval changed after", ["ok-g.example.net", "c2g.example.net"]),
    ("a signed approval, its status alone set REJECTED after the verify",
     [{"value": "c2r.example.net", "type": "domain-name"}],
     _approved("c2r.example.net"),
     "approve, then REJECTED after the verify", ["c2r.example.net"]),
    ("a signed rejection, the status verify judged",
     [{"value": "c2s.example.net", "type": "domain-name"}],
     _record("c2s.example.net", "domain-name", "REJECTED", True), "reject", []),
    ("a signed approval, its status left APPROVED",
     [{"value": "c2p.example.net", "type": "domain-name"}],
     _approved("c2p.example.net"), "approve",
     ["c2p.example.net"]),
]  # fmt: skip
FAILS = {  # the rows whose case fails verify, and its failures (none: a verdict fails it)
    "a second reviewed REJECTED record with a signed rejection's id": ["DUPLICATE_ID"],
    "a signed rejection in a case whose ledger fails elsewhere": ["ITEM_MISSING"],
    "a signed rejection in a case where another IOC changed after its approval": [],
}


def _sign(case: Path, record: dict, line: str, approved=()) -> None:
    """The record's ledger line, as `vhir reject` (or approve) signs it: a
    direct decision, or one coupled from the finding (a cascade), beside an
    approval of a record the case doesn't hold if `line` says so, and of each
    record in `approved`."""
    decision = "approve" if line.startswith("approve") else "reject"
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    signed = {**record, "status": "APPROVED" if decision == "approve" else "REJECTED"}
    decisions = [{"item_id": record["id"], "type": "ioc", "decision": decision,
                  "status_after": signed["status"],
                  "coupled_from": FINDING if line == "cascade" else None,
                  "content_snapshot": signed_text(signed, "ioc")}]  # fmt: skip
    if line.endswith("a record the case lacks"):
        gone = {**signed, "id": "IOC-tester-002", "status": "APPROVED"}
        decisions.append({"item_id": gone["id"], "type": "ioc", "decision": "approve",
                          "status_after": "APPROVED", "coupled_from": None,
                          "content_snapshot": signed_text(gone, "ioc")})  # fmt: skip
    decisions += [{"item_id": r["id"], "type": "ioc", "decision": "approve",
                   "status_after": "APPROVED", "coupled_from": None,
                   "content_snapshot": signed_text(r, "ioc")} for r in approved]  # fmt: skip
    bodies = ledger.prepare(
        case.name, decisions, "tester", pub, "cli", "2026-10-08T10:00:00+00:00"
    )
    with ledger.case_lock(case.name) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


def gathered(report_iocs, case: Path, field, record, line=None) -> list[str]:
    """What `report_iocs` gathers from a case holding `record` (or the list of
    records, the first one's), with `line` signed for it in the ledger, if
    any, for a report of one approved finding whose iocs field is `field`.
    Verify's verdicts are the real ones."""
    case.mkdir(exist_ok=True)
    records = list(record) if isinstance(record, list) else [record]
    beside = line is not None and line.endswith("an approval changed after")
    if line:
        _sign(case, records[0], line, records[1:] if beside else ())
    if line == "reject, then edit":
        records[0] = {**records[0], "description": "changed after the rejection"}
    if line == "reject, then tag":
        records[0] = {**records[0], "tags": ["changed after the rejection"]}
    if beside:
        records[1] = {**records[1], "description": "changed after the approval"}
    (case / "iocs.json").write_text(json.dumps(records))
    view = {"findings": [{"id": FINDING, "status": "APPROVED", "iocs": field}],
            "iocs": [r for r in records if r["status"] == "APPROVED"],
            "result": approved_view(case)["result"]}  # fmt: skip
    if line == "approve, then REJECTED after the verify":  # before the report reads it
        records[0] = {**records[0], "status": "REJECTED"}
        (case / "iocs.json").write_text(json.dumps(records))
    return report_iocs(case, view)


@pytest.mark.parametrize(("field", "record", "line", "expected", "fails"),
                         [(*r[1:], FAILS.get(r[0])) for r in ROWS],
                         ids=[r[0] for r in ROWS])  # fmt: skip
def test_a_value_the_examiner_rejected_is_no_ioc_of_the_report(
    tmp_path, field, record, line, expected, fails
):
    from vhir_cli.commands.report import _report_iocs

    assert gathered(_report_iocs, tmp_path / "case", field, record, line) == expected
    if fails is not None:  # the case fails verify, so no rejection counts
        result = approved_view(tmp_path / "case")["result"]
        assert result.exit_code == 2 and [f[0] for f in result.failures] == fails
