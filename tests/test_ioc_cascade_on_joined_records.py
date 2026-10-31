# ruff: noqa: F811 - `case` is the fixture imported below
"""Approving and rejecting findings whose IOC citations the writer joined to
one record by a shared key: the address with its port and without, a
double-bracket spelling, the odd types an older writer kept, and a finding
whose citation is past the 100 entries read. Each case states the case files
the writer leaves; `vhir approve` and `vhir reject` run in-process, and
`vhir review --findings --verify` reads every IOC as VALID after."""

from __future__ import annotations

import json

import pytest

from vhir_cli import case_io, ledger

from .test_ioc_cascade_cli import _vhir
from .test_signed_decisions import _status, case  # noqa: F401

F1, F2, IOC = "F-steve-001", "F-steve-002", "IOC-steve-001"
WHY = ("--reason", "duplicate")
PORT = {"value": "10.20.30.41:443", "type": "IPv4"}  # an older writer kept the port
BARE = {"value": "10.20.30.41", "type": "ipv4-addr"}
UNTYPED = {"value": "10.20.30.41:443", "type": "unknown"}


def _finding(fid, iocs):
    return {"id": fid, "title": fid, "observation": "o", "interpretation": "i",
            "confidence": "LOW", "status": "DRAFT", "iocs": iocs}  # fmt: skip


def _record(rid, value, type_, sources, category="host"):
    return {"id": rid, "value": value, "type": type_, "category": category,
            "description": "", "status": "DRAFT", "source_findings": sources,
            "manually_reviewed": False, "tags": [], "mitre_techniques": []}  # fmt: skip


def _write(case, findings, records):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "iocs.json").write_text(json.dumps(records))
    (case / "timeline.json").write_text("[]")


def _decide(monkeypatch, capsys, *argv):
    code, out, err = _vhir(monkeypatch, capsys, *argv)
    assert code == 0, out + err


def _verify(monkeypatch, capsys):
    """`vhir review --findings --verify` passes; each IOC's line, by id."""
    code, out, err = _vhir(monkeypatch, capsys, "review", "--findings", "--verify")
    assert code == 0 and "INVALID" not in out + err, out + err
    assert "CASCADE_UNSUPPORTED" not in out + err, out + err
    return {
        line.split()[0]: line.split(None, 1)[1]
        for line in out.splitlines()
        if line.strip().startswith("IOC-")
    }


@pytest.fixture
def steve(case, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "steve")
    return case


def test_a_citation_spelled_as_its_record_cascades_and_verifies(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, [BARE])],
           [_record(IOC, "10.20.30.41", "ipv4-addr", [F1], "network")])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F1)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC] == (
        f"VALID (cascade from {F1}; {F1} is now APPROVED)"
    )


def test_an_older_record_with_its_port_cascades_from_its_finding_and_verifies(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, [PORT])],
           [_record(IOC, "10.20.30.41:443", "IPv4", [F1])])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F1)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC] == (
        f"VALID (cascade from {F1}; {F1} is now APPROVED)"
    )


def test_a_bare_address_joined_to_an_approved_port_record_still_verifies(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, [PORT])],
           [_record(IOC, "10.20.30.41:443", "IPv4", [F1])])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F1)
    # the writer then joins a second finding's bare address to that record
    case_io.save_findings(steve, [*case_io.load_findings(steve), _finding(F2, [BARE])])
    records = case_io.load_iocs(steve)
    records[0]["source_findings"] = [F1, F2]
    case_io.save_iocs(steve, records)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC] == (
        f"VALID (cascade from {F1}; {F1} is now APPROVED)"
    )


def test_a_port_record_cited_typed_and_untyped_cascades_from_each(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, [PORT]), _finding(F2, [UNTYPED])],
           [_record(IOC, "10.20.30.41:443", "IPv4", [F1, F2])])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F1)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    _decide(monkeypatch, capsys, "approve", F2)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC].startswith(f"VALID (cascade from {F1};")


def test_approving_only_the_bare_address_approves_the_joined_port_record(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, [PORT]), _finding(F2, [BARE])],
           [_record(IOC, "10.20.30.41:443", "IPv4", [F1, F2])])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F2)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    want = f"VALID (cascade from {F2}; {F2} is now APPROVED)"
    assert _verify(monkeypatch, capsys)[IOC] == want
    _decide(monkeypatch, capsys, "approve", F1)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC] == want


def test_a_double_bracket_citation_cascades_to_its_record_and_verifies(
    steve, monkeypatch, capsys
):
    _write(steve, [_finding(F1, ["user[[@]]evilrf.example.com"])],
           [_record(IOC, "user[@]evilrf.example.com", "email-addr", [F1], "email")])  # fmt: skip
    _decide(monkeypatch, capsys, "approve", F1)
    assert _status(steve, "iocs.json", IOC) == "APPROVED"
    assert _verify(monkeypatch, capsys)[IOC] == (
        f"VALID (cascade from {F1}; {F1} is now APPROVED)"
    )


# what an older writer stored for each type shape: each finding's citation,
# and the record it made (None: no record)
OLD_TYPES = [
    ({"value": "10.20.31.1", "type": None}, ("10.20.31.1", "ipv4-addr", "network")),
    ({"value": "10.20.31.2", "type": ""}, ("10.20.31.2", "ipv4-addr", "network")),
    ({"value": "10.20.31.3", "type": "  "}, ("10.20.31.3", "  ", "host")),
    ({"value": "10.20.31.4", "type": 5}, None),
    ({"value": "10.20.31.5", "type": ["ipv4"]}, ("10.20.31.5", ["ipv4"], "host")),
    ({"value": "10.20.31.6", "type": {"t": "ipv4"}}, ("10.20.31.6", {"t": "ipv4"}, "host")),
    ({"value": "10.20.31.7:443", "type": "IPV4-ADDR"}, ("10.20.31.7:443", "IPV4-ADDR", "host")),
    ({"value": "10.20.31.8:443", "type": " ipv4-addr "}, ("10.20.31.8:443", " ipv4-addr ", "host")),
    ({"ip": "10.20.31.9", "type": "IPv4"}, ("{'ip': '10.20.31.9', 'type': 'IPv4'}", "unknown", "unknown")),
]  # fmt: skip


def test_records_an_older_writer_typed_oddly_are_listed_approved_and_verify(
    steve, monkeypatch, capsys
):
    findings, records = [], []
    for n, (cited, made) in enumerate(OLD_TYPES, 1):
        fid = f"F-steve-{n:03d}"
        findings.append(_finding(fid, [cited]))
        if made:
            rid = f"IOC-steve-{len(records) + 1:03d}"
            records.append(_record(rid, *made[:2], [fid], made[2]))
    _write(steve, findings, records)
    code, out, err = _vhir(monkeypatch, capsys, "review", "--iocs")
    assert code == 0, out + err
    assert all(f"10.20.31.{n}" in out for n in range(1, 10)), out
    _decide(monkeypatch, capsys, "approve", *(f["id"] for f in findings))
    assert {_status(steve, "iocs.json", r["id"]) for r in records} == {"APPROVED"}
    lines = _verify(monkeypatch, capsys)
    assert all(lines[r["id"]].startswith("VALID") for r in records), lines


@pytest.mark.parametrize(
    "entries, sources, after",
    [(101, [F2], "REJECTED"), (2, [F1, F2], "DRAFT")],
    ids=["past-the-100-read", "within-them"],
)
def test_rejecting_one_citer_reads_the_other_only_within_its_first_100(
    steve, monkeypatch, capsys, entries, sources, after
):
    big = [f"10.41.{i // 250}.{i % 250 + 1}" for i in range(entries - 1)]
    _write(steve, [_finding(F1, [*big, "10.20.30.99"]), _finding(F2, ["10.20.30.99"])],
           [_record(IOC, "10.20.30.99", "ipv4-addr", sources, "network")])  # fmt: skip
    _decide(monkeypatch, capsys, "reject", F2, *WHY)
    assert _status(steve, "iocs.json", IOC) == after
    assert (IOC in _verify(monkeypatch, capsys)) is (after == "REJECTED")


def test_reading_joined_and_oddly_typed_records_leaves_every_file_as_it_was(
    steve, monkeypatch, capsys
):
    findings = [_finding(F1, [PORT]), _finding(F2, [BARE])]
    records = [_record(IOC, "10.20.30.41:443", "IPv4", [F1, F2])]
    for n, (cited, made) in enumerate(OLD_TYPES, 3):
        findings.append(_finding(f"F-steve-{n:03d}", [cited]))
        if made:
            rid = f"IOC-steve-{len(records) + 1:03d}"
            records.append(_record(rid, *made[:2], [f"F-steve-{n:03d}"], made[2]))
    _write(steve, findings, records)
    _decide(monkeypatch, capsys, "approve", F2, "F-steve-003", "F-steve-005")
    chain = ledger.chain_path("C-9")
    files = [steve / "iocs.json", steve / "findings.json", chain]
    before = [p.read_bytes() for p in files]
    for argv in (["review", "--iocs"], ["report", "--ioc"], ["review", "--findings"],
                 ["review", "--findings", "--verify"]):  # fmt: skip
        code, out, err = _vhir(monkeypatch, capsys, *argv)
        assert code == 0, out + err
        assert [p.read_bytes() for p in files] == before, argv
