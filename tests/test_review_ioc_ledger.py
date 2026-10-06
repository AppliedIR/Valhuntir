"""Approved IOCs in the verification ledger reconcile like findings.

The real approve writes the ledger (VERIFICATION_DIR redirected to
tmp_path), then the real --verify reads it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest


def _ioc_hash(ioc: dict) -> str:
    keys = ("value", "type", "category", "description", "tags", "mitre_techniques")
    h = {k: ioc.get(k) for k in keys if ioc.get(k) is not None}
    return hashlib.sha256(
        json.dumps(h, sort_keys=True, default=str).encode()
    ).hexdigest()


def _new_ioc(seq: int, value: str, finding_id: str, now: str) -> dict:
    # Same record shape forensic-mcp writes for a new IOC.
    ioc = {
        "id": f"IOC-tester-{seq:03d}",
        "value": value,
        "type": "ipv4-addr",
        "category": "network",
        "description": "",
        "status": "DRAFT",
        "confidence": "MEDIUM",
        "source_findings": [finding_id],
        "sightings": [{"host": "", "finding_id": finding_id}],
        "mitre_techniques": [],
        "tags": [],
        "manually_reviewed": False,
        "examiner": "tester",
        "created_at": now,
        "modified_at": now,
    }
    ioc["content_hash"] = _ioc_hash(ioc)
    return ioc


@pytest.fixture
def ioc_case(tmp_path, monkeypatch):
    import vhir_cli.approval_auth as auth
    import vhir_cli.verification as ver
    from vhir_cli.commands import approve

    monkeypatch.setattr(ver, "VERIFICATION_DIR", tmp_path / "ledger")
    monkeypatch.setattr(auth, "get_analyst_salt", lambda cfg, ex, **k: b"\x01" * 16)
    monkeypatch.setattr(auth, "verify_password", lambda *a, **k: True)
    monkeypatch.setattr(auth, "getpass_prompt", lambda p: "pw")
    monkeypatch.setattr(approve, "require_confirmation", lambda cfg, ex: ("pw", "pw"))
    case = tmp_path / "V-case"
    case.mkdir()
    (case / "CASE.yaml").write_text(
        "case_id: INC-IOC-1\nstatus: open\nexaminer: tester\n"
    )
    now = "2026-01-01T00:00:00+00:00"
    finding = {
        "id": "F-tester-001",
        "title": "First finding",
        "observation": "obs 203.0.113.7",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "type": "finding",
        "examiner": "tester",
        "status": "DRAFT",
        "staged": now,
        "modified_at": now,
        "created_by": "tester",
        "iocs": ["203.0.113.7"],
    }
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "timeline.json").write_text("[]")
    iocs = [
        _new_ioc(1, "203.0.113.7", "F-tester-001", now),
        # Sourced from a finding that is never approved: stays DRAFT.
        _new_ioc(2, "198.51.100.9", "F-tester-999", now),
    ]
    (case / "iocs.json").write_text(json.dumps(iocs))
    ident = {"examiner": "tester", "os_user": "tester", "analyst": "tester"}
    approve._approve_specific(case, ["F-tester-001"], ident, Path("cfg"))
    return case, ident


def _edit_iocs(case: Path, fn) -> None:
    path = case / "iocs.json"
    path.chmod(0o644)
    path.write_text(json.dumps(fn(json.loads(path.read_text()))))


def _verify(case: Path, ident: dict, capsys) -> str:
    from vhir_cli.commands.review import _show_findings_verify

    capsys.readouterr()
    _show_findings_verify(case, identity=ident)
    return capsys.readouterr().out


def test_setup_approved_the_ioc_and_signed_it(ioc_case):
    import vhir_cli.verification as ver

    case, _ = ioc_case
    iocs = {i["id"]: i for i in json.loads((case / "iocs.json").read_text())}
    assert iocs["IOC-tester-001"]["status"] == "APPROVED"
    assert iocs["IOC-tester-002"]["status"] == "DRAFT"
    ids = [e["finding_id"] for e in ver.read_ledger("INC-IOC-1")]
    assert sorted(ids) == ["F-tester-001", "IOC-tester-001"], ids


def test_an_approved_ioc_raises_no_alert(ioc_case, capsys):
    out = _verify(*ioc_case, capsys)
    assert re.search(r"IOC-tester-001\s+VERIFIED", out), out
    assert "alert(s) found" not in out, out


def test_a_deleted_ioc_still_alerts(ioc_case, capsys):
    case, ident = ioc_case
    _edit_iocs(case, lambda xs: [x for x in xs if x["id"] != "IOC-tester-001"])
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-001\s+VERIFICATION_NO_FINDING", out), out
    assert "1 alert(s) found" in out, out


def test_an_ioc_changed_after_approval_is_flagged(ioc_case, capsys):
    case, ident = ioc_case

    def tamper(xs):
        for x in xs:
            if x["id"] == "IOC-tester-001":
                x["value"] = "192.0.2.66"
        return xs

    _edit_iocs(case, tamper)
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-001\s+DESCRIPTION_MISMATCH", out), out
    assert "1 alert(s) found" in out, out


def test_an_ioc_no_longer_approved_still_alerts(ioc_case, capsys):
    case, ident = ioc_case

    def unapprove(xs):
        for x in xs:
            if x["id"] == "IOC-tester-001":
                x["status"] = "REJECTED"
        return xs

    _edit_iocs(case, unapprove)
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-001\s+VERIFICATION_NO_FINDING", out), out


def test_an_ioc_marked_approved_without_signing_alerts(ioc_case, capsys):
    case, ident = ioc_case

    def forge(xs):
        for x in xs:
            if x["id"] == "IOC-tester-002":
                x["status"] = "APPROVED"
        return xs

    _edit_iocs(case, forge)
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-002\s+APPROVED_NO_VERIFICATION", out), out


def test_a_draft_ioc_is_not_reconciled(ioc_case, capsys):
    out = _verify(*ioc_case, capsys)
    assert "IOC-tester-002" not in out, out


def test_a_changed_ioc_signature_fails_hmac(ioc_case, capsys):
    import vhir_cli.verification as ver

    case, ident = ioc_case
    path = ver.VERIFICATION_DIR / "INC-IOC-1.jsonl"
    entries = [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    for e in entries:
        if e["finding_id"] == "IOC-tester-001":
            e["content_snapshot"] = e["content_snapshot"].replace(
                "203.0.113.7", "192.0.2.66"
            )
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-001\s+TAMPERED", out), out
    assert re.search(r"F-tester-001\s+CONFIRMED", out), out


def test_an_entry_that_is_not_an_ioc_record_does_not_break_verify(ioc_case, capsys):
    case, ident = ioc_case
    _edit_iocs(case, lambda xs: xs + ["not a record", 7])
    out = _verify(case, ident, capsys)
    assert re.search(r"IOC-tester-001\s+VERIFIED", out), out
    assert "alert(s) found" not in out, out
