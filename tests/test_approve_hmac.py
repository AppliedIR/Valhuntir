"""The approve flow's ledger writes: signed lines, never a 0.6 HMAC line.

0.6 wrote an HMAC line per approved item to the 0.6 verification file. Approve
now signs a ledger line per item with the examiner's key, of the item's
type, carrying the content signed; the 0.6 file is never written.
"""

from __future__ import annotations

import json

import pytest
import yaml

from vhir_cli import ledger
from vhir_cli.case_io import signed_text
from vhir_cli.commands.approve import _approve_specific
from vhir_cli.verification import read_ledger

from .signing import PASSPHRASE, enrol

IDENT = {"examiner": "alice", "os_user": "alice"}
FINDING = {
    "id": "F-alice-20260226-001",
    "observation": "Suspicious process found on host A",
    "interpretation": "Likely lateral movement",
    "title": "Suspicious process",
    "status": "DRAFT",
}
EVENT = {
    "id": "T-alice-20260226-001",
    "timestamp": "2026-02-26T14:00:00Z",
    "description": "User logged in at 14:00",
    "status": "DRAFT",
}


@pytest.fixture()
def case_dir(tmp_path, monkeypatch):
    d = tmp_path / "case"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-2026-TEST"}))
    (d / "findings.json").write_text(json.dumps([FINDING]))
    (d / "timeline.json").write_text(json.dumps([EVENT]))
    monkeypatch.setattr(
        "vhir_cli.approval_auth.getpass_prompt", lambda p="": PASSPHRASE
    )
    return d


def _lines():
    return [o for _, _, o in ledger.read_lines(ledger.chain_path("INC-2026-TEST")) if o]


def test_approve_signs_a_line_per_item_of_its_type_with_its_content(case_dir, tmp_path):
    enrol("alice")
    _approve_specific(case_dir, [FINDING["id"], EVENT["id"]], IDENT, tmp_path / "cfg")
    lines = {o["item_id"]: o for o in _lines()}
    assert lines[FINDING["id"]]["type"] == "finding"
    assert lines[EVENT["id"]]["type"] == "timeline"
    assert lines[FINDING["id"]]["content_snapshot"] == signed_text(FINDING, "finding")
    assert {o["examiner"] for o in lines.values()} == {"alice"}
    assert all(ledger.signature_valid(o) for o in lines.values())


def test_approve_writes_no_0_6_line(case_dir, tmp_path):
    enrol("alice")
    _approve_specific(case_dir, [FINDING["id"]], IDENT, tmp_path / "cfg")
    assert read_ledger("INC-2026-TEST") == [] and len(_lines()) == 1


def test_no_credential_writes_nothing(case_dir, tmp_path, capsys):
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    with pytest.raises(SystemExit):
        _approve_specific(case_dir, [FINDING["id"]], IDENT, tmp_path / "cfg")
    assert "No passphrase configured" in capsys.readouterr().err
    assert _lines() == [] and read_ledger("INC-2026-TEST") == []
