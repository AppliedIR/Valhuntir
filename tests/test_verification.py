"""The 0.6 verification file: read only, as 0.6's history.

0.7 never writes, re-signs or checks the HMAC of a 0.6 line (approvals are
signed ledger lines, and 0.6 lines are judged by `verify_case` against the
history signing froze). What remains is reading the file and copying it into
the case at close.
"""

from __future__ import annotations

import json

import pytest

from vhir_cli import verification
from vhir_cli.verification import copy_ledger_to_case, read_ledger

ENTRY = {
    "finding_id": "F-001",
    "type": "finding",
    "hmac": "deadbeef",
    "content_snapshot": "Test finding",
    "approved_by": "alice",
    "approved_at": "2026-01-01T00:00:00Z",
    "case_id": "INC-2026-001",
}


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path for all tests."""
    monkeypatch.setattr("vhir_cli.verification.VERIFICATION_DIR", tmp_path)
    (tmp_path / "INC-2026-001.jsonl").write_text(json.dumps(ENTRY) + "\n")


def test_read_ledger():
    entries = read_ledger("INC-2026-001")
    assert len(entries) == 1
    assert entries[0]["finding_id"] == "F-001"
    assert entries[0]["content_snapshot"] == "Test finding"


def test_copy_ledger_to_case(tmp_path):
    """Ledger file is copied to case directory."""
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    copy_ledger_to_case("INC-2026-001", case_dir)
    assert (case_dir / "verification.jsonl").exists()
    assert "F-001" in (case_dir / "verification.jsonl").read_text()


def test_case_id_validation():
    """Rejects path traversal in case IDs."""
    with pytest.raises(ValueError, match="path traversal"):
        read_ledger("../../etc/passwd")
    with pytest.raises(ValueError, match="empty"):
        read_ledger("")


def test_no_code_writes_re_signs_or_checks_a_0_6_line():
    for name in ("write_ledger_entry", "rehmac_entries", "verify_items",
                 "compute_hmac", "derive_hmac_key"):  # fmt: skip
        assert not hasattr(verification, name), name
