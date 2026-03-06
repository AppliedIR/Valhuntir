"""Tests for HMAC ledger integration in the approve flow."""

from __future__ import annotations

import pytest
import yaml

from aiir_cli.commands.approve import _write_verification_entries
from aiir_cli.verification import read_ledger


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path for all tests."""
    monkeypatch.setattr("aiir_cli.verification.VERIFICATION_DIR", tmp_path)


@pytest.fixture()
def case_dir(tmp_path):
    """Create a minimal case directory with CASE.yaml."""
    d = tmp_path / "case"
    d.mkdir()
    meta = {"case_id": "INC-2026-TEST"}
    (d / "CASE.yaml").write_text(yaml.dump(meta))
    return d


@pytest.fixture()
def config_path(tmp_path):
    """Create a config with password salt for test analyst."""
    import hashlib
    import secrets

    cfg_path = tmp_path / "config.yaml"
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", b"testpassword", salt, 600_000).hex()
    config = {"passwords": {"alice": {"hash": pw_hash, "salt": salt.hex()}}}
    cfg_path.write_text(yaml.dump(config))
    return cfg_path


def test_approve_writes_ledger_entry(case_dir, config_path, tmp_path):
    """Approving a finding writes an HMAC entry to the verification ledger."""
    items = [
        {
            "id": "F-alice-20260226-001",
            "observation": "Suspicious process found on host A",
            "interpretation": "Likely lateral movement",
            "title": "Suspicious process",
        }
    ]
    identity = {"examiner": "alice"}

    _write_verification_entries(
        case_dir,
        items,
        identity,
        config_path,
        password="testpassword",
        now="2026-02-26T00:00:00Z",
    )

    entries = read_ledger("INC-2026-TEST")
    assert len(entries) == 1
    assert entries[0]["finding_id"] == "F-alice-20260226-001"
    assert entries[0]["type"] == "finding"
    # HMAC signs all substantive fields as canonical JSON
    import json

    expected = json.dumps(
        {
            "id": "F-alice-20260226-001",
            "observation": "Suspicious process found on host A",
            "interpretation": "Likely lateral movement",
            "title": "Suspicious process",
        },
        sort_keys=True,
        default=str,
    )
    assert entries[0]["content_snapshot"] == expected
    assert entries[0]["hmac_version"] == 2
    assert entries[0]["approved_by"] == "alice"
    assert entries[0]["case_id"] == "INC-2026-TEST"
    assert len(entries[0]["hmac"]) == 64  # hex SHA-256


def test_approve_timeline_type_field(case_dir, config_path, tmp_path):
    """Timeline events get type='timeline' in ledger entries."""
    items = [
        {
            "id": "T-alice-20260226-001",
            "description": "User logged in at 14:00",
        },
        {
            "id": "F-alice-20260226-001",
            "observation": "Malware detected",
            "interpretation": "Known RAT variant",
            "title": "Malware detection",
        },
    ]
    identity = {"examiner": "alice"}

    _write_verification_entries(
        case_dir,
        items,
        identity,
        config_path,
        password="testpassword",
        now="2026-02-26T00:00:00Z",
    )

    entries = read_ledger("INC-2026-TEST")
    assert len(entries) == 2

    by_id = {e["finding_id"]: e for e in entries}
    assert by_id["T-alice-20260226-001"]["type"] == "timeline"
    assert by_id["F-alice-20260226-001"]["type"] == "finding"


def test_interactive_approve_writes_ledger(case_dir, config_path, tmp_path):
    """Batch approval of multiple items writes all ledger entries."""
    items = [
        {
            "id": "F-alice-20260226-001",
            "observation": "Finding one",
            "interpretation": "Interp one",
            "title": "F1",
        },
        {
            "id": "F-alice-20260226-002",
            "observation": "Finding two",
            "interpretation": "Interp two",
            "title": "F2",
        },
        {"id": "T-alice-20260226-001", "description": "Timeline event"},
    ]
    identity = {"examiner": "alice"}

    _write_verification_entries(
        case_dir,
        items,
        identity,
        config_path,
        password="testpassword",
        now="2026-02-26T00:00:00Z",
    )

    entries = read_ledger("INC-2026-TEST")
    assert len(entries) == 3
    ids = {e["finding_id"] for e in entries}
    assert ids == {
        "F-alice-20260226-001",
        "F-alice-20260226-002",
        "T-alice-20260226-001",
    }
    # All entries have valid HMACs
    for entry in entries:
        assert len(entry["hmac"]) == 64
        assert entry["approved_by"] == "alice"


def test_no_password_skips_ledger(case_dir, config_path, tmp_path):
    """When password is None, no ledger entries are written."""
    items = [
        {
            "id": "F-alice-20260226-001",
            "observation": "test",
            "interpretation": "interp",
            "title": "T",
        }
    ]
    identity = {"examiner": "alice"}

    _write_verification_entries(
        case_dir,
        items,
        identity,
        config_path,
        password=None,
        now="2026-02-26T00:00:00Z",
    )

    entries = read_ledger("INC-2026-TEST")
    assert len(entries) == 0
