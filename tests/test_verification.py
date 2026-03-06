"""Tests for the HMAC verification ledger module."""

from __future__ import annotations

import pytest

from aiir_cli.verification import (
    compute_hmac,
    copy_ledger_to_case,
    derive_hmac_key,
    read_ledger,
    rehmac_entries,
    verify_items,
    write_ledger_entry,
)


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path for all tests."""
    monkeypatch.setattr("aiir_cli.verification.VERIFICATION_DIR", tmp_path)


def test_derive_hmac_key():
    """Deterministic key derivation with known inputs."""
    key1 = derive_hmac_key("1234", b"salt")
    key2 = derive_hmac_key("1234", b"salt")
    assert key1 == key2
    assert len(key1) == 32  # SHA-256 output

    # Different password -> different key
    key3 = derive_hmac_key("5678", b"salt")
    assert key3 != key1


def test_compute_hmac():
    """Known description produces known HMAC."""
    key = derive_hmac_key("test", b"salt")
    h1 = compute_hmac(key, "Malware found on host A")
    h2 = compute_hmac(key, "Malware found on host A")
    assert h1 == h2
    assert len(h1) == 64  # hex SHA-256

    # Different description -> different HMAC
    h3 = compute_hmac(key, "Malware found on host B")
    assert h3 != h1


def test_write_and_read_ledger(tmp_path):
    """Round-trip write and read."""
    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": "deadbeef",
        "content_snapshot": "Test finding",
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)
    entries = read_ledger("INC-2026-001")
    assert len(entries) == 1
    assert entries[0]["finding_id"] == "F-001"
    assert entries[0]["content_snapshot"] == "Test finding"


def test_verify_items_correct_password(tmp_path):
    """Correct password produces CONFIRMED results."""
    password = "mypassword"
    salt = b"mysalt"
    key = derive_hmac_key(password, salt)
    desc = "Suspicious process found"

    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": compute_hmac(key, desc),
        "content_snapshot": desc,
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    results = verify_items("INC-2026-001", password, salt, "alice")
    assert len(results) == 1
    assert results[0]["verified"] is True
    assert results[0]["finding_id"] == "F-001"


def test_verify_items_wrong_password(tmp_path):
    """Wrong password produces unverified results."""
    correct_password = "correct1"
    wrong_password = "wrongpwd"
    salt = b"mysalt"
    key = derive_hmac_key(correct_password, salt)
    desc = "Suspicious process"

    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": compute_hmac(key, desc),
        "content_snapshot": desc,
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    results = verify_items("INC-2026-001", wrong_password, salt, "alice")
    assert len(results) == 1
    assert results[0]["verified"] is False


def test_verify_items_tampered_description(tmp_path):
    """HMAC fails if description was changed after signing."""
    password = "mypassword"
    salt = b"mysalt"
    key = derive_hmac_key(password, salt)
    original_desc = "Original description"
    tampered_desc = "Tampered description"

    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": compute_hmac(key, original_desc),
        "content_snapshot": tampered_desc,  # Tampered
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    results = verify_items("INC-2026-001", password, salt, "alice")
    assert len(results) == 1
    assert results[0]["verified"] is False


def test_copy_ledger_to_case(tmp_path):
    """Ledger file is copied to case directory."""
    entry = {
        "finding_id": "F-001",
        "hmac": "test",
        "content_snapshot": "test",
        "approved_by": "alice",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    copy_ledger_to_case("INC-2026-001", case_dir)

    assert (case_dir / "verification.jsonl").exists()
    content = (case_dir / "verification.jsonl").read_text()
    assert "F-001" in content


def test_rehmac_entries(tmp_path):
    """Entries are re-signed with new key."""
    old_password, old_salt = "oldpasswd", b"oldsalt"
    new_password, new_salt = "newpasswd", b"newsalt"

    old_key = derive_hmac_key(old_password, old_salt)
    desc = "Finding description"

    entry = {
        "finding_id": "F-001",
        "type": "finding",
        "hmac": compute_hmac(old_key, desc),
        "content_snapshot": desc,
        "approved_by": "alice",
        "approved_at": "2026-01-01T00:00:00Z",
        "case_id": "INC-2026-001",
    }
    write_ledger_entry("INC-2026-001", entry)

    count = rehmac_entries(
        "INC-2026-001", "alice", old_password, old_salt, new_password, new_salt
    )
    assert count == 1

    # Verify with new key
    results = verify_items("INC-2026-001", new_password, new_salt, "alice")
    assert len(results) == 1
    assert results[0]["verified"] is True

    # Old key should no longer work
    results_old = verify_items("INC-2026-001", old_password, old_salt, "alice")
    assert results_old[0]["verified"] is False


def test_case_id_validation():
    """Rejects path traversal in case IDs."""
    with pytest.raises(ValueError, match="path traversal"):
        write_ledger_entry("../evil", {"finding_id": "F-001"})

    with pytest.raises(ValueError, match="path traversal"):
        read_ledger("../../etc/passwd")

    with pytest.raises(ValueError, match="empty"):
        write_ledger_entry("", {"finding_id": "F-001"})
