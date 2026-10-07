"""Tests for backup manifest hashing (source-stream hash, not destination read-back)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from vhir_cli.commands.backup import (
    _copy_file_hashing,
    _verify_backup,
    create_backup_data,
)


@pytest.fixture(autouse=True)
def _patch_state_dirs(tmp_path, monkeypatch):
    """Keep tests off the real /var/lib/vhir ledger and password hashes."""
    monkeypatch.setattr(
        "vhir_cli.commands.backup.VERIFICATION_DIR", tmp_path / "verification-src"
    )
    monkeypatch.setattr(
        "vhir_cli.commands.backup._PASSWORDS_DIR", tmp_path / "passwords-src"
    )


def _seed_case(tmp_path: Path) -> Path:
    """Build a minimal case dir with two evidence files."""
    case_dir = tmp_path / "INC-TEST"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-TEST"}))
    (case_dir / "findings.json").write_text("[]")
    (case_dir / "evidence" / "host-a.tar").write_bytes(b"alpha payload" * 100)
    (case_dir / "evidence" / "host-b.tar").write_bytes(b"bravo payload" * 100)
    return case_dir


def _manifest(backup_dir: Path) -> dict:
    return json.loads((backup_dir / "backup-manifest.json").read_text())


def test_manifest_records_source_hash_not_destination(tmp_path):
    """A destination corrupted after the copy must not have its bad hash recorded.

    The manifest hash is what `vhir backup --verify` and the restore check compare
    against. If it is taken from a second read of the backup dir, a torn write bakes
    the corrupt bytes' own hash into the manifest and both checks PASS on a backup
    that no longer matches the evidence.
    """
    case_dir = _seed_case(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()

    source_hash = hashlib.sha256(
        (case_dir / "evidence" / "host-a.tar").read_bytes()
    ).hexdigest()

    def corrupt_after_copy(label, i, total):
        # Simulate a torn write: the bytes on the destination differ from the
        # source by the time the manifest is generated.
        if label == "Copying" and i == total:
            backup_dir = next(d for d in dest.iterdir() if d.is_dir())
            (backup_dir / "evidence" / "host-a.tar").write_bytes(b"corrupted")

    result = create_backup_data(
        case_dir=case_dir,
        destination=str(dest),
        examiner="alice",
        include_evidence=True,
        progress_fn=corrupt_after_copy,
    )

    backup_dir = Path(result["backup_path"])
    entries = {e["path"]: e for e in _manifest(backup_dir)["files"]}
    assert entries["evidence/host-a.tar"]["sha256"] == source_hash

    # ...and the corruption is therefore detectable.
    assert _verify_backup(backup_dir) is False


def test_manifest_hashes_match_sources_and_metadata_preserved(tmp_path):
    """Normal backup: every payload hash matches the source, mtime is preserved."""
    case_dir = _seed_case(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()

    result = create_backup_data(
        case_dir=case_dir,
        destination=str(dest),
        examiner="alice",
        include_evidence=True,
    )

    backup_dir = Path(result["backup_path"])
    entries = {e["path"]: e for e in _manifest(backup_dir)["files"]}

    for rel in ("evidence/host-a.tar", "evidence/host-b.tar", "CASE.yaml"):
        src = case_dir / rel
        dst = backup_dir / rel
        assert entries[rel]["sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
        assert entries[rel]["bytes"] == src.stat().st_size
        assert dst.read_bytes() == src.read_bytes()
        # shutil.copy2 preserved mtime; the replacement must too
        assert dst.stat().st_mtime_ns == src.stat().st_mtime_ns

    assert _verify_backup(backup_dir) is True


def test_non_payload_files_still_hashed_from_disk(tmp_path):
    """The verification ledger is copied outside the payload loop and still hashed."""
    ledger_dir = tmp_path / "verification-src"
    ledger_dir.mkdir()
    ledger = ledger_dir / "INC-TEST.jsonl"
    ledger.write_text('{"item": "F-001"}\n')

    case_dir = _seed_case(tmp_path)
    dest = tmp_path / "dest"
    dest.mkdir()

    result = create_backup_data(
        case_dir=case_dir,
        destination=str(dest),
        examiner="alice",
    )

    backup_dir = Path(result["backup_path"])
    entries = {e["path"]: e for e in _manifest(backup_dir)["files"]}
    rel = str(Path("verification") / "INC-TEST.jsonl")
    assert result["includes_verification_ledger"] is True
    assert entries[rel]["sha256"] == hashlib.sha256(ledger.read_bytes()).hexdigest()


def test_copy_into_existing_directory_matches_copy2(tmp_path):
    """A dst that is already a directory receives src inside it, as with copy2.

    The backup writes passwords/ and verification/ before copying the case, so a
    case file with one of those names meets a directory at its destination.
    """
    src = tmp_path / "passwords"
    src.write_bytes(b"examiner's own file")
    dst = tmp_path / "backup" / "passwords"
    dst.mkdir(parents=True)

    written, fhash = _copy_file_hashing(src, dst)

    assert written == dst / "passwords"
    assert written.read_bytes() == b"examiner's own file"
    assert fhash == hashlib.sha256(b"examiner's own file").hexdigest()
