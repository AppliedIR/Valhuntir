"""Tests for the backup command."""

import json
from pathlib import Path

import pytest
import yaml

from vhir_cli.commands.backup import create_backup_data

CASE_ID = "INC-2026-TEST"


@pytest.fixture
def case_dir(tmp_path):
    """Create a minimal flat case directory with findings staged by 'dana'."""
    case_path = tmp_path / "case" / CASE_ID
    case_path.mkdir(parents=True)

    meta = {"case_id": CASE_ID, "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "findings.json", "w") as f:
        json.dump([{"id": "F-1", "title": "Staged", "created_by": "dana"}], f)

    return case_path


@pytest.fixture
def passwords_dir(tmp_path, monkeypatch):
    """Point _PASSWORDS_DIR at a temp dir holding hashes for dana and ravi."""
    pw_dir = tmp_path / "passwords"
    pw_dir.mkdir()
    for name in ("dana", "ravi"):
        with open(pw_dir / f"{name}.json", "w") as f:
            json.dump({"hash": "de" + "ad" * 31, "salt": "be" + "ef" * 31}, f)
    monkeypatch.setattr("vhir_cli.commands.backup._PASSWORDS_DIR", pw_dir)
    return pw_dir


@pytest.fixture
def ledger_dir(tmp_path, monkeypatch):
    """Point VERIFICATION_DIR at a temp dir with a ledger approved by 'ravi'."""
    vdir = tmp_path / "verification"
    vdir.mkdir()
    entry = {
        "finding_id": "F-1",
        "type": "finding",
        "hmac": "00" * 32,
        "hmac_version": 2,
        "content_snapshot": "Staged",
        "approved_by": "ravi",
        "approved_at": "2026-01-01T00:00:00+00:00",
        "case_id": CASE_ID,
    }
    with open(vdir / f"{CASE_ID}.jsonl", "w") as f:
        f.write(json.dumps(entry) + "\n")
    monkeypatch.setattr("vhir_cli.commands.backup.VERIFICATION_DIR", vdir)
    return vdir


def test_backup_includes_approver_password_hash(
    case_dir, passwords_dir, ledger_dir, tmp_path
):
    """The salt of every examiner who signed the ledger must be backed up."""
    result = create_backup_data(case_dir, str(tmp_path / "dest"), "tester")

    assert result["password_examiners"] == ["dana", "ravi"]
    backup_path = Path(result["backup_path"])
    assert (backup_path / "passwords" / "ravi.json").is_file()
    assert (backup_path / "passwords" / "dana.json").is_file()

    manifest = json.loads((backup_path / "backup-manifest.json").read_text())
    assert manifest["password_examiners"] == ["dana", "ravi"]


def test_backup_includes_approver_without_created_by(
    case_dir, passwords_dir, ledger_dir, tmp_path
):
    """Findings with no created_by must not leave the ledger unverifiable."""
    with open(case_dir / "findings.json", "w") as f:
        json.dump([{"id": "F-1", "title": "Staged"}], f)

    result = create_backup_data(case_dir, str(tmp_path / "dest"), "tester")

    assert result["password_examiners"] == ["ravi"]
    assert (Path(result["backup_path"]) / "passwords" / "ravi.json").is_file()
