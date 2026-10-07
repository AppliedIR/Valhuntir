"""Tests for staleness detection in dashboard review mode (vhir approve --review)."""

import json
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.approval_auth import setup_password
from vhir_cli.case_io import compute_content_hash, load_approval_log, save_findings
from vhir_cli.commands.approve import _review_mode


@pytest.fixture
def case_dir(tmp_path):
    """Create a minimal flat case directory structure."""
    case_path = tmp_path / "INC-2026-TEST"
    case_path.mkdir()
    meta = {"case_id": "INC-2026-TEST", "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)
    with open(case_path / "todos.json", "w") as f:
        json.dump([], f)
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture(autouse=True)
def isolate_passwords_dir(tmp_path, monkeypatch):
    """Point _PASSWORDS_DIR to temp dir so tests never touch /var/lib/vhir/."""
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    return d


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir to avoid cross-test contamination."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


@pytest.fixture(autouse=True)
def isolate_verification_dir(tmp_path, monkeypatch):
    """Redirect VERIFICATION_DIR to tmp_path so no ledger touches the system."""
    monkeypatch.setattr("vhir_cli.verification.VERIFICATION_DIR", tmp_path / "ledger")


@pytest.fixture
def pw_config(tmp_path):
    """Set up a password for analyst1 and return config_path."""
    cfg_path = tmp_path / ".vhir" / "config.yaml"
    with patch(
        "vhir_cli.approval_auth.getpass_prompt",
        side_effect=["testpass1", "testpass1"],
    ):
        setup_password(cfg_path, "analyst1")
    return cfg_path


def _write_delta(case_dir, entries):
    """Write a pending-reviews.json delta file."""
    with open(case_dir / "pending-reviews.json", "w") as f:
        json.dump({"case_id": "INC-2026-TEST", "items": entries}, f)


def _run_review(case_dir, identity, pw_config):
    with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
        _review_mode(case_dir, identity, pw_config)


def _record_for(case_dir, item_id):
    return [r for r in load_approval_log(case_dir) if r["item_id"] == item_id][0]


def test_stale_detected_when_stored_hash_was_not_updated(
    case_dir, identity, pw_config, capsys
):
    """Content rewritten but content_hash left untouched still warns."""
    reviewed = {
        "id": "F-tester-001",
        "status": "DRAFT",
        "title": "Suspicious process",
        "observation": "svchost spawned from cmd",
        "interpretation": "unusual",
    }
    hash_at_review = compute_content_hash(reviewed)

    current = dict(reviewed)
    current["observation"] = "svchost spawned from explorer"
    current["content_hash"] = hash_at_review
    save_findings(case_dir, [current])
    _write_delta(
        case_dir,
        [
            {
                "id": "F-tester-001",
                "action": "approve",
                "content_hash_at_review": hash_at_review,
            }
        ],
    )

    _run_review(case_dir, identity, pw_config)

    out = capsys.readouterr().out
    assert "F-tester-001 was modified after you reviewed it" in out
    assert _record_for(case_dir, "F-tester-001").get("stale_at_approval") is True


def test_stale_detected_when_item_has_no_stored_hash(
    case_dir, identity, pw_config, capsys
):
    """A DRAFT item carrying no content_hash field still warns when changed."""
    reviewed = {
        "id": "F-tester-002",
        "status": "DRAFT",
        "title": "Suspicious process",
        "observation": "svchost spawned from cmd",
        "interpretation": "unusual",
    }
    hash_at_review = compute_content_hash(reviewed)

    current = dict(reviewed)
    current["observation"] = "svchost spawned from explorer"
    save_findings(case_dir, [current])
    _write_delta(
        case_dir,
        [
            {
                "id": "F-tester-002",
                "action": "approve",
                "content_hash_at_review": hash_at_review,
            }
        ],
    )

    _run_review(case_dir, identity, pw_config)

    out = capsys.readouterr().out
    assert "F-tester-002 was modified after you reviewed it" in out
    assert _record_for(case_dir, "F-tester-002").get("stale_at_approval") is True


def test_unchanged_item_is_not_flagged_stale(case_dir, identity, pw_config, capsys):
    """An item that did not change since review produces no stale warning."""
    reviewed = {
        "id": "F-tester-003",
        "status": "DRAFT",
        "title": "Suspicious process",
        "observation": "svchost spawned from cmd",
        "interpretation": "unusual",
    }
    hash_at_review = compute_content_hash(reviewed)
    save_findings(case_dir, [reviewed])
    _write_delta(
        case_dir,
        [
            {
                "id": "F-tester-003",
                "action": "approve",
                "content_hash_at_review": hash_at_review,
            }
        ],
    )

    _run_review(case_dir, identity, pw_config)

    out = capsys.readouterr().out
    assert "was modified after you reviewed it" not in out
    assert "stale_at_approval" not in _record_for(case_dir, "F-tester-003")
