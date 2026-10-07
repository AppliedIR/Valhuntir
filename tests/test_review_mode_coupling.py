"""Tests for dashboard review-mode (``vhir approve --review``) cascade coupling.

Regression coverage for the timeline coupling loop in ``_review_mode``: auto-created
timeline events must follow their source finding only when that finding was acted on
in the *current* invocation, and must never override an event the examiner acted on
directly in the same delta.
"""

import json
from pathlib import Path

import pytest
import yaml

from vhir_cli.commands.approve import _review_mode

OLD_TS = "2026-01-01T00:00:00+00:00"


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".vhir" / "config.yaml"


@pytest.fixture(autouse=True)
def _no_password_prompt(monkeypatch):
    """Review mode is password-gated; stub the gate out for these tests."""
    monkeypatch.setattr(
        "vhir_cli.commands.approve.require_confirmation",
        lambda config_path, examiner: ("password", "unused"),
    )


@pytest.fixture(autouse=True)
def _no_integrity_check(monkeypatch):
    monkeypatch.setattr(
        "vhir_cli.commands.approve.check_case_file_integrity",
        lambda case_dir, filename: None,
    )


def _make_case(tmp_path: Path, findings, timeline, delta_items) -> Path:
    case_id = "INC-2026-COUPLE"
    case_path = tmp_path / case_id
    case_path.mkdir()

    (case_path / "CASE.yaml").write_text(
        yaml.dump({"case_id": case_id, "name": "Test", "status": "open"})
    )
    (case_path / "findings.json").write_text(json.dumps(findings))
    (case_path / "timeline.json").write_text(json.dumps(timeline))
    (case_path / "iocs.json").write_text(json.dumps([]))
    (case_path / "evidence.json").write_text(json.dumps({"files": []}))
    (case_path / "todos.json").write_text(json.dumps([]))
    (case_path / "pending-reviews.json").write_text(
        json.dumps({"case_id": case_id, "items": delta_items})
    )
    return case_path


def test_previously_coupled_event_is_not_restamped(tmp_path, identity, config_path):
    """A later --review run must not re-stamp an already-coupled timeline event.

    F-001 was approved in an earlier session and T-001 was coupled to it then. A new
    delta that only touches the unrelated F-002 must leave T-001's approval metadata
    exactly as it was — re-stamping destroys the original chain-of-custody timestamp.
    """
    findings = [
        {
            "id": "F-001",
            "title": "Old finding",
            "status": "APPROVED",
            "approved_at": OLD_TS,
            "approved_by": "analyst0",
            "content_hash": "oldhash1",
        },
        {"id": "F-002", "title": "New finding", "status": "DRAFT"},
    ]
    timeline = [
        {
            "id": "T-001",
            "description": "Coupled event",
            "status": "APPROVED",
            "auto_created_from": "F-001",
            "approved_at": OLD_TS,
            "approved_by": "analyst0",
            "content_hash": "oldhash2",
        }
    ]
    delta = [{"id": "F-002", "action": "approve"}]

    case_path = _make_case(tmp_path, findings, timeline, delta)
    _review_mode(case_path, identity, config_path)

    saved = {t["id"]: t for t in json.loads((case_path / "timeline.json").read_text())}
    event = saved["T-001"]
    assert event["approved_at"] == OLD_TS, "coupled event was re-stamped on re-run"
    assert event["approved_by"] == "analyst0", "coupled event approver was overwritten"
    assert event["content_hash"] == "oldhash2", "coupled event hash was recomputed"


def test_explicit_rejection_survives_source_approval(tmp_path, identity, config_path):
    """An event rejected directly in the delta must stay rejected.

    The examiner approves F-003 but explicitly rejects the auto-created T-002. The
    coupling loop must not flip that rejection back to APPROVED.
    """
    findings = [{"id": "F-003", "title": "Finding", "status": "DRAFT"}]
    timeline = [
        {
            "id": "T-002",
            "description": "Auto event",
            "status": "DRAFT",
            "auto_created_from": "F-003",
        }
    ]
    delta = [
        {"id": "F-003", "action": "approve"},
        {"id": "T-002", "action": "reject", "rejection_reason": "not relevant"},
    ]

    case_path = _make_case(tmp_path, findings, timeline, delta)
    _review_mode(case_path, identity, config_path)

    saved = {t["id"]: t for t in json.loads((case_path / "timeline.json").read_text())}
    assert saved["T-002"]["status"] == "REJECTED", (
        "explicit rejection was overridden by finding-approval coupling"
    )
    assert saved["T-002"].get("rejection_reason") == "not relevant"


def test_coupling_still_applies_for_source_acted_on_now(
    tmp_path, identity, config_path
):
    """The intended cascade must keep working: approving F-004 approves T-003."""
    findings = [{"id": "F-004", "title": "Finding", "status": "DRAFT"}]
    timeline = [
        {
            "id": "T-003",
            "description": "Auto event",
            "status": "DRAFT",
            "auto_created_from": "F-004",
        }
    ]
    delta = [{"id": "F-004", "action": "approve"}]

    case_path = _make_case(tmp_path, findings, timeline, delta)
    _review_mode(case_path, identity, config_path)

    saved = {t["id"]: t for t in json.loads((case_path / "timeline.json").read_text())}
    assert saved["T-003"]["status"] == "APPROVED"
    assert saved["T-003"]["approved_by"] == "analyst1"


def test_event_staged_after_an_earlier_approval_is_not_approved_unseen(
    tmp_path, identity, config_path
):
    """A DRAFT event must not be approved by a review that never touched its finding.

    F-001 was approved in an earlier session. T-009 was staged later from it and has
    never been reviewed. A delta acting only on the unrelated F-002 must leave T-009
    as DRAFT: approving it would sign an item no examiner has seen.
    """
    findings = [
        {
            "id": "F-001",
            "title": "Old finding",
            "status": "APPROVED",
            "approved_at": OLD_TS,
            "approved_by": "analyst0",
        },
        {"id": "F-002", "title": "New finding", "status": "DRAFT"},
    ]
    timeline = [
        {
            "id": "T-009",
            "description": "Staged after F-001 was approved",
            "status": "DRAFT",
            "auto_created_from": "F-001",
        }
    ]
    delta = [{"id": "F-002", "action": "approve"}]

    case_path = _make_case(tmp_path, findings, timeline, delta)
    _review_mode(case_path, identity, config_path)

    saved = {t["id"]: t for t in json.loads((case_path / "timeline.json").read_text())}
    assert saved["T-009"]["status"] == "DRAFT", (
        "an event nobody reviewed was approved by an unrelated delta"
    )


def test_previously_rejected_event_is_not_restamped(tmp_path, identity, config_path):
    """A later --review run must not re-reject an event rejected in an earlier one.

    F-005 and its event T-010 were rejected in an earlier session. A delta acting
    only on the unrelated F-006 must leave T-010's rejection metadata untouched.
    """
    findings = [
        {
            "id": "F-005",
            "title": "Old finding",
            "status": "REJECTED",
            "rejected_at": OLD_TS,
            "rejected_by": "analyst0",
        },
        {"id": "F-006", "title": "New finding", "status": "DRAFT"},
    ]
    timeline = [
        {
            "id": "T-010",
            "description": "Coupled event",
            "status": "REJECTED",
            "auto_created_from": "F-005",
            "rejected_at": OLD_TS,
            "rejected_by": "analyst0",
            "rejection_reason": "Source finding rejected",
        }
    ]
    delta = [{"id": "F-006", "action": "approve"}]

    case_path = _make_case(tmp_path, findings, timeline, delta)
    _review_mode(case_path, identity, config_path)

    saved = {t["id"]: t for t in json.loads((case_path / "timeline.json").read_text())}
    assert saved["T-010"]["rejected_at"] == OLD_TS, "rejected event was re-stamped"
    assert saved["T-010"]["rejected_by"] == "analyst0"
