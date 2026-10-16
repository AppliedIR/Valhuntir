"""A merged item arrives as a DRAFT with no approval or rejection on it.

A decision belongs to the case that made it, which holds the ledger entry
behind it. A bundle that carries approved_*, rejected_*, rejection_reason or
verification must not leave them on the merged item, where review, report and
the AI's view of the findings would show them on a DRAFT.
"""

from __future__ import annotations

import json
from argparse import Namespace
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.case_io import (
    export_bundle,
    import_bundle,
    load_findings,
    save_findings,
    verify_approval_integrity,
)
from vhir_cli.commands.approve import _approve_specific
from vhir_cli.commands.reject import cmd_reject
from vhir_cli.commands.report import _report_findings
from vhir_cli.commands.review import _show_findings_detail

from .signing import enrol

DECISION = {
    "approved_at": "2026-09-01T00:00:00+00:00",
    "approved_by": "analyst1",
    "rejected_at": "2026-09-02T00:00:00+00:00",
    "rejected_by": "analyst1",
    "rejection_reason": "IMPORTED reason",
    "verification": "confirmed",
}
NEWER = "2099-01-01T00:00:00+00:00"


def _case(root, case_id, examiner, monkeypatch):
    path = root / case_id
    path.mkdir()
    (path / "CASE.yaml").write_text(yaml.dump({"case_id": case_id, "status": "open"}))
    (path / "evidence.json").write_text(json.dumps({"files": []}))
    (path / "todos.json").write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", examiner)
    monkeypatch.setenv("VHIR_CASE_DIR", str(path))
    return path


def _finding(fid, **extra):
    item = {
        "id": fid,
        "status": "DRAFT",
        "title": "Finding " + fid,
        "confidence": "MEDIUM",
        "observation": "svchost from cmd",
        "interpretation": "unusual",
        "type": "finding",
        "staged": "2026-02-19T12:00:00Z",
        "modified_at": "2026-02-19T12:00:00Z",
        "created_by": "tester",
    }
    item.update(extra)
    return item


def _peer_copy(fid, **extra):
    """A local copy of a peer's item, as a merge stores it: no `created_by`."""
    item = _finding(fid, **extra)
    del item["created_by"]
    return item


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    return _case(tmp_path, "INC-2026-TEST", "tester", monkeypatch)


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
def isolate_password_state(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", tmp_path / ".lockout")


@pytest.fixture
def pw_config(tmp_path):
    config = tmp_path / ".vhir" / "config.yaml"
    enrol("analyst1")  # passphrase testpass1
    return config


def _block(text, fid):
    """The lines printed for one finding."""
    start = text.index(f"[{fid}]")
    nxt = text.find("[F-", start + 1)
    return text[start : nxt if nxt != -1 else len(text)]


def _decision_lines(text):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("Approved:", "Rejected:", "Reason:"))
    ]


def _report(case_dir, fid, capsys):
    # The report's text, as cmd_report prints it
    return _block(
        _report_findings(case_dir, Namespace(report_findings=fid, save=None)), fid
    )


@pytest.mark.parametrize("how", ["added", "overwritten"])
def test_merge_stores_no_incoming_approval_or_rejection_fields(case_dir, how):
    save_findings(case_dir, [_peer_copy("F-tester-001")])
    fid = "F-other-001" if how == "added" else "F-tester-001"
    item = _finding(
        fid, status="APPROVED", modified_at=NEWER, title="incoming", **DECISION
    )
    result = import_bundle(case_dir, {"findings": [item], "timeline": []})
    assert result["findings"][how if how == "added" else "updated"] == 1
    (merged,) = [f for f in load_findings(case_dir) if f["id"] == fid]
    assert merged["status"] == "DRAFT" and merged["title"] == "incoming"
    assert sorted(set(DECISION) & set(merged)) == []


def test_a_merged_timeline_event_carries_no_decision(case_dir):
    event = {
        "id": "T-other-001",
        "status": "APPROVED",
        "timestamp": "2026-02-19T10:00:00Z",
        "description": "First lateral movement",
        "modified_at": NEWER,
        **DECISION,
    }
    import_bundle(case_dir, {"findings": [], "timeline": [event]})
    (merged,) = json.loads((case_dir / "timeline.json").read_text())
    assert merged["status"] == "DRAFT"
    assert sorted(set(DECISION) & set(merged)) == []


def test_review_and_report_show_no_decision_lines_on_a_merged_draft(case_dir, capsys):
    item = _finding("F-other-001", modified_at=NEWER, **DECISION)
    import_bundle(case_dir, {"findings": [item], "timeline": []})
    capsys.readouterr()
    _show_findings_detail(case_dir)
    assert _decision_lines(_block(capsys.readouterr().out, "F-other-001")) == []
    assert _decision_lines(_report(case_dir, "F-other-001", capsys)) == []
    (row,) = verify_approval_integrity(case_dir)
    assert row["verification"] == "draft"


def test_approving_a_merged_item_reports_no_incoming_rejection(
    case_dir, identity, pw_config, capsys
):
    item = _finding("F-other-001", modified_at=NEWER, **DECISION)
    import_bundle(case_dir, {"findings": [item], "timeline": []})
    with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
        _approve_specific(case_dir, ["F-other-001"], identity, pw_config)
    capsys.readouterr()
    lines = _decision_lines(_report(case_dir, "F-other-001", capsys))
    assert [line.split(":", 1)[0] for line in lines] == ["Approved"]
    (row,) = verify_approval_integrity(case_dir)
    assert row["verification"] == "confirmed"


def test_rejecting_a_merged_item_reports_no_incoming_approval(
    case_dir, identity, pw_config, capsys
):
    item = _finding("F-other-001", modified_at=NEWER, **DECISION)
    import_bundle(case_dir, {"findings": [item], "timeline": []})
    args = Namespace(
        ids=["F-other-001"], reason="not supported", case=None, analyst=None
    )
    with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            cmd_reject(args, identity)
    capsys.readouterr()
    lines = _decision_lines(_report(case_dir, "F-other-001", capsys))
    assert lines == [
        "Rejected:     " + load_findings(case_dir)[0]["rejected_at"],
        "Reason:       not supported",
    ]


def test_merge_keeps_a_peers_content_fields(tmp_path, monkeypatch):
    peer = _case(tmp_path, "PEER-CASE", "alice", monkeypatch)
    extra = {
        "timeline_event_id": "T-alice-001",
        "source_evidence": "evidence/host1/Security.evtx",
        "provenance_warnings": ["one source"],
        "custom_note_key": {"any": "value"},
    }
    save_findings(peer, [_finding("F-alice-001", **extra)])
    bundle = export_bundle(peer)
    mine = _case(tmp_path, "MY-CASE", "bob", monkeypatch)
    result = import_bundle(mine, bundle)
    assert result["findings"]["added"] == 1
    (merged,) = load_findings(mine)
    assert {k: merged.get(k) for k in extra} == extra
    assert merged["title"] == "Finding F-alice-001"


def test_merge_newer_peer_version_replaces_a_local_draft(case_dir):
    """A local copy of a peer's item (no `created_by`) takes the newer version;
    an item this case recorded never does, however new the incoming copy."""
    save_findings(case_dir, [_peer_copy("F-tester-001"), _finding("F-tester-002")])
    items = [
        _finding(fid, title="revised", modified_at=NEWER)
        for fid in ("F-tester-001", "F-tester-002")
    ]
    result = import_bundle(case_dir, {"findings": items, "timeline": []})
    stored = {f["id"]: f["title"] for f in load_findings(case_dir)}
    assert stored == {"F-tester-001": "revised", "F-tester-002": "Finding F-tester-002"}
    assert (result["findings"]["updated"], result["findings"]["own"]) == (1, 1)


def test_merge_keeps_a_local_approved_finding(case_dir, identity, pw_config):
    save_findings(case_dir, [_finding("F-tester-001")])
    with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
        _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
    item = _finding("F-tester-001", title="revised", modified_at=NEWER)
    result = import_bundle(case_dir, {"findings": [item], "timeline": []})
    assert result["findings"]["protected"] == 1
    (kept,) = load_findings(case_dir)
    assert kept["status"] == "APPROVED" and kept["title"] == "Finding F-tester-001"


def test_merge_skips_an_older_incoming_version(case_dir):
    save_findings(case_dir, [_peer_copy("F-tester-001", modified_at=NEWER)])
    item = _finding("F-tester-001", title="older", modified_at="2026-01-01T00:00:00Z")
    result = import_bundle(case_dir, {"findings": [item], "timeline": []})
    assert result["findings"]["skipped"] == 1
    assert load_findings(case_dir)[0]["title"] == "Finding F-tester-001"


def test_an_older_copy_of_an_item_this_case_recorded_counts_as_own(case_dir):
    save_findings(case_dir, [_finding("F-tester-001", modified_at=NEWER)])
    item = _finding("F-tester-001", title="older", modified_at="2026-01-01T00:00:00Z")
    result = import_bundle(case_dir, {"findings": [item], "timeline": []})
    assert (result["findings"]["own"], result["findings"]["skipped"]) == (1, 0)
    assert load_findings(case_dir)[0]["title"] == "Finding F-tester-001"


def test_a_merge_writes_no_approval_log(case_dir):
    item = _finding("F-other-001", status="APPROVED", modified_at=NEWER, **DECISION)
    import_bundle(case_dir, {"findings": [item], "timeline": []})
    assert not (case_dir / "approvals.jsonl").exists()
