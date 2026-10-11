"""A merge never replaces an item this case recorded.

Alice records F-alice-001; bob merges it, approves it and exports; alice merges
bob's export. Bob's copy is newer, but it is a stripped, imported copy of
alice's own record: storing it would drop her provenance, examiner and
timestamps and grade it IMPORTED. An item this case recorded (a top-level
`created_by`) keeps its record, and the merge counts the incoming copy under
`own` and says so.
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import patch

import pytest

from vhir_cli.case_io import (
    export_bundle,
    import_bundle,
    load_findings,
    load_timeline,
    save_findings,
    save_timeline,
)
from vhir_cli.commands.approve import _approve_specific
from vhir_cli.commands.sync import cmd_merge

from .signing import enrol
from .test_merge_decision_fields import _case, _finding


@pytest.fixture
def identity():
    return {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag",
            "analyst": "analyst1", "analyst_source": "flag"}  # fmt: skip


@pytest.fixture(autouse=True)
def isolate_password_state(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", tmp_path / ".lockout")


@pytest.fixture
def pw_config(tmp_path):
    enrol("analyst1")  # passphrase testpass1
    return tmp_path / ".vhir" / "config.yaml"


SIX = (
    "provenance",
    "provenance_detail",
    "examiner",
    "created_by",
    "staged",
    "modified_at",
)
KEPT = "1 kept: recorded in this case (incoming copy not applied)"


def _alice_finding():
    return _finding("F-alice-001", created_by="alice", examiner="alice",
                    provenance="MCP", provenance_detail={"tool": "run_command"},
                    provenance_grade="FULL")  # fmt: skip


def _alice_event():
    return {"id": "T-alice-001", "status": "DRAFT", "timestamp": "2026-02-19T10:00:00Z",
            "description": "own event", "staged": "2026-02-19T12:00:00Z",
            "modified_at": "2026-02-19T12:00:00Z", "created_by": "alice",
            "examiner": "alice"}  # fmt: skip


def _round_trip(tmp_path, monkeypatch, identity, pw_config, approve_ids):
    """Alice records; bob merges, approves (for real) and exports; alice's case
    and bob's bundle, ready for alice to merge it."""
    alice = _case(tmp_path, "A", "alice", monkeypatch)
    save_findings(alice, [_alice_finding()])
    save_timeline(alice, [_alice_event()])
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    import_bundle(bob, export_bundle(alice))
    with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
        _approve_specific(bob, approve_ids, identity, pw_config)
    assert {i["id"]: i["status"] for i in load_findings(bob) + load_timeline(bob)} == {
        "F-alice-001": "APPROVED",
        "T-alice-001": "APPROVED" if "T-alice-001" in approve_ids else "DRAFT",
    }
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    monkeypatch.setenv("VHIR_CASE_DIR", str(alice))
    return alice, export_bundle(bob)


def test_a_round_trip_keeps_alices_own_finding_as_she_recorded_it(
    tmp_path, monkeypatch, identity, pw_config
):
    alice, bundle = _round_trip(
        tmp_path, monkeypatch, identity, pw_config, ["F-alice-001"]
    )
    (before,) = load_findings(alice)
    (incoming,) = bundle["findings"]
    assert incoming["modified_at"] > before["modified_at"]  # bob's copy is newer
    result = import_bundle(alice, bundle)
    (after,) = load_findings(alice)
    assert json.dumps(after) == json.dumps(before)
    assert (result["findings"]["own"], result["findings"]["updated"]) == (1, 0)
    assert all(after.get(k) for k in SIX) and after["provenance_grade"] == "FULL"
    assert "imported_from" not in after


def test_a_round_trip_keeps_alices_own_timeline_event_as_she_recorded_it(
    tmp_path, monkeypatch, identity, pw_config
):
    ids = ["F-alice-001", "T-alice-001"]
    alice, bundle = _round_trip(tmp_path, monkeypatch, identity, pw_config, ids)
    (before,) = load_timeline(alice)
    (incoming,) = bundle["timeline"]
    assert incoming["modified_at"] > before["modified_at"]
    result = import_bundle(alice, bundle)
    (after,) = load_timeline(alice)
    assert json.dumps(after) == json.dumps(before)
    assert (result["timeline"]["own"], result["timeline"]["updated"]) == (1, 0)
    assert "imported_from" not in after


def test_vhir_merge_says_it_kept_the_cases_own_items(
    tmp_path, monkeypatch, identity, pw_config, capsys
):
    ids = ["F-alice-001", "T-alice-001"]
    alice, bundle = _round_trip(tmp_path, monkeypatch, identity, pw_config, ids)
    path = tmp_path / "bob.json"
    path.write_text(json.dumps(bundle))
    capsys.readouterr()
    cmd_merge(argparse.Namespace(file=str(path), case=None), {"examiner": "alice"})
    out = capsys.readouterr().out
    assert f"  Findings: 0 added, 0 updated, 0 skipped, {KEPT}\n" in out
    assert f"  Timeline: 0 added, 0 updated, 0 skipped, {KEPT}\n" in out
