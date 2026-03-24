"""Tests for approve and reject commands (hardened with mandatory password)."""

import json
from argparse import Namespace
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.approval_auth import setup_password
from vhir_cli.case_io import (
    load_approval_log,
    load_findings,
    load_timeline,
    load_todos,
    save_findings,
    save_timeline,
)
from vhir_cli.commands.approve import _approve_specific, cmd_approve
from vhir_cli.commands.reject import cmd_reject


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    meta = {"case_id": case_id, "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    with open(case_path / "todos.json", "w") as f:
        json.dump([], f)

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
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


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".vhir" / "config.yaml"


@pytest.fixture(autouse=True)
def isolate_passwords_dir(tmp_path, monkeypatch):
    """Point _PASSWORDS_DIR to temp dir so tests never touch /var/lib/vhir/."""
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    return d


@pytest.fixture
def pw_config(config_path):
    """Set up a password for analyst1 and return config_path."""
    with patch(
        "vhir_cli.approval_auth.getpass_prompt",
        side_effect=["testpass1", "testpass1"],
    ):
        setup_password(config_path, "analyst1")
    return config_path


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir to avoid cross-test contamination."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


@pytest.fixture
def staged_finding(case_dir):
    """Stage a DRAFT finding."""
    findings = [
        {
            "id": "F-tester-001",
            "status": "DRAFT",
            "title": "Suspicious process",
            "confidence": "MEDIUM",
            "audit_ids": ["ev-001"],
            "observation": "svchost from cmd",
            "interpretation": "unusual",
            "confidence_justification": "single source",
            "type": "finding",
            "staged": "2026-02-19T12:00:00Z",
            "created_by": "steve",
        }
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def staged_timeline(case_dir):
    """Stage a DRAFT timeline event."""
    events = [
        {
            "id": "T-tester-001",
            "status": "DRAFT",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "First lateral movement",
            "staged": "2026-02-19T12:00:00Z",
            "created_by": "jane",
        }
    ]
    save_timeline(case_dir, events)
    return events


class TestApproveSpecific:
    def test_approve_finding(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["approved_by"] == "analyst1"

    def test_approve_timeline_event(
        self, case_dir, identity, staged_timeline, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["T-tester-001"], identity, pw_config)
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_approve_nonexistent_id(
        self, case_dir, identity, staged_finding, capsys, pw_config
    ):
        _approve_specific(case_dir, ["F-999"], identity, pw_config)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_approve_already_approved(
        self, case_dir, identity, staged_finding, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_approval_log_written(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        log = load_approval_log(case_dir)
        assert len(log) == 1
        assert log[0]["item_id"] == "F-tester-001"
        assert log[0]["action"] == "APPROVED"
        assert log[0]["examiner"] == "analyst1"
        assert log[0]["mode"] == "password"

    def test_no_password_configured_exits(
        self, case_dir, identity, staged_finding, config_path, capsys
    ):
        """Approval without password configured exits with setup instructions."""
        with pytest.raises(SystemExit):
            _approve_specific(case_dir, ["F-tester-001"], identity, config_path)
        captured = capsys.readouterr()
        assert "No approval password configured" in captured.err

    def test_approve_with_note(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(
                case_dir,
                ["F-tester-001"],
                identity,
                pw_config,
                note="Correct finding, classify as generic.",
            )
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert len(findings[0]["examiner_notes"]) == 1
        assert (
            findings[0]["examiner_notes"][0]["note"]
            == "Correct finding, classify as generic."
        )

    def test_approve_with_interpretation_override(
        self, case_dir, identity, staged_finding, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(
                case_dir,
                ["F-tester-001"],
                identity,
                pw_config,
                interpretation="Process masquerading confirmed",
            )
        findings = load_findings(case_dir)
        assert findings[0]["interpretation"] == "Process masquerading confirmed"
        assert "interpretation" in findings[0]["examiner_modifications"]
        assert (
            findings[0]["examiner_modifications"]["interpretation"]["original"]
            == "unusual"
        )


class TestApproveInteractive:
    def test_no_drafts(self, case_dir, identity, capsys, monkeypatch):
        save_findings(case_dir, [])
        save_timeline(case_dir, [])
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("vhir_cli.commands.approve.Path.home", return_value=case_dir.parent):
            cmd_approve(args, identity)
        captured = capsys.readouterr()
        assert "No staged items" in captured.out

    def test_interactive_approve_all(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_interactive_note(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["n", "Good finding"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["examiner_notes"][0]["note"] == "Good finding"

    def test_interactive_reject(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["r", "Bad evidence"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Bad evidence"

    def test_interactive_skip(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["s"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"

    def test_interactive_todo(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch(
            "builtins.input",
            side_effect=["t", "Verify with net logs", "jane", "high"],
        ):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        # Finding stays DRAFT
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"
        # TODO created
        todos = load_todos(case_dir)
        assert len(todos) == 1
        assert todos[0]["description"] == "Verify with net logs"
        assert todos[0]["assignee"] == "jane"
        assert todos[0]["related_findings"] == ["F-tester-001"]

    def test_by_filter(
        self,
        case_dir,
        identity,
        staged_finding,
        staged_timeline,
        pw_config,
        capsys,
    ):
        """Filter by creator — only jane's items shown."""
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by="jane",
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        # Only T-tester-001 (by jane) approved, F-tester-001 (by steve) stays DRAFT
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_findings_only(
        self,
        case_dir,
        identity,
        staged_finding,
        staged_timeline,
        pw_config,
        capsys,
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=True,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "DRAFT"  # Not reviewed


class TestReject:
    def test_reject_finding(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(
            ids=["F-tester-001"],
            reason="Insufficient evidence",
            case=None,
            analyst=None,
        )
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Insufficient evidence"
        assert findings[0]["rejected_by"] == "analyst1"
        assert isinstance(findings[0]["rejected_by"], str)

    def test_reject_writes_log(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(
            ids=["F-tester-001"], reason="Bad data", case=None, analyst=None
        )
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        log = load_approval_log(case_dir)
        assert log[0]["action"] == "REJECTED"
        assert log[0]["reason"] == "Bad data"
        assert log[0]["mode"] == "password"

    def test_reject_nonexistent(
        self, case_dir, identity, staged_finding, capsys, pw_config
    ):
        args = Namespace(ids=["F-999"], reason="nope", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            cmd_reject(args, identity)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_reject_no_reason(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(ids=["F-tester-001"], reason="", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        log = load_approval_log(case_dir)
        assert "reason" not in log[0]

    def test_reject_preserves_concurrent_finding(
        self, case_dir, identity, staged_finding, pw_config
    ):
        """A finding added between display and confirmation survives rejection."""
        original_confirm = __import__(
            "vhir_cli.approval_auth", fromlist=["require_confirmation"]
        ).require_confirmation

        def confirm_and_add_finding(config_path, analyst):
            # Simulate an MCP write happening during the confirmation prompt
            findings = load_findings(case_dir)
            findings.append(
                {
                    "id": "F-tester-002",
                    "status": "DRAFT",
                    "title": "Concurrent finding",
                    "staged": "2026-02-19T13:00:00Z",
                    "created_by": "mcp",
                }
            )
            save_findings(case_dir, findings)
            return original_confirm(config_path, analyst)

        args = Namespace(ids=["F-tester-001"], reason="bad", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.commands.reject.require_confirmation",
                side_effect=confirm_and_add_finding,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_reject(args, identity)

        # F-tester-001 should be REJECTED, F-tester-002 should survive as DRAFT
        findings = load_findings(case_dir)
        assert len(findings) == 2
        f001 = next(f for f in findings if f["id"] == "F-tester-001")
        f002 = next(f for f in findings if f["id"] == "F-tester-002")
        assert f001["status"] == "REJECTED"
        assert f002["status"] == "DRAFT"
