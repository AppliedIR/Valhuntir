"""Tests for report generation commands."""

import json
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from vhir_cli.case_io import save_findings, save_timeline, save_todos
from vhir_cli.commands.report import cmd_report


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()
    (case_path / "reports").mkdir()
    (case_path / "audit").mkdir()

    monkeypatch.setenv("VHIR_EXAMINER", "tester")

    meta = {
        "case_id": case_id,
        "name": "Test Case",
        "status": "open",
        "created": "2026-02-19T00:00:00Z",
        "examiner": "tester",
    }
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    # Initialize empty data files
    for fname in ("findings.json", "timeline.json", "todos.json"):
        (case_path / fname).write_text("[]")

    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "tester",
        "examiner_source": "env",
        "analyst": "tester",
        "analyst_source": "env",
    }


@pytest.fixture
def sample_findings(case_dir):
    findings = [
        {
            "id": "F-tester-001",
            "status": "APPROVED",
            "title": "Lateral movement via PsExec",
            "confidence": "HIGH",
            "audit_ids": ["ev-001", "ev-002"],
            "observation": "PsExec executed from 192.168.1.50 to target host",
            "interpretation": "Attacker moved laterally",
            "iocs": {
                "IPv4": ["192.168.1.50", "10.0.0.15"],
                "Domain": ["evil.example.com"],
                "File": ["C:\\Windows\\Temp\\payload.exe"],
            },
            "examiner": "tester",
        },
        {
            "id": "F-tester-002",
            "status": "DRAFT",
            "title": "Suspicious scheduled task",
            "confidence": "MEDIUM",
            "audit_ids": ["ev-003"],
            "observation": "Observed connection to 172.16.0.99",
            "interpretation": "Possible persistence",
            "iocs": {"IPv4": ["172.16.0.99"]},
            "examiner": "tester",
        },
        {
            "id": "F-tester-003",
            "status": "REJECTED",
            "title": "Potential data staging",
            "confidence": "LOW",
            "audit_ids": [],
            "observation": "Files found in temp directory",
            "interpretation": "Benign activity",
            "rejected_at": "2026-02-19T12:00:00Z",
            "rejection_reason": "False positive",
            "examiner": "tester",
        },
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def sample_timeline(case_dir):
    events = [
        {
            "id": "T-tester-001",
            "status": "APPROVED",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "Initial access via phishing email",
            "audit_ids": ["ev-001"],
        },
        {
            "id": "T-tester-002",
            "status": "DRAFT",
            "timestamp": "2026-02-19T11:00:00Z",
            "description": "Lateral movement detected",
        },
        {
            "id": "T-tester-003",
            "status": "APPROVED",
            "timestamp": "2026-02-20T09:00:00Z",
            "description": "Data exfiltration attempt",
        },
    ]
    save_timeline(case_dir, events)
    return events


@pytest.fixture
def sample_todos(case_dir):
    todos = [
        {
            "todo_id": "TODO-001",
            "status": "open",
            "description": "Check logs",
            "priority": "high",
        },
        {
            "todo_id": "TODO-002",
            "status": "completed",
            "description": "Review registry",
            "priority": "medium",
        },
    ]
    save_todos(case_dir, todos)
    return todos


def _make_args(**kwargs):
    """Build Namespace with report defaults."""
    defaults = {
        "case": None,
        "full": False,
        "executive_summary": False,
        "report_timeline": False,
        "from_date": None,
        "to_date": None,
        "ioc": False,
        "report_findings": None,
        "status_brief": False,
        "save": None,
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


class TestReportFull:
    def test_full_report_outputs_json(
        self, case_dir, sample_findings, sample_timeline, identity, capsys
    ):
        cmd_report(_make_args(full=True), identity)
        output = capsys.readouterr().out
        data = json.loads(output.strip())
        assert data["report_type"] == "full"
        assert data["case"]["case_id"] == "INC-2026-TEST"
        assert data["summary"]["total_findings"] == 3
        assert data["summary"]["approved_findings"] == 1
        assert len(data["approved_findings"]) == 1
        assert data["approved_findings"][0]["id"] == "F-tester-001"

    def test_full_report_includes_iocs(
        self, case_dir, sample_findings, identity, capsys
    ):
        cmd_report(_make_args(full=True), identity)
        output = capsys.readouterr().out
        data = json.loads(output.strip())
        assert "IPv4" in data["iocs"]
        assert "192.168.1.50" in data["iocs"]["IPv4"]

    def test_full_report_empty_case(self, case_dir, identity, capsys):
        cmd_report(_make_args(full=True), identity)
        output = capsys.readouterr().out
        data = json.loads(output.strip())
        assert data["summary"]["total_findings"] == 0
        assert data["approved_findings"] == []

    def test_full_report_save(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(full=True, save="full-report.json"), identity)
        saved = case_dir / "reports" / "full-report.json"
        assert saved.exists()
        data = json.loads(saved.read_text())
        assert data["report_type"] == "full"


class TestReportExecutiveSummary:
    def test_executive_summary_shows_counts(
        self, case_dir, sample_findings, sample_timeline, sample_todos, identity, capsys
    ):
        cmd_report(_make_args(executive_summary=True), identity)
        output = capsys.readouterr().out
        assert "EXECUTIVE SUMMARY" in output
        assert "Total: 3" in output  # findings
        assert "APPROVED: 1" in output
        assert "DRAFT: 1" in output
        assert "Open TODOs: 1" in output

    def test_executive_summary_ioc_count(
        self, case_dir, sample_findings, identity, capsys
    ):
        cmd_report(_make_args(executive_summary=True), identity)
        output = capsys.readouterr().out
        assert "IOCs" in output

    def test_executive_summary_empty(self, case_dir, identity, capsys):
        cmd_report(_make_args(executive_summary=True), identity)
        output = capsys.readouterr().out
        assert "Total: 0" in output


class TestReportTimeline:
    def test_timeline_report(self, case_dir, sample_timeline, identity, capsys):
        cmd_report(_make_args(report_timeline=True), identity)
        output = capsys.readouterr().out
        assert "T-tester-001" in output
        assert "T-tester-002" in output
        assert "Total: 3 events" in output

    def test_timeline_filter_from(self, case_dir, sample_timeline, identity, capsys):
        cmd_report(
            _make_args(report_timeline=True, from_date="2026-02-19T10:30:00Z"), identity
        )
        output = capsys.readouterr().out
        assert "T-tester-001" not in output
        assert "T-tester-002" in output

    def test_timeline_filter_to(self, case_dir, sample_timeline, identity, capsys):
        cmd_report(
            _make_args(report_timeline=True, to_date="2026-02-19T10:30:00Z"), identity
        )
        output = capsys.readouterr().out
        assert "T-tester-001" in output
        assert "T-tester-003" not in output

    def test_timeline_filter_range(self, case_dir, sample_timeline, identity, capsys):
        cmd_report(
            _make_args(
                report_timeline=True,
                from_date="2026-02-19T10:30:00Z",
                to_date="2026-02-19T12:00:00Z",
            ),
            identity,
        )
        output = capsys.readouterr().out
        assert "T-tester-002" in output
        assert "T-tester-001" not in output
        assert "T-tester-003" not in output

    def test_timeline_empty(self, case_dir, identity, capsys):
        cmd_report(_make_args(report_timeline=True), identity)
        output = capsys.readouterr().out
        assert "No timeline events" in output

    def test_timeline_save(self, case_dir, sample_timeline, identity, capsys):
        cmd_report(_make_args(report_timeline=True, save="timeline.txt"), identity)
        saved = case_dir / "reports" / "timeline.txt"
        assert saved.exists()
        assert "T-tester-001" in saved.read_text()


class TestReportIOC:
    def test_ioc_report_approved_only(
        self, case_dir, sample_findings, identity, capsys
    ):
        cmd_report(_make_args(ioc=True), identity)
        output = capsys.readouterr().out
        assert "IOC REPORT" in output
        assert "192.168.1.50" in output
        assert "evil.example.com" in output
        # Draft IOC should NOT appear (only approved)
        assert "172.16.0.99" not in output

    def test_ioc_report_no_approved(self, case_dir, identity, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-010",
                    "status": "DRAFT",
                    "title": "Test",
                    "observation": "",
                    "interpretation": "",
                },
            ],
        )
        cmd_report(_make_args(ioc=True), identity)
        output = capsys.readouterr().out
        assert "No IOCs" in output or "No approved" in output

    def test_ioc_report_save(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(ioc=True, save="iocs.txt"), identity)
        saved = case_dir / "reports" / "iocs.txt"
        assert saved.exists()


class TestReportFindings:
    def test_specific_finding(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(report_findings="F-tester-001"), identity)
        output = capsys.readouterr().out
        assert "F-tester-001" in output
        assert "Lateral movement via PsExec" in output
        assert "Observation:" in output

    def test_multiple_findings(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(report_findings="F-tester-001,F-tester-002"), identity)
        output = capsys.readouterr().out
        assert "F-tester-001" in output
        assert "F-tester-002" in output

    def test_missing_finding(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(report_findings="F-tester-001,F-tester-999"), identity)
        captured = capsys.readouterr()
        assert "F-tester-001" in captured.out
        assert "F-tester-999" in captured.err  # missing ID warning

    def test_all_missing_findings(self, case_dir, sample_findings, identity):
        with pytest.raises(SystemExit):
            cmd_report(_make_args(report_findings="F-tester-999"), identity)

    def test_rejected_finding_shows_reason(
        self, case_dir, sample_findings, identity, capsys
    ):
        cmd_report(_make_args(report_findings="F-tester-003"), identity)
        output = capsys.readouterr().out
        assert "Rejected:" in output
        assert "False positive" in output

    def test_findings_save(self, case_dir, sample_findings, identity, capsys):
        cmd_report(
            _make_args(report_findings="F-tester-001", save="finding-detail.txt"),
            identity,
        )
        saved = case_dir / "reports" / "finding-detail.txt"
        assert saved.exists()


class TestReportStatusBrief:
    def test_status_brief(
        self, case_dir, sample_findings, sample_timeline, sample_todos, identity, capsys
    ):
        cmd_report(_make_args(status_brief=True), identity)
        output = capsys.readouterr().out
        assert "INC-2026-TEST" in output
        assert "Findings: 3" in output
        assert "Timeline: 3" in output
        assert "Open TODOs: 1" in output

    def test_status_brief_empty(self, case_dir, identity, capsys):
        cmd_report(_make_args(status_brief=True), identity)
        output = capsys.readouterr().out
        assert "Findings: 0" in output
        assert "Timeline: 0" in output

    def test_status_brief_save(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(status_brief=True, save="status.txt"), identity)
        saved = case_dir / "reports" / "status.txt"
        assert saved.exists()


class TestReportNoFlag:
    def test_no_report_type_exits(self, case_dir, identity):
        with pytest.raises(SystemExit):
            cmd_report(_make_args(), identity)


class TestReportSavePathSecurity:
    def test_save_absolute_path_outside_case_rejected(
        self, case_dir, sample_findings, identity, tmp_path
    ):
        abs_path = str(tmp_path / "absolute-report.json")
        with pytest.raises(SystemExit):
            cmd_report(_make_args(full=True, save=abs_path), identity)
        assert not Path(abs_path).exists()

    def test_save_path_traversal_rejected(self, case_dir, sample_findings, identity):
        with pytest.raises(SystemExit):
            cmd_report(_make_args(full=True, save="../../../etc/evil"), identity)

    def test_save_within_case_works(self, case_dir, sample_findings, identity, capsys):
        cmd_report(_make_args(full=True, save="my-report.json"), identity)
        saved = case_dir / "reports" / "my-report.json"
        assert saved.exists()
        data = json.loads(saved.read_text())
        assert data["report_type"] == "full"
