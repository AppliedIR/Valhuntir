"""Tests for audit CLI commands."""

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.audit_cmd import cmd_audit


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory with audit data."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()
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
def sample_audit(case_dir):
    """Write sample audit entries across multiple JSONL files."""
    sift_entries = [
        {
            "ts": "2026-02-19T10:00:00Z",
            "mcp": "sift-mcp",
            "tool": "run_tool",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-001",
        },
        {
            "ts": "2026-02-19T10:05:00Z",
            "mcp": "sift-mcp",
            "tool": "get_tool_help",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-002",
        },
        {
            "ts": "2026-02-19T10:10:00Z",
            "mcp": "sift-mcp",
            "tool": "run_tool",
            "examiner": "tester",
            "audit_id": "sift-tester-20260219-003",
        },
    ]
    with open(case_dir / "audit" / "sift-mcp.jsonl", "w") as f:
        for entry in sift_entries:
            f.write(json.dumps(entry) + "\n")

    forensic_entries = [
        {
            "ts": "2026-02-19T10:01:00Z",
            "mcp": "forensic-mcp",
            "tool": "record_finding",
            "examiner": "tester",
            "audit_id": "forensic-tester-20260219-001",
        },
        {
            "ts": "2026-02-19T10:06:00Z",
            "mcp": "forensic-mcp",
            "tool": "record_timeline_event",
            "examiner": "tester",
            "audit_id": "forensic-tester-20260219-002",
        },
    ]
    with open(case_dir / "audit" / "forensic-mcp.jsonl", "w") as f:
        for entry in forensic_entries:
            f.write(json.dumps(entry) + "\n")

    return sift_entries + forensic_entries


@pytest.fixture
def sample_approvals(case_dir):
    """Write sample approval entries."""
    approvals = [
        {
            "ts": "2026-02-19T11:00:00Z",
            "item_id": "F-tester-001",
            "action": "APPROVED",
            "os_user": "testuser",
            "examiner": "tester",
        },
        {
            "ts": "2026-02-19T11:05:00Z",
            "item_id": "T-tester-001",
            "action": "APPROVED",
            "os_user": "testuser",
            "examiner": "tester",
        },
    ]
    with open(case_dir / "approvals.jsonl", "w") as f:
        for entry in approvals:
            f.write(json.dumps(entry) + "\n")
    return approvals


def _make_args(audit_action=None, **kwargs):
    defaults = {"case": None, "audit_action": audit_action}
    defaults.update(kwargs)
    return Namespace(**defaults)


class TestAuditLog:
    def test_log_shows_entries(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("log", limit=50), identity)
        output = capsys.readouterr().out
        assert "sift-mcp" in output
        assert "forensic-mcp" in output
        assert "run_tool" in output

    def test_log_sorted_by_timestamp(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("log", limit=50), identity)
        output = capsys.readouterr().out
        lines = [line for line in output.strip().split("\n") if "2026-02-19" in line]
        timestamps = [line.split()[0] for line in lines]
        assert timestamps == sorted(timestamps)

    def test_log_includes_approvals(
        self, case_dir, sample_audit, sample_approvals, identity, capsys
    ):
        cmd_audit(_make_args("log", limit=50), identity)
        output = capsys.readouterr().out
        assert "vhir-cli" in output
        assert "approval" in output

    def test_log_filter_by_mcp(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("log", limit=50, mcp="sift-mcp"), identity)
        output = capsys.readouterr().out
        assert "sift-mcp" in output
        assert "forensic-mcp" not in output

    def test_log_filter_by_tool(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("log", limit=50, tool="run_tool"), identity)
        output = capsys.readouterr().out
        assert "run_tool" in output
        assert "get_tool_help" not in output
        assert "record_finding" not in output

    def test_log_limit(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("log", limit=2), identity)
        output = capsys.readouterr().out
        # Should show "Showing 2 entries"
        assert "2 entries" in output

    def test_log_empty(self, case_dir, identity, capsys):
        cmd_audit(_make_args("log", limit=50), identity)
        output = capsys.readouterr().out
        assert "No audit entries" in output

    def test_log_mcp_derived_from_filename(self, case_dir, identity, capsys):
        """When entry has no mcp field, derive from filename."""
        entry = {
            "ts": "2026-02-19T10:00:00Z",
            "tool": "some_tool",
            "examiner": "tester",
        }
        with open(case_dir / "audit" / "wintools.jsonl", "w") as f:
            f.write(json.dumps(entry) + "\n")
        cmd_audit(_make_args("log", limit=50), identity)
        output = capsys.readouterr().out
        assert "wintools" in output

    def test_log_combined_filter(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(
            _make_args("log", limit=50, mcp="sift-mcp", tool="run_tool"), identity
        )
        output = capsys.readouterr().out
        data_lines = [
            line for line in output.strip().split("\n") if "2026-02-19" in line
        ]
        assert len(data_lines) == 2  # Two run_tool entries in sift-mcp


class TestAuditSummary:
    def test_summary_shows_counts(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert "AUDIT SUMMARY" in output
        assert "Total entries: 5" in output
        assert "sift-mcp" in output
        assert "forensic-mcp" in output

    def test_summary_includes_audit_ids(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert "Audit IDs:     5" in output

    def test_summary_with_approvals(
        self, case_dir, sample_audit, sample_approvals, identity, capsys
    ):
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert "Total entries: 7" in output
        assert "vhir-cli" in output

    def test_summary_by_tool(self, case_dir, sample_audit, identity, capsys):
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert "run_tool" in output
        assert "record_finding" in output

    def test_summary_empty(self, case_dir, identity, capsys):
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert "No audit entries" in output


class TestAuditNoAction:
    def test_no_action_exits(self, case_dir, identity):
        with pytest.raises(SystemExit):
            cmd_audit(_make_args(), identity)
