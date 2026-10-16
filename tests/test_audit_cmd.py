"""Tests for audit CLI commands."""

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.audit_cmd import _load_audit_entries, cmd_audit


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


# A page is served from each file's tail, so these fixtures are deliberately
# longer than that tail window.
LONG = 6000


def _seq_ts(i: int) -> str:
    return (
        f"2026-03-{1 + i // 86400:02d}"
        f"T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z"
    )


def _write_trail(path, count, mcp="sift-mcp", step=1, first=0, tool="run_tool"):
    """Write `count` entries with strictly increasing timestamps."""
    with open(path, "w") as f:
        for n in range(count):
            f.write(
                json.dumps(
                    {
                        "ts": _seq_ts(first + n * step),
                        "mcp": mcp,
                        "tool": tool,
                        "examiner": "tester",
                        "audit_id": f"{mcp}-{n:06d}",
                    }
                )
                + "\n"
            )


class TestAuditLogLongTrail:
    def test_log_shows_newest_of_a_long_file(self, case_dir, identity, capsys):
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG)
        cmd_audit(_make_args("log", limit=5), identity)
        output = capsys.readouterr().out
        assert "Showing 5 entries" in output
        for n in range(LONG - 5, LONG):
            assert f"sift-mcp-{n:06d}" in output
        assert "sift-mcp-000010" not in output

    def test_log_merges_tails_across_files(self, case_dir, identity, capsys):
        # Two long files whose timestamps interleave.
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG, "sift-mcp", 2, 0)
        _write_trail(
            case_dir / "audit" / "forensic-mcp.jsonl", LONG, "forensic-mcp", 2, 1
        )
        cmd_audit(_make_args("log", limit=4), identity)
        output = capsys.readouterr().out
        assert f"sift-mcp-{LONG - 1:06d}" in output
        assert f"sift-mcp-{LONG - 2:06d}" in output
        assert f"forensic-mcp-{LONG - 1:06d}" in output
        assert f"forensic-mcp-{LONG - 2:06d}" in output

    def test_log_matches_full_scan_on_a_long_trail(self, case_dir, identity):
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG, "sift-mcp", 2, 0)
        _write_trail(
            case_dir / "audit" / "forensic-mcp.jsonl", LONG, "forensic-mcp", 2, 1
        )
        with open(case_dir / "approvals.jsonl", "w") as f:
            for n in range(20):
                f.write(
                    json.dumps(
                        {
                            "ts": _seq_ts(n * 3),
                            "item_id": f"F-tester-{n:03d}",
                            "action": "APPROVED",
                            "examiner": "tester",
                        }
                    )
                    + "\n"
                )
        paged = _load_audit_entries(case_dir, 50)[-50:]
        full = _load_audit_entries(case_dir)[-50:]
        assert paged == full

    def test_log_rereads_file_when_tail_is_out_of_order(
        self, case_dir, identity, capsys
    ):
        """A clock step inside the tail forces a full read of that file."""
        entries = [
            {
                "ts": _seq_ts(n),
                "mcp": "wintools-mcp",
                "tool": "run_tool",
                "examiner": "tester",
                "audit_id": f"wintools-mcp-{n:06d}",
            }
            for n in range(LONG)
        ]
        # A clock that jumped forward early in the file, then corrected.
        entries[100]["ts"] = "2027-01-01T00:00:00Z"
        # A later backward step, inside the tail, marks the file as unordered.
        entries[LONG - 500]["ts"] = _seq_ts(0)
        with open(case_dir / "audit" / "wintools-mcp.jsonl", "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        cmd_audit(_make_args("log", limit=3), identity)
        output = capsys.readouterr().out
        assert "wintools-mcp-000100" in output

    def test_log_filter_reaches_past_the_tail(self, case_dir, identity, capsys):
        """--tool entries older than the tail window are still found."""
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG)
        with open(case_dir / "audit" / "sift-mcp.jsonl") as f:
            lines = f.readlines()
        rare = json.loads(lines[10])
        rare["tool"] = "carve_files"
        rare["audit_id"] = "sift-mcp-rare"
        lines[10] = json.dumps(rare) + "\n"
        with open(case_dir / "audit" / "sift-mcp.jsonl", "w") as f:
            f.writelines(lines)

        cmd_audit(_make_args("log", limit=5, tool="carve_files"), identity)
        output = capsys.readouterr().out
        assert "sift-mcp-rare" in output
        assert "Showing 1 entries" in output

    def test_log_filter_by_mcp_on_a_long_trail(self, case_dir, identity, capsys):
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG, "sift-mcp", 2, 0)
        _write_trail(
            case_dir / "audit" / "forensic-mcp.jsonl", LONG, "forensic-mcp", 2, 1
        )
        cmd_audit(_make_args("log", limit=3, mcp="forensic-mcp"), identity)
        output = capsys.readouterr().out
        assert "sift-mcp" not in output
        assert f"forensic-mcp-{LONG - 1:06d}" in output
        assert "Showing 3 entries" in output

    def test_log_includes_newest_approvals_from_a_long_trail(
        self, case_dir, identity, capsys
    ):
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG)
        with open(case_dir / "approvals.jsonl", "w") as f:
            f.write(
                json.dumps(
                    {
                        "ts": "2027-01-01T00:00:00Z",
                        "item_id": "F-tester-001",
                        "action": "APPROVED",
                        "examiner": "tester",
                    }
                )
                + "\n"
            )
        cmd_audit(_make_args("log", limit=2), identity)
        output = capsys.readouterr().out
        assert "approval" in output
        assert "vhir-cli" in output

    def test_summary_still_counts_every_line(self, case_dir, identity, capsys):
        _write_trail(case_dir / "audit" / "sift-mcp.jsonl", LONG)
        cmd_audit(_make_args("summary"), identity)
        output = capsys.readouterr().out
        assert f"Total entries: {LONG}" in output
