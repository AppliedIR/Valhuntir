"""Tests for provenance display and cross-file verification in vhir CLI."""

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import (
    compute_content_hash,
    load_audit_index,
    load_findings,
    save_findings,
    verify_approval_integrity,
    write_approval_log,
)
from vhir_cli.commands.review import cmd_review


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    case_id = "INC-2026-PROV"
    case_path = tmp_path / case_id
    case_path.mkdir()
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    meta = {
        "case_id": case_id,
        "name": "Provenance Test",
        "status": "open",
        "created": "2026-02-25",
        "examiner": "tester",
    }
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)
    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "tester",
        "examiner_source": "env",
    }


def _review_args(**kwargs):
    defaults = dict(
        case=None,
        findings=False,
        detail=False,
        verify=False,
        iocs=False,
        timeline=False,
        audit=False,
        evidence=False,
        limit=50,
        todos=False,
        open=False,
    )
    defaults.update(kwargs)
    return Namespace(**defaults)


# --- Summary view columns ---


class TestSummaryColumns:
    def test_summary_shows_provenance(self, case_dir, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test finding",
                    "confidence": "HIGH",
                    "provenance": "MCP",
                }
            ],
        )
        cmd_review(_review_args(findings=True), {})
        output = capsys.readouterr().out
        assert "Title" in output
        assert "Confidence" in output
        assert "Provenance" in output
        assert "Status" in output
        assert "MCP" in output

    def test_summary_missing_provenance(self, case_dir, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Old finding",
                    "confidence": "MEDIUM",
                }
            ],
        )
        cmd_review(_review_args(findings=True), {})
        output = capsys.readouterr().out
        assert "\u2014" in output  # em dash for missing provenance


# --- Detail view evidence chain ---


class TestDetailEvidenceChain:
    def test_mcp_evidence(self, case_dir, capsys):
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps(
                {
                    "audit_id": "sift-tester-20260225-001",
                    "tool": "run_command",
                    "params": {"command": "fls -r /dev/sda1"},
                    "ts": "2026-02-25T10:00:00Z",
                }
            )
            + "\n"
        )
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "confidence": "HIGH",
                    "audit_ids": ["sift-tester-20260225-001"],
                    "observation": "obs",
                    "provenance": "MCP",
                }
            ],
        )
        cmd_review(_review_args(findings=True, detail=True), {})
        output = capsys.readouterr().out
        assert "[MCP]" in output
        assert "sift-tester-20260225-001" in output

    def test_hook_evidence(self, case_dir, capsys):
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "claude-code.jsonl").write_text(
            json.dumps(
                {
                    "audit_id": "hook-tester-20260225-001",
                    "command": "grep -r malware /var/log",
                    "ts": "2026-02-25T10:00:00Z",
                }
            )
            + "\n"
        )
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "confidence": "HIGH",
                    "audit_ids": ["hook-tester-20260225-001"],
                    "observation": "obs",
                    "provenance": "HOOK",
                }
            ],
        )
        cmd_review(_review_args(findings=True, detail=True), {})
        output = capsys.readouterr().out
        assert "[HOOK]" in output
        assert "hook-tester-20260225-001" in output

    def test_shell_evidence(self, case_dir, capsys):
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "forensic-mcp.jsonl").write_text(
            json.dumps(
                {
                    "audit_id": "shell-tester-20260225-001",
                    "tool": "supporting_command",
                    "params": {"command": "strings evil.exe"},
                    "ts": "2026-02-25T10:00:00Z",
                }
            )
            + "\n"
        )
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "confidence": "HIGH",
                    "audit_ids": ["shell-tester-20260225-001"],
                    "observation": "obs",
                    "provenance": "SHELL",
                }
            ],
        )
        cmd_review(_review_args(findings=True, detail=True), {})
        output = capsys.readouterr().out
        assert "[SHELL]" in output

    def test_none_evidence(self, case_dir, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "confidence": "HIGH",
                    "audit_ids": ["unknown-001"],
                    "observation": "obs",
                    "provenance": "NONE",
                }
            ],
        )
        cmd_review(_review_args(findings=True, detail=True), {})
        output = capsys.readouterr().out
        assert "[NONE]" in output
        assert "no audit record" in output

    def test_supporting_commands_display(self, case_dir, capsys):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "confidence": "HIGH",
                    "audit_ids": ["shell-tester-20260225-001"],
                    "observation": "obs",
                    "provenance": "SHELL",
                    "supporting_commands": [
                        {
                            "command": "vol.py pslist",
                            "purpose": "List processes",
                            "output_excerpt": "PID 1234 evil.exe",
                        }
                    ],
                }
            ],
        )
        cmd_review(_review_args(findings=True, detail=True), {})
        output = capsys.readouterr().out
        assert "Supporting Commands" in output
        assert "vol.py pslist" in output
        assert "List processes" in output


# --- Cross-file content hash ---


class TestCrossFileHash:
    def test_content_hash_in_approval_log(self, case_dir, identity):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "title": "Test",
                    "observation": "obs",
                    "status": "DRAFT",
                }
            ],
        )
        findings = load_findings(case_dir)
        content_hash = compute_content_hash(findings[0])
        write_approval_log(
            case_dir,
            "F-tester-001",
            "APPROVED",
            identity,
            content_hash=content_hash,
        )
        log_file = case_dir / "approvals.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["content_hash"] == content_hash

    def test_cross_file_confirmed(self, case_dir, identity):
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "title": "Test",
                    "observation": "obs",
                    "status": "DRAFT",
                }
            ],
        )
        findings = load_findings(case_dir)
        content_hash = compute_content_hash(findings[0])
        findings[0]["content_hash"] = content_hash
        findings[0]["status"] = "APPROVED"
        save_findings(case_dir, findings)
        write_approval_log(
            case_dir,
            "F-tester-001",
            "APPROVED",
            identity,
            content_hash=content_hash,
        )
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "confirmed"

    def test_cross_file_tampered(self, case_dir, identity):
        """Modify findings.json after approval -> tampered."""
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "title": "Test",
                    "observation": "original",
                    "status": "DRAFT",
                }
            ],
        )
        findings = load_findings(case_dir)
        content_hash = compute_content_hash(findings[0])
        findings[0]["content_hash"] = content_hash
        findings[0]["status"] = "APPROVED"
        save_findings(case_dir, findings)
        write_approval_log(
            case_dir,
            "F-tester-001",
            "APPROVED",
            identity,
            content_hash=content_hash,
        )
        # Tamper
        findings = load_findings(case_dir)
        findings[0]["observation"] = "tampered"
        save_findings(case_dir, findings)
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "tampered"

    def test_approval_hash_mismatch_detected(self, case_dir, identity):
        """Approval log hash different from recomputed -> tampered."""
        save_findings(
            case_dir,
            [
                {
                    "id": "F-tester-001",
                    "title": "Test",
                    "observation": "obs",
                    "status": "APPROVED",
                }
            ],
        )
        # Write approval log with a wrong hash
        write_approval_log(
            case_dir,
            "F-tester-001",
            "APPROVED",
            identity,
            content_hash="badhash",
        )
        results = verify_approval_integrity(case_dir)
        assert results[0]["verification"] == "tampered"


# --- load_audit_index ---


class TestLoadAuditIndex:
    def test_basic(self, case_dir):
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "sift-mcp.jsonl").write_text(
            json.dumps({"audit_id": "sift-001", "tool": "run_command"})
            + "\n"
            + json.dumps({"audit_id": "sift-002", "tool": "list_tools"})
            + "\n"
        )
        (audit_dir / "forensic-mcp.jsonl").write_text(
            json.dumps({"audit_id": "fmcp-001", "tool": "record_finding"}) + "\n"
        )
        index = load_audit_index(case_dir)
        assert "sift-001" in index
        assert "sift-002" in index
        assert "fmcp-001" in index
        assert index["sift-001"]["_source_file"] == "sift-mcp.jsonl"

    def test_corrupt_lines_skipped(self, case_dir):
        audit_dir = case_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        (audit_dir / "test.jsonl").write_text(
            "NOT JSON\n"
            + json.dumps({"audit_id": "ok-001", "tool": "test"})
            + "\n"
            + "ALSO BAD\n"
        )
        index = load_audit_index(case_dir)
        assert "ok-001" in index
        assert len(index) == 1

    def test_empty_audit_dir(self, case_dir):
        index = load_audit_index(case_dir)
        assert index == {}


# --- Provenance in _HASH_EXCLUDE_KEYS ---


class TestProvenanceExcluded:
    def test_provenance_excluded_from_hash(self):
        base = {"id": "F-001", "title": "Test"}
        with_prov = {**base, "provenance": "MCP"}
        assert compute_content_hash(base) == compute_content_hash(with_prov)
