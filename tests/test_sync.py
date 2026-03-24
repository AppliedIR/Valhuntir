"""Tests for vhir export/merge commands."""

import argparse
import json
from pathlib import Path

import pytest

from vhir_cli.commands.sync import cmd_export, cmd_merge


def _init_case(case_dir: Path, examiner: str = "alice") -> None:
    """Set up a minimal flat case directory for testing."""
    meta = {"case_id": "INC-2026-0001", "name": "Test Case"}
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(json.dumps(meta))
    (case_dir / "audit").mkdir(exist_ok=True)
    (case_dir / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": f"F-{examiner}-001",
                    "title": "Malware found",
                    "status": "DRAFT",
                    "staged": "2026-01-01T00:00:00Z",
                },
            ]
        )
    )
    (case_dir / "timeline.json").write_text(
        json.dumps(
            [
                {
                    "id": f"T-{examiner}-001",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "description": "First event",
                    "staged": "2026-01-01T00:00:00Z",
                },
            ]
        )
    )
    (case_dir / "todos.json").write_text(json.dumps([]))


def _make_export_args(**kwargs):
    defaults = {"case": None, "file": "", "since": ""}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_merge_args(**kwargs):
    defaults = {"case": None, "file": ""}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestExport:
    def test_export_writes_bundle(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        output = tmp_path / "bundle.json"
        args = _make_export_args(file=str(output))
        cmd_export(args, {"examiner": "alice"})

        assert output.is_file()
        bundle = json.loads(output.read_text())
        assert bundle["examiner"] == "alice"
        assert bundle["case_id"] == "INC-2026-0001"
        assert len(bundle["findings"]) == 1
        assert bundle["findings"][0]["id"] == "F-alice-001"

    def test_export_no_file_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        args = _make_export_args(file="")
        with pytest.raises(SystemExit):
            cmd_export(args, {"examiner": "alice"})

    def test_export_since_filter(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        # Add a newer finding
        findings = json.loads((case_dir / "findings.json").read_text())
        findings.append(
            {
                "id": "F-alice-002",
                "title": "New",
                "status": "DRAFT",
                "staged": "2026-06-01T00:00:00Z",
            }
        )
        (case_dir / "findings.json").write_text(json.dumps(findings))

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        output = tmp_path / "bundle.json"
        args = _make_export_args(file=str(output), since="2026-03-01T00:00:00Z")
        cmd_export(args, {"examiner": "alice"})

        bundle = json.loads(output.read_text())
        assert len(bundle["findings"]) == 1
        assert bundle["findings"][0]["id"] == "F-alice-002"


class TestMerge:
    def test_merge_reads_bundle(self, tmp_path, monkeypatch, capsys):
        case_dir = tmp_path / "case"
        _init_case(case_dir, examiner="alice")
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        bundle = {
            "case_id": "INC-2026-0001",
            "examiner": "bob",
            "findings": [
                {
                    "id": "F-bob-001",
                    "title": "Bob's finding",
                    "status": "DRAFT",
                    "staged": "2026-01-01T00:00:00Z",
                }
            ],
            "timeline": [],
        }
        bundle_file = tmp_path / "bob-bundle.json"
        bundle_file.write_text(json.dumps(bundle))

        args = _make_merge_args(file=str(bundle_file))
        cmd_merge(args, {"examiner": "alice"})

        # Check merged data at case root
        merged = json.loads((case_dir / "findings.json").read_text())
        ids = [f["id"] for f in merged]
        assert "F-alice-001" in ids
        assert "F-bob-001" in ids

    def test_merge_missing_file_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        args = _make_merge_args(file=str(tmp_path / "nonexistent.json"))
        with pytest.raises(SystemExit):
            cmd_merge(args, {"examiner": "alice"})

    def test_merge_no_file_flag_exits(self, tmp_path, monkeypatch):
        case_dir = tmp_path / "case"
        _init_case(case_dir)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        args = _make_merge_args(file="")
        with pytest.raises(SystemExit):
            cmd_merge(args, {"examiner": "alice"})

    def test_merge_last_write_wins(self, tmp_path, monkeypatch, capsys):
        case_dir = tmp_path / "case"
        _init_case(case_dir, examiner="alice")
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")

        # Import a bundle with a newer version of alice's finding
        bundle = {
            "findings": [
                {
                    "id": "F-alice-001",
                    "title": "Updated by Bob",
                    "status": "DRAFT",
                    "staged": "2026-06-01T00:00:00Z",
                }
            ],
            "timeline": [],
        }
        bundle_file = tmp_path / "updated.json"
        bundle_file.write_text(json.dumps(bundle))

        args = _make_merge_args(file=str(bundle_file))
        cmd_merge(args, {"examiner": "alice"})

        output = capsys.readouterr().out
        assert "updated" in output.lower() or "1 updated" in output

        merged = json.loads((case_dir / "findings.json").read_text())
        f001 = next(f for f in merged if f["id"] == "F-alice-001")
        assert f001["title"] == "Updated by Bob"
