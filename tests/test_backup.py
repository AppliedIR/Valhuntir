"""Tests for `vhir backup` case-directory scanning."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from vhir_cli.commands.backup import create_backup_data, scan_case_dir


def _seed_case(tmp_path: Path) -> Path:
    """Build a case dir with a little case data and a lot of evidence."""
    case_dir = tmp_path / "INC-TEST"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-TEST"}))
    (case_dir / "findings.json").write_text("[]")

    audit_dir = case_dir / "audit"
    audit_dir.mkdir()
    (audit_dir / "audit.jsonl").write_text("{}\n")

    for name in ("evidence", "extractions"):
        sub = case_dir / name / "host-01"
        sub.mkdir(parents=True)
        for i in range(3):
            (sub / f"artifact-{i}.bin").write_bytes(b"x" * 16)

    return case_dir


def _recording_walk(recorded: list[str]):
    """Wrap os.walk, recording each visited root.

    Yields the caller's own `dirs` list object so in-place pruning still works.
    """
    real_walk = os.walk

    def walker(top, *args, **kwargs):
        for root, dirs, files in real_walk(top, *args, **kwargs):
            recorded.append(root)
            yield root, dirs, files

    return walker


class TestScanCaseDir:
    def test_default_scan_includes_everything(self, tmp_path):
        """No flags: the prompt/--all path still prices evidence and extractions."""
        case_dir = _seed_case(tmp_path)
        scan = scan_case_dir(case_dir)

        assert len(scan["evidence"]) == 3
        assert len(scan["extractions"]) == 3
        assert any(rel == "CASE.yaml" for rel, _, _ in scan["case_data"])

    def test_excluded_categories_return_empty_lists(self, tmp_path):
        case_dir = _seed_case(tmp_path)
        scan = scan_case_dir(
            case_dir, include_evidence=False, include_extractions=False
        )

        assert scan["evidence"] == []
        assert scan["extractions"] == []
        assert any(rel == "CASE.yaml" for rel, _, _ in scan["case_data"])
        assert any(rel == "audit/audit.jsonl" for rel, _, _ in scan["case_data"])

    def test_nested_evidence_dir_is_still_case_data(self, tmp_path):
        """Only the top-level evidence/ is excluded — `foo/evidence/` is case data."""
        case_dir = _seed_case(tmp_path)
        nested = case_dir / "reports" / "evidence"
        nested.mkdir(parents=True)
        (nested / "chart.png").write_bytes(b"png")

        scan = scan_case_dir(
            case_dir, include_evidence=False, include_extractions=False
        )

        assert any(
            rel == "reports/evidence/chart.png" for rel, _, _ in scan["case_data"]
        )

    def test_symlinked_evidence_dir_is_excluded(self, tmp_path):
        """`case/evidence/` symlinked to an external mount is the documented layout."""
        case_dir = tmp_path / "INC-LINK"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-LINK"}))
        external = tmp_path / "forensic-store"
        external.mkdir()
        (external / "disk.vhdx").write_bytes(b"x" * 32)
        (case_dir / "evidence").symlink_to(external)

        scan = scan_case_dir(case_dir, include_evidence=False)

        assert scan["evidence"] == []
        assert not any("disk.vhdx" in rel for rel, _, _ in scan["case_data"])


class TestCreateBackupData:
    def test_default_backup_does_not_descend_into_evidence(self, tmp_path):
        """Excluded subtrees must never be walked, not merely discarded."""
        case_dir = _seed_case(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()

        recorded: list[str] = []
        real_walk = os.walk
        os.walk = _recording_walk(recorded)
        try:
            result = create_backup_data(
                case_dir=case_dir, destination=str(dest), examiner="alice"
            )
        finally:
            os.walk = real_walk

        walked = [r for r in recorded if r.startswith(str(case_dir))]
        assert walked == [str(case_dir), str(case_dir / "audit")]
        assert result["file_count"] > 0

    def test_included_evidence_is_copied(self, tmp_path):
        case_dir = _seed_case(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()

        result = create_backup_data(
            case_dir=case_dir,
            destination=str(dest),
            examiner="alice",
            include_evidence=True,
        )

        backup_dir = Path(result["backup_path"])
        assert (backup_dir / "evidence" / "host-01" / "artifact-0.bin").is_file()
        assert not (backup_dir / "extractions").exists()

    def test_symlinks_inside_excluded_evidence_are_not_reported(self, tmp_path):
        """Nothing is copied for them, so no 'Following symlink' line is due."""
        case_dir = _seed_case(tmp_path)
        target = tmp_path / "external.bin"
        target.write_bytes(b"y" * 64)
        (case_dir / "evidence" / "host-01" / "linked.bin").symlink_to(target)
        dest = tmp_path / "dest"
        dest.mkdir()

        result = create_backup_data(
            case_dir=case_dir, destination=str(dest), examiner="alice"
        )

        assert result["symlinks"] == []


class TestPruneWithRegisteredEvidence:
    """Registered evidence is evidence wherever it sits, so pruning a subtree
    must not hide registered evidence the backup was asked to include."""

    def _register(self, case_dir: Path, rel: str) -> None:
        import json

        (case_dir / "evidence.json").write_text(json.dumps({"files": [{"path": rel}]}))

    def test_registered_evidence_under_excluded_extractions_is_still_copied(
        self, tmp_path
    ):
        case_dir = _seed_case(tmp_path)
        carved = case_dir / "extractions" / "host-01" / "carved.bin"
        carved.write_bytes(b"c" * 8)
        self._register(case_dir, "extractions/host-01/carved.bin")
        dest = tmp_path / "dest"
        dest.mkdir()

        result = create_backup_data(
            case_dir=case_dir,
            destination=str(dest),
            examiner="alice",
            include_evidence=True,
            include_extractions=False,
        )

        backup_dir = Path(result["backup_path"])
        assert (backup_dir / "extractions" / "host-01" / "carved.bin").is_file()
        # The rest of extractions/ stays out.
        assert not (backup_dir / "extractions" / "host-01" / "artifact-0.bin").exists()

    def test_extractions_still_pruned_when_nothing_registered_there(self, tmp_path):
        case_dir = _seed_case(tmp_path)
        self._register(case_dir, "evidence/host-01/artifact-0.bin")

        recorded: list[str] = []
        real_walk = os.walk
        os.walk = _recording_walk(recorded)
        try:
            scan_case_dir(case_dir, include_evidence=True, include_extractions=False)
        finally:
            os.walk = real_walk

        pruned = str(case_dir / "extractions")
        assert not any(r.startswith(pruned) for r in recorded)
