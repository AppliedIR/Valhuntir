"""Tests for `scan_case_dir` — symlinked evidence trees must not loop."""

from __future__ import annotations

import os
from pathlib import Path

from vhir_cli.commands.backup import scan_case_dir


def _seed_case(tmp_path: Path, ndirs: int = 2, nfiles: int = 3) -> Path:
    """Build a case dir with evidence/host1/dN/fN.bin files."""
    case_dir = tmp_path / "INC-TEST"
    host = case_dir / "evidence" / "host1"
    host.mkdir(parents=True)
    for d in range(ndirs):
        sub = host / f"d{d}"
        sub.mkdir()
        for i in range(nfiles):
            (sub / f"f{i}.bin").write_bytes(b"x" * 8)
    (case_dir / "notes.md").write_text("notes\n")
    return case_dir


class TestScanCaseDirLoops:
    def test_parent_symlink_scans_subtree_once(self, tmp_path):
        """`ln -s .. evidence/host1/loop` must not re-list the subtree."""
        case_dir = _seed_case(tmp_path)
        os.symlink("..", case_dir / "evidence" / "host1" / "loop")

        scan = scan_case_dir(case_dir)

        paths = [p for p, _, _ in scan["evidence"]]
        assert len(paths) == 6
        assert [p for p in paths if "loop" in p] == []

    def test_symlink_to_case_root_scans_case_once(self, tmp_path):
        """A link back to the case dir itself must not re-list the case."""
        case_dir = _seed_case(tmp_path)
        os.symlink("..", case_dir / "evidence" / "top")

        scan = scan_case_dir(case_dir)

        assert len(scan["case_data"]) == 1
        paths = [p for p, _, _ in scan["evidence"]]
        assert len(paths) == 6
        assert [p for p in paths if "top" in p] == []

    def test_mutually_reachable_symlinks_terminate(self, tmp_path):
        """evidence -> external -> evidence must terminate, not spiral."""
        case_dir = _seed_case(tmp_path)
        external = tmp_path / "external"
        external.mkdir()
        (external / "mem.raw").write_bytes(b"y" * 8)
        os.symlink(str(external), case_dir / "evidence" / "ext")
        os.symlink(str(case_dir / "evidence"), external / "back")

        scan = scan_case_dir(case_dir)

        paths = [p for p, _, _ in scan["evidence"]]
        assert len(paths) == 7
        assert "evidence/ext/mem.raw" in paths


class TestScanCaseDirFollowsLinks:
    def test_evidence_symlink_target_is_scanned(self, tmp_path):
        """The documented `ln -s <resolved> evidence/<name>` layout still works."""
        case_dir = _seed_case(tmp_path, ndirs=0)
        collected = tmp_path / "mnt" / "disk1"
        collected.mkdir(parents=True)
        (collected / "image.E01").write_bytes(b"z" * 8)
        os.symlink(str(collected), case_dir / "evidence" / "disk1")

        scan = scan_case_dir(case_dir)

        paths = [p for p, _, _ in scan["evidence"]]
        assert paths == ["evidence/disk1/image.E01"]

    def test_sibling_symlink_is_still_scanned(self, tmp_path):
        """A non-looping duplicate path is still backed up under both names."""
        case_dir = _seed_case(tmp_path)
        os.symlink("host1", case_dir / "evidence" / "latest")

        scan = scan_case_dir(case_dir)

        paths = [p for p, _, _ in scan["evidence"]]
        assert len(paths) == 12
        assert [p for p in paths if p.startswith("evidence/latest/")] != []
