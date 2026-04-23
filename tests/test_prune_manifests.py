"""Tests for `vhir case prune-ingest-manifests`."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from vhir_cli.commands.prune_manifests import cmd_prune_ingest_manifests


@pytest.fixture
def identity():
    return {"examiner": "alice", "os_user": "alice"}


def _seed_case(tmp_path: Path, polluted=True, extra_real=None):
    """Build a case dir with optional polluted evidence.json."""
    case_dir = tmp_path / "INC-TEST"
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-TEST"}))
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir()

    real_files = [
        {"path": str(case_dir / "evidence" / "disk.vhdx"), "sha256": "aaa"},
        {"path": str(case_dir / "evidence" / "mem.img"), "sha256": "bbb"},
    ]
    for e in real_files:
        Path(e["path"]).write_bytes(b"")

    if extra_real:
        real_files.extend(extra_real)

    manifest_entries = []
    if polluted:
        for i in range(3):
            mf = evidence_dir / f"host{i}-evtx-Security.manifest.json"
            mf.write_text(json.dumps({"hostname": f"host{i}"}))
            manifest_entries.append(
                {"path": str(mf), "description": f"Ingest manifest host{i}"}
            )

    data = {"files": real_files + manifest_entries}
    (case_dir / "evidence.json").write_text(json.dumps(data, indent=2))
    return case_dir, len(real_files), len(manifest_entries)


class TestPruneIngestManifests:
    def test_filters_json_entries(self, tmp_path, monkeypatch, identity, capsys):
        case_dir, n_real, n_manifests = _seed_case(tmp_path, polluted=True)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)

        data = json.loads((case_dir / "evidence.json").read_text())
        assert len(data["files"]) == n_real
        assert all(not f["path"].endswith(".manifest.json") for f in data["files"])

        audit_dir = case_dir / "audit" / "ingest-manifests"
        assert audit_dir.is_dir()
        assert len(list(audit_dir.glob("*.manifest.json"))) == n_manifests
        assert not list((case_dir / "evidence").glob("*.manifest.json"))

        out = capsys.readouterr().out
        assert f"Manifests unregistered: {n_manifests}" in out
        assert f"Real evidence entries retained: {n_real}" in out

    def test_idempotent(self, tmp_path, monkeypatch, identity, capsys):
        case_dir, n_real, _ = _seed_case(tmp_path, polluted=True)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)
        capsys.readouterr()
        cmd_prune_ingest_manifests(args, identity)

        data = json.loads((case_dir / "evidence.json").read_text())
        assert len(data["files"]) == n_real
        out = capsys.readouterr().out
        assert "Nothing to prune" in out

    def test_preserves_non_manifest_json(self, tmp_path, monkeypatch, identity):
        """A legitimate .json evidence file in evidence/ must NOT be stripped.

        Discriminator is suffix `.manifest.json` AND prefix under
        case/evidence/ — a plain velociraptor.json must survive.
        """
        extra = tmp_path / "INC-TEST" / "evidence" / "velociraptor.json"
        case_dir, _, _ = _seed_case(
            tmp_path,
            polluted=True,
            extra_real=[{"path": str(extra), "sha256": "ccc"}],
        )
        extra.parent.mkdir(exist_ok=True)
        extra.write_text("{}")
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)

        data = json.loads((case_dir / "evidence.json").read_text())
        paths = [f["path"] for f in data["files"]]
        assert str(extra) in paths
        assert extra.exists()

    def test_no_evidence_json_is_noop(self, tmp_path, monkeypatch, identity, capsys):
        case_dir = tmp_path / "empty-case"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "empty"}))
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)
        assert "Nothing to prune" in capsys.readouterr().out

    def test_missing_on_disk_manifests_counted(
        self, tmp_path, monkeypatch, identity, capsys
    ):
        """If a manifest path is in evidence.json but the file is gone, report it."""
        case_dir, _, _ = _seed_case(tmp_path, polluted=True)
        for mf in (case_dir / "evidence").glob("*.manifest.json"):
            mf.unlink()
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)

        out = capsys.readouterr().out
        assert "Manifest files missing on disk: 3" in out
        data = json.loads((case_dir / "evidence.json").read_text())
        assert all(not f["path"].endswith(".manifest.json") for f in data["files"])
