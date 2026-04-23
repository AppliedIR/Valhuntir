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

    def test_symlinked_evidence_dir(self, tmp_path, monkeypatch, identity, capsys):
        """Prune must handle `case/evidence/` symlinked to external mount.

        evidence_register stores str(evidence_path.resolve()) — if evidence/
        is a symlink to /mnt/forensic-store/, entries look like
        /mnt/forensic-store/foo.manifest.json, not case_dir/evidence/.
        Pre-fix prefix check silently missed these → manifests stayed
        registered, Portal stayed polluted.
        """
        case_dir = tmp_path / "INC-TEST"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-TEST"}))

        external = tmp_path / "mnt" / "forensic-store"
        external.mkdir(parents=True)
        (case_dir / "evidence").symlink_to(external)

        # evidence.json stores resolved paths
        resolved_evidence = str(external.resolve())
        mf_path = Path(resolved_evidence) / "rd01-evtx-Security.manifest.json"
        mf_path.write_text(json.dumps({"hostname": "rd01"}))
        real_file = external / "disk.vhdx"
        real_file.write_bytes(b"")

        data = {
            "files": [
                {"path": str(mf_path), "description": "manifest"},
                {"path": str(real_file.resolve()), "description": "real disk"},
            ]
        }
        (case_dir / "evidence.json").write_text(json.dumps(data, indent=2))
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)

        out = capsys.readouterr().out
        assert "Manifests unregistered: 1" in out
        remaining = json.loads((case_dir / "evidence.json").read_text())["files"]
        assert len(remaining) == 1
        assert remaining[0]["path"] == str(real_file.resolve())
        assert not mf_path.exists()
        moved = list((case_dir / "audit" / "ingest-manifests").glob("*.manifest.json"))
        assert len(moved) == 1

    def test_overflow_past_999_collisions_is_skipped_with_warning(
        self, tmp_path, monkeypatch, identity, capsys
    ):
        """Pathological case: pre-existing audit dir has a collision at
        every disambiguator slot. Prune must skip + warn rather than
        silently overwriting stem-999."""
        case_dir = tmp_path / "INC-OVERFLOW"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-OVERFLOW"}))
        ev = case_dir / "evidence"
        ev.mkdir()

        audit_dir = case_dir / "audit" / "ingest-manifests"
        audit_dir.mkdir(parents=True)
        base = "foo.manifest.json"
        (audit_dir / base).write_text("original")

        mf = ev / base
        mf.write_text("new")
        (case_dir / "evidence.json").write_text(
            json.dumps({"files": [{"path": str(mf.resolve())}]})
        )

        import vhir_cli.commands.prune_manifests as pm

        # Force the for/else branch by patching builtins.range in the module
        monkeypatch.setattr(pm, "range", lambda *a, **kw: iter([]), raising=False)
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        pm.cmd_prune_ingest_manifests(args, identity)

        captured = capsys.readouterr()
        assert ">999 collisions for foo.manifest.json" in captured.err
        assert "skipped (>999 collisions): 1" in captured.out
        # Source file was skipped, not moved or clobbered
        assert mf.exists()
        assert (audit_dir / base).read_text() == "original"

    def test_move_does_not_overwrite_on_collision(
        self, tmp_path, monkeypatch, identity
    ):
        """Two source files with colliding manifest filenames must both survive the move.

        Pre-fix `_write_ingest_manifest` truncates stems at 50 chars;
        Windows Defender EVTX channel names collide (TerminalServices-...
        Admin vs Operational → same filename). Prune's shutil.move must
        not silently clobber the first move with the second.
        """
        case_dir = tmp_path / "INC-COLLIDE"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-COLLIDE"}))
        ev = case_dir / "evidence"
        ev.mkdir()

        # Pre-existing audit dir with a file of the same name already moved
        audit_dir = case_dir / "audit" / "ingest-manifests"
        audit_dir.mkdir(parents=True)
        collided_name = "rd01-evtx-Microsoft-Windows-TerminalSer.manifest.json"
        (audit_dir / collided_name).write_text('{"first": true}')

        # A manifest with the same name in evidence/ (pollution remnant)
        mf = ev / collided_name
        mf.write_text('{"second": true}')
        data = {
            "files": [
                {"path": str(mf.resolve()), "description": "colliding manifest"},
            ]
        }
        (case_dir / "evidence.json").write_text(json.dumps(data))
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))

        args = Namespace(case_id=None)
        cmd_prune_ingest_manifests(args, identity)

        survivors = sorted((audit_dir).glob("*.manifest.json"))
        assert len(survivors) == 2, (
            f"Expected 2 manifests after collision-safe move; got {len(survivors)}"
        )
        contents = {s.read_text() for s in survivors}
        assert '{"first": true}' in contents
        assert '{"second": true}' in contents
