"""A case restored to another folder has its evidence registry point at the copy.

The registry stores each evidence file's absolute path. After a restore to a
folder other than the one backed up, verify kept hashing the original's files:
a changed restored copy read OK, or MISSING once the original was gone.
Restore now re-points entries that were inside the backed-up case, and lists
any it leaves pointing outside the restored case.

Nothing here runs sudo: the backup module's subprocess calls are recorded.
"""

from __future__ import annotations

import json
import os
import shutil
import types
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B
from vhir_cli.commands.evidence import register_evidence_data, verify_evidence_data

IDENTITY = {"examiner": "analyst1", "os_user": "testuser"}


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(
        B,
        "subprocess",
        types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(
                returncode=0, stdout="", stderr=""
            )
        ),
    )


def _case(parent: Path, name: str = "CASE1") -> Path:
    case = parent / name
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\nname: r\n")
    (case / "findings.json").write_text("[]")
    (case / "evidence" / "disk.raw").write_bytes(b"original image")
    register_evidence_data(case, str(case / "evidence" / "disk.raw"), "analyst1")
    return case


def _backup(case: Path, out: Path, evidence: bool = True) -> str:
    return B.create_backup_data(case, str(out), "analyst1", include_evidence=evidence)[
        "backup_path"
    ]


def _restore(backup: str, target) -> None:
    args = types.SimpleNamespace(
        backup_path=backup, skip_opensearch=True, skip_ledger=True, target=str(target)
    )
    B.cmd_restore(args, IDENTITY)


def _status(case: Path, name: str = "disk.raw") -> list[tuple[str, str]]:
    return [
        (r["status"], r["path"])
        for r in verify_evidence_data(case)["results"]
        if r["path"].endswith(name)
    ]


def test_a_changed_restored_copy_is_reported_modified(tmp_path):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    restored = copy.resolve() / "evidence" / "disk.raw"
    restored.chmod(0o644)
    restored.write_bytes(b"changed after the restore")
    assert _status(copy) == [("MODIFIED", str(restored))]


def test_the_restored_copy_verifies_after_the_original_is_gone(tmp_path):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    shutil.rmtree(case, onerror=lambda f, p, e: (os.chmod(p, 0o755), f(p)))
    assert _status(copy) == [("OK", str(copy.resolve() / "evidence" / "disk.raw"))]


def test_evidence_linked_in_from_outside_is_kept_and_listed(tmp_path, capsys):
    case = _case(tmp_path / "cases")
    store = tmp_path / "store"
    store.mkdir()
    (store / "mem.raw").write_bytes(b"memory")
    (case / "evidence" / "mem.raw").symlink_to(store / "mem.raw")
    register_evidence_data(case, str(case / "evidence" / "mem.raw"), "analyst1")
    backup = _backup(case, tmp_path / "out", evidence=False)
    copy = tmp_path / "elsewhere" / "CASE1"
    capsys.readouterr()
    _restore(backup, copy)
    out = capsys.readouterr().out
    paths = [
        e["path"] for e in json.loads((copy / "evidence.json").read_text())["files"]
    ]
    assert str((store / "mem.raw").resolve()) in paths
    assert "registered outside the restored case" in out
    assert str((store / "mem.raw").resolve()) in out


def test_restoring_to_the_original_folder_leaves_the_registry_as_it_was(tmp_path):
    case = _case(tmp_path / "cases")
    before = (case / "evidence.json").read_bytes()
    backup = _backup(case, tmp_path / "out")
    shutil.rmtree(case, onerror=lambda f, p, e: (os.chmod(p, 0o755), f(p)))
    _restore(backup, case)
    assert (case / "evidence.json").read_bytes() == before


def test_restoring_to_the_original_through_a_symlinked_alias_leaves_it_as_it_was(
    tmp_path,
):
    case = _case(tmp_path / "real")
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    before = (case / "evidence.json").read_bytes()
    backup = _backup(case, tmp_path / "out")
    shutil.rmtree(case, onerror=lambda f, p, e: (os.chmod(p, 0o755), f(p)))
    _restore(backup, tmp_path / "alias" / "CASE1")
    assert (case / "evidence.json").read_bytes() == before


def test_a_case_reached_through_a_symlinked_parent_is_re_pointed(tmp_path):
    (tmp_path / "real" / "cases").mkdir(parents=True)
    (tmp_path / "link").symlink_to(tmp_path / "real")
    case = _case(tmp_path / "link" / "cases")  # registered paths are the real ones
    backup = _backup(case, tmp_path / "out")
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    restored = copy.resolve() / "evidence" / "disk.raw"
    restored.chmod(0o644)
    restored.write_bytes(b"changed")
    assert _status(copy) == [("MODIFIED", str(restored))]


def test_a_relative_target_is_recorded_as_an_absolute_path(tmp_path, monkeypatch):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    (tmp_path / "work").mkdir()
    monkeypatch.chdir(tmp_path / "work")
    _restore(backup, "rel/CASE1")
    monkeypatch.chdir(tmp_path)  # verify from somewhere else
    shutil.rmtree(case, onerror=lambda f, p, e: (os.chmod(p, 0o755), f(p)))
    copy = tmp_path / "work" / "rel" / "CASE1"
    assert _status(copy) == [("OK", str(copy.resolve() / "evidence" / "disk.raw"))]


def test_a_restore_without_evidence_reports_it_missing_not_ok(tmp_path):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out", evidence=False)
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    assert [s for s, _ in _status(copy)] == ["MISSING"]


def test_a_relocated_case_can_be_backed_up_with_its_evidence(tmp_path):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    again = B.create_backup_data(
        copy, str(tmp_path / "out2"), "analyst1", include_evidence=True
    )
    assert (
        Path(again["backup_path"], "evidence", "disk.raw").read_bytes()
        == b"original image"
    )


def test_a_registry_that_cannot_be_read_is_left_untouched(tmp_path, capsys):
    case = _case(tmp_path / "cases")
    reg = case / "evidence.json"
    reg.chmod(0o644)
    reg.write_text('{"files": [ broken')
    backup = _backup(case, tmp_path / "out", evidence=False)
    copy = tmp_path / "elsewhere" / "CASE1"
    capsys.readouterr()
    _restore(backup, copy)
    assert (copy / "evidence.json").read_text() == '{"files": [ broken'
    assert "evidence.json can't be read" in capsys.readouterr().out
    assert not (copy / ".restore-in-progress").exists()


def test_a_registry_that_cannot_be_written_leaves_the_restore_flagged(
    tmp_path, monkeypatch
):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    copy = tmp_path / "elsewhere" / "CASE1"

    def fail(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("vhir_cli.case_io._atomic_write", fail)
    with pytest.raises(SystemExit) as e:
        _restore(backup, copy)
    assert e.value.code == 1
    assert (copy / ".restore-in-progress").exists()


# Gaps in the destination and path checks


def test_a_typed_home_folder_is_expanded(tmp_path, monkeypatch):
    case = _case(tmp_path / "cases")
    backup = _backup(case, tmp_path / "out")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt="": "~/x" if prompt.startswith("Restore case") else "",
    )
    monkeypatch.chdir(tmp_path)
    B.cmd_restore(
        types.SimpleNamespace(
            backup_path=backup, skip_opensearch=True, skip_ledger=True
        ),
        IDENTITY,
    )
    assert (home / "x" / "findings.json").exists()
    assert not (tmp_path / "~").exists()


@pytest.mark.parametrize("rel", [".", "./."])
def test_a_manifest_path_naming_the_case_folder_itself_is_refused(tmp_path, rel):
    case = _case(tmp_path / "cases")
    backup = Path(_backup(case, tmp_path / "out", evidence=False))
    manifest = json.loads((backup / "backup-manifest.json").read_text())
    manifest["files"].append({"path": rel, "sha256": "0" * 64})
    (backup / "backup-manifest.json").write_text(json.dumps(manifest))
    copy = tmp_path / "elsewhere" / "CASE1"
    with pytest.raises(SystemExit) as e:
        _restore(str(backup), copy)
    assert e.value.code == 1
    assert not copy.exists()


def test_evidence_in_a_folder_whose_name_only_starts_like_the_case_is_kept(tmp_path):
    case = _case(tmp_path / "cases", "CASE1")
    sibling = tmp_path / "cases" / "CASE10"
    sibling.mkdir()
    (sibling / "shared.raw").write_bytes(b"another case's file")
    (case / "evidence" / "shared.raw").symlink_to(sibling / "shared.raw")
    register_evidence_data(case, str(case / "evidence" / "shared.raw"), "analyst1")
    backup = _backup(case, tmp_path / "out", evidence=False)
    copy = tmp_path / "elsewhere" / "CASE1"
    _restore(backup, copy)
    paths = [
        e["path"] for e in json.loads((copy / "evidence.json").read_text())["files"]
    ]
    assert str((sibling / "shared.raw").resolve()) in paths
