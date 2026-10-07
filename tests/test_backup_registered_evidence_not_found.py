"""Registered evidence the backup can't find (deleted, moved, in a folder that
can't be read, or on storage that isn't mounted) stops a backup that includes
evidence, with a reason of its own; the skip option records it in the manifest.
It is never left out without a word."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

import pytest

from vhir_cli.commands import backup as B
from vhir_cli.commands.evidence import register_evidence_data
from vhir_cli.main import build_parser

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)

CANT_FIND = "registered evidence the backup can't find"
CANT_REACH = "registered evidence the backup can't reach"

_LOCKED: list[Path] = []


@pytest.fixture(autouse=True)
def unlock():
    yield
    while _LOCKED:  # so tmp_path can be cleaned up
        _LOCKED.pop().chmod(0o755)


def _case(root: Path, name: str = "FIND-CASE") -> Path:
    case = root / name
    for d in ("evidence", "extractions", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {name}\nstatus: open\nname: f\n")
    (case / "findings.json").write_text("[]")
    (case / "evidence" / "a.img").write_bytes(b"present image\n")
    _register(case, case / "evidence" / "a.img")
    return case


def _register(case: Path, path: Path) -> None:
    register_evidence_data(case, str(path), "tester")


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


def _manifest(result: dict) -> dict:
    return json.loads(
        (Path(result["backup_path"]) / "backup-manifest.json").read_text()
    )


def _finished(dest: Path) -> list[Path]:
    if not dest.exists():
        return []
    return [p for p in dest.iterdir() if not p.name.endswith(".incomplete")]


def _line(message: str, path: Path) -> str:
    """The stop message's line for one path."""
    lines = [ln for ln in message.splitlines() if str(path) in ln]
    assert len(lines) == 1, message
    return lines[0]


def _stopped(case: Path, dest: Path, **kw) -> str:
    with pytest.raises(OSError) as exc:
        _backup(case, dest, include_evidence=True, **kw)
    message = str(exc.value)
    assert message.startswith("Backup stopped before copying")
    assert _finished(dest) == []
    return message


@pytest.mark.parametrize(
    "kw", [{}, {"include_extractions": True}], ids=["evidence", "everything"]
)
def test_a_deleted_registered_file_stops_a_backup_with_evidence(tmp_path, kw):
    case = _case(tmp_path / "cases")
    gone = case / "evidence" / "gone.img"
    gone.write_bytes(b"gone\n")
    _register(case, gone)
    gone.unlink()
    line = _line(_stopped(case, tmp_path / "out", **kw), gone.resolve())
    assert CANT_FIND in line
    assert CANT_REACH not in line


def test_skipping_records_the_missing_file_and_verify_and_restore_list_it(
    tmp_path, capsys, monkeypatch
):
    case = _case(tmp_path / "cases")
    gone = case / "evidence" / "gone.img"
    gone.write_bytes(b"gone\n")
    _register(case, gone)
    gone.unlink()
    result = _backup(
        case, tmp_path / "out", include_evidence=True, skip_unreadable=True
    )
    manifest = _manifest(result)
    assert manifest["includes_evidence"] is True
    assert [s["path"] for s in manifest["skipped"]] == ["evidence/gone.img"]
    assert manifest["skipped"][0]["reason"].startswith(CANT_FIND)
    assert "evidence/a.img" in {f["path"] for f in manifest["files"]}

    capsys.readouterr()
    assert B._verify_backup(Path(result["backup_path"])) is True
    out = capsys.readouterr().out
    assert f"SKIPPED: evidence/gone.img ({CANT_FIND}" in out
    assert "PASSED" in out

    monkeypatch.setattr(B.sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(
        B,
        "subprocess",
        argparse.Namespace(
            run=lambda *a, **k: argparse.Namespace(returncode=0, stdout="", stderr="")
        ),
    )
    B.cmd_restore(
        argparse.Namespace(
            backup_path=result["backup_path"],
            skip_opensearch=True,
            skip_ledger=True,
            target=str(tmp_path / "elsewhere" / "FIND-CASE"),
        ),
        {"examiner": "tester"},
    )
    assert f"SKIPPED: evidence/gone.img ({CANT_FIND}" in capsys.readouterr().out


def test_a_registered_file_in_a_folder_that_cant_be_read_stops_the_backup(tmp_path):
    case = _case(tmp_path / "cases")
    locked = case / "extractions" / "locked"
    locked.mkdir()
    (locked / "f.bin").write_bytes(b"hidden\n")
    _register(case, locked / "f.bin")
    locked.chmod(0o000)
    _LOCKED.append(locked)
    line = _line(_stopped(case, tmp_path / "out"), locked.resolve() / "f.bin")
    assert CANT_FIND in line
    assert CANT_REACH not in line


def test_registered_storage_that_is_no_longer_mounted_stops_the_backup(tmp_path):
    case = _case(tmp_path / "cases")
    store = tmp_path / "store"
    store.mkdir()
    (store / "x.img").write_bytes(b"stored image\n")
    (case / "extractions" / "mnt").symlink_to(store)
    _register(case, case / "extractions" / "mnt" / "x.img")
    image = store.resolve() / "x.img"

    mounted = _line(_stopped(case, tmp_path / "out1"), image)
    assert CANT_REACH in mounted

    store.rename(tmp_path / "store-unmounted")
    unmounted = _line(_stopped(case, tmp_path / "out2"), image)
    assert CANT_FIND in unmounted
    assert CANT_REACH not in unmounted
    assert unmounted != mounted


def test_a_case_moved_by_hand_stops_and_skipping_records_the_old_path(tmp_path):
    case = _case(tmp_path / "cases", "M")
    moved = tmp_path / "moved" / "M"
    moved.parent.mkdir()
    shutil.move(str(case), str(moved))
    old = case.resolve() / "evidence" / "a.img"  # what the registry still names

    assert CANT_FIND in _line(_stopped(moved, tmp_path / "out"), old)

    result = _backup(
        moved, tmp_path / "out2", include_evidence=True, skip_unreadable=True
    )
    manifest = _manifest(result)
    assert [s["path"] for s in manifest["skipped"]] == [os.path.relpath(old, moved)]
    assert "evidence/a.img" in {f["path"] for f in manifest["files"]}


def test_the_help_says_the_skip_option_covers_paths_that_cant_be_found(capsys):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["backup", "--help"])
    out = " ".join(capsys.readouterr().out.split())
    assert "Leave out paths that can't be read, found or followed" in out


# --- anchors (pass before and after) ----------------------------------------


def test_registered_evidence_that_is_there_backs_up(tmp_path):
    case = _case(tmp_path / "cases")
    result = _backup(case, tmp_path / "out", include_evidence=True)
    manifest = _manifest(result)
    assert "skipped" not in manifest
    assert "evidence/a.img" in {f["path"] for f in manifest["files"]}


def test_a_backup_without_evidence_is_not_stopped_by_a_missing_registered_file(
    tmp_path,
):
    case = _case(tmp_path / "cases")
    gone = case / "evidence" / "gone.img"
    gone.write_bytes(b"gone\n")
    _register(case, gone)
    gone.unlink()
    assert "skipped" not in _manifest(_backup(case, tmp_path / "out"))
    # as case-mcp's backup_case calls it
    result = B.create_backup_data(
        case_dir=case,
        destination=str(tmp_path / "out-mcp"),
        examiner="tester",
        purpose="p",
    )
    assert result["skipped"] == []
