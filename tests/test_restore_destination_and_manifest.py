"""Restore checks the backup's manifest, asks where to restore, and never removes
a folder without a yes; a merge never replaces a case file it can't read.

The manifest is a plain file in the backup folder. Its case id steered a root
copy into the ledger store, and its file list could name paths outside the
case. Restore went to the folder the manifest named without asking, and
removed an interrupted restore's folder without asking. A merge read a corrupt
findings or timeline file as empty and wrote back only the bundle's items.

Nothing here runs sudo: the backup module's subprocess calls are recorded.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B
from vhir_cli.case_io import import_bundle
from vhir_cli.main import build_parser

CASE_ID = "INC-2026-001"
IDENTITY = {"examiner": "analyst1", "os_user": "testuser"}


@pytest.fixture
def sudo(monkeypatch):
    calls: list[list[str]] = []

    def run(cmd, *a, **k):
        calls.append([str(c) for c in cmd])
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(B, "subprocess", types.SimpleNamespace(run=run))
    return calls


def _tty(monkeypatch, answers: dict[str, str]) -> list[str]:
    """A terminal whose answers are keyed by the start of each prompt."""
    asked: list[str] = []

    def answer(prompt=""):
        asked.append(prompt)
        return next((a for start, a in answers.items() if prompt.startswith(start)), "")

    monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", answer)
    return asked


@pytest.fixture(autouse=True)
def no_tty(monkeypatch):
    monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: False))


def _backup(tmp_path: Path, files: dict[str, str], **manifest) -> tuple[Path, Path]:
    """A backup folder whose manifest lists `files`; returns it and its source."""
    source = tmp_path / "cases" / CASE_ID
    backup = tmp_path / "backup"
    backup.mkdir()
    entries = []
    for rel, text in files.items():
        f = backup / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        entries.append(
            {"path": rel, "sha256": hashlib.sha256(text.encode()).hexdigest()}
        )
    data = {
        "version": 1,
        "case_id": CASE_ID,
        "timestamp": "2026-01-01T00:00:00Z",
        "source": str(source),
        "file_count": len(entries),
        "total_bytes": 0,
        "files": entries,
        **manifest,
    }
    (backup / "backup-manifest.json").write_text(json.dumps(data))
    return backup, source


def _args(backup: Path, target=None):
    return types.SimpleNamespace(
        backup_path=str(backup), skip_opensearch=True, skip_ledger=False, target=target
    )


def _tree(folder: Path) -> dict[str, str]:
    return {
        str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def _interrupted(source: Path) -> dict[str, str]:
    source.mkdir(parents=True)
    (source / ".restore-in-progress").touch()
    (source / "sentinel.txt").write_text("the examiner's partial restore\n")
    return _tree(source)


# The manifest is checked before anything else


def test_a_case_id_that_leaves_the_ledger_store_is_refused(tmp_path, sudo, capsys):
    backup, source = _backup(
        tmp_path,
        {"case.json": "{}"},
        case_id="../pwned",
        includes_verification_ledger=True,
    )
    (backup / "verification").mkdir()
    (backup / "verification" / "../pwned.jsonl").write_text("")
    with pytest.raises(SystemExit) as e:
        B.cmd_restore(_args(backup, target=str(source)), IDENTITY)
    assert e.value.code == 1
    assert "case_id" in capsys.readouterr().err
    assert sudo == []
    assert not source.exists()


def test_a_file_outside_the_case_is_refused_before_anything_is_removed(
    tmp_path, sudo, monkeypatch
):
    # even when the examiner would agree to remove the interrupted restore
    backup, source = _backup(tmp_path, {"case.json": "{}", "../escaped.txt": "planted"})
    before = _interrupted(source)
    _tty(monkeypatch, {"A previous restore was interrupted": "y"})
    with pytest.raises(SystemExit) as e:
        B.cmd_restore(_args(backup, target=str(source)), IDENTITY)
    assert e.value.code == 1
    assert _tree(source) == before
    assert not (source.parent / "escaped.txt").exists()


@pytest.mark.parametrize("rel", ["../escaped.txt", "evidence/../../escaped.txt"])
def test_a_file_outside_the_case_is_never_written(tmp_path, sudo, rel):
    backup, source = _backup(tmp_path, {"case.json": "{}", rel: "planted"})
    with pytest.raises(SystemExit):
        B.cmd_restore(_args(backup, target=str(source)), IDENTITY)
    assert not (source.parent / "escaped.txt").exists()
    assert not source.exists()


def test_a_real_backup_restores_including_a_name_with_two_dots(tmp_path, sudo):
    case = tmp_path / "cases" / "ROUNDTRIP"
    (case / "evidence").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: ROUNDTRIP\nstatus: open\nname: r\n")
    (case / "findings.json").write_text("[]")
    (case / "evidence" / "img..E01").write_bytes(b"image")
    result = B.create_backup_data(
        case, str(tmp_path / "out"), "analyst1", include_evidence=True
    )
    before = _tree(case)
    os.rename(case, tmp_path / "moved-away")
    B.cmd_restore(_args(result["backup_path"], target=str(case)), IDENTITY)
    assert _tree(case) == before


# Where to restore is the examiner's


def test_without_a_terminal_a_restore_needs_a_target(tmp_path, sudo, capsys):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    with pytest.raises(SystemExit) as e:
        B.cmd_restore(_args(backup), IDENTITY)
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "--target" in err and str(source) in err
    assert not source.exists()


def test_on_a_terminal_the_examiner_is_asked_and_a_typed_folder_is_used(
    tmp_path, sudo, monkeypatch
):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    chosen = tmp_path / "elsewhere" / "restored"
    asked = _tty(monkeypatch, {f"Restore case {CASE_ID} to": str(chosen)})
    B.cmd_restore(_args(backup), IDENTITY)
    assert asked[0] == f"Restore case {CASE_ID} to [{source}]: "
    assert (chosen / "case.json").read_text() == "{}"
    assert not source.exists()


def test_a_target_on_the_command_line_is_used_and_the_source_is_left_alone(
    tmp_path, sudo
):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    chosen = tmp_path / "chosen"
    args = build_parser().parse_args(
        ["restore", str(backup), "--target", str(chosen), "--skip-opensearch"]
    )
    B.cmd_restore(args, IDENTITY)
    assert (chosen / "case.json").read_text() == "{}"
    assert not source.exists()


# An interrupted restore's folder is removed only after a yes


def test_pressing_enter_keeps_an_interrupted_restore(tmp_path, sudo, monkeypatch):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    before = _interrupted(source)
    asked = _tty(monkeypatch, {})  # Enter at every prompt
    with pytest.raises(SystemExit):
        B.cmd_restore(_args(backup), IDENTITY)
    assert _tree(source) == before
    assert any("2 file(s)" in a and a.endswith("[y/N] ") for a in asked), asked


def test_without_a_terminal_an_interrupted_restore_is_kept(tmp_path, sudo, capsys):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    before = _interrupted(source)
    with pytest.raises(SystemExit) as e:
        B.cmd_restore(_args(backup, target=str(source)), IDENTITY)
    assert e.value.code == 1
    assert "Remove it first" in capsys.readouterr().err
    assert _tree(source) == before


def test_answering_yes_removes_an_interrupted_restore_and_restores(
    tmp_path, sudo, monkeypatch
):
    backup, source = _backup(tmp_path, {"case.json": "{}"})
    _interrupted(source)
    _tty(monkeypatch, {"A previous restore was interrupted": "y"})
    B.cmd_restore(_args(backup), IDENTITY)
    assert _tree(source) == {"case.json": hashlib.sha256(b"{}").hexdigest()}


# A merge never writes over a case file it can't read


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "case"
    case.mkdir()
    return case


BUNDLE = {
    "findings": [{"id": "F-x-099", "title": "incoming", "modified_at": "2026-01-02"}],
    "timeline": [
        {"id": "T-x-099", "description": "incoming", "modified_at": "2026-01-02"}
    ],
}


@pytest.mark.parametrize("corrupt", ["findings.json", "timeline.json"])
def test_a_merge_into_a_file_it_cannot_parse_writes_nothing(tmp_path, corrupt):
    case = _case(tmp_path)
    good = json.dumps([{"id": "F-x-001"}, {"id": "T-x-001"}])
    files = {"findings.json": good, "timeline.json": good}
    files[corrupt] = good + "\n{trailing garbage"
    for name, text in files.items():
        (case / name).write_text(text)
    result = import_bundle(case, BUNDLE)
    assert result["status"] == "error" and corrupt in result["message"]
    assert {n: (case / n).read_text() for n in files} == files


@pytest.mark.parametrize("local", [None, "", "  \n"], ids=["absent", "empty", "blank"])
def test_a_merge_into_an_absent_or_empty_file_still_merges(tmp_path, local):
    case = _case(tmp_path)
    if local is not None:
        (case / "timeline.json").write_text(local)
    result = import_bundle(case, BUNDLE)
    assert result["status"] == "merged"
    assert [t["id"] for t in json.loads((case / "timeline.json").read_text())] == [
        "T-x-099"
    ]


def test_restore_runs_its_checks_with_this_interpreter():
    # the restore rows above drive cmd_restore in-process
    assert B.sys is sys
