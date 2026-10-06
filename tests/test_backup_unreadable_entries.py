"""A backup never reports success while leaving out part of the case it covers.

An unreadable file under the case already fails the backup with its path in
the error. A directory the scan can't list, a directory it can't search, and
a symlink whose target is gone were skipped without a word, so the backup said
"complete" and verified. They now fail it the same way, unless they sit in a
part of the case the backup leaves out (evidence/ or extractions/ without the
matching option).
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from vhir_cli.commands import backup as B

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)


def _case(root: Path) -> Path:
    case = root / "UNREAD-CASE"
    (case / "work" / "scratch").mkdir(parents=True)
    (case / "evidence").mkdir()
    (case / "extractions").mkdir()
    (case / "CASE.yaml").write_text("case_id: UNREAD-CASE\nstatus: open\nname: u\n")
    (case / "findings.json").write_text("[]")
    (case / "work" / "scratch" / "notes.txt").write_text("notes\n")
    return case


_LOCKED: list[Path] = []


@pytest.fixture(params=["direct", "through a symlink"])
def case(tmp_path, request):
    real = _case(tmp_path / "real")
    if request.param == "direct":
        yield real
    else:
        link = tmp_path / "linked"
        link.symlink_to(real.parent)
        yield link / real.name
    while _LOCKED:  # so tmp_path can be cleaned up
        _LOCKED.pop().chmod(0o755)


def _locked_dir(parent: Path, mode: int = 0o000) -> Path:
    d = parent / "locked"
    d.mkdir(parents=True)
    (d / "inside.txt").write_text("cannot be read\n")
    d.chmod(mode)
    _LOCKED.append(d)
    return d


def _dangling(parent: Path, name: str = "gone.txt") -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    link = parent / name
    link.symlink_to("/nonexistent-target-for-test/" + name)
    return link


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


# --- rows that fail on the unfixed code -------------------------------------


def test_an_unreadable_directory_fails_the_backup_and_names_it(case, tmp_path):
    _locked_dir(case / "work")
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out")
    assert str(Path("work") / "locked") in str(exc.value)


def test_a_directory_that_cannot_be_searched_fails_the_backup(case, tmp_path):
    _locked_dir(case / "work", mode=0o444)  # listable, entries can't be stat'd
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out")
    assert "inside.txt" in str(exc.value)


def test_a_dangling_symlink_in_case_data_fails_the_backup(case, tmp_path):
    _dangling(case / "work" / "scratch")
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out")
    assert "gone.txt" in str(exc.value)


def test_unreadable_evidence_fails_a_backup_that_includes_evidence(case, tmp_path):
    _dangling(case / "evidence", "disk.E01")
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out", include_evidence=True)
    assert "disk.E01" in str(exc.value)


def test_unreadable_extractions_fail_a_backup_that_includes_them(case, tmp_path):
    _locked_dir(case / "extractions")
    with pytest.raises(OSError):
        _backup(case, tmp_path / "out", include_extractions=True)


def test_the_cli_reports_an_unreadable_directory_as_an_error(
    case, tmp_path, monkeypatch, capsys
):
    _locked_dir(case / "work")
    monkeypatch.setattr(B, "get_case_dir", lambda _case: case)
    monkeypatch.setattr(B, "_detect_opensearch", lambda _case: {"available": False})
    args = argparse.Namespace(
        verify=None,
        case=None,
        destination=str(tmp_path / "out"),
        all=True,
        include_evidence=False,
        include_extractions=False,
        include_opensearch=False,
    )
    with pytest.raises(SystemExit) as exc:
        B.cmd_backup(args, {"examiner": "tester"})
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("Error: ") and "locked" in err


def test_a_case_directory_that_cannot_be_listed_fails_the_backup(case, tmp_path):
    real = case.resolve()
    real.chmod(0o300)  # CASE.yaml still opens by name; the walk can't list
    _LOCKED.append(real)
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out")
    assert "UNREAD-CASE" in str(exc.value)


def test_a_work_folder_named_evidence_is_still_case_data(case, tmp_path):
    _locked_dir(case / "work" / "evidence")
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out")
    assert "locked" in str(exc.value)


def test_registered_evidence_outside_evidence_is_still_left_out(case, tmp_path):
    link = _dangling(case / "work", "disk.E01")  # its drive is not mounted
    target = os.readlink(link)
    (case / "evidence.json").write_text(json.dumps({"files": [{"path": target}]}))
    result = _backup(case, tmp_path / "out")
    assert result["file_count"] == 4  # evidence.json is case data
    with pytest.raises(OSError):
        _backup(case, tmp_path / "out", include_evidence=True)


# --- guards and anchors (pass before and after) ------------------------------


def test_unreadable_evidence_does_not_fail_a_backup_that_leaves_it_out(case, tmp_path):
    _dangling(case / "evidence", "disk.E01")
    _locked_dir(case / "evidence")
    result = _backup(case, tmp_path / "out")
    assert result["file_count"] == 3


def test_unreadable_extractions_do_not_fail_a_backup_that_leaves_them_out(
    case, tmp_path
):
    _dangling(case / "extractions", "x.bin")
    _locked_dir(case / "extractions")
    result = _backup(case, tmp_path / "out", include_evidence=True)
    assert result["file_count"] == 3


def test_an_unreadable_file_still_fails_the_backup_and_names_it(case, tmp_path):
    f = case / "work" / "scratch" / "unreadable.txt"
    f.write_text("x\n")
    f.chmod(0o000)
    try:
        with pytest.raises(OSError) as exc:
            _backup(case, tmp_path / "out")
        assert "unreadable.txt" in str(exc.value)
    finally:
        f.chmod(0o644)


def test_a_symlinked_directory_is_still_followed_and_copied(case, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.txt").write_text("outside\n")
    (case / "ext").symlink_to(outside)  # a top-level folder kept elsewhere
    result = _backup(case, tmp_path / "out")
    backup = Path(result["backup_path"])
    assert (backup / "ext" / "o.txt").read_text() == "outside\n"


def test_a_readable_case_backs_up_and_verifies(case, tmp_path, capsys):
    result = _backup(case, tmp_path / "out")
    assert result["file_count"] == 3
    assert B._verify_backup(Path(result["backup_path"]))
