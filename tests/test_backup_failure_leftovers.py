"""A backup that fails or is interrupted must not leave a directory that
looks like a finished backup, and a retry takes the plain name."""

from __future__ import annotations

import errno
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vhir_cli.commands import backup as bk


def _case(root: Path) -> Path:
    case = root / "LEFT-CASE"
    (case / "work" / "scratch").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("case_id: LEFT-CASE\nstatus: open\nname: l\n")
    (case / "findings.json").write_text("[]")
    for i in range(12):
        (case / "audit" / f"a{i}.jsonl").write_text(f"line {i}\n")
    (case / "work" / "scratch" / "note.txt").write_text("notes\n")
    return case


def _plain() -> str:
    return f"LEFT-CASE-{datetime.now(timezone.utc):%Y-%m-%d}"


def _backup_named(dest: Path) -> list[str]:
    """Entries in dest that carry a finished backup's name."""
    pat = re.compile(re.escape(_plain()) + r"(-\d+)?$")
    return sorted(p.name for p in dest.iterdir() if pat.fullmatch(p.name))


def _leftovers(dest: Path) -> list[Path]:
    return sorted(
        p for p in dest.iterdir() if p.is_dir() and p.name not in _backup_named(dest)
    )


@pytest.fixture
def case(tmp_path):
    return _case(tmp_path / "cases")


@pytest.fixture
def locked(case):
    f = case / "work" / "scratch" / "zz-unreadable.lnk"
    f.write_text("x")
    f.chmod(0)
    yield f
    f.chmod(0o644)


def _fail_on(monkeypatch, nth: int, exc: BaseException):
    """The backup's copy function fails on its nth file."""
    real, seen = bk._copy_file_hashing, {"n": 0}

    def copy(src, dst):
        seen["n"] += 1
        if seen["n"] == nth:
            raise exc
        return real(src, dst)

    monkeypatch.setattr(bk, "_copy_file_hashing", copy)


def test_a_failed_backup_never_takes_the_backup_name(case, locked, tmp_path):
    dest = tmp_path / "out"
    with pytest.raises(OSError):
        bk.create_backup_data(case, str(dest), "tester")
    assert _backup_named(dest) == []
    assert len(_leftovers(dest)) == 1


def test_the_retry_after_a_failure_takes_the_plain_name(case, locked, tmp_path):
    dest = tmp_path / "out"
    with pytest.raises(OSError):
        bk.create_backup_data(case, str(dest), "tester")
    locked.chmod(0o644)
    result = bk.create_backup_data(case, str(dest), "tester")
    assert Path(result["backup_path"]).name == _plain()


def test_the_error_names_the_unreadable_file(case, locked, tmp_path):
    with pytest.raises(OSError) as e:
        bk.create_backup_data(case, str(tmp_path / "out"), "tester")
    assert str(locked) in str(e.value)


def test_the_failed_copy_keeps_its_marker_and_is_refused(case, locked, tmp_path):
    dest = tmp_path / "out"
    with pytest.raises(OSError):
        bk.create_backup_data(case, str(dest), "tester")
    (left,) = [p for p in dest.iterdir() if p.is_dir()]
    assert (left / ".backup-in-progress").exists()
    assert not (left / "backup-manifest.json").exists()
    assert bk._verify_backup(left) is False


def test_a_write_failure_midway_never_takes_the_backup_name(
    case, tmp_path, monkeypatch
):
    dest = tmp_path / "out"
    _fail_on(monkeypatch, 5, OSError(errno.ENOSPC, "No space left on device"))
    with pytest.raises(OSError):
        bk.create_backup_data(case, str(dest), "tester")
    assert _backup_named(dest) == []


def test_an_interrupted_backup_never_takes_the_backup_name(case, tmp_path, monkeypatch):
    dest = tmp_path / "out"
    _fail_on(monkeypatch, 5, KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        bk.create_backup_data(case, str(dest), "tester")
    assert _backup_named(dest) == []


def test_two_failures_leave_two_separate_marked_copies(case, locked, tmp_path):
    dest = tmp_path / "out"
    for _ in range(2):
        with pytest.raises(OSError):
            bk.create_backup_data(case, str(dest), "tester")
    left = _leftovers(dest)
    assert _backup_named(dest) == []
    assert len(left) == 2
    assert all((p / ".backup-in-progress").exists() for p in left)


def test_a_successful_backup_takes_the_plain_name_and_leaves_nothing_else(
    case, tmp_path
):
    dest = tmp_path / "out"
    result = bk.create_backup_data(case, str(dest), "tester")
    assert Path(result["backup_path"]).name == _plain()
    assert [p.name for p in dest.iterdir()] == [_plain()]
    assert bk._verify_backup(Path(result["backup_path"])) is True


def test_a_second_backup_the_same_day_takes_the_next_number(case, tmp_path):
    dest = tmp_path / "out"
    first = Path(bk.create_backup_data(case, str(dest), "tester")["backup_path"])
    before = hashlib.sha256((first / "backup-manifest.json").read_bytes()).hexdigest()
    entries_before = sorted(str(p.relative_to(first)) for p in first.rglob("*"))
    second = Path(bk.create_backup_data(case, str(dest), "tester")["backup_path"])
    assert second.name == f"{_plain()}-1"
    assert (
        hashlib.sha256((first / "backup-manifest.json").read_bytes()).hexdigest()
        == before
    )
    assert sorted(str(p.relative_to(first)) for p in first.rglob("*")) == entries_before
    assert bk._verify_backup(second) is True
