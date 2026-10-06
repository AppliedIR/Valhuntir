"""A backup with paths it can't read or follow stops before copying anything,
lists every such path with its reason and says how to continue; the skip
option finishes the backup, and the manifest, verify and restore list what was
left out.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

import pytest

from vhir_cli.commands import backup as B
from vhir_cli.main import build_parser

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)

FOREIGN = b"content from outside the case\n"

# each is one problem in case data: relative path -> words its reason uses
KINDS = {
    "work/locked": "Permission denied",  # an unreadable directory
    "work/noexec/inside.txt": "Permission denied",  # a dir that can't be searched
    "work/scratch/gone.txt": "broken symlink",
    "work/scratch/loopa": "loop",  # a file symlink loop
    "work/scratch/loopb": "loop",
    "work/loop": "loop",  # a directory symlink loop
    "work/linux/etc/hostname": "outside the case",
    "work/scratch/unreadable.txt": "Permission denied",  # an unreadable file
}

_LOCKED: list[Path] = []


def _case(root: Path) -> Path:
    case = root / "SKIP-CASE"
    for d in ("work/scratch", "evidence", "extractions", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: SKIP-CASE\nstatus: open\nname: s\n")
    (case / "findings.json").write_text("[]")
    (case / "reports" / "r.md").write_text("report\n")
    (case / "work" / "scratch" / "notes.txt").write_text("notes\n")
    return case


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


@pytest.fixture
def outside(tmp_path) -> Path:
    f = tmp_path / "elsewhere" / "hostname"
    f.parent.mkdir()
    f.write_bytes(FOREIGN)
    return f


def _lock(p: Path, mode: int) -> None:
    p.chmod(mode)
    _LOCKED.append(p)


def _make(case: Path, rel: str, outside: Path) -> None:
    p = case / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if rel == "work/locked":
        p.mkdir()
        (p / "inside.txt").write_text("x\n")
        _lock(p, 0o000)
    elif rel == "work/noexec/inside.txt":
        p.write_text("x\n")
        _lock(p.parent, 0o444)
    elif rel == "work/scratch/gone.txt":
        p.symlink_to("missing.txt")
    elif rel == "work/scratch/loopa":
        p.symlink_to("loopb")
        (case / "work/scratch/loopb").symlink_to("loopa")
    elif rel == "work/loop":
        p.symlink_to("..")
    elif rel == "work/linux/etc/hostname":
        p.symlink_to(outside)
    elif rel == "work/scratch/unreadable.txt":
        p.write_text("x\n")
        _lock(p, 0o000)


def _all(case: Path, outside: Path) -> None:
    for rel in KINDS:
        if rel != "work/scratch/loopb":
            _make(case, rel, outside)


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


def _copied(dest: Path) -> list[str]:
    """Case files that reached the destination (markers aside)."""
    return sorted(
        str(p.relative_to(dest))
        for p in dest.rglob("*")
        if p.is_file() and p.name != ".backup-in-progress"
    )


def _manifest(result: dict) -> dict:
    return json.loads(
        (Path(result["backup_path"]) / "backup-manifest.json").read_text()
    )


# --- rows that fail on the unfixed code -------------------------------------


def test_every_problem_is_listed_before_anything_is_copied(case, outside, tmp_path):
    _all(case, outside)
    dest = tmp_path / "out"
    with pytest.raises(OSError) as exc:
        _backup(case, dest)
    msg = str(exc.value)
    first, *listed = msg.splitlines()
    assert "--skip-unreadable" in first and "skip_unreadable" in first
    for rel in KINDS:
        assert any(line.rstrip().split(": ")[0].endswith(rel) for line in listed), rel
    assert len(listed) == len(KINDS)
    assert _copied(dest) == []


@pytest.mark.parametrize("rel", [k for k in KINDS if k != "work/scratch/loopb"])
def test_each_kind_of_problem_stops_the_backup_and_is_named(
    case, outside, tmp_path, rel
):
    _make(case, rel, outside)
    dest = tmp_path / "out"
    with pytest.raises(OSError) as exc:
        _backup(case, dest)
    lines = [line.strip() for line in str(exc.value).splitlines()[1:]]
    (line,) = [x for x in lines if x.split(": ")[0].endswith(rel)]
    assert KINDS[rel] in line.split(": ", 1)[1]
    assert not any("loop/work" in x for x in lines)  # the link, not a path through it
    assert _copied(dest) == []


def test_the_skip_option_finishes_and_lists_every_skipped_path(case, outside, tmp_path):
    _all(case, outside)
    result = _backup(case, tmp_path / "out", skip_unreadable=True)
    manifest = _manifest(result)
    assert {s["path"] for s in manifest["skipped"]} == set(KINDS)
    assert all(KINDS[s["path"]] in s["reason"] for s in manifest["skipped"])
    assert result["skipped"] == manifest["skipped"]
    paths = {f["path"] for f in manifest["files"]}
    assert {"CASE.yaml", "work/scratch/notes.txt", "reports/r.md"} <= paths
    assert not any(p.startswith(tuple(KINDS)) for p in paths)
    backup = Path(result["backup_path"])
    assert not [
        p for p in backup.rglob("*") if p.is_file() and p.read_bytes() == FOREIGN
    ]
    assert B._verify_backup(backup)


def test_a_directory_loop_is_skipped_not_copied_over_and_over(case, tmp_path):
    (case / "work" / "loop").symlink_to("..")
    result = _backup(case, tmp_path / "out", skip_unreadable=True)
    manifest = _manifest(result)
    assert [s["path"] for s in manifest["skipped"]] == ["work/loop"]
    assert manifest["file_count"] == 4  # CASE.yaml, findings, report, notes


def test_verify_lists_the_skipped_paths_and_still_passes(
    case, outside, tmp_path, capsys
):
    _make(case, "work/scratch/gone.txt", outside)
    _make(case, "work/locked", outside)
    result = _backup(case, tmp_path / "out", skip_unreadable=True)
    capsys.readouterr()
    assert B._verify_backup(Path(result["backup_path"])) is True
    out = capsys.readouterr().out
    assert "SKIPPED: work/scratch/gone.txt" in out
    assert "SKIPPED: work/locked" in out
    assert "PASSED" in out


def test_restore_says_what_was_skipped(case, outside, tmp_path, capsys, monkeypatch):
    _make(case, "work/scratch/gone.txt", outside)
    result = _backup(case, tmp_path / "out", skip_unreadable=True)
    shutil.move(str(case.resolve()), str(tmp_path / "moved-away"))
    monkeypatch.setattr(B.sys.stdin, "isatty", lambda: False, raising=False)
    capsys.readouterr()
    B.cmd_restore(
        argparse.Namespace(
            backup_path=result["backup_path"], skip_opensearch=True, skip_ledger=True
        ),
        {"examiner": "tester"},
    )
    out = capsys.readouterr().out
    assert "SKIPPED: work/scratch/gone.txt" in out
    assert (case / "work" / "scratch" / "notes.txt").read_text() == "notes\n"


def test_the_cli_skip_option_reaches_the_backup(
    case, outside, tmp_path, monkeypatch, capsys
):
    _make(case, "work/scratch/gone.txt", outside)
    monkeypatch.setattr(B, "get_case_dir", lambda _case: case)
    monkeypatch.setattr(B, "_detect_opensearch", lambda _case: {"available": False})
    args = build_parser().parse_args(
        ["backup", str(tmp_path / "out"), "--all", "--skip-unreadable"]
    )
    B.cmd_backup(args, {"examiner": "tester"})
    assert "SKIPPED: work/scratch/gone.txt" in capsys.readouterr().out


def test_the_cli_lists_every_problem_as_one_error(
    case, outside, tmp_path, monkeypatch, capsys
):
    _all(case, outside)
    monkeypatch.setattr(B, "get_case_dir", lambda _case: case)
    monkeypatch.setattr(B, "_detect_opensearch", lambda _case: {"available": False})
    args = build_parser().parse_args(["backup", str(tmp_path / "out"), "--all"])
    with pytest.raises(SystemExit) as exc:
        B.cmd_backup(args, {"examiner": "tester"})
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("Error: Backup stopped before copying")
    assert all(rel in err for rel in KINDS)


def test_problems_in_parts_the_backup_leaves_out_are_not_listed(case, tmp_path):
    (case / "evidence" / "disk.E01").symlink_to("/nonexistent-for-test/disk.E01")
    noexec = case / "evidence" / "noexec"
    noexec.mkdir()
    (noexec / "x.bin").write_text("x\n")
    _lock(noexec, 0o444)
    (case / "extractions" / "gone").symlink_to("missing")
    result = _backup(case, tmp_path / "out")
    assert "skipped" not in _manifest(result)
    assert result["file_count"] == 4


# --- anchors (pass before and after) ----------------------------------------


def test_a_case_without_problems_gets_the_same_manifest_and_verify(
    case, tmp_path, capsys
):
    result = _backup(case, tmp_path / "out")
    manifest = _manifest(result)
    assert "skipped" not in manifest
    assert manifest["file_count"] == 4
    capsys.readouterr()
    assert B._verify_backup(Path(result["backup_path"]))
    assert "SKIPPED" not in capsys.readouterr().out


def test_a_readable_unix_tree_with_inside_links_still_backs_up(case, tmp_path):
    root = case / "work" / "tree"
    (root / "usr" / "bin").mkdir(parents=True)
    (root / "usr" / "bin" / "tool").write_text("tool\n")
    (root / "bin").symlink_to("usr/bin")
    (root / "sbin").symlink_to("bin")
    result = _backup(case, tmp_path / "out")
    paths = {f["path"] for f in _manifest(result)["files"]}
    assert {
        "work/tree/bin/tool",
        "work/tree/sbin/tool",
        "work/tree/usr/bin/tool",
    } <= paths


def test_a_link_to_a_folder_whose_name_starts_its_own_is_not_a_loop(case, tmp_path):
    (case / "reports-old").mkdir()
    (case / "reports-old" / "current").symlink_to("../reports")
    result = _backup(case, tmp_path / "out")
    paths = {f["path"] for f in _manifest(result)["files"]}
    assert "reports-old/current/r.md" in paths
