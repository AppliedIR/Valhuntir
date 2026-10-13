"""A backup made into a folder inside the case doesn't copy earlier backups.

The scan copied the whole case, earlier backups and the one being written
included, so each backup into <case>/backups held all the ones before it
(4 -> 9 -> 19 files), and the in-progress marker of the running one ended up
inside it. A folder holding a backup manifest or the in-progress marker is
now left out, and listed in the backup's result as skipped; it must be
Valhuntir's own (its manifest's fields, or its marker), so another tool's
backup-manifest.json beside evidence doesn't hide that evidence.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vhir_cli.commands.backup import create_backup_data


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "BK-CASE"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: BK-CASE\nstatus: open\nname: b\n")
    (case / "findings.json").write_text("[]")
    (case / "notes.txt").write_bytes(b"n" * 100_000)
    return case


def _files(backup: Path) -> list[Path]:
    return [p for p in backup.rglob("*") if p.is_file()]


def _three(case: Path, destinations) -> list[Path]:
    return [
        Path(create_backup_data(case, str(dest), "tester")["backup_path"])
        for dest in destinations
    ]


@pytest.mark.parametrize(
    "where",
    ["backups", ".", "rotating"],
    ids=["a folder in the case", "the case itself", "rotating folders"],
)
def test_backups_into_the_case_stay_the_same_size(case, where):
    if where == "rotating":
        destinations = [case / "backups" / f"r{n}" for n in (1, 2, 3)]
    else:
        destinations = [case / where] * 3
    backups = _three(case, destinations)
    # The data copied; the manifest itself grows by one line per earlier
    # backup, as it lists each one as skipped
    sizes = [
        (
            len(_files(b)),
            sum(
                p.stat().st_size for p in _files(b) if p.name != "backup-manifest.json"
            ),
        )
        for b in backups
    ]
    assert sizes[0] == sizes[1] == sizes[2], sizes
    for backup in backups:  # on disk: the manifest's walk hides the marker
        assert not list(backup.rglob(".backup-in-progress")), backup
        assert not list(backup.rglob("*/backup-manifest.json")), backup


def test_anchor_an_examiners_file_in_the_destination_is_kept(case):
    (case / "backups").mkdir()
    (case / "backups" / "README.txt").write_text("where the backups go")
    for backup in _three(case, [case / "backups"] * 3):
        assert (backup / "backups" / "README.txt").is_file(), _files(backup)


def test_anchor_a_destination_outside_the_case_is_unchanged(case, tmp_path):
    backups = _three(case, [tmp_path / "out"] * 3)
    assert [len(_files(b)) for b in backups] == [len(_files(backups[0]))] * 3


def test_each_earlier_backup_is_listed_as_skipped(case):
    results = [
        create_backup_data(case, str(case / "backups"), "tester") for _ in range(3)
    ]
    assert results[0]["skipped"] == []
    listed = [s["path"] for s in results[2]["skipped"]]
    assert listed == sorted(
        str(Path(r["backup_path"]).relative_to(case)) for r in results[:2]
    ), results[2]["skipped"]
    assert {s["reason"] for s in results[2]["skipped"]} == {
        "an earlier Valhuntir backup"
    }


@pytest.mark.parametrize(
    "manifest",
    [{"tool": "other", "files": ["a"]}, "not json"],
    ids=["another tool's manifest", "unreadable manifest"],
)
def test_evidence_beside_another_tools_manifest_is_backed_up(case, tmp_path, manifest):
    folder = case / "work" / "collected"
    folder.mkdir(parents=True)
    (folder / "backup-manifest.json").write_text(
        manifest if isinstance(manifest, str) else json.dumps(manifest)
    )
    (folder / "notes.txt").write_text("examiner notes")
    (folder / ".backup-in-progress").write_text("")  # not Valhuntir's marker
    result = create_backup_data(case, str(tmp_path / "out"), "tester")
    backup = Path(result["backup_path"])
    assert (backup / "work" / "collected" / "notes.txt").is_file()
    assert result["skipped"] == []


def test_a_manifest_nested_too_deep_is_not_vhir_s(case, tmp_path):
    folder = case / "work" / "deep"
    folder.mkdir(parents=True)
    (folder / "backup-manifest.json").write_text("[" * 100_000 + "]" * 100_000)
    (folder / "notes.txt").write_text("examiner notes")
    result = create_backup_data(case, str(tmp_path / "out"), "tester")
    assert (Path(result["backup_path"]) / "work" / "deep" / "notes.txt").is_file()


def test_another_tool_s_in_progress_file_is_backed_up_and_listed(case, tmp_path):
    folder = case / "work" / "collected"
    folder.mkdir(parents=True)
    (folder / ".backup-in-progress").write_text("another tool's")
    result = create_backup_data(case, str(tmp_path / "out"), "tester")
    backup = Path(result["backup_path"])
    manifest = json.loads((backup / "backup-manifest.json").read_text())
    listed = {f["path"] for f in manifest["files"]}
    assert "work/collected/.backup-in-progress" in listed, sorted(listed)
    assert not (backup / ".backup-in-progress").exists()  # its own is gone
