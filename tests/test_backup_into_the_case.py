"""A backup made into a folder inside the case doesn't copy earlier backups.

The scan copied the whole case, earlier backups and the one being written
included, so each backup into <case>/backups held all the ones before it
(4 -> 9 -> 19 files), and the in-progress marker of the running one ended up
inside it. A folder holding a backup manifest or the in-progress marker is
now left out; everything else in the destination is still backed up.
"""

from __future__ import annotations

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
    sizes = [
        (len(_files(b)), sum(p.stat().st_size for p in _files(b))) for b in backups
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
