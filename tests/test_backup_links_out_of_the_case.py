"""A backup never stores a file from outside the case as part of the case.

A symlink inside extracted or mounted evidence names a path on the system the
evidence came from: etc/hostname -> /etc/hostname means that system's
hostname. The backup followed it on this machine, so the backup held this
machine's own file under the evidence's path, and verified. Such a link now
fails a backup that includes it, naming the link.

Links the examiner makes to place storage elsewhere still work: a top-level
folder of the case, an entry directly in evidence/ (as evidence_register
suggests), and registered evidence may point anywhere.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import pytest

from vhir_cli.commands import backup as B

FOREIGN = b"content from outside the case\n"


def _case(root: Path) -> Path:
    case = root / "LINK-CASE"
    for d in ("work", "evidence", "extractions/host1/etc", "extractions/host1/usr/lib"):
        (case / d).mkdir(parents=True)
    (case / "reports").mkdir()
    (case / "CASE.yaml").write_text("case_id: LINK-CASE\nstatus: open\nname: l\n")
    (case / "findings.json").write_text("[]")
    (case / "reports" / "r.md").write_text("report\n")
    (case / "extractions/host1/usr/lib/os-release").write_text('NAME="EvidenceOS"\n')
    return case


@pytest.fixture(params=["direct", "through a symlink"])
def case(tmp_path, request):
    real = _case(tmp_path / "real")
    if request.param == "direct":
        return real
    link = tmp_path / "linked"
    link.symlink_to(real.parent)
    return link / real.name


@pytest.fixture
def outside(tmp_path) -> Path:
    """A folder outside the case, standing in for this machine's own files."""
    d = tmp_path / "elsewhere"
    (d / "dir").mkdir(parents=True)
    (d / "hostname").write_bytes(FOREIGN)
    (d / "dir" / "o.txt").write_bytes(FOREIGN)
    return d


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


def _fails_naming(case: Path, dest: Path, name: str, **kw) -> None:
    with pytest.raises(OSError) as exc:
        _backup(case, dest, **kw)
    assert name in str(exc.value) and "outside the case" in str(exc.value)
    copied = [p for p in dest.rglob("*") if p.is_file() and p.read_bytes() == FOREIGN]
    assert copied == []


def _files(result: dict) -> dict:
    backup = Path(result["backup_path"])
    return {
        str(p.relative_to(backup)): p.read_bytes()
        for p in backup.rglob("*")
        if p.is_file()
    }


# --- rows that fail on the unfixed code -------------------------------------


def test_an_absolute_link_in_extracted_evidence_fails_a_backup_that_includes_it(
    case, outside, tmp_path
):
    (case / "extractions/host1/etc/hostname").symlink_to(outside / "hostname")
    _fails_naming(
        case, tmp_path / "out", "host1/etc/hostname", include_extractions=True
    )


def test_a_directory_link_out_of_the_case_fails_the_backup(case, outside, tmp_path):
    (case / "extractions/host1/opt").symlink_to(outside / "dir")
    _fails_naming(case, tmp_path / "out", "host1/opt", include_extractions=True)


def test_a_relative_link_that_climbs_out_of_the_case_fails_the_backup(
    case, outside, tmp_path
):
    etc = case / "extractions/host1/etc"
    rel = os.path.relpath(outside / "hostname", etc.resolve())
    assert rel.startswith("..")
    (etc / "hostname").symlink_to(rel)
    _fails_naming(
        case, tmp_path / "out", "host1/etc/hostname", include_extractions=True
    )


def test_a_link_out_of_the_case_in_case_data_fails_every_backup(
    case, outside, tmp_path
):
    (case / "work/linux/etc").mkdir(parents=True)
    (case / "work/linux/etc/hostname").symlink_to(outside / "hostname")
    _fails_naming(case, tmp_path / "out", "linux/etc/hostname")


def test_a_link_one_level_down_in_work_that_leads_out_fails_the_backup(
    case, outside, tmp_path
):
    (case / "work" / "ext").symlink_to(outside / "dir")
    _fails_naming(case, tmp_path / "out", "work/ext")


def test_a_link_to_a_folder_whose_name_extends_the_case_name_fails_the_backup(
    case, tmp_path
):
    sibling = case.resolve().parent / "LINK-CASE-old"
    sibling.mkdir()
    (sibling / "secret.txt").write_bytes(FOREIGN)
    (case / "work" / "notes").mkdir()
    (case / "work" / "notes" / "peer").symlink_to("../../../LINK-CASE-old")
    _fails_naming(case, tmp_path / "out", "notes/peer")


def test_a_link_inside_evidence_content_fails_a_backup_that_includes_evidence(
    case, outside, tmp_path
):
    (case / "evidence/mnt/etc").mkdir(parents=True)
    (case / "evidence/mnt/etc/hostname").symlink_to(outside / "hostname")
    _fails_naming(case, tmp_path / "out", "mnt/etc/hostname", include_evidence=True)


def test_a_link_inside_evidence_storage_linked_into_the_case_is_still_checked(
    case, outside, tmp_path
):
    store = tmp_path / "store"
    (store / "root/etc").mkdir(parents=True)
    (store / "disk.E01").write_bytes(b"image\n")
    (store / "root/etc/hostname").symlink_to(outside / "hostname")
    (case / "evidence").rmdir()
    (case / "evidence").symlink_to(store)
    _fails_naming(case, tmp_path / "out", "root/etc/hostname", include_evidence=True)


def test_the_cli_reports_a_link_out_of_the_case_as_an_error(
    case, outside, tmp_path, monkeypatch, capsys
):
    (case / "extractions/host1/etc/hostname").symlink_to(outside / "hostname")
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
    assert err.startswith("Error: ") and "host1/etc/hostname" in err


# --- anchors (pass before and after) ----------------------------------------


def test_evidence_linked_in_from_other_storage_is_still_backed_up(case, tmp_path):
    store = tmp_path / "store"
    store.mkdir()
    (store / "disk.E01").write_bytes(b"image\n")
    (case / "evidence" / "disk.E01").symlink_to(store / "disk.E01")
    result = _backup(case, tmp_path / "out", include_evidence=True)
    assert _files(result)["evidence/disk.E01"] == b"image\n"
    assert B._verify_backup(Path(result["backup_path"]))
    assert "evidence/disk.E01" not in _files(_backup(case, tmp_path / "out2"))


def test_an_evidence_folder_on_other_storage_is_still_backed_up(case, tmp_path):
    store = tmp_path / "store"
    (store / "root/usr/bin").mkdir(parents=True)
    (store / "disk.E01").write_bytes(b"image\n")
    (store / "root/usr/bin/tool").write_bytes(b"tool\n")
    (store / "root/bin").symlink_to("usr/bin")  # a link inside the evidence
    (case / "evidence").rmdir()
    (case / "evidence").symlink_to(store)
    files = _files(_backup(case, tmp_path / "out", include_evidence=True))
    assert files["evidence/disk.E01"] == b"image\n"
    assert files["evidence/root/bin/tool"] == files["evidence/root/usr/bin/tool"]


def test_registered_evidence_linked_from_deeper_in_the_case_is_still_backed_up(
    case, tmp_path
):
    store = tmp_path / "store"
    store.mkdir()
    (store / "mem.img").write_bytes(b"memory\n")
    (case / "work" / "images").mkdir()
    (case / "work" / "images" / "mem.img").symlink_to(store / "mem.img")
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str((store / "mem.img").resolve())}]})
    )
    assert "work/images/mem.img" not in _files(_backup(case, tmp_path / "out"))
    files = _files(_backup(case, tmp_path / "out2", include_evidence=True))
    assert files["work/images/mem.img"] == b"memory\n"


def test_a_top_level_folder_on_other_storage_is_still_backed_up(case, tmp_path):
    store = tmp_path / "bigdisk" / "work"
    store.mkdir(parents=True)
    (store / "copy.bin").write_bytes(b"working copy\n")
    (case / "work").rmdir()
    (case / "work").symlink_to(store)
    assert _files(_backup(case, tmp_path / "out"))["work/copy.bin"] == b"working copy\n"


def test_links_that_stay_inside_the_case_are_still_followed(case, tmp_path):
    etc = case / "extractions/host1/etc"
    (etc / "os-release").symlink_to("../usr/lib/os-release")
    (case / "work" / "latest.md").symlink_to(case / "reports" / "r.md")
    files = _files(_backup(case, tmp_path / "out", include_extractions=True))
    assert files["extractions/host1/etc/os-release"] == b'NAME="EvidenceOS"\n'
    assert files["work/latest.md"] == b"report\n"


def test_a_link_out_of_the_case_in_a_part_left_out_does_not_fail_the_backup(
    case, outside, tmp_path
):
    (case / "extractions/host1/etc/hostname").symlink_to(outside / "hostname")
    (case / "evidence/mnt/etc").mkdir(parents=True)
    (case / "evidence/mnt/etc/hostname").symlink_to(outside / "hostname")
    result = _backup(case, tmp_path / "out")
    assert set(_files(result)) == {
        "CASE.yaml",
        "findings.json",
        "reports/r.md",
        "backup-manifest.json",
    }
