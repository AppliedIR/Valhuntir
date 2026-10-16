"""Registered evidence the backup can't reach stops a backup that includes
evidence, wherever the link or folder hiding it sits; it is never left out
without a word."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vhir_cli.commands import backup as B

pytestmark = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)

IMAGE = b"registered image\n"


def _case(root: Path) -> Path:
    case = root / "REG-CASE"
    for d in ("work", "evidence", "extractions/x", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: REG-CASE\nstatus: open\nname: r\n")
    (case / "findings.json").write_text("[]")
    (case / "reports" / "r.md").write_text("report\n")
    return case


@pytest.fixture(params=["direct", "through a symlink"])
def case(tmp_path, request):
    real = _case(tmp_path / "real")
    if request.param == "direct":
        return real
    link = tmp_path / "linked"
    link.symlink_to(real.parent)
    return link / real.name


def _register(case: Path, path: Path) -> None:
    # the product stores the resolved path
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": str(path.resolve())}]})
    )


def _store(tmp_path: Path, shape: str) -> tuple[Path, str]:
    """Storage outside the case holding the image; returns it and the image's
    path below the link."""
    store = tmp_path / "store"
    store.mkdir()
    if shape == "directly in the linked folder":
        (store / "disk.E01").write_bytes(IMAGE)
        return store, "disk.E01"
    if shape == "two folders down":
        (store / "sub/deeper").mkdir(parents=True)
        (store / "sub/deeper/disk.E01").write_bytes(IMAGE)
        return store, "sub/deeper/disk.E01"
    other = tmp_path / "store2"  # the store links the image in from more storage
    other.mkdir()
    (other / "disk.E01").write_bytes(IMAGE)
    (store / "disk.E01").symlink_to(other / "disk.E01")
    return store, "disk.E01"


SHAPES = ["directly in the linked folder", "two folders down", "linked on again"]


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


def _copied(dest: Path) -> list[Path]:
    return [p for p in dest.rglob("*") if p.is_file() and p.read_bytes() == IMAGE]


@pytest.mark.parametrize("shape", SHAPES)
def test_registered_evidence_behind_a_link_in_extractions_stops_a_backup_with_evidence(
    case, tmp_path, shape
):
    store, below = _store(tmp_path, shape)
    (case / "extractions/x/store").symlink_to(store)
    _register(case, case / "extractions/x/store" / below)
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out", include_evidence=True)
    assert str(exc.value).startswith("Backup stopped before copying")
    assert _copied(tmp_path / "out") == []


@pytest.mark.parametrize("shape", SHAPES)
def test_the_skip_option_lists_registered_evidence_it_could_not_reach(
    case, tmp_path, shape
):
    store, below = _store(tmp_path, shape)
    (case / "extractions/x/store").symlink_to(store)
    _register(case, case / "extractions/x/store" / below)
    result = _backup(
        case, tmp_path / "out", include_evidence=True, skip_unreadable=True
    )
    assert result["skipped"]
    assert _copied(Path(result["backup_path"])) == []


def test_registered_evidence_behind_a_link_does_not_stop_a_backup_without_evidence(
    case, tmp_path
):
    store, below = _store(tmp_path, SHAPES[0])
    (case / "extractions/x/store").symlink_to(store)
    _register(case, case / "extractions/x/store" / below)
    result = _backup(case, tmp_path / "out")
    assert result["skipped"] == []


def test_a_loop_above_registered_evidence_in_extractions_does_not_stop_the_backup(
    case, tmp_path
):
    # the loop's own folder is scanned on its own path, so the evidence is reached
    (case / "extractions/x/disk.E01").write_bytes(IMAGE)
    (case / "extractions/x/again").symlink_to(".")
    _register(case, case / "extractions/x/disk.E01")
    result = _backup(case, tmp_path / "out", include_evidence=True)
    assert result["skipped"] == []
    assert [
        str(p.relative_to(result["backup_path"]))
        for p in _copied(Path(result["backup_path"]))
    ] == ["extractions/x/disk.E01"]


def test_a_link_out_in_extractions_without_registered_evidence_still_backs_up(
    case, tmp_path
):
    store, _below = _store(tmp_path, SHAPES[0])
    (case / "extractions/x/store").symlink_to(store)
    result = _backup(case, tmp_path / "out", include_evidence=True)
    assert result["skipped"] == []
    assert _copied(Path(result["backup_path"])) == []


def test_the_stop_names_unreached_registered_evidence_and_how_to_reach_it(
    case, tmp_path
):
    store, below = _store(tmp_path, SHAPES[0])
    (case / "extractions/x/store").symlink_to(store)
    _register(case, case / "extractions/x/store" / below)
    with pytest.raises(OSError) as exc:
        _backup(case, tmp_path / "out", include_evidence=True)
    assert f"{(store / below).resolve()}: registered evidence" in str(exc.value)
    assert "link the storage at the top of the case or of evidence/" in str(exc.value)
