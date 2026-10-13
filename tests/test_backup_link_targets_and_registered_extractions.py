"""Registered evidence under extractions/ counts as evidence, and a link is
judged only against the storage linked in on its own path."""

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

FOREIGN = b"content from outside the case\n"


def _case(root: Path) -> Path:
    case = root / "ROW-CASE"
    for d in ("work", "evidence", "extractions/x", "reports"):
        (case / d).mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: ROW-CASE\nstatus: open\nname: r\n")
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


@pytest.fixture
def outside(tmp_path) -> Path:
    d = tmp_path / "elsewhere"
    d.mkdir()
    (d / "hostname").write_bytes(FOREIGN)
    return d


def _backup(case: Path, dest: Path, **kw) -> dict:
    return B.create_backup_data(case, str(dest), "tester", **kw)


# registered evidence under extractions/ that can't be read
def test_unreadable_registered_evidence_in_extractions_stops_a_backup_with_evidence(
    case, tmp_path
):
    f = case / "extractions/x/reg.bin"
    f.write_bytes(b"evidence\n")
    (case / "evidence.json").write_text(
        json.dumps({"files": [{"path": "extractions/x/reg.bin"}]})
    )
    f.chmod(0o000)
    try:
        with pytest.raises(OSError) as exc:
            _backup(case, tmp_path / "out", include_evidence=True)
        assert "extractions/x/reg.bin: Permission denied" in str(exc.value)
        result = _backup(
            case, tmp_path / "out2", include_evidence=True, skip_unreadable=True
        )
        assert [s["path"] for s in result["skipped"]] == ["extractions/x/reg.bin"]
    finally:
        f.chmod(0o644)


# an allowed link at the top of the case or of evidence/ must not let a link
# elsewhere in the case lead out
@pytest.mark.parametrize(
    "allowed",
    ["evidence/__pycache__ -> /", "evidence/root -> /", "evidence/broad", "broad"],
)
def test_a_link_in_work_cannot_lead_out_through_storage_linked_in_elsewhere(
    case, outside, tmp_path, allowed
):
    name, _, target = allowed.partition(" -> ")
    (case / name).symlink_to(target or outside)
    (case / "work" / "host").symlink_to(outside / "hostname")
    dest = tmp_path / "out"
    with pytest.raises(OSError) as exc:
        _backup(case, dest)
    line = [x for x in str(exc.value).splitlines() if "work/host" in x]
    assert line and "outside the case" in line[0]
    assert not [p for p in dest.rglob("*") if p.is_file() and p.read_bytes() == FOREIGN]


# anchor: a link between entries of evidence storage linked in still works
def test_a_link_between_entries_of_linked_evidence_storage_is_still_followed(
    case, tmp_path
):
    store = tmp_path / "store"
    (store / "a").mkdir(parents=True)
    (store / "disk.E01").write_bytes(b"image\n")
    (store / "a" / "l.E01").symlink_to("../disk.E01")
    (case / "evidence").rmdir()
    (case / "evidence").symlink_to(store)
    result = _backup(case, tmp_path / "out", include_evidence=True)
    backup = Path(result["backup_path"])
    assert (backup / "evidence/a/l.E01").read_bytes() == b"image\n"
