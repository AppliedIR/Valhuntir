# ruff: noqa: F401, F811 - `box` is the fixture imported below
"""A case reached through a link keeps its evidence on a box without that
link, and a manifest path in another spelling is refused.

Evidence is registered by real path; the backup records the case's real path
beside its source, and every restore that verified re-points the registry
from it, in place too. A backup without it lists such evidence as outside
the restored case. A manifest entry whose path isn't in normal form (`./x`,
`x/./y`, `x//y`, `x/`) is an alias a control-path check would miss, so
`--verify` and restore refuse the backup before anything is written.
"""

from __future__ import annotations

import json

import pytest

import vhir_cli.commands.backup as B

from .test_backup_restore_truth import CASE, _sha, box, make_backup, restore

DISK = b"\x00evidence\n"


def _linked_backup(box, realpath="data"):
    """A backup of <tmp>/cases/C-7, which was a link to <tmp>/data/C-7: its
    registry names the evidence by that real path."""
    real = box.tmp / "data" / CASE
    reg = {
        "files": [{"path": str(real / "evidence" / "disk.img"), "sha256": _sha(DISK)}]
    }
    registry = json.dumps(reg).encode()
    bk = make_backup(box, ledger=False, snapshot=False,
                     extra={"evidence/disk.img": DISK, "evidence.json": registry})  # fmt: skip
    m = json.loads((bk / "backup-manifest.json").read_text())
    if realpath == "data":
        m["source_realpath"] = str(real)
    elif realpath is not None:
        m["source_realpath"] = realpath
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    return bk


def _registered(target) -> list[str]:
    return [
        e["path"] for e in json.loads((target / "evidence.json").read_text())["files"]
    ]


@pytest.mark.parametrize("where", ["in place", "elsewhere"])
def test_evidence_follows_a_case_reached_through_a_link(box, capsys, where):
    target = box.tmp / ("cases" if where == "in place" else "elsewhere") / CASE
    assert restore(_linked_backup(box), target) == 0
    assert _registered(target) == [str(target.resolve() / "evidence" / "disk.img")]
    out = capsys.readouterr().out
    assert f"1 registry path(s) now point to {target}" in out
    assert "outside" not in out


@pytest.mark.parametrize(
    "realpath", [None, "data/C-7", 7], ids=["absent", "relative", "not-a-path"]
)
def test_without_a_usable_real_path_in_place_evidence_is_listed_outside(
    box, capsys, realpath
):
    """A backup made before the real path was recorded: loud, not silent."""
    target = box.tmp / "cases" / CASE
    assert restore(_linked_backup(box, realpath), target) == 0
    real = str(box.tmp / "data" / CASE / "evidence" / "disk.img")
    assert _registered(target) == [real]
    out = capsys.readouterr().out
    assert "Evidence still registered outside the restored case" in out and real in out


def test_an_unlinked_case_restored_in_place_prints_nothing_new(box, capsys):
    target = box.tmp / "cases" / CASE
    reg = {
        "files": [{"path": str(target / "evidence" / "disk.img"), "sha256": _sha(DISK)}]
    }
    bk = make_backup(box, ledger=False, snapshot=False,
                     extra={"evidence/disk.img": DISK,
                            "evidence.json": json.dumps(reg).encode()})  # fmt: skip
    m = json.loads((bk / "backup-manifest.json").read_text())
    m["source_realpath"] = m["source"]
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    assert restore(bk, target) == 0
    assert _registered(target) == [str(target / "evidence" / "disk.img")]
    assert "Evidence" not in capsys.readouterr().out


def test_a_relative_real_path_re_points_nothing(box):
    """Only an absolute real path is read: `.` would match a case-relative
    registry entry."""
    reg = {"files": [{"path": "evidence/disk.img", "sha256": _sha(DISK)}]}
    bk = make_backup(box, ledger=False, snapshot=False,
                     extra={"evidence/disk.img": DISK,
                            "evidence.json": json.dumps(reg).encode()})  # fmt: skip
    m = json.loads((bk / "backup-manifest.json").read_text())
    m["source_realpath"] = "."
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    target = box.tmp / "cases" / CASE
    assert restore(bk, target) == 0
    assert _registered(target) == ["evidence/disk.img"]


@pytest.mark.parametrize(
    "alias",
    ["./findings.json", "audit/./a.jsonl", "audit//a.jsonl", "audit/a.jsonl/", "audit/."],
)  # fmt: skip
def test_a_path_not_in_normal_form_refuses_the_backup(box, capsys, alias):
    bk = make_backup(
        box, ledger=False, snapshot=False, extra={"audit/a.jsonl": b"{}\n"}
    )
    m = json.loads((bk / "backup-manifest.json").read_text())
    m["files"].append({"path": alias, "sha256": _sha(b"{}\n")})
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    assert B._verify_backup(bk) is False
    assert "isn't a file path its backup writes" in capsys.readouterr().err
    target = box.tmp / "cases" / CASE
    assert restore(bk, target) == 1
    assert "isn't a file path its backup writes" in capsys.readouterr().err
    assert not target.exists() and box.sudo == []


@pytest.mark.parametrize("extra", ["normal", "repeated"])
def test_a_normal_or_repeated_path_is_accepted(box, extra):
    bk = make_backup(
        box, ledger=False, snapshot=False, extra={"audit/a.jsonl": b"{}\n"}
    )
    if extra == "repeated":
        m = json.loads((bk / "backup-manifest.json").read_text())
        m["files"].append(dict(m["files"][0]))
        (bk / "backup-manifest.json").write_text(json.dumps(m))
    assert B._verify_backup(bk) is True
    assert restore(bk, box.tmp / "cases" / CASE) == 0
