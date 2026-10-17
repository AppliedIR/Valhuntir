"""A backup that leaves out evidence/ or extractions/ doesn't walk it, but
registered evidence it copies is still reached wherever it was registered.

A registered link inside extractions/ resolves to storage outside it, or to a
folder the walk skips (__pycache__/), and a folder can be registered as
extractions/ itself: so when evidence is included and anything is registered,
extractions/ is walked as it was before the prune. With evidence left out,
registered evidence is left out with it, and that is no reason to stop.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from vhir_cli.commands.backup import create_backup_data, scan_case_dir
from vhir_cli.commands.evidence import register_evidence_data


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "PRUNE-CASE"
    for sub in ("evidence/h", "extractions/h"):
        (d / sub).mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: PRUNE-CASE\nstatus: open\nname: p\n")
    (d / "findings.json").write_text("[]")
    (d / "evidence.json").write_text('{"files": []}')
    (d / "evidence/h/e.bin").write_bytes(b"e" * 8)
    (d / "extractions/h/x.bin").write_bytes(b"x" * 8)
    return d


def _kape(k: Path) -> None:
    (k / "C").mkdir(parents=True)
    (k / "C" / "a.evtx").write_bytes(b"A" * 64)


def _hand_register(case: Path, path: Path) -> None:
    """An entry register_evidence_data now refuses (a path under extractions/),
    as an older registry holds it; a folder gets a manifest and its hash."""
    entry = {"path": str(path.relative_to(case))}
    if path.is_dir():
        rows = [
            {"path": str(f.relative_to(case))}
            for f in sorted(path.rglob("*"))
            if f.is_file()
        ]
        (case / "evidence-manifests").mkdir(exist_ok=True)
        m = case / "evidence-manifests" / "1.json"
        m.write_text(json.dumps({"files": rows}))
        entry.update(
            kind="folder",
            manifest_path="evidence-manifests/1.json",
            manifest_sha256=hashlib.sha256(m.read_bytes()).hexdigest(),
        )
    reg = json.loads((case / "evidence.json").read_text())
    reg["files"].append(entry)
    (case / "evidence.json").write_text(json.dumps(reg))


def _file_in_extractions(case, tmp_path):
    (case / "extractions/h/c.bin").write_bytes(b"c" * 8)
    _hand_register(case, case / "extractions/h/c.bin")
    return "extractions/h/c.bin"


def _folder_in_extractions(case, tmp_path):
    _kape(case / "extractions/kape")
    _hand_register(case, case / "extractions/kape")
    return "extractions/kape/C/a.evtx"


def _extractions_itself(case, tmp_path):
    _hand_register(case, case / "extractions")
    return "extractions/h/x.bin"


def _linked_folder_in_extractions(case, tmp_path):
    _kape(tmp_path / "store" / "kape")
    (case / "extractions/kape").symlink_to(tmp_path / "store" / "kape")
    register_evidence_data(case, str(case / "extractions/kape"), "tester")
    return "extractions/kape/C/a.evtx"


def _linked_file_in_extractions(case, tmp_path):
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "f.bin").write_bytes(b"f" * 8)
    (case / "extractions/h/f.bin").symlink_to(tmp_path / "store" / "f.bin")
    register_evidence_data(case, str(case / "extractions/h/f.bin"), "tester")
    return "extractions/h/f.bin"


def _the_whole_case(case, tmp_path):
    _hand_register(case, case)
    return "extractions/h/x.bin"


def _file_in_evidence(case, tmp_path):
    register_evidence_data(case, str(case / "evidence/h/e.bin"), "tester")
    return "evidence/h/e.bin"


def _folder_in_evidence(case, tmp_path):
    _kape(case / "evidence/kape")
    register_evidence_data(case, str(case / "evidence/kape"), "tester")
    return "evidence/kape/C/a.evtx"


IN_EXTRACTIONS = [
    _file_in_extractions,
    _folder_in_extractions,
    _extractions_itself,
    _linked_folder_in_extractions,
    _linked_file_in_extractions,
    _the_whole_case,
]
IN_EVIDENCE = [_file_in_evidence, _folder_in_evidence]


def _backup(case, tmp_path, **kw) -> Path:
    dest = tmp_path / "out"
    dest.mkdir()
    return Path(create_backup_data(case, str(dest), "tester", **kw)["backup_path"])


@pytest.mark.parametrize("shape", IN_EXTRACTIONS, ids=lambda f: f.__name__[1:])
def test_registered_evidence_in_a_left_out_extractions_is_still_copied(
    case, tmp_path, shape
):
    rel = shape(case, tmp_path)
    backup = _backup(case, tmp_path, include_evidence=True, include_extractions=False)
    assert (backup / rel).is_file()


@pytest.mark.parametrize("shape", IN_EXTRACTIONS, ids=lambda f: f.__name__[1:])
def test_with_evidence_left_out_registered_evidence_in_extractions_stays_out(
    case, tmp_path, shape
):
    rel = shape(case, tmp_path)
    backup = _backup(case, tmp_path, include_evidence=False, include_extractions=False)
    assert not (backup / rel).exists()
    assert not (backup / "extractions").exists()


@pytest.mark.parametrize("shape", IN_EVIDENCE, ids=lambda f: f.__name__[1:])
def test_registered_evidence_in_a_left_out_evidence_stays_out_without_a_stop(
    case, tmp_path, shape
):
    rel = shape(case, tmp_path)
    walked: list[str] = []
    real_walk = os.walk

    def walk(top, *a, **kw):
        for root, dirs, files in real_walk(top, *a, **kw):
            walked.append(root)
            yield root, dirs, files

    os.walk = walk
    try:
        backup = _backup(
            case, tmp_path, include_evidence=False, include_extractions=True
        )
    finally:
        os.walk = real_walk
    assert not (backup / rel).exists()
    assert (backup / "extractions/h/x.bin").is_file()
    ev = str(case / "evidence")
    assert not any(r == ev or r.startswith(ev + os.sep) for r in walked)


@pytest.mark.parametrize("shape", IN_EVIDENCE, ids=lambda f: f.__name__[1:])
def test_registered_evidence_in_evidence_is_copied_with_extractions_left_out(
    case, tmp_path, shape
):
    rel = shape(case, tmp_path)
    backup = _backup(case, tmp_path, include_evidence=True, include_extractions=False)
    assert (backup / rel).is_file()
    assert not (backup / "extractions").exists()
    scan = scan_case_dir(case)
    assert any(r == rel for r, _a, _s in scan["evidence"])


def _walked(case, tmp_path, **kw) -> tuple[Path, list[str]]:
    walked: list[str] = []
    real_walk = os.walk

    def walk(top, *a, **kwa):
        for root, dirs, files in real_walk(top, *a, **kwa):
            walked.append(root)
            yield root, dirs, files

    os.walk = walk
    try:
        backup = _backup(case, tmp_path, **kw)
    finally:
        os.walk = real_walk
    return backup, walked


def _under(walked: list[str], d: Path) -> bool:
    return any(r == str(d) or r.startswith(str(d) + os.sep) for r in walked)


def _register_in_evidence_and_work(case):
    (case / "work").mkdir()
    (case / "work" / "w.bin").write_bytes(b"w" * 8)
    register_evidence_data(case, str(case / "evidence/h/e.bin"), "tester")
    register_evidence_data(case, str(case / "work/w.bin"), "tester")


@pytest.mark.parametrize(
    "include_evidence, registers, walks",
    [(True, True, True), (True, False, False), (False, True, False)],
    ids=["evidence-in-registered", "evidence-in-none-registered", "evidence-out"],
)
def test_a_left_out_extractions_is_walked_only_for_registered_evidence(
    case, tmp_path, include_evidence, registers, walks
):
    if registers:
        _register_in_evidence_and_work(case)
    backup, walked = _walked(
        case, tmp_path, include_evidence=include_evidence, include_extractions=False
    )
    assert _under(walked, case / "extractions") is walks
    assert not (backup / "extractions").exists()
    if registers and include_evidence:
        assert (backup / "evidence/h/e.bin").is_file()
        assert (backup / "work/w.bin").is_file()


def _file_link_to_root_pycache(case):
    (case / "__pycache__").mkdir()
    (case / "__pycache__/image.E01").write_bytes(b"i" * 8)
    (case / "extractions/image.E01").symlink_to(case / "__pycache__/image.E01")
    _hand_register(case, case / "__pycache__/image.E01")
    return "extractions/image.E01"


def _dir_link_to_work_pycache(case):
    (case / "work/__pycache__").mkdir(parents=True)
    (case / "work/__pycache__/f.bin").write_bytes(b"f" * 8)
    (case / "extractions/d").symlink_to(case / "work/__pycache__")
    _hand_register(case, case / "work/__pycache__/f.bin")
    return "extractions/d/f.bin"


@pytest.mark.parametrize("skip", [False, True], ids=["stop", "skip-unreadable"])
@pytest.mark.parametrize(
    "shape", [_file_link_to_root_pycache, _dir_link_to_work_pycache], ids=["s29", "s23"]
)
def test_registered_evidence_the_walk_skips_is_copied_through_an_extractions_link(
    case, tmp_path, shape, skip
):
    rel = shape(case)
    dest = tmp_path / "out"
    dest.mkdir()
    result = create_backup_data(
        case,
        str(dest),
        "tester",
        include_evidence=True,
        include_extractions=False,
        skip_unreadable=skip,
    )
    assert (Path(result["backup_path"]) / rel).is_file()
    assert result["skipped"] == []


@pytest.mark.parametrize(
    "include_evidence, registers",
    [(False, True), (True, False)],
    ids=["evidence-out-registered", "evidence-in-none-registered"],
)
def test_included_extractions_is_copied(case, tmp_path, include_evidence, registers):
    if registers:
        _register_in_evidence_and_work(case)
    backup = _backup(
        case, tmp_path, include_evidence=include_evidence, include_extractions=True
    )
    assert (backup / "extractions/h/x.bin").is_file()
