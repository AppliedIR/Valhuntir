"""A default backup leaves out registered evidence wherever it sits.

backup_case documents "Does NOT include evidence", but scan_case_dir only
treated files under evidence/ as evidence: an image registered at the case
root or under work/ (as idx_ingest_memory's copy is) was copied as case
data. Registered evidence is now evidence wherever it is; an unregistered
file outside evidence/ is still case data.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vhir_cli.commands.backup import create_backup_data, scan_case_dir


def _case(root: Path) -> Path:
    case = root / "BKUP-CASE"
    (case / "work").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: BKUP-CASE\nstatus: open\nname: b\n")
    (case / "findings.json").write_text("[]")
    (case / "root.img").write_bytes(b"\0" * 64)
    (case / "work" / "mem.img").write_bytes(b"\1" * 64)
    (case / "work" / "notes.txt").write_text("unregistered working notes\n")
    registry = {
        "files": [
            {"path": str((case / p).resolve()), "sha256": ""}
            for p in ("root.img", "work/mem.img")
        ]
    }
    (case / "evidence.json").write_text(json.dumps(registry))
    return case


@pytest.fixture(params=["direct", "through a symlink"])
def case(tmp_path, request):
    real = _case(tmp_path / "real")
    if request.param == "direct":
        return real
    link = tmp_path / "linked"
    link.symlink_to(real.parent)
    return link / real.name


def _rels(entries) -> set:
    return {rel for rel, _abs, _size in entries}


def test_registered_files_outside_evidence_are_evidence(case):
    scan = scan_case_dir(case)
    assert {"root.img", "work/mem.img"} <= _rels(scan["evidence"])
    assert not {"root.img", "work/mem.img"} & _rels(scan["case_data"])
    assert "work/notes.txt" in _rels(scan["case_data"])  # unregistered: still case data


def _copied(case: Path, dest: Path, **kw) -> set:
    result = create_backup_data(case, str(dest), "tester", **kw)
    backup = Path(result["backup_path"])
    return {str(p.relative_to(backup)) for p in backup.rglob("*") if p.is_file()}


def test_a_default_backup_leaves_registered_evidence_out(case, tmp_path):
    copied = _copied(case, tmp_path / "out")
    assert "root.img" not in copied and "work/mem.img" not in copied
    assert {"CASE.yaml", "findings.json", "work/notes.txt"} <= copied


def test_include_evidence_still_copies_it(case, tmp_path):
    copied = _copied(case, tmp_path / "out", include_evidence=True)
    assert {"root.img", "work/mem.img", "work/notes.txt"} <= copied


def test_a_case_without_a_registry_backs_up_as_before(tmp_path):
    case = _case(tmp_path / "real")
    (case / "evidence.json").unlink()
    scan = scan_case_dir(case)
    assert {"root.img", "work/mem.img", "work/notes.txt"} <= _rels(scan["case_data"])
