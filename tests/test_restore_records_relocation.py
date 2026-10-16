"""A restore to another folder records the move in the case's audit trail.

The audit lines are restored byte for byte, so the paths they recorded still
name the folder the case was backed up from. Restore appends one relocation
entry to each log (the folder it came from, the one it's in now, and the
backup manifest's hash), and changes no other byte; provenance maps the lines
before it through it. A restore in place, or one that fails verification,
appends nothing.

Nothing here runs sudo: the backup module's subprocess calls are recorded.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import types
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B

IDENTITY = {"examiner": "analyst1", "os_user": "testuser"}
FIELDS = {"audit_id", "tool", "ts", "relocated_from", "to", "manifest_sha256"}


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(
        B,
        "subprocess",
        types.SimpleNamespace(
            run=lambda *a, **k: types.SimpleNamespace(
                returncode=0, stdout="", stderr=""
            )
        ),
    )


def _case(parent: Path) -> Path:
    """A case with two logs; the second's last line has no newline."""
    case = parent / "CASE1"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: CASE1\nstatus: open\nname: r\n")
    (case / "findings.json").write_text("[]")
    out = str(case / "extractions" / "out.csv")
    (case / "audit" / "sift-mcp.jsonl").write_text(
        json.dumps({"audit_id": "sift-a-1", "tool": "run_command", "outputs": [out]})
        + "\n"
        + json.dumps({"audit_id": "sift-a-2", "tool": "run_command"})
        + "\n"
    )
    (case / "audit" / "forensic-mcp.jsonl").write_bytes(
        json.dumps({"audit_id": "forensic-a-1", "tool": "record_finding"}).encode()
    )
    return case


def _lines(case: Path) -> dict[str, list[str]]:
    """Each log's lines, as their SHA-256."""
    return {
        p.name: [hashlib.sha256(x).hexdigest() for x in p.read_bytes().splitlines()]
        for p in sorted((case / "audit").glob("*.jsonl"))
    }


def _restore(backup: str, target) -> None:
    args = types.SimpleNamespace(
        backup_path=backup, skip_opensearch=True, skip_ledger=True, target=str(target)
    )
    B.cmd_restore(args, IDENTITY)


def _backup(tmp_path) -> tuple[Path, str]:
    case = _case(tmp_path / "cases")
    out = B.create_backup_data(case, str(tmp_path / "out"), "analyst1")
    return case, out["backup_path"]


@pytest.mark.parametrize("where", ["beside", "elsewhere"])
def test_a_restore_to_another_folder_appends_one_relocation_entry_to_each_log(
    tmp_path, where
):
    case, backup = _backup(tmp_path)
    before = _lines(case)
    if where == "elsewhere":
        shutil.move(str(case), str(tmp_path / "moved-away"))
        target = tmp_path / "cases2" / "CASE1"
    else:
        target = tmp_path / "cases" / "CASE1-copy"
    _restore(backup, target)
    after = _lines(target)
    assert set(after) == set(before)
    manifest = Path(backup) / "backup-manifest.json"
    ids = set()
    for name, lines in after.items():
        assert lines[:-1] == before[name]  # every other line, byte for byte
        last = (target / "audit" / name).read_bytes().splitlines()[-1]
        entry = json.loads(last)
        assert set(entry) == FIELDS and entry["tool"] == "restore"
        assert entry["relocated_from"] == [str(case)]
        assert entry["to"] == str(target.resolve())
        sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        assert entry["manifest_sha256"] == sha
        ids.add(entry["audit_id"])
    assert len(ids) == 1  # one restore, one entry
    assert (target / "audit" / "sift-mcp.jsonl").read_bytes().endswith(b"\n")


def test_the_entry_names_each_folder_by_its_real_path_too(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "cases").symlink_to(real)
    case, backup = _backup(tmp_path)
    _restore(backup, tmp_path / "cases" / "CASE1-copy")
    last = (real / "CASE1-copy" / "audit" / "sift-mcp.jsonl").read_bytes()
    entry = json.loads(last.splitlines()[-1])
    assert entry["relocated_from"] == [str(case), str(real / "CASE1")]
    assert entry["to"] == str(real / "CASE1-copy")


def test_a_restore_in_place_appends_nothing(tmp_path):
    case, backup = _backup(tmp_path)
    before = _lines(case)
    shutil.rmtree(case, onerror=lambda f, p, e: (os.chmod(p, 0o755), f(p)))
    _restore(backup, case)
    assert _lines(case) == before


def test_a_restore_that_fails_verification_appends_nothing(tmp_path):
    case, backup = _backup(tmp_path)
    before = _lines(case)
    copied = Path(backup) / "findings.json"
    copied.chmod(0o644)
    copied.write_text('[{"changed": true}]')
    target = tmp_path / "cases2" / "CASE1"
    with pytest.raises(SystemExit):
        _restore(backup, target)
    assert _lines(target) == before
