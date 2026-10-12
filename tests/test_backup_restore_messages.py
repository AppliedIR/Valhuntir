"""Backup and restore say what they did: no silent claim, no wrong refusal,
no traceback, no advice that can't be followed.

- The manifest's point_in_time names the case's own 0.6 copy that the
  backup's lock moved beside the box's.
- A backup made before the case had an identity, restored beside an original
  that has one now, gets the copy note.
- A CASE.yaml that is a named pipe is named with --include-opensearch too.
- A CASE.yaml that isn't UTF-8 is refused by name.
- A folder this box recorded for the case whose CASE.yaml can't be read
  doesn't hold the case: activation goes on, naming it.
- A case-relative evidence entry isn't "outside"; without sift-common the
  copy hint doesn't send the examiner to new-identity; the approvals note
  appears only when the backup holds approvals.jsonl.

Each leg runs `vhir` (main) with real arguments in this process.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B
from vhir_cli import verification

from .test_backup_restore_cli_legs import (
    _reachable_cluster,
    _within,
    _without_sift_common,
    backed_up,
    make_case,
    meta,
    only_backup,
    vhir,
)


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A scratch HOME, cases folder and backup destination (as the CLI legs' own)."""
    for name in ("home", "cases", "out"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    return tmp_path


BAD = b"case_id: C-1\nname: caf\xe9\nstatus: open\n"  # latin-1: not UTF-8
POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)


def test_the_case_s_0_6_copy_moved_beside_is_named_in_point_in_time(tmp_path):
    case = tmp_path / "cases" / "C-PIT"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: C-PIT\nstatus: open\n")
    (case / "findings.json").write_text("[]")
    (case / "verification.jsonl").write_text('{"note": "the case copy"}\n')
    verification.VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    (verification.VERIFICATION_DIR / "C-PIT.jsonl").write_text(
        '{"note": "the box file"}\n'
    )
    b = Path(B.create_backup_data(case, str(tmp_path / "out"), "alice")["backup_path"])
    m = json.loads((b / "backup-manifest.json").read_text())
    (beside,) = [p.name for p in b.glob("verification.*.jsonl")]
    assert (b / beside).read_text() == '{"note": "the case copy"}\n'
    assert beside in {e["path"] for e in m["files"]}
    assert beside in m["point_in_time"]["files"]


def test_a_pre_identity_backup_beside_an_original_that_gained_one_gets_the_copy_note(
    box,
    capsys,
):
    pytest.importorskip(
        "sift_common", reason="activating the original needs sift-common"
    )
    make_case(box)
    bk = backed_up(box, capsys)  # no case_uuid yet
    assert vhir(capsys, "case", "activate", "C-1")[0] == 0  # the original gains one
    assert not meta(bk).get("case_uuid") and meta(box / "cases" / "C-1").get(
        "case_uuid"
    )
    target = box / "cases" / "C-1-copy"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 0, out
    assert "Restored beside the original" in out


@POSIX
def test_with_opensearch_asked_for_a_pipe_at_case_yaml_is_named_not_hidden(
    box,
    capsys,
    monkeypatch,
):
    src = make_case(box)
    (src / "CASE.yaml").unlink()
    os.mkfifo(src / "CASE.yaml")
    _reachable_cluster(box, monkeypatch)
    code, out = _within(20, src / "CASE.yaml", lambda: vhir(
        capsys, "backup", "--case", "C-1", box / "out", "--include-opensearch"))  # fmt: skip
    assert code == 1
    assert f"{src / 'CASE.yaml'} isn't a regular file" in out
    assert "OpenSearch is not available" not in out
    assert list((box / "out").iterdir()) == []


def test_a_restore_beside_an_original_whose_case_yaml_isnt_utf8_is_refused_by_name(
    box,
    capsys,
):
    src = make_case(box)
    bk = backed_up(box, capsys)
    (src / "CASE.yaml").write_bytes(BAD)
    target = box / "cases" / "C-1-copy"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 1 and f"{src / 'CASE.yaml'} isn't UTF-8 text" in out
    assert not target.exists()


def test_a_backup_of_a_case_whose_case_yaml_isnt_utf8_is_refused_by_name(box, capsys):
    src = make_case(box)
    (src / "CASE.yaml").write_bytes(BAD)
    code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
    assert code == 1 and f"{src / 'CASE.yaml'} isn't UTF-8 text" in out
    assert list((box / "out").iterdir()) == []


@POSIX
@pytest.mark.parametrize("unreadable", ["pipe", "not utf-8"])
def test_a_recorded_folder_whose_case_yaml_cant_be_read_doesnt_hold_the_case(
    box,
    capsys,
    unreadable,
):
    uuid = "1d1d1d1d-2e2e-4f4f-8a8a-9b9b9b9b9b9b"
    case = make_case(box)
    (case / "CASE.yaml").write_text(
        f"case_id: C-1\ncase_uuid: {uuid}\nnaming_version: 2\nstatus: open\n"
    )
    old = box / "cases" / "C-1-old"
    old.mkdir()
    if unreadable == "pipe":
        os.mkfifo(old / "CASE.yaml")
    else:
        (old / "CASE.yaml").write_bytes(BAD)
    paths = box / "home" / ".vhir" / "case-paths.json"
    paths.parent.mkdir(exist_ok=True)
    paths.write_text(json.dumps({uuid: str(old.resolve())}))
    code, out = _within(
        20, old / "CASE.yaml", lambda: vhir(capsys, "case", "activate", "C-1")
    )
    assert code == 0, out
    assert str(old / "CASE.yaml") in out and "Warning" in out
    assert json.loads(paths.read_text())[uuid] == str(case.resolve())


# --- texts ---------------------------------------------------------------------


def test_a_case_relative_evidence_entry_is_not_called_outside(box, capsys):
    src = make_case(box)
    (src / "evidence").mkdir()
    (src / "evidence" / "x.bin").write_bytes(b"x")
    (src / "evidence.json").write_text(
        json.dumps({"files": [{"path": "evidence/x.bin", "sha256": "0" * 64}]})
    )
    assert (
        vhir(capsys, "backup", "--case", "C-1", box / "out", "--include-evidence")[0]
        == 0
    )
    target = box / "cases" / "R"
    code, out = vhir(
        capsys, "restore", only_backup(box), "--target", target, "--skip-opensearch"
    )
    assert code == 0, out
    assert "still registered outside" not in out


def test_without_sift_common_the_copy_note_doesnt_send_the_examiner_to_new_identity(
    box, capsys, monkeypatch
):
    make_case(box)
    bk = backed_up(box, capsys)
    _without_sift_common(monkeypatch)
    target = box / "cases" / "C-1-copy"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 0, out
    assert "Restored beside the original" in out
    assert "vhir case new-identity" not in out


def test_the_manifest_names_approvals_jsonl_only_when_the_backup_holds_it(box, capsys):
    make_case(box)
    bk = backed_up(box, capsys)
    notes = json.loads((bk / "backup-manifest.json").read_text()).get("notes", [])
    assert not (bk / "approvals.jsonl").exists()
    assert not any("approvals.jsonl" in n for n in notes)


def test_a_case_s_approvals_jsonl_keeps_its_note(box, capsys):
    src = make_case(box)
    (src / "approvals.jsonl").write_text("{}\n")
    bk = backed_up(box, capsys)
    notes = json.loads((bk / "backup-manifest.json").read_text()).get("notes", [])
    assert (bk / "approvals.jsonl").exists()
    assert any("approvals.jsonl" in n for n in notes)


def test_recovery_never_promises_a_box_ledger_restore():
    from vhir_cli import ledger_verify

    assert not any("box ledger" in t for t in ledger_verify.RECOVERY.values())


def test_with_opensearch_asked_for_a_case_yaml_that_isnt_utf8_is_named_not_hidden(
    box, capsys, monkeypatch
):
    src = make_case(box)
    (src / "CASE.yaml").write_bytes(BAD)
    _reachable_cluster(box, monkeypatch)
    code, out = vhir(
        capsys, "backup", "--case", "C-1", box / "out", "--include-opensearch"
    )
    assert code == 1
    assert f"{src / 'CASE.yaml'} isn't UTF-8 text" in out
    assert "OpenSearch is not available" not in out
    assert list((box / "out").iterdir()) == []


@pytest.mark.parametrize("path", ["../shared/x.bin", "evidence/../../shared/x.bin"])
def test_a_relative_evidence_entry_that_leaves_the_case_is_named_outside(
    box, capsys, path
):
    src = make_case(box)
    (src / "evidence").mkdir()
    (src / "evidence" / "x.bin").write_bytes(b"x")
    (src / "evidence.json").write_text(json.dumps({"files": [
        {"path": "evidence/x.bin", "sha256": "0" * 64}, {"path": path, "sha256": "1" * 64}]}))  # fmt: skip
    # the registry travels as case data (--include-evidence would refuse an entry
    # outside the case before copying)
    code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
    assert code == 0, out
    target = box / "cases" / "R"
    code, out = vhir(
        capsys, "restore", only_backup(box), "--target", target, "--skip-opensearch"
    )
    assert code == 0, out
    listed = out.split("still registered outside the restored case:")[-1].splitlines()
    assert f"    {path}" in listed
    assert "    evidence/x.bin" not in listed
