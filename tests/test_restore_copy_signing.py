# ruff: noqa: F401, F811 - `box` is the fixture imported below
"""A restored or copied case beside its original can't sign.

This box's chain for a case id belongs to the folder that began it (its
first line records that folder's identity). A copy beside the original (a
restore with --target while the original is there, or `cp -r`) can be read
and verified, but signing in it is refused before anything is shown. A case
restored after its original is gone is the case: it keeps its identity and
signs.
"""

from __future__ import annotations

import json
import shutil
from argparse import Namespace

import pytest
import yaml

import vhir_cli.commands.backup as B
from vhir_cli import approval_auth, ledger
from vhir_cli.case_identity import record_case_path
from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import verify_case

from .signing import PASSPHRASE, enrol
from .test_backup_case_identity import _backup, _identity, _meta, _restore, box

IDENT = {"examiner": "tester", "os_user": "tester", "analyst": "tester"}


@pytest.fixture
def signed(box, monkeypatch, tmp_path):
    """The case with an identity and a finding approved with a signed line."""
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    enrol("tester")
    _identity(box.case)
    (box.case / "findings.json").write_text(json.dumps([
        {"id": f"F-tester-00{n}", "title": "t", "observation": "o", "interpretation": "i",
         "confidence": "LOW", "status": "DRAFT"} for n in (1, 2)
    ]))  # fmt: skip
    record_case_path(box.case)
    A._approve_specific(box.case, ["F-tester-001"], IDENT, box.case / "cfg")
    (first,) = [o for _, _, o in ledger.read_lines(ledger.chain_path("C-1"))]
    assert first["case_uuid"] == _meta(box.case)["case_uuid"]
    box.os.existing = set()
    return box


def _sign(case, ids, decision="approve"):
    try:
        A._approve_specific(
            case, ids, IDENT, case / "cfg", decision=decision, reason="r"
        )
    except SystemExit as e:
        return e.code
    return 0


def _chain():
    return ledger.chain_path("C-1").read_bytes()


def test_a_copy_restored_beside_the_original_can_t_sign(signed, capsys):
    """CR's probe: back up, restore beside with --target, edit and sign in
    the copy. The copy is refused; the original's chain and verify stand."""
    path = _backup(signed)
    copy = signed.tmp / "cases" / "C-1-copy"
    capsys.readouterr()
    _restore(path, copy)
    out = capsys.readouterr().out
    assert B.cannot_sign_text("C-1", str(signed.case)) in out
    assert f"vhir case activate C-1-copy --cases-dir {copy.parent}" in out
    findings = json.loads((copy / "findings.json").read_text())
    findings[0]["observation"] = "edited in the copy"
    (copy / "findings.json").chmod(0o644)
    (copy / "findings.json").write_text(json.dumps(findings))
    before = _chain()
    assert _sign(copy, ["F-tester-002"]) == 1
    assert _sign(copy, ["F-tester-001"], "reject") == 1
    err = capsys.readouterr().err
    assert ledger.copy_text("C-1") in err
    assert _chain() == before
    assert verify_case(signed.case).exit_code == 0
    assert _sign(signed.case, ["F-tester-002"]) == 0  # the original still signs


def test_a_case_restored_after_its_original_is_gone_keeps_its_identity_and_signs(
    signed, capsys
):
    uuid = _meta(signed.case)["case_uuid"]
    path = _backup(signed)
    shutil.rmtree(signed.case)
    moved = signed.tmp / "cases" / "C-1-moved"
    capsys.readouterr()
    _restore(path, moved)
    out = capsys.readouterr().out
    assert _meta(moved)["case_uuid"] == uuid and "can't sign" not in out
    assert _sign(moved, ["F-tester-002"]) == 0
    assert [o["item_id"] for _, _, o in ledger.read_lines(ledger.chain_path("C-1"))] == [
        "F-tester-001", "F-tester-002"]  # fmt: skip
    assert verify_case(moved).exit_code == 0


def test_a_cp_r_copy_sharing_the_identity_can_t_sign(signed, capsys):
    copy = signed.tmp / "cases" / "C-1-cp"
    shutil.copytree(signed.case, copy)
    for f in copy.glob("*.json"):
        f.chmod(0o644)
    assert _meta(copy)["case_uuid"] == _meta(signed.case)["case_uuid"]
    before = _chain()
    capsys.readouterr()
    assert _sign(copy, ["F-tester-002"]) == 1
    err = capsys.readouterr().err.strip().splitlines()[-1]
    assert err == (
        f"{copy.resolve()} is a copy of the case in {signed.case.resolve()}: both have "
        f"case identity {_meta(copy)['case_uuid']}. Sign in {signed.case.resolve()}."
    )
    assert _chain() == before


def test_new_identity_says_the_copy_can_t_sign(signed, capsys):
    from vhir_cli.main import _case_new_identity

    copy = signed.tmp / "cases" / "C-1-cp"
    shutil.copytree(signed.case, copy)
    for f in copy.glob("*.json"):
        f.chmod(0o644)
    capsys.readouterr()
    _case_new_identity(Namespace(case_id="C-1-cp", cases_dir=str(copy.parent)))
    out = capsys.readouterr().out
    assert "can be read and verified, but can't sign" in out
    assert _sign(copy, ["F-tester-002"]) == 1
    assert ledger.copy_text("C-1") in capsys.readouterr().err


def test_the_closing_hint_names_the_restored_folder(box, capsys):
    _identity(box.case)
    path = _backup(box)
    target = box.tmp / "elsewhere" / "INC-X"
    _restore(path, target)
    out = capsys.readouterr().out
    assert f"vhir case activate INC-X --cases-dir {target.parent}" in out
    assert "vhir case activate C-1\n" not in out
    assert yaml.safe_load((target / "CASE.yaml").read_text())["case_id"] == "C-1"
