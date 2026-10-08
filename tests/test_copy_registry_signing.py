# ruff: noqa: F401, F811 - `box` is the fixture imported below
"""A hand copy of a case folder can't sign into the original's chain.

A `cp -r` copy shares its case's identity. This box records which folder
holds each identity (at activation, and now at the first signed commit, under
the case lock): the first folder to sign is taken as the original, and any
other folder holding the identity is refused by name. A record that can't be
read refuses signing; it never lets a copy through.
"""

from __future__ import annotations

import json
import shutil

import pytest

from vhir_cli import approval_auth, ledger
from vhir_cli.case_identity import _paths_file, copy_text, new_identity
from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import verify_case

from .signing import PASSPHRASE, enrol
from .test_backup_case_identity import _identity, _meta, box, pytestmark

IDENT = {"examiner": "tester", "os_user": "tester", "analyst": "tester"}


@pytest.fixture
def fresh(box, monkeypatch, tmp_path):
    """A case with an identity that was never activated: no record of its folder."""
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    enrol("tester")
    _identity(box.case)
    (box.case / "findings.json").write_text(json.dumps([
        {"id": f"F-tester-00{n}", "title": "t", "observation": "o", "interpretation": "i",
         "confidence": "LOW", "status": "DRAFT"} for n in (1, 2, 3)
    ]))  # fmt: skip
    assert not _paths_file().exists()
    return box


def _copy(case, name="C-1-cp"):
    copy = case.parent / name
    shutil.copytree(case, copy)
    for f in copy.glob("*.json"):
        f.chmod(0o644)
    return copy


def _sign(case, ids):
    try:
        A._approve_specific(case, ids, IDENT, case / "cfg")
    except SystemExit as e:
        return e.code
    return 0


def _recorded():
    return json.loads(_paths_file().read_text())


def _chain():
    path = ledger.chain_path("C-1")
    return path.read_bytes() if path.exists() else b""


def test_the_first_folder_to_sign_is_recorded_and_a_copy_is_then_refused(fresh, capsys):
    case = fresh.case
    uuid = _meta(case)["case_uuid"]
    copy = _copy(case)  # made before anything was signed
    assert _sign(case, ["F-tester-001"]) == 0
    assert _recorded() == {uuid: str(case.resolve())}
    before = _chain()
    capsys.readouterr()
    assert _sign(copy, ["F-tester-002"]) == 1
    err = capsys.readouterr().err.strip().splitlines()[-1]
    assert err == copy_text(str(copy.resolve()), str(case.resolve()), uuid)
    assert _chain() == before


def test_a_copy_that_signed_first_refuses_the_original_with_the_way_back(fresh, capsys):
    """The original is refused by name; following the recovery it prints
    lets the original sign again, and the copy gets its own identity."""
    case = fresh.case
    uuid = _meta(case)["case_uuid"]
    copy = _copy(case)
    assert _sign(copy, ["F-tester-001"]) == 0  # the copy is taken as the original
    capsys.readouterr()
    assert _sign(case, ["F-tester-002"]) == 1
    err = capsys.readouterr().err.strip().splitlines()[-1]
    assert err == copy_text(str(case.resolve()), str(copy.resolve()), uuid)
    assert f"move {copy.resolve()} aside" in err
    assert "new-identity` on the copy, never on the original" in err
    # the way back: move the copy aside, sign in the original, move the copy
    # back and give it its own identity
    aside = copy.with_name("C-1-cp.aside")
    copy.rename(aside)
    assert _sign(case, ["F-tester-002"]) == 0  # the stale record gives way
    assert _recorded() == {uuid: str(case.resolve())}
    aside.rename(copy)
    new_identity(copy)
    assert _meta(copy)["case_uuid"] != uuid and _meta(case)["case_uuid"] == uuid
    assert _sign(copy, ["F-tester-003"]) == 1  # its first line binds the original
    assert _sign(case, ["F-tester-003"]) == 0


def test_an_unreadable_record_refuses_signing(fresh, capsys, monkeypatch):
    _paths_file().parent.mkdir(parents=True, exist_ok=True)
    _paths_file().write_text("{not json")
    asked = []
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": asked.append(p))
    assert _sign(fresh.case, ["F-tester-001"]) == 1
    err = capsys.readouterr().err.strip().splitlines()[-1]
    assert "case-paths.json can't be read" in err and "move it aside" in err
    assert asked == [] and _chain() == b""
    assert _paths_file().read_text() == "{not json"  # never overwritten


def test_a_copy_recorded_while_the_original_signs_is_caught_at_the_commit(
    fresh, monkeypatch, capsys
):
    """Both pass the check before the prompt (no record yet); the copy is
    recorded in between, and the original's commit, under the lock, refuses."""
    from vhir_cli import credentials
    from vhir_cli.case_identity import record_case_path

    case = fresh.case
    copy = _copy(case)
    real = credentials.unlock

    def unlock(*a, **k):
        record_case_path(copy)  # the copy is activated meanwhile
        return real(*a, **k)

    monkeypatch.setattr(credentials, "unlock", unlock)
    assert _sign(case, ["F-tester-001"]) == 1
    err = capsys.readouterr().err
    assert (
        copy_text(str(case.resolve()), str(copy.resolve()), _meta(case)["case_uuid"])
        in err
    )
    assert _chain() == b""  # nothing signed; the decision is kept unsigned
    pending = json.loads((case / "pending-reviews.json").read_text())
    assert [e["id"] for e in pending["items"]] == ["F-tester-001"]


def test_a_cancelled_review_records_nothing(fresh, monkeypatch):
    def interrupt(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(approval_auth, "getpass_prompt", interrupt)
    assert _sign(fresh.case, ["F-tester-001"]) == 130
    assert not _paths_file().exists()


def test_activation_still_refuses_a_copy_of_a_recorded_case(fresh):
    from vhir_cli.case_identity import record_case_path

    case = fresh.case
    assert _sign(case, ["F-tester-001"]) == 0
    copy = _copy(case)
    with pytest.raises(ValueError, match="so both would write into the same indices"):
        record_case_path(copy)
    assert verify_case(case).exit_code == 0
