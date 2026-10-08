# ruff: noqa: F811 - `case` is the fixture imported below
"""A chain belongs to one case folder.

This box's chain for a case id begins in one folder: its first line records
that folder's identity (CASE.yaml's `case_uuid`). Another folder with the same
case id (a copy) can be read and verified, but it can't sign: signing there
would extend the original's chain and break its verify.
"""

from __future__ import annotations

import json
import shutil

import pytest

from vhir_cli import ledger
from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import _malformed, verify_case

from .test_signed_decisions import IDENT, _run, _signed, _status, case  # noqa: F401


@pytest.fixture(autouse=True)
def _own_home(tmp_path, monkeypatch):
    """Signing records the case's folder in ~/.vhir: each row has its own."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


UUID = "11111111-2222-4333-8444-555555555555"
OTHER = "99999999-8888-4777-8666-555555555555"


def _with_uuid(d, value):
    text = (d / "CASE.yaml").read_text()
    (d / "CASE.yaml").write_text(text + (f"case_uuid: {value}\n" if value else ""))


def _copy(case, tmp_path, value):
    copy = tmp_path / "copy" / "C-9"
    shutil.copytree(case, copy)
    meta = [
        x for x in (copy / "CASE.yaml").read_text().splitlines() if "case_uuid" not in x
    ]
    (copy / "CASE.yaml").write_text("\n".join(meta) + "\n")
    _with_uuid(copy, value)
    return copy


def test_the_first_line_records_the_folder_and_verifies(case):  # noqa: F811
    _with_uuid(case, UUID)
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    (first,) = [o for _, _, o in ledger.read_lines(ledger.chain_path("C-9"))]
    assert first["seq"] == 1 and first["case_uuid"] == UUID
    assert ledger.signature_valid(first)
    assert verify_case(case).exit_code == 0
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    later = [o for _, _, o in ledger.read_lines(ledger.chain_path("C-9"))][1:]
    assert later and all("case_uuid" not in o for o in later)  # the first line binds


def test_a_copy_beside_the_original_can_t_sign_and_the_original_still_verifies(
    case,
    tmp_path,
    monkeypatch,
    capsys,  # noqa: F811
):
    """Sign in the original, copy it (a restore beside it gives the copy its
    own identity), then edit and sign in the copy."""
    _with_uuid(case, UUID)
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    copy = _copy(case, tmp_path, OTHER)
    (copy / "findings.json").chmod(0o644)  # copied as the case leaves it
    findings = json.loads((copy / "findings.json").read_text())
    findings[1]["observation"] = "edited in the copy"
    (copy / "findings.json").write_text(json.dumps(findings))
    before = ledger.chain_path("C-9").read_bytes()
    capsys.readouterr()
    asked = []
    from vhir_cli import approval_auth

    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": asked.append(p))
    # approve a draft there; reject the approved item whose content it changed
    for ids, decision in ((["F-steve-001"], "approve"), (["F-steve-002"], "reject")):
        run = lambda ids=ids, decision=decision: A._approve_specific(  # noqa: E731
            copy, ids, IDENT, copy / "cfg", decision=decision, reason="r"
        )
        assert _run(run) == 1
        out = capsys.readouterr()
        assert out.err.strip().splitlines()[-1] == ledger.copy_text("C-9")
        assert "F-steve-001]" not in out.out  # refused before anything is shown
    assert asked == [] and ledger.chain_path("C-9").read_bytes() == before
    assert verify_case(case).exit_code == 0  # the original is untouched
    assert verify_case(copy).exit_code != 0  # the copy's edit shows as such


def test_a_copy_with_no_identity_is_refused_too(case, tmp_path):  # noqa: F811
    _with_uuid(case, UUID)
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    copy = _copy(case, tmp_path, None)
    assert (
        _run(lambda: A._approve_specific(copy, ["F-steve-001"], IDENT, copy / "cfg"))
        == 1
    )
    assert _signed() == [("F-steve-002", "approve")]


def test_the_commit_refuses_a_copy_under_the_lock_too():
    """Two folders racing to begin the chain: the check before the prompt
    passes in both, and prepare (under the lock) refuses the second."""
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    first = [{"item_id": "F-a-001", "type": "finding", "decision": "approve",
              "status_after": "APPROVED", "content_snapshot": "{}"}]  # fmt: skip
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from vhir_cli import keys

    priv = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(priv))
    with ledger.case_lock("C-R") as lock:
        bodies = ledger.prepare("C-R", first, "a", pub, "cli", "2026-10-08T00:00:00Z",
                                case_uuid=UUID)  # fmt: skip
        ledger.commit(lock, bodies, [ledger.sign_body(b, priv) for b in bodies], pub)
    with ledger.case_lock("C-R"), pytest.raises(ledger.CaseCopy) as raised:
        ledger.prepare("C-R", first, "a", pub, "cli", "2026-10-08T00:00:01Z",
                       case_uuid=OTHER)  # fmt: skip
    assert str(raised.value) == ledger.copy_text("C-R")
    assert ledger.prepare("C-R", first, "a", pub, "cli", "2026-10-08T00:00:01Z",
                          case_uuid=UUID)  # fmt: skip


def test_a_chain_begun_before_folders_were_bound_is_not_checked(
    case,
    tmp_path,  # noqa: F811
):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")  # no case_uuid
    (first,) = [o for _, _, o in ledger.read_lines(ledger.chain_path("C-9"))]
    assert "case_uuid" not in first
    _with_uuid(case, UUID)
    assert (
        _run(lambda: A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg"))
        == 0
    )
    assert _status(case, "findings.json", "F-steve-001") == "APPROVED"


def test_verify_checks_the_field_s_form():
    line = {"v": ledger.VERSION, "view": ledger.VIEW, "seq": 1, "prev": "p",
            "case_id": "C", "item_id": "F-a-001", "type": "finding",
            "decision": "approve", "status_after": "APPROVED", "examiner": "a",
            "at": "t", "mode": "cli", "public_key": "k", "content_sha256": "h",
            "content_snapshot": "{}", "sig": "s"}  # fmt: skip
    assert _malformed(line) == ""
    assert _malformed({**line, "case_uuid": UUID}) == ""
    assert _malformed({**line, "case_uuid": 7}) == "case_uuid"


@pytest.mark.parametrize("how", ["not UTF-8", "unreadable"])
def test_an_unreadable_chain_disables_signing_by_name(case, monkeypatch, capsys, how):
    """The check before anything is shown never raises: it names the problem."""
    from vhir_cli import approval_auth

    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    path = ledger.chain_path("C-9")
    if how == "not UTF-8":
        path.write_bytes(path.read_bytes() + b"\xff\xfe\n")
    else:
        path.chmod(0o000)
    asked = []
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": asked.append(p))
    capsys.readouterr()
    try:
        assert ledger.copy_problem("C-9", None) == ledger.CHAIN_UNREADABLE
        assert (
            _run(
                lambda: A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
            )
            == 1
        )
    finally:
        path.chmod(0o600)
    err = capsys.readouterr().err
    assert err.strip().splitlines()[-1] == ledger.CHAIN_UNREADABLE
    assert "Traceback" not in err and asked == []
