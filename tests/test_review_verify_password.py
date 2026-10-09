"""`vhir review --verify` needs no password, no terminal and no credential file.

It asked for each examiner's password on the terminal to check HMAC lines
keyed by it, so a typo could read as tampering, and no check could run
without the examiners at a terminal. Lines are now checked with the public
key each one carries: verify asks for nothing, and examiners with no
credential on this box verify the same way.
"""

from __future__ import annotations

import io
import json
import re
from argparse import Namespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import approval_auth, keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.commands.review import cmd_review

from .signing import NOT_CHECKED

AT = "2026-10-08T10:00:00+00:00"


@pytest.fixture
def case(tmp_path, monkeypatch):
    def no_prompt(*a, **k):
        raise AssertionError("verify asked for a password")

    monkeypatch.setattr(approval_auth, "getpass_prompt", no_prompt)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))  # no terminal input
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-1\nstatus: open\n")
    (d / "timeline.json").write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    return d


def _approve(case, examiner, n):
    """`examiner` approves finding n with a key no credential file on this box holds."""
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    item = {"id": f"F-{examiner}-{n:03d}", "title": "t", "status": "DRAFT"}
    decision = {"item_id": item["id"], "type": "finding", "decision": "approve", "checks": NOT_CHECKED,
                "status_after": "APPROVED", "coupled_from": None,
                "content_snapshot": signed_text(item, "finding")}  # fmt: skip
    bodies = ledger.prepare("C-1", [decision], examiner, pub, "cli", AT)
    with ledger.case_lock("C-1") as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    return dict(item, status="APPROVED", approved_by=examiner, approved_at=AT)


def _verify(capsys):
    args = Namespace(
        case=None,
        verify=True,
        mine=False,
        expect_key=None,
        expect_head=None,
        ledger=None,
    )
    with pytest.raises(SystemExit) as e:
        cmd_review(args, {"examiner": "steve"})
    return capsys.readouterr().out, e.value.code


def test_two_examiners_verify_with_no_prompt_and_no_credential(case, capsys):
    items = [_approve(case, "alice", 1), _approve(case, "steve", 1)]
    (case / "findings.json").write_text(json.dumps(items))
    assert not list(approval_auth._PASSWORDS_DIR.glob("*.json"))
    assert not list(keys.KEYS_DIR.glob("*.json"))
    out, code = _verify(capsys)
    assert re.search(r"F-alice-001\s+VALID", out) and re.search(
        r"F-steve-001\s+VALID", out
    )
    assert code == 0 and "not registered here" in out


def test_a_changed_item_fails_with_no_prompt(case, capsys):
    item = _approve(case, "steve", 1)
    (case / "findings.json").write_text(json.dumps([dict(item, title="changed")]))
    out, code = _verify(capsys)
    assert re.search(r"F-steve-001\s+ALTERED_AFTER_APPROVAL", out) and code == 2


def test_the_password_check_is_gone_from_review():
    import vhir_cli.commands.review as review

    for name in ("_show_hmac_verification", "_show_ledger_reconciliation"):
        assert not hasattr(review, name)
