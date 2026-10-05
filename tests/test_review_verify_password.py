"""A mistyped password at `vhir review --verify` is reported as a wrong
password, not as tampering.

The typed password went straight into the HMAC check, so a typo marked every
entry TAMPERED and raised the tampering ALERT. Now it's checked against the
examiner's stored password first; on a mismatch that examiner's entries are
skipped with a "Wrong password" line, and the next examiner is still checked.
Real password files and a real signed ledger, all under tmp_path.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest

import vhir_cli.approval_auth as auth
import vhir_cli.verification as ver
from vhir_cli.commands.review import _show_hmac_verification

PASSWORDS = {"alice": "alice-pass-1", "steve": "steve-pass-1"}


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home" / ".vhir").mkdir(parents=True)
    monkeypatch.setattr(auth, "_PASSWORDS_DIR", tmp_path / "passwords")
    monkeypatch.setattr(ver, "VERIFICATION_DIR", tmp_path / "ledger")
    config = tmp_path / "home" / ".vhir" / "config.yaml"
    for name, pw in PASSWORDS.items():
        with patch.object(auth, "getpass_prompt", side_effect=[pw, pw]):
            auth.setup_password(config, name)
    case = tmp_path / "C-1"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: C-1\nstatus: open\n")

    def sign(examiner, item_id, password=None):
        key = ver.derive_hmac_key(
            password or PASSWORDS[examiner], auth.get_analyst_salt(config, examiner)
        )
        snap = f"{item_id} content"
        ver.write_ledger_entry(
            "C-1",
            {
                "finding_id": item_id,
                "type": "finding",
                "hmac": ver.compute_hmac(key, snap),
                "content_snapshot": snap,
                "approved_by": examiner,
                "case_id": "C-1",
            },
        )

    return case, sign


def _verify(case_dir, capsys, *answers):
    with patch.object(auth, "getpass_prompt", side_effect=list(answers)):
        _show_hmac_verification(case_dir)
    out = capsys.readouterr().out
    return out[out.index("HMAC Verification") :]  # the HMAC block only


def test_a_wrong_password_is_not_reported_as_tampering(case, capsys):
    case_dir, sign = case
    sign("steve", "F-steve-001")
    sign("steve", "F-steve-002")
    out = _verify(case_dir, capsys, "typo")
    assert "Wrong password for 'steve'; their entries were not verified." in out
    assert "TAMPERED" not in out and "ALERT" not in out


def test_anchor_the_right_password_confirms(case, capsys):
    case_dir, sign = case
    sign("steve", "F-steve-001")
    out = _verify(case_dir, capsys, PASSWORDS["steve"])
    assert "CONFIRMED" in out and "TAMPERED" not in out and "Wrong password" not in out


def test_a_tampered_entry_is_still_caught(case, capsys):
    case_dir, sign = case
    sign("steve", "F-steve-001")
    sign("steve", "F-steve-002", password="not-the-real-one")  # its HMAC doesn't match
    out = _verify(case_dir, capsys, PASSWORDS["steve"])
    assert re.search(r"F-steve-002\s+TAMPERED", out) and "ALERT" in out
    assert re.search(r"F-steve-001\s+CONFIRMED", out)


def test_a_wrong_password_for_one_examiner_still_checks_the_next(case, capsys):
    case_dir, sign = case
    sign("alice", "F-alice-001")
    sign("steve", "F-steve-001")
    out = _verify(case_dir, capsys, "typo", PASSWORDS["steve"])  # alice first
    assert "Wrong password for 'alice'" in out
    assert re.search(r"F-steve-001\s+CONFIRMED", out) and "TAMPERED" not in out


def test_anchor_no_local_credential_is_still_skipped_as_before(case, capsys):
    case_dir, sign = case
    ver.write_ledger_entry(
        "C-1",
        {
            "finding_id": "F-bob-001",
            "hmac": "x",
            "content_snapshot": "s",
            "approved_by": "bob",
        },
    )
    out = _verify(case_dir, capsys, "anything")
    assert (
        "Skipped: No salt found for analyst 'bob'" in out
        and "Wrong password" not in out
    )
