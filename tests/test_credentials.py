"""The credential commands: setup (enrol), reset, forgot, upgrade, and the
checks and prompt every signing command runs.

The state of `passwords/{x}.json` picks the path: a 0.6 credential there is
upgraded (a keys file found beside it is set aside, never adopted); otherwise
`keys/{x}.json` is the credential. Credentials are made with the real key
derivation under the redirected /var/lib/vhir.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import approval_auth, credentials, keys, ledger
from vhir_cli.case_io import signed_text

PW = "plum orbit lantern 2026"
NEW = "quiet river copper 1987"
OLD_06 = "lab-pass-0.6"  # a 0.6 password of 12 characters


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    return tmp_path / "config.yaml"


def _typed(monkeypatch, *answers):
    replies = iter(answers)
    monkeypatch.setattr(
        approval_auth, "getpass_prompt", lambda prompt="": next(replies)
    )


def _legacy(password: str) -> None:
    """A 0.6 (schema 1) credential for steve."""
    salt = bytes(range(32))
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()
    approval_auth._PASSWORDS_DIR.mkdir(parents=True, exist_ok=True)
    (approval_auth._PASSWORDS_DIR / "steve.json").write_text(
        json.dumps({"hash": digest, "salt": salt.hex()})
    )


def _sha(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sign_line(case_id: str, examiner: str, key: Ed25519PrivateKey) -> None:
    """One signed line in the box chain for `case_id`, by `examiner` with `key`."""
    pub = keys.b64(keys.public_raw(key))
    item = {"id": f"F-{examiner}-001", "title": "t", "status": "DRAFT"}
    d = {"item_id": item["id"], "type": "finding", "decision": "approve",
         "status_after": "APPROVED", "coupled_from": None,
         "content_snapshot": signed_text(item, "finding")}  # fmt: skip
    bodies = ledger.prepare(
        case_id, [d], examiner, pub, "cli", "2026-10-08T10:00:00+00:00"
    )
    with ledger.case_lock(case_id) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


# --- Setup (enrol) -------------------------------------------------------------------


def test_setup_makes_a_key_and_prints_its_fingerprint(config, monkeypatch, capsys):
    _typed(monkeypatch, PW, PW)
    credentials.enrol("steve", config)
    data = keys.load("steve")
    assert keys.check_password(data, PW)
    out = capsys.readouterr().out
    assert keys.key_fingerprint(keys.active(data)) in out
    assert credentials.FINGERPRINT_NOTE in out


@pytest.mark.parametrize("held", ["schema 3", "0.6"])
def test_setup_refuses_an_examiner_who_has_a_credential_and_changes_nothing(
    config, monkeypatch, held
):
    if held == "0.6":
        _legacy(OLD_06)
        path = approval_auth._PASSWORDS_DIR / "steve.json"
    else:
        keys.save("steve", keys.new_credential("steve", PW))
        path = keys.keys_path("steve")
    before = _sha(path)
    _typed(monkeypatch)  # no prompt may be reached
    with pytest.raises(credentials.CredentialError, match="already has a credential"):
        credentials.enrol("steve", config)
    assert _sha(path) == before


def test_setup_records_a_key_this_name_signed_with_here_as_retired(config, monkeypatch):
    earlier = Ed25519PrivateKey.generate()
    _sign_line("C1", "steve", earlier)
    _typed(monkeypatch, PW, PW)
    credentials.enrol("steve", config)
    retired = [k for k in keys.load("steve")["keys"] if k["status"] == "retired"]
    assert [k["public_key"] for k in retired] == [keys.b64(keys.public_raw(earlier))]
    assert retired[0]["retired_reason"] == "found in ledger, not confirmed"


def test_a_passphrase_the_rule_rejects_three_times_sets_nothing(
    config, monkeypatch, capsys
):
    _typed(monkeypatch, "short", "tiny", "nope")
    with pytest.raises(credentials.CredentialError, match="No passphrase was set"):
        credentials.enrol("steve", config)
    assert keys.load("steve") is None
    assert "at least 8 characters" in capsys.readouterr().err


def test_setup_asks_again_when_the_confirmation_differs(config, monkeypatch, capsys):
    _typed(monkeypatch, PW, PW + "x", PW, PW)
    credentials.enrol("steve", config)
    assert keys.check_password(keys.load("steve"), PW)
    assert "do not match" in capsys.readouterr().err


# --- Reset --------------------------------------------------------------------------


def test_reset_rewraps_the_same_key_and_changes_no_ledger_byte(config, monkeypatch):
    keys.save("steve", keys.new_credential("steve", PW))
    before = keys.load("steve")
    _sign_line("C1", "steve", keys.open_key(before, "steve", PW))
    chain = ledger.chain_path("C1").read_bytes()
    _typed(monkeypatch, PW, NEW, NEW)
    credentials.reset("steve", config)
    after = keys.load("steve")
    assert keys.active(after)["public_key"] == keys.active(before)["public_key"]
    assert keys.check_password(after, NEW) and not keys.check_password(after, PW)
    assert keys.open_key(after, "steve", NEW)
    assert ledger.chain_path("C1").read_bytes() == chain


def test_reset_with_a_wrong_current_passphrase_changes_nothing_and_counts(
    config, monkeypatch
):
    keys.save("steve", keys.new_credential("steve", PW))
    before = _sha(keys.keys_path("steve"))
    _typed(monkeypatch, "not the passphrase")
    with pytest.raises(credentials.CredentialError, match="--forgot-password"):
        credentials.reset("steve", config)
    assert _sha(keys.keys_path("steve")) == before
    assert approval_auth._recent_failure_count("steve") == 1


def test_reset_of_a_0_6_credential_makes_a_key_pair(config, monkeypatch):
    _legacy(OLD_06)
    _typed(monkeypatch, OLD_06, NEW, NEW)
    credentials.reset("steve", config)
    assert keys.check_password(keys.load("steve"), NEW)
    assert credentials.state("steve", config) == "schema3"  # the 0.6 file is a stub now


# --- Forgot ------------------------------------------------------------------------


def test_forgot_retires_the_old_key_and_prints_both_fingerprints_and_the_pin(
    config, monkeypatch, capsys
):
    keys.save("steve", keys.new_credential("steve", PW))
    old = keys.active(keys.load("steve"))
    _sign_line("C1", "steve", keys.open_key(keys.load("steve"), "steve", PW))
    monkeypatch.setattr(credentials, "_confirm_new_key", lambda: None)
    _typed(monkeypatch, PW, NEW, NEW)  # the current one is refused first
    credentials.forgot("steve", config)
    data = keys.load("steve")
    retired = [k for k in data["keys"] if k["status"] == "retired"]
    assert [k["public_key"] for k in retired] == [old["public_key"]]
    assert keys.check_password(data, NEW)
    captured = capsys.readouterr()
    old_fp, new_fp = keys.key_fingerprint(old), keys.key_fingerprint(keys.active(data))
    assert f"Old signing key (retired): {old_fp}" in captured.out
    assert f"New signing key:           {new_fp}" in captured.out
    assert f"--expect-key steve={old_fp}:1-1" in captured.out
    assert "different from the current one" in captured.err


@pytest.mark.parametrize("answer, ok", [("NEW KEY\n", True), ("yes\n", False)])
def test_forgot_needs_new_key_typed_on_the_terminal(monkeypatch, answer, ok):
    import builtins
    import io

    real = builtins.open
    monkeypatch.setattr(
        builtins,
        "open",
        lambda f, *a, **k: io.StringIO(answer) if f == "/dev/tty" else real(f, *a, **k),
    )
    if ok:
        credentials._confirm_new_key()
    else:
        with pytest.raises(credentials.CredentialError, match="Nothing was changed"):
            credentials._confirm_new_key()


# --- Upgrade of a 0.6 credential ------------------------------------------------------------


def test_upgrade_sets_aside_a_keys_file_found_beside_a_0_6_credential(
    config, monkeypatch
):
    _legacy(OLD_06)
    planted = keys.new_credential("steve", OLD_06)  # opens with the 0.6 password
    keys.save("steve", planted)
    planted_bytes = keys.keys_path("steve").read_bytes()
    _typed(monkeypatch, OLD_06)
    credentials.upgrade("steve", config)
    aside = list(keys.KEYS_DIR.glob("steve.json.untrusted-*"))
    assert len(aside) == 1 and aside[0].read_bytes() == planted_bytes  # byte-identical
    data = keys.load("steve")
    assert keys.active(data)["public_key"] != keys.active(planted)["public_key"]
    (retired,) = [k for k in data["keys"] if k["status"] == "retired"]
    assert retired["public_key"] == keys.active(planted)["public_key"]
    assert retired["retired_reason"] == "set aside at upgrade"
    assert credentials.state("steve", config) == "schema3"


def test_upgrade_of_a_short_0_6_password_asks_for_a_new_passphrase(config, monkeypatch):
    _legacy("abc12")
    _typed(monkeypatch, "abc12", PW, PW)
    assert credentials.upgrade("steve", config) is True
    assert keys.check_password(keys.load("steve"), PW)


def test_upgrade_of_a_0_6_password_under_15_keeps_it_and_recommends_more(
    config, monkeypatch, capsys
):
    _legacy(OLD_06)
    _typed(monkeypatch, OLD_06)
    assert credentials.upgrade("steve", config) is False
    assert keys.check_password(keys.load("steve"), OLD_06)
    assert "15 or more is recommended" in capsys.readouterr().out


def test_upgrade_with_a_wrong_0_6_password_moves_nothing(config, monkeypatch):
    _legacy(OLD_06)
    keys.save("steve", keys.new_credential("steve", PW))
    before = _sha(keys.keys_path("steve"))
    _typed(monkeypatch, "wrong password")
    with pytest.raises(credentials.CredentialError, match="Incorrect password"):
        credentials.upgrade("steve", config)
    assert _sha(keys.keys_path("steve")) == before
    assert approval_auth._recent_failure_count("steve") == 1


# --- The checks before any item is shown, and the final prompt ----------------------------


def test_preflight_names_setup_when_there_is_no_credential(config):
    with pytest.raises(credentials.CredentialError, match="--setup-password"):
        credentials.preflight("steve", config)


def test_preflight_names_forgot_when_the_keys_file_is_invalid(config):
    keys.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    keys.keys_path("steve").write_text('{"schema": 3}')
    with pytest.raises(
        credentials.CredentialError, match="KEYS_FILE_INVALID.*--forgot-password"
    ):
        credentials.preflight("steve", config)


def test_preflight_stops_during_a_lockout(config):
    keys.save("steve", keys.new_credential("steve", PW))
    for _ in range(approval_auth._MAX_PASSWORD_ATTEMPTS):
        approval_auth._record_failure("steve")
    with pytest.raises(SystemExit):
        credentials.preflight("steve", config)


def test_the_final_prompt_is_retried_in_place(config, monkeypatch, capsys):
    keys.save("steve", keys.new_credential("steve", PW))
    _typed(monkeypatch, "typo", PW)
    private, public = credentials.unlock("steve", "Password: ")
    assert keys.b64(keys.public_raw(private)) == public
    assert "2 attempt(s) remaining" in capsys.readouterr().err
    assert approval_auth._recent_failure_count("steve") == 0  # cleared on success


def test_the_final_prompt_stops_when_the_attempts_are_used(config, monkeypatch):
    keys.save("steve", keys.new_credential("steve", PW))
    _typed(monkeypatch, "a1", "a2", "a3", PW)
    with pytest.raises(credentials.AttemptsExhausted):
        credentials.unlock("steve", "Password: ")
