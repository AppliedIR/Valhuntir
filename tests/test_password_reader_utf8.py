"""The password reader decodes UTF-8: a non-ASCII character is one character.

It decoded each byte on its own, so "é" became two U+FFFD and Backspace
removed half of it. It now decodes as UTF-8 incrementally; Backspace removes
one code point. Driven through a real pseudo-terminal.
"""

from __future__ import annotations

import os
import pty
import signal

from vhir_cli import approval_auth


def _read(monkeypatch, typed: bytes) -> str:
    """Type `typed` once the prompt has put the terminal in raw mode (which
    discards anything typed before it), with an alarm in case it never ends."""
    master, slave = pty.openpty()
    monkeypatch.setattr(
        approval_auth, "open", lambda *a, **k: os.fdopen(slave, "r"), raising=False
    )
    real_setraw = approval_auth.tty.setraw

    def setraw(fd, *a, **k):
        real_setraw(fd, *a, **k)
        os.write(master, typed)

    monkeypatch.setattr(approval_auth.tty, "setraw", setraw)
    signal.signal(
        signal.SIGALRM, lambda *a: (_ for _ in ()).throw(TimeoutError("no Enter"))
    )
    signal.alarm(10)
    try:
        return approval_auth.getpass_prompt("Password: ")
    finally:
        signal.alarm(0)
        os.close(master)


def test_a_non_ascii_character_is_one_character(monkeypatch):
    assert _read(monkeypatch, "café\r".encode()) == "café"


def test_backspace_removes_one_code_point(monkeypatch):
    assert _read(monkeypatch, "café".encode() + b"\x7f" + "é!\r".encode()) == "café!"


def test_the_0_6_reading_is_reproduced_for_the_upgrade_only():
    assert approval_auth.legacy_decoded("café") == "caf��"
    assert approval_auth.legacy_decoded("plain") == "plain"


def _legacy_entry(tmp_path, monkeypatch, password: str, stored_as: str):
    """A 0.6 (schema 1) entry whose hash was made from `stored_as`."""
    import hashlib
    import json

    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    salt = bytes(range(32))
    digest = hashlib.pbkdf2_hmac("sha256", stored_as.encode(), salt, 600_000).hex()
    approval_auth._PASSWORDS_DIR.mkdir(parents=True, exist_ok=True)
    path = approval_auth._PASSWORDS_DIR / "steve.json"
    path.write_text(json.dumps({"hash": digest, "salt": salt.hex()}))
    return tmp_path / "config.yaml", path


def test_a_0_6_non_ascii_password_still_opens_and_is_marked(tmp_path, monkeypatch):
    """0.6 stored its byte-wise reading; the UTF-8 reader types the real one."""
    pw = "café-lab-2026"
    config, path = _legacy_entry(
        tmp_path, monkeypatch, pw, approval_auth.legacy_decoded(pw)
    )
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda prompt: pw)
    assert approval_auth.require_confirmation(config, "steve") == ("password", pw)
    assert approval_auth._recent_failure_count("steve") == 0
    import json

    assert json.loads(path.read_text())["legacy_decoding"] is True


def test_anchor_a_wrong_or_ascii_password_is_unchanged(tmp_path, monkeypatch):
    config, path = _legacy_entry(tmp_path, monkeypatch, "plain-pass", "plain-pass")
    assert approval_auth.verify_password(config, "steve", "plain-pass")
    assert not approval_auth.verify_password(config, "steve", "café-lab-2026")
    assert "legacy_decoding" not in path.read_text()


def test_an_examiner_name_with_a_trailing_newline_is_refused():
    import pytest

    from vhir_cli.case_io import CaseError, _validate_examiner
    from vhir_cli.identity import valid_name

    assert not valid_name("steve\n")
    with pytest.raises(ValueError):
        approval_auth._validate_examiner_name("steve\n")
    with pytest.raises(CaseError):
        _validate_examiner("steve\n")
