"""Tests for post-restore examiner password verification in 'vhir restore'."""

import hashlib
import json
import secrets
from unittest.mock import patch

import pytest

from vhir_cli.approval_auth import PBKDF2_ITERATIONS
from vhir_cli.commands.backup import _verify_restored_password

_PASSWORD = "correct-horse"


@pytest.fixture
def restored_password(tmp_path, monkeypatch):
    """Real password entry for 'steve' in a temp passwords dir, as a restore leaves it."""
    passwords_dir = tmp_path / "passwords"
    passwords_dir.mkdir()
    salt = secrets.token_bytes(32)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", _PASSWORD.encode(), salt, PBKDF2_ITERATIONS
    ).hex()
    (passwords_dir / "steve.json").write_text(
        json.dumps({"hash": pw_hash, "salt": salt.hex()})
    )
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", passwords_dir)
    monkeypatch.setenv("HOME", str(tmp_path))
    return passwords_dir


class TestVerifyRestoredPassword:
    def test_correct_password_is_confirmed(self, restored_password, capsys):
        """The restored hash is actually checked and a matching password confirms."""
        with patch("getpass.getpass", return_value=_PASSWORD):
            _verify_restored_password("steve")
        out = capsys.readouterr().out
        assert "Password correct." in out

    def test_wrong_password_reports_mismatch(self, restored_password, capsys):
        """A non-matching password warns instead of silently returning."""
        with (
            patch("getpass.getpass", return_value="wrong-password"),
            patch("builtins.input", return_value="s"),
        ):
            _verify_restored_password("steve")
        out = capsys.readouterr().out
        assert "Password does not match." in out
