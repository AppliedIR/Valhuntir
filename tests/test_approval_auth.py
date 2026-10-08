"""Tests for approval authentication module."""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from vhir_cli.approval_auth import (
    _LOCKOUT_SECONDS,
    _MAX_PASSWORD_ATTEMPTS,
    _check_lockout,
    _clear_failures,
    _load_password_entry,
    _maybe_migrate,
    _recent_failure_count,
    _record_failure,
    _validate_examiner_name,
    require_tty_confirmation,
    verify_password,
)


@pytest.fixture
def config_path(tmp_path):
    """Config file path in a temp directory."""
    return tmp_path / ".vhir" / "config.yaml"


@pytest.fixture
def passwords_dir(tmp_path, monkeypatch):
    """Temp passwords directory (replaces /var/lib/vhir/passwords)."""
    d = tmp_path / "passwords"
    d.mkdir()
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    return d


class TestLegacyVerifier:
    """The 0.6 verifier stays, to check a 0.6 password before its upgrade."""

    @staticmethod
    def _entry(passwords_dir, name, password):
        import hashlib

        salt = bytes(range(32))
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000).hex()
        (passwords_dir / f"{name}.json").write_text(
            json.dumps({"hash": digest, "salt": salt.hex()})
        )

    def test_a_0_6_password_verifies(self, config_path, passwords_dir):
        self._entry(passwords_dir, "analyst1", "mypasswd1")
        assert verify_password(
            config_path, "analyst1", "mypasswd1", passwords_dir=passwords_dir
        )

    def test_wrong_password_fails(self, config_path, passwords_dir):
        self._entry(passwords_dir, "analyst1", "correctpw")
        assert not verify_password(
            config_path, "analyst1", "wrong", passwords_dir=passwords_dir
        )


class TestPasswordMigration:
    def test_migrate_from_config_to_passwords_dir(self, config_path, passwords_dir):
        """Password in config.yaml is auto-migrated to passwords_dir."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"hash": "abc123", "salt": "def456"}
        with open(config_path, "w") as f:
            yaml.dump({"pins": {"alice": entry}}, f)
        _maybe_migrate(config_path, passwords_dir, "alice")
        # New location should have the entry
        loaded = _load_password_entry(passwords_dir, "alice")
        assert loaded is not None
        assert loaded["hash"] == "abc123"
        assert loaded["salt"] == "def456"
        # Old location should be stripped
        config = yaml.safe_load(config_path.read_text())
        assert "pins" not in (config or {})

    def test_migrate_noop_if_already_migrated(self, config_path, passwords_dir):
        """Migration is a no-op if the new location already has the entry."""
        (passwords_dir / "alice.json").write_text(
            json.dumps({"hash": "new", "salt": "new"})
        )
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"pins": {"alice": {"hash": "old", "salt": "old"}}}, f)
        _maybe_migrate(config_path, passwords_dir, "alice")
        # New location keeps its value (not overwritten)
        loaded = _load_password_entry(passwords_dir, "alice")
        assert loaded["hash"] == "new"

    def test_migrate_preserves_other_analysts(self, config_path, passwords_dir):
        """Migrating one analyst doesn't affect others in config.yaml."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump(
                {
                    "pins": {
                        "alice": {"hash": "a", "salt": "a"},
                        "bob": {"hash": "b", "salt": "b"},
                    }
                },
                f,
            )
        _maybe_migrate(config_path, passwords_dir, "alice")
        config = yaml.safe_load(config_path.read_text())
        assert "bob" in config["pins"]
        assert "alice" not in config["pins"]


class TestExaminerNameValidation:
    def test_reject_path_traversal_dotdot(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("../etc/passwd")

    def test_reject_forward_slash(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("alice/bob")

    def test_reject_backslash(self):
        with pytest.raises(ValueError, match="Invalid examiner name"):
            _validate_examiner_name("alice\\bob")

    def test_accept_normal_names(self):
        _validate_examiner_name("alice")
        _validate_examiner_name("bob-smith")
        _validate_examiner_name("analyst1")


class TestTtyConfirmation:
    def test_tty_y_returns_true(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "y\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is True

    def test_tty_n_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "n\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_tty_empty_returns_false(self):
        mock_tty = MagicMock()
        mock_tty.readline.return_value = "\n"
        with patch("builtins.open", return_value=mock_tty):
            assert require_tty_confirmation("Confirm? ") is False

    def test_no_tty_exits(self):
        with patch("builtins.open", side_effect=OSError("No tty")):
            with pytest.raises(SystemExit):
                require_tty_confirmation("Confirm? ")


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir and clean between tests."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


class TestPasswordLockout:
    def test_three_failures_triggers_lockout(self, capsys):
        """3 failed password attempts triggers lockout."""
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(SystemExit):
            _check_lockout("analyst1")
        captured = capsys.readouterr()
        assert "Password locked" in captured.err
        assert "seconds" in captured.err

    def test_lockout_expires_after_timeout(self, monkeypatch):
        """Lockout expires after _LOCKOUT_SECONDS."""
        import time as time_mod

        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            call_count[0] += 1
            # First 3 calls are for _record_failure (recording timestamps)
            if call_count[0] <= _MAX_PASSWORD_ATTEMPTS:
                return base_time
            # Subsequent calls are after lockout has expired
            return base_time + _LOCKOUT_SECONDS + 1

        monkeypatch.setattr(time_mod, "time", mock_time)
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        # After lockout expires, check should NOT raise
        _check_lockout("analyst1")

    def test_successful_auth_clears_failure_count(self, config_path):
        """Successful authentication clears failure count."""
        _record_failure("analyst1")
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 2
        _clear_failures("analyst1")
        assert _recent_failure_count("analyst1") == 0

    def test_failures_do_not_cross_contaminate(self):
        """Failures from different analysts do not cross-contaminate."""
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        # analyst2 should not be locked out
        _check_lockout("analyst2")  # Should not raise
        assert _recent_failure_count("analyst2") == 0

    def test_under_threshold_no_lockout(self):
        """Fewer than _MAX_PASSWORD_ATTEMPTS failures does not trigger lockout."""
        for _ in range(_MAX_PASSWORD_ATTEMPTS - 1):
            _record_failure("analyst1")
        _check_lockout("analyst1")  # Should not raise

    def test_lockout_persists_across_clear(self, isolate_lockout_file):
        """Lockout file survives even if in-process state is gone."""
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure("analyst1")
        # Verify lockout file exists and has data
        assert isolate_lockout_file.exists()
        data = json.loads(isolate_lockout_file.read_text())
        assert len(data["analyst1"]) == _MAX_PASSWORD_ATTEMPTS
        # Simulating process restart: re-read from disk
        assert _recent_failure_count("analyst1") == _MAX_PASSWORD_ATTEMPTS

    def test_lockout_file_corrupt_treated_as_empty(self, isolate_lockout_file):
        """Corrupt lockout file is treated as empty (zero failures)."""
        isolate_lockout_file.parent.mkdir(parents=True, exist_ok=True)
        isolate_lockout_file.write_text("not valid json {{{")
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_file_permissions(self, isolate_lockout_file):
        """Lockout file has 0o600 permissions."""
        _record_failure("analyst1")
        assert isolate_lockout_file.exists()
        assert (isolate_lockout_file.stat().st_mode & 0o777) == 0o600
