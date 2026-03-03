"""Tests for approval authentication module."""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aiir_cli.approval_auth import (
    _LOCKOUT_SECONDS,
    _MAX_PIN_ATTEMPTS,
    _MIN_PIN_LENGTH,
    _check_lockout,
    _clear_failures,
    _load_pin_entry,
    _maybe_migrate,
    _recent_failure_count,
    _record_failure,
    _validate_examiner_name,
    get_analyst_salt,
    has_pin,
    require_confirmation,
    require_tty_confirmation,
    reset_pin,
    setup_pin,
    verify_pin,
)


@pytest.fixture
def config_path(tmp_path):
    """Config file path in a temp directory."""
    return tmp_path / ".aiir" / "config.yaml"


@pytest.fixture
def pins_dir(tmp_path, monkeypatch):
    """Temp pins directory (replaces /var/lib/aiir/pins)."""
    d = tmp_path / "pins"
    d.mkdir()
    monkeypatch.setattr("aiir_cli.approval_auth._PINS_DIR", d)
    return d


class TestPinSetup:
    def test_setup_pin_writes_to_pins_dir(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve", pins_dir=pins_dir)
        pin_file = pins_dir / "steve.json"
        assert pin_file.exists()
        data = json.loads(pin_file.read_text())
        assert "hash" in data
        assert "salt" in data
        # config.yaml should NOT have pins
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text())
            assert "pins" not in (config or {})

    def test_setup_pin_fallback_to_config(self, config_path, tmp_path):
        """When pins_dir doesn't exist and can't be created, falls back to config.yaml."""
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        bad_pins = blocker / "pins"
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve", pins_dir=bad_pins)
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert "steve" in config["pins"]

    def test_setup_pin_verify_roundtrip(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["mypin", "mypin"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        assert verify_pin(config_path, "analyst1", "mypin", pins_dir=pins_dir)

    def test_wrong_pin_fails(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt",
            side_effect=["correct", "correct"],
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        assert not verify_pin(config_path, "analyst1", "wrong", pins_dir=pins_dir)

    def test_has_pin_false_when_no_config(self, config_path, pins_dir):
        assert not has_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_has_pin_true_after_setup(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        assert has_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_setup_pin_mismatch_exits(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["pin1", "pin2"]
        ):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_setup_pin_empty_exits(self, config_path, pins_dir):
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["", ""]):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_setup_pin_too_short_exits(self, config_path, pins_dir):
        """PIN shorter than _MIN_PIN_LENGTH is rejected."""
        short = "x" * (_MIN_PIN_LENGTH - 1)
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=[short, short]):
            with pytest.raises(SystemExit):
                setup_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_setup_pin_exact_min_length_ok(self, config_path, pins_dir):
        """PIN exactly at _MIN_PIN_LENGTH is accepted."""
        pin = "x" * _MIN_PIN_LENGTH
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=[pin, pin]):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        assert has_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_setup_pin_preserves_existing_config(self, config_path, pins_dir):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"examiner": "steve"}, f)
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve", pins_dir=pins_dir)
        config = yaml.safe_load(config_path.read_text())
        assert config["examiner"] == "steve"
        # PIN should be in pins_dir, not config
        assert "pins" not in config

    def test_pin_file_permissions(self, config_path, pins_dir):
        """PIN file has 0o600 permissions."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "steve", pins_dir=pins_dir)
        pin_file = pins_dir / "steve.json"
        assert (pin_file.stat().st_mode & 0o777) == 0o600


class TestPinMigration:
    def test_migrate_from_config_to_pins_dir(self, config_path, pins_dir):
        """PIN in config.yaml is auto-migrated to pins_dir."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {"hash": "abc123", "salt": "def456"}
        with open(config_path, "w") as f:
            yaml.dump({"pins": {"alice": entry}}, f)
        _maybe_migrate(config_path, pins_dir, "alice")
        # New location should have the entry
        loaded = _load_pin_entry(pins_dir, "alice")
        assert loaded is not None
        assert loaded["hash"] == "abc123"
        assert loaded["salt"] == "def456"
        # Old location should be stripped
        config = yaml.safe_load(config_path.read_text())
        assert "pins" not in (config or {})

    def test_migrate_noop_if_already_migrated(self, config_path, pins_dir):
        """Migration is a no-op if the new location already has the entry."""
        (pins_dir / "alice.json").write_text(json.dumps({"hash": "new", "salt": "new"}))
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"pins": {"alice": {"hash": "old", "salt": "old"}}}, f)
        _maybe_migrate(config_path, pins_dir, "alice")
        # New location keeps its value (not overwritten)
        loaded = _load_pin_entry(pins_dir, "alice")
        assert loaded["hash"] == "new"

    def test_migrate_preserves_other_analysts(self, config_path, pins_dir):
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
        _maybe_migrate(config_path, pins_dir, "alice")
        config = yaml.safe_load(config_path.read_text())
        assert "bob" in config["pins"]
        assert "alice" not in config["pins"]

    def test_has_pin_with_legacy_config(self, config_path, pins_dir):
        """has_pin finds PIN in legacy config.yaml when pins_dir is empty."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w") as f:
            yaml.dump({"pins": {"alice": {"hash": "abc", "salt": "def"}}}, f)
        # After has_pin, migration should have happened
        assert has_pin(config_path, "alice", pins_dir=pins_dir)
        # Verify it was migrated
        assert _load_pin_entry(pins_dir, "alice") is not None


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


class TestPinReset:
    def test_reset_pin_requires_current(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["oldpin", "oldpin"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        # Wrong current PIN
        with patch("aiir_cli.approval_auth.getpass_prompt", side_effect=["wrong"]):
            with pytest.raises(SystemExit):
                reset_pin(config_path, "analyst1", pins_dir=pins_dir)

    def test_reset_pin_success(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["oldpin", "oldpin"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        # Correct current, then new PIN twice
        with patch(
            "aiir_cli.approval_auth.getpass_prompt",
            side_effect=["oldpin", "newpin", "newpin"],
        ):
            reset_pin(config_path, "analyst1", pins_dir=pins_dir)
        assert verify_pin(config_path, "analyst1", "newpin", pins_dir=pins_dir)
        assert not verify_pin(config_path, "analyst1", "oldpin", pins_dir=pins_dir)

    def test_reset_no_pin_exits(self, config_path, pins_dir):
        with pytest.raises(SystemExit):
            reset_pin(config_path, "analyst1", pins_dir=pins_dir)


class TestGetAnalystSalt:
    def test_salt_from_pins_dir(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        salt = get_analyst_salt(config_path, "analyst1", pins_dir=pins_dir)
        assert isinstance(salt, bytes)
        assert len(salt) == 32

    def test_salt_missing_raises(self, config_path, pins_dir):
        with pytest.raises(ValueError, match="No salt found"):
            get_analyst_salt(config_path, "nobody", pins_dir=pins_dir)


class TestRequireConfirmation:
    def test_pin_mode_correct(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="1234"):
            mode, pin = require_confirmation(config_path, "analyst1")
        assert mode == "pin"
        assert pin == "1234"

    def test_pin_mode_wrong_exits(self, config_path, pins_dir):
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")

    def test_no_pin_configured_exits(self, config_path, pins_dir, capsys):
        """require_confirmation with no PIN configured exits with setup instructions."""
        with pytest.raises(SystemExit):
            require_confirmation(config_path, "analyst1")
        captured = capsys.readouterr()
        assert "No approval PIN configured" in captured.err
        assert "aiir config --setup-pin" in captured.err


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
    lockout = tmp_path / ".pin_lockout"
    monkeypatch.setattr("aiir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


class TestPinLockout:
    def test_three_failures_triggers_lockout(self, capsys):
        """3 failed PIN attempts triggers lockout."""
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(SystemExit):
            _check_lockout("analyst1")
        captured = capsys.readouterr()
        assert "PIN locked" in captured.err
        assert "seconds" in captured.err

    def test_lockout_expires_after_timeout(self, monkeypatch):
        """Lockout expires after _LOCKOUT_SECONDS."""
        import time as time_mod

        base_time = 1000000.0
        call_count = [0]

        def mock_time():
            call_count[0] += 1
            # First 3 calls are for _record_failure (recording timestamps)
            if call_count[0] <= _MAX_PIN_ATTEMPTS:
                return base_time
            # Subsequent calls are after lockout has expired
            return base_time + _LOCKOUT_SECONDS + 1

        monkeypatch.setattr(time_mod, "time", mock_time)
        for _ in range(_MAX_PIN_ATTEMPTS):
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
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        # analyst2 should not be locked out
        _check_lockout("analyst2")  # Should not raise
        assert _recent_failure_count("analyst2") == 0

    def test_under_threshold_no_lockout(self):
        """Fewer than _MAX_PIN_ATTEMPTS failures does not trigger lockout."""
        for _ in range(_MAX_PIN_ATTEMPTS - 1):
            _record_failure("analyst1")
        _check_lockout("analyst1")  # Should not raise

    def test_require_confirmation_records_failure_on_wrong_pin(
        self, config_path, pins_dir
    ):
        """require_confirmation records failure on wrong PIN."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="wrong"):
            with pytest.raises(SystemExit):
                require_confirmation(config_path, "analyst1")
        assert _recent_failure_count("analyst1") == 1

    def test_require_confirmation_clears_on_success(self, config_path, pins_dir):
        """require_confirmation clears failures on correct PIN."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        _record_failure("analyst1")
        assert _recent_failure_count("analyst1") == 1
        with patch("aiir_cli.approval_auth.getpass_prompt", return_value="1234"):
            mode, pin = require_confirmation(config_path, "analyst1")
        assert mode == "pin"
        assert pin == "1234"
        assert _recent_failure_count("analyst1") == 0

    def test_lockout_blocks_require_confirmation(self, config_path, pins_dir):
        """Locked-out analyst cannot even attempt PIN entry."""
        with patch(
            "aiir_cli.approval_auth.getpass_prompt", side_effect=["1234", "1234"]
        ):
            setup_pin(config_path, "analyst1", pins_dir=pins_dir)
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        with pytest.raises(SystemExit):
            require_confirmation(config_path, "analyst1")

    def test_lockout_persists_across_clear(self, isolate_lockout_file):
        """Lockout file survives even if in-process state is gone."""
        for _ in range(_MAX_PIN_ATTEMPTS):
            _record_failure("analyst1")
        # Verify lockout file exists and has data
        assert isolate_lockout_file.exists()
        data = json.loads(isolate_lockout_file.read_text())
        assert len(data["analyst1"]) == _MAX_PIN_ATTEMPTS
        # Simulating process restart: re-read from disk
        assert _recent_failure_count("analyst1") == _MAX_PIN_ATTEMPTS

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
