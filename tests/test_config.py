"""Tests for vhir config command."""

from unittest.mock import patch

import pytest
import yaml

from vhir_cli.commands.config import cmd_config


@pytest.fixture
def config_dir(tmp_path):
    """Use tmp_path as home for config."""
    return tmp_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


class FakeArgs:
    def __init__(
        self, examiner=None, show=False, setup_password=False, reset_password=False
    ):
        self.examiner = examiner
        self.show = show
        self.setup_password = setup_password
        self.reset_password = reset_password


class TestConfig:
    def test_set_examiner(self, config_dir, identity):
        config_path = config_dir / ".vhir" / "config.yaml"
        args = FakeArgs(examiner="new_examiner")
        with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        config = yaml.safe_load(config_path.read_text())
        assert config["examiner"] == "new_examiner"

    def test_show_config(self, config_dir, identity, capsys):
        config_path = config_dir / ".vhir" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.dump({"examiner": "test_examiner"}))
        args = FakeArgs(show=True)
        with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        out = capsys.readouterr().out
        assert "test_examiner" in out

    def test_show_when_no_config_file(self, config_dir, identity, capsys):
        args = FakeArgs(show=True)
        with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        out = capsys.readouterr().out
        assert "No configuration file found" in out
