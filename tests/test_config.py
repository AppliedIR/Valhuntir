"""Tests for vhir config command."""

from pathlib import Path
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
        args = FakeArgs(examiner="new-examiner")
        with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
            cmd_config(args, identity)
        config = yaml.safe_load(config_path.read_text())
        assert config["examiner"] == "new-examiner"

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


RULE = "(lower-case letters, digits and hyphens, at most 20 characters)"


@pytest.mark.parametrize(
    "name",
    ["bad name!!", "new_examiner", "Alice", "-lead", "a" * 21, "!!!", "x\ny"],
)
def test_an_invalid_examiner_name_is_refused_and_config_kept(
    config_dir, identity, capsys, name
):
    config_path = config_dir / ".vhir" / "config.yaml"
    config_path.parent.mkdir()
    before = "analyst: old\nexaminer: kept\n"
    config_path.write_text(before)
    with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
        with pytest.raises(SystemExit) as exc:
            cmd_config(FakeArgs(examiner=name), identity)
    assert exc.value.code == 1
    out = capsys.readouterr()
    assert out.err == f"Invalid examiner name: {name!r} {RULE}\n"
    assert out.out == ""
    assert config_path.read_text() == before


def test_an_invalid_examiner_name_makes_no_config_folder(config_dir, identity):
    with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
        with pytest.raises(SystemExit):
            cmd_config(FakeArgs(examiner="bad name!!"), identity)
    assert not (config_dir / ".vhir").exists()


@pytest.mark.parametrize("name", ["alice", "a", "j-doe-2", "0" * 20, "9lives"])
def test_a_valid_examiner_name_is_written_and_echoed(
    config_dir, identity, capsys, name
):
    config_path = config_dir / ".vhir" / "config.yaml"
    with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
        cmd_config(FakeArgs(examiner=name), identity)
    assert yaml.safe_load(config_path.read_text()) == {"examiner": name}
    assert capsys.readouterr().out == f"Examiner identity set to: {name}\n"


class _EnrolArgs:
    reset = forgot = upgrade = False

    def __init__(self, name):
        self.name = name


def test_enrol_refuses_an_invalid_name_with_the_same_message(
    config_dir, identity, capsys
):
    from vhir_cli.commands.config import cmd_enrol

    with patch("vhir_cli.commands.config.Path.home", return_value=config_dir):
        with pytest.raises(SystemExit) as exc:
            cmd_enrol(_EnrolArgs("bad name!!"), identity)
    assert exc.value.code == 1
    assert capsys.readouterr().err == f"Invalid examiner name: 'bad name!!' {RULE}\n"


def test_enrol_passes_a_valid_name_on(config_dir, identity):
    from vhir_cli.commands import config as config_cmd

    seen = []
    with (
        patch("vhir_cli.commands.config.Path.home", return_value=config_dir),
        patch.object(
            config_cmd.credentials, "enrol", lambda *a, **k: seen.append((a, k))
        ),
    ):
        config_cmd.cmd_enrol(_EnrolArgs("alice"), identity)
    assert seen == [
        (("alice", config_dir / ".vhir" / "config.yaml"), {"by_name": True})
    ]


def _vhir(home, *argv, **env):
    import subprocess
    import sys

    import vhir_cli

    src = str(Path(vhir_cli.__file__).parent.parent)
    base = {"HOME": str(home), "USER": "alice", "PATH": "", "PYTHONPATH": src}
    return subprocess.run(
        [sys.executable, "-m", "vhir_cli.main", *argv],
        env={**base, **env},
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_the_vhir_command_refuses_an_invalid_config_name(tmp_path):
    r = _vhir(tmp_path, "config", "--examiner", "bad name!!")
    assert r.returncode == 1
    assert r.stderr.endswith(f"Invalid examiner name: 'bad name!!' {RULE}\n")
    assert r.stdout == ""
    assert not (tmp_path / ".vhir" / "config.yaml").exists()


def test_the_vhir_command_shows_the_os_user_for_an_unusable_name(tmp_path):
    r = _vhir(tmp_path, "config", "--show", VHIR_EXAMINER="!!!")
    assert r.returncode == 0
    assert "Current identity: alice (source: os_user)" in r.stdout
    assert "unknown" not in r.stdout
    assert (
        "Warning: empty examiner identity from source 'env'. "
        "Falling back to OS user 'alice'." in r.stderr
    )
