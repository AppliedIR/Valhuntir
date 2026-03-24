"""Tests for vhir exec command."""

import json
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands.execute import cmd_exec


def _mock_tty(response="y\n"):
    """Return a mock that simulates /dev/tty."""
    mock = MagicMock()
    mock.readline.return_value = response
    return mock


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a flat case directory with audit dir."""
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / "audit").mkdir(parents=True)
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
    def __init__(self, cmd, purpose, case=None):
        self.cmd = cmd
        self.purpose = purpose
        self.case = case


class TestExecEmptyCommand:
    def test_empty_cmd_exits_with_guidance(
        self, case_dir, identity, monkeypatch, capsys
    ):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=[], purpose="test")
        with pytest.raises(SystemExit):
            cmd_exec(args, identity)
        captured = capsys.readouterr()
        assert "No command provided" in captured.err
        assert "--" in captured.err

    def test_only_separator_exits_with_guidance(
        self, case_dir, identity, monkeypatch, capsys
    ):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["--"], purpose="test")
        with pytest.raises(SystemExit):
            cmd_exec(args, identity)
        captured = capsys.readouterr()
        assert "No command specified after" in captured.err


class TestExec:
    def test_audit_written_on_exec(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test command")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        log_file = case_dir / "audit" / "cli-exec.jsonl"
        assert log_file.exists()
        entry = json.loads(log_file.read_text().strip())
        assert entry["mcp"] == "cli-exec"
        assert entry["tool"] == "exec"
        assert entry["params"]["command"] == "echo hello"
        assert entry["params"]["purpose"] == "test command"
        assert entry["examiner"] == "analyst1"
        assert entry["source"] == "cli_exec"
        assert "audit_id" in entry
        assert "elapsed_ms" in entry

    def test_cancelled_exec_writes_nothing(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty("n\n")):
            cmd_exec(args, identity)
        log_file = case_dir / "audit" / "cli-exec.jsonl"
        assert not log_file.exists()

    def test_audit_id_sequence_increments(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "one"], purpose="first")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        args2 = FakeArgs(cmd=["echo", "two"], purpose="second")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args2, identity)
        log_file = case_dir / "audit" / "cli-exec.jsonl"
        lines = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        assert len(lines) == 2
        assert lines[0]["audit_id"].endswith("-001")
        assert lines[1]["audit_id"].endswith("-002")

    def test_result_summary_captures_exit_code(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(cmd=["echo", "hello"], purpose="test")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        log_file = case_dir / "audit" / "cli-exec.jsonl"
        entry = json.loads(log_file.read_text().strip())
        assert entry["result_summary"]["exit_code"] == 0
        assert "lines" in entry["result_summary"]["output"]
