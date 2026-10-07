"""Tests for vhir exec command."""

import json
import subprocess
import sys
import tracemalloc
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands import execute
from vhir_cli.commands.execute import cmd_exec

# Emits every str.splitlines() boundary, a line that straddles the 64 KiB read
# size, a line that ends exactly on it, blank lines and an unterminated tail.
MIXED_OUTPUT_PRODUCER = (
    "import sys\n"
    "w = sys.stdout.buffer.write\n"
    "w('a\\r\\nb\\rc\\x85d\\u2028e\\n'.encode())\n"
    "w(b'y' * 65535 + b'\\n')\n"
    "w(b'z' * 200000 + b'\\n')\n"
    "w(b'\\n\\n\\n')\n"
    "w(b'tail-with-no-newline')\n"
)

# 4096-char lines keep the number of traced allocations low so tracemalloc
# overhead stays small; only the peak matters.
BULK_OUTPUT_PRODUCER = (
    "import sys\n"
    "block = (b'q' * 4095 + b'\\n') * 256\n"
    "for _ in range(int(sys.argv[1])):\n"
    "    sys.stdout.buffer.write(block)\n"
)


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


class TestExecLargeOutput:
    def _entry(self, case_dir):
        log_file = case_dir / "audit" / "cli-exec.jsonl"
        return json.loads(log_file.read_text().strip())

    def test_line_count_matches_splitlines_across_chunks(
        self, case_dir, identity, monkeypatch
    ):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        cmd = [sys.executable, "-c", MIXED_OUTPUT_PRODUCER]
        reference = subprocess.run(cmd, capture_output=True, text=True).stdout
        args = FakeArgs(cmd=list(cmd), purpose="mixed line boundaries")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        expected = len(reference.splitlines())
        assert expected > 5
        assert self._entry(case_dir)["result_summary"]["output"] == f"{expected} lines"

    def test_head_is_first_10000_chars(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        cmd = [sys.executable, "-c", BULK_OUTPUT_PRODUCER, "1"]
        reference = subprocess.run(cmd, capture_output=True, text=True).stdout
        args = FakeArgs(cmd=list(cmd), purpose="head")
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        captured = capsys.readouterr()
        assert f"--- stdout ---\n{reference[:10000]}\n" in captured.out
        assert reference[:10001] not in captured.out

    def test_output_is_not_buffered_in_memory(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        # 24 MiB of child output must not become 24 MiB of resident Python
        # objects; only a bounded head and a line counter are retained.
        args = FakeArgs(
            cmd=[sys.executable, "-c", BULK_OUTPUT_PRODUCER, "24"],
            purpose="bulk output",
        )
        tracemalloc.start()
        try:
            tracemalloc.reset_peak()
            with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
                cmd_exec(args, identity)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert self._entry(case_dir)["result_summary"]["output"] == "6144 lines"
        assert peak < 8 * 1024 * 1024, f"peak traced memory was {peak} bytes"

    def test_timeout_still_writes_audit_entry(
        self, case_dir, identity, monkeypatch, capsys
    ):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        assert execute._TIMEOUT_SECONDS == 300
        monkeypatch.setattr(execute, "_TIMEOUT_SECONDS", 0.5)
        args = FakeArgs(
            cmd=[sys.executable, "-c", "import time; time.sleep(30)"],
            purpose="timeout",
        )
        with patch("vhir_cli.approval_auth.open", return_value=_mock_tty()):
            cmd_exec(args, identity)
        captured = capsys.readouterr()
        assert "timed out" in captured.err
        entry = self._entry(case_dir)
        assert entry["result_summary"]["exit_code"] == -1
        assert entry["result_summary"]["output"].startswith("0 lines")
