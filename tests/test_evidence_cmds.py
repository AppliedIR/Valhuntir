"""Tests for evidence CLI commands."""

import json
import stat

import pytest

from vhir_cli.commands.evidence import (
    cmd_evidence,
    cmd_evidence_log,
    cmd_list_evidence,
    cmd_lock_evidence,
    cmd_register_evidence,
    cmd_verify_evidence,
)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create flat case dir with evidence directory."""
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence.json").write_text('{"files": []}')
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
        self,
        case=None,
        path=None,
        description="",
        evidence_action=None,
        path_filter=None,
    ):
        self.case = case
        self.path = path
        self.description = description
        self.evidence_action = evidence_action
        self.path_filter = path_filter


class TestLockEvidence:
    def test_lock_sets_444_perms(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"evidence data")
        cmd_lock_evidence(FakeArgs(), identity)
        mode = ev_file.stat().st_mode
        assert mode & stat.S_IWUSR == 0  # no write
        assert mode & stat.S_IRUSR != 0  # has read


class TestRegisterEvidence:
    def test_register_updates_evidence_json(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "malware.bin"
        ev_file.write_bytes(b"malware content")
        args = FakeArgs(path=str(ev_file), description="Test malware")
        cmd_register_evidence(args, identity)
        reg = json.loads((case_dir / "evidence.json").read_text())
        assert len(reg["files"]) == 1
        assert reg["files"][0]["sha256"]
        assert reg["files"][0]["description"] == "Test malware"


class TestListEvidence:
    def test_list_shows_registered_files(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        # Register a file first
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"test data")
        cmd_register_evidence(
            FakeArgs(path=str(ev_file), description="Test file"), identity
        )
        capsys.readouterr()  # clear register output

        cmd_list_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "sample.bin" in output
        assert "Test file" in output
        assert "1 evidence file(s)" in output

    def test_list_empty_registry(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        cmd_list_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "No evidence files" in output

    def test_list_no_registry(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        (case_dir / "evidence.json").unlink()
        cmd_list_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "No evidence registry" in output


class TestVerifyEvidence:
    def test_verify_ok(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "intact.bin"
        ev_file.write_bytes(b"original data")
        cmd_register_evidence(FakeArgs(path=str(ev_file)), identity)
        capsys.readouterr()

        # Make file writable again to allow re-read (it's still readable)
        cmd_verify_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "OK" in output
        assert "1 verified" in output

    def test_verify_modified(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "tampered.bin"
        ev_file.write_bytes(b"original data")
        cmd_register_evidence(FakeArgs(path=str(ev_file)), identity)
        capsys.readouterr()

        # Tamper with the file
        ev_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        ev_file.write_bytes(b"tampered data")

        with pytest.raises(SystemExit) as exc_info:
            cmd_verify_evidence(FakeArgs(), identity)
        assert exc_info.value.code == 2
        output = capsys.readouterr().out
        assert "MODIFIED" in output
        assert "ALERT" in output

    def test_verify_missing(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "deleted.bin"
        ev_file.write_bytes(b"data")
        cmd_register_evidence(FakeArgs(path=str(ev_file)), identity)
        capsys.readouterr()

        ev_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        ev_file.unlink()

        cmd_verify_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "MISSING" in output
        assert "1 missing" in output

    def test_verify_empty_registry(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        cmd_verify_evidence(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "No evidence files" in output


class TestEvidenceLog:
    def test_log_shows_entries(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "sample.bin"
        ev_file.write_bytes(b"data")
        cmd_register_evidence(FakeArgs(path=str(ev_file)), identity)
        capsys.readouterr()

        cmd_evidence_log(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "register" in output
        assert "1 entries" in output

    def test_log_filter_by_path(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev1 = case_dir / "evidence" / "alpha.bin"
        ev2 = case_dir / "evidence" / "beta.bin"
        ev1.write_bytes(b"a")
        ev2.write_bytes(b"b")
        cmd_register_evidence(FakeArgs(path=str(ev1)), identity)
        cmd_register_evidence(FakeArgs(path=str(ev2)), identity)
        capsys.readouterr()

        # Without filter: 2 entries
        cmd_evidence_log(FakeArgs(), identity)
        output_all = capsys.readouterr().out
        assert "2 entries" in output_all

        # With filter: 1 entry (alpha only)
        cmd_evidence_log(FakeArgs(path_filter="alpha"), identity)
        output = capsys.readouterr().out
        assert "1 entries" in output

    def test_log_empty(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        cmd_evidence_log(FakeArgs(), identity)
        output = capsys.readouterr().out
        assert "No evidence access log" in output


class TestEvidenceSubcommandDispatch:
    def test_dispatch_register(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        ev_file = case_dir / "evidence" / "dispatch.bin"
        ev_file.write_bytes(b"dispatch test")
        args = FakeArgs(
            evidence_action="register", path=str(ev_file), description="via dispatch"
        )
        cmd_evidence(args, identity)
        output = capsys.readouterr().out
        assert "Registered" in output

    def test_dispatch_list(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(evidence_action="list")
        cmd_evidence(args, identity)
        output = capsys.readouterr().out
        assert "No evidence files" in output

    def test_dispatch_verify(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(evidence_action="verify")
        cmd_evidence(args, identity)
        output = capsys.readouterr().out
        assert "No evidence files" in output

    def test_dispatch_log(self, case_dir, identity, monkeypatch, capsys):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        args = FakeArgs(evidence_action="log")
        cmd_evidence(args, identity)
        output = capsys.readouterr().out
        assert "No evidence access log" in output

    def test_dispatch_no_action(self, case_dir, identity, monkeypatch):
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        with pytest.raises(SystemExit):
            cmd_evidence(FakeArgs(), identity)
