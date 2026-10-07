"""Tests for 'vhir restore' integrity handling."""

import hashlib
import io
import json
import sys

import pytest

from vhir_cli.commands.backup import cmd_restore

CASE_ID = "INC-2026-001"


class FakeArgs:
    def __init__(self, backup_path):
        self.backup_path = str(backup_path)
        self.skip_opensearch = True
        self.skip_ledger = True


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture(autouse=True)
def no_tty(monkeypatch):
    """Restore must take the non-interactive path in tests."""
    monkeypatch.setattr(sys, "stdin", io.StringIO())


def make_backup(tmp_path, contents):
    """Build a backup directory whose manifest matches `contents`."""
    target_dir = tmp_path / "cases" / CASE_ID
    backup_path = tmp_path / "backup"
    backup_path.mkdir()

    entries = []
    for rel, text in contents.items():
        fpath = backup_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(text)
        entries.append(
            {
                "path": rel,
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
            }
        )

    manifest = {
        "version": 1,
        "case_id": CASE_ID,
        "timestamp": "2026-01-01T00:00:00Z",
        "source": str(target_dir),
        "file_count": len(entries),
        "total_bytes": sum(len(t) for t in contents.values()),
        "files": entries,
    }
    (backup_path / "backup-manifest.json").write_text(json.dumps(manifest))
    return backup_path, target_dir


class TestRestoreIntegrity:
    def test_tampered_file_exits_nonzero(self, tmp_path, identity, capsys):
        backup_path, target_dir = make_backup(
            tmp_path, {"case.json": "{}", "findings.json": '{"findings": []}'}
        )
        # Tamper with the backup after the manifest was written.
        (backup_path / "findings.json").write_text('{"findings": ["injected"]}')

        with pytest.raises(SystemExit) as exc:
            cmd_restore(FakeArgs(backup_path), identity)

        assert exc.value.code == 1
        out = capsys.readouterr()
        assert "MISMATCH" in out.out
        # Marker stays so the partial restore is detectable and cleanable.
        assert (target_dir / ".restore-in-progress").exists()

    def test_missing_file_exits_nonzero(self, tmp_path, identity, capsys):
        backup_path, target_dir = make_backup(
            tmp_path, {"case.json": "{}", "findings.json": '{"findings": []}'}
        )
        (backup_path / "findings.json").unlink()

        with pytest.raises(SystemExit) as exc:
            cmd_restore(FakeArgs(backup_path), identity)

        assert exc.value.code == 1
        assert "MISSING" in capsys.readouterr().out
        assert (target_dir / ".restore-in-progress").exists()

    def test_intact_backup_restores(self, tmp_path, identity, capsys):
        backup_path, target_dir = make_backup(
            tmp_path, {"case.json": "{}", "findings.json": '{"findings": []}'}
        )

        cmd_restore(FakeArgs(backup_path), identity)

        assert (target_dir / "case.json").read_text() == "{}"
        assert not (target_dir / ".restore-in-progress").exists()
        assert "MISMATCH" not in capsys.readouterr().out

    def test_retry_after_repair_succeeds(self, tmp_path, identity):
        backup_path, target_dir = make_backup(
            tmp_path, {"case.json": "{}", "findings.json": '{"findings": []}'}
        )
        (backup_path / "findings.json").write_text('{"findings": ["injected"]}')

        with pytest.raises(SystemExit):
            cmd_restore(FakeArgs(backup_path), identity)

        # Repair the backup and re-run: the marker lets restore clean up.
        (backup_path / "findings.json").write_text('{"findings": []}')
        cmd_restore(FakeArgs(backup_path), identity)

        assert (target_dir / "findings.json").read_text() == '{"findings": []}'
        assert not (target_dir / ".restore-in-progress").exists()
