"""Tests for vhir case migrate command."""

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.migrate import _re_id, _re_id_refs, cmd_migrate


@pytest.fixture
def identity():
    return {"examiner": "alice", "os_user": "alice"}


def _make_old_case(
    case_dir,
    examiner="alice",
    findings=None,
    timeline=None,
    todos=None,
    actions=None,
    approvals=None,
    audit=None,
):
    """Create old examiners/ directory structure for migration testing."""
    case_dir.mkdir(exist_ok=True)
    meta = {
        "case_id": "INC-2026-001",
        "name": "Test case",
        "status": "open",
        "mode": "collaborative",
        "team": ["alice", "bob"],
    }
    (case_dir / "CASE.yaml").write_text(yaml.dump(meta, default_flow_style=False))

    exam_dir = case_dir / "examiners" / examiner
    exam_dir.mkdir(parents=True)

    if findings is not None:
        (exam_dir / "findings.json").write_text(json.dumps(findings))
    if timeline is not None:
        (exam_dir / "timeline.json").write_text(json.dumps(timeline))
    if todos is not None:
        (exam_dir / "todos.json").write_text(json.dumps(todos))
    if actions is not None:
        with open(exam_dir / "actions.jsonl", "w") as f:
            for entry in actions:
                f.write(json.dumps(entry) + "\n")
    if approvals is not None:
        with open(exam_dir / "approvals.jsonl", "w") as f:
            for entry in approvals:
                f.write(json.dumps(entry) + "\n")
    if audit is not None:
        audit_dir = exam_dir / "audit"
        audit_dir.mkdir()
        for filename, entries in audit.items():
            with open(audit_dir / filename, "w") as f:
                for entry in entries:
                    f.write(json.dumps(entry) + "\n")

    return case_dir


class TestReId:
    """Unit tests for the _re_id helper."""

    def test_basic_finding(self):
        assert _re_id("F-001", "F", "alice") == "F-alice-001"

    def test_basic_timeline(self):
        assert _re_id("T-001", "T", "alice") == "T-alice-001"

    def test_basic_todo(self):
        assert _re_id("TODO-001", "TODO", "alice") == "TODO-alice-001"

    def test_high_sequence(self):
        assert _re_id("F-042", "F", "alice") == "F-alice-042"

    def test_already_new_format_unchanged(self):
        assert _re_id("F-alice-001", "F", "alice") == "F-alice-001"

    def test_already_new_format_different_examiner(self):
        """An ID already in new format from another examiner is kept as-is."""
        assert _re_id("F-bob-001", "F", "bob") == "F-bob-001"

    def test_fallback_non_standard_id(self):
        """Non-standard IDs fall back to prefix-examiner-lastpart."""
        result = _re_id("F-custom", "F", "alice")
        assert result == "F-alice-custom"


class TestBasicMigration:
    """Test the core migration: examiners/{name}/ to flat case root."""

    def test_findings_re_id(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Suspicious process",
                    "staged": "2026-01-10T12:00:00Z",
                },
                {
                    "id": "F-002",
                    "status": "DRAFT",
                    "title": "Lateral movement",
                    "staged": "2026-01-11T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings) == 2
        assert findings[0]["id"] == "F-alice-001"
        assert findings[1]["id"] == "F-alice-002"
        assert findings[0]["examiner"] == "alice"

    def test_timeline_re_id(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            timeline=[
                {
                    "id": "T-001",
                    "timestamp": "2026-01-10T08:00:00Z",
                    "description": "Login event",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert len(timeline) == 1
        assert timeline[0]["id"] == "T-alice-001"
        assert timeline[0]["examiner"] == "alice"

    def test_todos_re_id(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            todos=[
                {
                    "todo_id": "TODO-001",
                    "description": "Check logs",
                    "related_findings": ["F-001"],
                },
            ],
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        todos = json.loads((case_dir / "todos.json").read_text())
        assert len(todos) == 1
        assert todos[0]["todo_id"] == "TODO-alice-001"
        assert todos[0]["examiner"] == "alice"

    def test_todo_related_findings_updated(self, tmp_path, monkeypatch, identity):
        """Cross-references in TODO related_findings are updated to new IDs."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            todos=[
                {
                    "todo_id": "TODO-001",
                    "description": "Verify",
                    "related_findings": ["F-001"],
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        todos = json.loads((case_dir / "todos.json").read_text())
        assert todos[0]["related_findings"] == ["F-alice-001"]

    def test_actions_migrated(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            actions=[
                {
                    "action": "exec",
                    "tool": "log2timeline",
                    "ts": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        actions_file = case_dir / "actions.jsonl"
        assert actions_file.exists()
        entries = [
            json.loads(line) for line in actions_file.read_text().strip().split("\n")
        ]
        assert len(entries) == 1
        assert entries[0]["tool"] == "log2timeline"


class TestApprovalCrossReferences:
    """Approval item_id references are updated during migration."""

    def test_approval_item_id_updated(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "APPROVED",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            approvals=[
                {
                    "item_id": "F-001",
                    "action": "APPROVED",
                    "examiner": "alice",
                    "ts": "2026-01-10T13:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        approvals_file = case_dir / "approvals.jsonl"
        assert approvals_file.exists()
        entries = [
            json.loads(line) for line in approvals_file.read_text().strip().split("\n")
        ]
        assert len(entries) == 1
        assert entries[0]["item_id"] == "F-alice-001"

    def test_approval_scoped_id_updated(self, tmp_path, monkeypatch, identity):
        """Scoped form alice/F-001 in approvals is also updated."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "APPROVED",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            approvals=[
                {
                    "item_id": "alice/F-001",
                    "action": "APPROVED",
                    "examiner": "alice",
                    "ts": "2026-01-10T13:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "approvals.jsonl").read_text().strip().split("\n")
        ]
        assert entries[0]["item_id"] == "F-alice-001"


class TestImportAll:
    """Test the --import-all flag merging multiple examiners."""

    def test_merge_two_examiners(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Alice finding",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        # Add bob's directory
        bob_dir = case_dir / "examiners" / "bob"
        bob_dir.mkdir(parents=True)
        (bob_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "F-001",
                        "status": "DRAFT",
                        "title": "Bob finding",
                        "staged": "2026-01-11T12:00:00Z",
                    },
                ]
            )
        )
        (bob_dir / "timeline.json").write_text(
            json.dumps(
                [
                    {
                        "id": "T-001",
                        "timestamp": "2026-01-11T09:00:00Z",
                        "description": "Bob event",
                        "staged": "2026-01-11T12:00:00Z",
                    },
                ]
            )
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=True)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings) == 2
        ids = {f["id"] for f in findings}
        assert "F-alice-001" in ids
        assert "F-bob-001" in ids

        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert len(timeline) == 1
        assert timeline[0]["id"] == "T-bob-001"

    def test_import_all_primary_first(self, tmp_path, monkeypatch, identity):
        """Primary examiner's data comes before others."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Alice first",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        bob_dir = case_dir / "examiners" / "bob"
        bob_dir.mkdir(parents=True)
        (bob_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "F-001",
                        "status": "DRAFT",
                        "title": "Bob first",
                        "staged": "2026-01-11T12:00:00Z",
                    },
                ]
            )
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=True)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["id"] == "F-alice-001"
        assert findings[1]["id"] == "F-bob-001"

    def test_import_all_merges_approvals(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "APPROVED",
                    "title": "A",
                    "staged": "2026-01-10T12:00:00Z",
                }
            ],
            approvals=[{"item_id": "F-001", "action": "APPROVED", "examiner": "alice"}],
        )
        bob_dir = case_dir / "examiners" / "bob"
        bob_dir.mkdir(parents=True)
        (bob_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "F-001",
                        "status": "APPROVED",
                        "title": "B",
                        "staged": "2026-01-11T12:00:00Z",
                    },
                ]
            )
        )
        with open(bob_dir / "approvals.jsonl", "w") as f:
            f.write(
                json.dumps(
                    {"item_id": "F-001", "action": "APPROVED", "examiner": "bob"}
                )
                + "\n"
            )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=True)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "approvals.jsonl").read_text().strip().split("\n")
        ]
        assert len(entries) == 2
        item_ids = {e["item_id"] for e in entries}
        assert "F-alice-001" in item_ids
        assert "F-bob-001" in item_ids


class TestBackup:
    """Verify the old examiners/ directory is backed up."""

    def test_examiners_renamed_to_bak(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        assert not (case_dir / "examiners").exists()
        assert (case_dir / "examiners.bak").is_dir()
        assert (case_dir / "examiners.bak" / "alice" / "findings.json").exists()

    def test_existing_backup_not_overwritten(
        self, tmp_path, monkeypatch, identity, capsys
    ):
        """If examiners.bak already exists, warn but don't overwrite."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        # Pre-create the backup dir
        (case_dir / "examiners.bak").mkdir()
        (case_dir / "examiners.bak" / "sentinel.txt").write_text("preserve me")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        # Original backup preserved
        assert (case_dir / "examiners.bak" / "sentinel.txt").exists()
        # examiners/ still exists (rename skipped)
        assert (case_dir / "examiners").is_dir()
        captured = capsys.readouterr()
        assert "already exists" in captured.err


class TestCaseYamlUpdate:
    """Verify CASE.yaml is cleaned up during migration."""

    def test_removes_old_fields(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        assert "mode" not in meta
        assert "team" not in meta
        assert "created_by" not in meta
        assert "migrated_at" in meta

    def test_extractions_dir_created(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        assert (case_dir / "extractions").is_dir()


class TestCorruptJsonGraceful:
    """Corrupt JSON files should not crash the migration."""

    def test_corrupt_findings_json(self, tmp_path, monkeypatch, identity, capsys):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice")
        exam_dir = case_dir / "examiners" / "alice"
        (exam_dir / "findings.json").write_text("{not valid json!!")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        # Should complete without crashing, empty findings
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.err

    def test_corrupt_timeline_json(self, tmp_path, monkeypatch, identity, capsys):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice")
        exam_dir = case_dir / "examiners" / "alice"
        (exam_dir / "timeline.json").write_text("corrupted!")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert timeline == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.err

    def test_corrupt_todos_json(self, tmp_path, monkeypatch, identity, capsys):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice")
        exam_dir = case_dir / "examiners" / "alice"
        (exam_dir / "todos.json").write_text("not json")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        todos = json.loads((case_dir / "todos.json").read_text())
        assert todos == []
        captured = capsys.readouterr()
        assert "WARNING" in captured.err

    def test_corrupt_actions_jsonl_line_skipped(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice")
        exam_dir = case_dir / "examiners" / "alice"
        with open(exam_dir / "actions.jsonl", "w") as f:
            f.write('{"action": "good"}\n')
            f.write("not json at all\n")
            f.write('{"action": "also_good"}\n')

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "actions.jsonl").read_text().strip().split("\n")
        ]
        assert len(entries) == 2

    def test_corrupt_approvals_jsonl_line_skipped(
        self, tmp_path, monkeypatch, identity
    ):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "APPROVED",
                    "title": "A",
                    "staged": "2026-01-10T12:00:00Z",
                }
            ],
        )
        exam_dir = case_dir / "examiners" / "alice"
        with open(exam_dir / "approvals.jsonl", "w") as f:
            f.write('{"item_id": "F-001", "action": "APPROVED"}\n')
            f.write("CORRUPT LINE\n")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "approvals.jsonl").read_text().strip().split("\n")
        ]
        assert len(entries) == 1
        assert entries[0]["item_id"] == "F-alice-001"


class TestNoExaminersDir:
    """No examiners/ directory should print a message and return."""

    def test_no_examiners_dir(self, tmp_path, monkeypatch, identity, capsys):
        case_dir = tmp_path / "case1"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-001"}))

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        captured = capsys.readouterr()
        assert "No examiners/ directory" in captured.out
        # No flat files created
        assert not (case_dir / "findings.json").exists()


class TestExistingFlatFilesRefusesOverwrite:
    """If flat files already have data, migration refuses to proceed."""

    def test_existing_findings_with_data(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        # Write existing flat findings with data
        (case_dir / "findings.json").write_text(
            json.dumps([{"id": "F-alice-001", "title": "Existing"}])
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        with pytest.raises(SystemExit):
            cmd_migrate(args, identity)

    def test_existing_timeline_with_data(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        (case_dir / "timeline.json").write_text(
            json.dumps([{"id": "T-alice-001", "timestamp": "2026-01-10T08:00:00Z"}])
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        with pytest.raises(SystemExit):
            cmd_migrate(args, identity)

    def test_existing_todos_with_data(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        (case_dir / "todos.json").write_text(
            json.dumps([{"todo_id": "TODO-alice-001", "description": "Existing"}])
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        with pytest.raises(SystemExit):
            cmd_migrate(args, identity)

    def test_empty_existing_files_ok(self, tmp_path, monkeypatch, identity):
        """Empty JSON arrays in flat files are not considered blocking data."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        # Write existing flat files with empty arrays
        (case_dir / "findings.json").write_text(json.dumps([]))
        (case_dir / "timeline.json").write_text(json.dumps([]))
        (case_dir / "todos.json").write_text(json.dumps([]))

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        # Should not raise
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings) == 1
        assert findings[0]["id"] == "F-alice-001"


class TestExaminerNotFound:
    """Missing examiner directory should print error and exit."""

    def test_examiner_not_found(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "bob")
        args = Namespace(case=None, examiner="bob", import_all=False)
        with pytest.raises(SystemExit):
            cmd_migrate(args, identity)

    def test_examiner_not_found_shows_available(
        self, tmp_path, monkeypatch, identity, capsys
    ):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "bob")
        args = Namespace(case=None, examiner="bob", import_all=False)
        with pytest.raises(SystemExit):
            cmd_migrate(args, identity)

        captured = capsys.readouterr()
        assert "alice" in captured.err
        assert "Available examiners" in captured.err


class TestAuditMerge:
    """Audit directories are merged into flat audit/."""

    def test_audit_files_copied(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[],
            audit={
                "sift.jsonl": [
                    {"tool": "plaso", "ts": "2026-01-10T12:00:00Z"},
                ]
            },
        )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        audit_file = case_dir / "audit" / "sift.jsonl"
        assert audit_file.exists()
        entries = [
            json.loads(line) for line in audit_file.read_text().strip().split("\n")
        ]
        assert len(entries) == 1
        assert entries[0]["tool"] == "plaso"

    def test_audit_files_appended_on_import_all(self, tmp_path, monkeypatch, identity):
        """When two examiners have the same audit file, entries are appended."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[],
            audit={
                "sift.jsonl": [
                    {"tool": "plaso", "examiner": "alice"},
                ]
            },
        )
        bob_dir = case_dir / "examiners" / "bob"
        bob_dir.mkdir(parents=True)
        bob_audit = bob_dir / "audit"
        bob_audit.mkdir()
        with open(bob_audit / "sift.jsonl", "w") as f:
            f.write(json.dumps({"tool": "vol3", "examiner": "bob"}) + "\n")

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=True)
        cmd_migrate(args, identity)

        audit_file = case_dir / "audit" / "sift.jsonl"
        entries = [
            json.loads(line) for line in audit_file.read_text().strip().split("\n")
        ]
        assert len(entries) == 2


class TestMissingOptionalFiles:
    """Migration works fine when optional files are absent."""

    def test_no_files_at_all(self, tmp_path, monkeypatch, identity):
        """Examiner dir exists but has no data files."""
        case_dir = tmp_path / "case1"
        case_dir.mkdir()
        (case_dir / "CASE.yaml").write_text(yaml.dump({"case_id": "INC-001"}))
        (case_dir / "examiners" / "alice").mkdir(parents=True)

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        # Flat files created but empty
        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings == []
        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert timeline == []
        todos = json.loads((case_dir / "todos.json").read_text())
        assert todos == []

    def test_findings_only(self, tmp_path, monkeypatch, identity):
        """Only findings.json present, others missing."""
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Only finding",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert len(findings) == 1
        # No actions or approvals files created since there were none
        assert not (case_dir / "actions.jsonl").exists()
        assert not (case_dir / "approvals.jsonl").exists()


class TestModifiedAtFallback:
    """modified_at is set from staged field as default."""

    def test_modified_at_uses_staged(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["modified_at"] == "2026-01-10T12:00:00Z"

    def test_existing_modified_at_preserved(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                    "modified_at": "2026-01-15T12:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        findings = json.loads((case_dir / "findings.json").read_text())
        assert findings[0]["modified_at"] == "2026-01-15T12:00:00Z"


class TestActionReIdRefs:
    """Actions.jsonl finding references are updated during migration."""

    def test_action_finding_id_updated(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            actions=[
                {
                    "action": "discuss",
                    "finding_id": "F-001",
                    "ts": "2026-01-10T14:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "actions.jsonl").read_text().strip().split("\n")
        ]
        assert entries[0]["finding_id"] == "F-alice-001"

    def test_action_related_findings_updated(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
                {
                    "id": "F-002",
                    "status": "DRAFT",
                    "title": "Test2",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            actions=[
                {
                    "action": "correlate",
                    "related_findings": ["F-001", "F-002"],
                    "ts": "2026-01-10T14:00:00Z",
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        entries = [
            json.loads(line)
            for line in (case_dir / "actions.jsonl").read_text().strip().split("\n")
        ]
        assert entries[0]["related_findings"] == ["F-alice-001", "F-alice-002"]

    def test_timeline_related_findings_updated(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(
            case_dir,
            examiner="alice",
            findings=[
                {
                    "id": "F-001",
                    "status": "DRAFT",
                    "title": "Test",
                    "staged": "2026-01-10T12:00:00Z",
                },
            ],
            timeline=[
                {
                    "id": "T-001",
                    "timestamp": "2026-01-10T08:00:00Z",
                    "description": "Event",
                    "staged": "2026-01-10T12:00:00Z",
                    "related_findings": ["F-001"],
                },
            ],
        )
        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        timeline = json.loads((case_dir / "timeline.json").read_text())
        assert timeline[0]["related_findings"] == ["F-alice-001"]

    def test_re_id_refs_helper(self):
        id_map = {"F-001": "F-alice-001", "F-002": "F-alice-002"}
        entry = {"finding_id": "F-001", "related_findings": ["F-001", "F-002"]}
        _re_id_refs(entry, id_map)
        assert entry["finding_id"] == "F-alice-001"
        assert entry["related_findings"] == ["F-alice-001", "F-alice-002"]

    def test_re_id_refs_no_match(self):
        id_map = {"F-001": "F-alice-001"}
        entry = {"finding_id": "F-999", "related_findings": ["F-999"]}
        _re_id_refs(entry, id_map)
        assert entry["finding_id"] == "F-999"  # Unchanged
        assert entry["related_findings"] == ["F-999"]  # Unchanged


class TestEvidenceCopy:
    """evidence.json and evidence_access.jsonl are copied from primary examiner."""

    def test_evidence_json_copied(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        exam_dir = case_dir / "examiners" / "alice"
        (exam_dir / "evidence.json").write_text(json.dumps({"files": ["disk.E01"]}))

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        evidence = json.loads((case_dir / "evidence.json").read_text())
        assert evidence["files"] == ["disk.E01"]

    def test_evidence_access_appended(self, tmp_path, monkeypatch, identity):
        case_dir = tmp_path / "case1"
        _make_old_case(case_dir, examiner="alice", findings=[])
        exam_dir = case_dir / "examiners" / "alice"
        with open(exam_dir / "evidence_access.jsonl", "w") as f:
            f.write(
                json.dumps({"action": "mount", "ts": "2026-01-10T12:00:00Z"}) + "\n"
            )

        monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        args = Namespace(case=None, examiner="alice", import_all=False)
        cmd_migrate(args, identity)

        access_file = case_dir / "evidence_access.jsonl"
        assert access_file.exists()
        entries = [
            json.loads(line) for line in access_file.read_text().strip().split("\n")
        ]
        assert len(entries) == 1
        assert entries[0]["action"] == "mount"
