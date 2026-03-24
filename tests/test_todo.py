"""Tests for TODO CLI commands."""

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import load_todos, save_todos
from vhir_cli.commands.todo import cmd_todo


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    monkeypatch.setenv("VHIR_EXAMINER", "tester")

    meta = {"case_id": case_id, "name": "Test", "status": "open", "examiner": "tester"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "todos.json", "w") as f:
        json.dump([], f)

    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


class TestTodoAdd:
    def test_add_basic(self, case_dir, identity, capsys):
        args = Namespace(
            case=None,
            todo_action="add",
            description="Run volatility",
            assignee="",
            priority="medium",
            finding=None,
        )
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "TODO-analyst1-001" in output

        todos = load_todos(case_dir)
        assert len(todos) == 1
        assert todos[0]["todo_id"] == "TODO-analyst1-001"
        assert todos[0]["description"] == "Run volatility"
        assert todos[0]["created_by"] == "analyst1"

    def test_add_with_details(self, case_dir, identity, capsys):
        args = Namespace(
            case=None,
            todo_action="add",
            description="Check lateral",
            assignee="jane",
            priority="high",
            finding=["F-tester-001", "F-tester-002"],
        )
        cmd_todo(args, identity)

        todos = load_todos(case_dir)
        assert todos[0]["assignee"] == "jane"
        assert todos[0]["priority"] == "high"
        assert todos[0]["related_findings"] == ["F-tester-001", "F-tester-002"]

    def test_add_sequential_ids(self, case_dir, identity, capsys):
        for desc in ["A", "B", "C"]:
            args = Namespace(
                case=None,
                todo_action="add",
                description=desc,
                assignee="",
                priority="medium",
                finding=None,
            )
            cmd_todo(args, identity)
        todos = load_todos(case_dir)
        assert [t["todo_id"] for t in todos] == [
            "TODO-analyst1-001",
            "TODO-analyst1-002",
            "TODO-analyst1-003",
        ]


class TestTodoComplete:
    def test_complete(self, case_dir, identity, capsys):
        save_todos(
            case_dir,
            [
                {
                    "todo_id": "TODO-001",
                    "description": "A",
                    "status": "open",
                    "priority": "medium",
                    "assignee": "",
                    "related_findings": [],
                    "created_by": "analyst1",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": None,
                }
            ],
        )
        args = Namespace(case=None, todo_action="complete", todo_id="TODO-001")
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "Completed" in output

        todos = load_todos(case_dir)
        assert todos[0]["status"] == "completed"
        assert todos[0]["completed_at"] is not None

    def test_complete_not_found(self, case_dir, identity, capsys):
        args = Namespace(case=None, todo_action="complete", todo_id="TODO-999")
        with pytest.raises(SystemExit):
            cmd_todo(args, identity)


class TestTodoUpdate:
    def test_update_note(self, case_dir, identity, capsys):
        save_todos(
            case_dir,
            [
                {
                    "todo_id": "TODO-001",
                    "description": "A",
                    "status": "open",
                    "priority": "medium",
                    "assignee": "",
                    "related_findings": [],
                    "created_by": "analyst1",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": None,
                }
            ],
        )
        args = Namespace(
            case=None,
            todo_action="update",
            todo_id="TODO-001",
            note="Waiting on data",
            assignee=None,
            priority=None,
        )
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "note added" in output

        todos = load_todos(case_dir)
        assert len(todos[0]["notes"]) == 1
        assert todos[0]["notes"][0]["note"] == "Waiting on data"

    def test_update_reassign(self, case_dir, identity, capsys):
        save_todos(
            case_dir,
            [
                {
                    "todo_id": "TODO-001",
                    "description": "A",
                    "status": "open",
                    "priority": "medium",
                    "assignee": "steve",
                    "related_findings": [],
                    "created_by": "analyst1",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": None,
                }
            ],
        )
        args = Namespace(
            case=None,
            todo_action="update",
            todo_id="TODO-001",
            note=None,
            assignee="jane",
            priority=None,
        )
        cmd_todo(args, identity)

        todos = load_todos(case_dir)
        assert todos[0]["assignee"] == "jane"


class TestTodoList:
    def test_list_open(self, case_dir, identity, capsys):
        save_todos(
            case_dir,
            [
                {
                    "todo_id": "TODO-001",
                    "description": "Open task",
                    "status": "open",
                    "priority": "high",
                    "assignee": "steve",
                    "related_findings": [],
                    "created_by": "analyst1",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": None,
                },
                {
                    "todo_id": "TODO-002",
                    "description": "Done task",
                    "status": "completed",
                    "priority": "medium",
                    "assignee": "",
                    "related_findings": [],
                    "created_by": "analyst1",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": "2026-01-02",
                },
            ],
        )
        args = Namespace(case=None, todo_action=None, all=False, assignee="")
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "TODO-001" in output
        assert "TODO-002" not in output  # Completed not shown by default

    def test_list_all(self, case_dir, identity, capsys):
        save_todos(
            case_dir,
            [
                {
                    "todo_id": "TODO-001",
                    "description": "Open",
                    "status": "open",
                    "priority": "medium",
                    "assignee": "",
                    "related_findings": [],
                    "created_by": "a",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": None,
                },
                {
                    "todo_id": "TODO-002",
                    "description": "Done",
                    "status": "completed",
                    "priority": "low",
                    "assignee": "",
                    "related_findings": [],
                    "created_by": "a",
                    "created_at": "2026-01-01",
                    "notes": [],
                    "completed_at": "2026-01-02",
                },
            ],
        )
        args = Namespace(case=None, todo_action=None, all=True, assignee="")
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "TODO-001" in output
        assert "TODO-002" in output

    def test_list_empty(self, case_dir, identity, capsys):
        args = Namespace(case=None, todo_action=None, all=False, assignee="")
        cmd_todo(args, identity)
        output = capsys.readouterr().out
        assert "No TODOs found" in output
