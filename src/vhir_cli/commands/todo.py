"""TODO management commands.

Operates on todos.json in the active case directory.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone

from vhir_cli.case_io import get_case_dir, load_todos, save_todos


def cmd_todo(args, identity: dict) -> None:
    """Route to the appropriate todo subcommand."""
    case_dir = get_case_dir(getattr(args, "case", None))
    action = getattr(args, "todo_action", None)

    if action == "add":
        _todo_add(case_dir, args, identity)
    elif action == "complete":
        _todo_complete(case_dir, args, identity)
    elif action == "update":
        _todo_update(case_dir, args, identity)
    else:
        _todo_list(case_dir, args)


def _todo_list(case_dir, args) -> None:
    """List TODOs, optionally filtered."""
    todos = load_todos(case_dir)
    show_all = getattr(args, "all", False)
    assignee_filter = getattr(args, "assignee", "")

    if not show_all:
        todos = [t for t in todos if t.get("status") == "open"]
    if assignee_filter:
        todos = [t for t in todos if t.get("assignee") == assignee_filter]

    if not todos:
        print("No TODOs found.")
        return

    # Table header
    print(f"{'ID':<16} {'Status':<11} {'Priority':<9} {'Assignee':<12} Description")
    print("-" * 80)
    for t in todos:
        todo_id = t["todo_id"]
        status = t.get("status", "open")
        priority = t.get("priority", "medium")
        assignee = t.get("assignee", "") or "-"
        desc = t.get("description", "")[:40]
        print(f"{todo_id:<16} {status:<11} {priority:<9} {assignee:<12} {desc}")


def _todo_add(case_dir, args, identity: dict) -> None:
    """Add a new TODO."""
    todos = load_todos(case_dir)
    examiner = identity["examiner"]
    prefix = f"TODO-{examiner}-"
    max_seq = 0
    for t in todos:
        tid = t.get("todo_id", "")
        if tid.startswith(prefix):
            try:
                seq = int(tid[len(prefix) :])
                max_seq = max(max_seq, seq)
            except ValueError:
                pass
    todo_id = f"{prefix}{max_seq + 1:03d}"

    todo = {
        "todo_id": todo_id,
        "description": args.description,
        "status": "open",
        "priority": getattr(args, "priority", "medium") or "medium",
        "assignee": getattr(args, "assignee", "") or "",
        "related_findings": [],
        "created_by": identity["examiner"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "notes": [],
        "completed_at": None,
    }

    # Parse --finding flags
    finding = getattr(args, "finding", None)
    if finding:
        todo["related_findings"] = finding if isinstance(finding, list) else [finding]

    todos.append(todo)
    save_todos(case_dir, todos)
    print(f"Created {todo_id}: {args.description}")


def _todo_complete(case_dir, args, identity: dict) -> None:
    """Mark a TODO as completed."""
    todos = load_todos(case_dir)
    for t in todos:
        if t["todo_id"] == args.todo_id:
            if t["status"] == "completed":
                print(f"{args.todo_id} is already completed.", file=sys.stderr)
                return
            t["status"] = "completed"
            t["completed_at"] = datetime.now(timezone.utc).isoformat()
            save_todos(case_dir, todos)
            print(f"Completed {args.todo_id}")
            return
    print(f"TODO not found: {args.todo_id}", file=sys.stderr)
    sys.exit(1)


def _todo_update(case_dir, args, identity: dict) -> None:
    """Update a TODO (add note, reassign, reprioritize)."""
    todos = load_todos(case_dir)
    for t in todos:
        if t["todo_id"] == args.todo_id:
            changed = []
            if getattr(args, "note", None):
                t.setdefault("notes", []).append(
                    {
                        "note": args.note,
                        "by": identity["examiner"],
                        "at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                changed.append("note added")
            if getattr(args, "assignee", None):
                t["assignee"] = args.assignee
                changed.append(f"assigned to {args.assignee}")
            if getattr(args, "priority", None):
                t["priority"] = args.priority
                changed.append(f"priority={args.priority}")
            if not changed:
                print(
                    "Nothing to update. Use --note, --assignee, or --priority.",
                    file=sys.stderr,
                )
                return
            save_todos(case_dir, todos)
            print(f"Updated {args.todo_id}: {', '.join(changed)}")
            return
    print(f"TODO not found: {args.todo_id}", file=sys.stderr)
    sys.exit(1)
