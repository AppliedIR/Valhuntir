"""Valhuntir CLI entry point.

Human-only actions that the LLM orchestrator cannot bypass:
- approve/reject findings and timeline events (/dev/tty + password)
- evidence management (lock/unlock)
- forensic command execution with audit
- analyst identity configuration
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import argcomplete

from vhir_cli import __version__
from vhir_cli.case_io import DEFAULT_CASES_DIR, CaseError
from vhir_cli.commands.approve import cmd_approve
from vhir_cli.commands.audit_cmd import cmd_audit
from vhir_cli.commands.backup import cmd_backup, cmd_restore
from vhir_cli.commands.config import cmd_config
from vhir_cli.commands.dashboard import cmd_dashboard, cmd_portal
from vhir_cli.commands.evidence import (
    cmd_evidence,
    cmd_lock_evidence,
    cmd_register_evidence,
    cmd_unlock_evidence,
)
from vhir_cli.commands.execute import cmd_exec
from vhir_cli.commands.join import cmd_join
from vhir_cli.commands.migrate import cmd_migrate
from vhir_cli.commands.reject import cmd_reject
from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review
from vhir_cli.commands.service import cmd_service
from vhir_cli.commands.setup import cmd_setup
from vhir_cli.commands.sync import cmd_export, cmd_merge
from vhir_cli.commands.todo import cmd_todo
from vhir_cli.commands.update import cmd_update
from vhir_cli.identity import get_examiner_identity, warn_if_unconfigured


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vhir",
        description="Valhuntir — forensic investigation CLI",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("--case", help="Case ID (overrides active case)")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # backup
    p_backup = sub.add_parser("backup", help="Back up case data")
    p_backup.add_argument("destination", nargs="?", help="Backup destination directory")
    p_backup.add_argument("--case", help="Case ID (default: active case)")
    p_backup.add_argument("--include-evidence", action="store_true")
    p_backup.add_argument("--include-extractions", action="store_true")
    p_backup.add_argument(
        "--all",
        action="store_true",
        help="Include evidence + extractions + OpenSearch (if available)",
    )
    p_backup.add_argument("--include-opensearch", action="store_true")
    p_backup.add_argument(
        "--verify", metavar="BACKUP_PATH", help="Verify backup integrity"
    )

    # restore
    p_restore = sub.add_parser("restore", help="Restore a case from backup")
    p_restore.add_argument("backup_path", help="Path to backup directory")
    p_restore.add_argument(
        "--skip-opensearch", action="store_true", help="Skip OpenSearch index restore"
    )
    p_restore.add_argument(
        "--skip-ledger",
        action="store_true",
        help="Skip verification ledger + password hash restore",
    )

    # approve
    p_approve = sub.add_parser(
        "approve", help="Approve staged findings/timeline events"
    )
    p_approve.add_argument(
        "ids",
        nargs="*",
        help="Finding/event IDs to approve (omit for interactive review)",
    )
    p_approve.add_argument(
        "--examiner", dest="examiner_override", help="Override examiner identity"
    )
    p_approve.add_argument(
        "--analyst", dest="examiner_override", help="(deprecated, use --examiner)"
    )
    p_approve.add_argument(
        "--note", help="Add examiner note when approving specific IDs"
    )
    p_approve.add_argument(
        "--edit", action="store_true", help="Open in $EDITOR before approving"
    )
    p_approve.add_argument("--interpretation", help="Override interpretation field")
    p_approve.add_argument(
        "--by", help="Filter items by creator examiner (interactive mode)"
    )
    p_approve.add_argument(
        "--findings-only", action="store_true", help="Review only findings"
    )
    p_approve.add_argument(
        "--timeline-only", action="store_true", help="Review only timeline events"
    )
    p_approve.add_argument(
        "--review",
        action="store_true",
        help="Apply pending Examiner Portal reviews from pending-reviews.json",
    )

    # reject
    p_reject = sub.add_parser("reject", help="Reject staged findings/timeline events")
    p_reject.add_argument("ids", nargs="*", help="Finding/event IDs to reject")
    p_reject.add_argument(
        "--reason", default="", help="Reason for rejection (optional)"
    )
    p_reject.add_argument(
        "--review",
        action="store_true",
        help="Interactive review: walk through DRAFT items",
    )
    p_reject.add_argument(
        "--examiner", dest="examiner_override", help="Override examiner identity"
    )
    p_reject.add_argument(
        "--analyst", dest="examiner_override", help="(deprecated, use --examiner)"
    )

    # case (init, activate, close, migrate)
    p_case = sub.add_parser("case", help="Case management")
    case_sub = p_case.add_subparsers(dest="case_action", help="Case actions")

    p_case_init = case_sub.add_parser("init", help="Initialize a new case")
    p_case_init.add_argument("name", nargs="?", default=None, help="Case name")
    p_case_init.add_argument(
        "--case-id", default=None, help="Override auto-generated case ID"
    )
    p_case_init.add_argument("--description", default="", help="Case description")
    p_case_init.add_argument(
        "--cases-dir",
        default=None,
        help="Cases root directory (default: $VHIR_CASES_DIR or ~/cases)",
    )

    p_case_activate = case_sub.add_parser(
        "activate", help="Set active case for session"
    )
    p_case_activate.add_argument("case_id", help="Case ID to activate")
    p_case_activate.add_argument(
        "--cases-dir",
        default=None,
        help="Cases root directory (default: $VHIR_CASES_DIR or ~/cases)",
    )

    p_case_close = case_sub.add_parser("close", help="Close a case")
    p_case_close.add_argument("case_id", help="Case ID to close")
    p_case_close.add_argument("--summary", default="", help="Closing summary")

    case_sub.add_parser("list", help="List available cases")
    case_sub.add_parser("status", help="Show active case summary")

    p_case_reopen = case_sub.add_parser("reopen", help="Reopen a closed case")
    p_case_reopen.add_argument("case_id", help="Case ID to reopen")

    p_case_migrate = case_sub.add_parser(
        "migrate", help="Migrate case from examiners/ to flat layout"
    )
    p_case_migrate.add_argument("--examiner", help="Primary examiner slug")
    p_case_migrate.add_argument(
        "--import-all", action="store_true", help="Re-ID and merge all examiners' data"
    )

    # review
    p_review = sub.add_parser("review", help="Review case status and audit trail")
    p_review.add_argument("--audit", action="store_true", help="Show audit log")
    p_review.add_argument(
        "--evidence", action="store_true", help="Show evidence integrity"
    )
    p_review.add_argument(
        "--findings", action="store_true", help="Show findings summary table"
    )
    p_review.add_argument(
        "--detail",
        action="store_true",
        help="Show full detail (with --findings or --timeline)",
    )
    p_review.add_argument(
        "--verify",
        action="store_true",
        help="Cross-check findings against approval records",
    )
    p_review.add_argument(
        "--mine",
        action="store_true",
        help="Filter HMAC verification to current examiner only",
    )
    p_review.add_argument(
        "--iocs",
        action="store_true",
        help="Extract IOCs from findings grouped by status",
    )
    p_review.add_argument(
        "--timeline", action="store_true", help="Show timeline events"
    )
    p_review.add_argument("--todos", action="store_true", help="Show TODO items")
    p_review.add_argument(
        "--open", action="store_true", help="Show only open TODOs (with --todos)"
    )
    p_review.add_argument("--status", help="Filter by status (DRAFT/APPROVED/REJECTED)")
    p_review.add_argument(
        "--start", help="Start date filter (ISO format, e.g. 2026-01-01)"
    )
    p_review.add_argument("--end", help="End date filter (ISO format, e.g. 2026-12-31)")
    p_review.add_argument("--type", help="Filter by event type (with --timeline)")
    p_review.add_argument("--limit", type=int, default=50, help="Limit entries shown")

    # exec
    p_exec = sub.add_parser("exec", help="Execute forensic command with audit trail")
    p_exec.add_argument(
        "--purpose",
        required=True,
        help="Why this command is being run (must appear BEFORE '--')",
    )
    p_exec.add_argument(
        "cmd", nargs=argparse.REMAINDER, help="Command to execute (after --)"
    )

    # lock-evidence / unlock-evidence
    sub.add_parser(
        "lock-evidence", help="Set evidence directory to read-only (bind mount)"
    )
    sub.add_parser("unlock-evidence", help="Unlock evidence directory for new files")

    # register-evidence
    p_reg = sub.add_parser(
        "register-evidence", help="Register evidence file (SHA-256 hash)"
    )
    p_reg.add_argument("path", help="Path to evidence file")
    p_reg.add_argument("--description", default="", help="Description of evidence")

    # todo
    p_todo = sub.add_parser("todo", help="Manage investigation TODOs")
    todo_sub = p_todo.add_subparsers(dest="todo_action", help="TODO actions")
    p_todo.add_argument(
        "--all", action="store_true", help="Show all TODOs including completed"
    )
    p_todo.add_argument("--assignee", default="", help="Filter by assignee")

    p_todo_add = todo_sub.add_parser("add", help="Add a new TODO")
    p_todo_add.add_argument("description", help="TODO description")
    p_todo_add.add_argument("--assignee", default="", help="Assign to analyst")
    p_todo_add.add_argument(
        "--priority", choices=["high", "medium", "low"], default="medium"
    )
    p_todo_add.add_argument(
        "--finding", action="append", help="Related finding ID (repeatable)"
    )

    p_todo_complete = todo_sub.add_parser("complete", help="Mark TODO as completed")
    p_todo_complete.add_argument("todo_id", help="TODO ID")

    p_todo_update = todo_sub.add_parser("update", help="Update a TODO")
    p_todo_update.add_argument("todo_id", help="TODO ID")
    p_todo_update.add_argument("--note", help="Add a note")
    p_todo_update.add_argument("--assignee", help="Reassign")
    p_todo_update.add_argument(
        "--priority", choices=["high", "medium", "low"], help="Change priority"
    )

    # join (top-level command for remote machines)
    p_join = sub.add_parser("join", help="Join a SIFT gateway from a remote machine")
    p_join.add_argument(
        "--sift",
        required=True,
        help="SIFT gateway address (e.g., 10.0.0.5 or 10.0.0.5:4508)",
    )
    p_join.add_argument(
        "--code", required=True, help="Join code from 'vhir setup join-code'"
    )
    p_join.add_argument(
        "--wintools", action="store_true", help="This is a wintools machine"
    )
    p_join.add_argument("--ca-cert", help="Path to CA certificate for TLS verification")
    p_join.add_argument(
        "--skip-setup", action="store_true", help="Skip client config generation"
    )

    # setup
    p_setup = sub.add_parser("setup", help="Configure LLM client and test connectivity")
    setup_sub = p_setup.add_subparsers(dest="setup_action")
    setup_sub.add_parser("test", help="Test connectivity to all detected MCP servers")

    p_client = setup_sub.add_parser(
        "client", help="Configure LLM client for Valhuntir endpoints"
    )
    p_client.add_argument(
        "--client",
        choices=[
            "claude-code",
            "claude-desktop",
            "librechat",
            "other",
        ],
        help="Target LLM client",
    )
    p_client.add_argument(
        "--sift", help="SIFT gateway URL (e.g., http://127.0.0.1:4508)"
    )
    p_client.add_argument(
        "--windows", help="Windows wintools-mcp endpoint (e.g., 192.168.1.20:4624)"
    )
    p_client.add_argument("--windows-token", help="Windows wintools-mcp bearer token")
    p_client.add_argument(
        "--remnux",
        nargs="?",
        const="",
        help="REMnux endpoint (e.g., 192.168.1.30:3000)",
    )
    p_client.add_argument("--remnux-token", help="REMnux bearer token")
    p_client.add_argument(
        "--add-remnux",
        nargs="?",
        const="",
        help="Add/update only the remnux-mcp entry in existing config",
    )
    p_client.add_argument("--examiner", help="Examiner identity")
    p_client.add_argument(
        "--no-mslearn", action="store_true", help="Exclude Microsoft Learn MCP"
    )
    p_client.add_argument(
        "-y", "--yes", action="store_true", help="Accept defaults, no prompts"
    )
    p_client.add_argument(
        "--remote",
        action="store_true",
        help="Remote setup mode (gateway on another host)",
    )
    p_client.add_argument("--token", help="Bearer token for gateway authentication")
    p_client.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove Valhuntir forensic controls",
    )

    p_join_code = setup_sub.add_parser(
        "join-code", help="Generate a join code for remote machines"
    )
    p_join_code.add_argument("--expires", type=int, help="Expiry in hours (default: 2)")

    # export
    p_export = sub.add_parser("export", help="Export findings + timeline as JSON")
    p_export.add_argument("--file", required=True, help="Output file path")
    p_export.add_argument(
        "--since",
        default="",
        help="Only export records modified after this ISO timestamp",
    )

    # merge
    p_merge = sub.add_parser(
        "merge", help="Merge incoming JSON into local findings + timeline"
    )
    p_merge.add_argument("--file", required=True, help="Input file path")

    # config
    p_config = sub.add_parser("config", help="Configure Valhuntir settings")
    p_config.add_argument("--examiner", help="Set examiner identity")
    p_config.add_argument(
        "--analyst", dest="examiner", help="(deprecated, use --examiner)"
    )
    p_config.add_argument(
        "--show", action="store_true", help="Show current configuration"
    )
    p_config.add_argument(
        "--setup-password",
        action="store_true",
        help="Set approval password for current examiner",
    )
    p_config.add_argument(
        "--reset-password",
        action="store_true",
        help="Reset approval password (requires current password)",
    )

    # report
    p_report = sub.add_parser("report", help="Generate case reports")
    p_report.add_argument("--full", action="store_true", help="Full case report (JSON)")
    p_report.add_argument(
        "--executive-summary", action="store_true", help="Executive summary"
    )
    p_report.add_argument(
        "--timeline",
        dest="report_timeline",
        action="store_true",
        help="Timeline report",
    )
    p_report.add_argument(
        "--from", dest="from_date", help="Start date filter (ISO format)"
    )
    p_report.add_argument("--to", dest="to_date", help="End date filter (ISO format)")
    p_report.add_argument(
        "--ioc", action="store_true", help="IOC report from approved findings"
    )
    p_report.add_argument(
        "--findings", dest="report_findings", help="Finding IDs (comma-separated)"
    )
    p_report.add_argument(
        "--status-brief", action="store_true", help="Quick status counts"
    )
    p_report.add_argument(
        "--save", help="Save output to file (relative paths use case_dir/reports/)"
    )

    # evidence (subcommand group)
    p_evidence = sub.add_parser("evidence", help="Evidence management")
    evidence_sub = p_evidence.add_subparsers(
        dest="evidence_action", help="Evidence actions"
    )

    p_ev_register = evidence_sub.add_parser(
        "register", help="Register evidence file (SHA-256 hash)"
    )
    p_ev_register.add_argument("path", help="Path to evidence file")
    p_ev_register.add_argument(
        "--description", default="", help="Description of evidence"
    )

    evidence_sub.add_parser("list", help="List registered evidence files")

    evidence_sub.add_parser(
        "verify", help="Re-hash registered evidence, report modifications"
    )

    p_ev_log = evidence_sub.add_parser("log", help="Show evidence access log")
    p_ev_log.add_argument("--path", dest="path_filter", help="Filter by path substring")

    evidence_sub.add_parser("lock", help="Set evidence directory to read-only")
    evidence_sub.add_parser("unlock", help="Unlock evidence directory for new files")

    # audit
    p_audit = sub.add_parser("audit", help="View audit trail")
    audit_sub = p_audit.add_subparsers(dest="audit_action", help="Audit actions")

    p_audit_log = audit_sub.add_parser("log", help="Show audit log entries")
    p_audit_log.add_argument(
        "--limit", type=int, default=50, help="Limit entries shown"
    )
    p_audit_log.add_argument("--mcp", help="Filter by MCP name")
    p_audit_log.add_argument("--tool", help="Filter by tool name")

    audit_sub.add_parser("summary", help="Audit summary: counts per MCP and tool")

    # service
    p_service = sub.add_parser("service", help="Manage gateway backend services")
    p_service.add_argument("--gateway", help="Gateway URL (overrides config)")
    p_service.add_argument("--token", help="Bearer token (overrides config)")
    service_sub = p_service.add_subparsers(dest="service_action")

    service_sub.add_parser("status", help="Show status of all backend services")

    p_svc_start = service_sub.add_parser("start", help="Start a backend service")
    p_svc_start.add_argument(
        "backend_name",
        nargs="?",
        default=None,
        help="Backend name to start (omit for all)",
    )

    p_svc_stop = service_sub.add_parser("stop", help="Stop a backend service")
    p_svc_stop.add_argument(
        "backend_name",
        nargs="?",
        default=None,
        help="Backend name to stop (omit for all)",
    )

    p_svc_restart = service_sub.add_parser("restart", help="Restart a backend service")
    p_svc_restart.add_argument(
        "backend_name",
        nargs="?",
        default=None,
        help="Backend name to restart (omit for all)",
    )

    # update
    p_update = sub.add_parser("update", help="Pull latest code and redeploy")
    p_update.add_argument(
        "--check",
        action="store_true",
        help="Check for updates without applying",
    )
    p_update.add_argument(
        "--no-restart",
        action="store_true",
        help="Skip gateway restart",
    )

    # portal / dashboard
    sub.add_parser("portal", help="Open the Examiner Portal in your browser")
    sub.add_parser("dashboard", help="Open the legacy dashboard (v1)")

    # Plugin discovery — external packages register subcommands
    from importlib.metadata import entry_points

    registered = set(sub.choices.keys())
    for ep in entry_points(group="vhir.plugins"):
        try:
            register_fn = ep.load()
            register_fn(sub, registered)
        except Exception as e:
            print(f"Warning: failed to load plugin {ep.name}: {e}", file=sys.stderr)

    return parser


def main() -> None:
    parser = build_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Identity check on every command
    flag_override = getattr(args, "examiner_override", None)
    identity = get_examiner_identity(flag_override)
    warn_if_unconfigured(identity)

    dispatch = {
        "backup": cmd_backup,
        "restore": cmd_restore,
        "approve": cmd_approve,
        "reject": cmd_reject,
        "review": cmd_review,
        "exec": cmd_exec,
        "lock-evidence": cmd_lock_evidence,
        "unlock-evidence": cmd_unlock_evidence,
        "register-evidence": cmd_register_evidence,
        "config": cmd_config,
        "todo": cmd_todo,
        "setup": cmd_setup,
        "export": cmd_export,
        "merge": cmd_merge,
        "case": _cmd_case,
        "report": cmd_report,
        "evidence": cmd_evidence,
        "audit": cmd_audit,
        "service": cmd_service,
        "join": cmd_join,
        "update": cmd_update,
        "portal": cmd_portal,
        "dashboard": cmd_dashboard,
    }

    handler = dispatch.get(args.command)
    if handler:
        try:
            handler(args, identity)
        except CaseError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    elif hasattr(args, "func"):
        try:
            args.func(args, identity)
        except SystemExit:
            raise
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


def _cmd_case(args, identity: dict) -> None:
    """Handle case subcommands."""
    action = getattr(args, "case_action", None)
    if action == "init":
        _case_init(args, identity)
    elif action == "activate":
        _case_activate(args, identity)
    elif action == "close":
        _case_close(args, identity)
    elif action == "reopen":
        _case_reopen(args, identity)
    elif action == "migrate":
        cmd_migrate(args, identity)
    elif action == "status":
        _case_status(args, identity)
    elif action == "list":
        _case_list(args, identity)
    else:
        print(
            "Usage: vhir case {init|activate|close|reopen|status|list|migrate}",
            file=sys.stderr,
        )
        sys.exit(1)


def _case_status_data(case_dir) -> dict:
    """Return case status as structured data.

    Args:
        case_dir: Path to the case directory.

    Returns:
        Dict with case_id, name, status, examiner, path, counts.

    Raises:
        ValueError: If case_dir is not a valid case directory.
    """
    from pathlib import Path

    import yaml

    from vhir_cli.case_io import load_findings, load_timeline, load_todos

    case_dir = Path(case_dir)
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        raise ValueError(f"Not a Valhuntir case directory: {case_dir}")

    with open(meta_file) as f:
        meta = yaml.safe_load(f) or {}

    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    draft_f = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved_f = sum(1 for f in findings if f.get("status") == "APPROVED")
    draft_t = sum(1 for t in timeline if t.get("status") == "DRAFT")
    approved_t = sum(1 for t in timeline if t.get("status") == "APPROVED")
    open_todos = sum(1 for t in todos if t.get("status") == "open")

    return {
        "case_id": meta.get("case_id", case_dir.name),
        "name": meta.get("name", "(unnamed)"),
        "status": meta.get("status", "unknown"),
        "examiner": meta.get("examiner", "unknown"),
        "path": str(case_dir),
        "finding_count": len(findings),
        "finding_draft": draft_f,
        "finding_approved": approved_f,
        "timeline_count": len(timeline),
        "timeline_draft": draft_t,
        "timeline_approved": approved_t,
        "todo_open": open_todos,
        "todo_total": len(todos),
    }


def _case_status(args, identity: dict) -> None:
    """CLI wrapper — prints formatted case status."""
    from vhir_cli.case_io import get_case_dir

    try:
        case_dir = get_case_dir(getattr(args, "case", None))
    except SystemExit:
        return

    try:
        data = _case_status_data(case_dir)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return

    print(f"Case: {data['case_id']}")
    print(f"  Name:     {data['name']}")
    print(f"  Status:   {data['status']}")
    print(f"  Examiner: {data['examiner']}")
    print(f"  Path:     {data['path']}")
    print(
        f"  Findings: {data['finding_count']} ({data['finding_draft']} draft, {data['finding_approved']} approved)"
    )
    print(
        f"  Timeline: {data['timeline_count']} ({data['timeline_draft']} draft, {data['timeline_approved']} approved)"
    )
    print(f"  TODOs:    {data['todo_open']} open / {data['todo_total']} total")

    pending = data["finding_draft"] + data["timeline_draft"]
    if pending:
        print(f"\n  {pending} item(s) awaiting approval — run: vhir approve")


def _case_list_data(cases_dir=None) -> dict:
    """Return list of cases as structured data.

    Args:
        cases_dir: Path to cases directory. Defaults to VHIR_CASES_DIR env or "cases".

    Returns:
        Dict with "cases" list, each entry having id, name, status, active bool.
    """
    import os
    from pathlib import Path

    import yaml

    if cases_dir is None:
        cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    else:
        cases_dir = Path(cases_dir)

    if not cases_dir.is_dir():
        return {"cases": []}

    # Determine active case (file may contain absolute path or legacy bare ID)
    active_case_dir_name = None
    active_file = Path.home() / ".vhir" / "active_case"
    if active_file.exists():
        try:
            content = active_file.read_text().strip()
            if os.path.isabs(content):
                active_case_dir_name = Path(content).name
            else:
                active_case_dir_name = content
        except OSError:
            pass

    cases = []
    for entry in sorted(cases_dir.iterdir()):
        if not entry.is_dir():
            continue
        meta_file = entry / "CASE.yaml"
        if not meta_file.exists():
            continue
        try:
            with open(meta_file) as f:
                meta = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError):
            meta = {}
        cases.append(
            {
                "id": meta.get("case_id", entry.name),
                "name": meta.get("name", ""),
                "status": meta.get("status", "unknown"),
                "active": entry.name == active_case_dir_name,
            }
        )

    return {"cases": cases}


def _case_list(args, identity: dict) -> None:
    """CLI wrapper — prints formatted case list."""
    import os
    from pathlib import Path

    cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    if not cases_dir.is_dir():
        print(f"No cases directory found: {cases_dir}")
        return

    data = _case_list_data(cases_dir)

    cases = data["cases"]
    if not cases:
        print("No cases found.")
        return

    print(f"{'Case ID':<25} {'Status':<10} Name")
    print("-" * 65)
    for c in cases:
        marker = " (active)" if c["active"] else ""
        print(f"{c['id']:<25} {c['status']:<10} {c['name']}{marker}")


def _case_init_data(
    name: str, examiner: str, description: str = "", cases_dir=None, case_id=None
) -> dict:
    """Create a new case and return structured data.

    Args:
        name: Case name.
        examiner: Examiner identity slug.
        description: Optional case description.
        cases_dir: Path to cases directory. Defaults to VHIR_CASES_DIR env or "cases".

    Returns:
        Dict with case_id, case_dir, examiner, created.

    Raises:
        ValueError: If examiner is empty or case directory already exists.
        OSError: If directory/file creation fails.
    """
    import json
    import os
    from datetime import datetime, timezone
    from pathlib import Path

    import yaml

    from vhir_cli.case_io import _atomic_write

    if cases_dir is None:
        cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    else:
        cases_dir = Path(cases_dir)

    if not examiner:
        raise ValueError("Cannot initialize case: examiner identity is empty.")

    ts = datetime.now(timezone.utc)
    if not case_id:
        case_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
    else:
        import re

        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$", case_id):
            raise ValueError(
                "case_id must be alphanumeric with hyphens/underscores, "
                "start with letter/digit, 2-64 chars"
            )
    case_dir = cases_dir / case_id

    if case_dir.exists():
        raise ValueError(f"Case directory already exists: {case_dir}")

    # Create flat directory structure
    case_dir.mkdir(parents=True)
    for subdir in ("evidence", "extractions", "reports", "audit"):
        (case_dir / subdir).mkdir()

    case_meta = {
        "case_id": case_id,
        "name": name,
        "description": description,
        "status": "open",
        "examiner": examiner,
        "created": ts.isoformat(),
    }

    _atomic_write(
        case_dir / "CASE.yaml", yaml.dump(case_meta, default_flow_style=False)
    )

    for fname in ("findings.json", "timeline.json", "todos.json"):
        with open(case_dir / fname, "w") as f:
            f.write("[]")
            f.flush()
            os.fsync(f.fileno())
    with open(case_dir / "evidence.json", "w") as f:
        json.dump({"files": []}, f)
        f.flush()
        os.fsync(f.fileno())

    # chmod 444 on protected case data files
    fs_warning = ""
    try:
        import subprocess

        result = subprocess.run(
            ["stat", "-f", "-c", "%T", str(case_dir)],
            capture_output=True,
            text=True,
        )
        fs_type = result.stdout.strip().lower()
        _NON_POSIX = {"fuseblk", "vfat", "exfat", "ntfs"}
        if fs_type in _NON_POSIX:
            fs_warning = (
                f"Filesystem ({fs_type}) does not support POSIX permissions. "
                "chmod 444 protection will not be enforced."
            )
    except (OSError, FileNotFoundError):
        pass

    if not fs_warning:
        for fname in (
            "findings.json",
            "timeline.json",
        ):
            try:
                os.chmod(case_dir / fname, 0o444)
            except OSError:
                pass

    # Set active case pointer
    try:
        vhir_dir = Path.home() / ".vhir"
        vhir_dir.mkdir(exist_ok=True)
        _atomic_write(vhir_dir / "active_case", str(case_dir.resolve()))
    except OSError:
        pass  # non-fatal — CLI wrapper will warn

    result = {
        "case_id": case_id,
        "case_dir": str(case_dir),
        "examiner": examiner,
        "created": ts.isoformat(),
    }
    if fs_warning:
        result["fs_warning"] = fs_warning
    return result


def _set_case_wintools_permissions(case_dir: Path) -> None:
    """Set group-based permissions for wintools access on a case directory."""
    import grp
    import os

    try:
        sift_gid = grp.getgrnam("sift").gr_gid
    except KeyError:
        raise RuntimeError(
            "Group 'sift' not found. Run 'vhir setup join-code' to set up wintools integration."
        ) from None

    # Create extractions/wintools/ with setgid + group-writable
    wintools_dir = case_dir / "extractions" / "wintools"
    wintools_dir.mkdir(parents=True, exist_ok=True)
    os.chown(str(wintools_dir), -1, sift_gid)
    os.chmod(str(wintools_dir), 0o2775)

    # Create audit/wintools-mcp.jsonl with group-writable
    audit_file = case_dir / "audit" / "wintools-mcp.jsonl"
    if not audit_file.exists():
        audit_file.parent.mkdir(parents=True, exist_ok=True)
        audit_file.touch()
    os.chown(str(audit_file), -1, sift_gid)
    os.chmod(str(audit_file), 0o664)


def _wintools_configured() -> bool:
    """Check if Samba sharing is set up (samba.yaml exists with share_name)."""
    from pathlib import Path

    import yaml

    p = Path.home() / ".vhir" / "samba.yaml"
    if not p.is_file():
        return False
    try:
        doc = yaml.safe_load(p.read_text())
        return bool(doc and doc.get("share_name"))
    except Exception:
        return False


def _gateway_has_wintools() -> bool:
    """Check if gateway.yaml has a wintools-mcp backend."""
    from pathlib import Path

    import yaml

    p = Path.home() / ".vhir" / "gateway.yaml"
    if not p.is_file():
        return False
    try:
        doc = yaml.safe_load(p.read_text())
        return bool(doc and doc.get("backends", {}).get("wintools-mcp"))
    except Exception:
        return False


def _case_init(args, identity: dict) -> None:
    """CLI wrapper — creates case and prints summary."""
    import os
    from pathlib import Path

    name = args.name
    case_id = getattr(args, "case_id", None)
    description = getattr(args, "description", "")
    cases_dir = getattr(args, "cases_dir", None)

    if name is None:
        if not sys.stdin.isatty():
            print(
                "Error: case name required. Usage: vhir case init <name>",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            name = input("Case name: ").strip()
            while not name:
                name = input("Case name (required): ").strip()

            from datetime import datetime, timezone

            ts = datetime.now(timezone.utc)
            default_id = f"INC-{ts.strftime('%Y')}-{ts.strftime('%m%d%H%M%S')}"
            id_input = input(f"Case ID [{default_id}]: ").strip()
            case_id = id_input if id_input else default_id

            default_dir = os.environ.get("VHIR_CASES_DIR", str(Path.home() / "cases"))
            dir_input = input(f"Cases directory [{default_dir}]: ").strip()
            cases_dir = dir_input if dir_input else default_dir

            description = input("Description (optional): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

    try:
        data = _case_init_data(
            name=name,
            examiner=identity["examiner"],
            description=description,
            cases_dir=cases_dir,
            case_id=case_id,
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Case initialized: {data['case_id']}")
    print(f"  Name: {name}")
    print(f"  Examiner: {data['examiner']}")
    print(f"  Path: {data['case_dir']}")
    if data.get("fs_warning"):
        print(f"  WARNING: {data['fs_warning']}")

    # Wintools sharing (after case creation succeeds)
    if _wintools_configured():
        if sys.stdin.isatty():
            share = input("Share this case with wintools? [y/N] ").strip().lower()
        else:
            share = "n"
        if share in ("y", "yes"):
            try:
                from vhir_cli.commands.join import (
                    _repoint_samba_share,
                    notify_wintools_case_activated,
                )

                _set_case_wintools_permissions(Path(data["case_dir"]))
                _repoint_samba_share(Path(data["case_dir"]))
                notify_wintools_case_activated(data["case_id"])
                print("Case permissions set for wintools")
            except Exception as e:
                print(
                    f"Warning: Failed to set up wintools sharing: {e}",
                    file=sys.stderr,
                )
    elif _gateway_has_wintools():
        print("Tip: Run 'vhir setup join-code' to set up file sharing with wintools")

    print()
    print("Next steps:")
    print(f"  1. Copy evidence into: {data['case_dir']}/evidence/")
    print("  2. Register each file:  vhir evidence register <file>")
    print("  3. If using Claude Code, launch from the case directory")
    print("     to ensure proper sandbox scope:")
    print(f"       cd {data['case_dir']}")


def _case_activate_data(case_id: str, cases_dir=None) -> dict:
    """Activate a case and return structured data.

    Args:
        case_id: Case ID to activate.
        cases_dir: Path to cases directory. Defaults to VHIR_CASES_DIR env or "cases".

    Returns:
        Dict with case_id, case_dir.

    Raises:
        ValueError: If case_id is invalid or case not found.
        OSError: If active case pointer write fails.
    """
    import os
    from pathlib import Path

    from vhir_cli.case_io import _atomic_write

    if cases_dir is None:
        cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    else:
        cases_dir = Path(cases_dir)

    # Inline validation (avoids _validate_case_id's sys.exit)
    if not case_id or ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID: {case_id}")

    case_dir = cases_dir / case_id

    if not case_dir.exists():
        raise ValueError(f"Case not found: {case_id}")

    vhir_dir = Path.home() / ".vhir"
    vhir_dir.mkdir(exist_ok=True)
    _atomic_write(vhir_dir / "active_case", str(case_dir.resolve()))

    return {"case_id": case_id, "case_dir": str(case_dir)}


def _case_activate(args, identity: dict) -> None:
    """CLI wrapper — activates case and prints confirmation."""
    from pathlib import Path

    try:
        data = _case_activate_data(
            args.case_id,
            cases_dir=getattr(args, "cases_dir", None),
        )
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Failed to set active case: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Active case: {data['case_id']}")

    # Repoint share and notify wintools
    case_path = Path(data["case_dir"])
    if _wintools_configured():
        try:
            from vhir_cli.commands.join import (
                _repoint_samba_share,
                notify_wintools_case_activated,
            )

            _repoint_samba_share(case_path)
            notify_wintools_case_activated(args.case_id)
        except Exception as e:
            print(
                f"Warning: wintools share update failed: {e}",
                file=sys.stderr,
            )


def _case_close(args, identity: dict) -> None:
    """Close a case."""
    import os
    from datetime import datetime, timezone
    from pathlib import Path

    import yaml

    from vhir_cli.case_io import _validate_case_id

    case_id = args.case_id
    _validate_case_id(case_id)
    cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    case_dir = cases_dir / case_id

    if not case_dir.exists():
        print(f"Case not found: {case_id}", file=sys.stderr)
        sys.exit(1)

    confirm = input(f"Close case {case_id}? [y/N] ")
    if confirm.lower() != "y":
        print("Cancelled.")
        return

    meta_file = case_dir / "CASE.yaml"
    with open(meta_file) as f:
        meta = yaml.safe_load(f) or {}

    if meta.get("status") == "closed":
        print(f"Case {case_id} is already closed.")
        return

    meta["status"] = "closed"
    meta["closed"] = datetime.now(timezone.utc).isoformat()
    summary = getattr(args, "summary", "")
    if summary:
        meta["close_summary"] = summary

    from vhir_cli.case_io import _atomic_write as _aw

    _aw(meta_file, yaml.dump(meta, default_flow_style=False))

    # Clear wintools share
    if _wintools_configured():
        try:
            from vhir_cli.commands.join import (
                _repoint_samba_share,
                notify_wintools_case_deactivated,
            )

            _repoint_samba_share(None)
            notify_wintools_case_deactivated()
        except Exception as e:
            print(f"Warning: failed to clear wintools share: {e}", file=sys.stderr)

    # Copy verification ledger into case directory
    try:
        from vhir_cli.verification import copy_ledger_to_case

        copy_ledger_to_case(case_id, case_dir)
    except (ImportError, OSError):
        pass  # Non-fatal — ledger may not exist

    # Clear active case pointer if this was the active case
    active_file = Path.home() / ".vhir" / "active_case"
    if active_file.exists():
        try:
            current = active_file.read_text().strip()
            # Handle both absolute path and legacy bare case ID formats
            current_id = Path(current).name if os.path.isabs(current) else current
            if current_id == case_id:
                active_file.unlink()
        except OSError:
            pass

    print(f"Case {case_id} closed.")


def _case_reopen(args, identity: dict) -> None:
    """Reopen a closed case."""
    import os
    from pathlib import Path

    import yaml

    from vhir_cli.case_io import _atomic_write, _validate_case_id

    case_id = args.case_id
    _validate_case_id(case_id)
    cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
    case_dir = cases_dir / case_id

    if not case_dir.exists():
        print(f"Case not found: {case_id}", file=sys.stderr)
        sys.exit(1)

    meta_file = case_dir / "CASE.yaml"
    with open(meta_file) as f:
        meta = yaml.safe_load(f) or {}

    if meta.get("status") != "closed":
        print(
            f"Case {case_id} is not closed (status: {meta.get('status', 'unknown')})."
        )
        return

    meta["status"] = "open"
    meta.pop("closed", None)
    meta.pop("close_summary", None)

    _atomic_write(meta_file, yaml.dump(meta, default_flow_style=False))

    # Set as active case
    vhir_dir = Path.home() / ".vhir"
    vhir_dir.mkdir(exist_ok=True)
    _atomic_write(vhir_dir / "active_case", str(case_dir.resolve()))

    print(f"Case {case_id} reopened and set as active.")

    # Repoint share if this case is shared
    if _wintools_configured():
        try:
            from vhir_cli.commands.join import (
                _repoint_samba_share,
                notify_wintools_case_activated,
            )

            _repoint_samba_share(case_dir)
            notify_wintools_case_activated(case_id)
        except Exception as e:
            print(f"Warning: wintools share update failed: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
