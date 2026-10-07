"""Audit trail commands.

Read and summarize audit entries from the case directory:
  vhir audit log [--limit N] [--mcp <name>] [--tool <name>]
  vhir audit summary
"""

from __future__ import annotations

import sys
from pathlib import Path

from vhir_cli.case_io import get_case_dir, tail_jsonl_entries


def cmd_audit(args, identity: dict) -> None:
    """Handle audit subcommands."""
    action = getattr(args, "audit_action", None)
    if action == "log":
        _audit_log(args)
    elif action == "summary":
        _audit_summary(args)
    else:
        print("Usage: vhir audit {log|summary}", file=sys.stderr)
        sys.exit(1)


def _make_keep(mcp_filter, tool_filter, mcp_default: str, tool_default: str):
    """Build the tail-read predicate matching the --mcp/--tool filters, or None.

    Applied to the raw entry, so it has to reproduce the defaults that
    _load_audit_entries fills in afterwards.
    """
    if not mcp_filter and not tool_filter:
        return None

    def keep(entry: dict) -> bool:
        if mcp_filter and entry.get("mcp", mcp_default) != mcp_filter:
            return False
        if tool_filter:
            return entry.get("tool", tool_default) == tool_filter
        return True

    return keep


def _load_audit_entries(
    case_dir: Path,
    limit: int | None = None,
    mcp_filter: str | None = None,
    tool_filter: str | None = None,
) -> list[dict]:
    """Load audit entries from audit/*.jsonl and approvals.jsonl.

    With `limit` set, only each file's tail is read — enough to cover a page of
    `limit` rows — instead of the whole append-only trail. The filters are
    pushed into that read, so a filtered page costs no more than the full scan
    it replaces and much less when the matches are recent; a filter with no
    recent match still reads the file out. `limit=None` loads everything, as
    the summary needs.
    """
    entries: list[dict] = []
    corrupt_lines = 0

    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
            stem = jsonl_file.stem
            keep = _make_keep(mcp_filter, tool_filter, stem, "")
            try:
                found, corrupt = tail_jsonl_entries(jsonl_file, limit, keep)
            except OSError as e:
                print(f"  Warning: could not read {jsonl_file}: {e}", file=sys.stderr)
                continue
            corrupt_lines += corrupt
            for entry in found:
                # Derive mcp name from filename if not present
                if "mcp" not in entry:
                    entry["mcp"] = stem
                entries.append(entry)

    approvals_file = case_dir / "approvals.jsonl"
    if approvals_file.exists():
        keep = _make_keep(mcp_filter, tool_filter, "vhir-cli", "approval")
        try:
            found, corrupt = tail_jsonl_entries(approvals_file, limit, keep)
        except OSError:
            found, corrupt = [], 0
        corrupt_lines += corrupt
        for entry in found:
            entry.setdefault("tool", "approval")
            entry.setdefault("mcp", "vhir-cli")
            entries.append(entry)

    if corrupt_lines:
        print(
            f"  Warning: {corrupt_lines} corrupt JSONL line(s) skipped in audit trail",
            file=sys.stderr,
        )

    entries.sort(key=lambda e: e.get("ts", ""))
    return entries


def _audit_log(args) -> None:
    """Show audit log entries with optional filters."""
    case_dir = get_case_dir(getattr(args, "case", None))

    mcp_filter = getattr(args, "mcp", None)
    tool_filter = getattr(args, "tool", None)
    limit = getattr(args, "limit", 50) or 50
    if limit < 1:
        print("Error: --limit must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    entries = _load_audit_entries(case_dir, limit, mcp_filter, tool_filter)
    entries = entries[-limit:]

    if not entries:
        print("No audit entries found.")
        return

    print(f"{'Timestamp':<22} {'Examiner':<12} {'MCP':<20} {'Tool':<25} Audit ID")
    print("-" * 100)
    for e in entries:
        ts = e.get("ts", "?")[:19]
        examiner = e.get("examiner", "?")
        mcp = e.get("mcp", "?")
        tool = e.get("tool", "?")
        eid = e.get("audit_id", "")
        print(f"{ts:<22} {examiner:<12} {mcp:<20} {tool:<25} {eid}")

    print(f"\nShowing {len(entries)} entries")


def audit_summary_data(case_dir) -> dict:
    """Return audit summary as structured data.

    Args:
        case_dir: Path to the active case directory.

    Returns:
        Dict with total_entries, audit_ids count, by_mcp, by_tool.
    """
    from pathlib import Path

    case_dir = Path(case_dir)
    entries = _load_audit_entries(case_dir)

    mcp_counts: dict[str, int] = {}
    tool_counts: dict[str, dict[str, int]] = {}
    audit_ids: set[str] = set()

    for e in entries:
        mcp = e.get("mcp", "unknown")
        tool = e.get("tool", "unknown")
        eid = e.get("audit_id", "")

        mcp_counts[mcp] = mcp_counts.get(mcp, 0) + 1

        if mcp not in tool_counts:
            tool_counts[mcp] = {}
        tool_counts[mcp][tool] = tool_counts[mcp].get(tool, 0) + 1

        if eid:
            audit_ids.add(eid)

    return {
        "total_entries": len(entries),
        "audit_ids": len(audit_ids),
        "by_mcp": mcp_counts,
        "by_tool": tool_counts,
    }


def _audit_summary(args) -> None:
    """CLI wrapper — prints formatted audit summary."""
    case_dir = get_case_dir(getattr(args, "case", None))
    data = audit_summary_data(case_dir)

    if data["total_entries"] == 0:
        print("No audit entries found.")
        return

    print("AUDIT SUMMARY")
    print("=" * 50)
    print(f"Total entries: {data['total_entries']}")
    print(f"Audit IDs:     {data['audit_ids']}")
    print()

    print("By MCP:")
    for mcp, count in sorted(data["by_mcp"].items()):
        print(f"  {mcp:<25} {count}")

    print()
    print("By Tool:")
    for mcp in sorted(data["by_tool"]):
        for tool, count in sorted(data["by_tool"][mcp].items()):
            print(f"  {mcp:<20} {tool:<25} {count}")
