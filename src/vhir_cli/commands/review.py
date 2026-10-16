"""Review case status, audit trail, evidence integrity, and findings.

Supports multiple view modes:
  vhir review                        — case summary
  vhir review --findings             — finding summary table
  vhir review --findings --detail    — full findings with all fields
  vhir review --findings --verify    — verify every signed decision (no password)
  vhir review --iocs                 — IOC records grouped by status
  vhir review --timeline             — timeline summary
  vhir review --timeline --detail    — full timeline with evidence refs
  vhir review --evidence             — evidence registry
  vhir review --audit                — audit trail
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from vhir_cli.case_io import (
    CORRUPT_LINE,
    _at_or_after,
    _at_or_before,
    display_instant,
    get_case_dir,
    iter_jsonl_entries,
    load_audit_index,
    load_case_meta,
    load_findings,
    load_iocs,
    load_timeline,
    load_todos,
    load_withdrawals,
    no_terminal_line,
    text_of,
)
from vhir_cli.display import cited as _cited
from vhir_cli.display import display_safe, ioc_text, list_text, one_line
from vhir_cli.display import lines as indent_lines
from vhir_cli.ioc_groups import (
    TEXT_ONLY,
    not_recorded,
    record_groups,
    record_status,
)
from vhir_cli.provenance_view import finding_lines, grade_label

_EM_DASH = "\u2014"


def cmd_review(args, identity: dict) -> None:
    """Review case information."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if getattr(args, "verify", False):
        mine_only = getattr(args, "mine", False)
        _show_findings_verify(
            case_dir, identity=identity, mine_only=mine_only, args=args
        )
    elif getattr(args, "todos", False):
        _show_todos(case_dir, open_only=getattr(args, "open", False))
    elif getattr(args, "withdrawn", False):
        _show_withdrawn(case_dir)
    elif getattr(args, "iocs", False):
        _show_iocs(case_dir)
    elif getattr(args, "timeline", False):
        detail = getattr(args, "detail", False)
        _show_timeline(
            case_dir,
            detail,
            status=getattr(args, "status", None),
            start=getattr(args, "start", None),
            end=getattr(args, "end", None),
            event_type=getattr(args, "type", None),
        )
    elif getattr(args, "audit", False):
        _show_audit(case_dir, getattr(args, "limit", 50))
    elif getattr(args, "evidence", False):
        _show_evidence(case_dir)
    elif getattr(args, "findings", False):
        detail = getattr(args, "detail", False)
        if detail:
            _show_findings_detail(case_dir)
        else:
            _show_findings_table(case_dir)
    else:
        _show_summary(case_dir)


def _show_summary(case_dir: Path) -> None:
    """Show case overview with status counts."""
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    evidence = _load_evidence(case_dir)

    print(f"Case: {one_line(meta.get('case_id', '?'))}")
    print(f"Name: {one_line(meta.get('name', ''))}")
    print(f"Status: {one_line(meta.get('status', 'unknown'))}")
    print(f"Examiner: {one_line(meta.get('examiner', '?'))}")
    print(f"Created: {one_line(meta.get('created', '?'))}")
    print()

    draft_f = sum(1 for f in findings if f.get("status") == "DRAFT")
    approved_f = sum(1 for f in findings if f.get("status") == "APPROVED")
    rejected_f = sum(1 for f in findings if f.get("status") == "REJECTED")
    print(
        f"Findings: {len(findings)} total ({draft_f} draft, {approved_f} approved, {rejected_f} rejected)"
    )

    draft_t = sum(1 for t in timeline if t.get("status") == "DRAFT")
    approved_t = sum(1 for t in timeline if t.get("status") == "APPROVED")
    print(f"Timeline: {len(timeline)} events ({draft_t} draft, {approved_t} approved)")

    print(f"Evidence: {len(evidence)} registered files")

    todos = load_todos(case_dir)
    open_t = sum(1 for t in todos if t.get("status") == "open")
    completed_t = sum(1 for t in todos if t.get("status") == "completed")
    print(f"TODOs: {len(todos)} total ({open_t} open, {completed_t} completed)")
    refused = no_terminal_line(case_dir)
    if refused:
        print(refused)


def _show_todos(case_dir: Path, open_only: bool = False) -> None:
    """Show TODO items in a table."""
    todos = load_todos(case_dir)
    if open_only:
        todos = [t for t in todos if t.get("status") == "open"]

    if not todos:
        print("No TODOs found.")
        return

    print(f"{'ID':<16} {'Status':<11} {'Priority':<9} {'Assignee':<12} Description")
    print("-" * 90)
    for t in todos:
        t = display_safe(t)  # for printing inline
        todo_id = t["todo_id"]
        status = t.get("status", "open")
        priority = t.get("priority", "medium")
        assignee = t.get("assignee", "") or "-"
        desc = one_line(t.get("description", ""))[:40]  # one row per todo
        print(f"{todo_id:<16} {status:<11} {priority:<9} {assignee:<12} {desc}")

    if any(t.get("notes") for t in todos):
        print()
        for t in todos:
            t = display_safe(t)
            for note in t.get("notes", []):
                print(f"  {t['todo_id']}: [{note.get('by', '?')}] {note['note']}")


def _show_findings_table(case_dir: Path) -> None:
    """Show findings as a summary table."""
    findings = load_findings(case_dir)
    if not findings:
        print("No findings recorded.")
        return

    print(f"{'Title':<40} {'Confidence':<12} {'Provenance':<12} {'Status':<10}")
    print("-" * 76)
    for f in findings:
        f = display_safe(f)  # for printing inline
        title = f.get("title", "Untitled")
        if len(title) > 37:
            title = title[:37] + "..."
        confidence = f.get("confidence", "?")
        provenance = grade_label(f, reason=False)
        status = f.get("status", "?")
        print(f"{title:<40} {confidence:<12} {provenance:<12} {status:<10}")


def _print_evidence_chain(audit_ids: list, audit_index: dict) -> None:
    """One line per audit id: where it came from, and the tool or command. An
    id that isn't text has no audit record."""
    for raw_eid in audit_ids:
        entry = audit_index.get(raw_eid) if isinstance(raw_eid, str) else None
        eid = one_line(raw_eid)
        if entry:
            entry = display_safe(entry)  # for printing inline
            source_file = entry.get("_source_file", "")
            ts = entry.get("ts", "")[:19]
            if source_file == "claude-code.jsonl":
                cmd = entry.get("command", "?")
                print(f'    [HOOK]  {eid} {_EM_DASH} "{cmd}" @ {ts}')
            elif raw_eid.startswith("shell-"):
                cmd = entry.get("params", {}).get("command", "?")
                print(f'    [SHELL] {eid} {_EM_DASH} "{cmd}"')
            else:
                tool = entry.get("tool", "?")
                params = entry.get("params", {})
                params_summary = ", ".join(
                    f"{k}={v}" for k, v in list(params.items())[:3]
                )
                print(f"    [MCP]   {eid} {_EM_DASH} {tool}({params_summary}) @ {ts}")
        else:
            print(f"    [NONE]  {eid} {_EM_DASH} no audit record")


def _show_withdrawn(case_dir: Path) -> None:
    """Candidate findings withdrawn after challenge, with the skeptic's evidence."""
    unread: list[str] = []
    try:
        withdrawals = load_withdrawals(case_dir, unread)
    except Exception as e:  # a damaged audit line: say so, never "none"
        print(f"Withdrawn candidates couldn't be read: {e}")
        sys.exit(1)
    if unread:  # never "none" while a log holding withdrawals went unread
        _print_withdrawn(case_dir, withdrawals)
        for log in unread:
            print(f"Couldn't read {log}: a candidate withdrawn there isn't shown.")
        sys.exit(1)
    if not withdrawals:
        print("No candidate findings withdrawn after challenge.")
        return
    _print_withdrawn(case_dir, withdrawals)


def _print_withdrawn(case_dir: Path, withdrawals: list[dict]) -> None:
    if not withdrawals:
        return
    # Only the skeptic's calls are resolved below: index just those.
    wanted = {
        eid
        for raw in withdrawals
        for eid in _cited(raw["result_summary"].get("skeptic_audit_ids"))
        if isinstance(eid, str)
    }
    audit_index = load_audit_index(case_dir, wanted)
    print(f"{len(withdrawals)} candidate finding(s) withdrawn after challenge")
    for raw in withdrawals:
        skeptic_ids = _cited(raw["result_summary"].get("skeptic_audit_ids"))
        entry = display_safe(raw)  # for printing inline
        result = entry["result_summary"]
        print(f"\n{'=' * 60}")
        print(
            f"  {entry.get('ts', '')[:19]}  {entry.get('examiner', '')}"
            f"  {entry.get('audit_id', '')}"
        )
        print(f"  Title:         {result.get('title', '')}")
        print(
            f"  Observation:   {indent_lines(raw['result_summary'].get('observation', ''), ' ' * 17)}"
        )
        print(f"  Contradiction: {result.get('contradiction', '')}")
        if skeptic_ids:
            print("\n  Skeptic's tool calls:")
            _print_evidence_chain(skeptic_ids, audit_index)


def _show_findings_detail(case_dir: Path) -> None:
    """Show full findings with all fields."""
    findings = load_findings(case_dir)
    if not findings:
        print("No findings recorded.")
        return

    # Only the audit_ids these findings cite are ever resolved below, so keep
    # the index bounded by that instead of by the whole audit trail.
    wanted = {
        eid
        for f in findings
        for eid in _cited(f.get("audit_ids"))
        if isinstance(eid, str)
    }
    audit_index = load_audit_index(case_dir, wanted)

    for raw in findings:
        f = display_safe(raw)  # for printing inline
        print(f"\n{'=' * 60}")
        print(f"  [{f['id']}] {f.get('title', 'Untitled')}")
        print(f"{'=' * 60}")
        print(f"  ID: {f['id']} | Examiner: {f.get('examiner', '?')}")
        print(f"  Status:       {f.get('status', '?')}")
        print(f"  Confidence:   {f.get('confidence', '?')}")
        if f.get("confidence_justification"):
            print(f"  Justification: {f['confidence_justification']}")
        print("\n".join(finding_lines(f)))
        audit_ids = _cited(raw.get("audit_ids"))
        print(f"  Evidence:     {', '.join(one_line(eid) for eid in audit_ids)}")
        print(f"  Observation:  {indent_lines(raw.get('observation', ''), ' ' * 16)}")
        print(
            f"  Interpretation: {indent_lines(raw.get('interpretation', ''), ' ' * 18)}"
        )
        if f.get("iocs"):
            print(f"  IOCs:         {one_line(ioc_text(raw['iocs']))}")
        # a finding's ids are mitre_ids (mitre_techniques is an IOC's field)
        if mitre := raw.get("mitre_ids") or raw.get("mitre_techniques"):
            print(f"  MITRE:        {one_line(list_text(mitre))}")
        if f.get("approved_at"):
            print(f"  Approved:     {f['approved_at']}")
        if f.get("rejected_at"):
            print(f"  Rejected:     {f['rejected_at']}")
            print(f"  Reason:       {f.get('rejection_reason', '?')}")

        # Evidence chain
        if audit_ids:
            print("\n  Evidence Chain:")
            _print_evidence_chain(audit_ids, audit_index)

        # Artifacts (raw evidence)
        artifacts = f.get("artifacts", [])
        if artifacts:
            print("\n  Artifacts:")
            for i, (art, raw_art) in enumerate(
                zip(artifacts, raw["artifacts"], strict=True), 1
            ):
                source = art.get("source", "?")
                extraction = art.get("extraction", "")
                content = str(raw_art.get("content") or "")
                content_type = art.get("content_type", "")
                badge = f" [{content_type}]" if content_type else ""
                print(f"    [{i}]{badge} {source}")
                if extraction:
                    print(f"        $ {extraction}")
                if content:
                    body, cut = _split_cut(content)
                    display = body[:200]
                    if len(body) > 200:
                        display += "..."
                    # A block: each line indented under the artifact
                    print(f"        {indent_lines(display, ' ' * 8)}")
                    if cut:  # the preview never hides that the text was cut
                        print(f"        {one_line(cut)}")

        # Supporting commands
        supporting = f.get("supporting_commands", [])
        if supporting:
            print("\n  Supporting Commands:")
            for i, cmd in enumerate(supporting, 1):
                print(f"    {i}. {cmd.get('command', '?')}")
                print(f"       Purpose: {cmd.get('purpose', '?')}")
                excerpt = cmd.get("output_excerpt", "")
                if excerpt:
                    display = excerpt[:120]
                    if len(excerpt) > 120:
                        display += "..."
                    print(f"       Output:  {display}")


def _show_findings_verify(
    case_dir: Path,
    identity: dict | None = None,
    mine_only: bool = False,
    args=None,
) -> None:
    """Verify every signed decision of the case (ledger.verify_case). No
    password, terminal or credential file is needed. Exit 0 or 2; a malformed
    pin or head exits 5. `--mine` only filters what's shown."""
    from vhir_cli.ledger_verify import (
        UsageError,
        parse_head,
        parse_pin,
        render,
        verify_case,
    )

    try:
        pins = [parse_pin(p) for p in getattr(args, "expect_key", None) or []]
        heads = [parse_head(h) for h in getattr(args, "expect_head", None) or []]
    except UsageError as e:
        print(f"vhir review: error: {e}", file=sys.stderr)
        sys.exit(5)
    ledgers = [Path(p) for p in getattr(args, "ledger", None) or []] or None
    result = verify_case(case_dir, ledgers, heads, pins)
    if mine_only and identity:
        me = identity.get("examiner")
        mine = {
            str(i.get("id"))
            for i in load_findings(case_dir)
            + load_timeline(case_dir)
            + load_iocs(case_dir)
            if isinstance(i, dict)
            and me in (i.get("approved_by"), i.get("rejected_by"))
        }
        code = result.exit_code
        result.items = [v for v in result.items if v.item_id in mine]
        print(render(result).rsplit("\n", 1)[0])
        print(f"Exit {code} (the whole case; --mine only filters what's shown)")
        sys.exit(code)
    print(render(result))
    sys.exit(result.exit_code)


def _show_iocs(case_dir: Path) -> None:
    """The case's IOC records, grouped by each record's own status as the
    Portal shows them, then the values the findings name that no record
    holds."""
    records = [r for r in load_iocs(case_dir) if isinstance(r, dict)]
    by_status: dict[str, list] = {}
    for r in records:
        by_status.setdefault(record_status(r), []).append(r)
    labels = {
        "APPROVED": "Approved IOCs",
        "DRAFT": "Draft IOCs (unverified)",
        "REJECTED": "Rejected IOCs",
    }
    order = [s for s in labels if s in by_status]
    order += sorted(s for s in by_status if s not in labels)
    shown = False
    for status in order:
        groups = record_groups(by_status[status])
        if not groups:
            continue
        shown = True
        print(f"\n=== {one_line(labels.get(status, status + ' IOCs'))} ===")
        for ioc_type, values in groups.items():
            print(
                f"  {one_line(ioc_type) + ':':<10} {', '.join(one_line(v) for v in values)}"
            )
    if not shown:
        print("IOC records: none")
    if rest := not_recorded(load_findings(case_dir), records):
        print(f"\n=== {TEXT_ONLY} ===")
        print(f"  {', '.join(one_line(v) for v in rest)}")


# The line forensic-mcp ends an artifact's content with when it stored only
# the first part of it
_CUT_LINE = re.compile(r"\n(\[cut: [0-9]+ of [0-9]+ chars stored\])\Z")


def _split_cut(content: str) -> tuple[str, str]:
    """The content, and the cut line it ends with ("" if none)."""
    m = _CUT_LINE.search(content)
    return (content[: m.start()], m.group(1)) if m else (content, "")


def _show_timeline(
    case_dir: Path,
    detail: bool,
    status: str | None = None,
    start: str | None = None,
    end: str | None = None,
    event_type: str | None = None,
) -> None:
    """Show timeline events with optional filters."""
    timeline = load_timeline(case_dir)
    timeline.sort(key=lambda t: text_of(t.get("timestamp")))
    if status:
        timeline = [t for t in timeline if t.get("status") == status.upper()]
    if start:
        timeline = [t for t in timeline if _at_or_after(t.get("timestamp", ""), start)]
    if end:
        timeline = [t for t in timeline if _at_or_before(t.get("timestamp", ""), end)]
    if event_type:
        timeline = [t for t in timeline if t.get("event_type", "") == event_type]
    if not timeline:
        print("No timeline events recorded.")
        return

    if detail:
        for raw in timeline:
            t = display_safe(raw)  # for printing inline
            print(f"\n{'=' * 60}")
            print(f"  [{t['id']}] {t.get('timestamp', '?')}")
            print(f"{'=' * 60}")
            print(f"  Status:      {t.get('status', '?')}")
            print(
                f"  Description: {indent_lines(raw.get('description', ''), ' ' * 15)}"
            )
            if audit_ids := _cited(raw.get("audit_ids")):
                print(f"  Evidence:    {', '.join(one_line(e) for e in audit_ids)}")
            if t.get("source"):
                print(f"  Source:      {t['source']}")
            if t.get("approved_at"):
                print(f"  Approved:    {t['approved_at']}")
    else:
        print(f"{'ID':<20} {'Status':<10} {'Timestamp':<22} Description")
        print("-" * 80)
        for t in timeline:
            tid = one_line(t.get("id", "?"))
            item_status = one_line(t.get("status", "?"))
            ts = one_line(display_instant(t.get("timestamp")))
            desc = one_line(text_of(t.get("description")))  # one row per event
            if len(desc) > 40:
                desc = desc[:37] + "..."
            print(f"{tid:<20} {item_status:<10} {ts:<22} {desc}")


def _show_evidence(case_dir: Path) -> None:
    """Show evidence registry and integrity status."""
    evidence = _load_evidence(case_dir)
    if not evidence:
        print("No evidence registered.")
        return

    print(f"{'=' * 60}")
    print(f"  Registered Evidence ({len(evidence)} files)")
    print(f"{'=' * 60}")

    for raw in evidence:
        e = display_safe(raw)  # for printing inline
        print(f"\n  {e.get('path', '?')}")
        print(f"    SHA256: {e.get('sha256', '?')}")
        print(f"    Description: {indent_lines(raw.get('description', ''), ' ' * 17)}")
        print(
            f"    Registered: {e.get('registered_at', '?')} by {e.get('registered_by', '?')}"
        )

    # Show access log if exists
    access_log = case_dir / "evidence_access.jsonl"
    if access_log.exists():
        print(f"\n{'=' * 60}")
        print("  Evidence Access Log")
        print(f"{'=' * 60}")
        try:
            with open(access_log, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        print("  Warning: skipping corrupt log line", file=sys.stderr)
                        continue
                    entry = display_safe(entry)  # for printing inline
                    print(
                        f"  {entry.get('ts', '?')} | {entry.get('action', '?')} | {entry.get('path', '?')} | {entry.get('examiner', '?')}"
                    )
        except OSError as e:
            print(
                f"  Warning: could not read evidence access log: {e}", file=sys.stderr
            )


def _show_audit(case_dir: Path, limit: int) -> None:
    """Show audit trail entries from audit/."""
    entries = []
    # A page of `limit` rows only needs each file's tail; a limit below 1 keeps
    # its old meaning of "everything" (entries[-0:] is the whole list).
    want = limit if limit >= 1 else None

    # Read from audit/
    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in audit_dir.glob("*.jsonl"):
            try:  # each entry as it is read, so those before a refusal are kept
                for entry in iter_jsonl_entries(jsonl_file, want):
                    if entry is CORRUPT_LINE:
                        print(
                            f"  Warning: skipping corrupt audit line in {one_line(jsonl_file.name)}",
                            file=sys.stderr,
                        )
                    else:
                        entries.append(entry)
            except OSError as e:
                print(
                    f"  Warning: could not read {one_line(f'{jsonl_file}: {e}')}",
                    file=sys.stderr,
                )

    # Read approvals
    approvals_file = case_dir / "approvals.jsonl"
    if approvals_file.exists():
        try:
            for entry in iter_jsonl_entries(approvals_file, want):
                if entry is CORRUPT_LINE:
                    print("  Warning: skipping corrupt approval line", file=sys.stderr)
                    continue
                entry["tool"] = "approval"
                entry["mcp"] = "vhir-cli"
                entries.append(entry)
        except OSError as e:
            print(f"  Warning: could not read {approvals_file}: {e}", file=sys.stderr)

    entries.sort(key=lambda e: e.get("ts", ""))
    entries = entries[-limit:]

    if not entries:
        print("No audit entries.")
        return

    print(f"{'=' * 60}")
    print(f"  Audit Trail (last {len(entries)} entries)")
    print(f"{'=' * 60}")

    for e in entries:
        e = display_safe(e)  # for printing inline
        ts = e.get("ts", "?")[:19]
        mcp = e.get("mcp", "?")
        tool = e.get("tool", "?")
        eid = e.get("audit_id", "")
        examiner = e.get("examiner", "?")
        print(f"  {ts} | {examiner:10s} | {mcp:20s} | {tool:25s} | {eid}")


def _load_evidence(case_dir: Path) -> list[dict]:
    reg_file = case_dir / "evidence.json"
    if not reg_file.exists():
        return []
    try:
        data = json.loads(reg_file.read_text())
        return data.get("files", [])
    except json.JSONDecodeError as e:
        print(f"Warning: evidence registry is corrupt: {e}", file=sys.stderr)
        return []
    except OSError as e:
        print(f"Warning: could not read evidence registry: {e}", file=sys.stderr)
        return []
