"""Review case status, audit trail, evidence integrity, and findings.

Supports multiple view modes:
  vhir review                        — case summary
  vhir review --findings             — finding summary table
  vhir review --findings --detail    — full findings with all fields
  vhir review --findings --verify    — verify every signed decision (no password)
  vhir review --iocs                 — IOCs grouped by approval status
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
    _at_or_after,
    _at_or_before,
    display_instant,
    get_case_dir,
    load_audit_index,
    load_case_meta,
    load_findings,
    load_iocs,
    load_timeline,
    load_todos,
    load_withdrawals,
    no_terminal_line,
)
from vhir_cli.display import display_safe, one_line
from vhir_cli.display import lines as indent_lines
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
    """One line per audit id: where it came from, and the tool or command."""
    for raw_eid in audit_ids:
        entry = audit_index.get(raw_eid)
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
    try:
        withdrawals = load_withdrawals(case_dir)
    except Exception as e:  # a damaged audit line: say so, never "none"
        print(f"Withdrawn candidates couldn't be read: {e}")
        sys.exit(1)
    if not withdrawals:
        print("No candidate findings withdrawn after challenge.")
        return
    # Only the skeptic's calls are resolved below: index just those. A list's
    # unhashable id is left for the chain printer to meet, as before.
    wanted = set()
    for raw in withdrawals:
        ids = raw["result_summary"].get("skeptic_audit_ids")
        for eid in ids if isinstance(ids, list) else []:
            try:
                wanted.add(eid)
            except TypeError:
                continue
    audit_index = load_audit_index(case_dir, wanted)
    print(f"{len(withdrawals)} candidate finding(s) withdrawn after challenge")
    for raw in withdrawals:
        skeptic_ids = raw["result_summary"].get("skeptic_audit_ids") or []
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
        if isinstance(skeptic_ids, list) and skeptic_ids:
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
    wanted = {eid for f in findings for eid in (f.get("audit_ids") or [])}
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
        print(f"  Evidence:     {', '.join(f.get('audit_ids', []))}")
        print(f"  Observation:  {indent_lines(raw.get('observation', ''), ' ' * 16)}")
        print(
            f"  Interpretation: {indent_lines(raw.get('interpretation', ''), ' ' * 18)}"
        )
        if f.get("iocs"):
            print(f"  IOCs:         {f['iocs']}")
        # a finding's ids are mitre_ids (mitre_techniques is an IOC's field)
        if mitre := f.get("mitre_ids") or f.get("mitre_techniques"):
            print(f"  MITRE:        {mitre}")
        if f.get("approved_at"):
            print(f"  Approved:     {f['approved_at']}")
        if f.get("rejected_at"):
            print(f"  Rejected:     {f['rejected_at']}")
            print(f"  Reason:       {f.get('rejection_reason', '?')}")

        # Evidence chain
        audit_ids = raw.get("audit_ids", [])
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
                    display = content[:200]
                    if len(content) > 200:
                        display += "..."
                    # A block: each line indented under the artifact
                    print(f"        {indent_lines(display, ' ' * 8)}")

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
    """Extract IOCs from findings, grouped by approval status."""
    findings = load_findings(case_dir)
    if not findings:
        print("No findings recorded.")
        return

    groups = {"APPROVED": [], "DRAFT": [], "REJECTED": []}
    for f in findings:
        status = f.get("status", "DRAFT")
        if status in groups:
            groups[status].append(f)

    labels = {
        "APPROVED": "IOCs from Approved Findings",
        "DRAFT": "IOCs from Draft Findings (unverified)",
        "REJECTED": "IOCs from Rejected Findings",
    }

    any_iocs = False
    for status in ("APPROVED", "DRAFT", "REJECTED"):
        iocs = _extract_iocs_from_findings(groups[status])
        if not iocs:
            continue
        any_iocs = True
        print(f"\n=== {labels[status]} ===")
        for ioc_type, values in sorted(iocs.items()):
            shown = ", ".join(one_line(v) for v in sorted(values))
            print(f"  {one_line(ioc_type) + ':':<10} {shown}")

    if not any_iocs:
        print("No IOCs found in findings.")


def _extract_iocs_from_findings(findings: list[dict]) -> dict[str, set[str]]:
    """Extract IOCs from a list of findings."""
    collected: dict[str, set[str]] = {}

    for f in findings:
        iocs_field = f.get("iocs")
        if isinstance(iocs_field, dict):
            for ioc_type, values in iocs_field.items():
                if ioc_type not in collected:
                    collected[ioc_type] = set()
                if isinstance(values, list):
                    collected[ioc_type].update(str(v) for v in values)
                else:
                    collected[ioc_type].add(str(values))
        elif isinstance(iocs_field, list):
            for ioc in iocs_field:
                if isinstance(ioc, dict):
                    ioc_type = ioc.get("type", "Unknown")
                    ioc_value = ioc.get("value", "")
                    if ioc_type not in collected:
                        collected[ioc_type] = set()
                    collected[ioc_type].add(str(ioc_value))

        text = f"{f.get('observation', '')} {f.get('interpretation', '')}"
        _extract_text_iocs(text, collected)

    return collected


def _extract_text_iocs(text: str, collected: dict[str, set[str]]) -> None:
    """Extract common IOC patterns from free text."""
    ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    for ip in re.findall(ipv4_pattern, text):
        if not ip.startswith(("0.", "127.", "255.")):
            collected.setdefault("IPv4", set()).add(ip)

    for h in re.findall(r"\b[a-fA-F0-9]{64}\b", text):
        collected.setdefault("SHA256", set()).add(h.lower())

    for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])", text):
        collected.setdefault("SHA1", set()).add(h.lower())

    for h in re.findall(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])", text):
        collected.setdefault("MD5", set()).add(h.lower())

    for fp in re.findall(r"[A-Z]:\\(?:[^\s,;]+)", text):
        collected.setdefault("File", set()).add(fp)

    for d in re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|cc|tk)\b", text
    ):
        collected.setdefault("Domain", set()).add(d.lower())


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
    timeline.sort(key=lambda t: t.get("timestamp", ""))
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
            if t.get("audit_ids"):
                print(f"  Evidence:    {', '.join(t['audit_ids'])}")
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
            desc = one_line(t.get("description", ""))  # one row per event
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

    # Read from audit/
    audit_dir = case_dir / "audit"
    if audit_dir.is_dir():
        for jsonl_file in audit_dir.glob("*.jsonl"):
            try:
                with open(jsonl_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            print(
                                f"  Warning: skipping corrupt audit line in {jsonl_file.name}",
                                file=sys.stderr,
                            )
            except OSError as e:
                print(f"  Warning: could not read {jsonl_file}: {e}", file=sys.stderr)
                continue

    # Read approvals
    approvals_file = case_dir / "approvals.jsonl"
    if approvals_file.exists():
        try:
            with open(approvals_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        print(
                            "  Warning: skipping corrupt approval line", file=sys.stderr
                        )
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
