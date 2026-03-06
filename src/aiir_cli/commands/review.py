"""Review case status, audit trail, evidence integrity, and findings.

Supports multiple view modes:
  aiir review                        — case summary
  aiir review --findings             — finding summary table
  aiir review --findings --detail    — full findings with all fields
  aiir review --findings --verify    — cross-check against approvals.jsonl
  aiir review --iocs                 — IOCs grouped by approval status
  aiir review --timeline             — timeline summary
  aiir review --timeline --detail    — full timeline with evidence refs
  aiir review --evidence             — evidence registry
  aiir review --audit                — audit trail
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from aiir_cli.case_io import (
    get_case_dir,
    hmac_text,
    load_audit_index,
    load_case_meta,
    load_findings,
    load_timeline,
    load_todos,
    verify_approval_integrity,
)

_EM_DASH = "\u2014"


def cmd_review(args, identity: dict) -> None:
    """Review case information."""
    case_dir = get_case_dir(getattr(args, "case", None))

    if getattr(args, "todos", False):
        _show_todos(case_dir, open_only=getattr(args, "open", False))
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
        verify = getattr(args, "verify", False)
        if verify:
            mine_only = getattr(args, "mine", False)
            _show_findings_verify(case_dir, identity=identity, mine_only=mine_only)
        elif detail:
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

    print(f"Case: {meta.get('case_id', '?')}")
    print(f"Name: {meta.get('name', '')}")
    print(f"Status: {meta.get('status', 'unknown')}")
    print(f"Examiner: {meta.get('examiner', '?')}")
    print(f"Created: {meta.get('created', '?')}")
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
        todo_id = t["todo_id"]
        status = t.get("status", "open")
        priority = t.get("priority", "medium")
        assignee = t.get("assignee", "") or "-"
        desc = t.get("description", "")[:40]
        print(f"{todo_id:<16} {status:<11} {priority:<9} {assignee:<12} {desc}")

    if any(t.get("notes") for t in todos):
        print()
        for t in todos:
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
        title = f.get("title", "Untitled")
        if len(title) > 37:
            title = title[:37] + "..."
        confidence = f.get("confidence", "?")
        provenance = f.get("provenance", _EM_DASH)
        status = f.get("status", "?")
        print(f"{title:<40} {confidence:<12} {provenance:<12} {status:<10}")


def _show_findings_detail(case_dir: Path) -> None:
    """Show full findings with all fields."""
    findings = load_findings(case_dir)
    if not findings:
        print("No findings recorded.")
        return

    audit_index = load_audit_index(case_dir)

    for f in findings:
        print(f"\n{'=' * 60}")
        print(f"  [{f['id']}] {f.get('title', 'Untitled')}")
        print(f"{'=' * 60}")
        print(f"  ID: {f['id']} | Examiner: {f.get('examiner', '?')}")
        print(f"  Status:       {f.get('status', '?')}")
        print(f"  Confidence:   {f.get('confidence', '?')}")
        if f.get("confidence_justification"):
            print(f"  Justification: {f['confidence_justification']}")
        print(f"  Provenance:   {f.get('provenance', _EM_DASH)}")
        print(f"  Evidence:     {', '.join(f.get('evidence_ids', []))}")
        print(f"  Observation:  {f.get('observation', '')}")
        print(f"  Interpretation: {f.get('interpretation', '')}")
        if f.get("iocs"):
            print(f"  IOCs:         {f['iocs']}")
        if f.get("mitre_techniques"):
            print(f"  MITRE:        {f['mitre_techniques']}")
        if f.get("approved_at"):
            print(f"  Approved:     {f['approved_at']}")
        if f.get("rejected_at"):
            print(f"  Rejected:     {f['rejected_at']}")
            print(f"  Reason:       {f.get('rejection_reason', '?')}")

        # Evidence chain
        evidence_ids = f.get("evidence_ids", [])
        if evidence_ids:
            print("\n  Evidence Chain:")
            for eid in evidence_ids:
                entry = audit_index.get(eid)
                if entry:
                    source_file = entry.get("_source_file", "")
                    ts = entry.get("ts", "")[:19]
                    if source_file == "claude-code.jsonl":
                        cmd = entry.get("command", "?")
                        print(f'    [HOOK]  {eid} {_EM_DASH} "{cmd}" @ {ts}')
                    elif eid.startswith("shell-"):
                        cmd = entry.get("params", {}).get("command", "?")
                        print(f'    [SHELL] {eid} {_EM_DASH} "{cmd}"')
                    else:
                        tool = entry.get("tool", "?")
                        params = entry.get("params", {})
                        params_summary = ", ".join(
                            f"{k}={v}" for k, v in list(params.items())[:3]
                        )
                        print(
                            f"    [MCP]   {eid} {_EM_DASH} {tool}({params_summary}) @ {ts}"
                        )
                else:
                    print(f"    [NONE]  {eid} {_EM_DASH} no audit record")

        # Artifacts (raw evidence)
        artifacts = f.get("artifacts", [])
        if artifacts:
            print("\n  Artifacts:")
            for i, art in enumerate(artifacts, 1):
                source = art.get("source", "?")
                extraction = art.get("extraction", "")
                content = art.get("content", "")
                content_type = art.get("content_type", "")
                badge = f" [{content_type}]" if content_type else ""
                print(f"    [{i}]{badge} {source}")
                if extraction:
                    print(f"        $ {extraction}")
                if content:
                    display = content[:200]
                    if len(content) > 200:
                        display += "..."
                    # Indent multiline content
                    lines = display.split("\n")
                    print(f"        {lines[0]}")
                    for line in lines[1:]:
                        print(f"        {line}")

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
) -> None:
    """Cross-check findings against approvals.jsonl and verification ledger."""
    results = verify_approval_integrity(case_dir)
    if not results:
        print("No findings recorded.")
        return

    # --- Content hash verification (existing) ---
    print("Content Hash Verification")
    print(f"{'ID':<20} {'Status':<12} {'Verification':<22} Title")
    print("-" * 80)
    for f in results:
        fid = f.get("id", "?")
        status = f.get("status", "?")
        verification = f.get("verification", "?")

        if verification == "confirmed":
            vdisplay = "confirmed"
        elif verification == "tampered":
            vdisplay = "TAMPERED"
        elif verification == "no approval record":
            vdisplay = "NO APPROVAL RECORD"
        else:
            vdisplay = "draft"

        title = f.get("title", "Untitled")
        print(f"{fid:<20} {status:<12} {vdisplay:<22} {title}")

    # Summary
    confirmed = sum(1 for f in results if f["verification"] == "confirmed")
    tampered = sum(1 for f in results if f["verification"] == "tampered")
    unverified = sum(1 for f in results if f["verification"] == "no approval record")
    draft = sum(1 for f in results if f["verification"] == "draft")
    parts = [f"{confirmed} confirmed"]
    if tampered:
        parts.append(f"{tampered} TAMPERED")
    parts.extend([f"{unverified} unverified", f"{draft} draft"])
    print(f"\n{', '.join(parts)}")
    if tampered:
        print("ALERT: Content was modified after approval. Investigate immediately.")
    if unverified:
        print("WARNING: Some findings have status changes without approval records.")

    # --- Ledger reconciliation (no password needed) ---
    _show_ledger_reconciliation(case_dir)

    # --- HMAC verification (requires password) ---
    _show_hmac_verification(case_dir, identity=identity, mine_only=mine_only)


def _show_ledger_reconciliation(case_dir: Path) -> None:
    """Show reconciliation between approved items and verification ledger."""
    try:
        from aiir_cli.verification import read_ledger
    except ImportError:
        return

    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)

    ledger = read_ledger(case_id)
    if not ledger:
        print(f"\nVerification Ledger: no entries for case {case_id}")
        return

    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    approved_findings = [f for f in findings if f.get("status") == "APPROVED"]
    approved_timeline = [t for t in timeline if t.get("status") == "APPROVED"]
    all_approved = approved_findings + approved_timeline

    items_by_id = {i["id"]: i for i in all_approved}
    ledger_by_id = {e["finding_id"]: e for e in ledger}
    all_ids = sorted(set(items_by_id) | set(ledger_by_id))

    print(f"\nVerification Ledger Reconciliation ({len(ledger)} entries)")
    print(f"{'ID':<20} {'Reconciliation':<25}")
    print("-" * 50)

    alerts = 0
    for item_id in all_ids:
        item = items_by_id.get(item_id)
        entry = ledger_by_id.get(item_id)
        if item and not entry:
            print(f"{item_id:<20} APPROVED_NO_VERIFICATION")
            alerts += 1
        elif entry and not item:
            print(f"{item_id:<20} VERIFICATION_NO_FINDING")
            alerts += 1
        elif item and entry:
            desc = hmac_text(item)
            snap = entry.get("content_snapshot", "")
            if desc != snap:
                print(f"{item_id:<20} DESCRIPTION_MISMATCH")
                alerts += 1
            else:
                print(f"{item_id:<20} VERIFIED")

    if alerts:
        print(
            f"\n{alerts} alert(s) found. Run 'aiir review --findings --verify' with password for full HMAC check."
        )


def _show_hmac_verification(
    case_dir: Path,
    identity: dict | None = None,
    mine_only: bool = False,
) -> None:
    """Perform full HMAC verification with password prompt."""
    try:
        from aiir_cli.approval_auth import get_analyst_salt, getpass_prompt
        from aiir_cli.verification import read_ledger, verify_items
    except ImportError:
        return

    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)
    config_path = Path.home() / ".aiir" / "config.yaml"

    ledger = read_ledger(case_id)
    if not ledger:
        return

    # Group entries by examiner
    examiners = sorted(
        set(e.get("approved_by", "") for e in ledger if e.get("approved_by"))
    )
    if not examiners:
        return

    if mine_only and identity:
        examiners = [e for e in examiners if e == identity.get("examiner")]

    print("\nHMAC Verification (password required)")
    print(f"Examiners with ledger entries: {', '.join(examiners)}")

    for examiner in examiners:
        try:
            print(f"\n  Verifying entries for examiner '{examiner}':")
            password = getpass_prompt(f"  Enter password for '{examiner}': ")
            salt = get_analyst_salt(config_path, examiner)
            results = verify_items(case_id, password, salt, examiner)

            confirmed = sum(1 for r in results if r["verified"])
            failed = sum(1 for r in results if not r["verified"])

            for r in results:
                status = "CONFIRMED" if r["verified"] else "TAMPERED"
                print(f"    {r['finding_id']:<20} {status}")

            print(f"  {confirmed} confirmed, {failed} failed")
            if failed:
                print(
                    "  ALERT: HMAC mismatch detected. Findings may have been tampered with."
                )
        except (ValueError, RuntimeError) as e:
            print(f"  Skipped: {e}")


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
            print(f"  {ioc_type + ':':<10} {', '.join(sorted(values))}")

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
        timeline = [t for t in timeline if t.get("timestamp", "") >= start]
    if end:
        timeline = [t for t in timeline if t.get("timestamp", "") <= end]
    if event_type:
        timeline = [t for t in timeline if t.get("event_type", "") == event_type]
    if not timeline:
        print("No timeline events recorded.")
        return

    if detail:
        for t in timeline:
            print(f"\n{'=' * 60}")
            print(f"  [{t['id']}] {t.get('timestamp', '?')}")
            print(f"{'=' * 60}")
            print(f"  Status:      {t.get('status', '?')}")
            print(f"  Description: {t.get('description', '')}")
            if t.get("evidence_ids"):
                print(f"  Evidence:    {', '.join(t['evidence_ids'])}")
            if t.get("source"):
                print(f"  Source:      {t['source']}")
            if t.get("approved_at"):
                print(f"  Approved:    {t['approved_at']}")
    else:
        print(f"{'ID':<20} {'Status':<10} {'Timestamp':<22} Description")
        print("-" * 80)
        for t in timeline:
            tid = t.get("id", "?")
            item_status = t.get("status", "?")
            ts = t.get("timestamp", "?")[:19] if t.get("timestamp") else "?"
            desc = t.get("description", "")
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

    for e in evidence:
        print(f"\n  {e.get('path', '?')}")
        print(f"    SHA256: {e.get('sha256', '?')}")
        print(f"    Description: {e.get('description', '')}")
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
                    entry["mcp"] = "aiir-cli"
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
        ts = e.get("ts", "?")[:19]
        mcp = e.get("mcp", "?")
        tool = e.get("tool", "?")
        eid = e.get("evidence_id", "")
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
