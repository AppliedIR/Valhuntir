"""Reject staged findings and timeline events.

Every rejection requires human confirmation via /dev/tty (or password).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_confirmation
from vhir_cli.case_io import (
    check_case_file_integrity,
    find_draft_item,
    get_case_dir,
    load_findings,
    load_timeline,
    save_findings,
    save_timeline,
    write_approval_log,
)


def cmd_reject(args, identity: dict) -> None:
    """Reject specific findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".vhir" / "config.yaml"

    review = getattr(args, "review", False)
    if review and args.ids:
        print("Error: --review cannot be used with specific IDs.", file=sys.stderr)
        sys.exit(1)

    if review:
        _interactive_reject(case_dir, identity, config_path)
        return

    if not args.ids:
        print(
            "Error: provide IDs to reject, or use --review for interactive mode.",
            file=sys.stderr,
        )
        sys.exit(1)

    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    to_reject = []

    for item_id in args.ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)
            continue
        _display_item(item)
        to_reject.append(item)

    if not to_reject:
        print("No items to reject.")
        return

    reason = getattr(args, "reason", "") or ""
    print(f"\n{len(to_reject)} item(s) to reject.")
    if reason:
        print(f"  Reason: {reason}")

    mode, _password = require_confirmation(config_path, identity["examiner"])

    # Reload from disk to preserve any concurrent MCP writes
    reject_ids = [item["id"] for item in to_reject]
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    now = datetime.now(timezone.utc).isoformat()
    rejected = []
    for item_id in reject_ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            continue
        item["status"] = "REJECTED"
        item["rejected_at"] = now
        item["rejected_by"] = identity["examiner"]
        item["modified_at"] = now
        if reason:
            item["rejection_reason"] = reason
        rejected.append(item_id)

    if not rejected:
        print("No items rejected.")
        return

    # Timeline rejection coupling: auto-created events follow their finding
    for tl_event in timeline:
        auto_from = tl_event.get("auto_created_from", "")
        if not auto_from or auto_from not in rejected:
            continue
        if tl_event.get("examiner_modifications"):
            continue
        tl_event["status"] = "REJECTED"
        tl_event["rejected_at"] = now
        tl_event["rejected_by"] = identity["examiner"]
        tl_event["rejection_reason"] = "Source finding rejected"
        tl_event["modified_at"] = now
        rejected.append(tl_event["id"])

    # IOC rejection coupling
    from vhir_cli.case_io import load_iocs, save_iocs

    # Build lookup for all finding statuses
    all_findings = load_findings(case_dir)
    finding_status = {fi["id"]: fi.get("status", "DRAFT") for fi in all_findings}
    for rid in rejected:
        finding_status[rid] = "REJECTED"

    iocs = load_iocs(case_dir)
    iocs_modified = False
    for ioc in iocs:
        if ioc.get("manually_reviewed"):
            continue
        source_ids = ioc.get("source_findings", [])
        if not source_ids:
            continue
        all_rejected = all(
            finding_status.get(sid, "DRAFT") == "REJECTED" for sid in source_ids
        )
        if all_rejected and ioc.get("status") != "REJECTED":
            ioc["status"] = "REJECTED"
            ioc["rejected_at"] = now
            ioc["rejected_by"] = identity["examiner"]
            ioc["rejection_reason"] = "All source findings rejected"
            ioc["modified_at"] = now
            iocs_modified = True
            rejected.append(ioc["id"])

    # Step 1: Persist primary data FIRST
    try:
        save_findings(case_dir, findings)
        save_timeline(case_dir, timeline)
        if iocs_modified:
            save_iocs(case_dir, iocs)
    except OSError as e:
        print(f"CRITICAL: Failed to save case data: {e}", file=sys.stderr)
        print(
            "No changes were committed. Retry after fixing the issue.", file=sys.stderr
        )
        sys.exit(1)

    # Step 2: Audit log (best-effort)
    log_failures = []
    for item_id in rejected:
        if not write_approval_log(
            case_dir, item_id, "REJECTED", identity, reason=reason, mode=mode
        ):
            log_failures.append(item_id)

    msg = f"Rejected: {', '.join(rejected)}"
    if reason:
        msg += f" — reason: {reason}"
    print(msg)
    if log_failures:
        print(f"  WARNING: Approval log failed for: {', '.join(log_failures)}")


def _interactive_reject(case_dir: Path, identity: dict, config_path: Path) -> None:
    """Walk through DRAFT items, prompting to reject or skip each."""
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    drafts = [f for f in findings if f.get("status") == "DRAFT"]
    draft_events = [t for t in timeline if t.get("status") == "DRAFT"]
    all_items = drafts + draft_events

    if not all_items:
        print("No DRAFT items to review.")
        return

    print(f"Reviewing {len(all_items)} DRAFT item(s) for rejection...\n")

    mode, _password = require_confirmation(config_path, identity["examiner"])

    to_reject: list[tuple[str, str]] = []  # (id, reason)

    for item in all_items:
        _display_item(item)
        while True:
            try:
                choice = input("  [r]eject / [s]kip / [q]uit? ").strip().lower()
            except EOFError:
                choice = "q"
            if choice in ("r", "reject"):
                try:
                    reason = input("  Reason (optional): ").strip()
                except EOFError:
                    reason = ""
                to_reject.append((item["id"], reason))
                print("  -> REJECT")
                break
            elif choice in ("s", "skip"):
                print("  -> skip (remains DRAFT)")
                break
            elif choice in ("q", "quit"):
                print("  Stopping review.")
                break
            else:
                print("  Enter r, s, or q.")
        if choice in ("q", "quit"):
            break

    if not to_reject:
        print("\nNo items rejected.")
        return

    # Reload and apply
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    now = datetime.now(timezone.utc).isoformat()
    rejected = []

    for item_id, reason in to_reject:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            continue
        item["status"] = "REJECTED"
        item["rejected_at"] = now
        item["rejected_by"] = identity["examiner"]
        item["modified_at"] = now
        if reason:
            item["rejection_reason"] = reason
        rejected.append(item_id)

    if not rejected:
        print("\nNo items rejected (all stale).")
        return

    # Timeline rejection coupling
    for tl_event in timeline:
        auto_from = tl_event.get("auto_created_from", "")
        if not auto_from or auto_from not in rejected:
            continue
        if tl_event.get("examiner_modifications"):
            continue
        tl_event["status"] = "REJECTED"
        tl_event["rejected_at"] = now
        tl_event["rejected_by"] = identity["examiner"]
        tl_event["rejection_reason"] = "Source finding rejected"
        tl_event["modified_at"] = now
        rejected.append(tl_event["id"])

    # IOC rejection coupling (interactive)
    from vhir_cli.case_io import load_iocs, save_iocs

    # Build lookup for all finding statuses
    all_findings_2 = load_findings(case_dir)
    finding_status_2 = {fi["id"]: fi.get("status", "DRAFT") for fi in all_findings_2}
    for rid in rejected:
        finding_status_2[rid] = "REJECTED"

    iocs = load_iocs(case_dir)
    iocs_modified = False
    for ioc in iocs:
        if ioc.get("manually_reviewed"):
            continue
        source_ids = ioc.get("source_findings", [])
        if not source_ids:
            continue
        all_rejected = all(
            finding_status_2.get(sid, "DRAFT") == "REJECTED" for sid in source_ids
        )
        if all_rejected and ioc.get("status") != "REJECTED":
            ioc["status"] = "REJECTED"
            ioc["rejected_at"] = now
            ioc["rejected_by"] = identity["examiner"]
            ioc["rejection_reason"] = "All source findings rejected"
            ioc["modified_at"] = now
            iocs_modified = True
            rejected.append(ioc["id"])

    # Step 1: Persist primary data FIRST
    try:
        save_findings(case_dir, findings)
        save_timeline(case_dir, timeline)
        if iocs_modified:
            save_iocs(case_dir, iocs)
    except OSError as e:
        print(f"CRITICAL: Failed to save case data: {e}", file=sys.stderr)
        print(
            "No changes were committed. Retry after fixing the issue.", file=sys.stderr
        )
        sys.exit(1)

    # Step 2: Audit log (best-effort)
    log_failures = []
    for item_id, reason in to_reject:
        if item_id in rejected and not write_approval_log(
            case_dir, item_id, "REJECTED", identity, reason=reason, mode=mode
        ):
            log_failures.append(item_id)
    # Coupled timeline events also need audit log entries
    for tl_event in timeline:
        if (
            tl_event.get("auto_created_from")
            and tl_event["id"] in rejected
            and not write_approval_log(
                case_dir,
                tl_event["id"],
                "REJECTED",
                identity,
                reason="Source finding rejected",
                mode=mode,
            )
        ):
            log_failures.append(tl_event["id"])
    # Cascaded IOC rejections also need audit log entries
    for ioc in iocs:
        if (
            ioc["id"] in rejected
            and ioc.get("rejection_reason") == "All source findings rejected"
            and not write_approval_log(
                case_dir,
                ioc["id"],
                "REJECTED",
                identity,
                reason="All source findings rejected",
                mode=mode,
            )
        ):
            log_failures.append(ioc["id"])

    print(f"\nRejected {len(rejected)} item(s): {', '.join(rejected)}")
    if log_failures:
        print(f"  WARNING: Approval log failed for: {', '.join(log_failures)}")


def _display_item(item: dict) -> None:
    """Display a finding or timeline event with full context for rejection decisions."""
    print(f"\n{'─' * 60}")
    print(f"  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    if item.get("confidence"):
        print(f"  Confidence: {item['confidence']}", end="")
    if item.get("audit_ids"):
        print(f"  | Evidence: {', '.join(item['audit_ids'])}", end="")
    print()
    print(f"{'─' * 60}")

    if "title" in item:
        print(f"  Observation: {item.get('observation', '')}")
        print(f"  Interpretation: {item.get('interpretation', '')}")
    else:
        print(f"  Timestamp: {item.get('timestamp', '?')}")
        print(f"  Description: {item.get('description', '')}")
    print()
