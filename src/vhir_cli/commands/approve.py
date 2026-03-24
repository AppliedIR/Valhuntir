"""Approve staged findings and timeline events.

Every approval requires password confirmation via /dev/tty.
This blocks AI-via-Bash from approving without human involvement.

Interactive review options per item:
  [a]pprove  — approve as-is
  [e]dit     — open in $EDITOR as YAML, approve with modifications tracked
  [n]ote     — add examiner note, then approve
  [r]eject   — reject with optional reason
  [t]odo     — create TODO and skip the item
  [s]kip     — leave as DRAFT
  [q]uit     — stop reviewing, commit what's been decided so far
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vhir_cli.approval_auth import require_confirmation
from vhir_cli.case_io import (
    check_case_file_integrity,
    compute_content_hash,
    find_draft_item,
    get_case_dir,
    hmac_text,
    load_findings,
    load_timeline,
    load_todos,
    save_findings,
    save_timeline,
    save_todos,
    write_approval_log,
)


def cmd_approve(args, identity: dict) -> None:
    """Approve findings/timeline events."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".vhir" / "config.yaml"

    review = getattr(args, "review", False)
    if review and args.ids:
        print("Error: --review cannot be used with specific IDs.", file=sys.stderr)
        sys.exit(1)

    if review:
        _review_mode(case_dir, identity, config_path)
        return

    # Inform about pending dashboard reviews (non-blocking)
    delta_path = case_dir / "pending-reviews.json"
    if delta_path.exists():
        try:
            delta = json.loads(delta_path.read_text())
            n_items = len(delta.get("items", []))
            if n_items > 0:
                print(
                    f"  Note: {n_items} pending dashboard review(s). "
                    "Use `vhir approve --review` to apply them."
                )
        except (json.JSONDecodeError, OSError):
            pass

    if args.ids:
        # Specific-ID mode with optional flags
        note = getattr(args, "note", None)
        edit = getattr(args, "edit", False)
        interpretation = getattr(args, "interpretation", None)
        _approve_specific(
            case_dir,
            args.ids,
            identity,
            config_path,
            note=note,
            edit=edit,
            interpretation=interpretation,
        )
    else:
        # Interactive review mode
        by_filter = getattr(args, "by", None)
        findings_only = getattr(args, "findings_only", False)
        timeline_only = getattr(args, "timeline_only", False)
        _interactive_review(
            case_dir,
            identity,
            config_path,
            by_filter=by_filter,
            findings_only=findings_only,
            timeline_only=timeline_only,
        )


def _approve_specific(
    case_dir: Path,
    ids: list[str],
    identity: dict,
    config_path: Path,
    note: str | None = None,
    edit: bool = False,
    interpretation: str | None = None,
) -> None:
    """Approve specific finding/event IDs with optional modifications."""
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    to_approve = []

    for item_id in ids:
        item = find_draft_item(item_id, findings, timeline)
        if item is None:
            print(f"  {item_id}: not found or not DRAFT", file=sys.stderr)
            continue
        _display_item(item)
        to_approve.append(item)

    if not to_approve:
        print("No items to approve.")
        return

    # Apply modifications before confirmation
    for item in to_approve:
        if edit:
            _apply_edit(item, identity)
        if interpretation:
            _apply_field_override(item, "interpretation", interpretation, identity)
        if note:
            _apply_note(item, note, identity)

    print(f"\n{len(to_approve)} item(s) to approve.")
    mode, password = require_confirmation(config_path, identity["examiner"])

    now = datetime.now(timezone.utc).isoformat()
    for item in to_approve:
        staging_hash = item.get("content_hash", "")
        new_hash = compute_content_hash(item)
        if staging_hash and staging_hash != new_hash:
            print(
                f"  NOTE: Finding {item['id']} was modified since staging "
                f"(content hash changed)."
            )
        item["content_hash"] = new_hash
        item["status"] = "APPROVED"
        item["approved_at"] = now
        item["approved_by"] = identity["examiner"]
        item["modified_at"] = now

    # Timeline approval coupling: auto-created events follow their finding
    approved_ids = {
        item["id"] for item in to_approve if item.get("status") == "APPROVED"
    }
    coupled_events = []
    for tl_event in timeline:
        auto_from = tl_event.get("auto_created_from", "")
        if not auto_from or auto_from not in approved_ids:
            continue
        if tl_event.get("examiner_modifications"):
            continue
        tl_event["status"] = "APPROVED"
        tl_event["approved_at"] = now
        tl_event["approved_by"] = identity["examiner"]
        tl_event["modified_at"] = now
        new_hash = compute_content_hash(tl_event)
        tl_event["content_hash"] = new_hash
        coupled_events.append(tl_event)

    # IOC approval coupling
    from vhir_cli.case_io import load_iocs, save_iocs

    # Build lookup for all findings (not just ones being approved)
    all_findings = load_findings(case_dir)
    finding_status = {fi["id"]: fi.get("status", "DRAFT") for fi in all_findings}
    # Overlay the just-approved statuses
    for item in to_approve:
        finding_status[item["id"]] = item.get("status", "DRAFT")

    iocs = load_iocs(case_dir)
    iocs_modified = False
    for ioc in iocs:
        if ioc.get("manually_reviewed"):
            continue
        source_ids = ioc.get("source_findings", [])
        if not source_ids:
            continue
        # ALL source findings must be APPROVED
        all_approved = all(
            finding_status.get(sid, "DRAFT") == "APPROVED" for sid in source_ids
        )
        if all_approved and ioc.get("status") != "APPROVED":
            ioc["status"] = "APPROVED"
            ioc["approved_at"] = now
            ioc["approved_by"] = identity["examiner"]
            ioc["modified_at"] = now
            iocs_modified = True
            coupled_events.append(ioc)

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

    # Step 2: Audit log (best-effort, warn on failure)
    log_failures = []
    all_approved = list(to_approve) + coupled_events
    for item in all_approved:
        if not write_approval_log(
            case_dir,
            item["id"],
            "APPROVED",
            identity,
            mode=mode,
            content_hash=item["content_hash"],
        ):
            log_failures.append(item["id"])

    # Step 3: HMAC ledger (warn on failure)
    hmac_failures = _write_verification_entries(
        case_dir, all_approved, identity, config_path, password, now
    )

    result_ids = [item["id"] for item in to_approve]
    print(f"Approved: {', '.join(result_ids)}")
    if coupled_events:
        coupled_tl = [e["id"] for e in coupled_events if e["id"].startswith("T-")]
        coupled_ioc = [e["id"] for e in coupled_events if e["id"].startswith("IOC-")]
        if coupled_tl:
            print(f"  Auto-approved timeline events: {', '.join(coupled_tl)}")
        if coupled_ioc:
            print(f"  Auto-approved IOCs: {', '.join(coupled_ioc)}")
    if log_failures:
        print(f"  WARNING: Approval log failed for: {', '.join(log_failures)}")
    if hmac_failures:
        print(f"  WARNING: HMAC ledger failed for: {', '.join(hmac_failures)}")
        print("  Re-run 'vhir approve' on these items to generate HMAC entries.")


def _interactive_review(
    case_dir: Path,
    identity: dict,
    config_path: Path,
    by_filter: str | None = None,
    findings_only: bool = False,
    timeline_only: bool = False,
) -> None:
    """Review each DRAFT item with full per-item options."""
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    drafts = (
        [] if timeline_only else [f for f in findings if f.get("status") == "DRAFT"]
    )
    draft_events = (
        [] if findings_only else [t for t in timeline if t.get("status") == "DRAFT"]
    )
    all_items = drafts + draft_events

    # Filter by creator
    if by_filter:
        all_items = [i for i in all_items if i.get("created_by") == by_filter]

    if not all_items:
        print("No staged items to review.")
        return

    print(f"Reviewing {len(all_items)} DRAFT item(s)...\n")

    # Authenticate before review so examiner doesn't lose work on password failure
    mode, password = require_confirmation(config_path, identity["examiner"])

    # Collect dispositions
    dispositions: dict[str, tuple] = {}  # id -> (action, extra_data)
    todos_to_create: list[dict] = []

    for item in all_items:
        _display_item(item)
        choice = _prompt_choice()

        if choice == "approve":
            dispositions[item["id"]] = ("approve", None)
            print("  -> APPROVE")

        elif choice == "edit":
            _apply_edit(item, identity)
            dispositions[item["id"]] = ("approve", "edited")
            print("  -> APPROVE (with edits)")

        elif choice == "note":
            try:
                note_text = input("  Note: ").strip()
            except EOFError:
                note_text = ""
            if note_text:
                _apply_note(item, note_text, identity)
            dispositions[item["id"]] = ("approve", "noted")
            print("  -> APPROVE (with note)")

        elif choice == "reject":
            try:
                reason = input("  Rejection reason (optional): ").strip()
            except EOFError:
                reason = ""
            dispositions[item["id"]] = ("reject", reason)
            print("  -> REJECT")

        elif choice == "todo":
            try:
                desc = input("  TODO description: ").strip()
                assignee = input("  Assign to [unassigned]: ").strip()
                priority = input("  Priority [medium]: ").strip() or "medium"
            except EOFError:
                desc = "Follow up on " + item["id"]
                assignee = ""
                priority = "medium"
            if desc:
                todos_to_create.append(
                    {
                        "description": desc,
                        "assignee": assignee,
                        "priority": priority,
                        "related_findings": [item["id"]],
                    }
                )
            dispositions[item["id"]] = ("skip", None)
            print("  -> skip (TODO created)")

        elif choice == "skip":
            dispositions[item["id"]] = ("skip", None)
            print("  -> skip (remains DRAFT)")

        elif choice == "quit":
            print("  Stopping review.")
            break

    # Summary
    approvals = {k for k, v in dispositions.items() if v[0] == "approve"}
    rejections = {k for k, v in dispositions.items() if v[0] == "reject"}
    skipped = {k for k, v in dispositions.items() if v[0] == "skip"}

    print(f"\n{'=' * 60}")
    print(
        f"  Summary: {len(approvals)} approve, {len(rejections)} reject, "
        f"{len(skipped)} skip, {len(todos_to_create)} TODO(s) created"
    )
    print(f"{'=' * 60}")

    if not approvals and not rejections:
        # Still create TODOs even if nothing to commit
        if todos_to_create:
            _create_todos(case_dir, todos_to_create, identity)
        print("Nothing to commit.")
        return

    now = datetime.now(timezone.utc).isoformat()

    # Apply approvals (in-memory)
    for item in all_items:
        if item["id"] in approvals:
            staging_hash = item.get("content_hash", "")
            new_hash = compute_content_hash(item)
            if staging_hash and staging_hash != new_hash:
                print(
                    f"  NOTE: Finding {item['id']} was modified since staging "
                    f"(content hash changed)."
                )
            item["content_hash"] = new_hash
            item["status"] = "APPROVED"
            item["approved_at"] = now
            item["approved_by"] = identity["examiner"]

    # Apply rejections (in-memory)
    for item in all_items:
        disp = dispositions.get(item["id"])
        if disp and disp[0] == "reject":
            reason = disp[1] or ""
            item["status"] = "REJECTED"
            item["rejected_at"] = now
            item["rejected_by"] = identity["examiner"]
            if reason:
                item["rejection_reason"] = reason

    # Update modified_at on changed items
    for item in all_items:
        if item["id"] in approvals or item["id"] in rejections:
            item["modified_at"] = now

    # Timeline approval coupling: auto-created events follow their finding
    coupled_tl = []
    coupled_ioc = []
    finding_by_id = {f["id"]: f for f in findings}
    for tl_event in timeline:
        auto_from = tl_event.get("auto_created_from", "")
        if not auto_from:
            continue
        if tl_event.get("examiner_modifications"):
            continue
        source = finding_by_id.get(auto_from)
        if not source:
            continue
        if source["id"] in approvals:
            tl_event["status"] = "APPROVED"
            tl_event["approved_at"] = now
            tl_event["approved_by"] = identity["examiner"]
            tl_event["modified_at"] = now
            new_hash = compute_content_hash(tl_event)
            tl_event["content_hash"] = new_hash
            coupled_tl.append(tl_event)
        elif source["id"] in rejections:
            tl_event["status"] = "REJECTED"
            tl_event["rejected_at"] = now
            tl_event["rejected_by"] = identity["examiner"]
            tl_event["rejection_reason"] = "Source finding rejected"
            tl_event["modified_at"] = now
            coupled_tl.append(tl_event)

    # IOC approval/rejection coupling
    from vhir_cli.case_io import load_iocs, save_iocs

    all_finding_status = {f["id"]: f.get("status", "DRAFT") for f in findings}
    iocs = load_iocs(case_dir)
    iocs_modified = False
    for ioc in iocs:
        if ioc.get("manually_reviewed"):
            continue
        source_ids = ioc.get("source_findings", [])
        if not source_ids:
            continue
        statuses = {all_finding_status.get(sid, "DRAFT") for sid in source_ids}
        if statuses == {"APPROVED"} and ioc.get("status") != "APPROVED":
            ioc["status"] = "APPROVED"
            ioc["approved_at"] = now
            ioc["approved_by"] = identity["examiner"]
            ioc["modified_at"] = now
            iocs_modified = True
            coupled_ioc.append(ioc)
        elif statuses == {"REJECTED"} and ioc.get("status") != "REJECTED":
            ioc["status"] = "REJECTED"
            ioc["rejected_at"] = now
            ioc["rejected_by"] = identity["examiner"]
            ioc["rejection_reason"] = "All source findings rejected"
            ioc["modified_at"] = now
            iocs_modified = True
            coupled_ioc.append(ioc)

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

    # Step 2: Approval log (best-effort, collect failures)
    log_failures = []
    for item in all_items:
        if item["id"] in approvals and not write_approval_log(
            case_dir,
            item["id"],
            "APPROVED",
            identity,
            mode=mode,
            content_hash=item["content_hash"],
        ):
            log_failures.append(item["id"])
    for item in all_items:
        disp = dispositions.get(item["id"])
        if disp and disp[0] == "reject":
            reason = disp[1] or ""
            if not write_approval_log(
                case_dir, item["id"], "REJECTED", identity, reason=reason, mode=mode
            ):
                log_failures.append(item["id"])
    # Coupled items also need audit log entries
    for item in coupled_tl:
        status = item.get("status", "")
        reason = (
            item.get("rejection_reason", "Source finding rejected")
            if status == "REJECTED"
            else ""
        )
        if not write_approval_log(
            case_dir,
            item["id"],
            status,
            identity,
            mode=mode,
            coupled_from=item.get("auto_created_from", ""),
            content_hash=item.get("content_hash", ""),
            reason=reason,
        ):
            log_failures.append(item["id"])
    for item in coupled_ioc:
        status = item.get("status", "")
        reason = item.get("rejection_reason", "") if status == "REJECTED" else ""
        if not write_approval_log(
            case_dir, item["id"], status, identity, mode=mode, reason=reason
        ):
            log_failures.append(item["id"])

    # Step 3: HMAC ledger (warn on failure)
    approved_items = [item for item in all_items if item["id"] in approvals]
    approved_items += [item for item in coupled_tl if item.get("status") == "APPROVED"]
    approved_items += [item for item in coupled_ioc if item.get("status") == "APPROVED"]
    hmac_failures = _write_verification_entries(
        case_dir, approved_items, identity, config_path, password, now
    )

    # Step 4: TODOs (best-effort)
    if todos_to_create:
        try:
            _create_todos(case_dir, todos_to_create, identity)
        except OSError as e:
            print(f"  WARNING: Failed to create TODOs: {e}", file=sys.stderr)

    print(f"Committed {len(approvals) + len(rejections)} disposition(s).")
    if coupled_tl:
        print(
            f"  Auto-coupled timeline events: {', '.join(e['id'] for e in coupled_tl)}"
        )
    if coupled_ioc:
        print(f"  Auto-coupled IOCs: {', '.join(e['id'] for e in coupled_ioc)}")
    if log_failures:
        print(f"  WARNING: Approval log failed for: {', '.join(log_failures)}")
    if hmac_failures:
        print(f"  WARNING: HMAC ledger failed for: {', '.join(hmac_failures)}")
        print("  Re-run 'vhir approve' on these items to generate HMAC entries.")


def _write_verification_entries(
    case_dir: Path,
    items: list[dict],
    identity: dict,
    config_path: Path,
    password: str | None,
    now: str,
) -> list[str]:
    """Write HMAC verification ledger entries. Returns list of failed item IDs."""
    if not password:
        return []  # No password — HMAC not applicable, not a failure

    try:
        from vhir_cli.approval_auth import get_analyst_salt
        from vhir_cli.verification import (
            compute_hmac,
            derive_hmac_key,
            write_ledger_entry,
        )
    except ImportError:
        return [item.get("id", "") for item in items]

    try:
        salt = get_analyst_salt(config_path, identity["examiner"])
    except (ValueError, OSError):
        return [item.get("id", "") for item in items]

    derived_key = derive_hmac_key(password, salt)

    # Resolve case_id from CASE.yaml
    case_id = ""
    try:
        meta_file = case_dir / "CASE.yaml"
        if meta_file.exists():
            import yaml

            meta = yaml.safe_load(meta_file.read_text()) or {}
            case_id = meta.get("case_id", "")
    except Exception:
        pass
    if not case_id:
        case_id = case_dir.name

    failures: list[str] = []
    for item in items:
        item_id = item.get("id", "")
        item_type = (
            "timeline"
            if item_id.startswith("T-")
            else "ioc"
            if item_id.startswith("IOC-")
            else "finding"
        )
        desc = hmac_text(item)
        entry = {
            "finding_id": item_id,
            "type": item_type,
            "hmac": compute_hmac(derived_key, desc),
            "hmac_version": 2,
            "content_snapshot": desc,
            "approved_by": identity["examiner"],
            "approved_at": now,
            "case_id": case_id,
        }
        try:
            write_ledger_entry(case_id, entry)
        except OSError:
            failures.append(item_id)

    return failures


def _prompt_choice() -> str:
    """Prompt for per-item action."""
    while True:
        try:
            response = (
                input("  [a]pprove  [e]dit  [n]ote  [r]eject  [t]odo  [s]kip  [q]uit: ")
                .strip()
                .lower()
            )
        except EOFError:
            return "skip"
        if response in ("", "a"):
            return "approve"
        if response == "e":
            return "edit"
        if response == "n":
            return "note"
        if response == "r":
            return "reject"
        if response == "t":
            return "todo"
        if response == "s":
            return "skip"
        if response == "q":
            return "quit"
        print("  Invalid choice.")


def _apply_edit(item: dict, identity: dict) -> None:
    """Open item in $EDITOR as YAML, track modifications."""
    editor = os.environ.get("EDITOR", "vi")

    # Serialize editable fields
    editable = {}
    if "title" in item:
        # Finding
        for key in (
            "title",
            "observation",
            "interpretation",
            "confidence",
            "confidence_justification",
            "context",
            "type",
        ):
            if key in item or key == "context":
                editable[key] = item.get(key, "")
    else:
        # Timeline event
        for key in ("timestamp", "description", "source"):
            if key in item:
                editable[key] = item[key]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(editable, f, default_flow_style=False, allow_unicode=True)
        tmpfile = f.name

    try:
        subprocess.run([editor, tmpfile], check=True, timeout=3600)
    except subprocess.TimeoutExpired:
        print("  Editor timed out after 1 hour.", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except subprocess.CalledProcessError as e:
        print(f"  Editor exited with error: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except OSError as e:
        print(f"  Failed to launch editor '{editor}': {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return

    try:
        with open(tmpfile) as f:
            edited = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        print(f"  Edited file contains invalid YAML: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    except OSError as e:
        print(f"  Failed to read edited file: {e}", file=sys.stderr)
        try:
            os.unlink(tmpfile)
        except OSError:
            pass
        return
    finally:
        try:
            os.unlink(tmpfile)
        except OSError:
            pass

    # Diff and record modifications
    modifications = {}
    now = datetime.now(timezone.utc).isoformat()
    for key, new_val in edited.items():
        old_val = editable.get(key)
        if new_val != old_val:
            modifications[key] = {
                "original": old_val,
                "modified": new_val,
                "modified_by": identity["examiner"],
                "modified_at": now,
            }
            item[key] = new_val

    if modifications:
        item.setdefault("examiner_modifications", {}).update(modifications)


def _apply_field_override(item: dict, field: str, value: str, identity: dict) -> None:
    """Override a specific field and track the modification."""
    original = item.get(field)
    if original == value:
        return
    now = datetime.now(timezone.utc).isoformat()
    item[field] = value
    item.setdefault("examiner_modifications", {})[field] = {
        "original": original,
        "modified": value,
        "modified_by": identity["examiner"],
        "modified_at": now,
    }


def _apply_note(item: dict, note: str, identity: dict) -> None:
    """Add an examiner note to the item."""
    now = datetime.now(timezone.utc).isoformat()
    item.setdefault("examiner_notes", []).append(
        {
            "note": note,
            "by": identity["examiner"],
            "at": now,
        }
    )


def _create_todos(case_dir: Path, todos_to_create: list[dict], identity: dict) -> None:
    """Create TODO items in the case."""
    todos = load_todos(case_dir)
    examiner = identity["examiner"]
    for td in todos_to_create:
        # Find next sequence for this examiner
        prefix = f"TODO-{examiner}-"
        max_num = 0
        for t in todos:
            tid = t.get("todo_id", "")
            if tid.startswith(prefix):
                try:
                    max_num = max(max_num, int(tid[len(prefix) :]))
                except ValueError:
                    pass
        todo_id = f"TODO-{examiner}-{max_num + 1:03d}"
        todo = {
            "todo_id": todo_id,
            "description": td["description"],
            "status": "open",
            "priority": td.get("priority", "medium"),
            "assignee": td.get("assignee", ""),
            "related_findings": td.get("related_findings", []),
            "created_by": identity["examiner"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "notes": [],
            "completed_at": None,
        }
        todos.append(todo)
        print(f"  Created {todo_id}: {td['description']}")
    save_todos(case_dir, todos)


def _display_item(item: dict) -> None:
    """Display a finding or timeline event."""
    created_by = item.get("created_by", "")
    examiner = item.get("examiner", "")
    print(f"\n{'─' * 60}")
    print(f"  [{item['id']}]  {item.get('title', item.get('description', 'Untitled'))}")
    if examiner:
        print(f"  Examiner: {examiner}", end="")
    if created_by:
        print(f"  | By: {created_by}", end="")
    if item.get("confidence"):
        print(f"  | Confidence: {item['confidence']}", end="")
    if item.get("audit_ids"):
        print(f"  | Evidence: {', '.join(item['audit_ids'])}", end="")
    print()
    print(f"{'─' * 60}")

    if "title" in item:
        # It's a finding
        print(f"  Observation: {item.get('observation', '')}")
        print(f"  Interpretation: {item.get('interpretation', '')}")
        if item.get("iocs"):
            print(f"  IOCs: {item['iocs']}")
    else:
        # It's a timeline event
        print(f"  Timestamp: {item.get('timestamp', '?')}")
        print(f"  Description: {item.get('description', '')}")
        if item.get("audit_ids"):
            print(f"  Evidence: {', '.join(item['audit_ids'])}")
    print()


# --- Dashboard review mode ---

_DELTA_EDITABLE_FIELDS = {
    # Finding fields
    "title",
    "observation",
    "interpretation",
    "confidence",
    "confidence_justification",
    "mitre_ids",
    "iocs",
    "context",
    # Timeline event fields
    "timestamp",
    "description",
    "source",
    # IOC fields
    "tags",
}

_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _render_terminal_diff(item: dict, delta_entry: dict) -> None:
    """Print a terminal diff for a single delta item."""
    item_id = delta_entry.get("id", "?")
    action = delta_entry.get("action", "?").upper()
    modifications = delta_entry.get("modifications", {})

    # Color for action
    action_color = {
        "APPROVE": _GREEN,
        "REJECT": _RED,
        "TODO": _YELLOW,
        "EDIT": _CYAN,
    }.get(action, _CYAN)

    # Header
    print(
        f"\n{_BOLD}{'─' * 20} {item_id} {'─' * 3} {action_color}{action}{_RESET}"
        f"{_BOLD} {'─' * (35 - len(item_id) - len(action))}{_RESET}"
    )

    if item is None:
        print(f"  {_RED}Item not found in case data{_RESET}")
        return

    # Finding fields
    if "title" in item:
        print(f"  Title:          {item.get('title', '')}")
        _render_field("Confidence", item, modifications, "confidence")
        _render_field("Observation", item, modifications, "observation")
        _render_field("Interpretation", item, modifications, "interpretation")
        if item.get("audit_ids"):
            print(f"  Evidence:       {', '.join(item['audit_ids'])}")
        if item.get("mitre_ids"):
            _render_field("MITRE", item, modifications, "mitre_ids")
        if item.get("iocs"):
            _render_field("IOCs", item, modifications, "iocs")
    else:
        # Timeline event
        print(f"  Timestamp:      {item.get('timestamp', '?')}")
        _render_field("Description", item, modifications, "description")
        if item.get("source"):
            print(f"  Source:         {item.get('source', '')}")

    # Note
    note = delta_entry.get("note")
    if note:
        print(f"  {_CYAN}Note: {note}{_RESET}")

    # Rejection reason
    if action == "REJECT":
        reason = delta_entry.get("rejection_reason", "") or delta_entry.get(
            "reason", ""
        )
        print(f"  {_RED}Reason: {reason or '(no reason given)'}{_RESET}")

    # TODO details
    if action == "TODO":
        desc = delta_entry.get("todo_description", "")
        prio = delta_entry.get("todo_priority", "medium")
        print(f"  {_YELLOW}TODO: {desc} (priority: {prio}){_RESET}")

    # Status line
    current_status = item.get("status", "DRAFT")
    if action == "APPROVE":
        print(
            f"  Status:         {_DIM}{current_status}{_RESET} → {_GREEN}APPROVED{_RESET}"
        )
    elif action == "REJECT":
        print(
            f"  Status:         {_DIM}{current_status}{_RESET} → {_RED}REJECTED{_RESET}"
        )
    elif action == "EDIT":
        print(
            f"  Status:         {_DIM}{current_status}{_RESET} → {_CYAN}EDITED (pending approval){_RESET}"
        )


def _render_field(label: str, item: dict, modifications: dict, field: str) -> None:
    """Render a field, showing diff if modified."""
    pad = max(0, 14 - len(label))
    prefix = f"  {label}:{' ' * pad}"

    if field in modifications:
        mod = modifications[field]
        original = mod.get("original", "")
        modified = mod.get("modified", "")
        # Format lists
        if isinstance(original, list):
            original = ", ".join(str(x) for x in original)
        if isinstance(modified, list):
            modified = ", ".join(str(x) for x in modified)
        print(f"{prefix}{_RED}- {original}{_RESET}")
        print(f"  {' ' * (len(label) + 1)}{' ' * pad}{_GREEN}+ {modified}{_RESET}")
    else:
        val = item.get(field, "")
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        print(f"{prefix}{val}")


def _review_mode(case_dir: Path, identity: dict, config_path: Path) -> None:
    """Apply pending dashboard reviews from pending-reviews.json."""
    delta_path = case_dir / "pending-reviews.json"
    processing_path = case_dir / "pending-reviews.processing"

    # Recovery: handle orphaned .processing from crashed session
    if processing_path.exists():
        if delta_path.exists():
            # Both exist: .processing is stale, delta is newer (user saved again)
            print(
                "Found stale .processing file from previous session. "
                "Removing (newer pending-reviews.json exists)."
            )
            processing_path.unlink()
        else:
            # Only .processing: crashed mid-apply. Restore for re-review.
            print(
                "Found unfinished review from previous session. "
                "Restoring for re-review."
            )
            processing_path.rename(delta_path)

    if not delta_path.exists():
        print("No pending dashboard reviews.")
        return

    # Atomically rename to .processing (TOCTOU mitigation)
    try:
        delta_path.rename(processing_path)
    except OSError as e:
        print(f"Error: Cannot lock delta file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        delta = json.loads(processing_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        # Restore original file on parse failure
        try:
            processing_path.rename(delta_path)
        except OSError:
            pass
        print(f"Error: Cannot read delta file: {e}", file=sys.stderr)
        sys.exit(1)

    items = delta.get("items", [])
    if not items:
        processing_path.unlink(missing_ok=True)
        print("No pending dashboard reviews.")
        return

    # Validate case_id
    delta_case_id = delta.get("case_id", "")
    case_meta_path = case_dir / "CASE.yaml"
    if case_meta_path.exists():
        try:
            meta = yaml.safe_load(case_meta_path.read_text()) or {}
            active_case_id = meta.get("case_id", "")
            if delta_case_id and active_case_id and delta_case_id != active_case_id:
                print(
                    f"Error: Delta case_id ({delta_case_id}) does not match "
                    f"active case ({active_case_id}).",
                    file=sys.stderr,
                )
                processing_path.rename(delta_path)
                sys.exit(1)
        except (yaml.YAMLError, OSError):
            pass

    # Check modified_at — warn if file was modified after last browser action
    delta_modified = delta.get("modified_at", "")
    try:
        file_mtime = datetime.fromtimestamp(
            processing_path.stat().st_mtime, tz=timezone.utc
        ).isoformat()
        if delta_modified and file_mtime > delta_modified:
            print(
                f"  {_YELLOW}WARNING: Delta file was modified after your last "
                f"review action.{_RESET}"
            )
    except OSError:
        pass

    # Load case data — all items, not just DRAFTs
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    from vhir_cli.case_io import load_iocs, save_iocs

    iocs = load_iocs(case_dir)

    # Build lookup by ID — includes findings, timeline, AND IOCs
    item_by_id: dict[str, dict] = {}
    for f in findings:
        item_by_id[f["id"]] = f
    for t in timeline:
        item_by_id[t["id"]] = t
    for ioc in iocs:
        item_by_id[ioc["id"]] = ioc

    # Categorize delta items
    approvals = []
    rejections = []
    todos = []
    edits = []
    stale_warnings = []

    for entry in items:
        item_id = entry.get("id", "")
        action = entry.get("action", "").lower()
        item = item_by_id.get(item_id)

        # Check content hash staleness
        hash_at_review = entry.get("content_hash_at_review", "")
        if item and hash_at_review:
            current_hash = item.get("content_hash", "")
            if current_hash and hash_at_review != current_hash:
                stale_warnings.append(item_id)

        # Render each item
        _render_terminal_diff(item, entry)

        if action == "approve":
            approvals.append(entry)
        elif action == "reject":
            rejections.append(entry)
        elif action == "todo":
            todos.append(entry)
        elif action == "edit":
            edits.append(entry)

    # Stale warnings
    for sid in stale_warnings:
        print(f"  {_YELLOW}WARNING: {sid} was modified after you reviewed it.{_RESET}")

    # Summary
    print(f"\n{'=' * 60}")
    print(
        f"  Apply {len(approvals)} approval(s), {len(rejections)} rejection(s), "
        f"{len(edits)} edit(s), {len(todos)} TODO(s)?"
    )
    print(f"{'=' * 60}")

    if not approvals and not rejections and not todos and not edits:
        processing_path.unlink(missing_ok=True)
        print("Nothing to apply.")
        return

    # Password confirmation
    mode, password = require_confirmation(config_path, identity["examiner"])
    now = datetime.now(timezone.utc).isoformat()

    # Process approvals (in-memory)
    skipped = []
    approved_ids = []
    for entry in approvals:
        item_id = entry.get("id", "")
        item = item_by_id.get(item_id)
        if item is None:
            skipped.append((item_id, "not found"))
            continue

        modifications = entry.get("modifications", {})

        # Verify modification originals match current values
        mod_conflict = False
        for field, mod in modifications.items():
            current_val = item.get(field)
            original_val = mod.get("original")
            if current_val != original_val:
                skipped.append((item_id, f"field '{field}' changed since review"))
                mod_conflict = True
                break

        if mod_conflict:
            continue

        # Apply modifications (only editable fields)
        if modifications:
            for field, mod in modifications.items():
                if field not in _DELTA_EDITABLE_FIELDS:
                    continue
                item[field] = mod.get("modified")
                item.setdefault("examiner_modifications", {})[field] = {
                    "original": mod.get("original"),
                    "modified": mod.get("modified"),
                    "modified_by": identity["examiner"],
                    "modified_at": now,
                }

        # Apply note
        note = entry.get("note")
        if note:
            _apply_note(item, note, identity)

        # Compute content hash AFTER modifications
        new_hash = compute_content_hash(item)
        item["content_hash"] = new_hash
        item["status"] = "APPROVED"
        item["approved_at"] = now
        item["approved_by"] = identity["examiner"]
        item["modified_at"] = now
        # Direct IOC actions decouple from cascade
        if item_id.startswith("IOC-"):
            item["manually_reviewed"] = True
        approved_ids.append(item_id)

    # Process edits (modifications only, no status change)
    edited_ids = []
    for entry in edits:
        item_id = entry.get("id", "")
        item = item_by_id.get(item_id)
        if item is None:
            skipped.append((item_id, "not found"))
            continue

        modifications = entry.get("modifications", {})
        if not modifications:
            continue

        # Verify originals match
        mod_conflict = False
        for field, mod in modifications.items():
            current_val = item.get(field)
            original_val = mod.get("original")
            if current_val != original_val:
                skipped.append((item_id, f"field '{field}' changed since review"))
                mod_conflict = True
                break
        if mod_conflict:
            continue

        # Apply modifications only
        for field, mod in modifications.items():
            if field not in _DELTA_EDITABLE_FIELDS:
                continue
            item[field] = mod.get("modified")
            item.setdefault("examiner_modifications", {})[field] = {
                "original": mod.get("original"),
                "modified": mod.get("modified"),
                "modified_by": identity["examiner"],
                "modified_at": now,
            }

        # Recompute hash
        new_hash = compute_content_hash(item)
        item["content_hash"] = new_hash
        item["modified_at"] = now
        edited_ids.append(item_id)

    # Process rejections (in-memory)
    rejected_ids = []
    for entry in rejections:
        item_id = entry.get("id", "")
        item = item_by_id.get(item_id)
        if item is None:
            skipped.append((item_id, "not found"))
            continue

        reason = entry.get("rejection_reason", "") or entry.get("reason", "")
        item["status"] = "REJECTED"
        item["rejected_at"] = now
        item["rejected_by"] = identity["examiner"]
        if reason:
            item["rejection_reason"] = reason
        item["modified_at"] = now
        # Direct IOC actions decouple from cascade
        if item_id.startswith("IOC-"):
            item["manually_reviewed"] = True
        rejected_ids.append(item_id)

    # Timeline approval coupling: auto-created events follow their finding
    for tl_event in timeline:
        auto_from = tl_event.get("auto_created_from", "")
        if not auto_from:
            continue
        if tl_event.get("examiner_modifications"):
            continue
        source = item_by_id.get(auto_from)
        if not source:
            continue
        if source.get("status") == "APPROVED":
            tl_event["status"] = "APPROVED"
            tl_event["approved_at"] = now
            tl_event["approved_by"] = identity["examiner"]
            tl_event["modified_at"] = now
            new_hash = compute_content_hash(tl_event)
            tl_event["content_hash"] = new_hash
            approved_ids.append(tl_event["id"])
        elif source.get("status") == "REJECTED":
            tl_event["status"] = "REJECTED"
            tl_event["rejected_at"] = now
            tl_event["rejected_by"] = identity["examiner"]
            tl_event["rejection_reason"] = "Source finding rejected"
            tl_event["modified_at"] = now
            rejected_ids.append(tl_event["id"])

    # IOC approval coupling (review mode)
    # iocs already loaded above (H2 fix) — reuse same objects
    any_ioc_acted = any(
        aid.startswith("IOC-") for aid in approved_ids + rejected_ids + edited_ids
    )
    iocs_modified = any_ioc_acted
    for ioc in iocs:
        if ioc.get("manually_reviewed"):
            continue
        source_ids = ioc.get("source_findings", [])
        relevant = [item_by_id.get(sid) for sid in source_ids if item_by_id.get(sid)]
        if not relevant:
            continue
        statuses = {r.get("status", "DRAFT") for r in relevant}
        if statuses == {"APPROVED"} and ioc.get("status") != "APPROVED":
            ioc["status"] = "APPROVED"
            ioc["approved_at"] = now
            ioc["approved_by"] = identity["examiner"]
            ioc["modified_at"] = now
            iocs_modified = True
            approved_ids.append(ioc["id"])
        elif statuses == {"REJECTED"} and ioc.get("status") != "REJECTED":
            ioc["status"] = "REJECTED"
            ioc["rejected_at"] = now
            ioc["rejected_by"] = identity["examiner"]
            ioc["rejection_reason"] = "All source findings rejected"
            ioc["modified_at"] = now
            iocs_modified = True
            rejected_ids.append(ioc["id"])

    # Step 1: Persist primary data FIRST
    try:
        save_findings(case_dir, findings)
        save_timeline(case_dir, timeline)
        if iocs_modified:
            save_iocs(case_dir, iocs)
    except OSError as e:
        print(f"CRITICAL: Failed to save case data: {e}", file=sys.stderr)
        print("The .processing file has been preserved for retry.", file=sys.stderr)
        sys.exit(1)

    # Step 2: Approval log (best-effort, collect failures)
    log_failures = []
    for item_id in approved_ids:
        item = item_by_id.get(item_id)
        if item and not write_approval_log(
            case_dir,
            item_id,
            "APPROVED",
            identity,
            mode=mode,
            content_hash=item.get("content_hash", ""),
            stale_at_approval=item_id in stale_warnings,
        ):
            log_failures.append(item_id)
    for entry in rejections:
        item_id = entry.get("id", "")
        if item_id in rejected_ids:
            reason = entry.get("rejection_reason", "") or entry.get("reason", "")
            if not write_approval_log(
                case_dir, item_id, "REJECTED", identity, reason=reason, mode=mode
            ):
                log_failures.append(item_id)
    for item_id in edited_ids:
        item = item_by_id.get(item_id)
        if item and not write_approval_log(
            case_dir,
            item_id,
            "EDITED",
            identity,
            mode=mode,
            content_hash=item.get("content_hash", ""),
        ):
            log_failures.append(item_id)

    # Step 3: HMAC ledger (warn on failure)
    approved_items = [item_by_id[aid] for aid in approved_ids if aid in item_by_id]
    hmac_failures = _write_verification_entries(
        case_dir, approved_items, identity, config_path, password, now
    )

    # Step 4: TODOs (best-effort)
    if todos:
        todos_to_create = []
        for entry in todos:
            todos_to_create.append(
                {
                    "description": entry.get(
                        "todo_description", f"Follow up on {entry.get('id', '')}"
                    ),
                    "priority": entry.get("todo_priority", "medium"),
                    "assignee": "",
                    "related_findings": [entry.get("id", "")],
                }
            )
        try:
            _create_todos(case_dir, todos_to_create, identity)
        except OSError as e:
            print(f"  WARNING: Failed to create TODOs: {e}", file=sys.stderr)

    # Step 5: Cleanup .processing
    try:
        processing_path.unlink(missing_ok=True)
    except OSError:
        print(
            "WARNING: Could not remove .processing file. Remove manually.",
            file=sys.stderr,
        )

    # Report
    if skipped:
        print(
            f"\n  {_YELLOW}Skipped {len(skipped)} item(s) (field changed since review):"
        )
        for sid, reason in skipped:
            print(f"    {sid}: {reason}")
        print(f"  Re-review in browser.{_RESET}")

    print(
        f"\nApplied: {len(approved_ids)} approved, {len(rejected_ids)} rejected, "
        f"{len(edited_ids)} edited, {len(todos)} TODO(s)."
    )
    if log_failures:
        print(f"  WARNING: Approval log failed for: {', '.join(log_failures)}")
    if hmac_failures:
        print(f"  WARNING: HMAC ledger failed for: {', '.join(hmac_failures)}")
        print("  Re-run 'vhir approve' on these items to generate HMAC entries.")
