"""Approve staged findings and timeline events.

Every decision is signed with the examiner's key: the password is asked for
last, on /dev/tty, after every item and cascade has been shown. That stops a
command that only pipes input; a program that controls a terminal can type it.

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

import copy
import json
import os
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

import yaml

from vhir_cli import (
    approval_auth,
    approval_checks,
    credentials,
    decide,
    ledger,
    provenance_view,
)
from vhir_cli.case_io import (
    case_id_of,
    check_case_file_integrity,
    compute_content_hash,
    find_draft_item,
    get_case_dir,
    load_findings,
    load_iocs,
    load_timeline,
    load_todos,
    load_withdrawals,
    save_todos,
    signed_text,
)
from vhir_cli.display import MULTI_LINE as _MULTI_LINE
from vhir_cli.display import lines as _lines
from vhir_cli.display import one_line as _one_line


def cmd_approve(args, identity: dict) -> None:
    """Approve findings/timeline events (or re-attest 0.6 approvals)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    config_path = Path.home() / ".vhir" / "config.yaml"
    show_signed = getattr(args, "show_signed", False)

    review = getattr(args, "review", False)
    if review and args.ids:
        print("Error: --review cannot be used with specific IDs.", file=sys.stderr)
        sys.exit(1)

    if getattr(args, "reattest", False):
        _reattest(
            case_dir,
            args.ids,
            identity,
            config_path,
            every=getattr(args, "all", False),
            show_signed=show_signed,
        )
        return

    try:
        withdrawn = len(load_withdrawals(case_dir))
    except Exception as e:  # the count is information; a bad line mustn't block
        print(f"  Warning: withdrawn candidates not counted: {e}", file=sys.stderr)
        withdrawn = 0
    withdrawn_line = (
        f"  {withdrawn} candidate finding(s) withdrawn after challenge"
        " — `vhir review --withdrawn`"
        if withdrawn
        else ""
    )

    if review:
        _review_mode(
            case_dir,
            identity,
            config_path,
            withdrawn_line=withdrawn_line,
            show_signed=show_signed,
        )
        return

    # Inform about pending dashboard reviews (non-blocking)
    delta_path = case_dir / "pending-reviews.json"
    if delta_path.exists():
        try:
            delta = json.loads(delta_path.read_text())
            items = [e for e in delta.get("items", []) if isinstance(e, dict)]
            mine = [
                e for e in items
                if e.get("saved_unsigned") and e.get("staged_by") == identity["examiner"]
            ]  # fmt: skip
            if mine:
                print(
                    f"  {len(mine)} of your decision(s) were saved unsigned "
                    f"({_one_line(mine[-1]['saved_unsigned'].get('reason', ''))}). "
                    "`vhir approve --review` signs those whose content still matches "
                    "what you saw."
                )
            if len(items) > len(mine):
                print(
                    f"  Note: {len(items) - len(mine)} pending dashboard review(s). "
                    "Use `vhir approve --review` to apply them."
                )
        except (json.JSONDecodeError, OSError):
            pass

    if args.ids:
        if withdrawn_line:
            print(withdrawn_line)
        _approve_specific(
            case_dir,
            args.ids,
            identity,
            config_path,
            note=getattr(args, "note", None),
            edit=getattr(args, "edit", False),
            interpretation=getattr(args, "interpretation", None),
            show_signed=show_signed,
        )
    else:
        _interactive_review(
            case_dir,
            identity,
            config_path,
            by_filter=getattr(args, "by", None),
            findings_only=getattr(args, "findings_only", False),
            timeline_only=getattr(args, "timeline_only", False),
            withdrawn_line=withdrawn_line,
            show_signed=show_signed,
        )


_STATUS_AFTER = {"approve": "APPROVED", "reject": "REJECTED"}


def _preflight(identity: dict, config_path: Path, case_dir: Path) -> bool:
    """The checks that can fail, before any item is shown (and a 0.6 upgrade).
    Returns True when a new passphrase was set."""
    try:
        new_passphrase = credentials.preflight(identity["examiner"], config_path)
    except credentials.CredentialError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    copy = decide.copy_problem(case_dir)
    if copy:  # signing would extend another folder's chain
        print(copy, file=sys.stderr)
        sys.exit(1)
    return new_passphrase


def _modifications(loaded: dict, item: dict) -> dict:
    """The field edits made in this command: {field: {original, modified}}."""
    before = loaded.get("examiner_modifications") or {}
    return {
        k: {"original": v.get("original"), "modified": v.get("modified")}
        for k, v in (item.get("examiner_modifications") or {}).items()
        if before.get(k) != v
    }


def _no_items(decision: str) -> None:
    if decision == "reject":
        print("No items to reject.")
        return
    print("No items to approve.")
    print(
        "  Staged portal work: `vhir approve --review`. Portal approvals need a signing "
        "key: `vhir config --upgrade-key`."
    )


def _show_as_signed(item: dict, loaded: dict, decision: str, show_signed: bool) -> None:
    """After this command's edits: an item whose signed body changed is shown
    again as it will be signed (each edit as - before / + after), and
    --show-signed prints the body itself."""
    kind = decide.item_type(item["id"])
    if signed_text(item, kind) != signed_text(loaded, kind):
        print("  As it will be signed:")
        _render_terminal_diff(
            item,
            {"id": item["id"], "action": decision,
             "modifications": _modifications(loaded, item)},
        )  # fmt: skip
    if show_signed:
        _print_signed(item)


def _print_signed(item: dict) -> None:
    """--show-signed: the full signed view of an item."""
    kind = decide.item_type(item["id"])
    print(f"  Signed view: {_one_line(signed_text(item, kind))}")


def _approve_specific(
    case_dir: Path,
    ids: list[str],
    identity: dict,
    config_path: Path,
    note: str | None = None,
    edit: bool = False,
    interpretation: str | None = None,
    decision: str = "approve",
    reason: str = "",
    show_signed: bool = False,
) -> None:
    """Approve (DRAFT findings and timeline events) or reject (findings,
    timeline events and IOCs not already rejected) specific ids."""
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    iocs = load_iocs(case_dir)
    picked = []
    for item_id in dict.fromkeys(ids):  # an id named twice is decided once
        if decision == "approve":
            item = find_draft_item(item_id, findings, timeline)
            if item is None:
                print(
                    f"  {_one_line(item_id)}: not found or not DRAFT", file=sys.stderr
                )
                continue
        else:
            item = next(
                (
                    x
                    for x in findings + timeline + iocs
                    if isinstance(x, dict) and x.get("id") == item_id
                ),
                None,
            )
            if item is None or item.get("status") == "REJECTED":
                print(
                    f"  {_one_line(item_id)}: not found or already rejected",
                    file=sys.stderr,
                )
                continue
        picked.append(item)
    if not picked:
        _no_items(decision)
        return

    new_passphrase = _preflight(identity, config_path, case_dir)
    direct = []
    for item in picked:
        loaded = copy.deepcopy(item)
        _display_item(item)
        if decision == "approve":
            if edit:
                _apply_edit(item, identity)
            if interpretation:
                _apply_field_override(item, "interpretation", interpretation, identity)
        if note:
            _apply_note(item, note, identity)
        kind = decide.item_type(item["id"])
        if kind == "ioc":
            item["manually_reviewed"] = (
                True  # a direct decision; no longer a cascade target
            )
        _show_as_signed(item, loaded, decision, show_signed)
        chosen = decide.Decision(
            item, kind, decision, _STATUS_AFTER[decision], loaded=loaded,
            reason=reason, note=note or "", modifications=_modifications(loaded, item),
        )  # fmt: skip
        if not _approval_checked(case_dir, chosen):
            continue
        direct.append(chosen)
    if not direct:
        print("Nothing to sign.")
        return
    planned = decide.cascades(direct, findings, timeline, iocs)
    print(f"\n{len(direct)} item(s) to {decision}.")
    decide.confirm_plan(direct, planned, _display_item)
    decide.sign_and_commit(
        case_dir, identity, direct, planned, new_passphrase=new_passphrase
    )


_APPROVE_CHOICES = ("approve", "edit", "note", "reject", "todo", "skip", "quit")
_REJECT_CHOICES = ("reject", "skip", "quit")


def _interactive_review(
    case_dir: Path,
    identity: dict,
    config_path: Path,
    by_filter: str | None = None,
    findings_only: bool = False,
    timeline_only: bool = False,
    withdrawn_line: str = "",
    choices: tuple[str, ...] = _APPROVE_CHOICES,
    show_signed: bool = False,
) -> None:
    """Review each DRAFT item. The evidence of every item is shown first, then
    each decision; the password comes last, after the cascades are listed."""
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    iocs = load_iocs(case_dir)

    drafts = (
        [] if timeline_only else [f for f in findings if f.get("status") == "DRAFT"]
    )
    draft_events = (
        [] if findings_only else [t for t in timeline if t.get("status") == "DRAFT"]
    )
    all_items = drafts + draft_events
    if by_filter:
        all_items = [i for i in all_items if i.get("created_by") == by_filter]
    if not all_items:
        print("No staged items to review.")
        if withdrawn_line:  # every candidate may have been withdrawn
            print(withdrawn_line)
        return

    new_passphrase = _preflight(identity, config_path, case_dir)
    print(f"Reviewing {len(all_items)} DRAFT item(s)...\n")
    for item in all_items:
        _print_pending_item(item, timeline)
        if show_signed:
            _print_signed(item)
    print()

    direct: list[decide.Decision] = []
    skipped: set[str] = set()  # skipped by the examiner: never cascaded
    todos_to_create: list[dict] = []
    not_reviewed = 0
    for n, item in enumerate(all_items):
        _print_decision_header(item)
        choice = _prompt_choice(choices)
        loaded = copy.deepcopy(item)
        kind = decide.item_type(item["id"])
        if choice in ("approve", "edit", "note"):
            if choice == "edit":
                _apply_edit(item, identity)
            note_text = ""
            if choice == "note":
                try:
                    note_text = input("  Note: ").strip()
                except EOFError:
                    note_text = ""
                if note_text:
                    _apply_note(item, note_text, identity)
            _show_as_signed(item, loaded, "approve", False)
            chosen = decide.Decision(item, kind, "approve", "APPROVED", loaded=loaded,
                                     note=note_text, modifications=_modifications(loaded, item))  # fmt: skip
            if not _approval_checked(case_dir, chosen):
                skipped.add(item["id"])
                continue
            direct.append(chosen)
            print(f"  -> APPROVE{' (with edits)' if choice == 'edit' else ''}")
        elif choice == "reject":
            try:
                reason = input("  Rejection reason (optional): ").strip()
            except EOFError:
                reason = ""
            direct.append(
                decide.Decision(
                    item, kind, "reject", "REJECTED", loaded=loaded, reason=reason
                )
            )
            print("  -> REJECT")
        elif choice == "todo":
            try:
                desc = input("  TODO description: ").strip()
                assignee = input("  Assign to [unassigned]: ").strip()
                priority = input("  Priority [medium]: ").strip() or "medium"
            except EOFError:
                desc, assignee, priority = "Follow up on " + item["id"], "", "medium"
            if desc:
                todos_to_create.append({"description": desc, "assignee": assignee,
                                        "priority": priority, "related_findings": [item["id"]]})  # fmt: skip
            skipped.add(item["id"])
            print("  -> skip (TODO created)")
        elif choice == "skip":
            skipped.add(item["id"])
            print("  -> skip (remains DRAFT)")
        elif choice == "quit":
            # not decided, so not skipped: one can still follow its finding,
            # listed with it before the prompt
            not_reviewed = len(all_items) - n
            print("  Stopping review.")
            break

    approvals = sum(1 for d in direct if d.decision == "approve")
    print(f"\n{'=' * 60}")
    print(
        f"  Summary: {approvals} approve, {len(direct) - approvals} reject, "
        f"{len(skipped)} skip, {len(todos_to_create)} TODO(s) created"
        + (f", {not_reviewed} not reviewed" if not_reviewed else "")
    )
    print(f"{'=' * 60}")
    if not direct:
        if todos_to_create:
            _create_todos(case_dir, todos_to_create, identity)
        if withdrawn_line:
            print(withdrawn_line)
        print("Nothing to sign.")
        return
    planned = decide.cascades(direct, findings, timeline, iocs, skipped)
    decide.confirm_plan(direct, planned, _display_item, lead=withdrawn_line)
    decide.sign_and_commit(
        case_dir,
        identity,
        direct,
        planned,
        new_passphrase=new_passphrase,
        skipped=skipped,
        todos=todos_to_create,
        make_todos=lambda todos: _create_todos(case_dir, todos, identity),
    )


# An approval with no signed line of its own: before 0.6.4, or none that counts
# (a 0.6 line outside the history signing froze, or no line at all).
_REATTESTABLE = {"APPROVED_UNDER_0_6", "APPROVED_NO_LINE"}


def _reattest(
    case_dir: Path,
    ids: list[str],
    identity: dict,
    config_path: Path,
    every: bool = False,
    show_signed: bool = False,
) -> None:
    """Sign a fresh approval of an item's current content, dated now and marked
    as a re-attestation. The 0.6 record is left as it is. An item with no
    earlier approval record takes its approver and time from the new line."""
    from vhir_cli.ledger_verify import verify_case

    if not ids and not every:
        print("Error: name the items to re-attest, or use --all.", file=sys.stderr)
        sys.exit(1)
    verdicts = {v.item_id: v for v in verify_case(case_dir).items}
    wanted = (
        [v for v in verdicts.values() if v.status in _REATTESTABLE] if every else []
    )
    for item_id in ids:
        v = verdicts.get(item_id)
        if v is None or v.status not in _REATTESTABLE:
            shown = v.status if v else "not an APPROVED item with lines to re-attest"
            print(
                f"  {_one_line(item_id)}: not re-attestable ({_one_line(shown)})",
                file=sys.stderr,
            )
            continue
        wanted.append(v)
    if not wanted:
        print("No items to re-attest.")
        return
    new_passphrase = _preflight(identity, config_path, case_dir)
    lists = {
        "finding": load_findings(case_dir),
        "timeline": load_timeline(case_dir),
        "ioc": load_iocs(case_dir),
    }
    direct = []
    for v in wanted:
        item = next(
            x
            for x in lists[v.item_type]
            if isinstance(x, dict) and x.get("id") == v.item_id
        )
        _display_item(item)
        if show_signed:
            _print_signed(item)
        by, at = (
            _one_line(item.get("approved_by", "?")),
            _one_line(item.get("approved_at", "?")),
        )
        if v.status == "APPROVED_NO_LINE":
            print(
                f"  unverified: {_one_line(v.label)} (the file says {by}, {at}); "
                "re-attesting makes you its approver"
            )
        else:
            print(
                f"  approved before 0.6.4 by {by} on {at} (unverified); {_one_line(v.status)}"
            )
        try:
            answer = (
                input(f"  Re-attest {_one_line(v.item_id)}? [y/N] ").strip().lower()
            )
        except EOFError:
            answer = ""
        if answer == "y":
            direct.append(
                decide.Decision(item, v.item_type, "reattest", "APPROVED", loaded=copy.deepcopy(item),
                                fresh_approver=v.status == "APPROVED_NO_LINE")
            )  # fmt: skip
    if not direct:
        print("Nothing to sign.")
        return
    decide.confirm_plan(direct, [], _display_item)
    decide.sign_and_commit(
        case_dir, identity, direct, [], new_passphrase=new_passphrase
    )


def _approval_checked(case_dir: Path, d: decide.Decision) -> bool:
    """Run the approval checks on a direct approval and show, before the
    passphrase, its roots, its grade and any failed check. A failed check
    needs a reason typed at the terminal; with none, the item stays DRAFT
    (False). Other decisions pass through."""
    if d.decision != "approve" or d.type not in ("finding", "timeline"):
        return True
    d.checks = approval_checks.check_item(case_dir, d.item, d.type, note=_hashing_note)
    for line in _approval_lines(d.item, d.checks):
        print(line)
    if d.checks["result"] != "failed":
        return True
    reason = approval_auth.read_tty_line(
        "  A check failed. Type why you approve it anyway (empty: leave it DRAFT): "
    )
    if not reason:
        print(
            f"  -> {_one_line(d.id)} left DRAFT: a check failed and no reason was typed"
        )
        return False
    d.approval_override_reason = reason
    return True


def _hashing_note(path: str, size: int) -> None:
    print(
        f"  Hashing {_safe(path)} ({size / 1e9:.1f} GB) once to verify it; "
        "later approvals won't need to read it again..."
    )


def _approval_lines(item: dict, checks: dict) -> list[str]:
    """What an approval shows before the passphrase: each root (path, SHA-256,
    label), the grade with its reason when it isn't FULL, and each failed
    check."""
    lines = []
    if checks.get("detail"):
        lines.append(f"  Checks: not applicable: {_safe(checks['detail'])}")
    if "title" in item and not item.get("imported_from"):
        arts = [a for a in item.get("artifacts") or [] if isinstance(a, dict)]
        roots = {}
        for a in arts if item.get("provenance_schema") == 2 else []:
            for r in approval_checks.roots_of(a):
                roots[(str(r["path"]), str(r.get("sha256") or ""))] = r
        lines += [
            f"  Root: {provenance_view.root_line(r)}" for _, r in sorted(roots.items())
        ]
        lines.append(
            f"  Provenance: {_safe(provenance_view.grade_label(item, reason=False))}"
        )
        for n, a in enumerate(arts if item.get("provenance_schema") == 2 else [], 1):
            label, why = provenance_view.grade(item, a)
            if label != "FULL" or why:
                lines.append(f"    [{n}] {_safe(provenance_view.grade_label(item, a))}")
    for i in checks.get("items", []):
        if i.get("status") == "failed":
            lines.append(
                f"  Check failed: {_safe(i.get('code', ''))} {_safe(i.get('subject', ''))}: "
                f"{_safe(i.get('detail', ''))}"
            )
    return lines


def _prompt_choice(choices: tuple[str, ...] = _APPROVE_CHOICES) -> str:
    """Prompt for a per-item action among `choices` (Enter approves, when it's one)."""
    labels = {"approve": "[a]pprove", "edit": "[e]dit", "note": "[n]ote", "reject": "[r]eject",
              "todo": "[t]odo", "skip": "[s]kip", "quit": "[q]uit"}  # fmt: skip
    keys = {c[0]: c for c in choices}
    prompt = "  " + "  ".join(labels[c] for c in choices) + ": "
    while True:
        try:
            response = input(prompt).strip().lower()
        except EOFError:
            return "skip"
        if response == "" and "approve" in choices:
            return "approve"
        if response in keys:
            return keys[response]
        print("  Invalid choice.")


class _EditLoader(yaml.SafeLoader):
    """SafeLoader that keeps an unquoted date or time as the text typed: a
    stored timestamp is text, and the examiner's form of it is what's signed."""


_EditLoader.yaml_implicit_resolvers = {
    first: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


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
        editable["alternatives"] = item.get("alternatives", [])
    else:
        # Timeline event
        for key in ("timestamp", "description", "source"):
            if key in item:
                editable[key] = item[key]

    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    tmpfile = f.name
    try:
        # written in the try, so a failed dump removes it too; closed for the
        # editor, which reopens it by name
        with f:
            yaml.dump(editable, f, default_flow_style=False, allow_unicode=True)
        try:
            subprocess.run([editor, tmpfile], check=True, timeout=3600)
        except subprocess.TimeoutExpired:
            print("  Editor timed out after 1 hour.", file=sys.stderr)
            return
        except subprocess.CalledProcessError as e:
            print(f"  Editor exited with error: {e}", file=sys.stderr)
            return
        except OSError as e:
            print(f"  Failed to launch editor '{editor}': {e}", file=sys.stderr)
            return

        try:
            with open(tmpfile) as f:
                edited = yaml.load(f, Loader=_EditLoader) or {}
        except yaml.YAMLError as e:
            print(f"  Edited file contains invalid YAML: {e}", file=sys.stderr)
            return
        except OSError as e:
            print(f"  Failed to read edited file: {e}", file=sys.stderr)
            return
    finally:
        try:
            os.unlink(tmpfile)
        except OSError:
            pass

    if not isinstance(edited, dict):
        print("  The edited file isn't a set of fields; the item is unchanged.",
              file=sys.stderr)  # fmt: skip
        return
    # Only the fields offered are applied: any other key (an id, a status,
    # the evidence) is named and left as it was.
    other = sorted(str(k) for k in edited if k not in editable)
    if other:
        print(f"  Not editable here, left unchanged: {_one_line(', '.join(other))}",
              file=sys.stderr)  # fmt: skip

    # Diff and record modifications
    modifications = {}
    now = datetime.now(timezone.utc).isoformat()
    for key, new_val in edited.items():
        if key not in editable:
            continue
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
        shown = f"  Created {_one_line(todo_id)}: "
        print(shown + _lines(td["description"], " " * len(shown)))
    save_todos(case_dir, todos)


def _challenge_line(challenged) -> str:
    """The finding's challenge state, in one line."""
    if not isinstance(challenged, dict):
        return "Not challenged"
    ids = challenged.get("skeptic_audit_ids") or []
    ids = ", ".join(str(i) for i in ids) if isinstance(ids, list) else str(ids)
    outcome = challenged.get("outcome")
    if outcome == "stands":
        return f"Challenged (client-reported): stands — skeptic: {ids}"
    if outcome == "revised":
        return f"Challenged (client-reported): revised after challenge — skeptic: {ids}"
    if outcome == "withdrawn":
        return (
            "Challenged (client-reported): withdrawn, not applied, staged for "
            f"your decision — skeptic: {ids or 'none'}"
        )
    return f"Challenged (client-reported): {outcome}"


def _challenge_reasons(challenged) -> list[str]:
    """The marker's stated contradiction and the server's refusal, escaped."""
    if not isinstance(challenged, dict):
        return []
    lines = []
    if challenged.get("contradiction"):
        lines.append(f"Contradiction (client-reported): {challenged['contradiction']}")
    if challenged.get("refused"):
        lines.append(f"Server: {challenged['refused']}")
    return [_safe(line) for line in lines]


def _alternative_lines(alternatives) -> list[str]:
    """One line per alternative; any other shape (an examiner's edit) as text."""
    if not isinstance(alternatives, list):
        return [_safe(alternatives)] if alternatives else []
    lines = []
    for a in alternatives:
        if not isinstance(a, dict):
            lines.append(_safe(a))
            continue
        status = str(a.get("status") or "open").replace("_", " ")
        line = f"[{status}] {a.get('explanation', '')}"
        if a.get("evidence"):
            line += f" — {a['evidence']}"
        if isinstance(a.get("audit_ids"), list) and a["audit_ids"]:
            line += f" (audit: {', '.join(str(i) for i in a['audit_ids'])})"
        lines.append(_safe(line))
    return lines


# --- Evidence before the decision -------------------------------------------
#
# Artifact content and the finding's text come from evidence and the model,
# and now print before the password prompt: every line goes through _safe,
# and content lines carry a gutter so they can't pass for a banner or prompt.

_GUTTER = "      │ "
_UNSAFE_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}


def _safe(text) -> str:
    """Text shown as written, with control, format, surrogate and line or
    paragraph separator characters (newlines included) as visible escapes."""
    out = []
    for ch in str(text):
        if unicodedata.category(ch) in _UNSAFE_CATEGORIES:
            cp = ord(ch)
            if cp <= 0xFF:
                out.append(f"\\x{cp:02x}")
            elif cp <= 0xFFFF:
                out.append(f"\\u{cp:04x}")
            else:
                out.append(f"\\U{cp:08x}")
        else:
            out.append(ch)
    return "".join(out)


def _content_lines(text) -> list[str]:
    """Content line by line, each behind the gutter; a run of more than two
    blank lines is shown as one."""
    lines: list[str] = []
    blanks = 0

    def flush() -> None:
        if blanks > 2:
            lines.append(f"{_GUTTER}({blanks} blank lines)")
        else:
            lines.extend([_GUTTER.rstrip()] * blanks)

    for line in str(text).split("\n"):
        if not line.strip():
            blanks += 1
            continue
        flush()
        blanks = 0
        lines.append(_GUTTER + _safe(line))
    flush()
    return lines


def _linked_events(item: dict, timeline: list[dict]) -> list[dict]:
    """The DRAFT timeline event approving this finding approves with it: the
    one its signed `timeline_event_id` names (the cascade's own rule)."""
    return [
        t
        for t in timeline
        if t.get("id") == item.get("timeline_event_id")
        and t.get("auto_created_from") == item.get("id")
        and t.get("status") == "DRAFT"
        and not t.get("examiner_modifications")
    ]


def _evidence_lines(item: dict, timeline: list[dict]) -> list[str]:
    """A finding's artifacts, then the events approved with it."""
    return _artifact_lines(item) + _linked_lines(item, timeline)


def _artifact_lines(item: dict) -> list[str]:
    artifacts = item.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, list) else []
    lines = []
    if not artifacts:
        lines.append("  Artifacts: no artifacts recorded")
    else:
        lines.append(f"  Artifacts ({len(artifacts)}):")
    for n, art in enumerate(artifacts, 1):
        if not isinstance(art, dict):
            lines.append(f"    {n}. {_safe(art)}")
            continue
        lines.append(f"    {n}. source:     {_safe(art.get('source', ''))}")
        lines.append(f"       extraction: {_safe(art.get('extraction', ''))}")
        lines.append(f"       audit id:   {_safe(art.get('audit_id', ''))}")
        lines.append("       content:")
        lines.extend(_content_lines(art.get("content", "")))
    return lines


def _linked_lines(item: dict, timeline: list[dict]) -> list[str]:
    lines = []
    linked = _linked_events(item, timeline)
    if linked:
        lines.append("  Timeline events approved with it:")
        for t in linked:
            lines.append(
                f"    [{_safe(t.get('id', ''))}] {_safe(t.get('timestamp', '?'))}"
                f"  {_safe(t.get('description', ''))}"
            )
    return lines


def _print_pending_item(item: dict, timeline: list[dict]) -> None:
    """Everything the examiner decides on, before the password prompt."""
    print(f"{'─' * 60}")
    if "title" in item:
        print(f"  {_safe(_challenge_line(item.get('challenged')))}")
        for line in _challenge_reasons(item.get("challenged")):
            print(f"    {line}")
        print(f"  [{_safe(item['id'])}]  {_safe(item.get('title', 'Untitled'))}")
        meta = [
            f"{label}: {_safe(item[key])}"
            for label, key in (
                ("Examiner", "examiner"),
                ("By", "created_by"),
                ("Confidence", "confidence"),
            )
            if item.get(key)
        ]
        if item.get("audit_ids"):
            meta.append(f"Evidence: {_safe(', '.join(map(str, item['audit_ids'])))}")
        if meta:
            print(f"  {' | '.join(meta)}")
        print(f"  Observation: {_safe(item.get('observation', ''))}")
        print(f"  Interpretation: {_safe(item.get('interpretation', ''))}")
        for line in _alternative_lines(item.get("alternatives")):
            print(f"  Alternative: {line}")
        if item.get("iocs"):
            print(f"  IOCs: {_safe(item['iocs'])}")
        for line in _evidence_lines(item, timeline):
            print(line)
    else:
        print(f"  [{_safe(item['id'])}]  {_safe(item.get('timestamp', '?'))}")
        print(f"  Description: {_safe(item.get('description', ''))}")
        if item.get("audit_ids"):
            print(f"  Evidence: {_safe(', '.join(map(str, item['audit_ids'])))}")


def _print_decision_header(item: dict) -> None:
    """One line per decision: the evidence was shown before the prompt."""
    if "title" in item:
        artifacts = item.get("artifacts")
        count = len(artifacts) if isinstance(artifacts, list) else 0
        label = f"{_safe(item.get('title', 'Untitled'))} — {count} artifact(s)"
    else:
        label = (
            f"{_safe(item.get('timestamp', '?'))}  {_safe(item.get('description', ''))}"
        )
    print(f"\n── [{_safe(item['id'])}]  {label}")


def _display_ioc(item: dict) -> None:
    """An IOC: what the examiner decides about it, and its derived context."""
    print(f"\n{'─' * 60}")
    print(f"  [{_one_line(item['id'])}]  {_one_line(item.get('value', ''))}")
    print(f"{'─' * 60}")
    for label, key in (("Value", "value"), ("Type", "type"), ("Category", "category"),
                       ("Tags", "tags"), ("Description", "description")):  # fmt: skip
        value = item.get(key, "")
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value)
        print(f"  {label}: {_one_line(value)}")
    print("  Sources, sightings, confidence, MITRE: derived, not signed")
    print()


def _display_item(item: dict) -> None:
    """Display a finding, timeline event or IOC."""
    if str(item.get("id", "")).startswith("IOC-"):
        _display_ioc(item)
        return
    created_by = item.get("created_by", "")
    examiner = item.get("examiner", "")
    print(f"\n{'─' * 60}")
    title = item.get("title", item.get("description", "Untitled"))
    print(f"  [{_one_line(item['id'])}]  {_one_line(title)}")
    if "title" in item:  # under the title, which can't hide it
        print(f"  {_one_line(_challenge_line(item.get('challenged')))}")
        for line in _challenge_reasons(item.get("challenged")):
            print(f"    {line}")
    if examiner:
        print(f"  Examiner: {_one_line(examiner)}", end="")
    if created_by:
        print(f"  | By: {_one_line(created_by)}", end="")
    if item.get("confidence"):
        print(f"  | Confidence: {_one_line(item['confidence'])}", end="")
    if item.get("audit_ids"):
        print(
            f"  | Evidence: {_one_line(', '.join(map(str, item['audit_ids'])))}", end=""
        )
    print()
    print(f"{'─' * 60}")

    if "title" in item:
        # It's a finding
        print(f"  Observation: {_lines(item.get('observation', ''), ' ' * 15)}")
        print(f"  Interpretation: {_lines(item.get('interpretation', ''), ' ' * 18)}")
        for line in _alternative_lines(item.get("alternatives")):
            print(f"  Alternative: {_one_line(line)}")
        if item.get("iocs"):
            print(f"  IOCs: {_one_line(item['iocs'])}")
        if item.get("timeline_event_id"):
            print(f"  Timeline event: {_one_line(item['timeline_event_id'])}")
    else:
        # It's a timeline event
        print(f"  Timestamp: {_one_line(item.get('timestamp', '?'))}")
        print(f"  Description: {_lines(item.get('description', ''), ' ' * 15)}")
        if item.get("audit_ids"):
            print(f"  Evidence: {_one_line(', '.join(map(str, item['audit_ids'])))}")
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
    "alternatives",
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


def _staged_body(item: dict, delta_entry: dict) -> dict:
    """The item as the entry would have it signed: its edits applied."""
    post = copy.deepcopy(item)
    mods = delta_entry.get("modifications") or {}
    for f, m in mods.items() if isinstance(mods, dict) else ():
        if f in _DELTA_EDITABLE_FIELDS and isinstance(m, dict):
            post[f] = m.get("modified")
    return post


def _render_terminal_diff(item: dict, delta_entry: dict) -> None:
    """Print a staged entry as it would be signed: the item with the entry's
    edits applied, each edited field shown as - before / + after, then every
    other field of the signed body, so nothing signed goes unshown."""
    item_id = _one_line(delta_entry.get("id", "?"))
    action = _one_line(delta_entry.get("action", "?")).upper()
    modifications = {
        f: m
        for f, m in (delta_entry.get("modifications") or {}).items()
        if f in _DELTA_EDITABLE_FIELDS and isinstance(m, dict)
    }

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
    item = _staged_body(item, delta_entry)
    shown = {"id", "status", "challenged", "alternatives"}

    # Finding fields
    if "title" in item:
        if "title" in modifications:
            _render_field("Title", item, modifications, "title")
        else:
            print(f"  Title:          {_one_line(item.get('title', ''))}")
        print(f"  {_one_line(_challenge_line(item.get('challenged')))}")
        for line in _challenge_reasons(item.get("challenged")):
            print(f"    {line}")
        _render_field("Confidence", item, modifications, "confidence")
        _render_field("Observation", item, modifications, "observation")
        _render_field("Interpretation", item, modifications, "interpretation")
        if item.get("audit_ids"):
            print(
                f"  Evidence:       {_one_line(', '.join(map(str, item['audit_ids'])))}"
            )
        for label, field in (("MITRE", "mitre_ids"), ("IOCs", "iocs"),
                             ("Context", "context"),
                             ("Justification", "confidence_justification")):  # fmt: skip
            if item.get(field) or field in modifications:
                _render_field(label, item, modifications, field)
        shown |= {"title", "confidence", "observation", "interpretation", "audit_ids",
                  "mitre_ids", "iocs", "context", "confidence_justification"}  # fmt: skip
        if "alternatives" in modifications:
            mod = modifications["alternatives"]
            for line in _alternative_lines(mod.get("original")):
                print(f"  Alternative:    {_RED}- {_one_line(line)}{_RESET}")
            for line in _alternative_lines(mod.get("modified")):
                print(f"  Alternative:    {_GREEN}+ {_one_line(line)}{_RESET}")
        else:
            for line in _alternative_lines(item.get("alternatives")):
                print(f"  Alternative:    {_one_line(line)}")
    else:
        # Timeline event
        _render_field("Timestamp", item, modifications, "timestamp")
        _render_field("Description", item, modifications, "description")
        if item.get("source") or "source" in modifications:
            _render_field("Source", item, modifications, "source")
        shown |= {"timestamp", "description", "source"}
    if item.get("tags") or "tags" in modifications:
        _render_field("Tags", item, modifications, "tags")
    shown.add("tags")
    if "artifacts" in item:  # signed: shown whatever the action
        for line in _artifact_lines(item):
            print(line)
        shown.add("artifacts")
    # every other field of the signed body
    body = json.loads(signed_text(item, decide.item_type(str(item.get("id", "")))))
    for field in sorted(set(body) - shown):
        value = body[field]
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        label = field.replace("_", " ").capitalize()
        print(f"  {label}:{' ' * max(1, 15 - len(label))}{_one_line(text)}")

    # Note
    note = delta_entry.get("note")
    if note:
        print(f"  {_CYAN}Note: {_one_line(note)}{_RESET}")

    # Rejection reason
    if action == "REJECT":
        reason = delta_entry.get("rejection_reason", "") or delta_entry.get(
            "reason", ""
        )
        print(f"  {_RED}Reason: {_one_line(reason or '(no reason given)')}{_RESET}")

    # TODO details
    if action == "TODO":
        desc = delta_entry.get("todo_description", "")
        prio = delta_entry.get("todo_priority", "medium")
        print(
            f"  {_YELLOW}TODO: {_one_line(desc)} (priority: {_one_line(prio)}){_RESET}"
        )

    # Status line
    current_status = _one_line(item.get("status", "DRAFT"))
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

    def shown(text, indent: str) -> str:
        return _lines(text, indent) if field in _MULTI_LINE else _one_line(text)

    if field in modifications:
        mod = modifications[field]
        original = mod.get("original", "")
        modified = mod.get("modified", "")
        # Format lists
        if isinstance(original, list):
            original = ", ".join(str(x) for x in original)
        if isinstance(modified, list):
            modified = ", ".join(str(x) for x in modified)
        indent = " " * (len(prefix) + 2)
        print(f"{prefix}{_RED}- {shown(original, indent)}{_RESET}")
        print(
            f"  {' ' * (len(label) + 1)}{' ' * pad}{_GREEN}+ {shown(modified, indent)}{_RESET}"
        )
    else:
        val = item.get(field, "")
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val)
        print(f"{prefix}{shown(val, ' ' * len(prefix))}")


# An IOC's value and type are what the examiner decides: only its tags and
# description are edited, here as in the portal
_IOC_EDITABLE = frozenset({"tags", "description"})


def _same_entry(a: dict, b: dict) -> bool:
    """Equal apart from the CLI's own stamps."""
    strip = lambda e: {  # noqa: E731
        k: v for k, v in e.items() if k not in ("saved_unsigned", "review_again")
    }
    return strip(a) == strip(b)


def _merge_processing(case_dir: Path) -> None:
    """A `.processing` file left by 0.6: its entries whose id isn't in
    pending-reviews.json are merged in as "staged by unknown", and it is kept
    as `.processing.merged-<UTC>`. Never deleted or overwritten."""
    processing = case_dir / "pending-reviews.processing"
    if not processing.exists():
        return
    delta_path = case_dir / "pending-reviews.json"
    with ledger.case_lock(case_id_of(case_dir)):
        try:
            old = json.loads(processing.read_text())
        except (OSError, ValueError):
            old = {}
        delta = decide.read_delta(delta_path) or {
            "case_id": case_id_of(case_dir),
            "items": [],
        }
        have = {e.get("id") for e in delta.get("items", []) if isinstance(e, dict)}
        for e in old.get("items", []) if isinstance(old, dict) else []:
            if isinstance(e, dict) and e.get("id") not in have:
                e = {
                    k: v
                    for k, v in e.items()
                    if k not in ("staged_by", "saved_unsigned")
                }
                delta.setdefault("items", []).append(e)
        decide._write_delta(delta_path, delta)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        processing.rename(
            processing.with_name(f"pending-reviews.processing.merged-{stamp}")
        )
    print(
        "A review file left by an earlier version was merged into pending-reviews.json."
    )


def _review_mode(
    case_dir: Path,
    identity: dict,
    config_path: Path,
    withdrawn_line: str = "",
    show_signed: bool = False,
) -> None:
    """Sign the decisions staged in pending-reviews.json (the portal's, or
    saved unsigned by the CLI). Your own entries are selected; entries
    staged by someone else are shown as theirs and included only if you say
    so. Only the entries signed (or turned into TODOs) are removed from the
    file, under the case lock; nothing else in it changes."""
    examiner = identity["examiner"]
    delta_path = case_dir / "pending-reviews.json"
    folders = credentials.signing_folders_problem()
    if folders:  # before the lock below needs ledger/
        print(folders, file=sys.stderr)
        sys.exit(1)
    _merge_processing(case_dir)
    with ledger.case_lock(case_id_of(case_dir)):  # a corrupt file is set aside
        delta = decide.read_delta(delta_path)
    if delta is None:
        print("No pending dashboard reviews.")
        if withdrawn_line:
            print(withdrawn_line)
        return
    entries = [e for e in delta.get("items", []) if isinstance(e, dict)]
    if not entries:
        print("No pending dashboard reviews.")
        if withdrawn_line:
            print(withdrawn_line)
        return
    delta_case_id = delta.get("case_id", "")
    if delta_case_id and delta_case_id != case_id_of(case_dir):
        print(
            f"Error: Delta case_id ({_one_line(delta_case_id)}) does not match "
            f"active case ({_one_line(case_id_of(case_dir))}).",
            file=sys.stderr,
        )
        sys.exit(1)

    new_passphrase = _preflight(identity, config_path, case_dir)
    check_case_file_integrity(case_dir, "findings.json")
    check_case_file_integrity(case_dir, "timeline.json")
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    iocs = load_iocs(case_dir)
    item_by_id = {
        x["id"]: x
        for x in findings + timeline + iocs
        if isinstance(x, dict) and "id" in x
    }

    selected = [e for e in entries if e.get("staged_by") == examiner]
    own_ids = {e.get("id") for e in selected}
    for e in entries:
        if e.get("staged_by") == examiner:
            continue
        who = e.get("staged_by") or "unknown"
        print(f"\n  Staged by {_one_line(who)}; not included unless you say so:")
        _render_terminal_diff(item_by_id.get(e.get("id")), e)
        if e.get("id") in own_ids:
            print(
                f"  You have your own entry for {_one_line(e.get('id'))}; not offered."
            )
            continue
        try:
            answer = (
                input(
                    f"  Include {_one_line(e.get('id'))} and sign as {_one_line(examiner)}? [y/N] "
                )
                .strip()
                .lower()
            )
        except EOFError:
            answer = ""
        if answer == "y":
            selected.append(e)
    ids = [e.get("id") for e in selected if e.get("action") != "todo"]
    duplicate = sorted({i for i in ids if ids.count(i) > 1})
    if duplicate:
        print(f"DUPLICATE_ITEM: {', '.join(map(_one_line, duplicate))} selected twice; nothing was signed.",
              file=sys.stderr)  # fmt: skip
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()
    direct: list[decide.Decision] = []
    todo_entries: list[dict] = []
    skipped: list[tuple[str, str]] = []
    for entry in selected:
        item_id, action = entry.get("id", ""), str(entry.get("action", "")).lower()
        if action == "todo":
            todo_entries.append(entry)
            _render_terminal_diff(item_by_id.get(item_id), entry)
            continue
        item = item_by_id.get(item_id)
        if item is None:
            skipped.append((item_id, "not found"))
            continue
        if entry.get("saved_unsigned"):
            print(
                f"  {_one_line(item_id)}: saved unsigned from the CLI {_one_line(entry['saved_unsigned'].get('at', ''))}"
            )
        at_review = entry.get("content_hash_at_review", "")
        if at_review and at_review != compute_content_hash(item):
            skipped.append((item_id, "changed after you reviewed it"))
            continue
        mods = entry.get("modifications") or {}
        fixed = sorted(f for f in mods if f not in _IOC_EDITABLE)
        if decide.item_type(item_id) == "ioc" and fixed:  # value and type are decided
            skipped.append((item_id, f"an IOC's {', '.join(fixed)} can't be edited"))
            continue
        conflict = next(
            (f for f, m in mods.items() if item.get(f) != m.get("original")), None
        )
        if conflict:
            skipped.append((item_id, f"field '{conflict}' changed since review"))
            continue
        loaded = copy.deepcopy(item)
        for f, m in mods.items():
            if f in _DELTA_EDITABLE_FIELDS:
                item[f] = m.get("modified")
                item.setdefault("examiner_modifications", {})[f] = {
                    "original": m.get("original"), "modified": m.get("modified"),
                    "modified_by": examiner, "modified_at": now,
                }  # fmt: skip
        if entry.get("note"):
            _apply_note(item, entry["note"], identity)
        kind = decide.item_type(item_id)
        if kind == "ioc" and action in ("approve", "reject"):
            item["manually_reviewed"] = True
        # shown as it will be signed: after its edits
        _render_terminal_diff(item, entry)
        if action == "approve" and "title" in item:
            for line in _linked_lines(item, timeline):
                print(line)
        if show_signed:
            _print_signed(item)
        if action == "edit":
            after = loaded.get("status", "DRAFT")
        else:
            after = _STATUS_AFTER.get(action)
        if after is None:
            skipped.append((item_id, f"unknown action {action!r}"))
            continue
        chosen = decide.Decision(item, kind, action, after, loaded=loaded,
                                 reason=entry.get("rejection_reason", "") or entry.get("reason", ""),
                                 note=entry.get("note", ""), modifications=mods, delta_entry=entry)  # fmt: skip
        if not _approval_checked(case_dir, chosen):
            skipped.append(
                (item_id, "a check failed and no reason was typed; left DRAFT")
            )
            continue
        direct.append(chosen)
    if skipped:
        print(f"\n  {_YELLOW}Skipped {len(skipped)} item(s), not signed:")
        for sid, why in skipped:
            print(f"    {_one_line(sid)}: {_one_line(why)}")
        print(f"  Re-review in browser.{_RESET}")

    def finish(lists=None, signed=()) -> None:
        """Inside the commit's lock span: the TODOs, then remove exactly the
        entries signed or turned into TODOs from the current file. Your own
        entries whose decision was discarded stay, marked to review again;
        another examiner's entry is never touched unless it was signed."""
        if todo_entries:
            _create_todos(case_dir, [
                {"description": e.get("todo_description", f"Follow up on {e.get('id', '')}"),
                 "priority": e.get("todo_priority", "medium"),
                 "assignee": e.get("todo_assignee", ""),
                 "related_findings": [e.get("id", "")]}
                for e in todo_entries
            ], identity)  # fmt: skip
        signed_ids = {id(d) for d in signed}
        done = [d.delta_entry for d in direct if id(d) in signed_ids] + todo_entries
        again = [
            d.delta_entry for d in direct
            if id(d) not in signed_ids and d.delta_entry.get("staged_by") == examiner
        ]  # fmt: skip
        current = decide.read_delta(delta_path)
        if current is None:
            return
        keep = []
        for e in current.get("items", []):
            if isinstance(e, dict) and any(_same_entry(e, x) for x in done):
                continue
            if isinstance(e, dict) and any(_same_entry(e, x) for x in again):
                e["review_again"] = {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "reason": "the item changed after you saw it; nothing was signed",
                }
            keep.append(e)
        current["items"] = keep
        decide._write_delta(delta_path, current)

    if not direct:
        if todo_entries:
            with ledger.case_lock(case_id_of(case_dir)):
                finish()
        print("Nothing to sign.")
        return
    planned = decide.cascades(direct, findings, timeline, iocs)
    print(f"\n{'=' * 60}")
    print(
        f"  Sign {len(direct)} decision(s) from pending reviews, {len(todo_entries)} TODO(s)"
    )
    print(f"{'=' * 60}")
    decide.confirm_plan(direct, planned, _display_item, lead=withdrawn_line)
    decide.sign_and_commit(
        case_dir, identity, direct, planned, new_passphrase=new_passphrase,
        inside_lock=finish,
    )  # fmt: skip
