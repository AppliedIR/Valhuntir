"""One commit tail for every CLI decision path (approve, reject, re-attest).

The order is the same everywhere:
1. the caller displays the items and collects the decisions (no lock held);
2. `confirm_plan` prints every cascaded item, marked "cascade from F-…";
3. `sign_and_commit` asks for the password last, retried in place. A failure
   that retrying can't fix saves the decisions, unsigned, to
   pending-reviews.json, so no review work is lost;
4. under the case lock it reloads the case files and judges each decision
   on its own: one whose item changed or was deleted after it was shown is
   discarded with a loud line; every other one is signed and appended, then
   applied to the reloaded items with times from the signed bodies, and the
   files are saved (every writer of the case files holds the lock from load
   to save). A case file that doesn't parse stops the commit: nothing is
   signed, and the decisions are saved unsigned;
5. after the lock, it writes the approvals.jsonl activity log (unsigned, best
   effort: a failure there never undoes or stops anything) and prints the head.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli import credentials, keys, ledger
from vhir_cli.case_io import (
    case_id_of,
    compute_content_hash,
    plan_cascades,
    save_findings,
    save_iocs,
    save_timeline,
    set_status,
    signed_text,
    write_approval_log,
)
from vhir_cli.display import one_line

# Fields a pending-reviews entry can carry as modifications (as the portal).
DELTA_EDITABLE_FIELDS = frozenset(
    {
        "title", "observation", "interpretation", "confidence", "confidence_justification",
        "mitre_ids", "iocs", "context", "alternatives", "timestamp", "description", "source",
        "tags",
    }
)  # fmt: skip


@dataclass
class Decision:
    item: dict  # as it will be signed (edits applied)
    type: str  # finding, timeline or ioc
    decision: str  # approve, reject, edit or reattest
    status_after: str
    loaded: dict = field(default_factory=dict)  # as loaded and displayed
    coupled_from: str | None = None
    reason: str = ""
    note: str = ""
    modifications: dict = field(default_factory=dict)
    fresh_approver: bool = False  # a re-attestation with no earlier record
    delta_entry: dict | None = None  # review mode: the stored entry it signs

    @property
    def id(self) -> str:
        return self.item["id"]


def item_type(item_id: str) -> str:
    if item_id.startswith("IOC-"):
        return "ioc"
    return "timeline" if item_id.startswith("T-") else "finding"


def cascades(
    direct: list[Decision], findings, timeline, iocs, skipped=()
) -> list[Decision]:
    """The cascades of `direct`, planned from the post-edit items."""
    edited = {d.id: d.item for d in direct}
    findings = [edited.get(f.get("id"), f) for f in findings]
    decided = {
        d.id: d.status_after
        for d in direct
        if d.type == "finding" and d.decision in ("approve", "reject", "edit")
    }
    exclude = {d.id for d in direct} | set(skipped)
    return [
        Decision(c["item"], c["type"], "approve" if c["status_after"] == "APPROVED" else "reject",
                 c["status_after"], loaded=copy.deepcopy(c["item"]), coupled_from=c["coupled_from"])
        for c in plan_cascades(decided, findings, timeline, iocs, exclude)
    ]  # fmt: skip


def confirm_plan(
    direct: list[Decision],
    planned: list[Decision],
    display: Callable[[dict], None],
    lead: str = "",
) -> None:
    """Print every cascaded item, after the direct ones, then `lead` and the
    ids to be signed, just above the prompt."""
    if planned:
        print(f"\n{len(planned)} item(s) decided with them:")
    for c in planned:
        display(c.item)
        print(f"  cascade from {one_line(c.coupled_from)}: {c.decision}")
    ids = ", ".join(one_line(d.id) for d in direct + planned)
    if lead:
        print(lead)
    print(f"\nTo be signed: {ids}")


def _prompt_text(direct, planned, new_passphrase: bool) -> str:
    n, k = len(direct), len(planned)
    lead = "Your new passphrase" if new_passphrase else "Password"
    return f"{lead} to sign {n + k} decisions ({n} direct, {k} cascaded): "


# --- Unsigned save ----------------------------------------------------------------------


def _write_delta(path: Path, delta: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(delta, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, str(path))


def save_unsigned(
    case_dir: Path, examiner: str, direct: list[Decision], why: str
) -> list[str]:
    """Save the decisions to pending-reviews.json, unsigned and marked so,
    merged under the case lock: an entry of this examiner's for the same id
    is replaced, others are kept. Returns what couldn't be saved."""
    now = datetime.now(timezone.utc).isoformat()
    path = case_dir / "pending-reviews.json"
    not_saved: list[str] = []
    with ledger.case_lock(case_id_of(case_dir)):
        try:
            delta = json.loads(path.read_text())
        except (OSError, ValueError):
            delta = {}
        if not isinstance(delta, dict):
            delta = {}
        entries = [e for e in delta.get("items", []) if isinstance(e, dict)]
        for d in direct:
            if d.delta_entry is not None:  # from the file: stamp it in place
                for e in entries:
                    if e == d.delta_entry and e.get("staged_by") == examiner:
                        e["saved_unsigned"] = {"at": now, "reason": why}
                continue
            if d.decision == "reattest":
                not_saved.append(f"{d.id} (re-run `vhir approve --reattest`)")
                continue
            dropped = sorted(set(d.modifications) - DELTA_EDITABLE_FIELDS)
            if dropped:
                not_saved.append(f"{d.id}: {', '.join(dropped)}; enter it again")
            entry = {
                "id": d.id,
                "type": d.type,
                "action": d.decision,
                "modifications": {
                    k: v
                    for k, v in d.modifications.items()
                    if k in DELTA_EDITABLE_FIELDS
                },
                "content_hash_at_review": compute_content_hash(d.loaded),
                "staged_by": examiner,
                "saved_unsigned": {"at": now, "reason": why},
            }
            if d.note:
                entry["note"] = d.note
            if d.reason:
                entry["rejection_reason"] = d.reason
            entries = [
                e
                for e in entries
                if not (e.get("id") == d.id and e.get("staged_by") == examiner)
            ]
            entries.append(entry)
        delta["items"] = entries
        delta.setdefault("case_id", case_id_of(case_dir))
        delta["modified_at"] = now
        _write_delta(path, delta)
    return not_saved


# --- Signing ------------------------------------------------------------------------------


def _find(lists: dict[str, list[dict]], kind: str, item_id: str) -> dict | None:
    return next(
        (x for x in lists[kind] if isinstance(x, dict) and x.get("id") == item_id), None
    )


def _reload(case_dir: Path) -> tuple[dict[str, list[dict]], list[str]]:
    """The case files as they are now, and the names of any that exist but
    don't read as a list (a commit never goes ahead on, or saves over, them)."""
    lists: dict[str, list[dict]] = {}
    bad: list[str] = []
    for kind, name in (
        ("finding", "findings.json"),
        ("timeline", "timeline.json"),
        ("ioc", "iocs.json"),
    ):
        path = case_dir / name
        try:
            data = json.loads(path.read_text()) if path.exists() else []
        except (OSError, ValueError):
            data = None
        if not isinstance(data, list):
            bad.append(name)
            data = []
        lists[kind] = data
    return lists, bad


def _changed(d: Decision, current: dict | None) -> bool:
    if current is None:
        return True
    return signed_text(current, d.type) != signed_text(d.loaded, d.type) or current.get(
        "status"
    ) != d.loaded.get("status")


def sign_and_commit(
    case_dir: Path,
    identity: dict,
    direct: list[Decision],
    planned: list[Decision],
    *,
    new_passphrase: bool = False,
    skipped=(),
    mode: str = "cli",
    inside_lock: Callable[[dict[str, list[dict]]], None] | None = None,
) -> None:
    """Sign `direct` and `planned` (cascades) and apply them. Exits non-zero
    with nothing signed when anything can't go ahead."""
    examiner = identity["examiner"]
    prompt = _prompt_text(direct, planned, new_passphrase)
    try:
        private, public = credentials.unlock(examiner, prompt)
    except KeyboardInterrupt:
        print("\nNothing was signed and nothing was saved.", file=sys.stderr)
        sys.exit(1)
    except (keys.KeyUnwrapFailed, credentials.AttemptsExhausted) as e:
        unwrap = isinstance(e, keys.KeyUnwrapFailed)
        if unwrap:
            print(keys.KeyUnwrapFailed.MESSAGE, file=sys.stderr)
        not_saved = save_unsigned(
            case_dir, examiner, direct, "KEY_UNWRAP_FAILED" if unwrap else "attempts"
        )
        after = (
            "after `vhir config --forgot-password`"
            if unwrap
            else "after the lockout ends"
        )
        print(
            f"Nothing was signed. Your {len(direct)} decisions were saved, unsigned, to "
            f"pending-reviews.json. Sign them with `vhir approve --review` {after}.",
            file=sys.stderr,
        )
        for x in not_saved:
            print(f"  not saved: {one_line(x)}", file=sys.stderr)
        sys.exit(1)

    case_id = case_id_of(case_dir)
    head, every, items, discarded = None, [], [], []
    with ledger.case_lock(
        case_id,
        on_wait=lambda: print(
            "Waiting for another writer to finish...", file=sys.stderr
        ),
    ) as lock:
        lists, unreadable = _reload(case_dir)
        if not unreadable:
            every, discarded = _still_as_shown(lists, direct, planned, skipped)
        if every:
            at = datetime.now(timezone.utc).isoformat()
            items = [_find(lists, d.type, d.id) for d in every]
            decisions = [
                {"item_id": d.id, "type": d.type, "decision": d.decision,
                 "status_after": d.status_after, "coupled_from": d.coupled_from,
                 "content_snapshot": signed_text(item, d.type)}
                for d, item in zip(every, items, strict=True)
            ]  # fmt: skip
            bodies = ledger.prepare(
                case_id, decisions, examiner, public, mode, at,
                retired=credentials.retired_fingerprints(examiner),
            )  # fmt: skip
            lines = [ledger.sign_body(b, private) for b in bodies]
            head = ledger.commit(lock, bodies, lines, public)
            for d, item, body in zip(every, items, bodies, strict=True):
                set_status(item, d.decision, d.status_after, body["examiner"], body["at"],
                           reason=d.reason, fresh_approver=d.fresh_approver)  # fmt: skip
            touched = {d.type for d in every}
            for attempt in (1, 2):
                try:
                    if "finding" in touched:
                        save_findings(case_dir, lists["finding"])
                    if "timeline" in touched:
                        save_timeline(case_dir, lists["timeline"])
                    if "ioc" in touched:
                        save_iocs(case_dir, lists["ioc"])
                    break
                except OSError as e:
                    if attempt == 2:
                        print(
                            f"Signed decisions were recorded; case data was not saved ({e}); "
                            f"re-run the same command for: {', '.join(d.id for d in every)}",
                            file=sys.stderr,
                        )
                        sys.exit(1)
        if inside_lock is not None and not unreadable:
            inside_lock(lists)

    if unreadable:  # no per-item judgement is possible: keep every decision
        not_saved = save_unsigned(case_dir, examiner, direct, "case file unreadable")
        print(
            f"\n{'!' * 60}\n{', '.join(unreadable)} couldn't be read as case data. "
            "Nothing was signed, and the file was left as it is.\n"
            f"Your {len(direct)} decision(s) were saved, unsigned, to pending-reviews.json. "
            "Once the file is repaired, `vhir approve --review` signs those whose content "
            f"still matches what you saw.\n{'!' * 60}",
            file=sys.stderr,
        )
        for x in not_saved:
            print(f"  not saved: {one_line(x)}", file=sys.stderr)
        sys.exit(1)
    for line in discarded:
        print(line, file=sys.stderr)
    if every:
        _activity_log(case_dir, identity, every, items, mode)
        _report(case_id, every, head, examiner, public)
    if discarded:
        print(
            f"{len(discarded)} decision(s) were discarded, as listed above"
            + ("; the others were signed." if every else "; nothing was signed."),
            file=sys.stderr,
        )
        sys.exit(1)


def _still_as_shown(lists, direct, planned, skipped):
    """Per item, under the lock: the decisions to sign (each direct one whose
    item is unchanged since it was shown, with its edit spliced in; each
    cascade that was shown and still holds), and a loud line for each one
    discarded. A cascade that only now appears wasn't shown, so it isn't signed."""
    discarded, kept = [], []
    for d in direct:
        if _changed(d, _find(lists, d.type, d.id)):
            discarded.append(
                f"  DISCARDED: {one_line(d.id)} was changed or deleted after you saw it; "
                f"your {d.decision} decision on it was not signed or saved. Review it again."
            )
            continue
        kept.append(d)
        lst = lists[d.type]
        for i, x in enumerate(lst):
            if isinstance(x, dict) and x.get("id") == d.id:
                lst[i] = d.item  # the edit, on the unchanged item
    shown = {(c.id, c.status_after, c.coupled_from): c for c in planned}
    again = cascades(kept, lists["finding"], lists["timeline"], lists["ioc"], skipped)
    now = {(c.id, c.status_after, c.coupled_from) for c in again}
    signed = []
    for key, c in shown.items():
        if key in now and not _changed(c, _find(lists, c.type, c.id)):
            signed.append(c)
        else:
            discarded.append(
                f"  DISCARDED: {one_line(c.id)} (cascade from {one_line(c.coupled_from)}) "
                "changed, or its source's decision was discarded; not signed or saved."
            )
    for key in sorted(now - set(shown)):
        discarded.append(
            f"  NOT SIGNED: {one_line(key[0])} would now be decided with "
            f"{one_line(key[2])}, but it wasn't shown to you; it is left as it is."
        )
    return kept + signed, discarded


def _activity_log(case_dir, identity, every, items, mode) -> None:
    """approvals.jsonl: an unsigned activity log, not verification. Written
    after the signed commit; a failure on one entry never stops the rest."""
    failed = []
    for d, item in zip(every, items, strict=True):
        try:
            ok = write_approval_log(
                case_dir, d.id, d.status_after if d.decision != "reattest" else "REATTESTED",
                identity, mode=mode, reason=d.reason, coupled_from=d.coupled_from or "",
                content_hash=item.get("content_hash", ""),
            )  # fmt: skip
        except Exception:  # noqa: BLE001 - the log is best effort
            ok = False
        if not ok:
            failed.append(d.id)
    if failed:
        print(
            f"  WARNING: the activity log (approvals.jsonl, unsigned) wasn't written for: "
            f"{', '.join(failed)}. The signed decisions stand.",
            file=sys.stderr,
        )


def _report(case_id, every, head, examiner, public) -> None:
    by = {}
    for d in every:
        if not d.coupled_from:
            by.setdefault(d.decision, []).append(d.id)
    for decision, ids in by.items():
        print(f"Signed {decision}: {', '.join(one_line(i) for i in ids)}")
    for c in every:
        if c.coupled_from:
            print(
                f"  cascade from {one_line(c.coupled_from)}: {c.decision} {one_line(c.id)}"
            )
    fp = keys.fingerprint(keys.unb64(public))
    print(f"{ledger.format_head(case_id, head)} | {examiner} {fp}")
    print(
        f"  Optional, to anchor later: --expect-head {head[0]}:{head[1]} --expect-key {examiner}={fp}"
    )
