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

from vhir_cli import approval_auth, case_io, credentials, keys, ledger
from vhir_cli.case_io import (
    case_id_of,
    compute_content_hash,
    load_case_meta,
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
    # A direct approval's checks (approval_checks.check_item) and, when they
    # failed, the reason the examiner typed: both are signed
    checks: dict | None = None
    approval_override_reason: str | None = None

    @property
    def id(self) -> str:
        return self.item["id"]


def item_type(item_id: str) -> str:
    return case_io.id_kind(item_id)  # one rule, which import_bundle also enforces


def cascades(
    direct: list[Decision], findings, timeline, iocs, skipped=()
) -> list[Decision]:
    """The cascades of `direct`, planned from the post-edit items."""
    return split_cascades(direct, findings, timeline, iocs, skipped)[0]


def split_cascades(
    direct: list[Decision], findings, timeline, iocs, skipped=()
) -> tuple[list[Decision], list[tuple[str, str]]]:
    """The cascades of `direct`, and the timeline events held back from them:
    `(event id, finding id)` for each event linked to a finding edited here or
    in an earlier review.

    An event was made from its finding's text, so it would be signed with the
    text the edit replaced. It needs its own decision, and stays as it is until
    the examiner decides it."""
    edited = {d.id: d.item for d in direct}
    findings = [edited.get(f.get("id"), f) for f in findings if isinstance(f, dict)]
    decided = {
        d.id: d.status_after
        for d in direct
        if d.type == "finding" and d.decision in ("approve", "reject", "edit")
    }
    changed = {d.id for d in direct if d.type == "finding" and d.modifications}
    changed |= {f.get("id") for f in findings if f.get("examiner_modifications")}
    exclude = {d.id for d in direct} | set(skipped)
    planned, held = [], []
    for c in plan_cascades(decided, findings, timeline, iocs, exclude):
        if c["type"] == "timeline" and c["coupled_from"] in changed:
            held.append((c["item"]["id"], c["coupled_from"]))
            continue
        planned.append(
            Decision(c["item"], c["type"], "approve" if c["status_after"] == "APPROVED" else "reject",
                     c["status_after"], loaded=copy.deepcopy(c["item"]), coupled_from=c["coupled_from"])
        )  # fmt: skip
    return planned, held


def held_line(event_id: str, finding_id: str) -> str:
    """Why a linked event isn't signed, and what to do about it."""
    return (
        f"{one_line(event_id)} is linked to {one_line(finding_id)}, which was edited "
        f"after the event was made from it. It won't be signed. Decide it on its own: "
        f"vhir approve {one_line(event_id)}"
    )


def confirm_plan(
    direct: list[Decision],
    planned: list[Decision],
    display: Callable[[dict], None],
    lead: str = "",
    held: list[tuple[str, str]] = (),
) -> None:
    """Print every cascaded item, after the direct ones, then the linked
    events held back, `lead` and the ids to be signed, just above the prompt."""
    if planned:
        print(f"\n{len(planned)} item(s) decided with them:")
    for c in planned:
        display(c.item)
        print(f"  cascade from {one_line(c.coupled_from)}: {c.decision}")
    if held:
        print(f"\n{len(held)} linked item(s) not signed:")
    for event_id, finding_id in held:
        print(f"  {held_line(event_id, finding_id)}")
    ids = ", ".join(one_line(d.id) for d in direct + planned)
    if lead:
        print(lead)
    print(f"\nTo be signed: {ids}")


def _prompt_text(direct, planned, new_passphrase: bool) -> str:
    n, k = len(direct), len(planned)
    lead = "Your new passphrase" if new_passphrase else "Passphrase"
    return f"{lead} to sign {n + k} decisions ({n} direct, {k} cascaded): "


# --- Unsigned save ----------------------------------------------------------------------


def read_delta(path: Path) -> dict | None:
    """pending-reviews.json as an object; None when there is none. A file
    that doesn't read as an object with a list of items is set aside as
    `.corrupt-<UTC>`, unchanged, and reported; it is never overwritten."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict) and isinstance(data.get("items", []), list):
        return data
    aside = _set_aside(path, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    print(
        f"WARNING: {path.name} couldn't be read; it was set aside, unchanged, as "
        f"{aside.name}. Its staged entries are in that file.",
        file=sys.stderr,
    )
    return {}


def _set_aside(path: Path, stamp: str) -> Path:
    """Move `path` to `<name>.corrupt-<stamp>`, or `-<n>` after it when that
    name is taken: a copy set aside earlier is never replaced."""
    for n in range(10000):
        aside = path.with_name(f"{path.name}.corrupt-{stamp}" + (f"-{n}" if n else ""))
        try:
            os.link(path, aside)  # fails on an existing name, never replaces it
        except FileExistsError:
            continue
        except OSError:  # no hard links here: copy into a name made new
            try:
                fd = os.open(aside, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as f:
                f.write(path.read_bytes())
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        return aside
    raise OSError(f"no free name to set {path.name} aside")


def _write_delta(path: Path, delta: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(delta, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, str(path))


def save_unsigned(
    case_dir: Path, examiner: str, direct: list[Decision], why: str, todos=()
) -> tuple[list[str], list[str]]:
    """Save the decisions and TODOs to pending-reviews.json, unsigned and
    marked so, merged under the case lock: an entry of this examiner's for
    the same id is replaced, others are kept. An entry from the file that
    another examiner staged is left as it is. Returns (what couldn't be
    saved, the entries left as another examiner staged them)."""
    now = datetime.now(timezone.utc).isoformat()
    path = case_dir / "pending-reviews.json"
    not_saved: list[str] = []
    left: list[str] = []
    try:
        lock = ledger.case_lock(case_id_of(case_dir))
        lock.acquire()
    except ledger.LockDirMissing:
        lock = None  # nothing else can hold it either; save the work anyway
    try:
        delta = read_delta(path) or {}
        entries = [e for e in delta.get("items", []) if isinstance(e, dict)]
        for d in direct:
            if d.delta_entry is not None:  # from the file: stamp your own in place
                if d.delta_entry.get("staged_by") != examiner:
                    left.append(
                        f"{d.id}: left as staged by {d.delta_entry.get('staged_by') or 'unknown'}"
                    )
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
            entries = [  # a decision replaces only this examiner's decision for the id
                e
                for e in entries
                if not (
                    e.get("id") == d.id
                    and e.get("staged_by") == examiner
                    and e.get("action") != "todo"
                )
            ]
            entries.append(entry)
        for t in todos:  # a TODO the examiner asked for, created by --review
            related = (t.get("related_findings") or [""])[0]
            entries.append({
                "id": related, "type": item_type(related), "action": "todo",
                "todo_description": t.get("description", ""),
                "todo_priority": t.get("priority", "medium"),
                "todo_assignee": t.get("assignee", ""),
                "staged_by": examiner, "saved_unsigned": {"at": now, "reason": why},
            })  # fmt: skip
        delta["items"] = entries
        delta.setdefault("case_id", case_id_of(case_dir))
        delta["modified_at"] = now
        _write_delta(path, delta)
    finally:
        if lock is not None:
            lock.release()
    return not_saved, left


def _kept_unsigned(case_dir, examiner, direct, todos, why: str, lead: str, after: str):
    """Every exit after the review that signs nothing: the session's
    decisions and TODOs go to the unsigned save, with one message."""
    try:
        not_saved, left = save_unsigned(case_dir, examiner, direct, why, todos)
    except Exception as e:  # noqa: BLE001 - say what was lost, never a traceback
        print(
            f"{lead}\nNothing was signed, and your decisions couldn't be saved either "
            f"({type(e).__name__}: {one_line(str(e))}). Decide them again: "
            f"{', '.join(one_line(d.id) for d in direct)}",
            file=sys.stderr,
        )
        sys.exit(1)
    n = len(direct) + len(todos)
    print(
        f"{lead}\nNothing was signed. Your {n} decision(s) and TODO(s) were saved, "
        f"unsigned, to pending-reviews.json. Sign them with `vhir approve --review` {after}.",
        file=sys.stderr,
    )
    for x in not_saved:
        print(f"  not saved: {one_line(x)}", file=sys.stderr)
    for x in left:
        print(f"  {one_line(x)}", file=sys.stderr)
    sys.exit(1)


# --- Signing ------------------------------------------------------------------------------


INTERRUPTED = "Interrupted; nothing was signed"


def mint_identity(case_dir: Path) -> None:
    """Give a case with no identity (one upgraded from 0.6.4) its identity
    before its first signed line, as activation does, so the line binds this
    folder. Under the case lock. A refusal (a CASE.yaml whose identity was
    lost) is CaseCopy, with nothing signed."""
    from vhir_cli.case_identity import ensure_identity

    try:
        ensure_identity(case_dir, naming_version=1)
    except ValueError as e:
        raise ledger.CaseCopy(str(e)) from None


def record_folder(case_dir: Path) -> None:
    """Record this folder as its case identity's folder on this box, as
    activation does (`record_case_path`); the first folder to sign is taken as
    the original. Called under the case lock just before a commit, so a
    preview or a cancelled review records nothing. A folder another one
    holds the identity for, or a record that can't be read: CaseCopy."""
    from vhir_cli.case_identity import copy_of, record_case_path

    refusal = copy_of(case_dir)  # the signing wording, with the way back
    if refusal:
        raise ledger.CaseCopy(refusal)
    try:
        record_case_path(case_dir)
    except ValueError as e:  # a copy recorded in between
        raise ledger.CaseCopy(str(e)) from None
    except OSError as e:
        raise ledger.CaseRecordUnwritable(
            f"This box's record of case folders couldn't be written ({e}); "
            "nothing was signed."
        ) from None


def copy_problem(case_dir: Path) -> str:
    """Why this case folder can't sign (it's a copy of a case whose chain on
    this box began in another folder), or "". Read-only: checked before any
    item is shown; the commit checks again under the lock."""
    from vhir_cli.case_identity import copy_of, recorded_folder

    case_id = case_id_of(case_dir)
    own = load_case_meta(case_dir).get("case_uuid")
    problem = ledger.copy_problem(case_id, own)
    if problem and not own and problem != ledger.CHAIN_UNREADABLE:
        # an upgraded case: name the folder that signed first
        try:
            bound = ledger.bound_uuid(ledger.read_lines(ledger.chain_path(case_id)))
        except (OSError, ValueError):
            return ledger.CHAIN_UNREADABLE
        problem = ledger.first_signed_text(case_id, recorded_folder(bound))
    return problem or copy_of(case_dir)


def _find(lists: dict[str, list[dict]], kind: str, item_id: str) -> dict | None:
    return next(
        (x for x in lists[kind] if isinstance(x, dict) and x.get("id") == item_id), None
    )


def _reload(case_dir: Path) -> tuple[dict[str, list[dict]], list[str]]:
    """The case files as they are now, and the names of any that exist but
    don't read as a list (a commit never goes ahead on, or saves over, them).
    A 0-byte or blank file reads as [] (verify still names an approved item
    it no longer holds, through the chain)."""
    lists: dict[str, list[dict]] = {}
    bad: list[str] = []
    for kind, name in (
        ("finding", "findings.json"),
        ("timeline", "timeline.json"),
        ("ioc", "iocs.json"),
    ):
        path = case_dir / name
        try:
            text = path.read_text() if path.exists() else ""
            data = json.loads(text) if text.strip() else []
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
    inside_lock: Callable[[dict[str, list[dict]], list[Decision]], None] | None = None,
    todos: list[dict] | tuple = (),
    make_todos: Callable[[list[dict]], None] | None = None,
) -> None:
    """Sign `direct` and `planned` (cascades) and apply them. `todos`: the
    TODOs the examiner asked for in this session, created by `make_todos`
    once the commit has run, or saved with the decisions when it can't.
    Every exit after the review keeps the examiner's work."""
    examiner = identity["examiner"]
    prompt = _prompt_text(direct, planned, new_passphrase)
    todos = list(todos)

    def keep(why: str, lead: str, after: str = "once the problem above is fixed",
             which=None):  # fmt: skip
        _kept_unsigned(case_dir, examiner, direct if which is None else which, todos,
                       why, lead, after)  # fmt: skip

    try:
        private, public = credentials.unlock(examiner, prompt)
    except KeyboardInterrupt:  # the examiner chose to stop (at the prompt, or deriving)
        print(f"\n{INTERRUPTED}", file=sys.stderr)
        sys.exit(130)
    except keys.KeyUnwrapFailed:
        keep("KEY_UNWRAP_FAILED", keys.KeyUnwrapFailed.MESSAGE,
             "after `vhir config --forgot-password`")  # fmt: skip
    except credentials.AttemptsExhausted:
        keep("attempts", "No attempts are left.", "after the lockout ends")
    except approval_auth.NoTerminal:  # no examiner here (an AI's run): nothing saved
        refused = direct + planned
        action = "reject" if all(d.decision == "reject" for d in refused) else "approve"
        case_io.record_no_terminal(case_dir, examiner, action, [d.id for d in refused])
        print(case_io.NO_TERMINAL_REFUSAL, file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # noqa: BLE001 - a keys file damaged, …
        keep(
            type(e).__name__,
            f"The passphrase prompt couldn't go ahead: {one_line(str(e))}",
        )

    from vhir_cli.ledger_verify import chain_references

    case_id = case_id_of(case_dir)
    head, every, items, discarded = None, [], [], []
    refs, ref_notes = [], []
    unreadable: list[str] = []
    committed, save_error = False, None
    try:
        with ledger.case_lock(
            case_id,
            on_wait=lambda: print(
                "Waiting for another writer to finish...", file=sys.stderr
            ),
        ) as lock:
            lists, unreadable = _reload(case_dir)
            if not unreadable:
                every, discarded = _still_as_shown(
                    lists, direct, planned, skipped, case_dir
                )
            if every:
                at = datetime.now(timezone.utc).isoformat()
                items = [_find(lists, d.type, d.id) for d in every]
                decisions = [
                    {"item_id": d.id, "type": d.type, "decision": d.decision,
                     "status_after": d.status_after, "coupled_from": d.coupled_from,
                     "content_snapshot": signed_text(item, d.type),
                     **({"checks": d.checks} if d.checks is not None else {}),
                     **({"approval_override_reason": d.approval_override_reason}
                        if d.approval_override_reason is not None else {})}
                    for d, item in zip(every, items, strict=True)
                ]  # fmt: skip
                refs, ref_notes = chain_references(case_dir, case_id)
                mint_identity(case_dir)  # so the chain's first line binds this folder
                bodies = ledger.prepare(
                    case_id, decisions, examiner, public, mode, at,
                    retired=credentials.retired_fingerprints(examiner),
                    prior_chains=refs or None,
                    case_uuid=load_case_meta(case_dir).get("case_uuid"),
                )  # fmt: skip
                lines = [ledger.sign_body(b, private) for b in bodies]
                head = ledger.commit(  # all or nothing
                    lock, bodies, lines, public,
                    before_write=lambda: record_folder(case_dir),  # once they verify
                )  # fmt: skip
                committed = True
                for d, item, body in zip(every, items, bodies, strict=True):
                    set_status(item, d.decision, d.status_after, body["examiner"],
                               body["at"], reason=d.reason,
                               fresh_approver=d.fresh_approver)  # fmt: skip
                save_error = _save_twice(case_dir, lists, {d.type for d in every})
            if inside_lock is not None and not unreadable and save_error is None:
                inside_lock(lists, every)  # `every`: exactly the decisions signed
    except SystemExit:
        raise
    except KeyboardInterrupt:  # an interrupted append is cut back: nothing signed
        if not committed:
            print(f"\n{INTERRUPTED}", file=sys.stderr)
            sys.exit(130)
        print(
            "\nInterrupted after the decisions were signed; case data may not be "
            f"saved. Re-run the same command for: {', '.join(one_line(d.id) for d in every)}",
            file=sys.stderr,
        )
        sys.exit(130)
    except Exception as e:  # noqa: BLE001 - never a traceback that loses the work
        if isinstance(e, ledger.LedgerTorn):
            # part of the write may be in the chain: stage nothing new, only
            # mark the review entries and keep the TODOs
            marked = [d for d in direct if d.delta_entry]
            try:
                if marked or todos:
                    save_unsigned(case_dir, examiner, marked, "LEDGER_TORN", todos)
            except Exception as saving:  # noqa: BLE001 - said, never silent
                print(
                    f"Your review entries and TODOs couldn't be saved ({one_line(str(saving))}).",
                    file=sys.stderr,
                )
                for t in todos:
                    print(
                        f"  Enter this TODO again: {one_line(t.get('description', ''))} "
                        f"({one_line(', '.join(t.get('related_findings') or []))})",
                        file=sys.stderr,
                    )
            print(
                f"{one_line(str(e))}\nSome of these decisions may already be signed. "
                "`vhir review --verify` lists each one as a failure, with its fix. If it "
                "reports UNPARSEABLE_LINE on the last line, restore the chain from a copy first.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not committed:  # the commit wrote nothing: keep every decision
            keep(type(e).__name__, f"The commit couldn't go ahead: {one_line(str(e))}")
        save_error = save_error or e

    if unreadable:  # no per-item judgement is possible: keep every decision
        keep(
            "case file unreadable",
            f"\n{'!' * 60}\n{', '.join(unreadable)} couldn't be read as case data. "
            f"The file was left as it is.\n{'!' * 60}",
            "once the file is repaired; it signs those whose content still matches what you saw",
        )
    todo_error = None
    if todos and make_todos is not None:
        try:
            make_todos(todos)
        except Exception as e:  # noqa: BLE001 - the TODOs are kept, below
            todo_error = e
    for line in discarded:
        print(line, file=sys.stderr)
    if every:
        _activity_log(case_dir, identity, every, items, mode)
        _report(case_id, every, head, examiner, public)
        for r in refs:
            print(
                f"  This approval references chain {r['chain_id']} "
                f"(head seq {r['head_seq']} sha256:{r['head_hash']})"
            )
        for note in ref_notes:
            print(f"  WARNING: {one_line(note)}", file=sys.stderr)
    if todo_error is not None:
        try:
            save_unsigned(case_dir, examiner, [], "TODO not written", todos)
            kept = "they were saved to pending-reviews.json; `vhir approve --review` creates them"
        except Exception as e:  # noqa: BLE001
            kept = f"they couldn't be saved either ({one_line(str(e))}); add them again"
        print(
            f"Your TODOs weren't created ({one_line(str(todo_error))}); {kept}."
            + (" The signed decisions stand." if every else ""),
            file=sys.stderr,
        )
    if save_error is not None:
        print(
            f"Signed decisions were recorded; case data was not saved ({one_line(str(save_error))}); "
            f"re-run the same command for: {', '.join(one_line(d.id) for d in every)}",
            file=sys.stderr,
        )
        sys.exit(1)
    if todo_error is not None:
        sys.exit(1)
    if discarded:
        print(
            f"{len(discarded)} decision(s) were discarded, as listed above"
            + ("; the others were signed." if every else "; nothing was signed."),
            file=sys.stderr,
        )
        sys.exit(1)


def _save_twice(case_dir: Path, lists, touched) -> Exception | None:
    """Save the touched case files, retrying once; the error if both fail."""
    error = None
    for _ in (1, 2):
        try:
            if "finding" in touched:
                save_findings(case_dir, lists["finding"])
            if "timeline" in touched:
                save_timeline(case_dir, lists["timeline"])
            if "ioc" in touched:
                save_iocs(case_dir, lists["ioc"])
            return None
        except OSError as e:
            error = e
    return error


def _spliced(current: dict, d: Decision) -> dict:
    """The reloaded record with only this decision on it: the signed view's
    fields as the examiner left them (an edit included; they equal the
    reloaded ones otherwise), the edit and note bookkeeping, and every other
    field as it is now (provenance, an IOC's sightings, notes added since).
    The status and approval fields are set from the signed body after."""
    out = copy.deepcopy(current)
    body = json.loads(signed_text(d.item, d.type))
    for k in body:
        if k in d.item:
            out[k] = copy.deepcopy(d.item[k])
    for k in ("examiner_modifications", "manually_reviewed"):
        if k in d.item and k not in body:
            out[k] = copy.deepcopy(d.item[k])
    if "examiner_notes" not in body:
        before = d.loaded.get("examiner_notes") or []
        mine = [n for n in d.item.get("examiner_notes") or [] if n not in before]
        if mine:
            out["examiner_notes"] = list(out.get("examiner_notes") or []) + mine
    return out


def _checks_as_shown(case_dir, d: Decision, item: dict, trail=None) -> bool:
    """A direct decision's approval checks, run again on `item`, give the
    result and failed checks it was shown with (none were run: True). An audit
    log they can't read raises approval_checks.AuditUnreadable."""
    if d.checks is None or case_dir is None:
        return True
    from vhir_cli import approval_checks

    now = approval_checks.check_item(case_dir, item, d.type, trail=trail)
    return (now["result"], approval_checks.failed_items(now)) == (
        d.checks["result"],
        approval_checks.failed_items(d.checks),
    )


def _still_as_shown(lists, direct, planned, skipped, case_dir=None):
    """Per item, under the lock: the decisions to sign (each direct one whose
    item is unchanged since it was shown, and whose approval checks give what
    was shown, with its edit spliced in; each cascade that was shown and
    still holds), and a loud line for each one discarded. A cascade that only
    now appears wasn't shown, so it isn't signed."""
    discarded, kept = [], []
    trail = None
    if case_dir is not None:  # the trail read once for every item's checks
        from vhir_cli import approval_checks

        trail = approval_checks.PlanTrail(case_dir, [
            (x, d.type) for d in direct
            if d.checks is not None and isinstance(x := _find(lists, d.type, d.id), dict)])  # fmt: skip
    for d in direct:
        if _changed(d, _find(lists, d.type, d.id)):
            discarded.append(
                f"  DISCARDED: {one_line(d.id)} was changed or deleted after you saw it; "
                f"your {d.decision} decision on it was not signed or saved. Review it again."
            )
            continue
        lst = lists[d.type]
        at = next(
            i for i, x in enumerate(lst) if isinstance(x, dict) and x.get("id") == d.id
        )
        spliced = _spliced(lst[at], d)
        if not _checks_as_shown(case_dir, d, spliced, trail):
            discarded.append(
                f"  DISCARDED: {one_line(d.id)}: its approval checks changed after you saw "
                f"them; your {d.decision} decision on it was not signed or saved. "
                "Review it again."
            )
            continue
        kept.append(d)
        lst[at] = spliced
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
            f"{', '.join(map(one_line, failed))}. The signed decisions stand.",
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
    print(f"{ledger.format_head(one_line(case_id), head)} | {examiner} {fp}")
    print(
        f"  Optional, to anchor later: --expect-head {head[0]}:{head[1]} --expect-key {examiner}={fp}"
    )
