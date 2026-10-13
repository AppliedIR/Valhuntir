"""An explicit reject wins over finding coupling.

Approving a finding approves the timeline event it names (its signed
`timeline_event_id`, auto-created from it). The coupling never looked at the
event's own status, so an event the examiner had rejected (earlier, or in
the same session or review) was approved and signed with the finding,
keeping its rejection fields. Coupling now approves only a DRAFT event, and
never one the examiner skipped; rejecting a finding still cascades. An event
that only claims the finding (`auto_created_from`) without the finding
naming it is never decided with it.

The real approve and reject commands run on a scratch case with an enrolled
examiner; `signed` reads what the ledger signed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import vhir_cli.commands.approve as A
import vhir_cli.commands.reject as RJ
from vhir_cli import ledger
from vhir_cli.case_io import compute_content_hash

from .signing import PASSPHRASE, enrol

IDENT = {"examiner": "steve", "os_user": "steve", "examiner_source": "test"}
NOW0 = "2026-10-03T07:00:00+00:00"


def _finding(fid, **links):
    f = {
        "id": fid,
        "type": "finding",
        "title": f"title {fid}",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "status": "DRAFT",
        "examiner": "steve",
        "created_by": "steve",
        "staged": NOW0,
        "modified_at": NOW0,
        "audit_ids": ["x-1"],
        **links,
    }
    f["content_hash"] = compute_content_hash(f)
    return f


def _event(tid, src):
    t = {
        "id": tid,
        "timestamp": NOW0,
        "description": f"ev {tid}",
        "event_type": "other",
        "related_findings": [src],
        "auto_created_from": src,
        "status": "DRAFT",
        "staged": NOW0,
        "modified_at": NOW0,
        "created_by": "steve",
        "examiner": "steve",
        "audit_ids": ["x-1"],
    }
    t["content_hash"] = compute_content_hash(t)
    return t


@pytest.fixture
def case(tmp_path, monkeypatch):
    """F (naming its auto event T1 and an IOC), an event T2 that claims F but
    that F doesn't name, and an unrelated finding X."""
    enrol("steve")
    monkeypatch.setattr(
        "vhir_cli.approval_auth.getpass_prompt", lambda p="": PASSPHRASE
    )
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-1\n")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))

    def make(**overrides):
        items = {
            "F": _finding(
                "F-steve-001", timeline_event_id="T-steve-001", iocs=["1.2.3.4"]
            ),
            "X": _finding("F-steve-002"),
            "T1": _event("T-steve-001", "F-steve-001"),
            "T2": _event("T-steve-002", "F-steve-001"),
        }
        for k, v in overrides.items():
            items[k].update(v)
        (d / "findings.json").write_text(json.dumps([items["F"], items["X"]]))
        (d / "timeline.json").write_text(json.dumps([items["T1"], items["T2"]]))
        ioc = {
            "id": "IOC-steve-001",
            "value": "1.2.3.4",
            "type": "ipv4-addr",
            "status": "DRAFT",
            "source_findings": ["F-steve-001"],
            "manually_reviewed": False,
            "confidence": "MEDIUM",
            "content_hash": "h",
        }
        (d / "iocs.json").write_text(json.dumps([ioc]))

    def run(fn, answers=None):
        if answers is not None:
            replies = iter(answers)

            def ask(prompt=""):
                try:
                    return next(replies)
                except StopIteration:
                    raise EOFError from None

            monkeypatch.setattr("builtins.input", ask)
        try:
            fn()
        except SystemExit:
            pass

    def approve(ids=None, review=False, answers=None):
        args = SimpleNamespace(
            ids=list(ids or []),
            review=review,
            case=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        run(lambda: A.cmd_approve(args, IDENT), answers)

    def reject(ids):
        args = SimpleNamespace(
            ids=list(ids), review=False, case=None, reason="explicit"
        )
        run(lambda: RJ.cmd_reject(args, IDENT))

    def delta(*entries):
        items = [{"type": "finding", "staged_by": "steve", **e} for e in entries]
        (d / "pending-reviews.json").write_text(
            json.dumps({"case_id": "C-1", "items": items})
        )

    def state():
        tl = {t["id"]: t for t in json.loads((d / "timeline.json").read_text())}
        fi = {f["id"]: f for f in json.loads((d / "findings.json").read_text())}
        p = d / "approvals.jsonl"
        log = (
            [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
            if p.exists()
            else []
        )
        return SimpleNamespace(
            F=fi["F-steve-001"]["status"],
            T1=tl["T-steve-001"]["status"],
            T2=tl["T-steve-002"]["status"],
            approved_log=lambda i: sum(
                1 for e in log if e["item_id"] == i and e["action"] == "APPROVED"
            ),
        )

    def signed(decision="approve"):
        """The ids the ledger signed with `decision`, from this point on."""
        lines = ledger.read_lines(ledger.chain_path("C-1"))
        return [
            o["item_id"]
            for _, _, o in lines[mark["n"] :]
            if o and o.get("decision") == decision
        ]

    mark = {"n": 0}

    def clear():
        mark["n"] = len(ledger.read_lines(ledger.chain_path("C-1")))

    return SimpleNamespace(
        make=make,
        approve=approve,
        reject=reject,
        delta=delta,
        state=state,
        signed=signed,
        clear=clear,
    )


# --- 1-3: a reject in the same session, call or review wins ----------------


def test_1_interactive_reject_then_approve_the_finding(case):
    """F approve, X skip, T1 reject, T2 skip."""
    case.make()
    case.approve(answers=["a", "s", "r", "uat said to", "s"])
    s = case.state()
    assert (s.F, s.T1) == ("APPROVED", "REJECTED")
    assert s.approved_log("T-steve-001") == 0
    assert "T-steve-001" not in case.signed() and case.signed("reject") == [
        "T-steve-001"
    ]
    assert s.T2 == "DRAFT"  # F doesn't name it


def test_2_specific_approve_leaves_an_earlier_reject(case):
    case.make()
    case.reject(["T-steve-001"])
    case.approve(["F-steve-001"])
    s = case.state()
    assert (s.F, s.T1, s.T2) == ("APPROVED", "REJECTED", "DRAFT")
    assert s.approved_log("T-steve-001") == 0 and "T-steve-001" not in case.signed()


def test_3_review_delta_rejecting_the_event_and_approving_the_finding(case):
    case.make()
    case.delta(
        {"id": "T-steve-001", "action": "reject", "rejection_reason": "no"},
        {"id": "F-steve-001", "action": "approve"},
    )
    case.approve(review=True)
    s = case.state()
    assert (s.F, s.T1) == ("APPROVED", "REJECTED")
    assert "T-steve-001" not in case.signed()


# --- A: an earlier reject survives a later, unrelated commit ----------------


def test_a_interactive_earlier_reject_survives(case):
    case.make()
    case.reject(["T-steve-001"])
    case.clear()
    case.approve(answers=["a", "s", "s"])  # F, X, T2
    s = case.state()
    assert (s.F, s.T1) == (
        "APPROVED",
        "REJECTED",
    ) and "T-steve-001" not in case.signed()


def test_a_review_stable_state_survives_an_unrelated_delta(case):
    case.make(
        F={"status": "APPROVED"},
        T1={"status": "REJECTED", "rejection_reason": "explicit"},
        T2={"status": "APPROVED"},
    )
    case.delta({"id": "F-steve-002", "action": "approve"})
    case.approve(review=True)
    s = case.state()
    assert (s.T1, s.T2) == ("REJECTED", "APPROVED")
    assert case.signed() == ["F-steve-002"]  # nothing else re-signed


# --- B: an event rejected after its finding was approved holds --------------


def test_b_review_reject_after_the_finding_was_approved(case):
    case.make()
    case.approve(["F-steve-001"])
    case.clear()
    case.delta(
        {
            "id": "T-steve-001",
            "action": "reject",
            "rejection_reason": "no",
            "type": "timeline",
        }
    )
    case.approve(review=True)
    s = case.state()
    assert (s.F, s.T1) == (
        "APPROVED",
        "REJECTED",
    ) and "T-steve-001" not in case.signed()


# --- C: an already APPROVED event is not re-approved or re-signed -----------


@pytest.mark.parametrize("mode", ["specific", "interactive"])
def test_c_an_approved_event_is_not_approved_again(case, mode):
    case.make()
    case.approve(["T-steve-001"])
    case.clear()
    if mode == "specific":
        case.approve(["F-steve-001"])
    else:
        case.approve(answers=["a", "s", "s"])  # F, X, T2
    s = case.state()
    assert (s.F, s.T1) == ("APPROVED", "APPROVED")
    assert s.approved_log("T-steve-001") == 1 and "T-steve-001" not in case.signed()


# --- D (anchor): rejecting a finding still cascades to its event ------------


def test_d_anchor_review_rejecting_the_finding_cascades(case):
    case.make(
        F={"status": "APPROVED"}, T1={"status": "APPROVED"}, T2={"status": "APPROVED"}
    )
    case.delta({"id": "F-steve-001", "action": "reject", "rejection_reason": "no"})
    case.approve(review=True)
    s = case.state()
    assert (s.F, s.T1, s.T2) == ("REJECTED", "REJECTED", "APPROVED")


def test_d_anchor_interactive_rejecting_the_finding_cascades(case):
    case.make()
    case.approve(answers=["r", "", "s", "q"])  # quit before T1 is decided
    s = case.state()
    assert (s.F, s.T1, s.T2) == ("REJECTED", "REJECTED", "DRAFT")


# --- Anchor: an untouched DRAFT event follows the finding that names it -----


@pytest.mark.parametrize("mode", ["specific", "review", "interactive"])
def test_anchor_untouched_events_follow_the_finding(case, mode):
    case.make()
    if mode == "specific":
        case.approve(["F-steve-001"])
    elif mode == "review":
        case.delta({"id": "F-steve-001", "action": "approve"})
        case.approve(review=True)
    else:
        case.approve(answers=["a", "s", "q"])  # quit before T1 and T2 are decided
    s = case.state()
    assert (s.F, s.T1, s.T2) == ("APPROVED", "APPROVED", "DRAFT")
    assert "T-steve-001" in case.signed()


def test_an_event_the_examiner_skipped_is_not_approved_with_its_finding(case):
    case.make()
    case.approve(answers=["a", "s", "s", "s"])  # F, X, T1 skipped, T2
    s = case.state()
    assert (s.F, s.T1) == ("APPROVED", "DRAFT") and "T-steve-001" not in case.signed()
