# ruff: noqa: F811 - `case` is the fixture imported below
"""An IOC's cascaded status follows the findings citing it: APPROVED when at
least one is approved, REJECTED when every one is rejected or none is left
approved, and otherwise as it is. A move is signed with a finding decided in
the same commit at that status; with none, the plan names the IOC, its status,
each citing finding and the commands that decide it directly."""

from __future__ import annotations

import copy
import json
import pickle

import pytest

from vhir_cli import decide
from vhir_cli.case_io import plan_cascades, undecided_iocs
from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import verify_case

from .test_signed_decisions import IDENT, _signed, _status, case  # noqa: F401

RULE = (
    "An IOC is approved when any finding citing it is approved, rejected when none is."
)
ROUTE = "Decide it now: vhir approve IOC-steve-001 or vhir reject IOC-steve-001"


def _f(fid, status="DRAFT", iocs=("10.0.0.7",)):
    return {"id": fid, "status": status, "iocs": list(iocs)}


def _ioc(iid="IOC-steve-001", value="10.0.0.7", status="DRAFT", **kw):
    return {"id": iid, "value": value, "status": status, **kw}


def _plan(before, ioc, decisions, manual=False):
    """`before`: each citing finding's status; `decisions`: (id, status
    after) in the order this commit decides them."""
    findings = [_f(fid, s) for fid, s in before.items()]
    by_id = {f["id"]: f for f in findings}
    direct = [
        decide.Decision(by_id[fid], "finding", "approve" if a == "APPROVED" else "reject", a)
        for fid, a in decisions
    ]  # fmt: skip
    iocs = [_ioc(status=ioc, manually_reviewed=manual)]
    return decide.split_cascades(direct, findings, [], iocs)


A1, R1 = ("F-steve-001", "APPROVED"), ("F-steve-001", "REJECTED")
A2, R2 = ("F-steve-002", "APPROVED"), ("F-steve-002", "REJECTED")
R3 = ("F-steve-003", "REJECTED")
D2 = {"F-steve-001": "DRAFT", "F-steve-002": "DRAFT"}


def _two(s1, s2, s3=None):
    out = {"F-steve-001": s1, "F-steve-002": s2}
    return out if s3 is None else {**out, "F-steve-003": s3}


# before, the IOC's status, this commit's decisions in order, manually
# reviewed, then the outcome: ("cascade", status, source), ("held", status
# now, the rule's status) or None
ROWS = {
    "one-rejected-then-the-other-approved": (_two("REJECTED", "DRAFT"), "DRAFT", [A2], False, ("cascade", "APPROVED", "F-steve-002")),
    "first-of-two-approved": (D2, "DRAFT", [A1], False, ("cascade", "APPROVED", "F-steve-001")),
    "first-rejected-other-draft": (D2, "DRAFT", [R1], False, ("held", "DRAFT", "DRAFT")),
    "both-rejected-in-one-commit": (D2, "DRAFT", [R2, R1], False, ("cascade", "REJECTED", "F-steve-001")),
    "both-approved-in-one-commit": (D2, "DRAFT", [A1, A2], False, ("cascade", "APPROVED", "F-steve-001")),
    "mixed-reject-first": (D2, "DRAFT", [R1, A2], False, ("cascade", "APPROVED", "F-steve-002")),
    "mixed-approve-first": (D2, "DRAFT", [A2, R1], False, ("cascade", "APPROVED", "F-steve-002")),
    "approved-other-still-draft-rejected": (_two("DRAFT", "APPROVED"), "APPROVED", [R1], False, None),
    "approved-second-citer-approved": (_two("APPROVED", "DRAFT"), "APPROVED", [A2], False, None),
    "approved-last-approved-rejected": (_two("REJECTED", "APPROVED"), "APPROVED", [R2], False, ("cascade", "REJECTED", "F-steve-002")),
    "approved-only-approved-rejected-other-draft": (_two("APPROVED", "DRAFT"), "APPROVED", [R1], False, ("cascade", "REJECTED", "F-steve-001")),
    "rejected-new-citer-approved": (_two("REJECTED", "DRAFT"), "REJECTED", [A2], False, ("cascade", "APPROVED", "F-steve-002")),
    "rejected-new-citer-rejected": (_two("REJECTED", "DRAFT"), "REJECTED", [R2], False, None),
    "no-coupling-rejected-with-approved-citer": (_two("REJECTED", "APPROVED", "DRAFT"), "REJECTED", [R3], False, ("held", "REJECTED", "APPROVED")),
    "no-coupling-draft-with-approved-citer": (_two("REJECTED", "APPROVED", "DRAFT"), "DRAFT", [R3], False, ("held", "DRAFT", "APPROVED")),
    "manual-rejected-citer-approved": (_two("REJECTED", "DRAFT"), "REJECTED", [A2], True, None),
    "manual-approved-every-citer-rejected": (_two("REJECTED", "APPROVED"), "APPROVED", [R2], True, None),
    "manual-draft-mixed": (D2, "DRAFT", [R1, A2], True, None),
}  # fmt: skip


@pytest.mark.parametrize(
    "before, ioc, decisions, manual, outcome", ROWS.values(), ids=ROWS.keys()
)
def test_the_rule(before, ioc, decisions, manual, outcome):
    planned, held = _plan(before, ioc, decisions, manual)
    got = [("cascade", c.status_after, c.coupled_from) for c in planned]
    got += [("held", h.status, h.target) for h in held]
    assert got == ([outcome] if outcome else [])
    for c in planned:  # a cascade's source is decided here at its status
        assert (c.coupled_from, c.status_after) in decisions
    for h in held:
        assert h.id == "IOC-steve-001" and h.citing == tuple(
            (fid, dict(decisions).get(fid, s)) for fid, s in sorted(before.items())
        )


def test_three_citing_findings_are_named_in_id_order():
    findings = [_f("F-steve-003", "REJECTED"), _f("F-steve-001"), _f("F-steve-002")]
    direct = [decide.Decision(findings[2], "finding", "reject", "REJECTED")]
    planned, held = decide.split_cascades(direct, findings, [], [_ioc()])
    assert planned == []
    (h,) = held
    assert (h.id, h.coupled_from, h.status, h.target) == (
        "IOC-steve-001", "F-steve-002", "DRAFT", "DRAFT",
    )  # fmt: skip
    assert h.citing == (
        ("F-steve-001", "DRAFT"), ("F-steve-002", "REJECTED"), ("F-steve-003", "REJECTED"),
    )  # fmt: skip
    assert decide.held_line(h.id, h.coupled_from, h.citing, h.status, h.target) == (
        "IOC-steve-001 stays DRAFT: cited by F-steve-001 (DRAFT), F-steve-002 "
        f"(REJECTED) and F-steve-003 (REJECTED). {RULE} {ROUTE}"
    )


def test_a_move_no_finding_here_can_sign_names_the_status_the_rule_gives():
    citing = (("F-steve-001", "REJECTED"), ("F-steve-002", "APPROVED"))
    assert decide.held_line("IOC-steve-001", "F-steve-001", citing, "REJECTED", "APPROVED") == (
        "IOC-steve-001 stays REJECTED (the rule gives APPROVED; no finding decided here "
        "has that status to sign it with): cited by F-steve-001 (REJECTED) and "
        f"F-steve-002 (APPROVED). {RULE} {ROUTE}"
    )  # fmt: skip


def test_ids_in_the_line_are_printed_on_one_line():
    line = decide.held_line(
        "IOC-x\nforged", "F-1", (("F-1", "APPROVED"), ("F-2\r\nx", "DRAFT")),
        "REJECTED\n", "APPROVED\r",
    )  # fmt: skip
    assert "\n" not in line and "\r" not in line


@pytest.mark.parametrize(
    "ioc",
    [
        _ioc(status="APPROVED"),
        _ioc(manually_reviewed=True),
        _ioc(value="10.0.0.8"),
        _ioc(status="ODD"),
        "not a record",
    ],
    ids=["already-where-the-rule-puts-it", "manually-reviewed", "not-cited", "unknown-status", "not-a-record"],
)  # fmt: skip
def test_iocs_the_rule_leaves_alone_are_not_named(ioc):
    findings = [_f("F-steve-001"), _f("F-steve-002", "REJECTED")]
    decided = {"F-steve-001": "APPROVED"}
    assert undecided_iocs(decided, findings, [ioc]) == []
    assert plan_cascades(decided, findings, [], [ioc]) == []


def test_an_ioc_decided_directly_is_not_named():
    findings = [_f("F-steve-001"), _f("F-steve-002")]
    decided = {"F-steve-001": "REJECTED"}
    assert undecided_iocs(decided, findings, [_ioc()], {"IOC-steve-001"}) == []
    # twin: not excluded, it is named
    (u,) = undecided_iocs(decided, findings, [_ioc()])
    assert (u["coupled_from"], u["status"], u["target"]) == (
        "F-steve-001",
        "DRAFT",
        "DRAFT",
    )
    assert u["citing"] == [("F-steve-001", "REJECTED"), ("F-steve-002", "DRAFT")]


def test_an_edit_that_leaves_the_finding_draft_names_nothing():
    findings = [_f("F-steve-001"), _f("F-steve-002", "REJECTED")]
    assert undecided_iocs({"F-steve-001": "DRAFT"}, findings, [_ioc()]) == []


def test_a_held_item_unpacks_as_its_id_and_finding_and_copies_whole():
    h = decide.Held(
        "IOC-steve-001",
        "F-steve-001",
        [("F-steve-001", "APPROVED")],
        "REJECTED",
        "APPROVED",
    )
    item_id, finding_id = h
    assert (item_id, finding_id) == ("IOC-steve-001", "F-steve-001")
    for c in (copy.deepcopy(h), pickle.loads(pickle.dumps(h))):
        assert tuple(c) == tuple(h) and c.citing == h.citing
        assert (c.status, c.target) == ("REJECTED", "APPROVED")
    event = decide.Held("T-steve-001", "F-steve-001")
    assert (event.citing, event.status, event.target) == ((), "", "")


# --- In the CLI -------------------------------------------------------------------


def _second_cites(case, status):
    """F-steve-002 cites the IOC too, at `status`."""
    findings = json.loads((case / "findings.json").read_text())
    findings[1].update(status=status, iocs=["10.0.0.7"])
    (case / "findings.json").write_text(json.dumps(findings))


@pytest.mark.parametrize("other", ["REJECTED", "DRAFT"])
def test_approving_one_citing_finding_approves_the_ioc_whatever_the_other(
    case, capsys, other
):
    _second_cites(case, other)
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    out = capsys.readouterr().out
    assert "linked item(s) not signed" not in out
    assert "To be signed: F-steve-001, T-steve-001, IOC-steve-001" in out
    assert ("IOC-steve-001", "approve") in _signed()
    assert _status(case, "iocs.json", "IOC-steve-001") == "APPROVED"
    assert verify_case(case).exit_code == 0


@pytest.mark.parametrize("command", ["approve", "reject"])
def test_each_command_the_held_line_names_decides_the_ioc(case, capsys, command):
    _second_cites(case, "DRAFT")
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg", decision="reject")
    out = capsys.readouterr().out
    line = (
        f"  IOC-steve-001 stays DRAFT: cited by F-steve-001 (REJECTED) and "
        f"F-steve-002 (DRAFT). {RULE} {ROUTE}"
    )
    assert line in out.splitlines()
    assert _status(case, "iocs.json", "IOC-steve-001") == "DRAFT"
    named = line.split("Decide it now: ", 1)[1].split(" or ")
    words = next(c for c in named if c.split()[1] == command).split()
    A._approve_specific(case, words[2:], IDENT, case / "cfg", decision=command)
    after = {"approve": "APPROVED", "reject": "REJECTED"}[command]
    assert _status(case, "iocs.json", "IOC-steve-001") == after
    assert ("IOC-steve-001", command) in _signed()
    assert verify_case(case).exit_code == 0
