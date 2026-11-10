# ruff: noqa: F811 - `case` is the fixture imported below
"""The IOC rule as the examiner meets it: two findings cite 10.0.0.7, each is
decided with `vhir approve` or `vhir reject`, the IOC report reads the result,
and `vhir review --findings --verify` passes after every step."""

from __future__ import annotations

import json
import sys

import pytest

from vhir_cli import approval_auth, case_io, ledger
from vhir_cli.commands import approve as A

from .test_signed_decisions import IDENT, PASSPHRASE, _status, case  # noqa: F401

F1, F2, F3, IOC = "F-steve-001", "F-steve-002", "F-steve-003", "IOC-steve-001"
ROUTE = f"vhir approve {IOC} or vhir reject {IOC}"


@pytest.fixture
def two(case, monkeypatch):
    """F-steve-002 cites the IOC too."""
    monkeypatch.setenv("VHIR_EXAMINER", "steve")
    findings = json.loads((case / "findings.json").read_text())
    findings[1]["iocs"] = ["10.0.0.7"]
    (case / "findings.json").write_text(json.dumps(findings))
    iocs = json.loads((case / "iocs.json").read_text())
    iocs[0]["source_findings"] = [F1, F2]
    (case / "iocs.json").write_text(json.dumps(iocs))
    return case


def _vhir(monkeypatch, capsys, *argv, replies=()):
    """Run the CLI; `replies` answer its prompts in order."""
    from vhir_cli.main import main

    queue = list(replies)
    monkeypatch.setattr("builtins.input", lambda p="": queue.pop(0) if queue else "")
    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code or 0
    out = capsys.readouterr()
    return code, out.out, out.err


def _ok(monkeypatch, capsys, *argv, replies=()):
    code, out, err = _vhir(monkeypatch, capsys, *argv, replies=replies)
    assert code == 0, out + err
    _verified(monkeypatch, capsys)
    return out, err


def _verified(monkeypatch, capsys):
    code, out, err = _vhir(monkeypatch, capsys, "review", "--findings", "--verify")
    assert code == 0 and "CASCADE_UNSUPPORTED" not in out + err, out + err


def _ioc_lines():
    """The IOC's signed lines: (decision, status after, coupled from)."""
    return [
        (o["decision"], o["status_after"], o.get("coupled_from"))
        for _, _, o in ledger.read_lines(ledger.chain_path("C-9"))
        if o and o["item_id"] == IOC
    ]


def _reported(monkeypatch, capsys):
    code, out, err = _vhir(monkeypatch, capsys, "report", "--ioc")
    assert code == 0, out + err
    # 10.0.0.7 is private, so it is listed in the non-routable section: it
    # counts as reported wherever it is listed
    listed = "10.0.0.7" in out
    if listed:
        assert "Total: 1 IOC records" in out or "Non-routable addresses (1)" in out, out
    else:
        assert "Total: 0 IOC records" in out, out
    return listed


def _ioc(case):
    return {i["id"]: i for i in case_io.load_iocs(case)}[IOC]


def _cite(case, fid):
    """`fid` is recorded, or re-recorded, citing the IOC's value."""
    findings = case_io.load_findings(case)
    old = next((f for f in findings if f["id"] == fid), None)
    if old is None:
        findings.append({"id": fid, "title": "Third", "observation": "o", "interpretation": "i",
                         "confidence": "LOW", "status": "DRAFT", "iocs": ["10.0.0.7"]})  # fmt: skip
    else:
        old["iocs"] = ["10.0.0.7"]
    case_io.save_findings(case, findings)


@pytest.fixture
def one(case, monkeypatch):
    """Only F-steve-001 cites the IOC."""
    monkeypatch.setenv("VHIR_EXAMINER", "steve")
    return case


def run(*argv, replies=()):
    return ("run", argv, replies)


def older(*argv):
    """Run as the rule before this one left a case: no IOC moves."""
    return ("older", argv, ())


def cite(fid):
    return ("cite", fid)


WHY = ("--reason", "duplicate")
HELD_LEGACY = (
    f"  {IOC} stays REJECTED (the rule gives APPROVED; no finding decided here has "
    f"that status to sign it with): cited by {F1} (REJECTED), {F2} (APPROVED) and "
    f"{F3} (REJECTED). An IOC is approved when any finding citing it is approved. "
    "An approved IOC is rejected as soon as no finding citing it is approved; any "
    f"other IOC is rejected when every finding citing it is rejected. Decide it now: {ROUTE}"
)

# who cites at the start, each step with the IOC's status after it, the IOC's
# signed lines (decision, status, coupled from), whether `vhir report --ioc`
# lists it (None: not asked), and a line the steps print
ROWS = {
    "one-rejected-then-the-other-approved": ("two", [(run("reject", F1, *WHY), "DRAFT"), (run("approve", F2), "APPROVED")], [("approve", "APPROVED", F2)], True, None),
    "both-approved": ("two", [(run("approve", F1, F2), "APPROVED")], [("approve", "APPROVED", F1)], True, None),
    "every-citer-rejected": ("two", [(run("approve", F1), "APPROVED"), (run("reject", F2, *WHY), "APPROVED"), (run("reject", F1, *WHY), "REJECTED")], [("approve", "APPROVED", F1), ("reject", "REJECTED", F1)], False, None),
    "approved-while-the-other-is-draft": ("two", [(run("approve", F2), "APPROVED"), (run("reject", F1, *WHY), "APPROVED")], [("approve", "APPROVED", F2)], True, None),
    "rejected-then-cited-by-an-approved-finding": ("one", [(run("reject", F1, *WHY), "REJECTED"), (cite(F2), "REJECTED"), (run("approve", F2), "APPROVED")], [("reject", "REJECTED", F1), ("approve", "APPROVED", F2)], True, f"To be signed: {F2}, {IOC}"),
    # one review: F-steve-001 rejected, F-steve-002 approved, then stop at the event
    "one-review-rejects-one-approves-the-other": ("two", [(run("approve", replies=["r", "", "a", "q"]), "APPROVED")], [("approve", "APPROVED", F2)], True, None),
    "legacy-rejected-with-an-approved-citer": ("one", [(run("reject", F1, *WHY), "REJECTED"), (cite(F2), "REJECTED"), (older("approve", F2), "REJECTED"), (cite(F3), "REJECTED"), (run("reject", F3, *WHY), "REJECTED")], [("reject", "REJECTED", F1)], None, HELD_LEGACY),
    "manually-approved-then-every-citer-rejected": ("two", [(run("approve", IOC), "APPROVED"), (run("reject", F1, F2, *WHY), "APPROVED")], [("approve", "APPROVED", None)], None, None),
    "approve-a-held-ioc": ("two", [(run("reject", F1, *WHY), "DRAFT"), (run("approve", IOC), "APPROVED")], [("approve", "APPROVED", None)], None, ROUTE),
    "approve-a-cascade-rejected-ioc": ("two", [(run("reject", F1, F2, *WHY), "REJECTED"), (run("approve", IOC), "APPROVED")], [("reject", "REJECTED", F1), ("approve", "APPROVED", None)], None, None),
    "approve-a-manually-rejected-ioc": ("two", [(run("reject", IOC, *WHY), "REJECTED"), (run("approve", IOC), "APPROVED")], [("reject", "REJECTED", None), ("approve", "APPROVED", None)], None, None),
}  # fmt: skip


@pytest.mark.parametrize(
    "start, steps, signed, reported, says", ROWS.values(), ids=ROWS.keys()
)
def test_each_step_through_the_cli(
    request, monkeypatch, capsys, start, steps, signed, reported, says
):
    case = request.getfixturevalue(start)
    said = ""
    for (kind, *what), status in steps:
        if kind == "cite":
            _cite(case, *what)
        else:
            with monkeypatch.context() as m:
                if kind == "older":
                    m.setattr(case_io, "_ioc_outcomes", lambda *a: iter(()))
                said += "".join(_ok(monkeypatch, capsys, *what[0], replies=what[1]))
        assert _status(case, "iocs.json", IOC) == status
    assert _ioc_lines() == signed
    # a direct decision, signed with no finding, takes it out of later cascades
    assert _ioc(case)["manually_reviewed"] is (signed[-1][2] is None)
    if reported is not None:
        assert _reported(monkeypatch, capsys) is reported
    assert says is None or says in said


@pytest.mark.parametrize(
    "item_id, why", [(IOC, "already APPROVED"), ("IOC-steve-404", "no such IOC")]
)
def test_approve_refuses_an_approved_or_unknown_ioc_with_its_reason_only(
    two, monkeypatch, capsys, item_id, why
):
    _ok(monkeypatch, capsys, "approve", F1)
    signed = _ioc_lines()
    code, out, err = _vhir(monkeypatch, capsys, "approve", item_id)
    assert code == 0
    assert (out + err).strip() == f"{item_id}: {why}"
    assert _ioc_lines() == signed


def _files(root):
    return {p: p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


REFUSED = {
    "interpretation": ([IOC], ("--interpretation", "x")),
    "note": ([IOC], ("--note", "x")),
    "edit": ([IOC], ("--edit",)),
    # a finding named with the IOC, before or after it, is not decided either
    "finding-first-note": ([F1, IOC], ("--note", "x")),
    "ioc-first-note": ([IOC, F1], ("--note", "x")),
    "finding-first-interpretation": ([F1, IOC], ("--interpretation", "x")),
    "ioc-first-interpretation": ([IOC, F1], ("--interpretation", "x")),
}


@pytest.mark.parametrize("ids, flag", REFUSED.values(), ids=REFUSED.keys())
def test_approve_refuses_a_finding_only_flag_on_an_ioc_and_writes_nothing(
    two, monkeypatch, capsys, ids, flag
):
    before, chain = _files(two), _files(ledger.LEDGER_DIR)
    code, out, err = _vhir(monkeypatch, capsys, "approve", *ids, *flag)
    assert code == 1 and f"{IOC}: {flag[0]} cannot be used on an IOC" in err, out + err
    assert _files(two) == before and _files(ledger.LEDGER_DIR) == chain
    assert _status(two, "findings.json", F1) == "DRAFT"
    # twin: without the flag, the same command decides the DRAFT IOC
    _ok(monkeypatch, capsys, "approve", IOC)
    assert _status(two, "iocs.json", IOC) == "APPROVED"
    assert _ioc_lines() == [("approve", "APPROVED", None)]


def test_a_lost_race_names_both_commands_and_approve_then_signs_it(
    two, monkeypatch, capsys
):
    _ok(monkeypatch, capsys, "approve", F1)
    raced = []

    def second_writer_then_type(prompt=""):
        if not raced:  # between the plan and the lock, F-steve-001 is rejected
            raced.append(prompt)
            monkeypatch.setattr(
                approval_auth, "getpass_prompt", lambda p="": PASSPHRASE
            )
            A._approve_specific(two, [F1], IDENT, two / "cfg", decision="reject")
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", second_writer_then_type)
    code, out, err = _vhir(monkeypatch, capsys, "approve", F2)
    assert raced and code == 1
    line = next(x for x in (out + err).splitlines() if "NOT SIGNED" in x and IOC in x)
    assert line.endswith(f"it is left as it is. Decide it now: {ROUTE}")
    assert _status(two, "findings.json", F2) == "APPROVED"
    assert _status(two, "iocs.json", IOC) == "REJECTED"
    _verified(monkeypatch, capsys)
    _ok(monkeypatch, capsys, "approve", IOC)
    assert _status(two, "iocs.json", IOC) == "APPROVED"
    assert _reported(monkeypatch, capsys)
