# ruff: noqa: F811 - `case` is the fixture imported below
"""An IOC cited by findings that end a commit at different statuses doesn't
cascade. The plan names it, with each citing finding and its status after the
commit, so the examiner knows it stays DRAFT and decides it on its own."""

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

LINE = (
    "  IOC-steve-001 stays DRAFT: cited by F-steve-001 (APPROVED) and "
    "F-steve-002 ({}). Decide it on its own: vhir approve IOC-steve-001"
)


def _second_cites(case, status):
    """F-steve-002 cites the IOC too, at `status`."""
    findings = json.loads((case / "findings.json").read_text())
    findings[1].update(status=status, iocs=["10.0.0.7"])
    (case / "findings.json").write_text(json.dumps(findings))


@pytest.mark.parametrize("other", ["REJECTED", "DRAFT"])
def test_an_ioc_split_between_findings_is_named_with_each_citing_one(
    case, capsys, other
):
    _second_cites(case, other)
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    out = capsys.readouterr().out
    assert LINE.format(other) in out.splitlines()
    assert "1 linked item(s) not signed:" in out
    assert "To be signed: F-steve-001, T-steve-001" in out
    assert _signed() == [("F-steve-001", "approve"), ("T-steve-001", "approve")]
    assert _status(case, "iocs.json", "IOC-steve-001") == "DRAFT"
    assert verify_case(case).exit_code == 0


def test_an_ioc_both_citing_findings_approve_is_signed_and_not_named(case, capsys):
    # twin: the other citing finding is already APPROVED, so the IOC cascades
    _second_cites(case, "APPROVED")
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    out = capsys.readouterr().out
    assert "stays DRAFT" not in out and "linked item(s) not signed" not in out
    assert ("IOC-steve-001", "approve") in _signed()
    assert _status(case, "iocs.json", "IOC-steve-001") == "APPROVED"


def test_an_ioc_cited_only_by_findings_not_decided_here_is_not_named(case, capsys):
    findings = json.loads((case / "findings.json").read_text())
    findings[0]["iocs"] = []
    findings[1]["iocs"] = ["10.0.0.7"]
    (case / "findings.json").write_text(json.dumps(findings))
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    out = capsys.readouterr().out
    assert "IOC-steve-001" not in out
    assert _status(case, "iocs.json", "IOC-steve-001") == "DRAFT"


# --- The plan itself ------------------------------------------------------------


def _f(fid, status="DRAFT", iocs=("10.0.0.7",)):
    return {"id": fid, "status": status, "iocs": list(iocs)}


def _ioc(iid="IOC-steve-001", value="10.0.0.7", **kw):
    return {"id": iid, "value": value, "status": "DRAFT", **kw}


def test_three_citing_findings_are_named_in_id_order():
    findings = [_f("F-steve-003", "REJECTED"), _f("F-steve-001"), _f("F-steve-002")]
    direct = [decide.Decision(findings[1], "finding", "approve", "APPROVED")]
    planned, held = decide.split_cascades(direct, findings, [], [_ioc()])
    assert planned == []
    (h,) = held
    assert h.id == "IOC-steve-001" and h.coupled_from == "F-steve-001"
    assert h.citing == (
        ("F-steve-001", "APPROVED"), ("F-steve-002", "DRAFT"), ("F-steve-003", "REJECTED"),
    )  # fmt: skip
    assert decide.held_line(h.id, h.coupled_from, h.citing) == (
        "IOC-steve-001 stays DRAFT: cited by F-steve-001 (APPROVED), F-steve-002 "
        "(DRAFT) and F-steve-003 (REJECTED). Decide it on its own: vhir approve "
        "IOC-steve-001"
    )


def test_ids_in_the_line_are_printed_on_one_line():
    line = decide.held_line(
        "IOC-x\nforged", "F-1", (("F-1", "APPROVED"), ("F-2\r\nx", "DRAFT"))
    )
    assert "\n" not in line and "\r" not in line


@pytest.mark.parametrize(
    "ioc",
    [
        _ioc(status="APPROVED"),
        _ioc(manually_reviewed=True),
        _ioc(value="10.0.0.8"),
        "not a record",
    ],
    ids=["decided-already", "manually-reviewed", "not-cited", "not-a-record"],
)
def test_iocs_that_would_never_cascade_are_not_named(ioc):
    findings = [_f("F-steve-001"), _f("F-steve-002", "REJECTED")]
    assert undecided_iocs({"F-steve-001": "APPROVED"}, findings, [ioc]) == []


def test_an_ioc_decided_directly_is_not_named():
    findings = [_f("F-steve-001"), _f("F-steve-002", "REJECTED")]
    decided = {"F-steve-001": "APPROVED"}
    assert undecided_iocs(decided, findings, [_ioc()], {"IOC-steve-001"}) == []
    # twin: not excluded, it is named
    (u,) = undecided_iocs(decided, findings, [_ioc()])
    assert u["coupled_from"] == "F-steve-001"
    assert u["citing"] == [("F-steve-001", "APPROVED"), ("F-steve-002", "REJECTED")]


def test_an_edit_that_leaves_the_finding_draft_names_nothing():
    findings = [_f("F-steve-001"), _f("F-steve-002", "REJECTED")]
    assert undecided_iocs({"F-steve-001": "DRAFT"}, findings, [_ioc()]) == []


@pytest.mark.parametrize(
    "decided, statuses",
    [
        ({"F-steve-001": "APPROVED", "F-steve-002": "APPROVED"}, ("DRAFT", "DRAFT")),
        ({"F-steve-001": "REJECTED"}, ("DRAFT", "REJECTED")),
        ({"F-steve-001": "APPROVED"}, ("DRAFT", "REJECTED")),
        ({"F-steve-001": "APPROVED", "F-steve-002": "REJECTED"}, ("DRAFT", "DRAFT")),
    ],
)
def test_each_cited_ioc_is_either_cascaded_or_named(decided, statuses):
    findings = [_f("F-steve-001", statuses[0]), _f("F-steve-002", statuses[1])]
    iocs = [_ioc()]
    cascaded = [c["item"]["id"] for c in plan_cascades(decided, findings, [], iocs)]
    named = [u["item"]["id"] for u in undecided_iocs(decided, findings, iocs)]
    assert sorted(cascaded + named) == ["IOC-steve-001"]
    assert not (cascaded and named)


def test_a_held_item_unpacks_as_its_id_and_finding_and_copies_whole():
    h = decide.Held("IOC-steve-001", "F-steve-001", [("F-steve-001", "APPROVED")])
    item_id, finding_id = h
    assert (item_id, finding_id) == ("IOC-steve-001", "F-steve-001")
    for c in (copy.deepcopy(h), pickle.loads(pickle.dumps(h))):
        assert tuple(c) == tuple(h) and c.citing == h.citing
    assert decide.Held("T-steve-001", "F-steve-001").citing == ()
