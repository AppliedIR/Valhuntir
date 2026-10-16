"""Review, approve and report show a record's cited audit ids as the same text
on their Evidence lines, whatever the stored shape, and none of them fails on it.
The as-it-will-be-signed view is driven for a finding (an event's lists its ids
under another label)."""

import re

import pytest

from tests.signing import sign_approved
from tests.test_report import _make_args, case_dir, identity  # noqa: F401
from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands import approve, review
from vhir_cli.commands.report import cmd_report

SHAPES = [
    (None, ""),
    (5, "5"),
    (0, "0"),  # falsy, yet one id: every view shows it
    ({"a": "ev-001"}, "{'a': 'ev-001'}"),
    ("abc", "abc"),
    ([1, 2], "1, 2"),
    ([{"x": 1}], "{'x': 1}"),
    ([None], "None"),
    ([["ev-001"]], "['ev-001']"),
    (["ev-001", "ev-002"], "ev-001, ev-002"),
    ([], ""),
]
_EVIDENCE = re.compile(r"Evidence:\s*(.*?)\s*$")


def _shown(out: str) -> list[str]:
    return [m[1] for line in out.splitlines() if (m := _EVIDENCE.search(line))]


@pytest.mark.parametrize("value,text", SHAPES, ids=[repr(v) for v, _ in SHAPES])
def test_every_view_shows_the_cited_ids_as_review_does(
    case_dir,  # noqa: F811
    identity,  # noqa: F811
    capsys,
    value,
    text,
):
    finding = {"id": "F-tester-001", "status": "APPROVED", "title": "t", "confidence": "LOW",
               "audit_ids": value, "observation": "o", "interpretation": "i",
               "examiner": "tester"}  # fmt: skip
    event = {"id": "T-tester-001", "status": "DRAFT", "timestamp": "2026-02-19T10:00:00Z",
             "description": "d", "audit_ids": value}  # fmt: skip
    save_findings(case_dir, [finding])
    save_timeline(case_dir, [event])
    sign_approved(case_dir)
    capsys.readouterr()
    views = {}
    for name, show in (
        ("report", lambda: cmd_report(_make_args(report_findings="F-tester-001"), identity)),
        ("review findings", lambda: review._show_findings_detail(case_dir)),
        ("review timeline", lambda: review._show_timeline(case_dir, detail=True)),
        ("approve pending", lambda: (approve._print_pending_item(finding, []),
                                     approve._print_pending_item(event, []))),
        ("approve item", lambda: (approve._display_item(finding), approve._display_item(event))),
        ("approve as signed", lambda: approve._render_terminal_diff(
            finding, {"id": "F-tester-001", "action": "approve", "modifications": {}})),
    ):  # fmt: skip
        show()
        views[name] = _shown(capsys.readouterr().out)
    assert views["report"] == [text]  # the report always has the line
    assert views["review findings"] == [text]
    for name, shown in views.items():
        assert set(shown) <= {text}, name  # absent only where the text is empty
        if text:
            assert shown, name
