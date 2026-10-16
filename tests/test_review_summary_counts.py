"""`vhir review` summary counts the rejected events next to the draft and approved ones."""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from vhir_cli.commands.review import cmd_review


def _items(prefix, draft, approved, rejected, other=()):
    statuses = ["DRAFT"] * draft + ["APPROVED"] * approved + ["REJECTED"] * rejected
    return [
        {"id": f"{prefix}-{n}", "status": s} for n, s in enumerate([*statuses, *other])
    ]


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C1"
    d.mkdir()
    (d / "CASE.yaml").write_text(
        "case_id: C1\nname: n\nstatus: open\nexaminer: tester\n"
    )
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _summary(case, capsys, findings, timeline):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text(json.dumps(timeline))
    cmd_review(Namespace(case=None), {})
    return capsys.readouterr().out


def test_a_rejected_event_is_counted(case, capsys):
    out = _summary(case, capsys, _items("F", 1, 1, 0), _items("T", 2, 1, 1))
    assert "Timeline: 4 events (2 draft, 1 approved, 1 rejected)\n" in out, out


def test_no_rejected_event_keeps_the_other_counts(case, capsys):
    out = _summary(case, capsys, _items("F", 1, 1, 0), _items("T", 2, 1, 0))
    assert "Timeline: 3 events (2 draft, 1 approved, 0 rejected)\n" in out, out
    assert "Findings: 2 total (1 draft, 1 approved, 0 rejected)\n" in out, out


def test_an_empty_timeline_shows_every_count_as_zero(case, capsys):
    out = _summary(case, capsys, [], [])
    assert "Timeline: 0 events (0 draft, 0 approved, 0 rejected)\n" in out, out


def test_a_status_outside_the_three_is_in_the_total_only(case, capsys):
    out = _summary(case, capsys, [], _items("T", 1, 1, 1, other=["PENDING", None]))
    assert "Timeline: 5 events (1 draft, 1 approved, 1 rejected)\n" in out, out
