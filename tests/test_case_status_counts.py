"""`vhir case status` counts the rejected items next to the draft and approved ones."""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from vhir_cli.main import _case_status, _case_status_data


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
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _status(case, capsys, findings, timeline):
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text(json.dumps(timeline))
    _case_status(Namespace(case=None), {"examiner": "tester"})
    return capsys.readouterr().out


def test_findings_and_events_show_the_rejected_count(case, capsys):
    out = _status(case, capsys, _items("F", 0, 21, 1), _items("T", 2, 3, 4))
    assert "  Findings: 22 (0 draft, 21 approved, 1 rejected)\n" in out, out
    assert "  Timeline: 9 (2 draft, 3 approved, 4 rejected)\n" in out, out


def test_a_zero_rejected_count_is_shown(case, capsys):
    out = _status(case, capsys, _items("F", 1, 2, 0), _items("T", 0, 1, 0))
    assert "  Findings: 3 (1 draft, 2 approved, 0 rejected)\n" in out, out
    assert "  Timeline: 1 (0 draft, 1 approved, 0 rejected)\n" in out, out


def test_an_empty_case_shows_every_count_as_zero(case, capsys):
    out = _status(case, capsys, [], [])
    assert "  Findings: 0 (0 draft, 0 approved, 0 rejected)\n" in out, out
    assert "  Timeline: 0 (0 draft, 0 approved, 0 rejected)\n" in out, out


def test_a_status_outside_the_three_is_in_the_total_only(case, capsys):
    out = _status(case, capsys, _items("F", 1, 1, 1, other=["PENDING", None]), [])
    assert "  Findings: 5 (1 draft, 1 approved, 1 rejected)\n" in out, out
    assert "other" not in out, out


def test_the_status_data_carries_the_rejected_counts(case):
    (case / "findings.json").write_text(json.dumps(_items("F", 1, 2, 3)))
    (case / "timeline.json").write_text(json.dumps(_items("T", 3, 2, 1)))
    data = _case_status_data(case)
    counts = {k: v for k, v in data.items() if k.startswith(("finding_", "timeline_"))}
    assert counts == {
        "finding_count": 6, "finding_draft": 1, "finding_approved": 2, "finding_rejected": 3,
        "timeline_count": 6, "timeline_draft": 3, "timeline_approved": 2, "timeline_rejected": 1,
    }  # fmt: skip
