"""`vhir review --timeline` and `vhir report --timeline` list events in the
order of their UTC instants, the times they print.

Both sorted the stored text: an event at 23:02:11+09:00 (14:02:11Z) was
printed as 14:02:11Z but listed after an event at 20:00:00Z. Within a printed
second the stored text still decides, so a timeline of UTC times lists as
before.
"""

from __future__ import annotations

import json
import re
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review

# listed in instant order
EVENTS = [
    ("T-x-A", "2023-01-29T10:00:00Z"),
    ("T-x-B", "2023-01-29T23:02:11+09:00"),  # 14:02:11Z
    ("T-x-C", "2023-01-29T20:00:00Z"),
]


# stored in this order; all UTC, three of them in one printed second
UTC_EVENTS = [
    ("T-x-D", "2023-01-29T10:00:00Z"),
    ("T-x-E", "2023-01-29T10:00:00.9Z"),
    ("T-x-F", "2023-01-29T20:00:00Z"),
    ("T-x-G", "2023-01-29T10:00:00.123456789Z"),
    ("T-x-H", "2023-01-29T09:59:59.999999Z"),
]


def _case(tmp_path, monkeypatch, events):
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    timeline = [
        {"id": tid, "timestamp": ts, "status": "DRAFT", "description": tid}
        for tid, ts in events
    ]
    (d / "timeline.json").write_text(json.dumps(timeline))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


@pytest.fixture
def case(tmp_path, monkeypatch):
    return _case(tmp_path, monkeypatch, EVENTS)


@pytest.fixture
def utc_case(tmp_path, monkeypatch):
    return _case(tmp_path, monkeypatch, UTC_EVENTS)


def _listed(out: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"T-x-[A-H]", out)))


@pytest.mark.parametrize("detail", [False, True], ids=["summary", "detail"])
def test_review_timeline_lists_an_offset_event_by_its_instant(case, capsys, detail):
    cmd_review(Namespace(case=None, timeline=True, detail=detail), {})
    out = capsys.readouterr().out
    assert _listed(out) == [tid for tid, _ in EVENTS]
    if not detail:
        assert "2023-01-29T14:02:11Z" in out


def test_report_timeline_lists_an_offset_event_by_its_instant(case, capsys):
    cmd_report(Namespace(case=None, report_timeline=True, save=None), {})
    out = capsys.readouterr().out
    assert _listed(out) == [tid for tid, _ in EVENTS]
    assert "2023-01-29T14:02:11Z" in out


@pytest.mark.parametrize("view", ["review", "review --detail", "report"])
def test_a_utc_timeline_lists_in_stored_text_order(utc_case, capsys, view):
    if view == "report":
        cmd_report(Namespace(case=None, report_timeline=True, save=None), {})
    else:
        cmd_review(Namespace(case=None, timeline=True, detail="detail" in view), {})
    by_text = [tid for tid, ts in sorted(UTC_EVENTS, key=lambda e: e[1])]
    assert by_text == ["T-x-H", "T-x-G", "T-x-E", "T-x-D", "T-x-F"]
    assert _listed(capsys.readouterr().out) == by_text
