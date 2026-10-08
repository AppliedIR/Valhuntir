"""`vhir review --timeline` and `vhir report --timeline` windows compare
instants, and a date-only end includes its whole day.

Both compared timestamps as text: an event at 20:00-05:00 (01:00 the next
day, UTC) passed an end of 21:00Z, an event at 08:00+05:30 passed a start of
03:00Z, and an end of 2023-01-29 dropped every event on the 29th. A value
that doesn't parse still compares as text, as before.
"""

from __future__ import annotations

import json
import re
from argparse import Namespace

import pytest
import yaml

from vhir_cli.commands.report import _report_timeline
from vhir_cli.commands.review import _show_timeline

EVENTS = {
    "E1": "2023-01-29T00:00:00Z",
    "E2": "2023-01-29T10:00:00Z",
    "E3": "2023-01-29T23:59:59.5Z",
    "E4": "2023-01-30T00:00:00Z",
    "E5": "2023-01-29T20:00:00-05:00",  # 30th 01:00Z
    "E6": "2023-01-29T08:00:00+05:30",  # 29th 02:30Z
    "E7": "2023-01-28T23:00:00Z",
    "E8": "2023-01-29T23:30:00-0500",  # ±HHMM: 30th 04:30Z
}
ALL = sorted(EVENTS)


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    d.mkdir()
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    timeline = [
        {"id": f"T-x-{name}", "timestamp": ts, "status": "DRAFT", "description": name}
        for name, ts in EVENTS.items()
    ]
    (d / "timeline.json").write_text(json.dumps(timeline))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _review(case, capsys, start=None, end=None):
    _show_timeline(case, False, start=start, end=end)
    return sorted(set(re.findall(r"T-x-(E\d)", capsys.readouterr().out)))


def _report(case, capsys, start=None, end=None):
    # the report's text is returned; cmd_report prints it
    text = (
        _report_timeline(case, Namespace(from_date=start, to_date=end, save=None)) or ""
    )
    return sorted(set(re.findall(r"T-x-(E\d)", text + capsys.readouterr().out)))


SITES = pytest.mark.parametrize("site", [_review, _report], ids=["review", "report"])


@SITES
@pytest.mark.parametrize(
    "start, end, expected",
    [
        (None, "2023-01-29", ["E1", "E2", "E3", "E6", "E7"]),
        (None, "2023-01-29T21:00:00Z", ["E1", "E2", "E6", "E7"]),
        ("2023-01-29T03:00:00Z", None, ["E2", "E3", "E4", "E5", "E8"]),
        ("2023-01-29T23:59:59Z", None, ["E3", "E4", "E5", "E8"]),
        ("2023-01-30T04:00:00Z", "2023-01-30T05:00:00Z", ["E8"]),
    ],
    ids=["date-only end", "end instant", "start instant", "late start", "+-HHMM"],
)
def test_a_window_compares_instants(case, capsys, site, start, end, expected):
    assert site(case, capsys, start, end) == expected


@SITES
@pytest.mark.parametrize(
    "start, end, expected",
    [
        ("2023-01-29T00:00:00Z", "2023-01-29T10:00:00Z", ["E1", "E2", "E6"]),
        ("2023-01-29", None, ["E1", "E2", "E3", "E4", "E5", "E6", "E8"]),
        (None, "9999-12-31", ALL),
    ],
    ids=["instant window", "date-only start", "the last day"],
)
def test_anchor_windows_that_were_already_right(
    case, capsys, site, start, end, expected
):
    assert site(case, capsys, start, end) == expected


@SITES
def test_anchor_a_value_that_doesn_t_parse_compares_as_text(case, capsys, site):
    timeline = json.loads((case / "timeline.json").read_text())
    timeline.append(
        {"id": "T-x-E9", "timestamp": "2023-01-29 sometime", "status": "DRAFT"}
    )
    (case / "timeline.json").write_text(json.dumps(timeline))
    assert "E9" in site(case, capsys, "2023-01-29", None)
    assert "E9" not in site(case, capsys, None, "2023-01-28")
