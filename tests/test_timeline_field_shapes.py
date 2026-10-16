"""`vhir report --timeline` and `vhir review --timeline` list an event whose
description or timestamp is not text: a number or a list, which a bundle, a
hand edit or (for the description) the MCP can store. Each shows as its text;
a missing or null one as empty. The order and the --from/--to filters compare
such a timestamp as text."""

# ruff: noqa: F811  (the shared `case` fixture is a test argument)
from __future__ import annotations

import pytest

from vhir_cli.case_io import _at_or_after, _at_or_before, save_findings, save_timeline

from .test_finding_iocs_and_tabs_shown import _cli, case  # noqa: F401

STEPS = [f"step {i}" for i in range(36)]


def _e(n, timestamp="2023-01-29T20:30:00Z", description="Logon", status="DRAFT"):
    return {"id": f"T-tester-{n:03d}", "status": status, "timestamp": timestamp,
            "description": description}  # fmt: skip


def _report_row(e, ts, desc):
    return f"{e['id']:<22} {e['status']:<10} {ts:<22} {desc}"


def _review_row(e, ts, desc):
    return f"{e['id']:<20} {e['status']:<10} {ts:<22} {desc}"


def _with(case, events):
    save_findings(case, [])
    save_timeline(case, events)


PLAIN = _e(1, "2023-01-29T20:00:00Z", "Service installed")


def test_report_lists_a_number_description(case, monkeypatch, capsys):
    e = _e(2, description=4624)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["report", "--timeline"])
    assert _report_row(e, "2023-01-29T20:30:00Z", "4624") in out.splitlines(), out
    assert "Total: 2 events" in out


def test_report_cuts_a_list_description_as_its_text(case, monkeypatch, capsys):
    e = _e(2, description=STEPS)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["report", "--timeline"])
    want = str(STEPS)[:32] + "..."
    assert _report_row(e, "2023-01-29T20:30:00Z", want) in out.splitlines(), out


def test_report_orders_a_number_timestamp_as_text(case, monkeypatch, capsys):
    e = _e(2, timestamp=1675024200)
    _with(case, [PLAIN, e])
    rows = _cli(monkeypatch, capsys, ["report", "--timeline"]).splitlines()
    first = _report_row(e, "1675024200", "Logon")
    second = _report_row(PLAIN, "2023-01-29T20:00:00Z", "Service installed")
    assert rows.index(first) < rows.index(second), rows


def test_report_lists_null_fields_as_empty(case, monkeypatch, capsys):
    e = _e(2, timestamp=None, description=None)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["report", "--timeline"])
    assert _report_row(e, "?", "") in out.splitlines(), out
    assert "None" not in out


def test_report_lists_text_fields_as_before(case, monkeypatch, capsys):
    e = _e(2, "2023-01-29T21:00:00Z", "x" * 40)
    _with(case, [e, PLAIN])
    rows = _cli(monkeypatch, capsys, ["report", "--timeline"]).splitlines()
    i = rows.index(_report_row(PLAIN, "2023-01-29T20:00:00Z", "Service installed"))
    assert rows[i + 1] == _report_row(e, "2023-01-29T21:00:00Z", "x" * 32 + "...")


def test_report_saves_number_fields(case, monkeypatch, capsys):
    e = _e(2, timestamp=1675024200, description=4624)
    _with(case, [PLAIN, e])
    _cli(monkeypatch, capsys, ["report", "--timeline", "--save", "tl.txt"])
    saved = (case / "reports" / "tl.txt").read_text()
    assert _report_row(e, "1675024200", "4624") in saved.splitlines(), saved


@pytest.mark.parametrize("flag", ["--from", "--to"])
def test_report_filters_by_date_past_a_number_timestamp(
    flag, case, monkeypatch, capsys
):
    e = _e(2, timestamp=1675024200)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["report", "--timeline", flag, "2023-01-29"])
    # as text "1675024200" sorts before "2023-01-29": after the --to, not the --from
    assert ("1675024200" in out) is (flag == "--to"), out
    assert "Service installed" in out


def test_review_orders_a_number_timestamp_as_text(case, monkeypatch, capsys):
    e = _e(2, timestamp=1675024200)
    _with(case, [PLAIN, e])
    rows = _cli(monkeypatch, capsys, ["review", "--timeline"]).splitlines()
    first = _review_row(e, "1675024200", "Logon")
    second = _review_row(PLAIN, "2023-01-29T20:00:00Z", "Service installed")
    assert rows.index(first) < rows.index(second), rows


def test_review_lists_number_list_and_null_descriptions(case, monkeypatch, capsys):
    events = [
        _e(2, description=4624),
        _e(3, description=STEPS),
        _e(4, description=None),
    ]
    _with(case, [PLAIN, *events])
    rows = _cli(monkeypatch, capsys, ["review", "--timeline"]).splitlines()
    ts = "2023-01-29T20:30:00Z"
    assert _review_row(events[0], ts, "4624") in rows
    assert _review_row(events[1], ts, str(STEPS)[:37] + "...") in rows
    assert _review_row(events[2], ts, "") in rows


@pytest.mark.parametrize("flag", ["--start", "--end"])
def test_review_filters_by_date_past_a_number_timestamp(
    flag, case, monkeypatch, capsys
):
    e = _e(2, timestamp=1675024200)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["review", "--timeline", flag, "2023-01-29"])
    assert ("1675024200" in out) is (flag == "--end"), out
    assert "Service installed" in out


def test_review_detail_lists_a_number_timestamp(case, monkeypatch, capsys):
    e = _e(2, timestamp=1675024200, description=4624)
    _with(case, [PLAIN, e])
    out = _cli(monkeypatch, capsys, ["review", "--timeline", "--detail"])
    assert "[T-tester-002] 1675024200" in out and "Description: 4624" in out, out


@pytest.mark.parametrize("ts", [1675024200, 1.5, None])
def test_the_date_filters_compare_a_non_text_timestamp_as_text(ts):
    text = "" if ts is None else str(ts)
    assert _at_or_after(ts, "2023-01-29") is (text >= "2023-01-29")
    assert _at_or_before(ts, "2023-01-29") is (text <= "2023-01-29")
