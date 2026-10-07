"""The Timestamp column of the review and report timeline tables keeps the instant.

It showed the first 19 characters, so 2023-01-29T08:00:00+05:30 read as
2023-01-29T08:00:00, which looks like 08:00 UTC; the event was at 02:30Z.
A time with an offset (or Z) now shows its UTC instant; one without an
offset shows as written; one that doesn't parse shows whole. Values are
synthetic.
"""

from __future__ import annotations

from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import display_instant, save_timeline
from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review

EVENTS = {
    "T-tester-001": ("2023-01-29T08:00:00+05:30", "2023-01-29T02:30:00Z"),
    "T-tester-002": ("2023-01-29T08:00:00-0800", "2023-01-29T16:00:00Z"),
    "T-tester-003": ("2023-01-29T08:00:00.1234567Z", "2023-01-29T08:00:00Z"),
    "T-tester-004": ("2023-01-29T08:00:00", "2023-01-29T08:00:00"),
    "T-tester-005": ("early on the 29th", "early on the 29th"),
    # longer than the 19 characters the column used to show
    "T-tester-006": ("2023-01-29 around 08:00 local", "2023-01-29 around 08:00 local"),
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    case_dir = tmp_path / "INC-1"
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(
        yaml.dump({"case_id": "INC-1", "status": "open"})
    )
    for name in ("findings.json", "timeline.json", "todos.json"):
        (case_dir / name).write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    save_timeline(
        case_dir,
        [
            {"id": tid, "status": "DRAFT", "timestamp": given, "description": "event"}
            for tid, (given, _) in EVENTS.items()
        ],
    )
    return case_dir


def _rows(out: str) -> dict[str, str]:
    """Each event's row, by id."""
    return {
        line.split()[0]: line
        for line in out.splitlines()
        if line.startswith("T-tester-")
    }


def _shown(row: str) -> str:
    return row.split(None, 2)[2].rsplit(" event", 1)[0].strip()


@pytest.mark.parametrize("command", ["review", "report"])
def test_the_timestamp_column_shows_the_instant(case, capsys, command):
    if command == "review":
        cmd_review(
            Namespace(
                case=None,
                findings=False,
                detail=False,
                verify=False,
                iocs=False,
                timeline=True,
                audit=False,
                evidence=False,
                limit=50,
            ),
            {},
        )
    else:
        cmd_report(
            Namespace(
                case=None,
                full=False,
                executive_summary=False,
                report_timeline=True,
                from_date=None,
                to_date=None,
                ioc=False,
                report_findings=None,
                status_brief=False,
                save=None,
            ),
            {"examiner": "tester"},
        )
    rows = _rows(capsys.readouterr().out)
    assert {tid: _shown(row) for tid, row in rows.items()} == {
        tid: shown for tid, (_, shown) in EVENTS.items()
    }


@pytest.mark.parametrize("value", [None, ""])
def test_no_timestamp_is_a_question_mark(value):
    assert display_instant(value) == "?"
