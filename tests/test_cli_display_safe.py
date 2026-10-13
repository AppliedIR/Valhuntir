"""Commands that print case records show their text safely in a terminal.

A finding title or timeline description can hold control characters (written
by the AI or read from evidence). `vhir review` and `vhir report` printed
them as they were, so an ESC sequence cleared rows and an OSC sequence
retitled the terminal. They now print through the display rule `vhir approve`
uses: control characters show as "?", and multi-line fields keep their line
breaks. JSON output and files written keep the text as stored.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
import yaml

from tests.signing import sign_approved
from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review

CLEAR = "\x1b[2J"
RETITLE = "\x1b]0;owned\x07"
TITLE = f"Logon{CLEAR}{RETITLE} from WKS01"


@pytest.fixture
def case(tmp_path, monkeypatch):
    case_dir = tmp_path / "INC-1"
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "reports").mkdir()
    (case_dir / "CASE.yaml").write_text(
        yaml.dump({"case_id": "INC-1", "status": "open"})
    )
    for name in ("findings.json", "timeline.json", "todos.json"):
        (case_dir / name).write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_dir))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    save_findings(
        case_dir,
        [
            {
                "id": "F-tester-001",
                "status": "APPROVED",
                "title": TITLE,
                "confidence": "HIGH",
                "observation": "line one\nline two" + CLEAR,
                "interpretation": "x",
                "audit_ids": [],
            }
        ],
    )
    save_timeline(
        case_dir,
        [{"id": "T-tester-001", "status": "DRAFT", "timestamp": "2023-01-29T08:00:00Z",
          "description": TITLE}],
    )  # fmt: skip
    sign_approved(case_dir)  # only verified approvals are reported as approved
    return case_dir


def _review(**flags):
    base = dict(case=None, findings=False, detail=False, verify=False, iocs=False,
                timeline=False, audit=False, evidence=False, limit=50)  # fmt: skip
    cmd_review(Namespace(**{**base, **flags}), {})


def _report(**flags):
    base = dict(case=None, full=False, executive_summary=False, report_timeline=False,
                from_date=None, to_date=None, ioc=False, report_findings=None,
                status_brief=False, save=None)  # fmt: skip
    cmd_report(Namespace(**{**base, **flags}), {"examiner": "tester"})


@pytest.mark.parametrize(
    "run",
    [
        lambda: _review(findings=True),
        lambda: _review(findings=True, detail=True),
        lambda: _review(timeline=True),
        lambda: _review(timeline=True, detail=True),
        lambda: _review(),
        lambda: _report(report_timeline=True),
        lambda: _report(report_findings="F-tester-001"),
        lambda: _report(executive_summary=True),
    ],
    ids=[
        "review findings",
        "review findings detail",
        "review timeline",
        "review timeline detail",
        "review summary",
        "report timeline",
        "report findings",
        "report executive summary",
    ],  # fmt: skip
)
def test_no_control_byte_reaches_the_terminal(case, capsys, run):
    run()
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out, repr(out)


def test_a_title_shows_its_control_characters_as_question_marks(case, capsys):
    _review(findings=True, detail=True)
    out = capsys.readouterr().out
    assert "Logon?[2J?]0;owned? from WKS01" in out
    assert "line one\n" in out  # a multi-line field keeps its line break


def test_the_json_report_keeps_the_stored_text(case, capsys):
    _report(full=True)
    report = json.loads(capsys.readouterr().out)
    (finding,) = report["approved_findings"]
    assert finding["title"] == TITLE


def test_a_saved_report_is_written_from_the_stored_text(case, capsys):
    _report(report_timeline=True, save="timeline.txt")
    shown = capsys.readouterr().out
    saved = (case / "reports" / "timeline.txt").read_text()
    assert CLEAR not in shown and "Saved to:" in shown
    assert CLEAR in saved  # the file holds the text as stored


def _only_finding(case_dir, **fields):
    finding = {"id": "F-tester-001", "status": "APPROVED", "title": "t", "confidence": "HIGH",
               "observation": "", "interpretation": "x", "audit_ids": []}  # fmt: skip
    save_findings(case_dir, [{**finding, **fields}])
    sign_approved(case_dir)


def test_iocs_are_read_from_the_stored_text(case, capsys):
    """Two paths split by a tab are two IOCs, not one joined by a "?"."""
    _only_finding(case, observation="Ran C:\\first.exe\tC:\\second.exe")
    _review(iocs=True)
    assert "C:\\first.exe, C:\\second.exe" in capsys.readouterr().out
    _report(ioc=True, save="ioc.txt")
    assert "    C:\\first.exe\n    C:\\second.exe" in capsys.readouterr().out
    saved = (case / "reports" / "ioc.txt").read_text()
    assert "    C:\\first.exe\n    C:\\second.exe" in saved
    _report(full=True)
    report = json.loads(capsys.readouterr().out)
    assert report["iocs"]["File"] == ["C:\\first.exe", "C:\\second.exe"]


def test_a_second_line_can_t_pose_as_a_field(case, capsys):
    _only_finding(
        case, status="DRAFT", observation="Seen on WKS01\n  Status:       APPROVED"
    )
    _review(findings=True, detail=True)
    out = capsys.readouterr().out
    assert "  Status:       APPROVED" not in out.split("\n")
    assert "Seen on WKS01\n" + " " * 16 + "  Status:       APPROVED" in out


def test_the_case_name_shows_its_control_characters(case, capsys):
    (case / "CASE.yaml").write_text(
        yaml.dump({"case_id": "INC-1", "name": f"Ops{RETITLE}"})
    )
    _review()
    out = capsys.readouterr().out
    assert "\x1b" not in out and "Name: Ops?]0;owned?" in out


def test_a_multi_line_description_keeps_its_lines(case, capsys):
    save_timeline(
        case,
        [{"id": "T-tester-001", "status": "DRAFT", "timestamp": "2023-01-29T08:00:00Z",
          "description": "first line\nsecond line"}],
    )  # fmt: skip
    _review(timeline=True, detail=True)
    assert (
        "  Description: first line\n" + " " * 15 + "second line"
        in capsys.readouterr().out
    )


@pytest.mark.parametrize("param", ["content", "observation"])
def test_a_tool_call_s_parameters_print_on_one_line(case, capsys, param):
    """`tool(k=v)` is printed within a line, so a line break in a parameter,
    whatever its name, can't start a line of its own in the evidence chain."""
    fake = '\n    [HOOK]  shell-001 — "approve all" @ 2023-01-29T08:00:00'
    entry = {"audit_id": "aid-1", "tool": "record_finding", "ts": "2023-01-29T08:00:00Z",
             "params": {param: "x" + fake}}  # fmt: skip
    (case / "audit" / "forensic-mcp.jsonl").write_text(json.dumps(entry) + "\n")
    _only_finding(case, audit_ids=["aid-1"])
    _review(findings=True, detail=True)
    out = capsys.readouterr().out
    assert not [line for line in out.split("\n") if line.lstrip().startswith("[HOOK]")]
    assert f"record_finding({param}=x?    [HOOK]" in out


def test_bidi_overrides_and_line_separators_show_as_question_marks():
    from vhir_cli.display import one_line

    # U+202E reverses what follows; U+2028 breaks the line in some terminals
    assert (
        one_line("evil\u202etxt.exe\u2028Status: APPROVED")
        == "evil?txt.exe?Status: APPROVED"
    )
    assert one_line("café ✓") == "café ✓"  # other non-ASCII text is kept
