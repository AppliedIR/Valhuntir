"""A signed case whose iocs.json and findings.json are both blank, and whose
approval records name an approved IOC the case no longer holds: verify reports
that IOC missing, as data (`missing_items`), and every report mode attributes
it to iocs.json through `case_io.id_kind`. So iocs.json gets the restore line
for a file that held approved items, and findings.json, which held none, gets
the "holds no records" line. `--findings` reports findings the case holds, so
its row keeps an approved F-tester-001 in findings.json and blanks iocs.json
only."""

from __future__ import annotations

import json
import sys
import traceback

import pytest

from vhir_cli import ledger_verify

from .signing import sign_approved

CASE = "INC-2026-MISSING"
FINDING = {"id": "F-tester-001", "status": "APPROVED", "title": "Beacon to a C2 host",
           "confidence": "HIGH", "observation": "beacons to c2.example.net",
           "interpretation": "C2", "iocs": []}  # fmt: skip
IOC = {"id": "IOC-tester-009", "value": "c2.example.net", "type": "domain-name",
       "status": "APPROVED", "manually_reviewed": True, "source_findings": []}  # fmt: skip
BLANK = " \n\t \n"
IOCS_LINE = (
    "iocs.json is empty, but the case's approval records show it held approved"
    " items. Restore the case from a backup (`vhir restore`)."
)
FINDINGS_LINE = (
    "findings.json holds no records. If the case never held any, write [] to it;"
    " otherwise restore the case from a backup (`vhir restore`)."
)
MODES = (
    "--full",
    "--executive-summary",
    "--timeline",
    "--ioc",
    "--status-brief",
)


def _case(tmp_path, monkeypatch, findings=()):
    """Both files blank; with `findings`, findings.json keeps them (signed) and
    only iocs.json is blank."""
    case = tmp_path / CASE
    case.mkdir()
    for sub in ("reports", "audit"):
        (case / sub).mkdir()
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    (case / "CASE.yaml").write_text(
        f"case_id: {CASE}\nname: Missing\nstatus: open\nexaminer: tester\n"
    )
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    for name in ("timeline.json", "todos.json"):
        (case / name).write_text("[]")
    (case / "findings.json").write_text(json.dumps(list(findings)))
    (case / "iocs.json").write_text(json.dumps([IOC]))
    sign_approved(case)  # the ledger now names IOC-tester-009, approved
    (case / "iocs.json").write_text(BLANK)
    if not findings:
        (case / "findings.json").write_text(BLANK)
    return case


def _vhir(monkeypatch, capsys, *argv) -> tuple[object, str, str | None]:
    """(exit code, stdout + stderr, what was raised out of main, if anything)."""
    from vhir_cli.main import main

    monkeypatch.setattr("builtins.input", lambda p="": "")
    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    raised = None
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code
    except Exception as e:  # noqa: BLE001  (shown in the assertion's message)
        code = "raised"
        raised = (
            f"{type(e).__name__}: {e} at {traceback.extract_tb(e.__traceback__)[-1]}"
        )
    out = capsys.readouterr()
    return code, out.out + out.err, raised


def test_verify_reports_the_missing_item_as_data(tmp_path, monkeypatch):
    case = _case(tmp_path, monkeypatch)
    result = ledger_verify.verify_case(case)
    assert any(code == "ITEM_MISSING" for code, _ in result.failures), result.failures
    assert getattr(result, "missing_items", None) == [IOC["id"]]


@pytest.mark.parametrize("mode", MODES)
def test_each_file_gets_its_own_remediation(tmp_path, monkeypatch, capsys, mode):
    _case(tmp_path, monkeypatch)
    code, text, raised = _vhir(monkeypatch, capsys, "report", *mode.split())
    assert IOCS_LINE in text, (
        f"rc {code}, raised {raised}; output tail: {text[-600:]!r}"
    )
    assert FINDINGS_LINE in text, (
        f"rc {code}, raised {raised}; output tail: {text[-600:]!r}"
    )


def test_findings_mode_attributes_the_missing_ioc(tmp_path, monkeypatch, capsys):
    case = _case(tmp_path, monkeypatch, findings=[FINDING])
    assert [f["id"] for f in json.loads((case / "findings.json").read_text())] == [
        FINDING["id"]
    ]
    code, text, raised = _vhir(
        monkeypatch, capsys, "report", "--findings", FINDING["id"]
    )
    tail = f"rc {code}, raised {raised}; output tail: {text[-600:]!r}"
    # the fixture's own guard: the finding is there to report
    assert f"Not found: {FINDING['id']}" not in text, tail
    assert IOCS_LINE in text, tail
