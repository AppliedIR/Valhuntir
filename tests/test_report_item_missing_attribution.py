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

from vhir_cli import case_io, ledger_verify

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
# the same two lines, with the files swapped
FINDINGS_RESTORE = IOCS_LINE.replace("iocs.json", "findings.json")
IOCS_NONE = FINDINGS_LINE.replace("findings.json", "iocs.json")
MODES = (
    "--full",
    "--executive-summary",
    "--timeline",
    "--ioc",
    "--status-brief",
)


def _case(tmp_path, monkeypatch, findings=(), ioc=IOC):
    """Both files blank; with `findings`, findings.json keeps them (signed) and
    only iocs.json is blank. `ioc` is the IOC record signed before the blank."""
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
    (case / "iocs.json").write_text(json.dumps([ioc]))
    sign_approved(case)  # the ledger now names the IOC, approved
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


def _missing_named(case):
    """verify's ITEM_MISSING messages, through ledger_verify as it stands."""
    failures = ledger_verify.verify_case(case).failures
    return [m for c, m in failures if c == "ITEM_MISSING"]


def _lines(text, code, raised):
    """Which of the four remediation lines the output holds."""
    held = {n: line in text for n, line in (("iocs restore", IOCS_LINE),
            ("findings none", FINDINGS_LINE), ("findings restore", FINDINGS_RESTORE),
            ("iocs none", IOCS_NONE))}  # fmt: skip
    return held, f"rc {code}, raised {raised}; output tail: {text[-600:]!r}"


@pytest.mark.parametrize("mode", MODES)
def test_the_attribution_follows_missing_items_not_the_message(
    tmp_path, monkeypatch, capsys, mode
):
    """verify's message names the finding, its missing_items the IOC: the IOC
    is what iocs.json is attributed."""
    case = _case(tmp_path, monkeypatch)
    real = ledger_verify.verify_case

    def verify(case_dir, *args, **kwargs):
        result = real(case_dir, *args, **kwargs)
        result.failures = [(c, m.replace(IOC["id"], FINDING["id"]))
                           for c, m in result.failures]  # fmt: skip
        return result

    monkeypatch.setattr(ledger_verify, "verify_case", verify)
    named = _missing_named(case)
    # the fixture's own guard: the message names the finding only
    assert named, named
    assert all(FINDING["id"] in m and IOC["id"] not in m for m in named), named
    code, text, raised = _vhir(monkeypatch, capsys, "report", *mode.split())
    held, tail = _lines(text, code, raised)
    assert held == {"iocs restore": True, "findings none": True,
                    "findings restore": False, "iocs none": False}, (held, tail)  # fmt: skip


@pytest.mark.parametrize("mode", MODES)
def test_the_attribution_follows_id_kind(tmp_path, monkeypatch, capsys, mode):
    """With case_io.id_kind patched to read the IOC's id as a finding's, the
    restore line goes to findings.json and iocs.json holds no records."""
    case = _case(tmp_path, monkeypatch)
    real = case_io.id_kind
    monkeypatch.setattr(
        case_io, "id_kind", lambda i: "finding" if i == IOC["id"] else real(i)
    )
    # the fixture's own guard: verify still reports the IOC missing
    named = _missing_named(case)
    assert named and all(IOC["id"] in m for m in named), named
    code, text, raised = _vhir(monkeypatch, capsys, "report", *mode.split())
    held, tail = _lines(text, code, raised)
    assert held == {"iocs restore": False, "findings none": False,
                    "findings restore": True, "iocs none": True}, (held, tail)  # fmt: skip


NO_PREFIX = dict(IOC, id="N-tester-001")


@pytest.mark.parametrize("mode", MODES)
def test_an_id_outside_the_prefixes_goes_where_id_kind_says(
    tmp_path, monkeypatch, capsys, mode
):
    """An IOC record signed under an id with none of the prefixes: id_kind
    reads it as a finding's, so findings.json gets the restore line and
    iocs.json holds no records (a stated limit)."""
    assert case_io.id_kind(NO_PREFIX["id"]) == "finding"
    case = _case(tmp_path, monkeypatch, ioc=NO_PREFIX)
    result = ledger_verify.verify_case(case)
    assert getattr(result, "missing_items", None) == [NO_PREFIX["id"]], result.failures
    code, text, raised = _vhir(monkeypatch, capsys, "report", *mode.split())
    held, tail = _lines(text, code, raised)
    assert held == {"iocs restore": False, "findings none": False,
                    "findings restore": True, "iocs none": True}, (held, tail)  # fmt: skip
