"""`vhir report` with --save: stdout is the document, exactly what the file
holds, and the "Saved to:" status line goes to stderr, in every mode. Before
0.6.6.1 the line followed the document on stdout, so `--full --save` printed
JSON that `json.loads` refused ("Extra data"). The case has no IOC and no
control character, so the saved text is the shown text."""

from __future__ import annotations

import contextlib
import io
import json
from argparse import Namespace

import pytest
import yaml

from tests.signing import sign_approved
from vhir_cli.commands.report import cmd_report

FID = "F-tester-001"
FINDING = {"id": FID, "status": "APPROVED", "title": "Logon from WKS01",
           "confidence": "HIGH", "observation": "a logon from WKS01",
           "interpretation": "lateral movement", "audit_ids": [], "iocs": []}  # fmt: skip
EVENT = {"id": "T-tester-001", "status": "APPROVED",
         "timestamp": "2026-10-08T09:00:00Z", "description": "Logon from WKS01"}  # fmt: skip
MODES = {  # mode: its flag
    "full": {"full": True},
    "executive_summary": {"executive_summary": True},
    "timeline": {"report_timeline": True},
    "ioc": {"ioc": True},
    "findings": {"report_findings": FID},
    "status_brief": {"status_brief": True},
}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    case = tmp_path / "INC-SAVED"
    (case / "audit").mkdir(parents=True)
    (case / "reports").mkdir()
    meta = {"case_id": "INC-SAVED", "name": "Saved", "status": "open",
            "created": "2026-10-08T00:00:00Z", "examiner": "tester"}  # fmt: skip
    (case / "CASE.yaml").write_text(yaml.dump(meta))
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    for name in ("todos.json", "iocs.json"):
        (case / name).write_text("[]")
    (case / "findings.json").write_text(json.dumps([FINDING]))
    (case / "timeline.json").write_text(json.dumps([EVENT]))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    sign_approved(case)
    return case


@pytest.mark.parametrize("mode", MODES)
def test_a_saved_report_prints_the_document_on_stdout_and_saved_to_on_stderr(
    case, mode
):
    base = dict(case=None, full=False, executive_summary=False, report_timeline=False,
                from_date=None, to_date=None, ioc=False, report_findings=None,
                status_brief=False, save=f"{mode}.out")  # fmt: skip
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        cmd_report(Namespace(**{**base, **MODES[mode]}), {"examiner": "tester"})
    path = case / "reports" / f"{mode}.out"
    saved = path.read_text()
    assert out.getvalue() == saved + "\n", (out.getvalue()[-300:], saved[-300:])
    assert err.getvalue() == f"\nSaved to: {path}\n", err.getvalue()
    if mode == "full":
        assert json.loads(out.getvalue())["report_type"] == "full"
    else:
        assert "VERIFICATION" in saved.splitlines(), saved[-600:]
