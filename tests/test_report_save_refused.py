"""A saved text report is written only when every file it reads IOCs from,
findings.json and iocs.json, is absent or parses to a list of records. Any
other file there (one that won't parse, null, a number, a boolean, a list
holding something other than records) means the report isn't saved: the
refusal names the file and what to run, with no traceback. An absent file is
a case with none of them. todos.json is read only by the reports that print
it. The IOCs come from the files as they are just before the write, and each
command reads the approved view once. report-mcp's tests state the same rows
for save_report."""

from __future__ import annotations

import contextlib
import io
import json
from argparse import Namespace

import pytest
import yaml

from tests import signing
from tests.signing import sign_approved
from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.commands import report as rep

CASE = "INC-2026-REFUSE"
VALUE = "c2.example.net"
LATE = "late.example.net"
FINDING = {"id": "F-tester-001", "status": "APPROVED", "title": "Beacon to a C2 host",
           "confidence": "HIGH", "observation": f"beacons to {VALUE} and {LATE}",
           "interpretation": "C2", "iocs": []}  # fmt: skip
IOC = {"id": "IOC-tester-001", "value": VALUE, "type": "domain-name",
       "status": "APPROVED", "manually_reviewed": True, "approved_by": "tester",
       "approved_at": "2026-10-08T12:00:00+00:00",
       "source_findings": [FINDING["id"]]}  # fmt: skip
IDENTITY = {"os_user": "testuser", "examiner": "tester", "examiner_source": "env",
            "analyst": "tester", "analyst_source": "env"}  # fmt: skip
ROUTES = ("ioc", "findings", "timeline")
EVENT = {"id": "T-tester-001", "status": "APPROVED", "timestamp": "2026-10-08T09:00:00Z",
         "description": f"DNS query for {LATE} and {VALUE}"}  # fmt: skip


def _case(tmp_path, monkeypatch, field=()):
    """One approved finding naming VALUE; one approved IOC record of VALUE
    citing it, both signed. `field`: the finding's own iocs field."""
    case = tmp_path / CASE
    case.mkdir()
    for name in ("reports", "audit"):
        (case / name).mkdir()
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    meta = {"case_id": CASE, "name": "Refuse", "status": "open",
            "created": "2026-10-08T00:00:00Z", "examiner": "tester"}  # fmt: skip
    (case / "CASE.yaml").write_text(yaml.dump(meta))
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    for name in ("todos.json", "iocs.json"):
        (case / name).write_text("[]")
    (case / "timeline.json").write_text(json.dumps([EVENT]))
    (case / "findings.json").write_text(json.dumps([dict(FINDING, iocs=list(field))]))
    sign_approved(case)
    key = signing._KEYS[(str(case), "tester")]
    pub = keys.b64(keys.public_raw(key))
    d = [{"item_id": IOC["id"], "type": "ioc", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(IOC, "ioc")}]  # fmt: skip
    bodies = ledger.prepare(CASE, d, "tester", pub, "cli", IOC["approved_at"])
    with ledger.case_lock(CASE) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    (case / "iocs.json").write_text(json.dumps([IOC], indent=2))
    return case


def _args(route, **kw):
    a = dict(case=None, full=False, executive_summary=False, report_timeline=False,
             from_date=None, to_date=None, ioc=False, status_brief=False,
             report_findings=None, save=f"{route}.txt")  # fmt: skip
    a.update({"ioc": {"ioc": True}, "timeline": {"report_timeline": True},
              "findings": {"report_findings": FINDING["id"]},
              "executive_summary": {"executive_summary": True},
              "status_brief": {"status_brief": True},
              "full": {"full": True}}[route])  # fmt: skip
    a.update(kw)
    return Namespace(**a)


def _save(case, route):
    """(how it ended, the saved text or None, stderr)."""
    out, err, ended = io.StringIO(), io.StringIO(), "returned"
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rep.cmd_report(_args(route), IDENTITY)
        except SystemExit as e:
            ended = f"SystemExit({e.code})"
    path = case / "reports" / f"{route}.txt"
    return ended, (path.read_text() if path.exists() else None), err.getvalue()


BAD = {  # (file, what is written in it, what the refusal says about it)
    "iocs.json that won't parse (VALUE only in its record)":
        ("iocs.json", None, "couldn't be read"),
    "iocs.json null": ("iocs.json", "null", "holds null, not a list of records"),
    "iocs.json 7": ("iocs.json", "7", "holds a number, not a list of records"),
    "iocs.json true": ("iocs.json", "true", "holds a boolean, not a list of records"),
    "iocs.json a list of strings": ("iocs.json", json.dumps([VALUE]),
                                    "holds a list with an entry that isn't a record"),
    "findings.json that won't parse": ("findings.json", None, "couldn't be read"),
    "findings.json null": ("findings.json", "null", "holds null, not a list of records"),
    "findings.json 7": ("findings.json", "7", "holds a number, not a list of records"),
    "findings.json true": ("findings.json", "true",
                           "holds a boolean, not a list of records"),
}  # fmt: skip


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("row", BAD)
def test_a_file_that_is_not_a_list_of_records_refuses_the_save(
    tmp_path, monkeypatch, row, route
):
    case = _case(tmp_path, monkeypatch)
    name, text, why = BAD[row]
    path = case / name
    path.write_text(path.read_text().rstrip().rstrip("]") if text is None else text)
    ended, saved, err = _save(case, route)
    assert (ended, saved) == ("SystemExit(1)", None), (ended, saved)
    assert "Traceback" not in err, err
    if (route, name) == ("findings", "findings.json"):
        # the finding asked for can't be read, so the report stops before it
        # saves anything, as it always has
        assert f"Not found: {FINDING['id']}" in err, err
        return
    assert f"Error: report not saved. {path} {why}" in err, err
    assert "vhir review --findings --verify" in err and "vhir restore" in err, err


@pytest.mark.parametrize("route", ROUTES)
def test_an_absent_iocs_json_saves(tmp_path, monkeypatch, route):
    case = _case(tmp_path, monkeypatch, field=[{"value": VALUE, "type": "domain-name"}])
    (case / "iocs.json").unlink()
    ended, saved, err = _save(case, route)
    assert ended == "returned" and saved is not None, (ended, err)
    assert VALUE not in saved, saved


@pytest.mark.parametrize("route", ("ioc", "findings"))
def test_an_iocs_json_past_the_verify_cap_saves_defanged(tmp_path, monkeypatch, route):
    case = _case(tmp_path, monkeypatch)  # VALUE only in the IOC record
    path = case / "iocs.json"
    path.write_text(path.read_text() + " " * (17 << 20))
    ended, saved, err = _save(case, route)
    assert ended == "returned" and saved is not None, (ended, err)
    assert VALUE not in saved, saved
    if route == "findings":
        assert "c2[.]example[.]net" in saved, saved


@pytest.mark.parametrize("route", ROUTES)
def test_an_unreadable_todos_json_doesnt_stop_a_report_that_doesnt_print_it(
    tmp_path, monkeypatch, route
):
    case = _case(tmp_path, monkeypatch)
    (case / "todos.json").write_bytes(b'[{"id": "TODO-1", "description": "\xff"}]')
    ended, saved, err = _save(case, route)
    assert ended == "returned" and saved is not None, (ended, err)
    assert VALUE not in saved, saved


@pytest.mark.parametrize("route", ("findings", "timeline"))
def test_a_record_written_after_the_view_is_read_is_defanged(
    tmp_path, monkeypatch, route
):
    case = _case(tmp_path, monkeypatch)
    real = rep.approved_view

    def view_then_record(case_dir):
        view = real(case_dir)
        late = dict(IOC, id="IOC-tester-002", value=LATE, status="DRAFT",
                    manually_reviewed=False)  # fmt: skip
        records = json.loads((case_dir / "iocs.json").read_text())
        (case_dir / "iocs.json").write_text(json.dumps([*records, late]))
        return view

    monkeypatch.setattr(rep, "approved_view", view_then_record)
    ended, saved, err = _save(case, route)
    assert ended == "returned" and saved is not None, (ended, err)
    assert LATE not in saved, saved
    assert "late[.]example[.]net" in saved, saved


@pytest.mark.parametrize(
    "route",
    ("ioc", "findings", "timeline", "executive_summary", "status_brief", "full"),
)
def test_each_saved_report_reads_the_approved_view_once(tmp_path, monkeypatch, route):
    case = _case(tmp_path, monkeypatch)
    real, calls = rep.approved_view, []

    def counted(case_dir):
        calls.append(case_dir)
        return real(case_dir)

    monkeypatch.setattr(rep, "approved_view", counted)
    ended, saved, err = _save(case, route)
    assert ended == "returned" and saved is not None, (ended, err)
    assert len(calls) == 1, calls
