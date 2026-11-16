"""The stop matrix: each of the 20 forms of a record file the reader can't
read, in each of findings, timeline, iocs and todos.json, in each of the six
report modes, shown and saved, on a DRAFT case and on a signed case. Where the
mode reads the file, the first lines name it with its fixed phrase (on stderr
in --full), its remediation line follows, the verification block prints, it
exits 1, nothing raises, and reports/ (which always holds a prior report) is
unchanged; a refused save says `Report not saved:` on stderr, and --full's
stdout is JSON carrying `unreadable`. A damaged todos.json doesn't stop
--timeline, --findings or --ioc, which don't read it. Two damaged files are
named in order, then their remediation lines. A 500-deep list parses and is a
list with an entry that isn't a record. Mode 000 doesn't refuse root, so that
form is skipped under euid 0."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import traceback

import pytest
import yaml

from tests.test_report_save_refused import IDENTITY, PRIOR, _args
from tests.test_report_save_refused import _case as _signed_case
from vhir_cli.commands import report as rep

CASE = "INC-2026-STOP"
VERIFIED = ("findings.json", "timeline.json", "iocs.json")
FILES = (*VERIFIED, "todos.json")
MODES = ("timeline", "findings", "ioc", "executive_summary", "status_brief", "full")
TODO_MODES = ("executive_summary", "status_brief", "full")  # the modes that read it
TODO = {"todo_id": "TODO-tester-001", "status": "open", "description": "Pull logs"}
EMPTY = "is empty, not a list of records"
NOT_A_RECORD = "holds a list with an entry that isn't a record"
DIR, LINK, CUT, MIXED, MODE000, TO_VALID, HARD_LINK, FIFO = (object() for _ in range(8))
FORMS = {  # form: (what is written in the file, the phrase the header gives it)
    "null": ("null", "holds null, not a list of records"),
    "number": ("7", "holds a number, not a list of records"),
    "boolean": ("true", "holds a boolean, not a list of records"),
    "list-of-strings": ('["c2.example.net"]', NOT_A_RECORD),
    "empty": ("", EMPTY),
    "blank": (" \n\t \n", EMPTY),
    "not-utf8": (b'[{"id": "X-1", "note": "\xff"}]', "couldn't be read (not UTF-8 text)"),
    "directory": (DIR, "couldn't be read (it is a folder)"),
    "dangling-symlink": (LINK, "couldn't be read (it is a symbolic link)"),
    "string": ('"records"', "holds a string, not a list of records"),
    "list-of-numbers": ("[1]", NOT_A_RECORD),
    "mixed-list": (MIXED, NOT_A_RECORD),
    "dict": ('{"id": "X-1"}', "holds an object, not a list of records"),
    "unparseable": (CUT, "couldn't be read (not valid JSON)"),
    "permission-denied": (MODE000, "couldn't be read (permission denied)"),
    "symlink-valid": (TO_VALID, "couldn't be read (it is a symbolic link)"),
    "hard-link": (HARD_LINK, "couldn't be read (another name links to it)"),
    "fifo": (FIFO, "couldn't be read (it isn't a regular file)"),
    "nested": ("[" * 100000 + "]" * 100000, "couldn't be read (nested too deeply)"),
}  # fmt: skip
DEEP = "[" * 500 + "]" * 500  # parses: a list whose one entry is a list
RESTORE = "restore the case from a backup (`vhir restore`)"


def _draft_case(tmp_path, monkeypatch):
    """A finding, an event and an IOC record, all DRAFT; nothing signed."""
    case = tmp_path / CASE
    case.mkdir()
    for name in ("reports", "audit"):
        (case / name).mkdir()
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    meta = {"case_id": CASE, "name": "Stop", "status": "open",
            "created": "2026-10-08T00:00:00Z", "examiner": "tester"}  # fmt: skip
    (case / "CASE.yaml").write_text(yaml.dump(meta))
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    finding = {"id": "F-tester-001", "status": "DRAFT", "title": "Beacon",
               "confidence": "LOW", "observation": "beacons to c2.example.net",
               "interpretation": "C2", "iocs": []}  # fmt: skip
    event = {"id": "T-tester-001", "status": "DRAFT",
             "timestamp": "2026-10-08T09:00:00Z", "description": "DNS query"}  # fmt: skip
    ioc = {"id": "IOC-tester-001", "value": "c2.example.net", "type": "domain-name",
           "status": "DRAFT", "source_findings": [finding["id"]]}  # fmt: skip
    for name, item in (("findings.json", finding), ("timeline.json", event),
                       ("iocs.json", ioc)):  # fmt: skip
        (case / name).write_text(json.dumps([item], indent=2))
    return case


def _fixture(kind, tmp_path, monkeypatch):
    """The case, with an open todo and a prior report under each mode's name."""
    case = (_draft_case if kind == "draft" else _signed_case)(tmp_path, monkeypatch)
    (case / "todos.json").write_text(json.dumps([TODO]))
    for mode in MODES:
        (case / "reports" / f"{mode}.txt").write_bytes(PRIOR)
    return case


def _spoil(path, form):
    """Leave `path` in `form`."""
    how = FORMS[form][0] if form in FORMS else form
    if how is MODE000 and os.geteuid() == 0:
        pytest.skip("mode 000 doesn't refuse root: the form is skipped under euid 0")
    if how in (DIR, LINK, TO_VALID, FIFO):
        if how is TO_VALID:
            real = path.with_name(path.name + ".real")
            real.write_bytes(path.read_bytes())
        path.unlink()
        if how is DIR:
            path.mkdir()
        elif how is LINK:
            path.symlink_to(path.with_name("no-such-file.json"))
        elif how is TO_VALID:
            path.symlink_to(real)
        else:
            os.mkfifo(path)
    elif how is CUT:
        path.write_text(path.read_text().rstrip().rstrip("]"))
    elif how is MIXED:
        path.write_text(json.dumps([*json.loads(path.read_text())[:1], 1]))
    elif how is MODE000:
        path.chmod(0)
    elif how is HARD_LINK:
        os.link(path, path.with_name(path.name + ".2"))
    else:
        path.write_bytes(how if isinstance(how, bytes) else how.encode())


def _remedy(name, form, kind):
    """5b.4.2's line for `name` in `form` on a `kind` case. The signed case's
    ledger holds an approved item of each verified file; the DRAFT case's
    none. verify reads only the three verified files, and passes over a name
    with nothing behind it (a dangling symlink)."""
    if FORMS[form][1] == EMPTY:
        if kind == "signed" and name in VERIFIED:
            return (f"{name} is empty, but the case's approval records show it held"
                    f" approved items. {RESTORE[0].upper()}{RESTORE[1:]}.")  # fmt: skip
        return (f"{name} holds no records. If the case never held any, write [] to"
                f" it; otherwise {RESTORE}.")  # fmt: skip
    if name in VERIFIED and form != "dangling-symlink":
        return ("Run `vhir review --findings --verify` to see the file's state;"
                f" repair it, or {RESTORE}.")  # fmt: skip
    return f"Repair {name}, or {RESTORE}."


def _listing(case):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((case / "reports").iterdir())}  # fmt: skip


def _run(case, mode, save):
    """How `vhir report` in `mode` ended (rc, or the traceback it raised),
    its stdout and stderr, and reports/ before and after."""
    before = _listing(case)
    out, err, rc, raised = io.StringIO(), io.StringIO(), 0, None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rep.cmd_report(_args(mode, save=f"{mode}.txt" if save else None), IDENTITY)
        except SystemExit as e:
            rc = e.code
        except Exception as e:  # noqa: BLE001  (shown in the assertion's message)
            raised = "".join(traceback.format_exception(type(e), e, e.__traceback__))
    return {"rc": rc, "raised": raised, "out": out.getvalue(), "err": err.getvalue(),
            "before": before, "after": _listing(case)}  # fmt: skip


def _lines(text):
    return [line for line in text.splitlines() if line.strip()]


def _stopped(res, mode, save, named):
    """`named`: [(file, why, remediation)], in the header's order."""
    assert res["raised"] is None, res["raised"]
    for stream in ("out", "err"):
        assert "Traceback" not in res[stream], res[stream][-800:]
    header = [f"{n} {why}" for n, why, _ in named] + [r for _, _, r in named]
    first = _lines(res["err"] if mode == "full" else res["out"])
    assert first[: len(header)] == header, first[: len(header) + 2]
    if mode == "full":
        body = json.loads(res["out"])
        assert body["unreadable"] == [{"file": n, "why": why} for n, why, _ in named]
        assert "verification" in body
    else:
        assert "VERIFICATION" in res["out"].splitlines(), res["out"][-800:]
        assert "PROVENANCE" in res["out"].splitlines(), res["out"][-800:]
    assert res["rc"] == 1, (res["rc"], res["err"][-400:])
    assert res["after"] == res["before"], "reports/ changed"
    refusal = [x for x in res["err"].splitlines() if x.startswith("Report not saved:")]
    if save:
        names = [n for n, _, _ in named]
        listed = names[0] if len(names) == 1 else " and ".join(names)
        assert refusal == [f"Report not saved: {listed} can't be read."], res["err"]
    else:
        assert refusal == [], res["err"]
    assert "Saved to:" not in res["out"] + res["err"]


CELLS = [
    pytest.param(kind, name, form, mode, save,
                 id=f"{kind}-{name}-{form}-{mode}-{'save' if save else 'show'}")
    for kind in ("draft", "signed") for name in FILES for form in FORMS
    for mode in MODES for save in (False, True)
    if name != "todos.json" or mode in TODO_MODES
]  # fmt: skip


@pytest.mark.parametrize("kind,name,form,mode,save", CELLS)
def test_a_file_the_mode_reads_stops_it(tmp_path, monkeypatch, kind, name, form, mode, save):  # fmt: skip
    case = _fixture(kind, tmp_path, monkeypatch)
    _spoil(case / name, form)
    res = _run(case, mode, save)
    _stopped(res, mode, save, [(name, FORMS[form][1], _remedy(name, form, kind))])


UNREAD = [
    pytest.param(kind, form, mode, save,
                 id=f"{kind}-{form}-{mode}-{'save' if save else 'show'}")
    for kind in ("draft", "signed") for form in FORMS
    for mode in MODES if mode not in TODO_MODES for save in (False, True)
]  # fmt: skip


@pytest.mark.parametrize("kind,form,mode,save", UNREAD)
def test_a_damaged_todos_json_doesnt_stop_a_mode_that_doesnt_read_it(
    tmp_path, monkeypatch, kind, form, mode, save
):
    case = _fixture(kind, tmp_path, monkeypatch)
    _spoil(case / "todos.json", form)
    res = _run(case, mode, save)
    assert res["raised"] is None, res["raised"]
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    assert not any(x.startswith("todos.json ") for x in res["out"].splitlines())
    assert "Traceback" not in res["out"] + res["err"]
    saved = (case / "reports" / f"{mode}.txt").read_bytes()
    if save:
        assert saved != PRIOR, "the report wasn't saved"
    else:
        assert res["after"] == res["before"], "reports/ changed"


TWO = {  # the mode, then the two damaged files and their forms, in header order
    "exec-findings-unparseable-todos-null":
        ("executive_summary", (("findings.json", "unparseable"), ("todos.json", "null"))),
    "exec-timeline-blank-iocs-dict":
        ("executive_summary", (("timeline.json", "blank"), ("iocs.json", "dict"))),
    "ioc-findings-unparseable-iocs-dict":
        ("ioc", (("findings.json", "unparseable"), ("iocs.json", "dict"))),
    "findings-findings-unparseable-iocs-dict":
        ("findings", (("findings.json", "unparseable"), ("iocs.json", "dict"))),
}  # fmt: skip


@pytest.mark.parametrize("save", (False, True), ids=("show", "save"))
@pytest.mark.parametrize("kind", ("draft", "signed"))
@pytest.mark.parametrize("cell", TWO)
def test_two_damaged_files_are_named_in_order(tmp_path, monkeypatch, cell, kind, save):
    mode, damaged = TWO[cell]
    case = _fixture(kind, tmp_path, monkeypatch)
    for name, form in damaged:
        _spoil(case / name, form)
    res = _run(case, mode, save)
    named = [(n, FORMS[f][1], _remedy(n, f, kind)) for n, f in damaged]
    _stopped(res, mode, save, named)


# the interpreter the 500-deep cells ran on, named in each cell's id
PY = "python{}.{}.{}".format(*sys.version_info[:3])


@pytest.mark.parametrize("save", (False, True), ids=("show", "save"))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", ("draft", "signed"))
@pytest.mark.parametrize("name", ("findings.json", "timeline.json"))
@pytest.mark.parametrize("py", (PY,))
def test_a_500_deep_list_is_a_list_with_an_entry_that_isnt_a_record(
    tmp_path, monkeypatch, py, name, kind, mode, save
):
    assert py == "python{}.{}.{}".format(*sys.version_info[:3]), py
    case = _fixture(kind, tmp_path, monkeypatch)
    _spoil(case / name, DEEP)
    res = _run(case, mode, save)
    _stopped(res, mode, save, [(name, NOT_A_RECORD, _remedy(name, "list-of-numbers", kind))])  # fmt: skip
