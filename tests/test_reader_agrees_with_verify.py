"""The reader every report reads its record files through agrees with verify,
which reads findings, timeline and iocs.json on its own. Each of the 20 forms
of a file the reader can't read, in each verified file, on a DRAFT case and on
a signed case: verify raises nothing, and each file verify can't read is one
the reader names too. An empty or blank file is a case-level failure to
neither: verify reads it as no records, as signing does, and the reader names
it empty, not damaged. A decided record with no id, and an id two records
use, are verify's to report: the reader reads the file, and the executive
summary has no header and withholds the approved view. A list with an entry
that isn't a record is one both name.

test_blank_case_file_signing.py, which pins how signing reads a blank file,
passes unchanged. The other places that read a case file as something other
than a list of records (CASE.yaml, evidence.json, the ledger) aren't the
reader's and aren't in these rows."""

from __future__ import annotations

import json

import pytest

from tests.test_report_stop_matrix import (
    FORMS,
    VERIFIED,
    _fixture,
    _lines,
    _run,
    _spoil,
)
from vhir_cli import case_io
from vhir_cli.ledger_verify import verify_case

W = "withheld: the case fails verification (see below)"
KINDS = ("draft", "signed")
# the forms verify reads as no list of records (CASE_FILE_UNREADABLE); in the
# other 6 it reads the file (a list: MALFORMED_RECORD, or empty: no records) or,
# for a dangling link, skips it as absent, so those cells name nothing to agree on
VERIFY_UNREADABLE = {
    "null", "number", "boolean", "string", "dict", "not-utf8", "unparseable",
    "nested", "directory", "fifo", "symlink-valid", "hard-link",
    "permission-denied",
}  # fmt: skip


def _case(kind, tmp_path, monkeypatch):
    return _fixture(kind, tmp_path, monkeypatch)


def _codes(result, code):
    return [msg for c, msg in result.failures if c == code]


def _whys(case):
    return {n: f.why for n, f in case_io.read_record_files(case).items() if f.why}


DAMAGE = [
    pytest.param(kind, name, form, id=f"{kind}-{name}-{form}")
    for kind in KINDS
    for name in VERIFIED
    for form in FORMS
]


@pytest.mark.parametrize("kind,name,form", DAMAGE)
def test_each_file_verify_cant_read_the_reader_names(
    tmp_path, monkeypatch, kind, name, form
):
    case = _case(kind, tmp_path, monkeypatch)
    _spoil(case / name, form)
    result = verify_case(case)
    unread = {msg.split(" ", 1)[0] for msg in _codes(result, "CASE_FILE_UNREADABLE")}
    whys = _whys(case)
    assert FORMS.keys() > VERIFY_UNREADABLE, VERIFY_UNREADABLE - FORMS.keys()
    if form not in VERIFY_UNREADABLE:  # not a cell: verify names no file
        assert unread == set(), (unread, result.failures)
        return
    assert unread == {name}, (unread, result.failures)
    assert name in whys, (whys, result.failures)


BLANK = [
    pytest.param(kind, name, form, id=f"{kind}-{name}-{form}")
    for kind in KINDS
    for name in VERIFIED
    for form in ("empty", "blank")
]


@pytest.mark.parametrize("kind,name,form", BLANK)
def test_an_empty_file_is_no_records_to_verify(tmp_path, monkeypatch, kind, name, form):
    case = _case(kind, tmp_path, monkeypatch)
    _spoil(case / name, form)
    result = verify_case(case)
    unread = [
        m for m in _codes(result, "CASE_FILE_UNREADABLE") if m.startswith(f"{name} ")
    ]
    assert unread == [], result.failures
    assert _whys(case).get(name) == case_io.EMPTY_FILE


def _approved_no_id(first):
    return {"status": "APPROVED", "title": "No id"}


def _rejected_no_id(first):
    return {"status": "REJECTED", "title": "No id"}


def _duplicate_id(first):
    return {**first, "status": "DRAFT"}


RECORD = {"approved-no-id": ("MALFORMED_RECORD", _approved_no_id),
          "rejected-no-id": ("MALFORMED_RECORD", _rejected_no_id),
          "duplicate-id": ("DUPLICATE_ID", _duplicate_id)}  # fmt: skip
RECORDS = [
    pytest.param(kind, name, what, id=f"{kind}-{name}-{what}")
    for kind in KINDS
    for name in VERIFIED
    for what in RECORD
]


@pytest.mark.parametrize("kind,name,what", RECORDS)
def test_a_record_verify_rejects_is_verifys_to_report(
    tmp_path, monkeypatch, kind, name, what
):
    case = _case(kind, tmp_path, monkeypatch)
    code, extra = RECORD[what]
    path = case / name
    held = json.loads(path.read_text())
    path.write_text(json.dumps([*held, extra(held[0])]))
    result = verify_case(case)
    assert [m for m in _codes(result, code) if name in m], result.failures
    assert name not in _whys(case)
    res = _run(case, "executive_summary", False)
    assert res["raised"] is None, res["raised"]
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    for line in _lines(res["out"] + res["err"]):
        assert not any(line.startswith(f"{n} ") for n in (*VERIFIED, "todos.json")), (
            line
        )
    assert f"Approved (verified): {W}" in _lines(res["out"]), res["out"]


MIXED = [
    pytest.param(kind, name, id=f"{kind}-{name}") for kind in KINDS for name in VERIFIED
]


@pytest.mark.parametrize("kind,name", MIXED)
def test_an_entry_that_isnt_a_record_both_name(tmp_path, monkeypatch, kind, name):
    case = _case(kind, tmp_path, monkeypatch)
    _spoil(case / name, "mixed-list")
    result = verify_case(case)
    entry = [m for m in _codes(result, "MALFORMED_RECORD")
             if m.startswith(f"{name} entry ") and m.endswith(" isn't a record")]  # fmt: skip
    assert entry, result.failures
    assert _whys(case).get(name) == case_io.NOT_A_RECORD
