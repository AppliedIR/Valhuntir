"""The edges of reading record files that no other row reaches: a read error
the reader has no fixed phrase for, a file gone between the check and the
read, a findings report that matches nothing while another file is
unreadable, and IOC records that hold no value."""

from __future__ import annotations

import contextlib
import errno
import io
import os

import pytest

from tests.test_report_save_refused import _args, _case, _spoil
from vhir_cli import case_io, defang
from vhir_cli.commands import report as rep

IDENTITY = {"os_user": "testuser", "examiner": "tester", "examiner_source": "env",
            "analyst": "tester", "analyst_source": "env"}  # fmt: skip
EIO = {  # (the error the read raises, its kind)
    "the OS's words": (OSError(errno.EIO, os.strerror(errno.EIO)),
                       os.strerror(errno.EIO).lower()),
    "no words: its type": (OSError(errno.EIO), "oserror"),
}  # fmt: skip


def _raising(monkeypatch, exc):
    def read(path):
        raise exc

    monkeypatch.setattr(case_io, "read_case_document", read)


@pytest.mark.parametrize("row", EIO)
def test_a_read_error_without_a_fixed_phrase_is_named_in_its_own_words(
    tmp_path, monkeypatch, row
):
    exc, kind = EIO[row]
    assert case_io.refusal_kind(exc) == kind
    path = tmp_path / "iocs.json"
    path.write_text("[]")
    _raising(monkeypatch, exc)
    got = case_io.read_record_file(path)
    why = f"couldn't be read ({kind})"
    assert (got.records, got.why, got.absent) == ([], why, False)


def test_a_file_gone_between_the_check_and_the_read_is_absent(tmp_path, monkeypatch):
    path = tmp_path / "iocs.json"
    path.write_text("[]")  # there when the reader looks for it
    _raising(monkeypatch, FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT)))
    got = case_io.read_record_file(path)
    assert (got.records, got.why, got.absent) == ([], "", True)
    assert case_io.unreadable_of({"iocs.json": got}) == []


@pytest.mark.parametrize("save", (None, "findings.txt"), ids=("shown", "saved"))
def test_no_matching_finding_with_another_file_unreadable_prints_the_block(
    tmp_path, monkeypatch, save
):
    """The header and the block print; it ends as an unreadable file ends a
    report, not at "No matching findings."."""
    case = _case(tmp_path, monkeypatch)
    _spoil(case / "iocs.json", "null")
    out, err, ended = io.StringIO(), io.StringIO(), "returned"
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rep.cmd_report(_args("findings", report_findings="F-tester-999", save=save),
                           IDENTITY)  # fmt: skip
        except SystemExit as e:
            ended = f"SystemExit({e.code})"
    out, err = out.getvalue(), err.getvalue()
    lines = [line for line in out.splitlines() if line.strip()]
    assert lines[:1] == ["iocs.json holds null, not a list of records"], out
    assert "VERIFICATION" in lines, out
    assert "Not found: F-tester-999" in err and "No matching findings." in err, err
    assert ended == "SystemExit(1)" and "Traceback" not in out + err, (ended, err)
    assert not (case / "reports" / "findings.txt").exists()


RECORD = {"id": "IOC-tester-001", "value": "c2.example.net", "type": "domain-name"}
NO_VALUE = {  # a record that holds no value, before one that does
    "not a dict": 7,
    "a string": "c2.example.net",
    "no value key": {"id": "IOC-tester-000", "type": "domain-name"},
}  # fmt: skip


@pytest.mark.parametrize("row", NO_VALUE)
def test_a_record_with_no_value_is_passed_over(row):
    got = defang.walk_records([NO_VALUE[row], RECORD])
    assert got == defang.walk_records([RECORD])
    assert [v for v, _, _ in got] == ["c2.example.net"]
