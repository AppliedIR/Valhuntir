"""A record file that isn't a list of records is unreadable: it holds no
records, and its `why` is the fixed phrase for what it is. report-mcp reads
the case's record files through the same reader."""

from __future__ import annotations

import pytest

from vhir_cli import case_io

DIR = object()  # in place of the file: a directory
UNREADABLE = {  # (what is written in iocs.json, its why)
    "not-json": ("not json", "couldn't be read (not valid JSON)"),
    "a-dict": ("{}", "holds an object, not a list of records"),
    "a-number": ("7", "holds a number, not a list of records"),
    "a-string": ('"x"', "holds a string, not a list of records"),
    "a-boolean": ("true", "holds a boolean, not a list of records"),
    "null": ("null", "holds null, not a list of records"),
    "a-folder": (DIR, "couldn't be read (it is a folder)"),
}  # fmt: skip


@pytest.mark.parametrize("shape", UNREADABLE)
def test_a_record_file_that_isnt_a_list_of_records_holds_none(tmp_path, shape):
    text, why = UNREADABLE[shape]
    path = tmp_path / "iocs.json"
    if text is DIR:
        path.mkdir()
    else:
        path.write_text(text)
    got = case_io.read_record_files(tmp_path, ("iocs.json",))["iocs.json"]
    assert (got.records, got.why, got.absent) == ([], why, False)
