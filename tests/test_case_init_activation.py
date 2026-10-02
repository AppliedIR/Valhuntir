"""Creating a case says that it became the active case, and which was before.

`case init` (the CLI and case-mcp's case_init, through _case_init_data)
moves the active-case pointer that every session sharing it follows, and
said nothing: another examiner's session switched cases silently.
"""

from __future__ import annotations

import argparse

import pytest

from vhir_cli import case_io, main


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


def _point_at(home, case_id):
    (home / ".vhir" / "active_case").write_text(str(home / "cases" / case_id))


def test_the_result_names_the_switch(home):
    _point_at(home, "CASE-A")
    data = main._case_init_data(
        name="b", examiner="tester", cases_dir=str(home / "cases"), case_id="CASE-B"
    )
    assert data["activation"] == {"active": "CASE-B", "previous": "CASE-A"}


def test_the_cli_says_so_on_its_own_line(home, capsys):
    _point_at(home, "CASE-A")
    args = argparse.Namespace(
        name="c", case_id="CASE-C", description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})
    lines = capsys.readouterr().out.splitlines()
    assert "Active case is now CASE-C (was CASE-A)" in lines
    # Scripts read this line: the switch must not be folded into it.
    assert [x for x in lines if "Case initialized" in x] == ["Case initialized: CASE-C"]


def test_no_case_was_active_before(home, capsys):
    data = main._case_init_data(
        name="b", examiner="tester", cases_dir=str(home / "cases"), case_id="CASE-B"
    )
    assert data["activation"] == {"active": "CASE-B", "previous": None}
    args = argparse.Namespace(
        name="c", case_id="CASE-C", description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})
    assert (
        "Active case is now CASE-C (was CASE-B)" in capsys.readouterr().out.splitlines()
    )


def test_a_pointer_that_cannot_be_written_is_not_reported_as_a_switch(
    home, monkeypatch, capsys
):
    _point_at(home, "CASE-A")

    real = case_io._atomic_write

    def write(path, text):
        if path.name == "active_case":
            raise OSError("read-only")
        real(path, text)

    monkeypatch.setattr(case_io, "_atomic_write", write)
    data = main._case_init_data(
        name="b", examiner="tester", cases_dir=str(home / "cases"), case_id="CASE-B"
    )
    assert "activation" not in data
    args = argparse.Namespace(
        name="c", case_id="CASE-C", description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})
    out = capsys.readouterr().out
    assert "Active case is now" not in out
    assert "could not be made the active case" in out
