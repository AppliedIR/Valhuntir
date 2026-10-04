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


def test_an_undecodable_pointer_is_still_switched(home):
    pointer = home / ".vhir" / "active_case"
    pointer.write_bytes(b"/home/x/cases/\xff\xfe-CASE-A")
    data = main._case_init_data(
        name="b", examiner="tester", cases_dir=str(home / "cases"), case_id="CASE-B"
    )
    assert data["activation"] == {"active": "CASE-B", "previous": None}
    assert pointer.read_text() == str((home / "cases" / "CASE-B").resolve())


def _init_cli(home, capsys, case_id):
    args = argparse.Namespace(
        name="x", case_id=case_id, description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})
    return capsys.readouterr().out.splitlines()


def test_an_override_naming_another_case_is_said_to_still_apply(
    home, capsys, monkeypatch
):
    """get_case_dir() reads VHIR_CASE_DIR before the pointer, so the shell
    keeps working on that case after the switch."""
    other = home / "cases" / "CASE-A"
    other.mkdir(parents=True)
    monkeypatch.setenv("VHIR_CASE_DIR", str(other))
    lines = _init_cli(home, capsys, "CASE-B")
    assert "Active case is now CASE-B" in lines
    (note,) = [x for x in lines if "VHIR_CASE_DIR" in x]
    assert str(other) in note and "still overrides" in note
    assert case_io.get_case_dir() == other  # what the note warns about


def test_an_override_naming_the_new_case_or_none_says_nothing(
    home, capsys, monkeypatch
):
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    assert not [x for x in _init_cli(home, capsys, "CASE-B") if "VHIR_CASE_DIR" in x]
    monkeypatch.setenv("VHIR_CASE_DIR", str(home / "cases" / "CASE-C"))
    assert not [x for x in _init_cli(home, capsys, "CASE-C") if "VHIR_CASE_DIR" in x]


@pytest.mark.parametrize("spelling", ["trailing slash", "through a symlink"])
def test_the_new_case_spelled_differently_says_nothing(
    home, capsys, monkeypatch, spelling
):
    new = home / "cases" / "CASE-D"
    if spelling == "trailing slash":
        override = f"{new}/"
    else:
        (home / "alias").symlink_to(home / "cases", target_is_directory=True)
        override = str(home / "alias" / "CASE-D")
    monkeypatch.setenv("VHIR_CASE_DIR", override)
    assert not [x for x in _init_cli(home, capsys, "CASE-D") if "VHIR_CASE_DIR" in x]


def test_an_override_that_cannot_be_resolved_still_lets_init_finish(
    home, capsys, monkeypatch
):
    """A symlink loop: resolve() raises after the case exists and is active."""
    monkeypatch.setenv("VHIR_CASE_DIR", str(home / "loop"))
    real = main.Path.resolve

    def resolve(self, *a, **k):
        if self.name == "loop":
            raise RuntimeError("Symlink loop from 'loop'")
        return real(self, *a, **k)

    monkeypatch.setattr(main.Path, "resolve", resolve)
    lines = _init_cli(home, capsys, "CASE-E")
    assert "Active case is now CASE-E" in lines
    assert [x for x in lines if "VHIR_CASE_DIR" in x]
