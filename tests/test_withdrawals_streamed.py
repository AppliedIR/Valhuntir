"""The withdrawn candidates are read from the audit trail line by line, keeping
only the withdrawals, and every audit log is read only if it's a regular file:
a FIFO no one writes to, or a link to a device, is named and skipped, never
waited on or read without end."""

from __future__ import annotations

import contextlib
import io
import json
import os

import pytest

import vhir_cli.case_io as case_io
import vhir_cli.commands.review as review
from vhir_cli.case_io import load_withdrawals

from .test_approval_checks import _within

W = {"ts": "2026-10-07T08:00:00Z", "tool": "record_finding", "examiner": "tester",
     "audit_id": "forensic-tester-001",
     "result_summary": {"status": "WITHDRAWN", "title": "t", "observation": "o",
                        "contradiction": "c", "skeptic_audit_ids": ["sift-tester-001"]}}  # fmt: skip
POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / "audit").mkdir()
    calls = [{"ts": "2026-10-07T07:00:00Z", "tool": "run_command",
              "audit_id": f"sift-tester-{n:03d}"} for n in range(20)]  # fmt: skip
    (tmp_path / "audit" / "sift-mcp.jsonl").write_text(
        "".join(json.dumps(c) + "\n" for c in calls)
    )
    (tmp_path / "audit" / "forensic-mcp.jsonl").write_text(json.dumps(W) + "\n")
    return tmp_path


def test_only_withdrawals_are_kept_and_each_log_is_read_line_by_line(case, monkeypatch):
    opened = []
    real = case_io.open_regular
    monkeypatch.setattr(
        case_io, "open_regular", lambda p: opened.append(p.name) or real(p)
    )
    assert [w["audit_id"] for w in load_withdrawals(case)] == ["forensic-tester-001"]
    assert opened == ["forensic-mcp.jsonl", "sift-mcp.jsonl"]


@POSIX
@pytest.mark.parametrize("bad", ["fifo", "devzero"])
@pytest.mark.parametrize("reader", ["count", "withdrawn view"])
def test_a_log_that_isnt_a_regular_file_is_named_and_skipped(case, capsys, bad, reader):
    path = case / "audit" / "wintools-mcp.jsonl"
    os.mkfifo(path) if bad == "fifo" else path.symlink_to("/dev/zero")
    fn = (lambda: len(load_withdrawals(case))) if reader == "count" else (
        lambda: review._show_withdrawn(case))  # fmt: skip

    def run():  # in a child with memory capped; its output kept for the check
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            try:
                result = fn()
            except SystemExit as e:  # the view never says "none" past an unread log
                result = ("exit", e.code)
        what = ("isn't a regular file (a named pipe, socket or device)." if bad == "fifo"
                else "is a symbolic link, so it wasn't read: a case log is read only "
                "under its own name.")  # fmt: skip
        return (
            result,
            f"Warning: could not read {path}: {path} {what} {case_io.KEPT}"
            in err.getvalue(),
            "Couldn't read audit/wintools-mcp.jsonl (" in out.getvalue(),
        )

    viewed = reader != "count"
    assert _within(run) == ("ok", (("exit", 1) if viewed else 1, True, viewed))


@POSIX
@pytest.mark.parametrize("reader", ["count", "withdrawn view"])
def test_a_log_named_with_terminal_controls_is_named_with_them_shown(case, reader):
    """The warning names a file the case's trail holds: an escape sequence in
    its name (or in the error's text) never reaches the terminal."""
    path = case / "audit" / "wintools-\x1b[2J\x1b[H.jsonl"
    os.mkfifo(path)
    fn = (lambda: len(load_withdrawals(case))) if reader == "count" else (
        lambda: review._show_withdrawn(case))  # fmt: skip

    def run():
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            with contextlib.suppress(SystemExit):
                fn()
        return err.getvalue() + out.getvalue()

    status, err = _within(run)
    assert status == "ok"
    assert "\x1b" not in err
    assert f"could not read {case}/audit/wintools-?[2J?[H.jsonl: " in err


def _over_cap_line(case):
    """forensic-mcp.jsonl, where withdrawals are written, with one line over
    the cap after a withdrawal: the log isn't read past it."""
    with open(case / "audit" / "forensic-mcp.jsonl", "ab") as f:
        f.write(b'{"pad": "' + b"x" * (16 << 20) + b'"}\n')


def test_the_withdrawn_view_names_an_unread_log_and_exits_1_never_none(case):
    _over_cap_line(case)

    def run():
        out = io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(out):
            try:
                review._show_withdrawn(case)
            except SystemExit as e:
                return e.code, out.getvalue()
        return None, out.getvalue()

    status, (code, out) = _within(run)
    assert (status, code) == ("ok", 1)
    assert "No candidate findings withdrawn" not in out
    assert "1 candidate finding(s) withdrawn after challenge" in out  # read before it
    assert (
        "Couldn't read audit/forensic-mcp.jsonl (line 2 is longer than 16 MiB): "
        "a candidate withdrawn there isn't shown." in out
    )


def test_approves_count_says_a_log_went_unread(case, monkeypatch, capsys):
    from argparse import Namespace

    import vhir_cli.commands.approve as approve_mod

    _over_cap_line(case)
    monkeypatch.setattr(approve_mod, "_preflight", lambda *a: True, raising=False)
    monkeypatch.setattr(
        approve_mod,
        "_interactive_review",
        lambda *a, withdrawn_line="", **k: print(withdrawn_line),
    )
    monkeypatch.setattr(approve_mod, "get_case_dir", lambda *a: case, raising=False)
    approve_mod.cmd_approve(
        Namespace(case=None, ids=[], review=False), {"examiner": "tester"}
    )
    assert (
        "1 candidate finding(s) withdrawn after challenge counted; audit/forensic-mcp.jsonl "
        "(line 2 is longer than 16 MiB) couldn't be read, so there may be more — "
        "`vhir review --withdrawn`" in capsys.readouterr().out
    )
