"""A page of the audit trail (`vhir audit log`, `vhir review --audit`) read
from each log's tail is read as the full reader reads the whole log: opened
only as a regular file under its own name, split at \\n, \\r\\n and a lone \\r,
each line within LINE_CAP. What the tail can't read that way is read whole by
the full reader, so a page is refused, or shown, exactly as a full read is."""

from __future__ import annotations

import contextlib
import io
import json
import os
from argparse import Namespace

import pytest

from vhir_cli.case_io import LINE_CAP
from vhir_cli.commands import audit_cmd
from vhir_cli.commands.review import cmd_review

from .test_approval_checks import _within

POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)


def _entry(n: int, ts: str | None = None) -> dict:
    return {"ts": ts or f"2026-10-13T{n // 3600:02d}:{n // 60 % 60:02d}:{n % 60:02d}Z",
            "tool": "run_command", "audit_id": f"sift-tester-{n:06d}"}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    c = tmp_path / "case"
    (c / "audit").mkdir(parents=True)
    (c / "CASE.yaml").write_text("case_id: TL-1\nname: TL-1\n")
    trail = "".join(json.dumps(_entry(n)) + "\n" for n in range(3000))
    (c / "audit" / "sift-mcp.jsonl").write_text(trail)
    return c


def _page_and_full(case):
    """What a page of 20 and a full read give: ids, warnings, unread logs."""

    def read(limit):
        err, unread = io.StringIO(), []
        with contextlib.redirect_stderr(err):
            got = audit_cmd._load_audit_entries(case, limit, unread=unread)
        return [e.get("audit_id") for e in got][-20:], err.getvalue(), unread

    return read(20), read(None)


@POSIX
def test_a_fifo_log_is_named_and_skipped_on_a_page_as_in_a_full_read(case):
    os.mkfifo(case / "audit" / "wintools-mcp.jsonl")
    status, (page, full) = _within(lambda: _page_and_full(case))
    assert status == "ok"
    assert page == full
    assert page[2] == ["audit/wintools-mcp.jsonl (not a regular file)"]


def _read_measured(case, limit):
    """A page (`limit`) or a full read in a child: ids, warnings, unread logs,
    and the child's peak growth in MiB."""

    def run():
        import resource

        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        err, unread = io.StringIO(), []
        with contextlib.redirect_stderr(err):
            got = audit_cmd._load_audit_entries(case, limit, unread=unread)
        grew = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) >> 10
        return ([e.get("audit_id") for e in got][-20:], err.getvalue(), unread), grew

    status, got = _within(run, timeout=60.0)
    assert status == "ok", got
    return got


@POSIX
@pytest.mark.parametrize("over", [0, 1])
def test_a_long_line_without_a_newline_reads_on_a_page_as_in_a_full_read(case, over):
    """The log's last line has no \\n and is LINE_CAP bytes long, or one more:
    at the cap it's read (a corrupt line), past it the log is refused at that
    line, by name, on a page as in a full read, and a page costs no more."""
    with open(case / "audit" / "sift-mcp.jsonl", "ab") as f:
        f.write(b"x" * (LINE_CAP + over))
    page, page_mib = _read_measured(case, 20)
    full, full_mib = _read_measured(case, None)
    assert page == full
    if over:
        assert page[2] == ["audit/sift-mcp.jsonl (line 3001 is longer than 16 MiB)"]
        assert page[0][-1] == "sift-tester-002999"  # read before the line
    else:
        assert page[2] == [] and "1 corrupt JSONL line(s) skipped" in page[1]
    assert page_mib <= full_mib + 8, (page_mib, full_mib)


def test_a_log_of_lone_cr_lines_reads_on_a_page_as_in_a_full_read(case):
    data = "\r".join(json.dumps(_entry(n)) for n in range(3000, 3100)) + "\r"
    (case / "audit" / "wintools-mcp.jsonl").write_text(data, newline="")
    page, full = _page_and_full(case)
    assert page == full
    assert page[0][-1] == "sift-tester-003099" and page[1] == "" and page[2] == []


def test_a_log_out_of_time_order_in_its_tail_is_read_whole(case):
    """Its tail isn't in time order: the whole log is read, so its newest
    entry by time (written early) is on the page, as in a full read."""
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        f.write(json.dumps(_entry(9999, "2026-10-12T00:00:00Z")) + "\n")
    with open(case / "audit" / "sift-mcp.jsonl", "r+") as f:
        lines = f.readlines()
        lines.insert(0, json.dumps(_entry(8888, "2027-01-01T00:00:00Z")) + "\n")
        f.seek(0)
        f.writelines(lines)
    page, full = _page_and_full(case)
    assert page == full and page[0][-1] == "sift-tester-008888"


def test_a_ts_that_isnt_text_reads_on_a_page_as_in_a_full_read(case):
    """The tail itself never compares it: the full reader decides, as alone."""
    with open(case / "audit" / "sift-mcp.jsonl", "a") as f:
        f.write(json.dumps({"ts": 5, "audit_id": "sift-tester-bad"}) + "\n")

    def outcome(limit):
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                audit_cmd._load_audit_entries(case, limit)
        except TypeError as e:
            return f"TypeError: {e}"
        return "read"

    assert (
        outcome(20) == outcome(None) == "TypeError: an audit entry's ts isn't text: 5"
    )


@POSIX
def test_review_audit_names_a_fifo_log_and_never_waits_on_it(case, monkeypatch):
    monkeypatch.setattr("vhir_cli.commands.review.get_case_dir", lambda *a: case)
    os.mkfifo(case / "audit" / "wintools-mcp.jsonl")

    def run():
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            cmd_review(Namespace(case=None, audit=True, limit=20), {})
        return (
            "sift-tester-002999" in out.getvalue(),
            "isn't a regular file" in err.getvalue(),
        )

    assert _within(run) == ("ok", (True, True))
