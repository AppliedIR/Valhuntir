"""The case logs that feed an action are read through one reader: a regular
file only, under its own name, line by line, each line and the whole file
capped. A FIFO no one writes to, a device, a folder, a symbolic or second
name, an over-long line and an over-large file are each refused by name, in
bounded memory and time, with the one class's text; lines split as text mode
splits them, so every reader sees the same records."""

from __future__ import annotations

import contextlib
import io
import json
import os
import resource
from datetime import datetime, timezone

import pytest

import vhir_cli.case_io as case_io
from vhir_cli import approval_checks
from vhir_cli.case_io import (
    FILE_BUDGET,
    LINE_CAP,
    CaseFileNotRegular,
    CaseFileTooLarge,
)
from vhir_cli.commands import audit_cmd, evidence, execute

from .test_approval_checks import _within

POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)
BACK = "Put the case's own file back, then try again."
KEEP = "It holds the case's {h}: keep a copy of it before you move it out of the case, then try again."
TEXT = {  # input -> (why, the refusal's text)
    "fifo": ("not a regular file",
             "{p} isn't a regular file (a named pipe, socket or device). " + BACK),
    "folder": ("a folder", "{p} is a folder, not a file. " + BACK),
    "symlink": ("a symbolic link", "{p} is a symbolic link, so it wasn't read: a case "
                "log is read only under its own name. " + BACK),
    "devzero": ("a symbolic link", "{p} is a symbolic link, so it wasn't read: a case "
                "log is read only under its own name. " + BACK),
    "hardlink": ("another name links to it",
                 "{p} has another name linking to it, so it wasn't read. " + BACK),
    "over": ("line 1 is longer than 16 MiB",
             "{p} line 1 is longer than 16 MiB, so the file wasn't read past it. " + KEEP),
    "budget": ("larger than 256 MiB",
               "{p} is larger than 256 MiB, so it wasn't read. " + KEEP),
}  # fmt: skip
TODAY = datetime.now(timezone.utc).strftime("%Y%m%d")


def _quiet(fn):
    """fn's result, or the error it raised, and its stderr."""
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            got = fn()
    except (OSError, case_io.CaseError) as e:
        got = f"raised {type(e).__name__}: {e}"
    return got, err.getvalue()


# reader -> (the file it reads, relative to the case; how to call it)
READERS = {
    "load_approval_log": ("approvals.jsonl", lambda c: case_io.load_approval_log(c)),
    "load_audit_index": ("audit/wintools-mcp.jsonl", lambda c: sorted(case_io.load_audit_index(c))),
    "audit log (trail)": ("audit/wintools-mcp.jsonl", lambda c: len(audit_cmd._load_audit_entries(c))),
    "audit log (approvals)": ("approvals.jsonl", lambda c: len(audit_cmd._load_audit_entries(c))),
    "evidence register": ("audit/wintools-mcp.jsonl", lambda c: evidence._recorded_outputs(c)[1]),
    "vhir exec": ("audit/cli-exec.jsonl", lambda c: execute._next_audit_id(c, "tester")),
    "approval checks": ("audit/wintools-mcp.jsonl", lambda c: sorted(approval_checks.audit_lines(c))),
}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    c = tmp_path / "case"
    (c / "audit").mkdir(parents=True)
    (c / "CASE.yaml").write_text("case_id: CR-1\nname: CR-1\n")
    (c / "audit" / "sift-mcp.jsonl").write_text(
        json.dumps({"audit_id": "sift-tester-001", "ts": "2026-10-07T07:00:00Z"}) + "\n"
    )
    (c / "evidence").mkdir()
    (c / "evidence" / "disk.txt").write_text('{"audit_id": "x"}\n')
    other = tmp_path / "other" / "audit" / "wintools-mcp.jsonl"
    other.parent.mkdir(parents=True)
    other.write_text(json.dumps({"audit_id": "wintools-other-001"}) + "\n")
    return c


def _plant(case, path, bad):
    path.parent.mkdir(parents=True, exist_ok=True)
    if bad == "fifo":
        os.mkfifo(path)  # no writer holds it open
    elif bad == "devzero":
        path.symlink_to("/dev/zero")
    elif bad == "folder":
        path.mkdir()
    elif bad == "symlink":  # another case's log
        path.symlink_to(case.parent / "other" / "audit" / "wintools-mcp.jsonl")
    elif bad == "hardlink":  # the registered evidence
        os.link(case / "evidence" / "disk.txt", path)
    elif bad == "over":
        path.write_bytes(b'{"pad": "' + b"A" * (LINE_CAP + 64) + b'"}\n')
    elif bad == "budget":  # sparse: refused by its size before any read
        with open(path, "wb") as f:
            f.truncate(FILE_BUDGET + 1)


@POSIX
@pytest.mark.parametrize("bad", sorted(TEXT))
@pytest.mark.parametrize("reader", sorted(READERS))
def test_each_reader_refuses_by_name_with_the_one_class(case, reader, bad):
    rel, call = READERS[reader]
    path = case / rel
    _plant(case, path, bad)
    status, (got, err) = _within(lambda: _quiet(lambda: call(case)), timeout=20.0)
    assert status == "ok"
    held = "approval records" if path.name == "approvals.jsonl" else "audit entries"
    why, text = TEXT[bad][0], TEXT[bad][1].format(p=path, h=held)
    cls = CaseFileTooLarge if bad in ("over", "budget") else CaseFileNotRegular
    if reader in ("vhir exec", "load_approval_log"):
        assert got == f"raised {cls.__name__}: {text}"
    elif reader == "approval checks":
        assert got.startswith(
            f"raised AuditUnreadable: The approval checks couldn't read {rel} ({why})"
        )
    elif reader == "evidence register":
        assert got == [f"{rel} can't be read ({text})"]
    else:  # named on stderr, the rest of the case still read
        assert f"Warning: could not read {path}: {text}" in err
        assert "Traceback" not in err


@POSIX
@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_fifo_swapped_in_before_the_open_never_blocks(case, reader, monkeypatch):
    """The check is made on the open descriptor: a FIFO put in place after a
    path check and before the open is still refused, never waited on."""
    rel, call = READERS[reader]
    path = case / rel
    path.write_text(json.dumps({"audit_id": "x"}) + "\n")
    real, swapped = os.open, []

    def racing(p, flags, *a, **k):
        if os.fspath(p) == str(path) and not swapped:
            swapped.append(1)
            os.unlink(path)
            os.mkfifo(path)
        return real(p, flags, *a, **k)

    monkeypatch.setattr(os, "open", racing)
    status, (got, err) = _within(lambda: _quiet(lambda: call(case)), timeout=10.0)
    assert status == "ok"
    assert "a regular file" in f"{got} {err}"


@POSIX
@pytest.mark.parametrize("name", ["findings.json", "iocs.json"])
@pytest.mark.parametrize("swap", [False, True])
def test_verify_never_waits_on_a_case_file(case, name, swap, monkeypatch):
    """The approval check every route runs (get_findings, get_timeline,
    export_bundle, the reports) reads the case's files as the logs are read:
    a FIFO, planted or put in place just before the open, is named, never
    waited on."""
    from vhir_cli import ledger_verify

    (case / "ledger").mkdir()
    approved = [{"id": "F-tester-001", "status": "APPROVED"}]
    (case / "findings.json").write_text(json.dumps(approved))
    (case / "iocs.json").write_text("[]")
    (case / "ledger" / "keys.json").write_text("{}")
    path = case / name
    if swap:
        real, swapped = os.open, []

        def racing(p, flags, *a, **k):
            if os.fspath(p) == str(path) and not swapped:
                swapped.append(1)
                os.unlink(path)
                os.mkfifo(path)
            return real(p, flags, *a, **k)

        monkeypatch.setattr(os, "open", racing)
    else:
        path.unlink()
        os.mkfifo(path)

    def run():
        result = ledger_verify.verify_case(case)
        return [d for _, d in result.failures]

    status, *got = _within(run, timeout=10.0)
    assert status == "ok"
    assert f"{name} couldn't be read ({TEXT['fifo'][1].format(p=path)})" in got[0]


@POSIX
@pytest.mark.parametrize("reader", sorted(READERS))
def test_a_long_line_is_never_held_whole(case, reader):
    """A 64 MiB line costs at most the cap twice over, not the line."""
    rel, call = READERS[reader]
    path = case / rel
    with open(path, "wb") as f:
        f.write(b'{"audit_id": "x", "pad": "' + b"A" * (64 << 20) + b'"}\n')

    def run():
        before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        _quiet(lambda: call(case))
        return (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) // 1024

    status, grew_mib = _within(run, timeout=20.0)
    assert status == "ok" and grew_mib <= 2 * (LINE_CAP >> 20) + 8, grew_mib


@POSIX
def test_lines_split_alike_in_every_reader(case):
    """A log whose lines end in a lone CR is three records to every reader,
    and vhir exec's next id follows them."""
    ids = [f"cliexec-tester-{TODAY}-{n:03d}" for n in (1, 2, 3)]
    data = "\r".join(json.dumps({"audit_id": i, "ts": f"2026-10-0{n}"}) for n, i in
                     enumerate(ids, 1)).encode() + b"\r"  # fmt: skip
    (case / "audit" / "wintools-mcp.jsonl").write_bytes(data)
    (case / "audit" / "cli-exec.jsonl").write_bytes(data)
    (case / "approvals.jsonl").write_bytes(data)

    def run():
        return (
            [i for i in case_io.load_audit_index(case) if i.startswith("cliexec")],
            [e["audit_id"] for e in audit_cmd._load_audit_entries(case) if "cliexec" in e.get("audit_id", "")],
            sorted(i for i in approval_checks.audit_lines(case) if i.startswith("cliexec")),
            [e["audit_id"] for e in case_io.load_approval_log(case)],
            execute._next_audit_id(case, "tester"),
        )  # fmt: skip

    status, got = _within(run)
    assert status == "ok"
    index, entries, trail, approvals, next_id = got
    assert index == trail == approvals == ids
    assert sorted(entries) == sorted(ids * 3)  # wintools, cli-exec, approvals.jsonl
    assert next_id == f"cliexec-tester-{TODAY}-004"


def test_a_line_at_the_cap_is_read_and_one_over_is_refused(tmp_path):
    at = tmp_path / "at.jsonl"
    at.write_bytes(b"A" * LINE_CAP + b"\n" + b"{}\n")
    assert [len(x) for x in case_io.case_lines(at)] == [LINE_CAP + 1, 3]
    over = tmp_path / "over.jsonl"
    over.write_bytes(b"{}\n" + b"A" * (LINE_CAP + 1))  # the last line, no newline
    lines = case_io.case_lines(over)
    assert next(lines) == b"{}\n"
    with pytest.raises(CaseFileTooLarge) as e:
        next(lines)
    assert e.value.line == 2  # never split into records


def test_a_file_that_grows_past_the_budget_while_read_is_refused(tmp_path, monkeypatch):
    log = tmp_path / "grown.jsonl"
    log.write_bytes(b"{}\n" * 10)
    lines = case_io._capped_lines(open(log, "rb"), log)  # opened while it was small
    monkeypatch.setattr(case_io, "FILE_BUDGET", 12)
    with pytest.raises(CaseFileTooLarge) as e:
        list(lines)
    assert e.value.line is None


def test_one_class_for_a_case_file_that_isnt_regular():
    assert not hasattr(case_io, "NotRegularFile")
    assert issubclass(CaseFileNotRegular, OSError)
    assert issubclass(CaseFileNotRegular, case_io.CaseError)
    assert issubclass(CaseFileTooLarge, OSError)
    assert issubclass(CaseFileTooLarge, case_io.CaseError)


# --- case documents: read whole, within DOC_CAP ------------------------------

_ITEMS_IN_256MIB = """
import resource, sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
from vhir_cli import ledger_verify as lv
r = lv.Result(case_id="c", case_id_source="test")
lv._items(Path(sys.argv[1]), r)
print(r.failures)
"""


@POSIX
def test_a_document_padded_with_newlines_is_read_as_one_document(case):
    """findings.json of [] and 4 MiB of newlines is one valid document: read
    whole, never as millions of lines, it verifies in a 256 MiB address space."""
    import subprocess
    import sys

    (case / "findings.json").write_bytes(b"[]" + b"\n" * (4 << 20))
    p = subprocess.run([sys.executable, "-c", _ITEMS_IN_256MIB, str(case)],
                       capture_output=True, text=True, timeout=60)  # fmt: skip
    assert p.returncode == 0 and p.stdout.strip() == "[]", (p.stdout, p.stderr[-500:])


def test_a_document_over_the_cap_is_refused_by_name(case):
    """A document is refused by its size, with the document's text, not as a
    long line of a log."""
    from vhir_cli import ledger_verify

    path = case / "findings.json"
    path.write_bytes(b"[" + b" " * ((16 << 20) - 1) + b"]")  # 16 MiB + 1 bytes
    text = (
        f"{path} is larger than 16 MiB, so it wasn't read. It holds the case's findings: "
        "keep a copy of it before you move it out of the case, then try again."
    )
    result = ledger_verify.Result(case_id="c", case_id_source="test")
    ledger_verify._items(case, result)
    assert result.failures == [
        ("CASE_FILE_UNREADABLE", f"findings.json couldn't be read ({text})")
    ]
    with pytest.raises(CaseFileTooLarge) as e:
        case_io.read_case_document(path)
    assert str(e.value) == text


def test_a_large_real_shaped_document_is_read(case):
    """About 5.3 MB of findings, as the largest real findings.json here is."""
    from vhir_cli import ledger_verify

    one = {"id": "F-tester-{n:04d}", "status": "DRAFT", "title": "t" * 40,
           "observation": "o" * 1500, "interpretation": "i" * 800,
           "artifacts": [{"source": "s" * 80, "content": "c" * 1200}]}  # fmt: skip
    findings = [{**one, "id": one["id"].format(n=n)} for n in range(1, 1400)]
    data = json.dumps(findings, indent=2).encode()
    assert (
        5 << 20 < len(data) < 16 << 20
    )  # under the cap: a control, the same before the cap
    (case / "findings.json").write_bytes(data)
    result = ledger_verify.Result(case_id="c", case_id_source="test")
    items = ledger_verify._items(case, result)
    assert not result.failures and len(items) == 1399


def test_the_cap_counts_a_lines_content_not_its_crlf(tmp_path):
    at = tmp_path / "crlf.jsonl"
    at.write_bytes(b"A" * LINE_CAP + b"\r\n" + b"{}\r\n")
    assert [len(x) for x in case_io.case_lines(at)] == [LINE_CAP + 2, 4]
    over = tmp_path / "over.jsonl"
    over.write_bytes(b"A" * (LINE_CAP + 1) + b"\r\n")
    with pytest.raises(CaseFileTooLarge) as e:
        list(case_io.case_lines(over))
    assert e.value.line == 1


@POSIX
def test_a_wintools_log_of_crlf_lines_reads_as_its_lf_twin(tmp_path):
    """wintools-mcp.jsonl comes over the share in Windows text mode: its lines
    end in CRLF. Short lines and one entry of exactly 16 MiB read as the same
    log with LF endings does, in the readers that read it."""
    head = b'{"audit_id": "wintools-tester-20261012-001", "tool": "run_windows_command", "pad": "'
    big = head + b"A" * (LINE_CAP - len(head) - 2) + b'"}'
    assert len(big) == LINE_CAP
    lines = [json.dumps({"audit_id": f"wintools-tester-20261012-{n:03d}", "ts": "2026-10-12"}).encode()
             for n in range(2, 200)] + [big]  # fmt: skip
    read = {}
    for end in (b"\r\n", b"\n"):
        case = tmp_path / ("crlf" if end == b"\r\n" else "lf")
        (case / "audit").mkdir(parents=True)
        (case / "audit" / "wintools-mcp.jsonl").write_bytes(
            b"".join(x + end for x in lines)
        )

        def run(case=case):
            return (approval_checks.audit_lines(case),
                    [e["audit_id"] for e in _quiet(lambda: audit_cmd._load_audit_entries(case))[0]])  # fmt: skip

        status, got = _within(run, timeout=60.0)
        assert status == "ok", got
        read[end] = got
    assert read[b"\r\n"] == read[b"\n"]
    assert (
        len(read[b"\n"][1]) == 199 and "wintools-tester-20261012-001" in read[b"\n"][0]
    )


# --- the 0.6 sources: read a line at a time, never joined ---------------------

_LEGACY_PEAK = """
import json, resource, sys
from pathlib import Path
from vhir_cli import ledger_verify as lv, verification
case, which = Path(sys.argv[1]), sys.argv[2]
verification.VERIFICATION_DIR = case.parent / "box"
r = lv.Result(case_id="c", case_id_source="test")
before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
counted, uncounted, problems = lv._legacy("c", case, {}, r)
grew = (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before) // 1024
print(json.dumps({"counted": counted, "grew_mib": grew, "sources": len(r.sources)}))
"""
_SOURCES = {"box 0.6 file": "box/c.jsonl", "0.6 copy": "case/ledger/legacy-1.jsonl",
            "0.6 close copy": "case/verification.jsonl"}  # fmt: skip


@POSIX
@pytest.mark.parametrize("source", sorted(_SOURCES))
def test_a_0_6_source_padded_with_newlines_is_read_a_line_at_a_time(tmp_path, source):
    """One 0.6 record and 16 MiB of newlines: the same record comes out, and
    the read holds no more than a line (a whole read held it all, then millions
    of tiny lines)."""
    import subprocess
    import sys

    record = {
        "finding_id": "F-tester-001",
        "action": "APPROVED",
        "ts": "2026-01-01T00:00:00Z",
    }
    path = tmp_path / _SOURCES[source]
    path.parent.mkdir(parents=True)
    (tmp_path / "case").mkdir(exist_ok=True)
    path.write_bytes(json.dumps(record).encode() + b"\n" + b"\n" * (16 << 20))
    p = subprocess.run([sys.executable, "-c", _LEGACY_PEAK, str(tmp_path / "case"), source],
                       capture_output=True, text=True, timeout=120)  # fmt: skip
    assert p.returncode == 0, p.stderr[-500:]
    got = json.loads(p.stdout)
    assert got["counted"] == {"F-tester-001": [record]} and got["sources"] == 1
    assert got["grew_mib"] <= 32, got["grew_mib"]


def test_a_genesis_prefix_reads_as_a_whole_read_did_at_every_cut(tmp_path):
    """The prefix a genesis froze, cut at every byte of a source (inside a
    line, at its end, in a CRLF), holds the records a whole read of those
    bytes held, and matches by the same hash."""
    import hashlib
    from types import SimpleNamespace

    from vhir_cli import ledger_verify, verification

    lines = [json.dumps({"finding_id": f"F-tester-00{n}", "action": "APPROVED"}).encode()
             for n in (1, 2, 3)]  # fmt: skip
    data = lines[0] + b"\n" + lines[1] + b"\r\n" + b"  \n" + lines[2] + b"\n"
    case = tmp_path / "case"
    (case / "ledger").mkdir(parents=True)
    (case / "ledger" / "legacy-x.jsonl").write_bytes(data)

    def whole_read(n):  # the read before this change: the bytes held, then split
        held = data[:n]
        out = []
        for raw in held.splitlines():
            text = raw.strip()
            try:
                obj = json.loads(text) if text else None
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("finding_id"):
                out.append(obj)
        return {o["finding_id"]: [o] for o in out}

    old = verification.VERIFICATION_DIR
    verification.VERIFICATION_DIR = tmp_path / "box"
    try:
        for n in range(1, len(data) + 1):
            genesis = {
                "legacy_sha256": hashlib.sha256(data[:n]).hexdigest(),
                "legacy_bytes": n,
            }
            chains = {
                "x": SimpleNamespace(
                    lines=[SimpleNamespace(seq=1, obj={"genesis": genesis})]
                )
            }
            result = ledger_verify.Result(case_id="c", case_id_source="test")
            counted, _, problems = ledger_verify._legacy("c", case, chains, result)
            assert problems == [] and counted == whole_read(n), n
    finally:
        verification.VERIFICATION_DIR = old
