"""Every route that reads a case file reads it whatever its size: a findings.json
over 20 MiB, an audit line over 20 MiB, an audit log over 256 MiB and a 0.6
source over 256 MiB, each made of lines shaped as real ones are. Nothing is
refused for its size. A file that isn't a regular file is still refused by
name, never waited on. Each row runs in a forked child, which reports its own
peak memory growth (printed with -s)."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pickle
import select
import signal
from argparse import Namespace
from datetime import datetime, timezone

import pytest

from vhir_cli import approval_checks, case_io, ledger_verify
from vhir_cli.commands import audit_cmd, evidence, execute
from vhir_cli.commands.review import cmd_review

POSIX = pytest.mark.skipif(
    not hasattr(os, "mkfifo") or os.geteuid() == 0, reason="posix"
)
MIB = 1 << 20
TODAY = datetime.now(timezone.utc).strftime("%Y%m%d")
SHA = hashlib.sha256(b"output").hexdigest()


def _in_child(fn, timeout):
    """("ok", fn()) or ("raised", text), from a forked child, with the child's
    peak memory growth in MiB; ("blocked",) if it didn't end within `timeout`."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            with open("/proc/self/clear_refs", "w") as f:
                f.write("5")  # the peak starts from here
            before = _hwm()
            try:
                out = ("ok", fn())
            except BaseException as e:  # noqa: BLE001 - reported to the parent
                out = ("raised", f"{type(e).__name__}: {e}"[:2000])
            out = (*out, (_hwm() - before) >> 10)
        except BaseException as e:  # noqa: BLE001
            out = ("raised", repr(e)[:2000], 0)
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    try:
        ready, _, _ = select.select([r], [], [], timeout)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            return ("blocked", "", 0)
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        return pickle.loads(data)
    finally:
        os.close(r)
        os.waitpid(pid, 0)


def _hwm() -> int:
    """This process's peak resident memory, KiB."""
    with open("/proc/self/status") as f:
        return next(int(x.split()[1]) for x in f if x.startswith("VmHWM:"))


def _said(fn):
    """fn's result, and what it printed (stdout and stderr together)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        got = fn()
    return got, out.getvalue()


# --- inputs, shaped as real case files are --------------------------------------


def _audit_entry(n: int, prefix: str, pad: int = 0) -> dict:
    """A run_command entry as the MCP servers write one (about 900 bytes);
    `pad` adds that many bytes of tool output to its result."""
    return {
        "ts": f"2026-11-16T{n // 3600 % 24:02d}:{n // 60 % 60:02d}:{n % 60:02d}.123456Z",
        "tool": "run_command",
        "audit_id": f"{prefix}-{n:06d}",
        "examiner": "tester",
        "case_id": "SZ-1",
        "source": "mcp_server",
        "params": {
            "command": "vol -f /cases/SZ-1/evidence/rd01.mem windows.pslist",
            "purpose": "list the processes running at capture",
            "save_output": True,
        },  # fmt: skip
        "result_summary": {
            "exit_code": 0,
            "lines": 412,
            "stdout": "x" * pad,
            "output_file": f"/cases/SZ-1/extractions/out-{n:06d}.txt",
            "sha256": SHA,
        },  # fmt: skip
        "input_files": ["/cases/SZ-1/evidence/rd01.mem"],
        "elapsed_ms": 4123.5,
        "data_provenance": "tool output, untrusted",
    }


def _withdrawn(n: int, prefix: str, pad: int = 0) -> dict:
    """A record_finding entry whose result is WITHDRAWN, as forensic-mcp writes
    one; `pad` adds that many bytes of artifact content."""
    entry = _audit_entry(n, prefix)
    entry["tool"] = "record_finding"
    entry["params"] = {"title": "Run key persistence", "artifacts": [
        {"source": "/cases/SZ-1/extractions/reg.csv", "content": "c" * pad}]}  # fmt: skip
    entry["result_summary"] = {"status": "WITHDRAWN", "finding_id": f"F-tester-{n:03d}"}
    return entry


def _write_log(path, size: int, prefix: str) -> str:
    """A log of real-shaped lines whose last line is a withdrawal; `size` is
    the least it holds. With size over 16 MiB and one line, that line holds it
    all. The last line's audit id is returned."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        if size < 64 * MIB:  # two lines: one short, then one of `size` bytes
            f.write(json.dumps(_audit_entry(1, prefix)).encode() + b"\n")
            f.write(json.dumps(_withdrawn(2, prefix, size)).encode() + b"\n")
            return f"{prefix}-{2:06d}"
        n, written, batch = 0, 0, []
        while written < size:
            n += 1
            line = json.dumps(_audit_entry(n, prefix)).encode() + b"\n"
            batch.append(line)
            written += len(line)
            if len(batch) == 4096:
                f.write(b"".join(batch))
                batch.clear()
        n += 1
        f.write(b"".join(batch) + json.dumps(_withdrawn(n, prefix)).encode() + b"\n")
        return f"{prefix}-{n:06d}"


def _write_findings(path, size: int) -> str:
    """findings.json of real-shaped findings (about 10 KB each, written as the
    case writes it) past `size` bytes; the last one's id is returned."""
    one = {"status": "DRAFT", "title": "Prefetch shows svc-upd.exe run from Temp",
           "observation": "o" * 3000, "interpretation": "i" * 1500,
           "confidence": "MEDIUM", "examiner": "tester", "host": "rd01",
           "artifacts": [{"source": "/cases/SZ-1/extractions/pf.csv", "extraction":
                          "PECmd -d ...", "content": "c" * 4000,
                          "audit_id": "sift-tester-000001"}]}  # fmt: skip
    n = size // 8000 + 1
    found = [{"id": f"F-tester-{i:04d}", **one} for i in range(1, n + 1)]
    found[-1]["title"] = found[-1]["id"]  # the last one is shown by its title
    data = json.dumps(found, indent=2).encode()
    assert len(data) > size
    path.write_bytes(data)
    return f"F-tester-{n:04d}"


def _write_source(path, size: int) -> int:
    """A 0.6 approval file of real-shaped records past `size` bytes, each a
    different finding; how many records it holds is returned."""
    path.parent.mkdir(parents=True, exist_ok=True)
    n = written = 0
    with open(path, "wb") as f:
        batch = []
        while written <= size:
            n += 1
            rec = {"finding_id": f"F-tester-{n:07d}", "action": "APPROVED",
                   "ts": "2026-01-01T00:00:00Z", "examiner": "tester",
                   "content_hash": SHA, "hmac": SHA, "mode": "interactive"}  # fmt: skip
            line = json.dumps(rec).encode() + b"\n"
            batch.append(line)
            written += len(line)
            if len(batch) == 4096:
                f.write(b"".join(batch))
                batch.clear()
        f.write(b"".join(batch))
    return n


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    c = tmp_path / "SZ-1"
    (c / "audit").mkdir(parents=True)
    (c / "CASE.yaml").write_text("case_id: SZ-1\nname: SZ-1\nstatus: open\n")
    (c / "findings.json").write_text("[]")
    (c / "timeline.json").write_text("[]")
    (c / "iocs.json").write_text("[]")
    (c / "todos.json").write_text("[]")
    (c / "evidence.json").write_text('{"files": []}')
    monkeypatch.setattr("vhir_cli.commands.review.get_case_dir", lambda *a: c)
    yield c
    for big in (c / "audit").iterdir():  # never left for the next run
        if big.is_file():
            big.unlink()


# --- the routes ------------------------------------------------------------------
# route -> (the file it reads, relative to the case; call(case, marker) -> what it read;
#           read(got, marker) -> True when the marker's record was read)

LOG = "audit/forensic-mcp.jsonl"
LOG_ROUTES = {
    "vhir audit": (LOG, lambda c, m: _said(lambda: [e.get("audit_id") for e in audit_cmd._load_audit_entries(c)]),
                   lambda got, m: m in got[0] and "Warning" not in got[1]),
    "vhir review --audit": (LOG, lambda c, m: _said(lambda: cmd_review(Namespace(case=None, audit=True, limit=20), {})),
                            lambda got, m: m in got[1] and "can't" not in got[1] and "could not" not in got[1]),
    "audit index": (LOG, lambda c, m: _said(lambda: sorted(case_io.load_audit_index(c, {m}))),
                    lambda got, m: m in got[0] and "Warning" not in got[1]),
    "approval checks": (LOG, lambda c, m: sorted(approval_checks.audit_lines(c)), lambda got, m: m in got),
    "withdrawals (vhir approve, review --withdrawn)": (
        LOG, lambda c, m: (lambda unread: ([w["audit_id"] for w in case_io.load_withdrawals(c, unread)], unread))([]),
        lambda got, m: got[0] == [m] and got[1] == []),
    "evidence register": (LOG, lambda c, m: evidence._recorded_outputs(c)[1], lambda got, m: got == []),
    "vhir exec": ("audit/cli-exec.jsonl", lambda c, m: execute._next_audit_id(c, "tester"),
                  lambda got, m: got == f"cliexec-tester-{TODAY}-{int(m.rsplit('-', 1)[1]) + 1:03d}"),
}  # fmt: skip
DOC_ROUTES = {
    "vhir review": ("findings.json", lambda c, m: _said(lambda: cmd_review(Namespace(case=None, findings=True), {})),
                    lambda got, m: m in got[1] and "couldn't be read" not in got[1]),
    "vhir report": ("findings.json", lambda c, m: (lambda f: (len(f["findings.json"].records), case_io.unreadable_of(f)))(case_io.read_record_files(c)),
                    lambda got, m: got[0] == int(m.rsplit("-", 1)[1]) and got[1] == []),
    "verify": ("findings.json", lambda c, m: [d for _, d in ledger_verify.verify_case(c).failures],
               lambda got, m: not any("findings.json" in d for d in got)),
}  # fmt: skip
SIZES = {"20 MiB line": 20 * MIB, "log over 256 MiB": 257 * MIB}


def _prefix(rel: str) -> str:
    return (
        f"cliexec-tester-{TODAY}"
        if rel.endswith("cli-exec.jsonl")
        else "forensic-tester"
    )


def _report(route, what, got):
    status, value, grew = got
    print(f"\nPEAK {route} | {what} | grew {grew} MiB | {status}")
    return status, value


@pytest.mark.parametrize("what", sorted(SIZES))
@pytest.mark.parametrize("route", sorted(LOG_ROUTES))
def test_an_audit_log_of_any_size_is_read(case, route, what):
    rel, call, read = LOG_ROUTES[route]
    marker = _write_log(case / rel, SIZES[what], _prefix(rel))
    status, got = _report(
        route, what, _in_child(lambda: call(case, marker), timeout=900)
    )
    assert status == "ok", got
    assert read(got, marker), str(got)[:2000]


@pytest.mark.parametrize("route", sorted(DOC_ROUTES))
def test_a_findings_json_over_20_mib_is_read(case, route):
    rel, call, read = DOC_ROUTES[route]
    marker = _write_findings(case / rel, 20 * MIB)
    status, got = _report(
        route,
        "findings.json over 20 MiB",
        _in_child(lambda: call(case, marker), timeout=300),
    )
    assert status == "ok", got
    assert read(got, marker), str(got)[-2000:]


_SOURCES = {"box 0.6 file": "box/SZ-1.jsonl", "0.6 copy": "SZ-1/ledger/legacy-1.jsonl",
            "0.6 close copy": "SZ-1/verification.jsonl"}  # fmt: skip


@pytest.mark.parametrize("source", sorted(_SOURCES))
def test_a_0_6_source_over_256_mib_is_read_and_counted(case, source):
    """Verify reads a 0.6 source whole: one over 256 MiB is read and every one
    of its approvals counted, never dropped as if it weren't there."""
    from vhir_cli import verification

    path = case.parent / _SOURCES[source]
    n = _write_source(path, 257 * MIB)

    def run():
        verification.VERIFICATION_DIR = case.parent / "box"
        r = ledger_verify.Result(case_id="SZ-1", case_id_source="test")
        counted, _, problems = ledger_verify._legacy("SZ-1", case, {}, r)
        return len(counted), len(r.sources), problems

    try:
        status, got = _report(
            "verify (0.6 source)", source, _in_child(run, timeout=900)
        )
    finally:
        path.unlink()
    assert status == "ok", got
    assert got == (n, 1, []), got


@POSIX
@pytest.mark.parametrize(
    "route", sorted(LOG_ROUTES) + sorted(f"doc:{r}" for r in DOC_ROUTES)
)
def test_a_case_file_that_isnt_regular_is_refused_by_name(case, route):
    """A FIFO no one writes to, in the file's place: named, never waited on."""
    rel, call, _ = (
        DOC_ROUTES[route[4:]] if route.startswith("doc:") else LOG_ROUTES[route]
    )
    path = case / rel
    path.unlink(missing_ok=True)
    os.mkfifo(path)
    status, got, _ = _in_child(lambda: str(call(case, "none")), timeout=20)
    assert status in ("ok", "raised"), status
    assert "regular file" in got or "regular" in got, got[:2000]
