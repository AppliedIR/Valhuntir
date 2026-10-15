"""The approval checks' read of the audit trail: each line is counted as
json.loads counts it, and a line longer than LINE_CAP is read in pieces,
never held, never refused. A log's size is not capped for this read.

Each case holds a log with one line past the cap, as a large hash job's
file-identity entry was written: the shape that refused an approval.
"""

from __future__ import annotations

import errno
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from vhir_cli import approval_checks, case_io
from vhir_cli.case_io import FILE_BUDGET, LINE_CAP, CaseFileTooLarge
from vhir_cli.commands import execute

CHUNK = 1 << 20  # the scan reads this much at a time
PAD = LINE_CAP + 3 * CHUNK + 12345  # past the cap, off the chunk boundaries
A_ID, B_ID = "sift-analyst1-001", "sift-analyst1-002"
G_ID = "fileidentity-analyst1-20261015-001"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def line(audit_id, **more) -> bytes:
    return json.dumps({"audit_id": audit_id, "tool": "run_command", **more}).encode()


A, B = line(A_ID), line(B_ID)


def giant(head: bytes = b'{"audit_id": "' + G_ID.encode() + b'", ', pad: int = PAD,
          tail: bytes = b"}") -> bytes:  # fmt: skip
    """`head`, a "pad" string past the cap, then `tail`."""
    return head + b'"pad": "' + b"A" * pad + b'"' + tail


@pytest.fixture
def case(tmp_path):
    (tmp_path / "audit").mkdir()
    (tmp_path / "audit" / "sift-mcp.jsonl").write_bytes(A + b"\n" + B + b"\n")
    (tmp_path / "audit" / "file-identity.jsonl").write_bytes(giant() + b"\n")
    return tmp_path


def fi(case, data: bytes):
    (case / "audit" / "file-identity.jsonl").write_bytes(data)


def check(case, *chain):
    """What the approval checks say of a finding chaining (id, line) pairs."""
    item = {"provenance_schema": 2, "artifacts": [{"provenance_chain": [
        {"audit_id": i, "entry_sha256": sha(b)} for i, b in chain]}]}  # fmt: skip
    try:
        got = approval_checks.check_item(case, item, "finding")
    except Exception as e:  # noqa: BLE001 - what it raised is the result
        return f"raised {type(e).__name__}: {str(e)[:200]}"
    return sorted((i["status"], i["subject"], i["detail"]) for i in got["items"])


def ok(*ids):
    return [("ok", i, "unchanged") for i in sorted(ids)]


DUP_A = [("failed", A_ID, "2 audit lines have this id")]


# --- the shape that refused --------------------------------------------------


def test_a_chain_citing_another_log_is_checked_past_a_giant_line(case):
    assert check(case, (A_ID, A), (B_ID, B)) == ok(A_ID, B_ID)


def test_the_portals_signing_checks_read_past_a_giant_line(case):
    """The Portal's sign step runs the same checks (background=True)."""
    item = {"provenance_schema": 2, "artifacts": [{"provenance_chain": [
        {"audit_id": i, "entry_sha256": sha(b)} for i, b in ((A_ID, A), (B_ID, B))]}]}  # fmt: skip
    got = approval_checks.check_item(case, item, "finding", background=True)
    assert sorted((i["status"], i["subject"], i["detail"]) for i in got["items"]) == ok(
        A_ID, B_ID
    )


def test_the_giant_line_itself_can_be_chained_and_a_change_is_seen(case):
    assert check(case, (G_ID, giant())) == ok(G_ID)
    changed = bytearray(giant())
    changed[LINE_CAP + 5] = ord("B")  # one byte, past the cap
    fi(case, bytes(changed) + b"\n")
    assert check(case, (G_ID, giant())) == [
        ("failed", G_ID, "the audit line changed since the chain was resolved")
    ]


def test_a_duplicate_planted_in_a_giant_line_is_counted(case):
    fi(case, giant(b'{"audit_id": "' + A_ID.encode() + b'", ') + b"\n")
    assert check(case, (A_ID, A)) == DUP_A


@pytest.mark.parametrize("n", [LINE_CAP - 1, LINE_CAP, LINE_CAP + 1])
def test_lines_either_side_of_the_cap_read_alike(case, n):
    head = b'{"audit_id": "' + G_ID.encode() + b'", '
    g = giant(head, pad=n - len(giant(head, pad=0)))
    assert len(g) == n
    fi(case, g + b"\n")
    assert check(case, (G_ID, g)) == ok(G_ID)
    fi(case, g[:-3] + b'B"}' + b"\n")
    assert check(case, (G_ID, g))[0][:2] == ("failed", G_ID)


# --- P1: the last top-level audit_id decides ---------------------------------

LAST = {
    "a string, then another": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": "x"', 0),
    "another, then the string": (b'"audit_id": "x", "audit_id": "' + A_ID.encode() + b'"', 1),
    "the string, then a number": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": 5', 0),
    "the string, then null": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": null', 0),
    "the string, then true": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": true', 0),
    "the string, then an object": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": {"a": "' + A_ID.encode() + b'"}', 0),
    "the string, then an array": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": ["' + A_ID.encode() + b'"]', 0),
    "the string, then a long string": (b'"audit_id": "' + A_ID.encode() + b'", "audit_id": "' + A_ID.encode() + b"x" * 4096 + b'"', 0),
    "a number, then the string": (b'"audit_id": 5, "audit_id": "' + A_ID.encode() + b'"', 1),
}  # fmt: skip


@pytest.mark.parametrize("where", ["before the pad", "after the pad"])
@pytest.mark.parametrize("ids", sorted(LAST))
def test_the_last_audit_id_decides(case, ids, where):
    keys, counted = LAST[ids]
    if where == "before the pad":
        g = giant(b"{" + keys + b", ")
    else:
        g = giant(b"{", tail=b", " + keys + b"}")
    assert json.loads(g).get("audit_id") == (
        A_ID if counted else json.loads(g)["audit_id"]
    )
    fi(case, g + b"\n")
    assert check(case, (A_ID, A)) == (DUP_A if counted else ok(A_ID))


# --- P2: only an object at the top counts ------------------------------------

NOT_OBJECTS = {
    "an array": b'["audit_id", "' + A_ID.encode() + b'", "' + b"A" * PAD + b'"]',
    "a string": b'"audit_id: ' + A_ID.encode() + b" " + b"A" * PAD + b'"',
    "a number": b"1" * PAD,
    "at depth 2": b'{"x": {"audit_id": "' + A_ID.encode() + b'"}, "pad": "' + b"A" * PAD + b'"}',
    "in an array value": b'{"x": ["audit_id", "' + A_ID.encode() + b'"], "pad": "' + b"A" * PAD + b'"}',
    "as a value": b'{"x": "audit_id", "y": "' + A_ID.encode() + b'", "pad": "' + b"A" * PAD + b'"}',
}  # fmt: skip


@pytest.mark.parametrize("shape", sorted(NOT_OBJECTS))
def test_an_id_not_a_top_level_key_isnt_counted(case, shape):
    fi(case, NOT_OBJECTS[shape] + b"\n")
    assert check(case, (A_ID, A)) == ok(A_ID)


# --- P3: lines split as bytes.splitlines() splits ----------------------------


def test_a_short_line_after_a_bare_cr_in_a_giant_raw_line_counts(case):
    fi(case, giant() + b"\r" + A + b"\n")
    assert check(case, (A_ID, A), (G_ID, giant())) == DUP_A + ok(G_ID)


@pytest.mark.parametrize("end", [b"\r\n", b"\r", b"\n"])
def test_a_line_ending_at_a_chunk_boundary(case, end):
    """The giant line's last byte is a chunk's last byte: \\r\\n is split over
    two chunks, or a bare \\r ends the chunk."""
    head = b'{"audit_id": "' + G_ID.encode() + b'", '
    g = giant(head, pad=17 * CHUNK - 1 - len(giant(head, pad=0)))
    assert len(g) == 17 * CHUNK - 1
    fi(case, g + end + B + end)
    assert check(case, (G_ID, g), (B_ID, B)) == [
        ("failed", B_ID, "2 audit lines have this id")] + ok(G_ID)  # fmt: skip


def test_a_short_line_crlf_over_a_chunk_boundary(case):
    fill = b'{"f": "' + b"x" * (CHUNK - 1 - len(A) - 1 - 9) + b'"}'
    data = fill + b"\n" + A + b"\r\n" + B + b"\r\n"
    assert data[CHUNK - 1 : CHUNK + 1] == b"\r\n"
    (case / "audit" / "sift-mcp.jsonl").write_bytes(data)
    assert check(case, (A_ID, A), (B_ID, B)) == ok(A_ID, B_ID)


# --- P4: a line json.loads can't read is skipped, never refused --------------

INVALID = {
    "cut in a string": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', tail=b"")[:-1],
    "cut after a string": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', tail=b""),
    "a bracket left open": giant(b'{"audit_id": "' + A_ID.encode() + b'", "x": [', tail=b"}"),
    "bytes after the object": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', tail=b"} x"),
    "a second object": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', tail=b"}{}"),
    "not UTF-8": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', tail=b'\xff"}')[:-2] + b"}",
    "a bad escape in a key": giant(b'{"\\q": 1, "audit_id": "' + A_ID.encode() + b'", '),
    "a bad escape in the id": giant(b'{"audit_id": "' + A_ID.encode() + b'\\x", '),
    "a control character in the id": giant(b'{"audit_id": "' + A_ID.encode() + b'\t", '),
}  # fmt: skip


@pytest.mark.parametrize("shape", sorted(INVALID))
def test_a_giant_line_json_loads_refuses_is_skipped(case, shape):
    with pytest.raises(ValueError):
        json.loads(INVALID[shape])
    fi(case, INVALID[shape] + b"\n")
    assert check(case, (A_ID, A), (B_ID, B)) == ok(A_ID, B_ID)


def test_an_oom_cut_line_with_its_own_id_and_a_chain_citing_another_log(case):
    fi(case, giant()[: LINE_CAP + 777])  # the writer died mid-line
    assert check(case, (B_ID, B)) == ok(B_ID)


VALID = {
    "whitespace around it": b" \t" + giant(b'{ "audit_id" : "' + A_ID.encode() + b'" , ') + b" \t",
    "a UTF-8 BOM": b"\xef\xbb\xbf" + giant(b'{"audit_id": "' + A_ID.encode() + b'", '),
    "UTF-16-LE": giant(b'{"audit_id": "' + A_ID.encode() + b'", ').decode().encode("utf-16-le"),
    "UTF-32-BE": giant(b'{"audit_id": "' + A_ID.encode() + b'", ', pad=LINE_CAP // 4).decode().encode("utf-32-be"),
    "deep nesting before it": giant(b'{"x": ' + b"[" * 200_000 + b"]" * 200_000 + b', "audit_id": "' + A_ID.encode() + b'", '),
    "a pad of escapes": b'{"audit_id": "' + A_ID.encode() + b'", "pad": "' + b'\\"\\\\' * (PAD // 4) + b'"}',
}  # fmt: skip


@pytest.mark.parametrize("shape", sorted(VALID))
def test_a_giant_line_json_loads_reads_is_counted(case, shape):
    if shape != "deep nesting before it":  # too deep for json.loads on 3.10/3.12
        assert json.loads(VALID[shape])["audit_id"] == A_ID
    fi(case, VALID[shape] + b"\n")
    assert check(case, (A_ID, A)) == DUP_A


def test_a_short_line_too_deep_for_json_loads_is_counted_on_every_version(case):
    """It raised RecursionError out of the checks (3.10: 2,000 levels; 3.12:
    100,000): now it is read as a giant line is."""
    deep = (
        b'{"x": '
        + b"[" * 200_000
        + b"]" * 200_000
        + b', "audit_id": "'
        + A_ID.encode()
        + b'"}'
    )
    assert len(deep) < LINE_CAP
    with pytest.raises(RecursionError):
        json.loads(deep)
    fi(case, deep + b"\n")
    assert check(case, (A_ID, A)) == DUP_A


# --- P5: keys and values decode their escapes in full ------------------------

ASTRAL = "\U0001f600" * 4  # each written 😀: 12 characters


@pytest.mark.parametrize("escaped", ["key", "value", "both", "solidus"])
def test_an_escaped_key_or_id_is_counted(case, escaped):
    key = b"audit\\u005fid" if escaped in ("key", "both") else b"audit_id"
    value = A_ID.encode()
    if escaped in ("value", "both"):
        value = b"".join(b"\\u%04x" % c for c in value)
    elif escaped == "solidus":
        value = b"sift\\u002danalyst1\\u002d001"
    g = giant(b'{"' + key + b'": "' + value + b'", ')
    assert json.loads(g)["audit_id"] == A_ID
    fi(case, g + b"\n")
    assert check(case, (A_ID, A)) == DUP_A


def test_an_id_of_surrogate_pairs_is_counted(case):
    mine = line(ASTRAL)
    (case / "audit" / "sift-mcp.jsonl").write_bytes(A + b"\n" + mine + b"\n")
    pairs = json.dumps(ASTRAL).encode()  # ensure_ascii: "😀..."
    assert len(pairs) - 2 == 12 * len(ASTRAL)
    fi(case, giant(b'{"audit_id": ' + pairs + b", ") + b"\n")
    assert check(case, (ASTRAL, mine)) == [
        ("failed", ASTRAL, "2 audit lines have this id")
    ]


@pytest.mark.parametrize("lone", [b'"audit_id\\ud800"', b'"audit\\ud800_id"'])
def test_a_key_with_a_lone_surrogate_isnt_audit_id(case, lone):
    fi(case, giant(b"{" + lone + b': "' + A_ID.encode() + b'", ') + b"\n")
    assert check(case, (A_ID, A)) == ok(A_ID)


def test_an_id_with_a_lone_surrogate_isnt_the_id(case):
    fi(case, giant(b'{"audit_id": "' + A_ID.encode() + b'\\ud800", ') + b"\n")
    assert check(case, (A_ID, A)) == ok(A_ID)


def test_an_escape_split_over_a_chunk_boundary(case):
    """The pad ends a chunk on a backslash; the id's \\u escapes cross the
    next boundary."""
    head = b'{"pad": "'
    n = 17 * CHUNK - len(head)
    pad = b"A" * (n - 1) + b"\\"  # the backslash is the chunk's last byte
    value = b"".join(b"\\u%04x" % c for c in A_ID.encode())
    g = head + pad + b'n", "audit_id": "' + value + b'"}'
    assert (
        g[17 * CHUNK - 1 : 17 * CHUNK + 1] == b"\\n"
        and json.loads(g)["audit_id"] == A_ID
    )
    fi(case, g + b"\n")
    assert check(case, (A_ID, A)) == DUP_A


# --- size and memory ---------------------------------------------------------

_PEAK = """
import hashlib, json, sys
from vhir_cli import approval_checks
case, chain = sys.argv[1], json.loads(sys.argv[2])
item = {"provenance_schema": 2, "artifacts": [{"provenance_chain": chain}]}
try:
    got = [(i["status"], i["detail"]) for i in approval_checks.check_item(case, item, "finding")["items"]]
except Exception as e:
    got = f"{type(e).__name__}: {str(e)[:200]}"
with open("/proc/self/status") as f:
    hwm = next(int(x.split()[1]) for x in f if x.startswith("VmHWM:"))
print(json.dumps([got, hwm]))
"""


def _peak(case, chain):
    p = subprocess.run([sys.executable, "-c", _PEAK, str(case), json.dumps(chain)],
                       capture_output=True, text=True, timeout=300)  # fmt: skip
    assert p.returncode == 0, p.stderr[-800:]
    return json.loads(p.stdout)


@pytest.mark.skipif(not Path("/proc/self/status").exists(), reason="VmHWM")
def test_a_log_over_the_file_budget_is_read_in_bounded_memory(case, tmp_path):
    """A 257 MiB log of one line, chained: ok, within 100 MiB of a small case."""
    small = tmp_path / "small"
    (small / "audit").mkdir(parents=True)
    (small / "audit" / "sift-mcp.jsonl").write_bytes(A + b"\n" + B + b"\n")
    head = b'{"audit_id": "' + G_ID.encode() + b'", '
    g = giant(head, pad=FILE_BUDGET + CHUNK)
    fi(case, g + b"\n")
    assert (case / "audit" / "file-identity.jsonl").stat().st_size > FILE_BUDGET
    chain = [
        {"audit_id": G_ID, "entry_sha256": sha(g)},
        {"audit_id": A_ID, "entry_sha256": sha(A)},
    ]
    del g
    got, hwm = _peak(case, chain)
    base, base_hwm = _peak(small, [{"audit_id": A_ID, "entry_sha256": sha(A)}])
    assert got == [["ok", "unchanged"]] * 2 and base == [["ok", "unchanged"]], (
        got,
        base,
    )
    assert hwm - base_hwm < 100 << 10, (hwm, base_hwm)  # KiB


def test_other_readers_keep_the_file_budget(case):
    (case / "audit" / "file-identity.jsonl").unlink()
    with open(case / "audit" / "file-identity.jsonl", "wb") as f:
        f.truncate(FILE_BUDGET + 1)
    with pytest.raises(CaseFileTooLarge):
        list(case_io.case_lines(case / "audit" / "file-identity.jsonl"))
    assert check(case, (A_ID, A)) == ok(A_ID)


# --- item 3: no refusal tells the user to change an audit log ---------------

# advice that would change the log: move, edit, delete, replace or put back
_TAMPER = re.compile(
    r"\b(mov(e|ed|ing)|delet\w*|edit\w*|replac\w*|remov\w*|renam\w*|aside|copy|"
    r"put\b[^.]*\bback|make each log)\b", re.I)  # fmt: skip


def _audit_refusals(case) -> dict[str, str]:
    log = case / "audit" / "cli-exec.jsonl"
    out = {
        f"not regular: {w}": str(case_io._not_regular(log, w))
        for w in case_io._NOT_REGULAR
    }
    out["too large: line"] = str(CaseFileTooLarge(log, line=3))
    out["too large: file"] = str(CaseFileTooLarge(log))
    out["approval: not regular"] = str(approval_checks.AuditUnreadable(
        ["audit/x.jsonl (not a regular file)", "audit/y.jsonl (a symbolic link)"]))  # fmt: skip
    out["approval: permissions"] = str(approval_checks.AuditUnreadable(
        ["audit/x.jsonl (Permission denied)", "audit/ (Permission denied)"]))  # fmt: skip
    for w in case_io._NOT_REGULAR:
        out[f"exec: {w}"] = execute._advice(case_io._not_regular(log, w))
    out["exec: too large"] = execute._advice(CaseFileTooLarge(log, line=3))
    out["exec: link"] = execute._advice(OSError(errno.ELOOP, "Too many levels"))
    out["exec: second name"] = execute._advice(OSError(errno.EMLINK, "Too many links"))
    out["exec: permissions"] = execute._advice(
        OSError(errno.EACCES, "Permission denied")
    )
    return out


def test_no_refusal_over_an_audit_log_says_to_change_it(case):
    got = _audit_refusals(case)
    assert len(got) == 2 * len(case_io._NOT_REGULAR) + 8
    said = {k: _TAMPER.findall(v) for k, v in got.items()}
    assert {k: v for k, v in said.items() if v} == {}, got
    for k, text in got.items():
        if "permissions" in k:
            assert "Check the permissions of" in text, (k, text)
        else:
            assert "audit logs are evidence and stay as they are" in text, (k, text)
    assert "Nothing was signed" in got["approval: not regular"]
    assert got["approval: permissions"].endswith(
        "Check the permissions of audit/x.jsonl, audit/, then approve again."
    )


def test_other_case_files_keep_their_advice(case):
    for name in ("findings.json", "approvals.jsonl"):
        assert str(case_io._not_regular(case / name)).endswith(
            "Put the case's own file back, then try again."
        )
    assert "keep a copy of it before you move it out of the case" in str(
        CaseFileTooLarge(case / "findings.json")
    )
