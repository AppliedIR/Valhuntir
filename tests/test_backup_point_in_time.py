"""A backup is one point in time, hashes what it read, and changes nothing in
the case.

- This box's copies of the signed history (the chain, the 0.6 copy and
  keys.json) are written into the backup, never into the case: a read-only
  case backs up, and a case's files, folders and times are unchanged.
- The files the writers change together (findings, timeline, iocs, todos,
  pending reviews, approvals, the 0.6 copy and everything under ledger/) are
  copied in one hold of the writers' lock, with those copies, and never
  copied again; the manifest names them (`point_in_time`).
- Every file copied from the case is hashed as it is read, so a copy changed
  afterwards fails --verify; a path the copies rewrote is hashed from disk.

The real ledger.case_lock runs on the tests' store folder; a hook in the
backup's copy function stands in for a writer racing the copy.
"""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import sys
import threading
from argparse import Namespace
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B
from vhir_cli import case_copies, ledger

from .signing import sign_approved

CID = "C-PIT"


def _case(tmp_path, signed=True, files=None) -> Path:
    case = tmp_path / "cases" / CID
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(f"case_id: {CID}\nstatus: open\nname: n\n")
    findings = [{"id": "F-alice-001", "title": "one", "observation": "o",
                 "status": "APPROVED" if signed else "DRAFT"}]  # fmt: skip
    (case / "findings.json").write_text(json.dumps(findings))
    (case / "timeline.json").write_text(json.dumps([{"id": "T-alice-001"}]))
    for rel, text in (files or {}).items():
        (case / rel).parent.mkdir(parents=True, exist_ok=True)
        (case / rel).write_text(text)
    if signed:
        sign_approved(case, "alice")
    return case


def _snap(root: Path) -> dict:
    """Every file and folder under root: its bytes' hash, size, mtime and mode."""
    out = {}
    for d, dirs, files in os.walk(root):
        for n in dirs + files:
            p = Path(d, n)
            st = p.lstat()
            h = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""
            out[str(p.relative_to(root))] = (h, st.st_size, st.st_mtime_ns, st.st_mode)
    return out


def _backup(case, tmp_path, name="out") -> Path:
    return Path(
        B.create_backup_data(case, str(tmp_path / name), "alice")["backup_path"]
    )


def _manifest(b: Path) -> dict:
    return json.loads((b / "backup-manifest.json").read_text())


def _box() -> bytes:
    return ledger.chain_path(CID).read_bytes()


def _chains(b: Path) -> list[bytes]:
    return [p.read_bytes() for p in (b / "ledger" / "chains").glob("*.jsonl")]


def _hook(monkeypatch, fn):
    """Run fn(src, dst) after each file the backup copies from the case."""
    real = B._copy_file_hashing

    def copy(src, dst):
        out = real(src, dst)
        fn(Path(src), out[0])
        return out

    monkeypatch.setattr(B, "_copy_file_hashing", copy)


def _lock_held() -> bool:
    fd = os.open(ledger.lock_path(CID), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


def _writer_set(rel: str) -> bool:
    return rel in B._WRITER_SET or rel.startswith("ledger/")


# --- the case is never written ----------------------------------------------


def test_a_backup_and_a_repeat_change_nothing_in_the_case(tmp_path):
    case = _case(tmp_path)
    for n in ("one", "two"):
        before = _snap(case)
        b = _backup(case, tmp_path, n)
        assert _snap(case) == before
        assert _box() in _chains(b) and B._verify_backup(b)


def test_a_read_only_signed_case_backs_up_and_restores_with_its_chain(
    tmp_path, monkeypatch
):
    case = _case(tmp_path)
    for d, dirs, files in os.walk(case):
        for n in dirs + files:
            Path(d, n).chmod(Path(d, n).stat().st_mode & ~0o222)
    case.chmod(0o555)
    try:
        before = _snap(case)
        b = _backup(case, tmp_path)
        assert _snap(case) == before
        assert _box() in _chains(b) and (b / "ledger" / "keys.json").is_file()
        assert B._verify_backup(b)
    finally:
        for d, _dirs, _files in os.walk(case):
            os.chmod(d, 0o755)
    monkeypatch.setattr(sys, "stdin", io.StringIO())
    target = tmp_path / "restored" / CID
    args = Namespace(
        backup_path=str(b), target=str(target), skip_opensearch=True, skip_ledger=True
    )
    B.cmd_restore(args, {"examiner": "alice"})
    assert [p.read_bytes() for p in (target / "ledger" / "chains").glob("*.jsonl")] == [
        _box()
    ]


def test_a_stale_copy_an_export_left_is_brought_up_to_date_in_the_backup_only(tmp_path):
    case = _case(tmp_path)
    case_copies.write_case_copies(CID, case)  # what close and export leave in the case
    f = json.loads((case / "findings.json").read_text())
    f.append(
        {"id": "F-alice-002", "title": "two", "observation": "o", "status": "APPROVED"}
    )
    (case / "findings.json").write_text(json.dumps(f))
    sign_approved(case, "alice")
    stale = next((case / "ledger" / "chains").glob("*.jsonl")).read_bytes()
    assert _box().startswith(stale) and _box() != stale
    before = _snap(case)
    b = _backup(case, tmp_path)
    assert _snap(case) == before and _box() in _chains(b)
    heads = json.loads((b / "ledger" / "keys.json").read_text())["heads"]
    assert [h["seq"] for h in heads] == [len(_box().splitlines())]
    assert B._verify_backup(b)  # the rewritten copies are hashed from disk


def test_a_different_copy_in_the_case_is_moved_beside_in_the_backup_and_verifies(
    tmp_path,
):
    case = _case(tmp_path)
    case_copies.write_case_copies(CID, case)
    copy = next((case / "ledger" / "chains").glob("*.jsonl"))
    copy.write_bytes(copy.read_bytes().replace(b'"seq":1', b'"seq":1 ', 1) + b"{}\n")
    b = _backup(case, tmp_path)
    assert _box() in _chains(b) and B._verify_backup(b)


# --- one point in time --------------------------------------------------------


def test_the_writer_set_is_copied_only_under_the_lock_and_only_once(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, files={"iocs.json": "[]", "todos.json": "[]"})
    seen = []
    _hook(
        monkeypatch,
        lambda src, dst: seen.append((str(src.relative_to(case)), _lock_held())),
    )
    _backup(case, tmp_path)
    writer = [(rel, held) for rel, held in seen if _writer_set(rel)]
    assert writer and all(held for _rel, held in writer), writer
    assert len({rel for rel, _ in writer}) == len(writer)  # none copied twice


def test_a_writer_waiting_for_the_lock_never_tears_the_pair(tmp_path, monkeypatch):
    """A writer that holds the lock across its two-file change: a backup
    started in that span copies the pair after it (both new)."""
    case = _case(tmp_path, signed=False)
    started, done = threading.Event(), threading.Event()

    def writer():
        with ledger.case_lock(CID):
            (case / "findings.json").write_text(
                json.dumps([{"id": "F-alice-001"}, {"id": "F-alice-002"}])
            )
            started.set()
            done.wait(0.5)  # the backup starts and blocks here
            (case / "timeline.json").write_text(
                json.dumps([{"id": "T-alice-001"}, {"id": "T-alice-002"}])
            )

    t = threading.Thread(target=writer)
    t.start()
    started.wait(5)
    b = _backup(case, tmp_path)
    t.join(5)
    ids = [
        [i["id"] for i in json.loads((b / n).read_text())]
        for n in ("findings.json", "timeline.json")
    ]
    assert ids == [["F-alice-001", "F-alice-002"], ["T-alice-001", "T-alice-002"]]


def test_a_writer_just_after_the_lock_is_released_never_lands_in_the_backup(
    tmp_path, monkeypatch
):
    case = _case(tmp_path, signed=False, files={"report.md": "r"})
    fired = []

    def hook(src, dst):
        if not fired and not _lock_held():  # the first copy after the critical section
            fired.append(1)
            with ledger.case_lock(CID, timeout=5):
                (case / "findings.json").write_text(json.dumps([{"id": "F-alice-002"}]))
                (case / "timeline.json").write_text(json.dumps([{"id": "T-alice-002"}]))

    _hook(monkeypatch, hook)
    b = _backup(case, tmp_path)
    assert fired
    ids = [
        [i["id"] for i in json.loads((b / n).read_text())]
        for n in ("findings.json", "timeline.json")
    ]
    assert ids == [["F-alice-001"], ["T-alice-001"]]


def test_a_writer_set_file_created_before_the_lock_is_copied_and_named(
    tmp_path, monkeypatch
):
    case = _case(tmp_path)
    real = case_copies.write_case_copies

    def after_the_scan(*a, **k):  # an IOC recorded between the scan and the lock
        (case / "iocs.json").write_text(json.dumps([{"id": "I-alice-001"}]))
        return real(*a, **k)

    monkeypatch.setattr(case_copies, "write_case_copies", after_the_scan)
    b = _backup(case, tmp_path)
    assert (b / "iocs.json").is_file() and "iocs.json" in _manifest(b)["point_in_time"][
        "files"
    ]


def test_the_manifest_names_exactly_what_the_locked_section_copied_or_wrote(tmp_path):
    case = _case(
        tmp_path,
        files={
            "iocs.json": "[]",
            "todos.json": "[]",
            "audit/forensic-mcp.jsonl": "{}\n",
            "evidence/note.txt": "x",
        },
    )
    b = _backup(case, tmp_path)
    pit = set(_manifest(b)["point_in_time"]["files"])
    ledger_files = {
        str(p.relative_to(b)) for p in (b / "ledger").rglob("*") if p.is_file()
    }
    assert (
        pit
        == {"findings.json", "timeline.json", "iocs.json", "todos.json"} | ledger_files
    )
    assert pit <= {e["path"] for e in _manifest(b)["files"]} and B._verify_backup(b)


# --- each hash is of the bytes read ---------------------------------------------


@pytest.mark.parametrize("name", ["timeline.json", "report.md"])
def test_a_copy_changed_after_it_was_read_fails_verify(
    tmp_path, monkeypatch, name, capsys
):
    """One byte appended to the backup's copy, another to the source, after
    the copy: the manifest holds the hash of what was read."""
    case = _case(tmp_path, signed=False, files={"report.md": "report v1\n"})
    read = hashlib.sha256((case / name).read_bytes()).hexdigest()

    def hook(src, dst):
        if src.name == name:
            with open(dst, "ab") as f:
                f.write(b" ")
            with open(src, "ab") as f:
                f.write(b"#")

    _hook(monkeypatch, hook)
    b = _backup(case, tmp_path)
    assert {e["path"]: e["sha256"] for e in _manifest(b)["files"]}[name] == read
    assert not B._verify_backup(b) and f"MISMATCH: {name}" in capsys.readouterr().out
