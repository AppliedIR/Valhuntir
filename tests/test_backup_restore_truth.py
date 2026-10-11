"""Backup and restore tell the truth, and change nothing outside the case
until every file has verified.

- Restore copies and verifies every file, the 0.6 ledger included (read once,
  as the user, never through a link), before it installs that ledger, merges
  keys, gives a copy its identity or restores indices.
- A part asked for that didn't happen exits 1: a PARTIAL backup is kept, valid
  without it; a PARTIAL restore keeps its marker, naming the steps a re-run
  finishes, and a re-run never deletes a folder the examiner worked in.
- `--verify` and restore check a manifest the same way.
- The snapshot lock is held by one process at a time.

sudo, OpenSearch and sift-common are stand-ins at the call boundary, so these
rows run with vhir alone; nothing here writes /var/lib/vhir.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import multiprocessing as mp
import shutil
import subprocess
import sys
import types
import uuid
from argparse import Namespace
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B

CASE = "C-7"
UUID = str(uuid.UUID(int=7))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Box:
    """The stand-ins one test drives: sudo, OpenSearch, the identity module."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.sudo: list[list[str]] = []
        self.sudo_fails: set[str] = set()  # "cp", "chown"
        self.restores: list[dict] = []
        self.restore_fails = 0  # how many index restores raise
        self.keys_merged: list[Path] = []
        self.os_up = True
        self.answers: dict[str, str] | None = None  # a terminal: prompt -> answer
        self.asked: list[str] = []
        self.real_run = subprocess.run  # sudo's work, done as this user

    def run(self, argv, *a, **k):
        argv = [str(x) for x in argv]
        assert argv[0] == "sudo", argv
        self.sudo.append(argv)
        rc = 1 if argv[1] in self.sudo_fails else 0
        if not rc and argv[1] in ("cp", "rm"):  # done as this user, on tmp paths
            self.real_run(argv[1:], check=True)
        return subprocess.CompletedProcess(
            argv, rc, "", "stand-in refused" if rc else ""
        )

    def snapshot_restore(self, case_id, snapshot_dir, progress=None, **k):
        self.restores.append({"case_id": case_id, **k})
        if self.restore_fails:
            self.restore_fails -= 1
            raise RuntimeError("stand-in cluster: restore refused")

    def input(self, prompt=""):
        self.asked.append(prompt)
        return next((a for p, a in (self.answers or {}).items() if p in prompt), "")


class FakeClient:
    def __init__(self):
        self.cat = types.SimpleNamespace(indices=lambda **k: [])

    def info(self):
        return {"version": {"number": "2.19.1"}}


@pytest.fixture
def box(tmp_path, monkeypatch):
    b = Box(tmp_path)
    for name, value in (
        ("VERIFICATION_DIR", tmp_path / "sys" / "verification"),
        ("_SNAPSHOTS_DIR", tmp_path / "sys" / "snapshots"),
        ("_PASSWORDS_DIR", tmp_path / "sys" / "passwords"),
    ):
        value.mkdir(parents=True)
        monkeypatch.setattr(B, name, value)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(B.subprocess, "run", b.run)
    monkeypatch.setattr(B, "_is_opensearch_available", lambda: b.os_up)
    monkeypatch.setattr(B, "_restore_opensearch_snapshot", b.snapshot_restore)
    monkeypatch.setattr(B, "_merge_keys", b.keys_merged.append)
    monkeypatch.setattr(
        B.sys, "stdin", types.SimpleNamespace(isatty=lambda: b.answers is not None)
    )
    monkeypatch.setattr("builtins.input", b.input)
    osm = types.ModuleType("opensearch_mcp")
    osm.client = types.SimpleNamespace(get_client=lambda *a, **k: FakeClient())
    osm.paths = types.SimpleNamespace(sanitize_index_component=lambda s: s.lower())
    for name, mod in (("opensearch_mcp", osm), ("opensearch_mcp.client", osm.client),
                      ("opensearch_mcp.paths", osm.paths)):  # fmt: skip
        monkeypatch.setitem(sys.modules, name, mod)
    return b


def make_backup(box, *, ledger=True, snapshot=True, case_yaml=True, extra=None):
    """A backup of case C-7 (taken from <tmp>/cases/C-7) with its manifest."""
    bk = box.tmp / "backup" / f"{CASE}-2026-10-11"
    files = {"findings.json": b'[{"id": "F-a-001"}]\n', "timeline.json": b"[]\n"}
    if case_yaml:
        files["CASE.yaml"] = f"case_id: {CASE}\ncase_uuid: {UUID}\n".encode()
    if ledger:
        files[f"verification/{CASE}.jsonl"] = b'{"legacy": 1}\n'
    if snapshot:
        files["opensearch-snapshot/index-0"] = b"snapshot bytes"
    files.update(extra or {})
    for rel, data in files.items():
        (bk / rel).parent.mkdir(parents=True, exist_ok=True)
        (bk / rel).write_bytes(data)
    manifest = {
        "version": 1, "case_id": CASE, "timestamp": "t",
        "source": str(box.tmp / "cases" / CASE),
        "includes_verification_ledger": ledger, "includes_opensearch": snapshot,
        "files": [{"path": r, "sha256": _sha(d)} for r, d in files.items()],
    }  # fmt: skip
    if snapshot:
        manifest["opensearch_snapshot"] = {
            "case_uuid": UUID,
            "opensearch_version": "2.19.1",
        }
    (bk / "backup-manifest.json").write_text(json.dumps(manifest))
    return bk


def restore(bk, target, **flags) -> int:
    args = Namespace(backup_path=str(bk), target=str(target), skip_opensearch=False,
                     skip_ledger=False, **flags)  # fmt: skip
    try:
        B.cmd_restore(args, {"examiner": "alice"})
    except SystemExit as e:
        return e.code
    return 0


def beside(box):
    """The original still in its folder (so the restore makes a copy), and a
    stand-in sift-common to give the copy its identity."""
    src = box.tmp / "cases" / CASE
    src.mkdir(parents=True)
    (src / "CASE.yaml").write_text(f"case_id: {CASE}\ncase_uuid: {UUID}\n")
    calls = []

    class HostLogError(Exception):
        pass

    def update_case_meta(d, fields):
        calls.append(fields)
        if box.identity_fails:
            raise HostLogError("stand-in host log refused")

    box.identity_fails = False
    module = types.SimpleNamespace(update_case_meta=update_case_meta, HostLogError=HostLogError,
                                   write_case_header=lambda *a, **k: None)  # fmt: skip
    return module, calls


def _no_box_writes(box):
    assert box.sudo == [] and box.restores == [] and box.keys_merged == []
    assert list((box.tmp / "sys" / "verification").iterdir()) == []


# --- nothing outside the case before every file has verified -----------------


@pytest.mark.parametrize("place", ["in place", "beside the original"])
def test_a_damaged_backup_writes_nothing_outside_the_case(box, monkeypatch, place):
    bk = make_backup(box)
    (bk / "findings.json").write_bytes(b"damaged")
    target = box.tmp / "cases" / CASE
    if place != "in place":
        module, _ = beside(box)
        monkeypatch.setattr(B, "_host_identity", lambda: module)
        target = box.tmp / "elsewhere" / CASE
    assert restore(bk, target) == 1
    _no_box_writes(box)
    assert (target / ".restore-in-progress").exists()


def test_a_ledger_conflict_is_refused_before_the_interrupted_folder_is_deleted(box):
    bk = make_backup(box, snapshot=False)
    (B.VERIFICATION_DIR / f"{CASE}.jsonl").write_text("installed earlier\n")
    target = box.tmp / "cases" / CASE
    target.mkdir(parents=True)
    (target / ".restore-in-progress").touch()
    (target / "notes.txt").write_text("kept")
    box.answers = {"Delete it and restore again": "y"}
    assert restore(bk, target) == 1
    assert (target / "notes.txt").read_text() == "kept"


def test_a_linked_ledger_with_its_targets_hash_is_refused_before_any_sudo(box):
    secret = box.tmp / "secret.txt"
    secret.write_bytes(b"not the backup's to give\n")
    bk = make_backup(
        box, snapshot=False, extra={f"verification/{CASE}.jsonl": secret.read_bytes()}
    )
    (bk / "verification" / f"{CASE}.jsonl").unlink()
    (bk / "verification" / f"{CASE}.jsonl").symlink_to(secret)
    assert restore(bk, box.tmp / "cases" / CASE) == 1
    _no_box_writes(box)


def test_a_ledger_the_manifest_doesnt_list_is_refused_before_the_target(box):
    bk = make_backup(box, snapshot=False)
    m = json.loads((bk / "backup-manifest.json").read_text())
    m["files"] = [e for e in m["files"] if not e["path"].startswith("verification/")]
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    assert restore(bk, box.tmp / "cases" / CASE) == 1
    assert box.sudo == [] and not (box.tmp / "cases" / CASE).exists()


def test_indices_wanted_with_opensearch_unavailable_are_refused_up_front(box):
    box.os_up = False
    assert restore(make_backup(box, ledger=False), box.tmp / "cases" / CASE) == 1
    assert not (box.tmp / "cases" / CASE).exists()


def test_the_verified_ledger_is_installed_from_a_file_this_user_wrote(box):
    bk = make_backup(box, snapshot=False)
    assert restore(bk, box.tmp / "cases" / CASE) == 0
    (cp,) = [a for a in box.sudo if a[1] == "cp"]
    assert not cp[2].startswith(str(bk)), cp  # root never opens the backup
    assert (B.VERIFICATION_DIR / f"{CASE}.jsonl").read_bytes() == b'{"legacy": 1}\n'
    assert not (box.tmp / "cases" / CASE / ".restore-in-progress").exists()


def test_roots_snapshot_copy_follows_no_link(box, monkeypatch):
    """A link inside the snapshot is copied as a link, and the ownership
    change doesn't follow it; a snapshot folder that is a link is refused."""
    monkeypatch.setattr(B, "_restore_opensearch_snapshot", RESTORE)
    outside = box.tmp / "outside.txt"
    outside.write_text("outside content")
    bk = make_backup(
        box, ledger=False, extra={"opensearch-snapshot/x": outside.read_bytes()}
    )
    (bk / "opensearch-snapshot" / "x").unlink()
    (bk / "opensearch-snapshot" / "x").symlink_to(outside)
    holds = types.SimpleNamespace(get=lambda **k: {"snapshots": [{"indices": []}]},
                                  create_repository=lambda **k: None,
                                  delete_repository=lambda **k: None)  # fmt: skip
    sys.modules["opensearch_mcp.client"].get_client = lambda *a, **k: (
        types.SimpleNamespace(
            snapshot=holds,
            cat=types.SimpleNamespace(indices=lambda **k: []),
            info=FakeClient().info,
        )
    )
    monkeypatch.setattr(
        B, "subprocess", types.SimpleNamespace(**{**vars(subprocess), "run": box.run})
    )
    copied = []
    real_run = box.run

    def run(argv, *a, **k):  # the staging copy, before the clean-up removes it
        if argv[1] == "chown":
            staged = Path(argv[-1]) / "x"
            copied.append(staged.is_symlink() or not staged.exists())
        return real_run(argv, *a, **k)

    monkeypatch.setattr(B.subprocess, "run", run)
    assert restore(bk, box.tmp / "cases" / CASE) == 0
    (chown,) = [a for a in box.sudo if a[1] == "chown"]
    assert copied == [True]  # cp -r copies a link as a link
    assert "-h" in chown  # and the ownership change mustn't follow it


def test_a_snapshot_folder_that_is_a_link_is_refused(box):
    """Its files hash right (the manifest names the linked folder's own), so
    only the link check can refuse it, before anything is created."""
    linked = make_backup(box, ledger=False)
    elsewhere = box.tmp / "elsewhere-snapshot"
    shutil.move(str(linked / "opensearch-snapshot"), str(elsewhere))
    (linked / "opensearch-snapshot").symlink_to(elsewhere, target_is_directory=True)
    assert restore(linked, box.tmp / "cases" / CASE) == 1
    assert box.restores == [] and not (box.tmp / "cases" / CASE).exists()


RESTORE = B._restore_opensearch_snapshot  # the real one, for the rows that need it


# --- a part asked for that didn't happen exits 1 ------------------------------


def _backup(box, monkeypatch, *, available=True, local=True, fails=True, **flags):
    case = box.tmp / "live" / CASE
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(f"case_id: {CASE}\n")
    (case / "findings.json").write_text("[]")
    monkeypatch.setattr(
        B, "_detect_opensearch", lambda d: {"available": available, "local": local}
    )
    monkeypatch.setattr(B, "_index_scope", lambda d, c: "case-c-7-*")

    def snapshot(*a, **k):
        if fails:
            raise RuntimeError("stand-in cluster: no path.repo")
        return {"opensearch_version": "2.19.1", "index_count": 1, "total_docs": 1}

    if fails != "empty":
        monkeypatch.setattr(B, "_create_opensearch_snapshot", snapshot)
    else:
        monkeypatch.setattr(B, "_index_scope", lambda d, c: "")
    args = Namespace(destination=str(box.tmp / "dest"), case=None, verify=None,
                     **{"all": False, "include_evidence": False, "include_extractions": False,
                        "include_opensearch": False, "skip_unreadable": False, **flags})  # fmt: skip
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    try:
        B.cmd_backup(args, {"examiner": "alice"})
    except SystemExit as e:
        return e.code
    return 0


@pytest.mark.parametrize("how", ["--include-opensearch", "--all", "a terminal yes"])
def test_a_backup_whose_requested_snapshot_failed_exits_1_and_is_kept(
    box, monkeypatch, capsys, how
):
    flags = {
        "--include-opensearch": {"include_opensearch": True},
        "--all": {"all": True},
    }
    if how == "a terminal yes":
        box.answers = {"Include OpenSearch indices": "y"}
    assert _backup(box, monkeypatch, **flags.get(how, {})) == 1
    assert "without its OpenSearch indices" in capsys.readouterr().err.splitlines()[-1]
    (kept,) = (box.tmp / "dest").iterdir()
    assert B._verify_backup(kept) and not kept.name.endswith(".incomplete")


def test_a_backup_whose_0_6_records_couldnt_be_copied_exits_1(box, monkeypatch, capsys):
    (B.VERIFICATION_DIR / f"{CASE}.jsonl").write_text("legacy\n")
    real = shutil.copy2

    def copy2(src, dst, **k):
        if "/verification/" in str(dst):
            raise OSError("stand-in disk refused")
        return real(src, dst, **k)

    monkeypatch.setattr(B.shutil, "copy2", copy2)
    assert _backup(box, monkeypatch) == 1
    assert "0.6 approval records" in capsys.readouterr().err.splitlines()[-1]


@pytest.mark.parametrize(
    "case", ["a terminal no", "--all, remote cluster", "--all, no indices"]
)
def test_a_part_not_asked_for_or_with_nothing_to_include_keeps_exit_0(
    box, monkeypatch, case
):
    if case == "a terminal no":
        box.answers = {"Include OpenSearch indices": "n"}
        assert _backup(box, monkeypatch) == 0
    elif case == "--all, remote cluster":
        assert _backup(box, monkeypatch, local=False, all=True) == 0
    else:
        assert _backup(box, monkeypatch, fails="empty", all=True) == 0


# --- a PARTIAL restore is non-zero, keeps its marker, and is finished later ---


def test_a_failed_index_restore_is_partial_and_keeps_the_marker(box, capsys):
    box.restore_fails = 1
    target = box.tmp / "cases" / CASE
    assert restore(make_backup(box, ledger=False), target) == 1
    out = capsys.readouterr()
    assert "Restored case" not in out.out and "PARTIAL" in out.err
    assert json.loads((target / ".restore-in-progress").read_text())["partial"] == [
        "indices"
    ]


def test_the_second_of_several_renamed_restores_failing_is_partial(box, monkeypatch):
    module, _ = beside(box)
    monkeypatch.setattr(B, "_host_identity", lambda: module)
    monkeypatch.setattr(B, "_restore_opensearch_snapshot", RESTORE)
    old = UUID.replace("-", "")[:12]
    calls = []

    def snap_restore(**k):
        calls.append(k)
        if len(calls) == 2:
            raise RuntimeError("stand-in cluster: second restore refused")

    holds = [f"case-{old}-evtx-0", f"case-{CASE.lower()}-evtx-host1"]
    client = types.SimpleNamespace(
        snapshot=types.SimpleNamespace(get=lambda **k: {"snapshots": [{"indices": holds}]},
                                       restore=snap_restore, create_repository=lambda **k: None,
                                       delete_repository=lambda **k: None),
        cat=types.SimpleNamespace(indices=lambda **k: []), info=FakeClient().info,
        indices=types.SimpleNamespace(get=lambda **k: {}))  # fmt: skip
    sys.modules["opensearch_mcp.client"].get_client = lambda *a, **k: client
    target = box.tmp / "elsewhere" / CASE
    assert restore(make_backup(box, ledger=False), target) == 1
    assert len(calls) == 2
    assert (
        "indices"
        in json.loads((target / ".restore-in-progress").read_text())["partial"]
    )


@pytest.mark.parametrize("fails", ["cp", "chown"])
def test_a_failed_0_6_install_is_partial(box, capsys, fails):
    box.sudo_fails = {fails}
    target = box.tmp / "cases" / CASE
    assert restore(make_backup(box, snapshot=False), target) == 1
    out = capsys.readouterr()
    assert "Ledger: restored" not in out.out and "PARTIAL" in out.err
    assert json.loads((target / ".restore-in-progress").read_text())["partial"] == [
        "ledger"
    ]


@pytest.mark.parametrize("why", ["the host log refuses", "no CASE.yaml"])
def test_a_copy_that_gets_no_identity_is_partial_not_silent(box, monkeypatch, why):
    module, _ = beside(box)
    monkeypatch.setattr(B, "_host_identity", lambda: module)
    box.identity_fails = why == "the host log refuses"
    target = box.tmp / "elsewhere" / CASE
    bk = make_backup(box, ledger=False, case_yaml=why != "no CASE.yaml")
    if why == "no CASE.yaml":
        (box.tmp / "cases" / CASE / "CASE.yaml").write_text(f"case_id: {CASE}\n")
        m = json.loads((bk / "backup-manifest.json").read_text())
        m["opensearch_snapshot"]["case_uuid"] = ""
        (bk / "backup-manifest.json").write_text(json.dumps(m))
    assert restore(bk, target) == 1
    assert box.restores == []  # never under the original's names
    assert (
        "indices"
        in json.loads((target / ".restore-in-progress").read_text())["partial"]
    )


def test_a_partial_restore_run_again_finishes_only_the_missing_step(box):
    box.restore_fails = 1
    bk, target = make_backup(box, ledger=False), box.tmp / "cases" / CASE
    assert restore(bk, target) == 1
    (target / "added-by-hand.txt").write_text(
        "not the restore's"
    )  # not a restored file
    assert restore(bk, target) == 0
    assert len(box.restores) == 2 and not (target / ".restore-in-progress").exists()
    assert (target / "added-by-hand.txt").exists()


def test_work_done_in_a_partial_restore_survives_a_rerun(box):
    box.restore_fails = 1
    bk, target = make_backup(box, ledger=False), box.tmp / "cases" / CASE
    assert restore(bk, target) == 1
    (target / "findings.json").write_text('[{"id": "F-a-001"}, {"id": "F-a-002"}]')
    (target / "new.txt").write_text("new work")
    box.answers = {"": "y"}  # a terminal that says yes to anything
    assert restore(bk, target) == 1
    assert "F-a-002" in (target / "findings.json").read_text()
    assert (target / "new.txt").read_text() == "new work"
    assert not any("Delete it" in p for p in box.asked)


@pytest.mark.parametrize(
    "control", ["--skip-opensearch", "--skip-ledger", "n to indices", "n to ledger"]
)
def test_a_step_not_asked_for_keeps_exit_0(box, control):
    box.restore_fails = 1 if control in ("--skip-opensearch", "n to indices") else 0
    box.sudo_fails = {"cp"} if control in ("--skip-ledger", "n to ledger") else set()
    flags = {
        "--skip-opensearch": {"skip_opensearch": True},
        "--skip-ledger": {"skip_ledger": True},
    }
    if control.startswith("n to"):
        box.answers = {
            "OpenSearch" if control.endswith("indices") else "0.6 approval": "n"
        }
    bk = make_backup(box)
    args = {"skip_opensearch": False, "skip_ledger": False, **flags.get(control, {})}
    a = Namespace(backup_path=str(bk), target=str(box.tmp / "cases" / CASE), **args)
    with pytest.raises(SystemExit) as e:
        B.cmd_restore(a, {})
        raise SystemExit(0)
    assert e.value.code == 0


# --- one manifest check for --verify and restore ------------------------------


def _manifest(box, shape):
    bk = make_backup(box, ledger=False, snapshot=False)
    m = json.loads((bk / "backup-manifest.json").read_text())
    outside = (
        bk.parent / "outside.txt"
    )  # there, with its own hash: only the path is wrong
    outside.write_bytes(b"outside")
    entry = {"path": "../outside.txt", "sha256": _sha(b"outside")}
    m = {
        "{}": {},
        "../outside.txt": {**m, "files": m["files"] + [entry]},
        "no sha256": {**m, "files": [{"path": "findings.json"}]},
        "version 2": {**m, "version": 2},
        "no files": {**m, "files": []},
        "a non-dict entry": {**m, "files": m["files"] + ["x"]},
    }[shape]
    (bk / "backup-manifest.json").write_text(json.dumps(m))
    return bk


SHAPES = [
    "{}",
    "../outside.txt",
    "no sha256",
    "version 2",
    "no files",
    "a non-dict entry",
]


@pytest.mark.parametrize("shape", SHAPES)
def test_verify_refuses_a_manifest_restore_would_refuse(box, capsys, shape):
    assert B._verify_backup(_manifest(box, shape)) is False
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("shape", SHAPES)
def test_restore_refuses_the_manifest_before_creating_anything(box, shape):
    assert restore(_manifest(box, shape), box.tmp / "cases" / CASE) == 1
    assert not (box.tmp / "cases" / CASE).exists()


# --- the snapshot lock ---------------------------------------------------------


def _take(lock, barrier, out):
    barrier.wait(10)
    try:
        B._acquire_lock(lock)
        out.put("took")
    except RuntimeError:
        out.put("refused")
    except Exception as e:  # a taker that crashes is a failure too, not a hang
        out.put(f"crashed: {e!r}")
    with contextlib.suppress(Exception):
        barrier.wait(10)


def _race(lock: Path, start: str | None, trials: int) -> list[str]:
    """What went wrong across the trials of two processes taking the lock at
    once: both took it, or one crashed."""
    ctx, wrong = mp.get_context("fork"), []
    for _ in range(trials):
        lock.unlink(missing_ok=True)
        if start is not None:
            lock.write_text(start)
        barrier, out = ctx.Barrier(2), ctx.Queue()
        ps = [ctx.Process(target=_take, args=(lock, barrier, out)) for _ in range(2)]
        for p in ps:
            p.start()
        got = sorted(out.get(timeout=30) for _ in ps)
        for p in ps:
            p.join(30)
        if got != ["refused", "took"]:
            wrong.append(" / ".join(got))
    return wrong


def _dead_pid() -> str:
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return str(p.pid)


@pytest.mark.parametrize("start", ["free", "stale"])
def test_two_takers_never_both_hold_the_snapshot_lock(tmp_path, start):
    lock = tmp_path / ".backup.lock"
    wrong = _race(lock, _dead_pid() if start == "stale" else None, 500)
    assert wrong == [], f"{len(wrong)} of 500: {sorted(set(wrong))}"


def test_a_lock_held_by_another_users_live_process_is_held(tmp_path):
    lock = tmp_path / ".backup.lock"
    lock.write_text("1")  # init: alive, and not this user's to signal
    with pytest.raises(RuntimeError, match="in progress"):
        B._acquire_lock(lock)
    B._release_lock(lock)
    assert lock.read_text() == "1"
