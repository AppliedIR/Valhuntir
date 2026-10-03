"""Backup and restore keep the control files out of the case tree.

A backup holds the live ledger (verification/<case_id>.jsonl), the
declared examiners' hashes (passwords/<ex>.json) and an optional OpenSearch
snapshot alongside the case files. Restore copied all of them into the case
directory too (hash material where the LLM can read it); the next backup then
copied those stale case-dir copies over the live ones it had just written,
and a later restore installed them. Restore also installed any
passwords/*.json in the backup, declared or not.

Every sudo call is intercepted, and the ledger and password directories are
redirected to tmp_path: nothing here writes /var/lib/vhir.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import types

import pytest

import vhir_cli.commands.backup as B

CONTROL_TOPS = ("verification", "passwords", "opensearch-snapshot")


@pytest.fixture
def box(tmp_path, monkeypatch):
    sysdir = tmp_path / "sys"
    pw_dir = sysdir / "passwords"
    ver_dir = sysdir / "verification"
    pw_dir.mkdir(parents=True)
    ver_dir.mkdir()
    monkeypatch.setattr(B, "_PASSWORDS_DIR", pw_dir)
    monkeypatch.setattr(B, "VERIFICATION_DIR", ver_dir)
    monkeypatch.setattr(B, "_SNAPSHOTS_DIR", sysdir / "snapshots")
    monkeypatch.setattr(B, "_is_opensearch_available", lambda: False)
    monkeypatch.setattr(B, "_verify_restored_password", lambda examiner: None)
    installed = []

    def sudo(argv, *a, **k):
        argv = [str(x) for x in argv]
        assert argv[0] == "sudo", argv
        for p in argv[2:]:
            if p.startswith("/") and ":" not in p:
                assert p.startswith(str(tmp_path)), ("sudo outside tmp_path", argv)
        if argv[1] == "cp":  # as root: the destination's mode doesn't matter
            if os.path.exists(argv[-1]):
                os.chmod(argv[-1], 0o600)
            shutil.copy(argv[-2], argv[-1])
            installed.append(os.path.basename(argv[-1]))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(
        B, "subprocess", types.SimpleNamespace(**{**vars(subprocess), "run": sudo})
    )
    case = tmp_path / "cases" / "backups"

    def make_case(examiners=("steve",)):
        case.mkdir(parents=True)
        (case / "CASE.yaml").write_text("case_id: backups\nstatus: open\nname: r\n")
        findings = [{"id": f"F-{e}-001", "created_by": e} for e in examiners]
        (case / "findings.json").write_text(json.dumps(findings))
        return case

    def pwfile(name, salt):
        (pw_dir / f"{name}.json").write_text(
            json.dumps({"salt": salt, "hash": "h-" + salt})
        )

    def ledger(n):
        lines = [
            json.dumps({"finding_id": f"F-steve-{i:03d}"}) for i in range(1, n + 1)
        ]
        (ver_dir / "backups.jsonl").write_text("\n".join(lines) + "\n")

    def backup():
        return B.create_backup_data(case, str(tmp_path / "backups"), "steve")

    def lose_case():
        """Disaster: the case dir and the live ledger are gone."""
        shutil.rmtree(case)
        (ver_dir / "backups.jsonl").unlink(missing_ok=True)

    def restore(path, answers=("y",)):
        replies = iter(answers)
        monkeypatch.setattr(B.sys, "stdin", types.SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
        args = types.SimpleNamespace(
            backup_path=str(path), skip_ledger=False, skip_opensearch=True
        )
        try:
            B.cmd_restore(args, {"examiner": "steve"})
        except SystemExit as e:
            return e.code
        return 0

    def salt(name, where=pw_dir):
        p = where / f"{name}.json"
        return json.loads(p.read_text())["salt"] if p.exists() else None

    def control_in_case():
        return sorted(
            str(p.relative_to(case))
            for p in case.rglob("*")
            if p.is_file() and p.relative_to(case).parts[0] in CONTROL_TOPS
        )

    return types.SimpleNamespace(
        case=case,
        make_case=make_case,
        pwfile=pwfile,
        ledger=ledger,
        backup=backup,
        lose_case=lose_case,
        restore=restore,
        salt=salt,
        control_in_case=control_in_case,
        pw_dir=pw_dir,
        ver_dir=ver_dir,
        installed=installed,
    )


def _declare_snapshot(path):
    """Add a declared OpenSearch snapshot, as _create_opensearch_snapshot would."""
    path = os.fspath(path)
    snap = os.path.join(path, "opensearch-snapshot")
    os.mkdir(snap)
    with open(os.path.join(snap, "index-0"), "w") as fh:
        fh.write("snapshot blob")
    mpath = os.path.join(path, "backup-manifest.json")
    with open(mpath) as fh:
        m = json.load(fh)
    m["files"].append(
        {
            "path": "opensearch-snapshot/index-0",
            "sha256": hashlib.sha256(b"snapshot blob").hexdigest(),
            "bytes": 13,
        }
    )
    m["includes_opensearch"] = True
    m["opensearch_snapshot"] = {"index_count": 1, "total_docs": 1}
    with open(mpath, "w") as fh:
        json.dump(m, fh)


def _restore_once(box):
    """Back up a case with ledger, hash and a declared snapshot, lose it,
    restore it. Returns the restore's stdout via capsys in the caller."""
    box.make_case()
    box.pwfile("steve", "aa" * 16)
    box.ledger(1)
    path = box.backup()["backup_path"]
    _declare_snapshot(path)
    box.lose_case()
    assert box.restore(path) == 0
    return path


def test_restore_puts_no_control_files_in_the_case_dir(box):
    _restore_once(box)
    assert box.control_in_case() == []


def test_after_a_restore_the_next_backup_and_restore_use_the_live_copies(box):
    _restore_once(box)
    box.ledger(2)  # the examiner keeps working: one more approval
    box.pwfile("steve", "cc" * 16)  # and changes their password
    path = box.backup()["backup_path"]
    backed = os.path.join(path, "verification", "backups.jsonl")
    with open(backed) as fh:
        assert len(fh.read().splitlines()) == 2
    assert box.salt("steve", B.Path(path) / "passwords") == "cc" * 16
    box.lose_case()
    (box.pw_dir / "steve.json").unlink()
    assert box.restore(path) == 0
    assert len((box.ver_dir / "backups.jsonl").read_text().splitlines()) == 2
    assert box.salt("steve") == "cc" * 16


def test_a_case_restored_by_older_code_still_backs_up_the_live_copies(box):
    case = box.make_case()
    (case / "verification").mkdir()
    (case / "verification" / "backups.jsonl").write_text(
        '{"finding_id": "F-steve-001"}\n'
    )
    (case / "passwords").mkdir()
    (case / "passwords" / "steve.json").write_text(json.dumps({"salt": "aa" * 16}))
    box.pwfile("steve", "cc" * 16)
    box.ledger(2)
    path = B.Path(box.backup()["backup_path"])
    assert len((path / "verification" / "backups.jsonl").read_text().splitlines()) == 2
    assert box.salt("steve", path / "passwords") == "cc" * 16


@pytest.mark.parametrize(
    "alice_on_box", [True, False], ids=["alice-live", "fresh-alice"]
)
def test_a_hash_planted_in_the_case_dir_is_not_installed(box, alice_on_box):
    case = box.make_case()
    (case / "passwords").mkdir()
    (case / "passwords" / "alice.json").write_text(json.dumps({"salt": "ee" * 16}))
    box.pwfile("steve", "aa" * 16)
    if alice_on_box:
        box.pwfile("alice", "11" * 16)
    box.ledger(1)
    path = box.backup()["backup_path"]
    box.lose_case()
    box.restore(path)
    assert "alice.json" not in box.installed
    assert box.salt("alice") == ("11" * 16 if alice_on_box else None)


def test_anchor_user_files_under_those_names_are_restored(box):
    case = box.make_case()
    (case / "passwords").mkdir()
    (case / "passwords" / "cracked-hashes.txt").write_text("user data 1")
    (case / "verification").mkdir()
    (case / "verification" / "hash-check-notes.txt").write_text("user data 2")
    box.pwfile("steve", "aa" * 16)
    box.ledger(1)
    path = box.backup()["backup_path"]
    box.lose_case()
    assert box.restore(path) == 0
    assert (case / "passwords" / "cracked-hashes.txt").read_text() == "user data 1"
    assert (case / "verification" / "hash-check-notes.txt").read_text() == "user data 2"


def test_anchor_post_restore_verification_has_nothing_missing(box, capsys):
    path = _restore_once(box)
    out = capsys.readouterr().out
    with open(os.path.join(path, "backup-manifest.json")) as fh:
        n = len(json.load(fh)["files"])
    assert f"Files: {n} verified\n" in out and "MISSING" not in out, out


def test_anchor_both_declared_examiners_are_installed_on_a_fresh_box(box):
    box.make_case(examiners=("alice", "steve"))
    box.pwfile("steve", "aa" * 16)
    box.pwfile("alice", "a1" * 16)
    box.ledger(1)
    path = box.backup()["backup_path"]
    box.lose_case()
    for p in box.pw_dir.glob("*.json"):
        p.unlink()
    assert box.restore(path) == 0
    assert sorted(p.stem for p in box.pw_dir.glob("*.json")) == ["alice", "steve"]


def test_anchor_plain_files_named_like_the_control_dirs(box):
    case = box.make_case()
    (case / "passwords").write_text("examiner's own file named 'passwords'")
    (case / "verification").write_text("examiner's own file named 'verification'")
    box.pwfile("steve", "aa" * 16)
    box.ledger(2)
    r = box.backup()
    path = B.Path(r["backup_path"])
    assert r["includes_verification_ledger"] and r["password_examiners"] == ["steve"]
    assert len((path / "verification" / "backups.jsonl").read_text().splitlines()) == 2
    assert (path / "passwords" / "steve.json").is_file()
