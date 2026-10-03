"""Restore never replaces a different password hash already on this box.

The examiner may have changed their password since the backup: installing
the backup's hash over it broke HMAC verification of the live ledger (and
did so even when the examiner declined to restore the ledger). A box with
no hash for the examiner still gets the backup's. Declining the ledger at
the prompt is reported as "Ledger: skipped".

Every sudo call is intercepted, and the ledger and password directories
are redirected to tmp_path: nothing here writes /var/lib/vhir.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import types

import pytest

import vhir_cli.commands.backup as B
import vhir_cli.verification as V

OLD = "aa" * 16  # the salt in the backup
NEW = "bb" * 16  # the salt after a password change since the backup


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
    monkeypatch.setattr(V, "VERIFICATION_DIR", ver_dir)
    monkeypatch.setattr(B, "_is_opensearch_available", lambda: False)
    verified = []
    monkeypatch.setattr(B, "_verify_restored_password", verified.append)

    def sudo(argv, *a, **k):
        argv = [str(x) for x in argv]
        assert argv[0] == "sudo", argv
        for p in argv[2:]:
            if p.startswith("/") and ":" not in p:
                assert p.startswith(str(tmp_path)), ("sudo outside tmp_path", argv)
        if argv[1] == "cp":  # as root: the destination's mode doesn't matter
            dest = argv[-1]
            if shutil.os.path.exists(dest):
                shutil.os.chmod(dest, 0o600)
            shutil.copy(argv[-2], dest)
        return subprocess.CompletedProcess(argv, 0, "", "")

    fake = types.SimpleNamespace(**{**vars(subprocess), "run": sudo})
    monkeypatch.setattr(B, "subprocess", fake)

    def pwfile(name, salt):
        (pw_dir / f"{name}.json").write_text(
            json.dumps({"salt": salt, "hash": "h-" + salt, "iterations": 600000})
        )

    def salt(name):
        p = pw_dir / f"{name}.json"
        return json.loads(p.read_text())["salt"] if p.exists() else None

    def backup(*, ledger=True, examiners=("steve",)):
        case = tmp_path / "cases" / "hashes"
        case.mkdir(parents=True)
        (case / "CASE.yaml").write_text("case_id: hashes\nstatus: open\nname: r\n")
        findings = [{"id": f"F-{e}-001", "created_by": e} for e in examiners]
        (case / "findings.json").write_text(json.dumps(findings))
        for e in examiners:
            pwfile(e, OLD)
        if ledger:
            (ver_dir / "hashes.jsonl").write_text(
                json.dumps({"finding_id": "F-steve-001"}) + "\n"
            )
        path = B.create_backup_data(case, str(tmp_path / "backups"), "steve")[
            "backup_path"
        ]
        shutil.rmtree(case)
        (ver_dir / "hashes.jsonl").unlink(missing_ok=True)
        return path

    def restore(path, answers=None, skip_ledger=False):
        if answers is None:
            monkeypatch.setattr(
                B.sys, "stdin", types.SimpleNamespace(isatty=lambda: False)
            )
        else:
            replies = iter(answers)
            monkeypatch.setattr(
                B.sys, "stdin", types.SimpleNamespace(isatty=lambda: True)
            )
            monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
        args = types.SimpleNamespace(
            backup_path=str(path), skip_ledger=skip_ledger, skip_opensearch=False
        )
        try:
            B.cmd_restore(args, {"examiner": "steve"})
        except SystemExit as e:
            return e.code
        return 0

    return types.SimpleNamespace(
        pwfile=pwfile,
        salt=salt,
        backup=backup,
        restore=restore,
        pw_dir=pw_dir,
        ver_dir=ver_dir,
        verified=verified,
    )


def _warned(out, name="steve"):
    return f"({name})" in out and "not installed" in out


def test_a_different_hash_is_kept_and_warned(box, capsys):
    path = box.backup()
    box.pwfile("steve", NEW)
    assert box.restore(path, ["y"]) == 0
    out = capsys.readouterr()
    assert box.salt("steve") == NEW and _warned(out.err), out


def test_declining_the_ledger_keeps_live_hmac_working(box, capsys):
    path = box.backup()
    box.pwfile("steve", NEW)
    key = V.derive_hmac_key("pw", bytes.fromhex(NEW))
    snap = "F-steve-001 First finding"
    entry = {
        "finding_id": "F-steve-001",
        "approved_by": "steve",
        "hmac": V.compute_hmac(key, snap),
        "content_snapshot": snap,
    }
    (box.ver_dir / "hashes.jsonl").write_text(json.dumps(entry) + "\n")

    def verified():
        current = bytes.fromhex(box.salt("steve"))
        return [r["verified"] for r in V.verify_items("hashes", "pw", current, "steve")]

    assert verified() == [True]
    assert box.restore(path, ["n"]) == 0
    assert box.salt("steve") == NEW and verified() == [True]


def test_no_ledger_in_the_backup_still_keeps_the_hash(box, capsys):
    path = box.backup(ledger=False)
    box.pwfile("steve", NEW)
    assert box.restore(path) == 0
    assert box.salt("steve") == NEW and _warned(capsys.readouterr().err)


@pytest.mark.parametrize("answer", ["n", "y"], ids=["declined", "accepted"])
def test_anchor_a_fresh_box_gets_the_backup_hash(box, capsys, answer):
    path = box.backup()
    (box.pw_dir / "steve.json").unlink()
    assert box.restore(path, [answer]) == 0
    assert box.salt("steve") == OLD and box.verified == ["steve"]


def test_anchor_skip_ledger_installs_no_hash(box):
    path = box.backup()
    (box.pw_dir / "steve.json").unlink()
    box.restore(path, skip_ledger=True)
    assert box.salt("steve") is None


def test_anchor_an_identical_hash_is_restored_as_today(box, capsys):
    path = box.backup()
    assert box.restore(path, ["y"]) == 0
    out = capsys.readouterr()
    assert "Password hashes... restored (steve)" in out.out and not _warned(out.err)
    assert box.salt("steve") == OLD


def test_declining_the_ledger_is_reported_as_skipped(box, capsys):
    path = box.backup()
    box.restore(path, ["n"])
    lines = [ln.strip() for ln in capsys.readouterr().out.splitlines()]
    # the summary line, not the padded "Ledger:       yes" of the backup's header
    summary = [
        ln
        for ln in lines
        if ln.startswith("Ledger: ") and not ln.startswith("Ledger:  ")
    ]
    assert summary == ["Ledger: skipped"]


def test_each_examiner_is_decided_separately(box, capsys):
    path = box.backup(examiners=("alice", "steve"))
    box.pwfile("steve", NEW)
    (box.pw_dir / "alice.json").unlink()
    assert box.restore(path, ["y"]) == 0
    err = capsys.readouterr().err
    assert box.salt("steve") == NEW and box.salt("alice") == OLD
    assert _warned(err, "steve") and not _warned(err, "alice")


def test_an_unreadable_hash_is_kept_and_warned(box, capsys):
    path = box.backup()
    box.pwfile("steve", NEW)
    (box.pw_dir / "steve.json").chmod(0)
    try:
        if (box.pw_dir / "steve.json").stat().st_mode & 0o777 == 0:
            try:
                (box.pw_dir / "steve.json").read_bytes()
                pytest.skip("running as root: a mode-000 file is still readable")
            except PermissionError:
                pass
        assert box.restore(path, ["y"]) == 0
    finally:
        (box.pw_dir / "steve.json").chmod(0o600)
    assert box.salt("steve") == NEW and _warned(capsys.readouterr().err)


def test_an_unsearchable_store_is_reported_as_unchecked(box, capsys):
    """The restoring user can't search the password directory: whether a
    hash exists is unknown, so nothing is installed and the message says so
    (not "existing, different")."""
    path = box.backup()
    (box.pw_dir / "steve.json").unlink()
    box.pw_dir.chmod(0)
    try:
        try:
            (box.pw_dir / "steve.json").exists()
            searchable = True
        except PermissionError:
            searchable = False
        if searchable:
            pytest.skip("this Python or user can still search a mode-000 directory")
        assert box.restore(path, ["y"]) == 0
    finally:
        box.pw_dir.chmod(0o755)
    err = capsys.readouterr().err
    assert box.salt("steve") is None
    assert (
        "(steve)... couldn't check for an existing hash" in err
        and "not installed" in err
    )
    assert "existing, different" not in err
