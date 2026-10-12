"""A backup carries no credential, and a restore never installs one.

0.6 copied the examiners' password files into the backup and installed them
on restore. A signing key's private half now stays on its box: the backup
carries the case's signed history and the public keys that check it
(`case_dir/ledger/`), and a restore adds each of those keys to the box as a
retired key ("KEY ADDED"), never replacing a live credential. A 0.6
backup's password file is never installed; the restore says to enrol.

Every sudo call is intercepted, and /var/lib/vhir is redirected to tmp_path.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import types
from pathlib import Path

import pytest

import vhir_cli.commands.backup as B
import vhir_cli.verification as V
from vhir_cli import credentials, keys, ledger
from vhir_cli.ledger_verify import verify_case

from .signing import NOT_CHECKED, PASSPHRASE, enrol, sign_approved

OLD = "aa" * 16  # the salt in a 0.6 backup
NEW = "bb" * 16  # the salt on this box


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
        return Path(path)

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
            backup_path=str(path),
            skip_ledger=skip_ledger,
            skip_opensearch=False,
            target=json.loads((Path(path) / "backup-manifest.json").read_text())[
                "source"
            ],  # where it came from, without the prompt
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
    )


def test_a_backup_carries_no_credential_file(box):
    enrol("steve")
    path = box.backup()
    assert not (path / "passwords").exists() and not (path / "keys").exists()
    manifest = json.loads((path / "backup-manifest.json").read_text())
    assert manifest["includes_password_hashes"] is False


def test_a_restore_never_touches_this_box_s_password_file(box, capsys):
    path = box.backup()
    box.pwfile("steve", NEW)
    assert box.restore(path, ["y"]) == 0
    assert box.salt("steve") == NEW


def test_a_0_6_backup_s_password_file_is_never_installed(box, capsys):
    path = box.backup()
    (box.pw_dir / "steve.json").unlink()
    (path / "passwords").mkdir()
    (path / "passwords" / "steve.json").write_text(
        json.dumps({"salt": OLD, "hash": "h"})
    )
    manifest = json.loads((path / "backup-manifest.json").read_text())
    manifest["password_examiners"] = ["steve"]
    (path / "backup-manifest.json").write_text(json.dumps(manifest))
    assert box.restore(path) == 0
    assert box.salt("steve") is None
    assert (
        "isn't restored. Enrol with `vhir config --setup-password`"
        in capsys.readouterr().out
    )


def test_declining_the_ledger_keeps_the_live_0_6_file(box, capsys):
    path = box.backup()
    live = box.ver_dir / "hashes.jsonl"
    live.write_text(json.dumps({"finding_id": "F-steve-001", "hmac": "00"}) + "\n")
    before = live.read_bytes()
    assert box.restore(path, ["n"]) == 0
    assert live.read_bytes() == before


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


def _signed_backup(box, tmp_path, before_backup=None):
    """A case whose finding steve approved with a signed line, backed up,
    then gone from this box with its chain: a rebuilt box."""
    case = tmp_path / "cases" / "hashes"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: hashes\nstatus: open\nname: r\n")
    (case / "findings.json").write_text(json.dumps([
        {"id": "F-steve-001", "title": "t", "status": "APPROVED", "created_by": "steve"}
    ]))  # fmt: skip
    sign_approved(case, "steve")
    signer = verify_case(case).keys[0]
    if before_backup:
        before_backup(case)
    path = B.create_backup_data(case, str(tmp_path / "backups"), "steve")["backup_path"]
    shutil.rmtree(case)
    ledger.chain_path("hashes").unlink()
    return path, signer, case


def test_a_restore_adds_the_case_s_keys_as_retired_on_a_box_with_no_credential(
    box, tmp_path, capsys, monkeypatch
):
    path, signer, case = _signed_backup(box, tmp_path)
    assert box.restore(path) == 0
    assert f"KEY ADDED steve {signer['fingerprint']}" in capsys.readouterr().out
    data = keys.load("steve")
    assert [(k["status"], k["retired_reason"]) for k in data["keys"]] == [
        ("retired", "restored from a backup")
    ]
    assert credentials.state("steve", tmp_path / "cfg") == "none"  # still to enrol
    result = verify_case(case)
    assert (
        result.exit_code == 0
        and "registered here (retired: restored from a backup" in str(result.keys)
    )
    replies = iter([PASSPHRASE, PASSPHRASE])
    monkeypatch.setattr(
        "vhir_cli.approval_auth.getpass_prompt", lambda p="": next(replies)
    )
    credentials.enrol("steve", tmp_path / "cfg")  # enrolment keeps the restored record
    statuses = sorted(k["status"] for k in keys.load("steve")["keys"])
    assert statuses == ["active", "retired"]


def test_a_restore_never_replaces_a_live_credential(box, tmp_path):
    path, signer, _ = _signed_backup(box, tmp_path)
    keys.save("steve", keys.new_credential("steve", PASSPHRASE))
    active = keys.active(keys.load("steve"))["public_key"]
    assert box.restore(path) == 0
    data = keys.load("steve")
    assert keys.active(data)["public_key"] == active
    assert keys.check_password(data, PASSPHRASE)
    assert any(
        k.get("retired_reason") == "restored from a backup" for k in data["keys"]
    )


def _plant_chain(path: Path, case_id: str, key=None, bad_sig=False, examiner="alice"):
    """A one-line chain of `case_id` signed by `key` (a fresh one by default)
    at `path`. Returns the line's public key."""
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from vhir_cli.case_io import signed_text

    key = key or Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    item = {"id": "F-alice-009", "title": "t", "status": "APPROVED"}
    (body,) = ledger.prepare(case_id, [{"item_id": item["id"], "type": "finding",
                                        "decision": "approve", "checks": NOT_CHECKED, "status_after": "APPROVED",
                                        "coupled_from": None,
                                        "content_snapshot": signed_text(item, "finding")}],
                             examiner, pub, "cli", "2026-10-08T10:00:00+00:00",
                             head=(0, ledger.genesis_prev(case_id)))  # fmt: skip
    body["genesis"] = {
        "legacy_sha256": hashlib.sha256(b"").hexdigest(),
        "legacy_bytes": 0,
    }
    line = json.loads(ledger.sign_body(body, key))
    if bad_sig:
        line["sig"] = keys.b64(b"\0" * 64)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(line) + "\n")
    return pub


def test_a_restore_refuses_another_case_s_chain(box, tmp_path, capsys):
    path, signer, case = _signed_backup(box, tmp_path)
    planted = Path(path) / "ledger" / "chains" / "0123456789abcdef.jsonl"
    _plant_chain(planted, "another-case")
    manifest = json.loads((Path(path) / "backup-manifest.json").read_text())
    manifest["files"].append({"path": "ledger/chains/0123456789abcdef.jsonl",
                              "sha256": B.sha256_file(planted), "size": 1})  # fmt: skip
    (Path(path) / "backup-manifest.json").write_text(json.dumps(manifest))
    assert box.restore(path) == 0
    err = capsys.readouterr().err
    assert "Ledger copy not restored: ledger/chains/0123456789abcdef.jsonl" in err
    assert "is case 'another-case', not hashes" in err
    assert not (case / "ledger" / "chains" / "0123456789abcdef.jsonl").exists()
    assert verify_case(case).exit_code == 0


@pytest.mark.parametrize(
    "rel,why,code",
    # a path not in normal form, or with a `..` component, refuses the whole
    # restore, before anything is written
    [("./ledger/chains/0123456789abcdef.jsonl", "isn't a file path its backup writes", 1),
     ("ledger/x/../chains/0123456789abcdef.jsonl", "lists a file outside the case folder", 1),
     ("../escaped.jsonl", "lists a file outside the case folder", 1)],
)  # fmt: skip
def test_a_restore_path_is_judged_where_it_lands(box, tmp_path, capsys, rel, why, code):
    path, signer, case = _signed_backup(box, tmp_path)
    src = Path(path) / rel
    src.parent.mkdir(parents=True, exist_ok=True)
    _plant_chain(src, "another-case")
    manifest = json.loads((Path(path) / "backup-manifest.json").read_text())
    manifest["files"].append({"path": rel, "sha256": B.sha256_file(src), "size": 1})
    (Path(path) / "backup-manifest.json").write_text(json.dumps(manifest))
    assert box.restore(path) == code
    assert why in capsys.readouterr().err
    assert not (case / "ledger" / "chains" / "0123456789abcdef.jsonl").exists()
    assert not (case.parent / "escaped.jsonl").exists()
    assert verify_case(case).exit_code == 0


def test_a_restore_adds_only_keys_from_verifying_lines(box, tmp_path, capsys):
    """A chain copy whose line doesn't verify is in the case when it's backed
    up: its key reaches neither keys.json nor this box."""
    planted = {}

    def plant(case):
        planted["pub"] = _plant_chain(case / "ledger" / "chains" / "x.jsonl", "hashes",
                                      bad_sig=True, examiner="steve")  # fmt: skip

    path, signer, case = _signed_backup(box, tmp_path, plant)
    bad = keys.fingerprint(keys.unb64(planted["pub"]))
    assert bad not in (Path(path) / "ledger" / "keys.json").read_text()
    assert box.restore(path) == 0
    held = [keys.key_fingerprint(k) for k in keys.load("steve")["keys"]]
    assert held == [signer["fingerprint"]]
    assert bad not in capsys.readouterr().out


def test_a_crafted_keys_json_adds_nothing(box, tmp_path, capsys):
    """keys.json is a printout; restore reads the keys from the chains."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path, signer, case = _signed_backup(box, tmp_path)
    other = keys.b64(keys.public_raw(Ed25519PrivateKey.generate()))
    kj = Path(path) / "ledger" / "keys.json"
    kj.write_text(json.dumps({"keys": [
        {"examiner": "steve", "public_key": other, "status": "active", "wrapped_private": "AAAA"},
        {"examiner": "victim", "public_key": other},
    ]}))  # fmt: skip
    manifest = json.loads((Path(path) / "backup-manifest.json").read_text())
    for f in manifest["files"]:
        if f["path"] == "ledger/keys.json":
            f["sha256"] = B.sha256_file(kj)
    (Path(path) / "backup-manifest.json").write_text(json.dumps(manifest))
    assert box.restore(path) == 0
    assert [keys.key_fingerprint(k) for k in keys.load("steve")["keys"]] == [
        signer["fingerprint"]
    ]
    assert keys.load("victim") is None
