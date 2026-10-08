"""A case carries its own signed history, so it verifies on any box.

Close and export write the case's copies (`ledger/chains/<chain_id>.jsonl`,
`ledger/legacy-<chain_id>.jsonl`, `ledger/keys.json`); a copy that can't be
written stops the close, and this box's chain always sits at its own id. A
bundle carries the chains as data, and its keys and heads as anchors; an
import adds no chain file. A new line on a box references the head of each
other chain copy that verifies. A box ledger already under a case id stops a
new case with that id. `vhir update` makes the signing folders and reports
the examiner's signing key.
"""

from __future__ import annotations

import json
import types
from argparse import Namespace
from pathlib import Path

import pytest

from vhir_cli import approval_auth, keys, ledger, verification
from vhir_cli.case_io import export_bundle, import_bundle, signed_text
from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import verify_case

from .signing import PASSPHRASE, enrol, sign_approved

IDENT = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}


@pytest.fixture
def cases(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("VHIR_CASES_DIR", str(root))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    return root


def _case(cases, case_id="C-5", findings=None):
    d = cases / case_id
    d.mkdir()
    (d / "CASE.yaml").write_text(f"case_id: {case_id}\nstatus: open\n")
    (d / "findings.json").write_text(json.dumps(findings or []))
    (d / "timeline.json").write_text("[]")
    return d


def _finding(n, status="DRAFT"):
    return {"id": f"F-steve-{n:03d}", "title": f"t{n}", "observation": "o",
            "status": status}  # fmt: skip


def _close(case_id, monkeypatch):
    from vhir_cli.main import _case_close

    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    try:
        _case_close(Namespace(case_id=case_id, summary=""), IDENT)
    except SystemExit as e:
        return e.code
    return 0


def _status(d):
    import yaml

    return yaml.safe_load((d / "CASE.yaml").read_text())["status"]


# --- Close ----------------------------------------------------------------------------


def test_close_writes_the_case_s_chain_its_0_6_copy_and_keys_then_marks_it_closed(
    cases, monkeypatch, capsys
):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    verification.VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    (verification.VERIFICATION_DIR / "C-5.jsonl").write_text("")  # a 0.6 file, empty
    sign_approved(d, "steve")
    assert _close("C-5", monkeypatch) == 0
    cid = verify_case(d).chains[0].chain_id
    assert (d / "ledger" / "chains" / f"{cid}.jsonl").read_bytes() == (
        ledger.chain_path("C-5").read_bytes()
    )
    assert (d / "ledger" / f"legacy-{cid}.jsonl").exists()
    record = json.loads((d / "ledger" / "keys.json").read_text())
    (key,) = record["keys"]
    assert key["examiner"] == "steve" and key["fingerprint"].startswith("SHA256:")
    assert record["heads"][0]["chain_id"] == cid and "copied_at" in record
    out = capsys.readouterr().out
    assert (
        f"steve {key['fingerprint']}" in out and f"Ledger head C-5 chain {cid}" in out
    )
    assert _status(d) == "closed"
    ledger.chain_path("C-5").unlink()  # on another box: the case copies alone
    assert verify_case(d).exit_code == 0


def test_a_copy_that_can_t_be_written_stops_the_close(cases, monkeypatch, capsys):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    (d / "ledger").write_text("a file where the folder goes")
    assert _close("C-5", monkeypatch) == 1
    assert "The case was not closed" in capsys.readouterr().err
    assert _status(d) == "open"


def test_close_on_a_closed_case_writes_the_copies_again(cases, monkeypatch, capsys):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    (d / "CASE.yaml").write_text("case_id: C-5\nstatus: closed\n")
    assert _close("C-5", monkeypatch) == 0
    assert list((d / "ledger" / "chains").glob("*.jsonl"))
    assert "its ledger copies are up to date" in capsys.readouterr().out


def test_after_a_reopen_the_stale_case_copy_and_the_longer_box_chain_verify(
    cases, monkeypatch
):
    d = _case(cases, findings=[_finding(1, "APPROVED"), _finding(2)])
    sign_approved(d, "steve")
    _close("C-5", monkeypatch)
    (d / "CASE.yaml").write_text("case_id: C-5\nstatus: open\n")
    enrol("steve")
    A._approve_specific(d, ["F-steve-002"], IDENT, d / "cfg")  # with a different key
    result = verify_case(d, expect_keys=[])
    assert not [c for c, _ in result.failures if c == "CHAIN_COPY_DIVERGED"]
    assert "case copy (copied " in " ".join(result.sources)


# --- Export and import ---------------------------------------------------------------------


def test_a_bundle_carries_the_keys_heads_and_chains_and_an_import_adds_none(
    cases, capsys
):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    bundle = json.loads(json.dumps(export_bundle(d)))
    block = bundle["ledger"]
    (key,) = block["keys"]
    assert set(key) >= {"examiner", "fingerprint", "public_key", "first_seq", "last_seq",
                        "label"}  # fmt: skip
    (cid,) = block["chains"]
    assert block["heads"][0]["chain_id"] == cid
    other = _case(cases, "C-6")
    (other / "CASE.yaml").write_text("case_id: C-5\nstatus: open\n")
    result = import_bundle(other, bundle)
    assert not (other / "ledger").exists()  # decisions don't travel by merge
    assert result["ledger"]["keys"] == block["keys"]
    assert result["ledger"]["heads"] == block["heads"]


def test_merge_prints_the_bundle_s_keys_and_heads_as_anchors(cases, capsys, tmp_path):
    from vhir_cli.commands.sync import cmd_merge

    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    bundle = export_bundle(d)
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    other = _case(cases, "C-6")
    capsys.readouterr()
    cmd_merge(Namespace(case="C-6", file=str(path)), IDENT)
    out = capsys.readouterr().out
    assert "The bundle's signed history wasn't added" in out
    assert bundle["ledger"]["keys"][0]["fingerprint"] in out
    assert not (other / "ledger").exists()


def test_another_case_s_bundle_changes_no_verdict(cases):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    elsewhere = _case(cases, "C-6", findings=[_finding(2, "APPROVED")])
    sign_approved(elsewhere, "steve")
    import_bundle(d, {"findings": [], "ledger": export_bundle(elsewhere)["ledger"]})
    assert verify_case(d).exit_code == 0


def _fork_of_own_chain(d):
    """A file at this box's chain id holding a different history: the box's
    seq 1 and a forged seq 2."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    box = ledger.chain_path("C-5").read_text().splitlines()
    first = json.loads(box[0])
    key = Ed25519PrivateKey.generate()
    item = _finding(9, "APPROVED")
    (body,) = ledger.prepare("C-5", [{"item_id": item["id"], "type": "finding",
                                      "decision": "approve", "status_after": "APPROVED",
                                      "coupled_from": None,
                                      "content_snapshot": signed_text(item, "finding")}],
                             "steve", keys.b64(keys.public_raw(key)), "cli",
                             "2026-10-08T11:00:00+00:00",
                             head=(1, ledger.body_hash(ledger.body_of(first))))  # fmt: skip
    cid = ledger.chain_id(ledger.body_of(first))
    path = d / "ledger" / "chains" / f"{cid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return cid, path, box[0] + "\n" + ledger.sign_body(body, key) + "\n"


def test_close_puts_this_box_s_chain_at_its_id_and_moves_a_fork_beside(
    cases, monkeypatch, capsys
):
    d = _case(cases, findings=[_finding(1, "APPROVED"), _finding(2, "APPROVED")])
    sign_approved(d, "steve")
    cid, path, fork = _fork_of_own_chain(d)
    path.write_text(fork)
    assert _close("C-5", monkeypatch) == 0
    assert "it was moved beside it" in capsys.readouterr().out
    real = ledger.chain_path("C-5").read_text()
    assert path.read_text() == real
    (beside,) = [p for p in path.parent.glob(f"{cid}.*.jsonl")]
    assert beside.read_text() == fork  # moved, never deleted
    chains = export_bundle(d)["ledger"]["chains"]
    assert chains == {cid: real}  # the recipient gets the real chain


def test_close_moves_aside_a_longer_copy_with_forged_lines(cases, monkeypatch, capsys):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = _case(cases, findings=[_finding(1, "APPROVED"), _finding(2, "APPROVED")])
    sign_approved(d, "steve")
    real = ledger.chain_path("C-5").read_text()
    last = json.loads(real.splitlines()[-1])
    key = Ed25519PrivateKey.generate()
    item = _finding(3, "APPROVED")
    (body,) = ledger.prepare("C-5", [{"item_id": item["id"], "type": "finding",
                                      "decision": "approve", "status_after": "APPROVED",
                                      "coupled_from": None,
                                      "content_snapshot": signed_text(item, "finding")}],
                             "steve", keys.b64(keys.public_raw(key)), "cli",
                             "2026-10-08T11:00:00+00:00",
                             head=(last["seq"], ledger.body_hash(ledger.body_of(last))))  # fmt: skip
    cid = ledger.chain_id(ledger.body_of(json.loads(real.splitlines()[0])))
    path = d / "ledger" / "chains" / f"{cid}.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(real + ledger.sign_body(body, key) + "\n")
    assert _close("C-5", monkeypatch) == 0
    out = capsys.readouterr().out
    assert path.read_text() == real
    forged_fp = keys.fingerprint(keys.public_raw(key))
    assert f"seq {last['seq']} " in out and forged_fp not in out


def test_a_longer_fork_diverging_before_the_box_head_supplies_no_anchor(
    cases, monkeypatch, capsys
):
    """Box chain [A1, A2]; a file at its id holding [A1, B2, B3], signed by
    another key and linked. The anchors close prints are A's alone."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = _case(cases, findings=[_finding(1, "APPROVED"), _finding(2, "APPROVED")])
    sign_approved(d, "steve")
    real = ledger.chain_path("C-5").read_text().splitlines()
    a1, a2 = json.loads(real[0]), json.loads(real[1])
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    prev, fork = a1, [real[0]]
    for seq, n in ((2, 8), (3, 9)):
        item = _finding(n, "APPROVED")
        (body,) = ledger.prepare("C-5", [{"item_id": item["id"], "type": "finding",
                                          "decision": "approve", "status_after": "APPROVED",
                                          "coupled_from": None,
                                          "content_snapshot": signed_text(item, "finding")}],
                                 "steve", pub, "cli", "2026-10-08T11:00:00+00:00",
                                 head=(seq - 1, ledger.body_hash(ledger.body_of(prev))))  # fmt: skip
        fork.append(ledger.sign_body(body, key))
        prev = body
    cid = ledger.chain_id(ledger.body_of(a1))
    path = d / "ledger" / "chains" / f"{cid}.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text("\n".join(fork) + "\n")
    assert _close("C-5", monkeypatch) == 0
    out = capsys.readouterr().out
    forged = keys.fingerprint(keys.public_raw(key))
    a2_hash = ledger.body_hash(ledger.body_of(a2))
    assert forged not in out
    assert f"chain {cid}: seq 2 sha256:{a2_hash}" in out
    assert "a copy in the case differs from this box's chain" in out
    record = json.loads((d / "ledger" / "keys.json").read_text())
    assert forged not in json.dumps(record)
    assert [(h["seq"], h["hash"]) for h in record["heads"]] == [(2, a2_hash)]


def test_another_chain_whose_copies_diverge_gives_no_anchor(cases, monkeypatch, capsys):
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))

    def line(n, head):
        item = _finding(n, "APPROVED")
        (body,) = ledger.prepare("C-5", [{"item_id": item["id"], "type": "finding",
                                          "decision": "approve", "status_after": "APPROVED",
                                          "coupled_from": None,
                                          "content_snapshot": signed_text(item, "finding")}],
                                 "alice", pub, "cli", "2026-10-08T10:00:00+00:00", head=head)  # fmt: skip
        if body["seq"] == 1:
            body["genesis"] = {"legacy_sha256": hashlib.sha256(b"").hexdigest(),
                               "legacy_bytes": 0}  # fmt: skip
        return body, ledger.sign_body(body, key)

    b1, l1 = line(7, (0, ledger.genesis_prev("C-5")))
    after = (1, ledger.body_hash(b1))
    cid = ledger.chain_id(b1)
    chains = d / "ledger" / "chains"
    chains.mkdir(parents=True)
    (chains / f"{cid}.jsonl").write_text(l1 + "\n" + line(8, after)[1] + "\n")
    (chains / f"{cid}.x.jsonl").write_text(l1 + "\n" + line(9, after)[1] + "\n")
    assert _close("C-5", monkeypatch) == 0
    out = capsys.readouterr().out
    assert keys.fingerprint(keys.unb64(pub)) not in out
    assert f"Chain {cid}: its copies diverge, so no key or head is taken from it" in out
    assert f"chain {cid}:" not in out  # no head printed for it


def test_a_malformed_anchor_block_merges_the_items_and_prints_nothing(cases):
    d = _case(cases)
    for block in ({"keys": 42}, {"keys": [{}], "heads": [{}]}, "x"):
        result = import_bundle(d, {"findings": [_finding(7)], "ledger": block})
        assert result["ledger"] == {"keys": [], "heads": []}
    assert [f["id"] for f in json.loads((d / "findings.json").read_text())] == [
        "F-steve-007"
    ]


def test_a_key_or_head_from_a_failing_line_is_never_printed(cases, monkeypatch, capsys):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    cid, path = _another_box_chain(d)
    line = json.loads(path.read_text())
    line["sig"] = keys.b64(b"\0" * 64)
    path.write_text(json.dumps(line) + "\n")
    bad_fp = keys.fingerprint(keys.unb64(line["public_key"]))
    assert _close("C-5", monkeypatch) == 0
    assert bad_fp not in capsys.readouterr().out
    record = json.loads((d / "ledger" / "keys.json").read_text())
    assert bad_fp not in json.dumps(record)
    assert cid not in {h["chain_id"] for h in record["heads"]}


def test_the_copies_wait_for_a_commit_holding_the_case_lock(cases, monkeypatch):
    import threading

    from vhir_cli import case_copies

    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    monkeypatch.setattr(case_copies, "LOCK_SECONDS", 0.2)
    with ledger.case_lock("C-5"):
        with pytest.raises(case_copies.CopyFailed, match="try again"):
            case_copies.write_case_copies("C-5", d)
    assert not (d / "ledger").exists()
    monkeypatch.setattr(case_copies, "LOCK_SECONDS", 5)
    held, release, done = threading.Event(), threading.Event(), {}

    def hold():
        with ledger.case_lock("C-5"):
            held.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    held.wait(5)
    w = threading.Thread(
        target=lambda: done.update(r=case_copies.write_case_copies("C-5", d))
    )
    w.start()
    w.join(0.3)
    assert "r" not in done  # waiting for the lock
    release.set()
    t.join()
    w.join(5)
    assert done["r"]["chain_id"]


# --- A new line references the heads of the other chain copies that verify ------------------


def _another_box_chain(d, case_id="C-5"):
    """A chain copy from another box: a signed line under another key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    item = _finding(9)
    body = ledger.prepare(case_id, [{"item_id": item["id"], "type": "finding",
                                     "decision": "approve", "status_after": "APPROVED",
                                     "coupled_from": None,
                                     "content_snapshot": signed_text(item, "finding")}],
                          "alice", pub, "cli", "2026-10-08T10:00:00+00:00",
                          head=(0, ledger.genesis_prev(case_id)))  # fmt: skip
    body[0]["genesis"] = {"legacy_sha256": __import__("hashlib").sha256(b"").hexdigest(),
                          "legacy_bytes": 0}  # fmt: skip
    cid = ledger.chain_id(body[0])
    path = d / "ledger" / "chains" / f"{cid}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(ledger.sign_body(body[0], key) + "\n")
    return cid, path


def test_a_new_line_references_a_verifying_chain_copy_and_says_so(cases, capsys):
    d = _case(cases, findings=[_finding(1)])
    cid, _ = _another_box_chain(d)
    enrol("steve")
    A._approve_specific(d, ["F-steve-001"], IDENT, d / "cfg")
    first = json.loads(ledger.chain_path("C-5").read_text().splitlines()[0])
    (ref,) = first["prior_chains"]
    assert ref["chain_id"] == cid and ref["head_seq"] == 1
    assert (
        f"This approval references chain {cid} (head seq 1 sha256:"
        in capsys.readouterr().out
    )


def test_a_chain_copy_that_doesn_t_verify_is_reported_and_not_referenced(cases, capsys):
    d = _case(cases, findings=[_finding(1)])
    _, path = _another_box_chain(d)
    line = json.loads(path.read_text())
    line["sig"] = keys.b64(b"\0" * 64)
    path.write_text(json.dumps(line) + "\n")
    enrol("steve")
    A._approve_specific(d, ["F-steve-001"], IDENT, d / "cfg")
    first = json.loads(ledger.chain_path("C-5").read_text().splitlines()[0])
    assert "prior_chains" not in first
    assert "doesn't verify end to end; not referenced" in capsys.readouterr().err


# --- A new case never takes an id this box's ledger already holds ---------------------------


@pytest.mark.parametrize("which", ["chain", "0.6 file"])
def test_case_init_refuses_an_id_this_box_already_holds_a_ledger_for(cases, which):
    from vhir_cli.main import _case_init_data

    if which == "chain":
        ledger.chain_path("C-7").write_text("{}\n")
    else:
        verification.VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
        (verification.VERIFICATION_DIR / "C-7.jsonl").write_text("{}\n")
    with pytest.raises(ValueError, match="already holds a ledger for case id C-7"):
        _case_init_data("n", "steve", cases_dir=cases, case_id="C-7")
    assert not (cases / "C-7").exists()


# --- vhir update -------------------------------------------------------------------------------


def test_update_makes_the_signing_folders_it_lacks(tmp_path, monkeypatch):
    from vhir_cli.commands import update

    made = []
    from vhir_cli.commands import client_setup

    monkeypatch.setattr(
        client_setup, "SIGNING_DIRS", (tmp_path / "keys", tmp_path / "ledger")
    )
    (tmp_path / "keys").mkdir()
    monkeypatch.setattr(
        "subprocess.run",
        lambda argv, **k: made.append(argv) or types.SimpleNamespace(returncode=0, stderr=""),
    )  # fmt: skip
    update._ensure_signing_dirs()
    (cmd,) = made
    assert (
        cmd[:3] == ["sudo", "sh", "-c"] and f"mkdir -p {tmp_path / 'ledger'}" in cmd[3]
    )
    assert "chmod 700" in cmd[3]


@pytest.mark.parametrize("state", ["schema3", "none", "legacy"])
def test_update_reports_the_signing_key_and_offers_the_upgrade(
    cases, monkeypatch, capsys, state
):
    from vhir_cli.commands import update

    if state == "schema3":
        enrol("steve")
    elif state == "legacy":
        import hashlib

        approval_auth._PASSWORDS_DIR.mkdir(parents=True, exist_ok=True)
        (approval_auth._PASSWORDS_DIR / "steve.json").write_text(json.dumps({
            "hash": hashlib.pbkdf2_hmac("sha256", b"lab-pass-0.6", bytes(32), 600_000).hex(),
            "salt": bytes(32).hex()}))  # fmt: skip
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    update._offer_signing_key(IDENT)
    out = capsys.readouterr().out
    if state == "schema3":
        assert "Signing key for steve: SHA256:" in out
    elif state == "none":
        assert "`vhir config --setup-password`" in out
    else:
        assert "0.6 password" in out and "`vhir config --upgrade-key`" in out
        assert not keys.load("steve")  # offered, not done without a terminal


def test_no_restart_says_what_the_old_gateway_still_does():
    import inspect

    from vhir_cli.commands import update

    src = inspect.getsource(update.cmd_update)
    assert "must wait for the gateway restart" in src
    assert "gateway applies every staged entry as the committer's decision" in src


def test_a_decision_signed_while_a_backup_copies_the_files_fails_it(
    tmp_path, monkeypatch
):
    """The chain copies are written first; a line appended while the case
    files are copied would leave a backup whose files are newer than its
    chain. The backup fails, and none is left under the backup's name."""
    import vhir_cli.commands.backup as B

    case = tmp_path / "cases" / "C-B"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: C-B\nstatus: open\nname: r\n")
    (case / "findings.json").write_text(json.dumps([
        {"id": "F-steve-001", "title": "t", "status": "APPROVED", "created_by": "steve"}
    ]))  # fmt: skip
    sign_approved(case, "steve")
    real = B.shutil.copy2
    signed = []

    def copy2(src, dst, **kw):
        if not signed:  # a signer commits after the chain copies were written
            signed.append(1)
            sign_approved(case, "steve")
        return real(src, dst, **kw)

    monkeypatch.setattr(B.shutil, "copy2", copy2)
    with pytest.raises(
        OSError, match="a decision was signed during the backup; run it again"
    ):
        B.create_backup_data(case, str(tmp_path / "backups"), "steve")
    assert signed and not list((tmp_path / "backups").glob("C-B-*[0-9]"))
    monkeypatch.setattr(B.shutil, "copy2", real)
    out = B.create_backup_data(case, str(tmp_path / "backups"), "steve")
    assert Path(out["backup_path"]).name.startswith("C-B-")
