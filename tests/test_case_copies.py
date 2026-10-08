"""A case carries its own signed history, so it verifies on any box.

Close and export write the case's copies (`ledger/chains/<chain_id>.jsonl`,
`ledger/legacy-<chain_id>.jsonl`, `ledger/keys.json`); a copy that can't be
written stops the close. A bundle carries the chains, and an import adds
them without overwriting. A new line on a box references the head of each
other chain copy that verifies. A box ledger already under a case id stops a
new case with that id. `vhir update` makes the signing folders and reports
the examiner's signing key.
"""

from __future__ import annotations

import json
import types
from argparse import Namespace

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


def test_a_bundle_carries_the_keys_heads_and_chains_and_an_import_adds_them(cases):
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
    assert result["chains"]["added"] and not result["chains"]["kept_beside"]
    assert (other / "ledger" / "chains" / f"{cid}.jsonl").exists()


def test_an_import_never_overwrites_a_different_copy_of_one_chain(cases):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    bundle = export_bundle(d)
    ((cid, text),) = bundle["ledger"]["chains"].items()
    mine = d / "ledger" / "chains" / f"{cid}.jsonl"
    mine.write_text("X" + text[1:])  # differs at its first byte: neither is a prefix
    before = mine.read_bytes()
    result = import_bundle(d, bundle)
    assert mine.read_bytes() == before and len(result["chains"]["kept_beside"]) == 1


@pytest.mark.parametrize("cid", ["../evil", "notachainid0000", "ABCDEF0123456789"])
def test_an_import_refuses_a_chain_named_outside_the_rule(cases, cid):
    d = _case(cases)
    result = import_bundle(d, {"findings": [], "ledger": {"chains": {cid: "{}\n"}}})
    assert result["chains"]["refused"] and not (d / "ledger" / "chains").exists()


def test_an_import_refuses_a_chain_whose_first_line_isn_t_that_chain(cases):
    d = _case(cases, findings=[_finding(1, "APPROVED")])
    sign_approved(d, "steve")
    ((cid, text),) = export_bundle(d)["ledger"]["chains"].items()
    other = _case(cases, "C-6")
    result = import_bundle(other, {"ledger": {"chains": {"0" * 16: text}}})
    assert result["chains"]["refused"] == [
        f"chain {'0' * 16}: its first line isn't that chain's seq 1"
    ]


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
    monkeypatch.setattr(
        update, "SIGNING_DIRS", (tmp_path / "keys", tmp_path / "ledger")
    )
    (tmp_path / "keys").mkdir()
    monkeypatch.setattr(
        update, "subprocess",
        types.SimpleNamespace(run=lambda argv, **k: made.append(argv) or
                              types.SimpleNamespace(returncode=0, stderr="")),
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
