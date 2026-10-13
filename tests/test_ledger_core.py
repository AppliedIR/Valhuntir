"""The signed ledger's one writer: bodies, the chain, the case lock, commit.

`commit` appends only under the case lock, only on the head the bodies were
prepared on, and only lines whose signatures verify under the examiner's
active key; otherwise nothing is written. Locking never creates the chain.
"""

from __future__ import annotations

import base64
import hashlib
import json
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys, ledger, verification

from .signing import NOT_CHECKED

AT = "2026-10-08T10:00:00+00:00"


@pytest.fixture
def steve():
    cred = keys.new_credential("steve", "four unrelated words here")
    return keys.open_key(cred, "steve", "four unrelated words here")


def _pub(private) -> str:
    return keys.b64(keys.public_raw(private))


def _decision(
    item_id="F-steve-001", decision="approve", status="APPROVED", text='{"t":1}'
):
    return {
        "item_id": item_id,
        "type": "finding",
        "decision": decision,
        "status_after": status,
        "coupled_from": None,
        **({"checks": NOT_CHECKED} if decision == "approve" else {}),
        "content_snapshot": text,
    }


def _commit(private, decisions, case="C1", **kw):
    bodies = ledger.prepare(case, decisions, "steve", _pub(private), "cli", AT, **kw)
    lines = [ledger.sign_body(b, private) for b in bodies]
    with ledger.case_lock(case) as lock:
        return ledger.commit(lock, bodies, lines, _pub(private)), bodies, lines


@pytest.fixture(autouse=True)
def ledger_dir():
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)


def test_the_first_line_names_the_case_and_freezes_the_legacy_ledger(steve):
    verification.VERIFICATION_DIR.mkdir(parents=True)
    legacy = b'{"finding_id": "F-old-001"}\n'
    (verification.VERIFICATION_DIR / "C1.jsonl").write_bytes(legacy)
    head, (body,), _ = _commit(steve, [_decision()])
    assert (
        body["seq"] == 1
        and body["prev"] == hashlib.sha256(b"vhir-ledger-genesis|C1").hexdigest()
    )
    assert body["genesis"] == {
        "legacy_sha256": hashlib.sha256(legacy).hexdigest(),
        "legacy_bytes": len(legacy),
    }
    assert body["v"] == 4 and body["view"] == 2 and body["mode"] == "cli"
    assert body["content_sha256"] == hashlib.sha256(b'{"t":1}').hexdigest()
    assert head == (1, ledger.body_hash(body)) == ledger.current_head("C1")


def test_lines_are_chained_and_canonical(steve):
    _, (first,), _ = _commit(steve, [_decision()])
    _, (second, third), lines = _commit(
        steve, [_decision("F-steve-002"), _decision("F-steve-003")]
    )
    assert (second["seq"], second["prev"]) == (2, ledger.body_hash(first))
    assert (third["seq"], third["prev"]) == (3, ledger.body_hash(second))
    assert "genesis" not in second
    for text in lines:
        assert text == json.dumps(
            json.loads(text), sort_keys=True, separators=(",", ":")
        )
        assert ledger.signature_valid(json.loads(text))
    stored = [p for _, _, p in ledger.read_lines(ledger.chain_path("C1"))]
    assert [p["seq"] for p in stored] == [1, 2, 3]
    assert stat.S_IMODE(ledger.chain_path("C1").stat().st_mode) == 0o600


def test_a_changed_field_breaks_the_signature(steve):
    _, _, (text,) = _commit(steve, [_decision()])
    line = json.loads(text)
    line["at"] = "2026-10-09T00:00:00+00:00"
    assert not ledger.signature_valid(line)


def test_commit_needs_the_case_lock(steve):
    bodies = ledger.prepare("C1", [_decision()], "steve", _pub(steve), "cli", AT)
    lines = [ledger.sign_body(b, steve) for b in bodies]
    with pytest.raises(ledger.LockNotHeld):
        ledger.commit(
            ledger.case_lock("C1"), bodies, lines, _pub(steve)
        )  # not acquired
    with ledger.case_lock("C2") as other, pytest.raises(ledger.LockNotHeld):
        ledger.commit(other, bodies, lines, _pub(steve))
    assert not ledger.chain_path("C1").exists()


def test_a_moved_head_writes_nothing(steve):
    bodies = ledger.prepare("C1", [_decision()], "steve", _pub(steve), "cli", AT)
    lines = [ledger.sign_body(b, steve) for b in bodies]
    _commit(steve, [_decision("F-steve-009")])  # someone else's commit lands first
    before = ledger.chain_path("C1").read_bytes()
    with ledger.case_lock("C1") as lock, pytest.raises(ledger.LedgerMoved):
        ledger.commit(lock, bodies, lines, _pub(steve))
    assert ledger.chain_path("C1").read_bytes() == before


def test_a_line_signed_by_another_key_writes_nothing(steve):
    eve = keys.open_key(keys.new_credential("steve", "x" * 20), "steve", "x" * 20)
    bodies = ledger.prepare("C1", [_decision()], "steve", _pub(eve), "cli", AT)
    lines = [ledger.sign_body(b, eve) for b in bodies]
    with ledger.case_lock("C1") as lock, pytest.raises(ledger.BadSignature):
        ledger.commit(lock, bodies, lines, _pub(steve))  # steve's active key
    assert not ledger.chain_path("C1").exists()


def test_a_line_that_isn_t_its_body_writes_nothing(steve):
    bodies = ledger.prepare("C1", [_decision()], "steve", _pub(steve), "cli", AT)
    swapped = dict(bodies[0], content_snapshot='{"t":2}')
    lines = [ledger.sign_body(swapped, steve)]  # validly signed, but not the body
    with ledger.case_lock("C1") as lock, pytest.raises(ledger.BadSignature):
        ledger.commit(lock, bodies, lines, _pub(steve))
    assert not ledger.chain_path("C1").exists()


def test_the_lock_never_creates_the_chain():
    with ledger.case_lock("C1"):
        assert ledger.lock_path("C1").exists()
        assert not ledger.chain_path("C1").exists()


def test_a_held_lock_makes_another_writer_wait_then_give_up():
    waited = []
    with ledger.case_lock("C1"):
        with pytest.raises(ledger.LedgerBusy, match="nothing was written"):
            ledger.case_lock(
                "C1", timeout=0.2, on_wait=lambda: waited.append(1)
            ).acquire()
    assert waited == [1]  # told once
    with ledger.case_lock("C1", timeout=0.2):  # free again
        pass


def test_a_missing_ledger_folder_names_vhir_update():
    ledger.LEDGER_DIR.rmdir()
    with pytest.raises(ledger.LockDirMissing, match="run `vhir update` to create it"):
        ledger.case_lock("C1").acquire()


def test_a_new_key_s_first_line_names_the_keys_it_supersedes(steve):
    _commit(steve, [_decision()])
    old_fp = keys.fingerprint(keys.public_raw(steve))
    new = keys.open_key(keys.new_credential("steve", "y" * 20), "steve", "y" * 20)
    unused = keys.fingerprint(keys.public_raw(Ed25519PrivateKey.generate()))
    bodies = ledger.prepare(
        "C1",
        [_decision("F-steve-002")],
        "steve",
        _pub(new),
        "cli",
        AT,
        retired=[old_fp, unused],
    )
    assert bodies[0]["supersedes"] == [old_fp]  # a key with no lines here isn't named
    lines = [ledger.sign_body(b, new) for b in bodies]
    with ledger.case_lock("C1") as lock:
        ledger.commit(lock, bodies, lines, _pub(new))
    later = ledger.prepare(
        "C1",
        [_decision("F-steve-003")],
        "steve",
        _pub(new),
        "cli",
        AT,
        retired=[old_fp],
    )
    assert "supersedes" not in later[0]  # only on the key's first line here
    mine = ledger.prepare(
        "C1",
        [_decision("F-steve-003")],
        "steve",
        _pub(steve),
        "cli",
        AT,
        retired=[old_fp],
    )
    assert "supersedes" not in mine[0]  # never the signing key itself


def test_prior_chains_go_on_the_first_body_only(steve):
    refs = [{"chain_id": "0123456789abcdef", "head_seq": 4, "head_hash": "ab" * 32}]
    bodies = ledger.prepare(
        "C1", [_decision(), _decision("F-steve-002")], "steve", _pub(steve), "cli", AT,
        prior_chains=refs,
    )  # fmt: skip
    assert bodies[0]["prior_chains"] == refs and "prior_chains" not in bodies[1]


def test_a_chain_id_is_the_first_body_s_hash_prefix(steve):
    _, (first,), _ = _commit(steve, [_decision()])
    assert ledger.chain_id(first) == ledger.body_hash(first)[:16]


@pytest.mark.parametrize("case_id", ["", "../x", "a/b", "a\\b"])
def test_a_case_id_can_t_leave_the_ledger_folder(case_id):
    with pytest.raises(ValueError):
        ledger.chain_path(case_id)


def test_a_line_whose_signature_was_altered_writes_nothing(steve):
    """The body and key are right; the signature bytes aren't."""
    bodies = ledger.prepare("C1", [_decision()], "steve", _pub(steve), "cli", AT)
    line = json.loads(ledger.sign_body(bodies[0], steve))
    sig = bytearray(base64.b64decode(line["sig"]))
    sig[0] ^= 1
    line["sig"] = base64.b64encode(bytes(sig)).decode()
    with ledger.case_lock("C1") as lock, pytest.raises(ledger.BadSignature):
        ledger.commit(lock, bodies, [json.dumps(line)], _pub(steve))
    assert not ledger.chain_path("C1").exists()


def test_a_last_line_without_its_newline_gets_one_before_the_append(steve):
    _commit(steve, [_decision()])
    path = ledger.chain_path("C1")
    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    _commit(steve, [_decision("F-steve-002")])
    lines = ledger.read_lines(path)
    assert [p["seq"] for _, _, p in lines] == [1, 2]


def test_a_torn_last_line_refuses_the_write(steve):
    """Torn after the bodies were prepared (a portal plan): commit refuses."""
    _commit(steve, [_decision()])
    bodies = ledger.prepare(
        "C1", [_decision("F-steve-002")], "steve", _pub(steve), "cli", AT
    )
    lines = [ledger.sign_body(b, steve) for b in bodies]
    path = ledger.chain_path("C1")
    path.write_bytes(path.read_bytes() + b'{"v":3,"seq":2,"pre')
    before = path.read_bytes()
    with ledger.case_lock("C1") as lock:
        with pytest.raises(ledger.LedgerError, match="last line is incomplete"):
            ledger.commit(lock, bodies, lines, _pub(steve))
    with pytest.raises(ledger.LedgerError, match="last line is incomplete"):
        _commit(steve, [_decision("F-steve-003")])  # and prepare refuses too
    assert path.read_bytes() == before


def test_bodies_that_don_t_follow_one_another_write_nothing(steve):
    bodies = ledger.prepare(
        "C1", [_decision(), _decision("F-steve-002")], "steve", _pub(steve), "cli", AT
    )
    bodies[1] = dict(bodies[1], prev="00" * 32)
    lines = [ledger.sign_body(b, steve) for b in bodies]
    with (
        ledger.case_lock("C1") as lock,
        pytest.raises(ValueError, match="don't follow"),
    ):
        ledger.commit(lock, bodies, lines, _pub(steve))
    assert not ledger.chain_path("C1").exists()


@pytest.mark.parametrize("case_id", [".", "..", "C\n1", "C\x7f"])
def test_dot_names_and_control_characters_aren_t_case_ids(case_id):
    with pytest.raises(ValueError):
        ledger.chain_path(case_id)
