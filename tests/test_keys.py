"""The schema-3 signing credential: what opens the key, and what can't.

The login verifier and the key-encryption key come from one passphrase with
different salts and prefixes, so the stored verifier can't stand in for the
key; the wrapped key is bound to its examiner and public key; a file weaker
than this release writes is refused; and a key is never dropped.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys

PW = "four unrelated words here"


@pytest.fixture
def cred():
    return keys.new_credential("steve", PW)


def test_a_new_credential_opens_with_its_passphrase_only(cred):
    assert cred["schema"] == 3 and cred["kdf"] == {
        "alg": "pbkdf2-sha256",
        "iterations": 600000,
    }
    assert keys.check_password(cred, PW) and not keys.check_password(cred, PW + "x")
    private = keys.open_key(cred, "steve", PW)
    assert keys.b64(keys.public_raw(private)) == keys.active(cred)["public_key"]
    with pytest.raises(keys.KeyUnwrapFailed):
        keys.open_key(cred, "steve", PW + "x")


def test_the_fingerprint_is_recomputed_from_the_key_bytes(cred):
    fp = keys.key_fingerprint(keys.active(cred))
    assert re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fp)
    raw = keys.unb64(keys.active(cred)["public_key"])
    assert fp == "SHA256:" + __import__("base64").b64encode(
        hashlib.sha256(raw).digest()
    ).decode().rstrip("=")
    assert "key_id" not in keys.active(cred)  # never stored


def test_the_stored_verifier_opens_nothing(cred):
    """The verifier used as the KEK, as an Ed25519 seed or as an HMAC key."""
    stored = bytes.fromhex(cred["auth_hash"])
    with pytest.raises(keys.KeyUnwrapFailed):
        keys.unwrap(keys.active(cred), stored, "steve")
    seed_key = Ed25519PrivateKey.from_private_bytes(stored)
    assert keys.b64(keys.public_raw(seed_key)) != keys.active(cred)["public_key"]
    assert hmac.new(stored, b"x", hashlib.sha256).digest() != keys.derive_kek(
        PW, cred["salt_ledger"]
    )


def test_the_two_derivations_differ_even_with_equal_salts():
    salt = "ab" * 32
    assert keys.derive_auth(PW, salt) != keys.derive_kek(PW, salt).hex()


def test_a_swapped_public_key_doesn_t_open(cred):
    other = keys.new_credential("steve", PW)
    keys.active(cred)["public_key"] = keys.active(other)["public_key"]
    with pytest.raises(keys.KeyUnwrapFailed, match="--forgot-password"):
        keys.open_key(cred, "steve", PW)


def test_a_wrapped_key_bound_to_another_examiner_doesn_t_open(cred):
    with pytest.raises(keys.KeyUnwrapFailed):
        keys.open_key(cred, "eve", PW)


def test_a_replaced_wrapped_key_doesn_t_open(cred):
    keys.active(cred)["wrapped_private"] = keys.active(
        keys.new_credential("steve", "x" * 20)
    )["wrapped_private"]
    assert keys.check_password(cred, PW)  # the passphrase is right; the key file isn't
    with pytest.raises(keys.KeyUnwrapFailed) as e:
        keys.open_key(cred, "steve", PW)
    assert "Your password is correct, but your signing-key file doesn't open" in str(
        e.value
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["kdf"].update(iterations=1000),
        lambda d: d["kdf"].update(alg="argon2id"),
        lambda d: d.update(schema=2),
        lambda d: d.update(salt_auth="zz"),
        lambda d: d["keys"][0].update(public_key="AAAA"),
        lambda d: d["keys"].append(dict(d["keys"][0])),  # two active keys
    ],
    ids=["iterations", "alg", "schema", "salt", "public key", "two active"],
)
def test_a_weaker_or_malformed_file_is_refused(cred, change):
    change(cred)
    keys.KEYS_DIR.mkdir(parents=True)
    (keys.KEYS_DIR / "steve.json").write_text(json.dumps(cred))
    with pytest.raises(keys.KeysFileInvalid):
        keys.load("steve")


def test_anchor_a_saved_credential_loads_and_is_owner_only(cred):
    keys.save("steve", cred)
    path = keys.KEYS_DIR / "steve.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert keys.load("steve") == cred
    assert keys.load("eve") is None


def test_a_password_change_rewraps_the_same_key(cred):
    new = keys.rewrap(cred, "steve", PW, "a different long passphrase")
    assert keys.active(new)["public_key"] == keys.active(cred)["public_key"]
    for field in ("salt_auth", "salt_ledger", "auth_hash"):
        assert new[field] != cred[field]
    assert keys.active(new)["wrapped_private"] != keys.active(cred)["wrapped_private"]
    assert keys.check_password(new, "a different long passphrase")
    keys.open_key(new, "steve", "a different long passphrase")
    with pytest.raises(keys.KeyUnwrapFailed):
        keys.open_key(new, "steve", PW)


def test_a_replaced_key_keeps_the_old_one_as_retired(cred):
    old_fp = keys.key_fingerprint(keys.active(cred))
    new = keys.replace_key(
        cred, "steve", "a new long passphrase here", "forgotten-password reset"
    )
    retired, current = new["keys"]
    assert keys.key_fingerprint(retired) == old_fp
    assert retired["status"] == "retired" and retired["wrapped_private"] is None
    assert retired["retired_reason"] == "forgotten-password reset"
    assert retired["superseded_by"] == keys.key_fingerprint(current) != old_fp
    assert current["status"] == "active"
    keys.open_key(new, "steve", "a new long passphrase here")


def test_a_write_never_drops_a_key(cred):
    keys.save(
        "steve", keys.replace_key(cred, "steve", "a new long passphrase", "reset")
    )
    fresh = keys.new_credential("steve", "yet another passphrase")
    with pytest.raises(ValueError, match="may not drop a key"):
        keys.save("steve", fresh)


def test_a_retired_record_is_added_once(cred):
    other = keys.active(keys.new_credential("steve", PW))["public_key"]
    assert keys.add_retired(cred, other, "found in ledger, not confirmed")
    assert not keys.add_retired(cred, other, "found in ledger, not confirmed")
    assert [k["status"] for k in cred["keys"]] == ["active", "retired"]
