"""Signing keys: the schema-3 credential in /var/lib/vhir/keys/{examiner}.json.

Each examiner has an Ed25519 key pair. The private key is stored only
AES-GCM-wrapped under a key-encryption key derived from the passphrase; the
login verifier is derived from the same passphrase with a different salt and
prefix, so neither value can stand in for the other. The public key is stored
in the clear, and its fingerprint is always recomputed from its bytes.

    auth_hash = PBKDF2-SHA256(pw, "vhir-auth\\0" + salt_auth,   600000)
    KEK       = PBKDF2-SHA256(pw, "vhir-kek\\0"  + salt_ledger, 600000)
    AAD       = "vhir-ledger-key|3|" + examiner + "|" + fingerprint(public_key)

The key list is append-only: a write may add a key or retire one, and never
drops an entry. Credential files can be read and written by processes running
as the examiner, so they are a target for offline guessing (stated limit 2).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vhir_cli.identity import valid_name

KEYS_DIR = Path("/var/lib/vhir/keys")
SCHEMA = 3
ITERATIONS = 600_000
KDF_ALG = "pbkdf2-sha256"
_AUTH_PREFIX = b"vhir-auth\x00"
_KEK_PREFIX = b"vhir-kek\x00"


class KeysFileInvalid(ValueError):
    """The keys file doesn't parse, or its parameters are weaker than this
    release writes (KEYS_FILE_INVALID)."""


class KeyUnwrapFailed(Exception):
    """The passphrase is accepted, but the signing key doesn't open with it
    (KEY_UNWRAP_FAILED)."""

    MESSAGE = (
        "Your passphrase is correct, but your signing-key file doesn't open with it; "
        "it may have been replaced. Run `vhir config --forgot-password`."
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def fingerprint(public_raw: bytes) -> str:
    """`SHA256:` and the unpadded base64 of the SHA-256 of the raw public key."""
    digest = hashlib.sha256(public_raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def public_raw(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_auth(password: str, salt_auth: str) -> str:
    """The login verifier: hex PBKDF2 over the prefixed `salt_auth`."""
    salt = _AUTH_PREFIX + bytes.fromhex(salt_auth)
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS
    ).hex()


def derive_kek(password: str, salt_ledger: str) -> bytes:
    """The key-encryption key: PBKDF2 over the prefixed `salt_ledger`. Never stored."""
    salt = _KEK_PREFIX + bytes.fromhex(salt_ledger)
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)


def _aad(examiner: str, public_b64: str) -> bytes:
    fp = fingerprint(unb64(public_b64))
    return f"vhir-ledger-key|3|{examiner}|{fp}".encode("ascii")


def wrap(private: Ed25519PrivateKey, kek: bytes, examiner: str) -> tuple[str, str]:
    """`(public_key, wrapped_private)`, both base64: the PKCS#8 private key
    under AES-256-GCM with a fresh nonce, bound to the examiner and key."""
    public_b64 = b64(public_raw(private))
    der = private.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    nonce = secrets.token_bytes(12)
    blob = nonce + AESGCM(kek).encrypt(nonce, der, _aad(examiner, public_b64))
    return public_b64, b64(blob)


def unwrap(entry: dict, kek: bytes, examiner: str) -> Ed25519PrivateKey:
    """The private key of a key entry. A KEK that doesn't open it, or a public
    key swapped in the file (it's in the AAD), raises KeyUnwrapFailed."""
    try:
        blob = unb64(entry["wrapped_private"])
        der = AESGCM(kek).decrypt(
            blob[:12], blob[12:], _aad(examiner, entry["public_key"])
        )
    except (InvalidTag, KeyError, TypeError, ValueError) as e:
        raise KeyUnwrapFailed(KeyUnwrapFailed.MESSAGE) from e
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyUnwrapFailed(KeyUnwrapFailed.MESSAGE)
    return key


# --- The file -----------------------------------------------------------------


def keys_path(examiner: str, keys_dir: Path | None = None) -> Path:
    if not valid_name(examiner):
        raise ValueError(f"Invalid examiner name: {examiner!r}")
    return (keys_dir or KEYS_DIR) / f"{examiner}.json"


def _validate(data: object) -> dict:
    """The parsed file, or KeysFileInvalid: a malformed file, a schema this
    release doesn't write, or iterations below 600000."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise KeysFileInvalid("not a schema-3 keys file")
    kdf = data.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("alg") != KDF_ALG:
        raise KeysFileInvalid("unknown key derivation")
    if not isinstance(kdf.get("iterations"), int) or kdf["iterations"] < ITERATIONS:
        raise KeysFileInvalid(f"iterations below {ITERATIONS}")
    try:
        for field in ("salt_auth", "salt_ledger", "auth_hash"):
            bytes.fromhex(data[field])
        keys = data["keys"]
        if not isinstance(keys, list):
            raise TypeError
        for k in keys:
            if len(unb64(k["public_key"])) != 32 or k.get("status") not in (
                "active",
                "retired",
            ):
                raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError) as e:
        raise KeysFileInvalid("malformed keys file") from e
    if sum(1 for k in keys if k["status"] == "active") > 1:
        raise KeysFileInvalid("more than one active key")
    return data


def load(examiner: str, keys_dir: Path | None = None) -> dict | None:
    """The examiner's keys file, None when there is none, or KeysFileInvalid."""
    path = keys_path(examiner, keys_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except UnicodeDecodeError as e:
        raise KeysFileInvalid("malformed keys file") from e
    try:
        return _validate(json.loads(text))
    except json.JSONDecodeError as e:
        raise KeysFileInvalid("malformed keys file") from e


def save(
    examiner: str,
    data: dict,
    keys_dir: Path | None = None,
    set_aside: Path | None = None,
) -> None:
    """Write atomically (0600 in a 0700 folder). Append-only: every key the
    file on disk holds must still be in `data`, by fingerprint. A file on
    disk that doesn't load is never overwritten, unless `set_aside` is a
    byte-identical copy of it just made (its keys are then recorded by the
    caller as retired)."""
    _validate(data)
    path = keys_path(examiner, keys_dir)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        on_disk = load(examiner, keys_dir)  # a file that doesn't load refuses the save
    except KeysFileInvalid as e:
        if not (set_aside is not None and _same_bytes(set_aside, path)):
            raise KeysFileInvalid(
                f"{path} doesn't load ({e}); it isn't overwritten (set it aside first)"
            ) from e
        on_disk = None
    kept = {key_fingerprint(k) for k in data["keys"]}
    dropped = [
        k for k in (on_disk or {}).get("keys", []) if key_fingerprint(k) not in kept
    ]
    if dropped:
        raise ValueError("a keys file write may not drop a key")
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _same_bytes(a: Path, b: Path) -> bool:
    try:
        return Path(a).read_bytes() == Path(b).read_bytes()
    except OSError:
        return False


def active(data: dict) -> dict | None:
    return next((k for k in data["keys"] if k["status"] == "active"), None)


def key_fingerprint(entry: dict) -> str:
    """An entry's fingerprint, recomputed from its public key bytes."""
    return fingerprint(unb64(entry["public_key"]))


# --- Lifecycle ----------------------------------------------------------------


def _fresh(examiner: str, password: str, private: Ed25519PrivateKey) -> dict:
    """The salts, verifier and wrapped key for `password`."""
    salt_auth, salt_ledger = secrets.token_hex(32), secrets.token_hex(32)
    public_b64, wrapped = wrap(private, derive_kek(password, salt_ledger), examiner)
    return {
        "salt_auth": salt_auth,
        "salt_ledger": salt_ledger,
        "auth_hash": derive_auth(password, salt_auth),
        "public_key": public_b64,
        "wrapped_private": wrapped,
    }


def new_credential(examiner: str, password: str) -> dict:
    """A schema-3 credential with a new key pair."""
    fresh = _fresh(examiner, password, Ed25519PrivateKey.generate())
    return {
        "schema": SCHEMA,
        "kdf": {"alg": KDF_ALG, "iterations": ITERATIONS},
        "auth_hash": fresh["auth_hash"],
        "salt_auth": fresh["salt_auth"],
        "salt_ledger": fresh["salt_ledger"],
        "keys": [
            {
                "public_key": fresh["public_key"],
                "wrapped_private": fresh["wrapped_private"],
                "created_at": _now(),
                "status": "active",
            }
        ],
    }


def check_password(data: dict, password: str) -> bool:
    return secrets.compare_digest(
        derive_auth(password, data["salt_auth"]), data["auth_hash"]
    )


def open_key(data: dict, examiner: str, password: str) -> Ed25519PrivateKey:
    """The active private key, unwrapped with a KEK derived from `password`.
    The verifier isn't consulted: a wrong password, or a replaced or swapped
    key, raises KeyUnwrapFailed."""
    entry = active(data)
    if entry is None or not entry.get("wrapped_private"):
        raise KeyUnwrapFailed(KeyUnwrapFailed.MESSAGE)
    return unwrap(entry, derive_kek(password, data["salt_ledger"]), examiner)


def rewrap(data: dict, examiner: str, old_password: str, new_password: str) -> dict:
    """The same key under a new passphrase: new salts, verifier and wrap; the
    public key and fingerprint unchanged (a password change, not a revocation)."""
    private = open_key(data, examiner, old_password)
    fresh = _fresh(examiner, new_password, private)
    out = json.loads(json.dumps(data))
    for field in ("salt_auth", "salt_ledger", "auth_hash"):
        out[field] = fresh[field]
    entry = active(out)
    entry["wrapped_private"] = fresh["wrapped_private"]
    return out


def retired_entry(
    public_b64: str, reason: str, superseded_by: str | None = None
) -> dict:
    entry = {
        "public_key": public_b64,
        "wrapped_private": None,
        "status": "retired",
        "retired_at": _now(),
        "retired_reason": reason,
    }
    if superseded_by:
        entry["superseded_by"] = superseded_by
    return entry


def replace_key(
    data: dict | None, examiner: str, new_password: str, reason: str
) -> dict:
    """A new active key under `new_password`. The previous active key, if any,
    is kept as retired (public key only) with `superseded_by` naming the new
    one. Every earlier entry is kept."""
    fresh = new_credential(examiner, new_password)
    if data is None:
        return fresh
    new_fp = key_fingerprint(active(fresh))
    kept = []
    for k in data["keys"]:
        if k["status"] == "active":
            k = retired_entry(k["public_key"], reason, superseded_by=new_fp)
        kept.append(k)
    fresh["keys"] = kept + fresh["keys"]
    return fresh


def public_only() -> dict:
    """A keys file with no credential: only retired public keys (a restore
    onto a box where the examiner hasn't enrolled). Enrolment treats it as
    no credential and keeps its records."""
    return {
        "schema": SCHEMA,
        "kdf": {"alg": KDF_ALG, "iterations": ITERATIONS},
        "auth_hash": "",
        "salt_auth": "",
        "salt_ledger": "",
        "keys": [],
    }


def add_retired(
    data: dict, public_b64: str, reason: str, superseded_by: str | None = None
) -> bool:
    """Record a public key as retired unless the file already holds it."""
    fp = fingerprint(unb64(public_b64))
    if any(key_fingerprint(k) == fp for k in data["keys"]):
        return False
    data["keys"].append(retired_entry(public_b64, reason, superseded_by))
    return True
