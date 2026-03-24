"""HMAC verification ledger for approved findings and timeline events.

The verification ledger lives at /var/lib/vhir/verification/{case-id}.jsonl.
This path is outside any user's home directory and is unreachable by the
Claude Code sandbox from any CWD.

Each entry records an HMAC-SHA256 over the description text, keyed by
PBKDF2(password, salt). The LLM cannot forge entries because it does not know
the password-derived key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

VERIFICATION_DIR = Path("/var/lib/vhir/verification")
PBKDF2_ITERATIONS = 600_000


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id:
        raise ValueError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise ValueError(f"Invalid case ID (path traversal characters): {case_id}")


def derive_hmac_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-derive HMAC key from password + salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


def compute_hmac(derived_key: bytes, description: str) -> str:
    """HMAC-SHA256 over description text."""
    return hmac.new(
        derived_key, description.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def write_ledger_entry(case_id: str, entry: dict) -> None:
    """Append entry to /var/lib/vhir/verification/{case_id}.jsonl."""
    _validate_case_id(case_id)
    VERIFICATION_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(path, 0o600)


def read_ledger(case_id: str) -> list[dict]:
    """Read all entries from verification ledger."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


def copy_ledger_to_case(case_id: str, case_dir: Path) -> None:
    """Copy ledger to case dir for case close."""
    _validate_case_id(case_id)
    src = VERIFICATION_DIR / f"{case_id}.jsonl"
    if src.exists():
        shutil.copy2(src, case_dir / "verification.jsonl")


def verify_items(case_id: str, password: str, salt: bytes, examiner: str) -> list[dict]:
    """Verify HMAC for all items belonging to examiner."""
    derived_key = derive_hmac_key(password, salt)
    entries = read_ledger(case_id)
    results = []
    for entry in entries:
        if entry.get("approved_by") != examiner:
            continue
        expected = compute_hmac(derived_key, entry.get("content_snapshot", ""))
        actual = entry.get("hmac", "")
        results.append(
            {
                "finding_id": entry["finding_id"],
                "type": entry.get("type", "finding"),
                "verified": hmac.compare_digest(expected, actual),
            }
        )
    return results


def rehmac_entries(
    case_id: str,
    examiner: str,
    old_password: str,
    old_salt: bytes,
    new_password: str,
    new_salt: bytes,
    *,
    old_key: bytes | None = None,
    new_key: bytes | None = None,
) -> int:
    """Re-HMAC all entries for examiner after password rotation. Returns count.

    Pass pre-derived old_key/new_key to avoid redundant PBKDF2 derivation
    when calling in a loop across multiple ledger files.
    """
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return 0

    if old_key is None:
        old_key = derive_hmac_key(old_password, old_salt)
    if new_key is None:
        new_key = derive_hmac_key(new_password, new_salt)

    entries = read_ledger(case_id)
    count = 0
    updated = []
    for entry in entries:
        if entry.get("approved_by") != examiner:
            updated.append(entry)
            continue
        # Verify old HMAC first
        desc = entry.get("content_snapshot", "")
        expected = compute_hmac(old_key, desc)
        actual = entry.get("hmac", "")
        if not hmac.compare_digest(expected, actual):
            # HMAC doesn't match with old key — skip (don't corrupt)
            updated.append(entry)
            continue
        # Re-sign with new key
        entry["hmac"] = compute_hmac(new_key, desc)
        updated.append(entry)
        count += 1

    # Rewrite the file atomically (temp + rename to prevent truncation on crash)
    import tempfile

    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for entry in updated:
                f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)
    return count
