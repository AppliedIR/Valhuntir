"""HMAC verification ledger for approved findings and timeline events.

The verification ledger lives at /var/lib/vhir/verification/{case-id}.jsonl,
outside every user's home directory. Claude Code's deny rules and sandbox keep
that client's own tools away from it; they don't limit other programs running
as the examiner's user.

Each entry records an HMAC-SHA256 over the description text, keyed by
PBKDF2(password, salt). That key is the same value as the stored password
hash, so anyone (or any program) running as a user who can read the
examiner's password file in /var/lib/vhir/passwords can create entries that
verify. The ledger does show a later change to approved text made by anyone
without that file or the password.
"""

from __future__ import annotations

import json
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


def read_ledger(case_id: str) -> list[dict]:
    """Read all entries from verification ledger."""
    _validate_case_id(case_id)
    path = VERIFICATION_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def copy_ledger_to_case(case_id: str, case_dir: Path) -> None:
    """Copy ledger to case dir for case close."""
    _validate_case_id(case_id)
    src = VERIFICATION_DIR / f"{case_id}.jsonl"
    if src.exists():
        shutil.copy2(src, case_dir / "verification.jsonl")
