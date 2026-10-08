"""The 0.6 approval records: /var/lib/vhir/verification/{case-id}.jsonl.

0.6 wrote one HMAC line per approval here, keyed by the stored password hash,
so anyone who could read that file could make lines it accepted. 0.7 never
writes this file: every decision is a signed line in the case's ledger
(vhir_cli.ledger). Verify reads these records only to show 0.6 approvals as
"approved under 0.6 (before signing)"; once a case has its first signed line,
its 0.6 records are fixed by length and hash in that line. This module keeps
the folder's location and the reader backup uses.
"""

from __future__ import annotations

import json
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
