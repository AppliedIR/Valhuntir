"""Sign a test case's APPROVED items, as the approve command will.

Rows whose subject isn't signing (reports, displays) still need approvals
that verify, because only verified approvals count as approved. This signs
every APPROVED item with one fresh key into the (redirected) box chain and
stamps `approved_by`/`approved_at` from the signed line.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys, ledger
from vhir_cli.case_io import load_case_meta, signed_text

AT = "2026-10-08T10:00:00+00:00"
_FILES = (
    ("findings.json", "finding"),
    ("timeline.json", "timeline"),
    ("iocs.json", "ioc"),
)
_KEYS: dict[tuple[str, str], Ed25519PrivateKey] = {}  # one key per examiner and case


def sign_approved(case_dir: Path, examiner: str = "tester") -> None:
    case_id = load_case_meta(case_dir).get("case_id") or case_dir.name
    key = _KEYS.setdefault((str(case_dir), examiner), Ed25519PrivateKey.generate())
    pub = keys.b64(keys.public_raw(key))
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    for name, kind in _FILES:
        path = case_dir / name
        if not path.exists():
            continue
        items = json.loads(path.read_text())
        approved = [
            i for i in items if isinstance(i, dict) and i.get("status") == "APPROVED"
        ]
        for item in approved:
            item["approved_by"] = item.get("approved_by") or examiner
            item["approved_at"] = AT
        decisions = [
            {"item_id": i["id"], "type": kind, "decision": "approve", "status_after": "APPROVED",
             "coupled_from": None, "content_snapshot": signed_text(i, kind)}
            for i in approved
        ]  # fmt: skip
        if not decisions:
            continue
        by = {i["approved_by"] for i in approved}
        assert len(by) == 1, "one examiner per file in this helper"
        bodies = ledger.prepare(case_id, decisions, by.pop(), pub, "cli", AT)
        with ledger.case_lock(case_id) as lock:
            ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
        mode = path.stat().st_mode
        path.chmod(0o644)
        path.write_text(json.dumps(items, indent=2))
        path.chmod(mode)
