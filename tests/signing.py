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
PASSPHRASE = "testpass1"
_CREDENTIALS: dict[
    tuple[str, str], dict
] = {}  # one credential per examiner and passphrase


def enrol(examiner: str, passphrase: str = PASSPHRASE) -> dict:
    """A schema-3 credential for `examiner` in the (redirected) keys folder, and
    the ledger folder the installer makes: the state `vhir enrol` leaves. The
    key pair is made once per run (deriving is slow); each test's ledger is its own."""
    data = _CREDENTIALS.get((examiner, passphrase))
    if data is None:
        data = _CREDENTIALS[(examiner, passphrase)] = keys.new_credential(
            examiner, passphrase
        )
    keys.save(examiner, json.loads(json.dumps(data)))
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    return data


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
        bodies = ledger.prepare(
            case_id, [with_checks(d) for d in decisions], by.pop(), pub, "cli", AT
        )
        with ledger.case_lock(case_id) as lock:
            ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
        mode = path.stat().st_mode
        path.chmod(0o644)
        path.write_text(json.dumps(items, indent=2))
        path.chmod(mode)


# What the approving paths sign for an item that records no chain (one made
# before chains, as every test item here): the approval checks don't apply
NOT_CHECKED = {"result": "not-applicable", "items": []}


def with_checks(decision: dict) -> dict:
    """`decision` as the approving paths hand it to ledger.prepare: a direct
    approval of a finding or event carries the approval checks' result."""
    direct = (
        decision["decision"] == "approve"
        and decision["type"] in ("finding", "timeline")
        and not decision.get("coupled_from")
    )
    return {**decision, "checks": NOT_CHECKED} if direct else decision


def approve_under_0_6(
    case_dir: Path, ids, examiner: str = "tester", at: str = AT
) -> None:
    """A case approved under 0.6, as 0.6's approve left it (its writer is
    gone): each of `ids` APPROVED and stamped, with its 0.6 line in the
    (redirected) 0.6 file. Nothing is signed, so the case has no genesis."""
    from vhir_cli import verification

    case_id = load_case_meta(case_dir).get("case_id") or case_dir.name
    for name, kind in _FILES:
        path = case_dir / name
        if not path.exists():
            continue
        items = json.loads(path.read_text())
        for item in items:
            if isinstance(item, dict) and item.get("id") in ids:
                item.update(status="APPROVED", approved_by=examiner, approved_at=at)
                verification.VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
                with open(
                    verification.VERIFICATION_DIR / f"{case_id}.jsonl", "a"
                ) as fh:
                    fh.write(json.dumps({
                        "finding_id": item["id"], "type": kind, "hmac": "00",
                        "hmac_version": 2, "content_snapshot": signed_text(item, kind, 0),
                        "approved_by": examiner, "approved_at": at, "case_id": case_id,
                    }) + "\n")  # fmt: skip
        mode = path.stat().st_mode
        path.chmod(0o644)
        path.write_text(json.dumps(items, indent=2))
        path.chmod(mode)
