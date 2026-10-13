"""Each VALID verdict names the key of its own signing line.

The portal's badge showed one fingerprint per examiner, the last in verify's
key list, so after a key rotation an approval signed with the retired key
showed the new key's fingerprint. A verdict now carries the examiner and the
fingerprint of the line that makes it VALID.
"""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.ledger_verify import parse_pin, verify_case

from .signing import NOT_CHECKED


def _sign(case_id, item, key, examiner="steve"):
    pub = keys.b64(keys.public_raw(key))
    bodies = ledger.prepare(case_id, [{"item_id": item["id"], "type": "finding",
                                       "decision": "approve", "checks": NOT_CHECKED, "status_after": "APPROVED",
                                       "coupled_from": None,
                                       "content_snapshot": signed_text(item, "finding")}],
                            examiner, pub, "cli", "2026-10-08T10:00:00+00:00")  # fmt: skip
    with ledger.case_lock(case_id) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)
    return keys.fingerprint(keys.public_raw(key))


def test_each_verdict_names_its_own_line_s_key(tmp_path):
    ledger.LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    d = tmp_path / "C-R"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-R\n")
    items = [
        {"id": f"F-steve-00{n}", "title": "t", "status": "APPROVED", "approved_by": "steve",
         "approved_at": "2026-10-08T10:00:00+00:00"}
        for n in (1, 2)
    ]  # fmt: skip
    (d / "findings.json").write_text(json.dumps(items))
    (d / "timeline.json").write_text("[]")
    old = _sign("C-R", items[0], Ed25519PrivateKey.generate())
    new = _sign("C-R", items[1], Ed25519PrivateKey.generate())
    result = verify_case(
        d, expect_keys=[parse_pin(f"steve={old}"), parse_pin(f"steve={new}")]
    )
    assert result.exit_code == 0
    first, second = result.verdict("F-steve-001"), result.verdict("F-steve-002")
    assert (first.examiner, first.fingerprint) == ("steve", old)
    assert (second.examiner, second.fingerprint) == ("steve", new)
