"""Findings signed under 0.6.4 still verify: the 0.6.5 challenge fields
change no hash or view list.

Three findings in the shapes 0.6.4 stored (a native finding with the 0.6.4
challenge marker, an old writer's provenance_warnings, and an import), with
the content hash and the three signed views 0.6.4 computed for them (vhir
2a99ba1, recorded below). Every value must still come out the same, or a
signed finding would read as tampered. The new fields are inside the hash.
"""

from __future__ import annotations

import hashlib

import pytest

from vhir_cli.case_io import compute_content_hash, signed_text

FIXTURES = {
    "native": {
        "id": "F-alice-001",
        "status": "APPROVED",
        "title": "evil.exe ran",
        "observation": "o",
        "interpretation": "i",
        "confidence": "MEDIUM",
        "confidence_justification": "j",
        "type": "finding",
        "audit_ids": ["sift-alice-20261001-001"],
        "staged": "2026-10-01T10:00:00+00:00",
        "modified_at": "2026-10-01T10:00:00+00:00",
        "created_by": "alice",
        "examiner": "alice",
        "provenance": "MCP",
        "provenance_detail": {"summary": "MCP", "mcp": ["sift-alice-20261001-001"]},
        "provenance_grade": "FULL",
        "provenance_schema": 2,
        "challenged": {
            "outcome": "stands",
            "skeptic_audit_ids": ["sift-alice-20261001-002"],
        },
    },
    "old writer": {
        "id": "F-alice-002",
        "status": "APPROVED",
        "title": "evil.exe ran",
        "observation": "o",
        "interpretation": "i",
        "confidence": "MEDIUM",
        "confidence_justification": "j",
        "type": "finding",
        "audit_ids": ["sift-alice-20261001-001"],
        "staged": "2026-10-01T10:00:00+00:00",
        "modified_at": "2026-10-01T10:00:00+00:00",
        "created_by": "alice",
        "examiner": "alice",
        "provenance": "MCP",
        "provenance_detail": {"summary": "MCP", "mcp": ["sift-alice-20261001-001"]},
        "provenance_grade": "FULL",
        "provenance_schema": 2,
        "provenance_warnings": ["Failed to resolve source evidence (filesystem error)"],
    },
    "imported": {
        "id": "F-other-001",
        "status": "APPROVED",
        "title": "evil.exe ran",
        "observation": "o",
        "interpretation": "i",
        "confidence": "MEDIUM",
        "confidence_justification": "j",
        "type": "finding",
        "audit_ids": ["sift-alice-20261001-001"],
        "staged": "2026-10-01T10:00:00+00:00",
        "modified_at": "2026-10-01T10:00:00+00:00",
        "created_by": "alice",
        "examiner": "alice",
        "provenance": "MCP",
        "provenance_detail": {"summary": "MCP", "mcp": ["sift-alice-20261001-001"]},
        "provenance_grade": "FULL",
        "provenance_schema": 2,
        "provenance_warnings": ["w-from-bundle"],
        "imported_from": {
            "case_id": "c-src",
            "examiner": "other",
            "exported_at": "2026-10-01T09:00:00+00:00",
        },
        "challenged": {
            "outcome": "withdrawn",
            "skeptic_audit_ids": ["sift-other-20261001-001"],
            "contradiction": "no such file",
        },
    },
}

# compute_content_hash, then sha256(signed_text(item, "finding", view)) for views 0, 1, 2
HASHES_064 = {
    "native": [
        "d892f57b1f85d8f43ebe2e20ca63f24222d0efaf0b1f75a979a48a219e7db041",
        "d892f57b1f85d8f43ebe2e20ca63f24222d0efaf0b1f75a979a48a219e7db041",
        "d892f57b1f85d8f43ebe2e20ca63f24222d0efaf0b1f75a979a48a219e7db041",
        "a4d53eb7a19016753b6fe9ddbbae275cfe7ffed4a567eac82a088dd71b0555b5",
    ],
    "old writer": [
        "546a28a278af7a68d926c788443f2f8ac21afce21497915e1a824555cac8768c",
        "546a28a278af7a68d926c788443f2f8ac21afce21497915e1a824555cac8768c",
        "546a28a278af7a68d926c788443f2f8ac21afce21497915e1a824555cac8768c",
        "209720c1bcd836a633f87c071352e65444c38963138b564869522aa03e3c202e",
    ],
    "imported": [
        "21f9a15ceb5ef660f42355e0e406c55f625809ca8ab455ef1b3cca9406e30d49",
        "21f9a15ceb5ef660f42355e0e406c55f625809ca8ab455ef1b3cca9406e30d49",
        "21f9a15ceb5ef660f42355e0e406c55f625809ca8ab455ef1b3cca9406e30d49",
        "17ce9138b56c8e85dfa1d15ce97705785b272967c4b9b3c09ede5abb91368fd2",
    ],
}


@pytest.mark.parametrize("name", list(FIXTURES))
def test_a_finding_signed_under_064_hashes_as_it_did(name):
    item = FIXTURES[name]
    now = [compute_content_hash(item)] + [
        hashlib.sha256(signed_text(item, "finding", v).encode()).hexdigest()
        for v in (0, 1, 2)
    ]
    assert now == HASHES_064[name]


@pytest.mark.parametrize("field, value", [
    ("challenged", {"outcome": "contested", "checks": [], "skeptic_audit_ids": [],
                     "contradiction": "c"}),
    ("prior_challenge", [{"kind": "withdrawn", "ref": "r", "contradiction": "c", "new_since": []}]),
    ("produced_by", {"client": "codex", "model": "m", "self_reported": True}),
])  # fmt: skip
def test_the_new_challenge_fields_are_signed(field, value):
    item = dict(FIXTURES["native"])
    before = [compute_content_hash(item)] + [
        signed_text(item, "finding", v) for v in (0, 1, 2)
    ]
    item[field] = value
    after = [compute_content_hash(item)] + [
        signed_text(item, "finding", v) for v in (0, 1, 2)
    ]
    assert all(b != a for b, a in zip(before, after, strict=True))
