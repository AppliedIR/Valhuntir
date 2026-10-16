"""What a ledger line signs: the item's signed view.

View 0 is the 0.6 set, for legacy lines. View 1 also signs
`timeline_event_id`, which a timeline cascade follows, and leaves out the
re-attestation stamp. An IOC's four derived fields are signed in neither.
View 1's key set is pinned: a change adds a view, it never edits one.
"""

from __future__ import annotations

import json

from vhir_cli.case_io import (
    HASH_EXCLUDE_KEYS,
    IOC_DERIVED_KEYS,
    VIEW_EXCLUDES,
    hmac_text,
    signed_text,
)

FINDING = {
    "id": "F-steve-001",
    "title": "PsExec",
    "observation": "seen",
    "status": "APPROVED",
    "approved_by": "steve",
    "timeline_event_id": "T-steve-001",
    "reattested_by": "steve",
    "reattested_at": "2026-10-08T00:00:00Z",
    "content_hash": "x",
}


def test_view_1_s_exclusions_are_pinned():
    assert VIEW_EXCLUDES[1] == {
        "status", "approved_at", "approved_by", "rejected_at", "rejected_by",
        "rejection_reason", "examiner_notes", "examiner_modifications", "content_hash",
        "verification", "modified_at", "provenance", "provenance_warnings",
        "source_evidence", "reattested_at", "reattested_by",
    }  # fmt: skip
    assert VIEW_EXCLUDES[0] == HASH_EXCLUDE_KEYS
    assert {
        "source_findings",
        "sightings",
        "confidence",
        "mitre_techniques",
    } == IOC_DERIVED_KEYS


def test_view_1_signs_the_timeline_link_and_not_the_reattest_stamp():
    signed = json.loads(signed_text(FINDING, "finding"))
    assert signed == {
        "id": "F-steve-001",
        "title": "PsExec",
        "observation": "seen",
        "timeline_event_id": "T-steve-001",
    }


def test_view_0_is_the_0_6_text():
    assert signed_text(FINDING, "finding", view=0) == hmac_text(FINDING)


def test_an_ioc_s_derived_fields_aren_t_signed():
    ioc = {"id": "IOC-steve-001", "value": "1.2.3.4", "type": "ip", "tags": ["c2"],
           "confidence": "HIGH", "sightings": ["WKS01"], "source_findings": ["F-1"],
           "mitre_techniques": ["T1071"], "manually_reviewed": False}  # fmt: skip
    for view in (0, 1):
        assert json.loads(signed_text(ioc, "ioc", view)) == {
            "id": "IOC-steve-001", "value": "1.2.3.4", "type": "ip", "tags": ["c2"],
            "manually_reviewed": False,
        }  # fmt: skip
    assert "confidence" in json.loads(signed_text({"confidence": "LOW"}, "finding"))


def test_view_2_signs_the_provenance_fields_and_is_pinned():
    assert VIEW_EXCLUDES[2] == VIEW_EXCLUDES[1] - {
        "source_evidence", "provenance", "provenance_warnings", "examiner_modifications",
    }  # fmt: skip
    item = {**FINDING, "provenance": "MCP", "source_evidence": "/e/mem.7z",
            "provenance_warnings": ["w"], "examiner_modifications": {"a": 1}}  # fmt: skip
    signed = json.loads(signed_text(item, "finding"))
    assert {"provenance", "source_evidence", "provenance_warnings",
            "examiner_modifications"} <= set(signed)  # fmt: skip
    assert signed_text(item, "finding") == signed_text(item, "finding", view=2)
