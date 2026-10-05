"""An imported timeline event can't couple to a finding's approval.

Approval approves and signs every timeline event whose auto_created_from
names the finding being approved. Only forensic-mcp's auto-timeline sets that
field, but an imported bundle (`vhir merge`, case-mcp's import_bundle, both
through case_io.import_bundle) kept it, so a bundle's event was approved and
signed unseen with a local finding, could overwrite the local event's
text and keep the coupling, or ride along with its own finding.
The password step and the HMAC ledger are stood in for; the ledger records
what would be signed.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.case_io import import_bundle
from vhir_cli.commands import approve

IDENTITY = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}
NOW = "2026-01-01T00:00:00+00:00"


def _finding(fid):
    return {
        "id": fid,
        "title": "Local finding",
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "type": "finding",
        "status": "DRAFT",
        "staged": NOW,
        "modified_at": NOW,
        "created_by": "steve",
        "examiner": "steve",
        "timeline_event_id": "T-steve-001",
    }


def _auto_event(fid):
    """The event forensic-mcp's record_finding writes for a finding."""
    return {
        "id": "T-steve-001",
        "timestamp": "2026-01-01T00:00:00Z",
        "description": "Local finding",
        "source": "",
        "event_type": "other",
        "related_findings": [fid],
        "auto_created_from": fid,
        "status": "DRAFT",
        "staged": NOW,
        "modified_at": NOW,
        "created_by": "steve",
        "examiner": "steve",
    }


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "INC-2026-1571"
    case.mkdir()
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": case.name, "status": "open"}))
    (case / "findings.json").write_text(json.dumps([_finding("F-steve-001")]))
    (case / "timeline.json").write_text(json.dumps([_auto_event("F-steve-001")]))
    return case


def _timeline(case):
    return {t["id"]: t for t in json.loads((case / "timeline.json").read_text())}


def _signed_by(run):
    signed = []

    def ledger(case_dir, items, *a, **kw):
        signed.extend(i["id"] for i in items)
        return []

    with (
        patch.object(approve, "require_confirmation", return_value=("pw", "pw")),
        patch.object(approve, "_write_verification_entries", side_effect=ledger),
    ):
        run()
    return signed


R1_R2 = {
    "timeline": [
        {
            "id": "T-x-900",  # a bundle event citing the local finding
            "timestamp": "2026-01-03T00:00:00Z",
            "description": "INJECTED via bundle",
            "auto_created_from": "F-steve-001",
            "related_findings": ["F-steve-001"],
            "host": "h9",
            "custom_key": "v",
            "modified_at": "2099-01-01T00:00:00+00:00",
        },
        {
            "id": "T-steve-001",  # a newer copy of the local auto event
            "timestamp": "2026-01-01T00:00:00Z",
            "description": "OVERWRITTEN legit event text",
            "auto_created_from": "F-steve-001",
            "related_findings": ["F-steve-001"],
            "modified_at": "2099-01-01T00:00:00+00:00",
        },
    ]
}


def test_imported_events_dont_carry_the_coupling_or_get_signed(case):
    import_bundle(case, R1_R2)
    stored = _timeline(case)
    assert stored["T-steve-001"]["description"].startswith(
        "OVERWRITTEN"
    )  # LWW, as documented
    for tid in ("T-x-900", "T-steve-001"):
        assert "auto_created_from" not in stored[tid], stored[tid]
    signed = _signed_by(
        lambda: approve._approve_specific(case, ["F-steve-001"], IDENTITY, Path("x"))
    )
    stored = _timeline(case)
    assert signed == ["F-steve-001"]
    assert {stored[t]["status"] for t in ("T-x-900", "T-steve-001")} == {"DRAFT"}


def test_a_bundle_carrying_its_own_finding_and_event_signs_only_the_finding(case):
    """Riding along with its own finding, on the dashboard review path."""
    import_bundle(
        case,
        {
            "findings": [
                {
                    "id": "F-mallory-001",
                    "title": "plausible finding",
                    "observation": "o",
                    "interpretation": "i",
                    "confidence": "LOW",
                    "type": "finding",
                    "modified_at": "2026-01-05T00:00:00+00:00",
                }
            ],
            "timeline": [
                {
                    "id": "T-mallory-001",
                    "timestamp": "2026-01-04T00:00:00Z",
                    "description": "ARBITRARY narrative",
                    "auto_created_from": "F-mallory-001",
                    "modified_at": "2026-01-05T00:00:00+00:00",
                }
            ],
        },
    )
    assert "auto_created_from" not in _timeline(case)["T-mallory-001"]
    (case / "pending-reviews.json").write_text(
        json.dumps(
            {
                "case_id": case.name,
                "items": [{"id": "F-mallory-001", "action": "approve"}],
            }
        )
    )
    signed = _signed_by(lambda: approve._review_mode(case, IDENTITY, Path("x")))
    assert signed == ["F-mallory-001"]
    assert _timeline(case)["T-mallory-001"]["status"] == "DRAFT"


def test_a_local_auto_created_event_still_couples(case):
    signed = _signed_by(
        lambda: approve._approve_specific(case, ["F-steve-001"], IDENTITY, Path("x"))
    )
    assert sorted(signed) == ["F-steve-001", "T-steve-001"]
    assert _timeline(case)["T-steve-001"]["status"] == "APPROVED"


def test_an_imported_event_keeps_its_other_fields(case):
    import_bundle(case, R1_R2)
    event = _timeline(case)["T-x-900"]
    assert (event["host"], event["custom_key"], event["related_findings"]) == (
        "h9",
        "v",
        ["F-steve-001"],
    )
