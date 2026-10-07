"""Tests for the evidence-support lint."""

from __future__ import annotations

from vhir_cli.evidence_lint import lint_finding, lint_findings


def _codes(finding):
    return {f.code for f in lint_finding(finding)}


WELL_SUPPORTED = {
    "id": "F-good",
    "title": "Scheduled task created",
    "observation": "Task \\Updater created by svchost.exe at 04:12; binary at C:\\Temp\\u.exe",
    "interpretation": "Persistence mechanism.",
    "confidence": "HIGH",
    "confidence_justification": "Directly observed in the task registry hive.",
    "audit_ids": ["evt-1"],
}


def test_well_supported_finding_is_not_flagged():
    assert lint_finding(WELL_SUPPORTED) == []


def test_high_confidence_without_citations_is_flagged():
    finding = {**WELL_SUPPORTED, "audit_ids": []}
    assert "confidence-without-evidence" in _codes(finding)


def test_medium_confidence_without_citations_is_not_flagged_for_that():
    finding = {**WELL_SUPPORTED, "audit_ids": [], "confidence": "MEDIUM"}
    assert "confidence-without-evidence" not in _codes(finding)


def test_unsupported_intent_claim():
    finding = {
        "id": "F-1",
        "observation": "File deleted.",
        "interpretation": "The file was deleted in order to evade detection.",
        "confidence": "MEDIUM",
    }
    assert "unsupported-intent" in _codes(finding)


def test_intent_claim_with_citations_is_not_flagged():
    finding = {
        "id": "F-1",
        "observation": "File deleted.",
        "interpretation": "Deleted in order to evade detection.",
        "confidence": "MEDIUM",
        "audit_ids": ["evt-9"],
    }
    assert "unsupported-intent" not in _codes(finding)


def test_attribution_claim_is_always_flagged():
    finding = {
        "id": "F-1",
        "observation": "Beacon observed.",
        "interpretation": "Consistent with a known ransomware group affiliate.",
        "confidence": "MEDIUM",
        "audit_ids": ["evt-3"],
    }
    assert "attribution-claim" in _codes(finding)


def test_interpretation_far_longer_than_observation():
    finding = {
        "id": "F-1",
        "observation": "Port open.",
        "interpretation": (
            "This strongly indicates that a remote access service was installed "
            "and configured by someone with administrative rights on the host, "
            "and that it was subsequently used for interactive sessions."
        ),
        "confidence": "MEDIUM",
    }
    assert "interpretation-exceeds-observation" in _codes(finding)


def test_verbosity_not_flagged_when_evidence_cited():
    finding = {
        "id": "F-1",
        "observation": "Port open.",
        "interpretation": "A long interpretation " * 10,
        "confidence": "MEDIUM",
        "audit_ids": ["evt-2"],
    }
    assert "interpretation-exceeds-observation" not in _codes(finding)


def test_missing_observation():
    assert "no-observation" in _codes({"id": "F-1", "observation": "   "})


def test_high_confidence_without_justification():
    finding = {**WELL_SUPPORTED, "confidence_justification": ""}
    assert "unjustified-confidence" in _codes(finding)


def test_high_confidence_with_hedged_interpretation():
    finding = {**WELL_SUPPORTED, "interpretation": "This likely indicates persistence."}
    assert "hedged-but-high" in _codes(finding)


def test_hedging_at_lower_confidence_is_fine():
    finding = {
        **WELL_SUPPORTED,
        "confidence": "MEDIUM",
        "interpretation": "This likely indicates persistence.",
    }
    assert "hedged-but-high" not in _codes(finding)


def test_lint_never_mutates_or_touches_status():
    finding = {**WELL_SUPPORTED, "status": "DRAFT", "audit_ids": []}
    before = dict(finding)
    lint_finding(finding)
    assert finding == before
    assert finding["status"] == "DRAFT"
    assert finding["confidence"] == "HIGH"


def test_lint_findings_only_returns_flagged():
    flagged = lint_findings(
        [WELL_SUPPORTED, {"id": "F-bad", "confidence": "HIGH", "observation": "x"}]
    )
    assert "F-good" not in flagged
    assert "F-bad" in flagged


def test_lint_findings_empty():
    assert lint_findings([]) == {}


def test_flags_are_stable_and_deterministic():
    finding = {**WELL_SUPPORTED, "audit_ids": []}
    assert [f.code for f in lint_finding(finding)] == [
        f.code for f in lint_finding(finding)
    ]


def test_attribution_terms_match_whole_words_only():
    # "apt" is a substring of captured/adapter/attempt/laptop. Substring
    # matching flagged an attribution claim nobody made.
    for text in (
        "credentials were captured",
        "network adapter reconfigured",
        "an attempt was logged",
        "the laptop was imaged",
    ):
        finding = {"id": "F-1", "observation": text, "interpretation": text}
        assert "attribution-claim" not in _codes(finding), text


def test_real_attribution_still_flagged():
    finding = {
        "id": "F-1",
        "observation": "Beacon seen.",
        "interpretation": "Activity consistent with APT tradecraft.",
        "audit_ids": ["e1"],
    }
    assert "attribution-claim" in _codes(finding)
