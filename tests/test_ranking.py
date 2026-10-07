"""Tests for deterministic review-queue ranking."""

from __future__ import annotations

from vhir_cli.ranking import (
    DEFAULT_WEIGHTS,
    actionable_signal,
    capability_signal,
    ioc_richness_signal,
    objective_overlap_signal,
    objective_terms,
    rank_findings,
    score_finding,
)

INVENTORY_NOISE = {
    "id": "F-noise",
    "title": "Installed software inventory",
    "observation": "Host has 148 packages installed.",
    "interpretation": "Baseline inventory captured.",
    "confidence": "LOW",
    "status": "DRAFT",
}

REAL_ATTACK = {
    "id": "F-real",
    "title": "Credential dumping",
    "observation": "lsass.exe accessed by rundll32.exe; memory dumped to disk.",
    "interpretation": "Credential access, likely preceding lateral movement via RDP.",
    "confidence": "HIGH",
    "status": "DRAFT",
    "audit_ids": ["evt-001"],
    "mitre_techniques": ["T1003"],
    "iocs": {"SHA256": ["a" * 64]},
}


def test_real_attack_outranks_inventory_noise():
    ranked = rank_findings([INVENTORY_NOISE, REAL_ATTACK])
    assert [r.id for r in ranked] == ["F-real", "F-noise"]


def test_ranking_is_a_permutation_nothing_hidden():
    items = [INVENTORY_NOISE, REAL_ATTACK, {"id": "F-x", "title": "Other"}]
    ranked = rank_findings(items)
    assert sorted(r.id for r in ranked) == sorted(str(i["id"]) for i in items)
    assert len(ranked) == len(items)


def test_ranking_never_mutates_findings():
    items = [dict(INVENTORY_NOISE), dict(REAL_ATTACK)]
    before = [dict(i) for i in items]
    rank_findings(items)
    assert items == before


def test_ranking_never_touches_status():
    ranked = rank_findings([dict(REAL_ATTACK)])
    assert ranked[0].item["status"] == "DRAFT"


def test_ranking_is_deterministic():
    items = [INVENTORY_NOISE, REAL_ATTACK]
    assert [r.id for r in rank_findings(items)] == [r.id for r in rank_findings(items)]


def test_equal_scores_keep_input_order():
    a = {"id": "A", "title": "x", "observation": "y"}
    b = {"id": "B", "title": "x", "observation": "y"}
    assert [r.id for r in rank_findings([a, b])] == ["A", "B"]
    assert [r.id for r in rank_findings([b, a])] == ["B", "A"]


def test_capability_signal_detects_categories():
    value, hits = capability_signal(
        {"observation": "lsass accessed then lateral movement over RDP"}
    )
    assert "credential_access" in hits
    assert "lateral_movement" in hits
    assert value > 0


def test_capability_signal_quiet_on_inventory():
    value, hits = capability_signal(INVENTORY_NOISE)
    assert hits == []
    assert value == 0.0


def test_actionable_signal_requires_cited_evidence():
    assert actionable_signal({"audit_ids": ["e1"]}) == 1.0
    assert actionable_signal({"audit_ids": []}) == 0.0
    assert actionable_signal({}) == 0.0


def test_ioc_richness_prefers_hashes_over_addresses():
    hashed = ioc_richness_signal({"iocs": {"SHA256": ["a" * 64]}})
    addressed = ioc_richness_signal({"iocs": {"IPv4": ["10.0.0.1"]}})
    assert hashed > addressed
    assert ioc_richness_signal({}) == 0.0


def test_ioc_richness_saturates():
    many = {"iocs": {"SHA256": ["a" * 64] * 50}}
    assert ioc_richness_signal(many) == 1.0


def test_ioc_richness_handles_list_form():
    value = ioc_richness_signal({"iocs": [{"type": "SHA256", "value": "a" * 64}]})
    assert value > 0


def test_objective_overlap_uses_case_metadata():
    terms = objective_terms({"scope": "ransomware deployment", "incident_type": ""})
    assert "ransomware" in terms
    hit = objective_overlap_signal({"observation": "ransomware note dropped"}, terms)
    miss = objective_overlap_signal({"observation": "printer driver installed"}, terms)
    assert hit > miss


def test_objective_overlap_is_zero_without_metadata():
    assert objective_overlap_signal({"observation": "anything"}, set()) == 0.0


def test_objective_terms_drops_short_words():
    assert "the" not in objective_terms({"name": "the big case"})


def test_reweighting_reorders_without_new_evidence():
    # The signals are the evidence; weights are policy. Changing policy must
    # re-sort without recomputing anything about the findings.
    quiet_but_cited = {
        "id": "F-cited",
        "title": "Config captured",
        "observation": "Registry hive exported.",
        "audit_ids": ["e1"],
    }
    loud_uncited = {
        "id": "F-loud",
        "title": "Beacon",
        "observation": "beacon to c2 with reverse shell",
    }
    items = [quiet_but_cited, loud_uncited]
    by_capability = rank_findings(items, weights={**DEFAULT_WEIGHTS, "actionable": 0.0})
    by_evidence = rank_findings(
        items, weights={**DEFAULT_WEIGHTS, "capability": 0.0, "actionable": 10.0}
    )
    assert by_capability[0].id == "F-loud"
    assert by_evidence[0].id == "F-cited"


def test_score_finding_exposes_breakdown():
    r = score_finding(REAL_ATTACK, objective_terms({"scope": "credential theft"}))
    assert set(r.signals) == set(DEFAULT_WEIGHTS)
    assert r.score > 0
    assert "credential_access" in r.capabilities


def test_empty_input():
    assert rank_findings([]) == []


def test_capability_terms_match_whole_words_only():
    # "c2" occurs inside most SHA-256 hex strings; substring matching tagged
    # any finding quoting a hash as command-and-control.
    digest = "a3c2ff" + "0" * 58
    _, hits = capability_signal({"observation": f"file hash {digest}"})
    assert "command_and_control" not in hits


def test_real_c2_reference_still_detected():
    _, hits = capability_signal({"observation": "beacon to C2 server"})
    assert "command_and_control" in hits
