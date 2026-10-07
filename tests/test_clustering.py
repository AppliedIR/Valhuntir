"""Tests for near-duplicate finding clustering."""

from __future__ import annotations

from vhir_cli.clustering import (
    Cluster,
    cluster_findings,
    normalise,
    similarity,
    template_of,
)


def _finding(fid: str, observation: str, title: str = "Suspicious scheduled task"):
    return {
        "id": fid,
        "title": title,
        "observation": observation,
        "interpretation": "Likely persistence.",
        "status": "DRAFT",
        "confidence": "MEDIUM",
    }


def test_normalise_masks_host_varying_spans():
    assert normalise("beacon from 10.1.2.3") == "beacon from <ip>"
    assert normalise("pid 4172 exited") == "pid <n> exited"
    assert normalise("at 2026-09-17T05:12:00Z") == "at <ts>"
    assert normalise(r"C:\Users\jdoe\run.exe") == r"c:\users\<user>\run.exe"
    assert normalise("host WIN-4K2J1 flagged") == "host <host> flagged"


def test_normalise_masks_hashes_without_nibbling():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert normalise(f"hash {md5}") == "hash <md5>"
    assert normalise(f"hash {sha256}") == "hash <sha256>"


def test_identical_activity_across_hosts_forms_one_cluster():
    findings = [
        _finding("F-1", r"Task \Updater on WIN-AAA11 runs C:\Users\alice\p.exe"),
        _finding("F-2", r"Task \Updater on WIN-BBB22 runs C:\Users\bob\p.exe"),
        _finding("F-3", r"Task \Updater on WIN-CCC33 runs C:\Users\carol\p.exe"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].size == 3
    assert clusters[0].is_duplicate_group


def test_distinct_activity_stays_separate():
    findings = [
        _finding("F-1", "Scheduled task created", title="Persistence"),
        _finding("F-2", "Mimikatz executed from temp", title="Credential access"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 2
    assert all(not c.is_duplicate_group for c in clusters)


def test_wording_drift_merges_on_similarity():
    findings = [
        _finding("F-1", "The service binary was replaced on disk by the installer"),
        _finding("F-2", "The service binary was replaced on disk by an installer"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 1
    assert clusters[0].size == 2


def test_dissimilar_text_does_not_merge():
    findings = [
        _finding("F-1", "Registry run key added for persistence", title="A"),
        _finding("F-2", "Outbound transfer of 4 GB to external host", title="B"),
    ]
    clusters = cluster_findings(findings)
    assert len(clusters) == 2


def test_every_finding_appears_exactly_once():
    findings = [
        _finding(f"F-{i}", f"Task on WIN-H{i:03d} runs p.exe") for i in range(10)
    ] + [_finding("F-X", "Unrelated observation about a firewall rule", title="Net")]
    clusters = cluster_findings(findings)
    seen = [m["id"] for c in clusters for m in c.members]
    assert sorted(seen) == sorted(f["id"] for f in findings)
    assert len(seen) == len(set(seen))


def test_clustering_never_touches_status_or_identity():
    findings = [
        _finding("F-1", "Task on WIN-AAA11 runs p.exe"),
        _finding("F-2", "Task on WIN-BBB22 runs p.exe"),
    ]
    before = [dict(f) for f in findings]
    cluster_findings(findings)
    assert findings == before


def test_ordering_is_deterministic():
    findings = [
        _finding("F-1", "Unique alpha observation", title="A"),
        _finding("F-2", "Task on WIN-AAA11 runs p.exe"),
        _finding("F-3", "Task on WIN-BBB22 runs p.exe"),
    ]
    first = [c.representative["id"] for c in cluster_findings(findings)]
    second = [c.representative["id"] for c in cluster_findings(findings)]
    assert first == second
    # Largest cluster leads.
    assert first[0] == "F-2"


def test_empty_input():
    assert cluster_findings([]) == []


def test_similarity_bounds():
    assert similarity("a b c", "a b c") == 1.0
    assert similarity("a b c", "x y z") == 0.0
    assert 0.0 < similarity("a b c d", "a b c e") < 1.0


def test_template_of_uses_title_and_text():
    item = {"title": "T", "observation": "O", "interpretation": "I"}
    assert template_of(item) == "t o i"


def test_cluster_representative_is_first_member():
    c = Cluster(template="t", members=[{"id": "A"}, {"id": "B"}])
    assert c.representative["id"] == "A"
    assert c.size == 2


def test_different_cves_do_not_merge():
    # CVE-2024-1234 would otherwise normalise to "<HOST>-<N>": the host-label
    # rule eats "CVE-2024" and the integer rule eats the rest.
    a = _finding("F-1", "Exploited CVE-2024-1234 remotely", title="Exploit")
    b = _finding("F-2", "Exploited CVE-2021-44228 remotely", title="Exploit")
    assert len(cluster_findings([a, b])) == 2


def test_different_mitre_subtechniques_do_not_merge():
    a = _finding("F-1", "Technique T1003.001 observed", title="Technique")
    b = _finding("F-2", "Technique T1003.002 observed", title="Technique")
    assert len(cluster_findings([a, b])) == 2


def test_same_cve_across_hosts_still_merges():
    a = _finding("F-1", "Exploited CVE-2024-1234 on WIN-AAA11")
    b = _finding("F-2", "Exploited CVE-2024-1234 on WIN-BBB22")
    assert len(cluster_findings([a, b])) == 1


def test_normalise_preserves_identifiers():
    assert "cve_2024_1234" in normalise("Exploited CVE-2024-1234")
    assert "t1003_001" in normalise("Technique T1003.001")
