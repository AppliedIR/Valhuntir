"""Group near-duplicate findings so they can be reviewed as one unit.

An automated sweep across many hosts routinely produces the same observation
once per host. Nothing here deduplicates them today, so an examiner reads and
decides on N near-identical items individually.

The grouping is deterministic: a finding's text is reduced to a *template* by
replacing the parts that vary between hosts (addresses, hashes, GUIDs, user
names, timestamps, host labels) with placeholders. Findings sharing a template
are the same observation. Templates that are not identical but very similar are
then merged on token overlap, which catches wording drift from a generative
model writing the same finding N times.

No model, no network, no stored state: the clustering is recomputed on read and
is identical on every machine for the same case, which is the property a
forensic tool needs.

**This changes presentation only.** Every finding keeps its own id, its own
``content_hash`` and its own row in ``approvals.jsonl``. Nothing here reads or
writes ``status``. Collapsing findings into a single custody record would
destroy the per-host provenance this tool exists to preserve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Substitutions are applied in order; earlier ones win. Each replaces a span
# that legitimately differs between two reports of the same activity.
_NORMALISERS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Identifiers that MUST survive normalisation, folded to \w-only tokens so
    # the host-label and bare-integer rules below cannot reach into them. Two
    # findings that differ only in which CVE was exploited, or in the MITRE
    # sub-technique observed, are different findings and must not merge.
    (re.compile(r"(?i)\bCVE-(\d{4})-(\d{4,7})\b"), r"cve_\1_\2"),
    (re.compile(r"\bT(\d{4})\.(\d{3})\b"), r"t\1_\2"),
    (re.compile(r"\bT(\d{4})\b"), r"t\1"),
    # Hashes next: a 32/40/64-hex run must not be nibbled by the number rule.
    (re.compile(r"\b[a-fA-F0-9]{64}\b"), "<SHA256>"),
    (re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{40}(?![a-fA-F0-9])"), "<SHA1>"),
    (re.compile(r"(?<![a-fA-F0-9])[a-fA-F0-9]{32}(?![a-fA-F0-9])"), "<MD5>"),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<GUID>",
    ),
    # Timestamps before dates, dates before bare numbers.
    (
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:?\d{2})?"
        ),
        "<TS>",
    ),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<DATE>"),
    (re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"), "<TIME>"),
    (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        "<IP>",
    ),
    # C:\Users\<someone>\... — the user name varies, the rest of the path does not.
    (re.compile(r"(?i)(\\Users\\)[^\\\s,;]+"), r"\1<USER>"),
    (re.compile(r"(?i)(/home/)[^/\s,;]+"), r"\1<USER>"),
    # Host labels: WIN-4K2J1, DESKTOP-A1B2C3, SRV-DC01. Heuristic, and the most
    # likely source of a wrong merge, which is why clustering never decides
    # anything on its own.
    (re.compile(r"\b[A-Z][A-Z0-9]{1,}-[A-Z0-9]{2,}\b"), "<HOST>"),
    # PIDs, ports, counts.
    (re.compile(r"\b\d+\b"), "<N>"),
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9<>_]+")

# Above this many distinct templates, the pairwise merge pass is skipped and
# only exact template matches group. Keeps the cost bounded on large cases;
# the doc'd failure mode for this feature is quadratic blow-up, not a missed merge.
MAX_TEMPLATES_FOR_MERGE = 400

DEFAULT_SIMILARITY = 0.85


def normalise(text: str) -> str:
    """Reduce ``text`` to a template by masking host-varying spans."""
    for pattern, replacement in _NORMALISERS:
        text = pattern.sub(replacement, text)
    return " ".join(text.split()).lower()


def template_of(item: dict) -> str:
    """Return the template for a finding or timeline event."""
    parts = [
        str(item.get("title", "")),
        str(item.get("observation", "")),
        str(item.get("interpretation", "")),
    ]
    return normalise(" ".join(p for p in parts if p))


def _tokens(template: str) -> frozenset[str]:
    return frozenset(_TOKEN_RE.findall(template))


def similarity(a: str, b: str) -> float:
    """Jaccard overlap of the token sets of two templates."""
    ta, tb = _tokens(a), _tokens(b)
    if not ta and not tb:
        return 1.0
    union = ta | tb
    if not union:
        return 1.0
    return len(ta & tb) / len(union)


@dataclass
class Cluster:
    """A group of findings describing the same underlying activity."""

    template: str
    members: list[dict] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def representative(self) -> dict:
        """The member shown as the cluster's headline row."""
        return self.members[0]

    @property
    def is_duplicate_group(self) -> bool:
        return len(self.members) > 1


def cluster_findings(
    items: list[dict], threshold: float = DEFAULT_SIMILARITY
) -> list[Cluster]:
    """Group ``items`` into clusters of near-duplicate findings.

    Exact template matches group in linear time. A second pass then merges
    templates whose token overlap reaches ``threshold``, which is where wording
    drift is caught. Ordering is deterministic: largest clusters first, ties
    broken by the first member's position in the input.
    """
    if not items:
        return []

    by_template: dict[str, list[dict]] = {}
    order: dict[str, int] = {}
    # Input position by identity, so the deterministic sort below stays linear
    # rather than calling list.index() once per member.
    position = {id(item): index for index, item in enumerate(items)}
    for index, item in enumerate(items):
        tpl = template_of(item)
        if tpl not in by_template:
            by_template[tpl] = []
            order[tpl] = index
        by_template[tpl].append(item)

    templates = list(by_template)
    merged_into: dict[str, str] = {}

    if len(templates) <= MAX_TEMPLATES_FOR_MERGE:
        for i, tpl in enumerate(templates):
            if tpl in merged_into:
                continue
            for other in templates[i + 1 :]:
                if other in merged_into:
                    continue
                if similarity(tpl, other) >= threshold:
                    merged_into[other] = tpl

    clusters: dict[str, Cluster] = {}
    for tpl in templates:
        target = merged_into.get(tpl, tpl)
        cluster = clusters.get(target)
        if cluster is None:
            cluster = Cluster(template=target)
            clusters[target] = cluster
        cluster.members.extend(by_template[tpl])

    result = list(clusters.values())
    for cluster in result:
        cluster.members.sort(key=lambda m: position[id(m)])
    result.sort(key=lambda c: (-c.size, order[c.template]))
    return result
