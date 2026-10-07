"""Order the review queue by investigative value.

A sweep can stage hundreds of DRAFT findings, and they are reviewed in whatever
order the backend appended them. Examiner attention is the scarcest resource in
the platform and it is currently spent uniformly.

This module scores each finding on a handful of **independent, explainable**
signals and combines them with weights the examiner can see. It is deliberately
not a model:

* It is reproducible — the same case ranks identically on every machine, which
  a probabilistic score cannot promise.
* It needs no network, so it is safe in the approval path of an air-gapped
  workstation.
* Every point of the score can be traced to a named signal, and
  ``--explain`` prints that breakdown. In a forensic tool an opaque ranking is
  worse than no ranking: the examiner has to be able to disagree with it.

**Ordering only.** Nothing here filters, hides, approves, rejects or writes
``status``. The examiner still sees every item. Scores are recomputed on read
and never stored — a finding's ``content_hash`` covers every field that is not
explicitly excluded, so writing a score into the finding would invalidate its
integrity check.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Attacker-capability vocabulary, grouped by what it evidences. Matched as whole
# words against the finding's text. These describe capability, as opposed to
# inventory or configuration noise.
_CAPABILITY_TERMS: dict[str, tuple[str, ...]] = {
    "execution": ("execute", "executed", "execution", "launched", "spawned", "invoked"),
    "persistence": (
        "persistence",
        "scheduled task",
        "run key",
        "autorun",
        "service created",
        "startup",
        "wmi subscription",
    ),
    "credential_access": (
        "lsass",
        "credential",
        "credentials",
        "mimikatz",
        "hashdump",
        "ntds",
        "sam hive",
        "kerberoast",
    ),
    "lateral_movement": (
        "lateral",
        "psexec",
        "smbexec",
        "wmiexec",
        "remote desktop",
        "rdp",
        "pass-the-hash",
        "admin share",
    ),
    "exfiltration": (
        "exfil",
        "exfiltration",
        "transferred",
        "upload",
        "uploaded",
        "staged for transfer",
        "archive created",
    ),
    "defense_evasion": (
        "cleared",
        "deleted log",
        "log cleared",
        "timestomp",
        "obfuscated",
        "disabled defender",
        "amsi",
        "unhooked",
    ),
    "command_and_control": (
        "beacon",
        "c2",
        "command and control",
        "callback",
        "reverse shell",
        "tunnel",
    ),
}

_CONFIDENCE_POINTS = {"HIGH": 1.0, "MEDIUM": 0.5, "LOW": 0.1}

# Rarer IOC types are worth more: a hash pins one artefact, an address may be
# shared infrastructure.
_IOC_TYPE_POINTS = {
    "SHA256": 1.0,
    "SHA1": 0.9,
    "MD5": 0.8,
    "File": 0.6,
    "Domain": 0.5,
    "IPv4": 0.4,
}

_WORD_RE = re.compile(r"[a-z0-9]+")


def _term_matcher(terms: tuple[str, ...]) -> re.Pattern[str]:
    """Whole-word matcher for a term list.

    Substring matching is wrong here: "c2" occurs inside roughly every SHA-256
    an observation might quote, which would tag any finding citing a hash as
    command-and-control.
    """
    joined = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"\b(?:{joined})\b", re.IGNORECASE)


_CAPABILITY_MATCHERS: dict[str, re.Pattern[str]] = {
    name: _term_matcher(terms) for name, terms in _CAPABILITY_TERMS.items()
}

#: Signal weights. Exposed so an examiner can re-weight without re-deriving
#: anything: the signals are stored per finding in the RankedFinding, so
#: changing a weight re-sorts without recomputing the evidence.
DEFAULT_WEIGHTS: dict[str, float] = {
    "actionable": 2.0,
    "capability": 3.0,
    "objective_overlap": 2.5,
    "ioc_richness": 1.5,
    "mitre_tagged": 1.0,
    "stated_confidence": 0.5,
}


def _text_of(item: dict) -> str:
    parts = (
        str(item.get("title", "")),
        str(item.get("observation", "")),
        str(item.get("interpretation", "")),
    )
    return " ".join(parts).lower()


def _words(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower()))


def capability_signal(item: dict) -> tuple[float, list[str]]:
    """Fraction of capability categories the finding's text evidences."""
    text = _text_of(item)
    hit = [
        name for name, matcher in _CAPABILITY_MATCHERS.items() if matcher.search(text)
    ]
    return len(hit) / len(_CAPABILITY_TERMS), sorted(hit)


def actionable_signal(item: dict) -> float:
    """1.0 when the finding cites evidence an examiner can pull up now."""
    return 1.0 if item.get("audit_ids") else 0.0


def ioc_richness_signal(item: dict) -> float:
    """Weighted count of attached IOCs, saturating at 1.0."""
    iocs = item.get("iocs")
    if not iocs:
        return 0.0
    total = 0.0
    if isinstance(iocs, dict):
        for ioc_type, values in iocs.items():
            count = len(values) if isinstance(values, list) else 1
            total += _IOC_TYPE_POINTS.get(ioc_type, 0.3) * count
    elif isinstance(iocs, list):
        for ioc in iocs:
            ioc_type = ioc.get("type") if isinstance(ioc, dict) else None
            total += _IOC_TYPE_POINTS.get(ioc_type, 0.3)
    return min(total / 3.0, 1.0)


def mitre_signal(item: dict) -> float:
    return 1.0 if item.get("mitre_techniques") else 0.0


def confidence_signal(item: dict) -> float:
    """The finding's own stated confidence, weighted low on purpose.

    This is the generative model's self-report. It is included because it
    carries some information, and weighted at a fraction of the evidence-based
    signals because a self-report is not calibrated.
    """
    return _CONFIDENCE_POINTS.get(str(item.get("confidence", "")).upper(), 0.0)


def objective_terms(case_meta: dict) -> set[str]:
    """Distinctive words describing what the case is investigating."""
    parts = [
        str(case_meta.get("scope", "")),
        str(case_meta.get("incident_type", "")),
        str(case_meta.get("name", "")),
    ]
    terms = _words(" ".join(parts))
    return {t for t in terms if len(t) > 3}


def objective_overlap_signal(item: dict, terms: set[str]) -> float:
    """Fraction of the case's objective vocabulary the finding touches."""
    if not terms:
        return 0.0
    return len(_words(_text_of(item)) & terms) / len(terms)


@dataclass
class RankedFinding:
    """A finding with its score and the per-signal breakdown behind it."""

    item: dict
    score: float
    signals: dict[str, float]
    capabilities: list[str]

    @property
    def id(self) -> str:
        return str(self.item.get("id", "?"))


def score_finding(
    item: dict,
    objective: set[str] | None = None,
    weights: dict[str, float] | None = None,
) -> RankedFinding:
    """Score one finding. Pure function of the finding and the case objective."""
    w = weights or DEFAULT_WEIGHTS
    capability, capabilities = capability_signal(item)
    signals = {
        "actionable": actionable_signal(item),
        "capability": capability,
        "objective_overlap": objective_overlap_signal(item, objective or set()),
        "ioc_richness": ioc_richness_signal(item),
        "mitre_tagged": mitre_signal(item),
        "stated_confidence": confidence_signal(item),
    }
    score = sum(signals[name] * w.get(name, 0.0) for name in signals)
    return RankedFinding(
        item=item, score=score, signals=signals, capabilities=capabilities
    )


def rank_findings(
    items: list[dict],
    case_meta: dict | None = None,
    weights: dict[str, float] | None = None,
) -> list[RankedFinding]:
    """Return ``items`` ordered by investigative value, highest first.

    Stable: equal scores keep their original relative order, so the ranking
    never shuffles items it has no opinion about.
    """
    terms = objective_terms(case_meta or {})
    ranked = [score_finding(item, terms, weights) for item in items]
    # sorted() is stable, so equal scores retain input order.
    return sorted(ranked, key=lambda r: -r.score)
