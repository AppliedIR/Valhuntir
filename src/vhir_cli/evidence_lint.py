"""Flag findings whose stated confidence outruns their cited evidence.

Every finding carries ``confidence`` (HIGH/MEDIUM/LOW) and
``confidence_justification``, both written by the same generative model that
wrote the finding. A model's self-report of its own certainty is not
calibrated, and the examiner is shown it as though it were.

**What this is.** A lint over surface features: does the finding cite evidence,
does the interpretation assert intent or attribution the observation cannot
show, is the interpretation doing more work than the observation. These are
checkable facts about the text.

**What this is not.** A judgement of whether the evidence actually supports the
claim. That requires reading the cited artifacts and understanding them, which
no amount of pattern matching does. A finding can pass every check here and
still be wrong, and can trip a check and be perfectly sound. The flags are
prompts for examiner attention, nothing more.

The finding's own ``confidence`` is never overwritten or hidden. Flags are
shown beside it, and the disagreement — the model says HIGH, nothing is
cited — is the signal worth surfacing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Language asserting purpose, goal or authorship. An observation records what
# was seen; these words claim why, which evidence has to earn.
_INTENT_TERMS = (
    "in order to",
    "intended to",
    "intent",
    "designed to",
    "attempted to",
    "aimed to",
    "so that the attacker",
    "with the goal",
    "to evade",
    "to exfiltrate",
    "to maintain access",
    "deliberately",
)

_ATTRIBUTION_TERMS = (
    "apt",
    "threat actor",
    "nation-state",
    "state-sponsored",
    "ransomware group",
    "affiliate",
    "operator known as",
)

_HEDGE_TERMS = (
    "likely",
    "probably",
    "suggests",
    "appears to",
    "presumably",
    "consistent with",
    "may indicate",
    "possibly",
)

#: Ratio above which an interpretation is doing more work than its observation.
VERBOSITY_RATIO = 2.5

_WORD_RE = re.compile(r"\w+")


@dataclass(frozen=True)
class Flag:
    """One lint result. ``code`` is stable; ``message`` is for humans."""

    code: str
    message: str


def _words(text: str) -> int:
    return len(_WORD_RE.findall(text))


def _matcher(terms: tuple[str, ...]) -> re.Pattern[str]:
    """Whole-word matcher. Substring matching would fire ``apt`` on
    "captured", "adapter" and "attempt", flagging an attribution claim that
    nobody made."""
    joined = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"\b(?:{joined})\b", re.IGNORECASE)


_INTENT_RE = _matcher(_INTENT_TERMS)
_ATTRIBUTION_RE = _matcher(_ATTRIBUTION_TERMS)
_HEDGE_RE = _matcher(_HEDGE_TERMS)


def _contains(text: str, matcher: re.Pattern[str]) -> list[str]:
    return [m.group(0).lower() for m in matcher.finditer(text)]


def lint_finding(finding: dict) -> list[Flag]:
    """Return the evidence-support flags raised by ``finding``.

    Pure function of the finding. Reads no files and never mutates its input.
    """
    flags: list[Flag] = []
    confidence = str(finding.get("confidence", "")).upper()
    cited = bool(finding.get("audit_ids"))
    observation = str(finding.get("observation", ""))
    interpretation = str(finding.get("interpretation", ""))

    if confidence == "HIGH" and not cited:
        flags.append(
            Flag(
                "confidence-without-evidence",
                "stated HIGH confidence but cites no audit_ids",
            )
        )

    if not observation.strip():
        flags.append(Flag("no-observation", "no observation recorded"))

    intent = _contains(interpretation, _INTENT_RE)
    if intent and not cited:
        flags.append(
            Flag(
                "unsupported-intent",
                f"interpretation asserts intent ({intent[0]!r}) with nothing cited",
            )
        )

    attribution = _contains(interpretation, _ATTRIBUTION_RE)
    if attribution:
        flags.append(
            Flag(
                "attribution-claim",
                f"interpretation makes an attribution claim ({attribution[0]!r})",
            )
        )

    obs_words = _words(observation)
    interp_words = _words(interpretation)
    if obs_words and interp_words > obs_words * VERBOSITY_RATIO and not cited:
        flags.append(
            Flag(
                "interpretation-exceeds-observation",
                f"interpretation is {interp_words / obs_words:.1f}x the observation "
                "with nothing cited",
            )
        )

    if (
        confidence == "HIGH"
        and not str(finding.get("confidence_justification", "")).strip()
    ):
        flags.append(
            Flag(
                "unjustified-confidence",
                "stated HIGH confidence with no confidence_justification",
            )
        )

    hedges = _contains(interpretation, _HEDGE_RE)
    if confidence == "HIGH" and hedges:
        flags.append(
            Flag(
                "hedged-but-high",
                f"stated HIGH confidence but the interpretation hedges ({hedges[0]!r})",
            )
        )

    return flags


def lint_findings(findings: list[dict]) -> dict[str, list[Flag]]:
    """Lint many findings, keyed by finding id. Only flagged findings appear."""
    out: dict[str, list[Flag]] = {}
    for finding in findings:
        flags = lint_finding(finding)
        if flags:
            out[str(finding.get("id", "?"))] = flags
    return out
