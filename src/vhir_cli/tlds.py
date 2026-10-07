"""Top-level domain data for IOC extraction.

The TLD set is read from a vendored snapshot of IANA's authoritative list
(``data/tlds.txt``, from https://data.iana.org/TLD/tlds-alpha-by-domain.txt).
It is vendored rather than fetched at runtime for three reasons:

* Forensic workstations are often air-gapped; extraction must not need network.
* Re-running a report on the same case must produce the same IOC list. A list
  fetched at runtime would make derived artifacts non-reproducible, which is a
  chain-of-custody problem, not just an inconvenience.
* The package depends only on pyyaml and argcomplete, deliberately.

Refresh it with ``scripts/update_tlds.py``; a scheduled workflow opens a PR when
IANA publishes a new version, so the list stays current through review.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_TLD_FILE = Path(__file__).parent / "data" / "tlds.txt"

# Special-use TLDs that are not in the IANA DNS root but matter in IR work.
# .onion is reserved by RFC 7686 and appears routinely in malware C2 references.
_EXTRA_TLDS = frozenset({"ONION"})

# TLDs that are also common file extensions. In forensic prose "payload.zip" is
# almost always a file, not a domain, so a bare single-label name using one of
# these is not treated as a domain. A multi-label name (cdn.evil.zip) still is.
#
# Kept deliberately small. Only extensions that dominate their TLD in incident
# text qualify: MD is Moldova but far more often Markdown; SH is Saint Helena but
# far more often a shell script. Country codes that are genuinely common as
# domains in IR work are NOT listed even though they collide with extensions
# (PL, RS, SO, PS), because suppressing them would lose real IOCs. COM is absent
# for the same reason.
_FILENAME_LIKE_TLDS = frozenset(
    {"ZIP", "MOV", "PY", "SH", "MD", "APP", "DEV", "CAB", "BOX"}
)

# Candidate shape only — the TLD itself is validated against the IANA set below,
# not enumerated here. Requires at least one label before the TLD.
DOMAIN_CANDIDATE_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


@lru_cache(maxsize=1)
def load_tlds() -> frozenset[str]:
    """Return the known TLDs, uppercase, from the vendored IANA snapshot."""
    try:
        text = _TLD_FILE.read_text(encoding="utf-8")
    except OSError:
        return _EXTRA_TLDS
    tlds = {
        line.strip().upper()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    return frozenset(tlds | _EXTRA_TLDS)


def tld_of(candidate: str) -> str:
    """Return the uppercase TLD of a dotted name."""
    return candidate.rsplit(".", 1)[-1].upper()


def is_domain(candidate: str) -> bool:
    """True if ``candidate`` should be recorded as a domain IOC.

    Validates the TLD against the IANA list, and rejects a bare ``name.ext``
    whose extension is a TLD that is far more often a file extension.
    """
    tld = tld_of(candidate)
    if tld not in load_tlds():
        return False
    return not (tld in _FILENAME_LIKE_TLDS and candidate.count(".") < 2)


def extract_domains(text: str, exclude: set[str] | None = None) -> set[str]:
    """Extract lowercase domain IOCs from ``text``.

    ``exclude`` holds already-matched file paths; a candidate appearing inside
    one of them is a filename, not a domain.
    """
    paths = exclude or set()
    found = set()
    for candidate in DOMAIN_CANDIDATE_RE.findall(text):
        if not is_domain(candidate):
            continue
        if any(candidate in p for p in paths):
            continue
        found.add(candidate.lower())
    return found
