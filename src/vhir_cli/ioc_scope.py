"""Classify extracted IOCs by routability so reports can tier them.

An IOC list is handed to blocklists and to other responders. Today every
extracted address is presented identically, so ``10.4.1.22`` — a domain
controller, or the examiner's own jump box — appears in the same list as an
external C2 address, with nothing to tell them apart.

The only filtering the extractors do is a string-prefix check against ``0.``,
``127.`` and ``255.``. That misses every RFC 1918 range, link-local, carrier-grade
NAT, the documentation ranges and multicast.

Addresses are **classified, never dropped**. A private address in a finding is
usually meaningful — it is lateral movement, or the compromised host itself —
it just is not a blocklist candidate, and the report should say which is which.
Deciding whether a given internal address is an indicator or infrastructure
needs context this module does not have, so it does not pretend to: it reports
routability, which is a fact, and leaves the judgement to the examiner.

Uses the standard library's ``ipaddress``, so the classification follows the
IANA special-purpose registries rather than a hand-maintained prefix list.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

#: Scope labels, ordered from "hand this to a blocklist" to "definitely not".
ROUTABLE = "routable"
PRIVATE = "private"
LOOPBACK = "loopback"
LINK_LOCAL = "link-local"
CGNAT = "cgnat"
DOCUMENTATION = "documentation"
MULTICAST = "multicast"
RESERVED = "reserved"
UNSPECIFIED = "unspecified"
NOT_AN_ADDRESS = "not-an-address"

#: What each label means, shown in reports so the tiering explains itself.
SCOPE_NOTES: dict[str, str] = {
    ROUTABLE: "publicly routable",
    PRIVATE: "RFC 1918 private — internal host, not a blocklist candidate",
    LOOPBACK: "loopback",
    LINK_LOCAL: "link-local (RFC 3927 / RFC 4291)",
    CGNAT: "carrier-grade NAT (RFC 6598)",
    DOCUMENTATION: "documentation range (RFC 5737 / RFC 3849)",
    MULTICAST: "multicast",
    RESERVED: "reserved by IANA",
    UNSPECIFIED: "unspecified address",
    NOT_AN_ADDRESS: "not parseable as an IP address",
}

_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
_DOC_V4 = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
_DOC_V6 = ipaddress.ip_network("2001:db8::/32")


def classify_address(value: str) -> str:
    """Return the routability scope of ``value``.

    Order matters: an address can satisfy several predicates, and the most
    specific, most useful-to-an-examiner label wins.
    """
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return NOT_AN_ADDRESS

    if addr.is_unspecified:
        return UNSPECIFIED
    if addr.is_loopback:
        return LOOPBACK
    if addr.is_link_local:
        return LINK_LOCAL
    if addr.is_multicast:
        return MULTICAST
    if addr.version == 4:
        if addr in _CGNAT_V4:
            return CGNAT
        if any(addr in net for net in _DOC_V4):
            return DOCUMENTATION
    elif addr in _DOC_V6:
        return DOCUMENTATION
    if addr.is_private:
        return PRIVATE
    if addr.is_reserved:
        return RESERVED
    return ROUTABLE


def is_blocklist_candidate(value: str) -> bool:
    """True when an address could sensibly be sent to a blocklist."""
    return classify_address(value) == ROUTABLE


@dataclass
class ScopedIocs:
    """An IOC set split by whether its addresses are externally routable.

    ``non_routable`` maps each address to its scope label. Every input value
    appears in exactly one of the two, so nothing is lost by tiering.
    """

    routable: dict[str, list[str]]
    non_routable: dict[str, list[tuple[str, str]]]

    @property
    def non_routable_count(self) -> int:
        return sum(len(v) for v in self.non_routable.values())


#: IOC types whose values are addresses. Others pass through untouched.
ADDRESS_TYPES = frozenset({"IPv4", "IPv6", "IP"})


def scope_iocs(iocs: dict[str, object]) -> ScopedIocs:
    """Split an extracted IOC mapping into routable and non-routable parts.

    Non-address IOC types (hashes, domains, file paths) are passed through to
    ``routable`` unchanged — this only knows about addresses.
    """
    routable: dict[str, list[str]] = {}
    non_routable: dict[str, list[tuple[str, str]]] = {}

    for ioc_type, values in iocs.items():
        items = sorted(str(v) for v in values) if values else []
        if ioc_type not in ADDRESS_TYPES:
            if items:
                routable[ioc_type] = items
            continue
        keep: list[str] = []
        aside: list[tuple[str, str]] = []
        for value in items:
            scope = classify_address(value)
            if scope == ROUTABLE:
                keep.append(value)
            else:
                aside.append((value, scope))
        if keep:
            routable[ioc_type] = keep
        if aside:
            non_routable[ioc_type] = aside

    return ScopedIocs(routable=routable, non_routable=non_routable)
