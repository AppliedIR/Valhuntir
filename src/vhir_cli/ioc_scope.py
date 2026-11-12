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

The ranges are the IANA IPv4 and IPv6 special-purpose address registries, written
out below as one table rather than read from ``ipaddress``'s ``is_*`` flags:
those flags changed between Python versions, and an examiner must get the same
answer for the same address on every supported Python. An IPv4-mapped IPv6
address (``::ffff:10.0.0.1``) is classified as the IPv4 address it carries.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from vhir_cli import ioc_types
from vhir_cli.ioc_groups import TEXT_ONLY

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
THIS_NETWORK = "this-network"
PROTOCOL = "protocol-assignments"
BENCHMARKING = "benchmarking"
BROADCAST = "broadcast"
UNIQUE_LOCAL = "unique-local"
SIX_TO_FOUR = "6to4"
SIX_A_FOUR = "6a44"
TRANSLATION = "translation"
DISCARD = "discard"
SRV6 = "srv6"
NOT_AN_ADDRESS = "not-an-address"

#: What each label means, shown in reports so the tiering explains itself.
SCOPE_NOTES: dict[str, str] = {
    ROUTABLE: "publicly routable",
    PRIVATE: "RFC 1918 private — internal host, not a blocklist candidate",
    LOOPBACK: "loopback",
    LINK_LOCAL: "link-local (RFC 3927 / RFC 4291)",
    CGNAT: "carrier-grade NAT (RFC 6598)",
    DOCUMENTATION: "documentation range (RFC 5737 / RFC 3849 / RFC 9637)",
    MULTICAST: "multicast",
    RESERVED: "reserved by IANA",
    UNSPECIFIED: "unspecified address",
    THIS_NETWORK: '"this network" (RFC 791)',
    PROTOCOL: "IETF protocol assignments (RFC 6890)",
    BENCHMARKING: "benchmarking (RFC 2544 / RFC 5180)",
    BROADCAST: "limited broadcast (RFC 919)",
    UNIQUE_LOCAL: "unique local (RFC 4193) — internal host, not a blocklist candidate",
    SIX_TO_FOUR: "6to4 transition address (RFC 3056)",
    SIX_A_FOUR: "6a44 relay anycast (RFC 6751)",
    TRANSLATION: "local-use IPv4/IPv6 translation (RFC 8215)",
    DISCARD: "discard-only (RFC 6666)",
    SRV6: "SRv6 segment identifiers (RFC 9602)",
    NOT_AN_ADDRESS: "not parseable as an IP address",
}


def _table(rows: tuple[tuple[str, str], ...]) -> tuple:
    return tuple((ipaddress.ip_network(net), scope) for net, scope in rows)


#: First match wins, so a globally reachable exception sits above its block.
_V4 = _table(
    (
        ("0.0.0.0/32", UNSPECIFIED),
        ("0.0.0.0/8", THIS_NETWORK),
        ("10.0.0.0/8", PRIVATE),
        ("100.64.0.0/10", CGNAT),
        ("127.0.0.0/8", LOOPBACK),
        ("169.254.0.0/16", LINK_LOCAL),
        ("172.16.0.0/12", PRIVATE),
        ("192.0.0.9/32", ROUTABLE),
        ("192.0.0.10/32", ROUTABLE),
        ("192.0.0.0/24", PROTOCOL),
        ("192.0.2.0/24", DOCUMENTATION),
        ("192.88.99.2/32", SIX_A_FOUR),  # IANA: not globally reachable
        ("192.168.0.0/16", PRIVATE),
        ("198.18.0.0/15", BENCHMARKING),
        ("198.51.100.0/24", DOCUMENTATION),
        ("203.0.113.0/24", DOCUMENTATION),
        ("224.0.0.0/4", MULTICAST),
        ("255.255.255.255/32", BROADCAST),
        ("240.0.0.0/4", RESERVED),
        ("0.0.0.0/0", ROUTABLE),
    )
)
_V6 = _table(
    (
        ("::/128", UNSPECIFIED),
        ("::1/128", LOOPBACK),
        ("64:ff9b::/96", ROUTABLE),
        ("64:ff9b:1::/48", TRANSLATION),
        ("100::/64", DISCARD),
        ("2001:1::1/128", ROUTABLE),
        ("2001:1::2/128", ROUTABLE),
        ("2001:1::3/128", ROUTABLE),  # IANA: SRP anycast (RFC 9665)
        ("2001:3::/32", ROUTABLE),
        ("2001:4:112::/48", ROUTABLE),
        ("2001:20::/28", ROUTABLE),
        ("2001:30::/28", ROUTABLE),
        ("2001:2::/48", BENCHMARKING),
        ("2001::/23", PROTOCOL),
        ("2001:db8::/32", DOCUMENTATION),
        ("2002::/16", SIX_TO_FOUR),
        ("3fff::/20", DOCUMENTATION),
        ("5f00::/16", SRV6),
        ("fc00::/7", UNIQUE_LOCAL),
        ("fe80::/10", LINK_LOCAL),
        ("ff00::/8", MULTICAST),
        ("2000::/3", ROUTABLE),
        ("::/0", RESERVED),
    )
)


def classify_address(value: str) -> str:
    """Return the routability scope of ``value``, refanged as record_finding
    refangs it: the first row of its family's table that holds it."""
    try:
        addr = ipaddress.ip_address(ioc_types.refang(value).strip())
    except ValueError:
        return NOT_AN_ADDRESS
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    table = _V4 if addr.version == 4 else _V6
    return next(scope for net, scope in table if addr in net)


def is_blocklist_candidate(value: str) -> bool:
    """True when an address could sensibly be sent to a blocklist."""
    return classify_address(value) == ROUTABLE


@dataclass
class ScopedIocs:
    """An IOC set split by whether its addresses are externally routable.

    ``non_routable`` maps each label to its (address, scope) pairs. Every input value
    appears in exactly one of the two, so nothing is lost by tiering.
    """

    routable: dict[str, list[str]]
    non_routable: dict[str, list[tuple[str, str]]]

    @property
    def non_routable_count(self) -> int:
        return sum(len(v) for v in self.non_routable.values())


#: IOC labels whose values are addresses. Others pass through untouched.
ADDRESS_TYPES = frozenset({"IPv4", "IPv6", "IP"})

#: A group that mixes types (the values found in text, no record holds, and
#: the records with no type a pattern names): each value is tiered only if it
#: parses as an address.
MIXED_GROUPS = frozenset({TEXT_ONLY, ioc_types.label("unknown")})

#: Scopes that stay in the main list. A documentation address (RFC 5737 /
#: RFC 3849) is the placeholder every example, report template and test corpus
#: uses, so an examiner who sees one wants it listed as given; it is still
#: classified as such by ``classify_address``. An unparseable value is not
#: claimed to be anything.
_LISTED_WITH_ROUTABLE = frozenset({ROUTABLE, DOCUMENTATION, NOT_AN_ADDRESS})

_PORT = re.compile(r":\d{1,5}$")


def _bare(value: str) -> str:
    """The address of a value that may carry a trailing :port (IPv4 only; an
    IPv6 address has colons of its own), refanged first: 10[.]0[.]0[.]5[:]445."""
    v = ioc_types.refang(value).strip()
    return _PORT.sub("", v) if v.count(":") == 1 else v


def scope_iocs(groups: dict[str, object]) -> ScopedIocs:
    """Split label -> values groups into routable and non-routable parts.

    A value that is not an address (a hash, a domain, a path, or an address
    typed value that does not parse) stays in ``routable`` unchanged: this
    reports routability, which is a fact about an address, and claims nothing
    about anything else.
    """
    routable: dict[str, list[str]] = {}
    non_routable: dict[str, list[tuple[str, str]]] = {}

    for label, values in groups.items():
        items = sorted(str(v) for v in values) if values else []
        if label not in ADDRESS_TYPES and label not in MIXED_GROUPS:
            if items:
                routable[label] = items
            continue
        keep: list[str] = []
        aside: list[tuple[str, str]] = []
        for value in items:
            scope = classify_address(_bare(value))
            if scope in _LISTED_WITH_ROUTABLE:
                keep.append(value)
            else:
                aside.append((value, scope))
        if keep:
            routable[label] = keep
        if aside:
            non_routable[label] = aside

    return ScopedIocs(routable=routable, non_routable=non_routable)
