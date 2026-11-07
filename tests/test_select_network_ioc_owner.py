"""One owner picks which value a report defangs: `defang.select_network_ioc`.
An IPv4 address with a port is defanged as its bare address when its type is
any spelling of ipv4-addr; under any other type, or a type that isn't text,
it is never the bare address. The rule is looked up through the module, as
every caller reads it."""

from __future__ import annotations

import pytest

from vhir_cli import defang

ADDRESS = "10.0.0.5:8080"
BARE = "10.0.0.5"
IPV4_SPELLINGS = (
    "ipv4-addr", "ipv4", "ip", "ip-src", "ip-dst", "ip-address", "ipv4-address",
    "src-ip", "dst-ip", "source-ip", "destination-ip", "dest-ip", "ip4",
)  # fmt: skip
NOT_IPV4 = ("url", "domain-name", "indicator", 5)


def _owner():
    fn = getattr(defang, "select_network_ioc", None)
    assert fn is not None, "vhir_cli.defang has no select_network_ioc"
    return fn


@pytest.mark.parametrize("t", IPV4_SPELLINGS)
def test_an_ipv4_spelling_defangs_the_bare_address(t):
    assert _owner()(ADDRESS, t) == BARE


@pytest.mark.parametrize("t", NOT_IPV4, ids=str)
def test_any_other_type_never_gives_the_bare_address(t):
    assert _owner()(ADDRESS, t) != BARE
