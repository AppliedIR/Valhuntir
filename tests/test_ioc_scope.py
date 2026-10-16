"""Tests for IOC routability classification."""

from __future__ import annotations

import pytest

from vhir_cli.ioc_scope import (
    CGNAT,
    DOCUMENTATION,
    LINK_LOCAL,
    LOOPBACK,
    MULTICAST,
    NOT_AN_ADDRESS,
    PRIVATE,
    ROUTABLE,
    UNSPECIFIED,
    classify_address,
    is_blocklist_candidate,
    scope_iocs,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", ROUTABLE),
        ("185.220.101.45", ROUTABLE),
        # The gap the prefix check missed: every RFC 1918 range.
        ("10.4.1.22", PRIVATE),
        ("172.16.0.5", PRIVATE),
        ("172.31.255.254", PRIVATE),
        ("192.168.1.1", PRIVATE),
        ("127.0.0.1", LOOPBACK),
        ("169.254.10.1", LINK_LOCAL),
        ("100.64.0.1", CGNAT),
        ("192.0.2.5", DOCUMENTATION),
        ("198.51.100.5", DOCUMENTATION),
        ("203.0.113.9", DOCUMENTATION),
        ("224.0.0.1", MULTICAST),
        ("0.0.0.0", UNSPECIFIED),
        ("not-an-ip", NOT_AN_ADDRESS),
        ("", NOT_AN_ADDRESS),
    ],
)
def test_classify_ipv4(value, expected):
    assert classify_address(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("2606:4700:4700::1111", ROUTABLE),
        ("::1", LOOPBACK),
        ("fe80::1", LINK_LOCAL),
        ("fd00::1", PRIVATE),
        ("2001:db8::1", DOCUMENTATION),
        ("ff02::1", MULTICAST),
    ],
)
def test_classify_ipv6(value, expected):
    assert classify_address(value) == expected


def test_172_16_boundaries_are_exact():
    # 172.16/12 is the private range; 172.15 and 172.32 are not in it.
    assert classify_address("172.15.255.255") == ROUTABLE
    assert classify_address("172.32.0.1") == ROUTABLE


def test_is_blocklist_candidate():
    assert is_blocklist_candidate("185.220.101.45")
    assert not is_blocklist_candidate("192.168.1.1")
    assert not is_blocklist_candidate("nonsense")


def test_scope_iocs_splits_addresses():
    scoped = scope_iocs({"IPv4": ["185.220.101.45", "10.4.1.22", "192.168.1.1"]})
    assert scoped.routable["IPv4"] == ["185.220.101.45"]
    assert [v for v, _ in scoped.non_routable["IPv4"]] == ["10.4.1.22", "192.168.1.1"]
    assert scoped.non_routable_count == 2


def test_scope_iocs_never_drops_anything():
    values = ["185.220.101.45", "10.4.1.22", "127.0.0.1", "224.0.0.1"]
    scoped = scope_iocs({"IPv4": values})
    seen = scoped.routable.get("IPv4", []) + [
        v for v, _ in scoped.non_routable.get("IPv4", [])
    ]
    assert sorted(seen) == sorted(values)


def test_non_address_types_pass_through():
    scoped = scope_iocs(
        {"SHA256": ["a" * 64], "Domain": ["evil.com"], "File": [r"C:\x\y.exe"]}
    )
    assert scoped.routable["SHA256"] == ["a" * 64]
    assert scoped.routable["Domain"] == ["evil.com"]
    assert scoped.non_routable == {}


def test_scope_iocs_handles_sets_and_empty():
    scoped = scope_iocs({"IPv4": {"8.8.8.8"}, "Domain": set()})
    assert scoped.routable["IPv4"] == ["8.8.8.8"]
    assert "Domain" not in scoped.routable
    assert scope_iocs({}).routable == {}


def test_type_with_only_non_routable_addresses_is_not_in_routable():
    scoped = scope_iocs({"IPv4": ["10.0.0.1"]})
    assert "IPv4" not in scoped.routable
    assert scoped.non_routable_count == 1


def test_values_are_sorted_deterministically():
    a = scope_iocs({"IPv4": ["9.9.9.9", "1.1.1.1"]})
    b = scope_iocs({"IPv4": ["1.1.1.1", "9.9.9.9"]})
    assert a.routable == b.routable
