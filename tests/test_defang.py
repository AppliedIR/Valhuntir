"""Tests for refanging defanged IOCs before extraction."""

from __future__ import annotations

import pytest

from vhir_cli.commands.report import _extract_all_iocs
from vhir_cli.commands.review import _extract_text_iocs
from vhir_cli.defang import refang


@pytest.mark.parametrize(
    "defanged,expected",
    [
        ("evil[.]com", "evil.com"),
        ("evil(.)com", "evil.com"),
        ("evil{.}com", "evil.com"),
        ("evil[dot]com", "evil.com"),
        ("evil(dot)com", "evil.com"),
        ("evil{dot}com", "evil.com"),
        ("evil[DOT]com", "evil.com"),
        ("a[.]b[.]example[.]com", "a.b.example.com"),
    ],
)
def test_dot_substitutes(defanged, expected):
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    "defanged,expected",
    [
        ("hxxp://evil.com", "http://evil.com"),
        ("hxxps://evil.com", "https://evil.com"),
        ("HXXP://EVIL.COM", "HTTP://EVIL.COM"),
        ("hXXps://evil.com", "hTTps://evil.com"),
        ("hxxp[://]evil.com", "http://evil.com"),
        ("hxxp[:]//evil.com", "http://evil.com"),
    ],
)
def test_scheme_masking(defanged, expected):
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    "defanged,expected",
    [
        ("185[.]220[.]101[.]45", "185.220.101.45"),
        ("185.220.101[.]45", "185.220.101.45"),  # partially defanged
    ],
)
def test_defanged_ipv4(defanged, expected):
    assert refang(defanged) == expected


@pytest.mark.parametrize(
    "text",
    [
        r"C:\Users\victim\.ssh\id_rsa",  # backslash-dot is a real path, not defanging
        r"C:\Windows\System32\.config",
        "see footnote [.] for detail",  # bracketed prose, not an indicator
        "array [dot] notation",
        "no defanging here: evil.com and 8.8.8.8",
        "",
    ],
)
def test_left_alone(text):
    assert refang(text) == text


def test_spaced_forms_are_not_refanged():
    # Indistinguishable from ordinary prose; deliberately out of scope.
    assert refang("evil . com") == "evil . com"
    assert refang("evil dot com") == "evil dot com"


def test_idempotent():
    text = "hxxp://evil[.]com and 185[.]220[.]101[.]45"
    once = refang(text)
    assert refang(once) == once


def test_mixed_text_refangs_every_indicator():
    text = "beacon to hxxps://bad[.]example[.]com from 185[.]220[.]101[.]45"
    assert refang(text) == ("beacon to https://bad.example.com from 185.220.101.45")


def test_extractor_finds_defanged_domain_and_ip():
    collected: dict[str, set[str]] = {}
    _extract_text_iocs(
        "C2 at hxxp://evil[.]com, beacon to 185[.]220[.]101[.]45", collected
    )
    assert "evil.com" in collected["Domain"]
    assert "185.220.101.45" in collected["IPv4"]


def test_extractor_still_finds_live_indicators():
    collected: dict[str, set[str]] = {}
    _extract_text_iocs("C2 at evil.com, beacon to 185.220.101.45", collected)
    assert "evil.com" in collected["Domain"]
    assert "185.220.101.45" in collected["IPv4"]


def test_extractor_does_not_invent_iocs_from_paths():
    collected: dict[str, set[str]] = {}
    _extract_text_iocs(r"dropped C:\Users\victim\.ssh\id_rsa", collected)
    assert not collected.get("Domain")


def test_report_extractor_finds_defanged_indicators():
    # The report.py call site is separate from review.py's; exercise it too.
    out = _extract_all_iocs(
        [
            {
                "observation": "C2 at hxxp://evil[.]com",
                "interpretation": "relay via 185[.]220[.]101[.]45",
            }
        ]
    )
    assert "evil.com" in out["Domain"]
    assert "185.220.101.45" in out["IPv4"]
