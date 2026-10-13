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


SAMPLE = (
    "C2 at hxxp://evil[.]com via bad(dot)example.com, beacon to 185[.]220[.]101[.]45"
)


def test_the_sample_gives_its_live_indicators_never_the_parent_domain():
    """Both extractors: the defanged domains and IP come out live, and
    bad(dot)example.com is bad.example.com, never its parent example.com."""
    collected: dict[str, set[str]] = {}
    _extract_text_iocs(SAMPLE, collected)
    report = _extract_all_iocs([{"observation": SAMPLE, "interpretation": ""}])
    for got in (collected, report):
        assert set(got["Domain"]) == {"evil.com", "bad.example.com"}
        assert set(got["IPv4"]) == {"185.220.101.45"}


@pytest.mark.parametrize(
    ("text", "kind", "value"),
    [
        ("C2 at hxxp://hxxp[.]example[.]com", "Domain", "hxxp.example.com"),
        (r"dropped C:\Tools\hxxp\payload.exe", "File", r"C:\Tools\hxxp\payload.exe"),
    ],
)
def test_hxxp_is_a_scheme_only_before_its_separator(text, kind, value):
    """Only a scheme's hxxp is refanged: the same letters in a host name or a
    path are part of the indicator, in both extractors."""
    collected: dict[str, set[str]] = {}
    _extract_text_iocs(text, collected)
    report = _extract_all_iocs([{"observation": text, "interpretation": ""}])
    for got in (collected, report):
        assert value in got[kind]
        assert not any("http" in v for v in got.get(kind, ())), got


# --- writing the case's IOCs defanged in a saved report -------------------------

IOCS = ["https://evil.com/payload", "evil.com"]


@pytest.mark.parametrize(
    "text",
    [
        "evil.com", "https://evil.com/x", "hxxp://evil.com", r"\\evil.com\share",
        r"\\evil.com@SSL\DavWWWRoot\x.dll", "//evil.com/x", "mail@evil.com",
        "https://web.archive.org/web/2026/https://evil.com/payload",
        r"https:/\evil.com/x", r"http:\/evil.com",  # a mixed pair is a host too
    ],
)  # fmt: skip
def test_an_ioc_where_it_names_a_host_is_defanged(text):
    from vhir_cli.defang import defang_iocs

    got = defang_iocs(text, IOCS)
    assert "evil[.]com" in got and "evil.com" not in got, got


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("https://vendor.example/download/evil.com/tool", "/download/evil.com/tool"),
        (r"C:\Users\x\evil.com\a", r"\x\evil.com\a"),
        ("https://evil.com/evil.com/payload", "/evil.com/payload"),
    ],
)
def test_a_domain_after_a_single_separator_is_a_path_and_stays(text, kept):
    """After one / or \\ a domain is a path component; after // or \\\\ a host."""
    from vhir_cli.defang import defang_iocs

    assert defang_iocs(text, IOCS).endswith(kept)


def test_a_range_counts_as_its_base_address():
    from vhir_cli.defang import defang_iocs, network_ioc

    assert network_ioc("185.220.101.0/24", False) == "185.220.101.0"
    assert network_ioc("185.220.101.45/32", False) == "185.220.101.45"
    got = defang_iocs("185.220.101.0/24 via http://185.220.101.0/24", ["185.220.101.0"])
    assert got == "185[.]220[.]101[.]0/24 via http://185[.]220[.]101[.]0/24"


def test_a_typed_domain_with_its_root_dot_counts_without_it():
    from vhir_cli.defang import defang_iocs, network_ioc

    assert network_ioc("evil.com.", True) == "evil.com"
    got = defang_iocs("evil.com. and https://evil.com./x", ["evil.com"])
    assert got == "evil[.]com. and https://evil[.]com./x"
