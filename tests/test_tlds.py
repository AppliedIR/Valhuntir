"""Tests for TLD-validated domain IOC extraction."""

import pytest

from vhir_cli.ioc_groups import record_groups, text_iocs
from vhir_cli.tlds import extract_domains, is_domain, load_tlds


def test_iana_list_loads():
    tlds = load_tlds()
    assert len(tlds) > 1000, "vendored IANA list looks truncated"
    assert "COM" in tlds
    assert "UK" in tlds


def test_onion_is_included_though_not_in_iana_root():
    """RFC 7686 special-use TLD, routinely seen in C2 references."""
    assert "ONION" in load_tlds()
    assert is_domain("expyuzz4wqqyqhjn.onion")


@pytest.mark.parametrize(
    "domain",
    [
        "evil.com",
        "malware.net",
        "c2.ru",
        # The whole point: these were silently missed by the hardcoded list.
        "attacker.co.uk",
        "bad.de",
        "legacy.su",
        "payload.gov.pl",
        "exfil.zone",
        "beacon.click",
    ],
)
def test_real_domains_are_extracted(domain):
    assert extract_domains(f"connection to {domain} observed") == {domain}


@pytest.mark.parametrize(
    "not_a_domain",
    ["file.txt", "report.docx", "dump.raw", "image.e01", "hive.dat"],
)
def test_non_tld_extensions_are_not_domains(not_a_domain):
    assert extract_domains(f"wrote {not_a_domain} to disk") == set()


@pytest.mark.parametrize(
    "name", ["payload.zip", "script.py", "run.sh", "clip.mov", "notes.md"]
)
def test_bare_filename_with_tld_like_extension_is_not_a_domain(name):
    """ZIP/PY/SH/MOV/MD are real TLDs but overwhelmingly file extensions here."""
    assert extract_domains(f"dropped {name} in temp") == set()


@pytest.mark.parametrize("domain", ["sklep.pl", "news.rs", "host.so"])
def test_country_codes_that_collide_with_extensions_stay_domains(domain):
    """PL/RS/SO collide with extensions but are common real domains — keep them."""
    assert extract_domains(f"resolved {domain}") == {domain}


@pytest.mark.parametrize("domain", ["cdn.evil.zip", "files.attacker.mov"])
def test_multi_label_name_with_tld_like_extension_is_a_domain(domain):
    assert extract_domains(f"fetched from {domain}") == {domain}


def test_domain_inside_a_file_path_is_not_extracted():
    text = r"dropped C:\Users\v\AppData\payload.zip.com on host"
    paths = {r"C:\Users\v\AppData\payload.zip.com"}
    assert extract_domains(text, exclude=paths) == set()


def test_domain_is_lowercased():
    assert extract_domains("beacon to EVIL.COM") == {"evil.com"}


def test_hyphenated_and_multi_label_domains():
    text = "resolved cdn-1.evil-corp.co.uk during the window"
    assert extract_domains(text) == {"cdn-1.evil-corp.co.uk"}


def test_no_leading_or_trailing_hyphen_label():
    """A label may not start or end with a hyphen (RFC 1035)."""
    assert extract_domains("see -bad.com here") == {"bad.com"}


def test_empty_text_yields_nothing():
    assert extract_domains("") == set()


@pytest.mark.parametrize("name", ["CMD.EXE-0BD30981.pf", "svchost.exe-36ae4b2e.pf"])
def test_prefetch_file_name_is_not_a_domain(name):
    """PF is a TLD (French Polynesia), but NAME.EXT-XXXXXXXX.pf is a Prefetch file."""
    assert extract_domains(f"prefetch shows {name} ran") == set()


def test_finding_text_domains_are_checked_against_the_iana_list():
    """The finding-text extractor the review and report listings use."""
    text = (
        r"beacon to attacker.co.uk and bad.de, then wrote C:\Temp\evil.com\run.ps1 "
        "and notes.md; prefetch shows CMD.EXE-0BD30981.pf"
    )
    domains = {v for label, v in text_iocs(text) if label == "Domain"}
    assert domains == {"attacker.co.uk", "bad.de"}


@pytest.mark.parametrize(
    ("value", "label"),
    [("bad.de", "Domain"), ("evil.com", "Domain"), ("notepad.exe", "Unknown")],
)
def test_untyped_record_is_a_domain_only_with_an_iana_tld(value, label):
    assert record_groups([{"value": value}]) == {label: [value]}
