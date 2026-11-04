"""`vhir report --save` writes every IOC of the case that is a domain, URL or
IPv4 address (evil[.]com, hxxp://bad[.]example[.]com/x, 185[.]220[.]101[.]45)
defanged, in the report and its block, as report-mcp's saved reports do. The
case's IOCs are its approved findings' IOC fields and the IOC records they
cite; a name a finding's text merely mentions isn't one. Other URLs and names
stay live, a name that is only part of a longer one isn't touched, and a
defanged one isn't twice."""

from __future__ import annotations

import json

from tests.signing import sign_approved
from tests.test_report import _make_args, case_dir, identity  # noqa: F401
from vhir_cli.case_io import save_findings
from vhir_cli.commands.report import cmd_report

APPROVED = {
    "id": "F-tester-001", "status": "APPROVED", "title": ("C2 at evil.com (see https://learn.microsoft.com/kb; notevil.com, "
              "sub.evil.com, evil.com.au, 185.220.101.450)"),
    "observation": ("Beacon to evil.com and EVIL.COM from 185.220.101.45; payload "
                    "http://bad.example.com/x.php. Hash d41d8cd98f00b204e9800998ecf8427e, "
                    "file C:\\Tools\\drop.exe, a.exe. Already evil[.]com; tool from "
                    "download.vendor.com; relay.example.dev; "
                    "stage.example.dev."),
    "interpretation": "i", "confidence": "HIGH",
    "iocs": [{"type": "domain", "value": "evil.com"}, "185.220.101.45",
             {"type": "url", "value": "http://bad.example.com/x.php"}, "a.exe"],
}  # fmt: skip


def _saved(case_dir, identity, findings, iocs=(), **report):  # noqa: F811
    save_findings(case_dir, findings)
    (case_dir / "iocs.json").write_text(json.dumps(list(iocs)))
    sign_approved(case_dir)
    cmd_report(_make_args(save="r.txt", **report), identity)
    return (case_dir / "reports" / "r.txt").read_text()


def test_an_approved_findings_iocs_are_written_defanged(case_dir, identity, capsys):  # noqa: F811
    saved = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    assert "Beacon to evil[.]com and EVIL[.]COM from 185[.]220[.]101[.]45" in saved
    assert "payload hxxp://bad[.]example[.]com/x.php." in saved
    # hashes, paths and an untyped name like a file aren't indicators to defang
    assert "d41d8cd98f00b204e9800998ecf8427e, file C:\\Tools\\drop.exe, a.exe." in saved
    assert (
        "evil.com" in capsys.readouterr().out
    )  # the terminal shows the records as stored


def test_the_block_writes_them_defanged_too(case_dir, identity):  # noqa: F811
    saved = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    block = saved[saved.index("VERIFICATION") :]
    assert (
        "[F-tester-001] C2 at evil[.]com (see https://learn.microsoft.com/kb" in block
    )


def test_a_url_or_name_that_isnt_an_ioc_stays_live_and_none_twice(case_dir, identity):  # noqa: F811
    """The title isn't read for IOCs: its other names stay live in the report."""
    saved = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    for live in ("https://learn.microsoft.com/kb", "notevil.com", "sub.evil.com",
                 "evil.com.au", "185.220.101.450"):  # fmt: skip
        assert live in saved, live
    assert "Already evil[.]com;" in saved and "[[" not in saved


def test_a_case_ioc_record_typed_as_a_domain_is_defanged_whoever_cites_it(  # noqa: F811
    case_dir, identity  # noqa: F811
):  # fmt: skip
    """A .dev name isn't one the text extractor finds: a case IOC record typed
    as a domain decides it, whatever its status and whichever finding cites it."""
    draft = {"id": "F-tester-002", "status": "DRAFT", "title": "t", "observation": "o",
             "interpretation": "i"}  # fmt: skip
    records = [
        {"id": "I-tester-001", "type": "domain-name", "value": "stage.example.dev",
         "status": "DRAFT", "source_findings": ["F-tester-001"]},
        {"id": "I-tester-002", "type": "domain-name", "value": "relay.example.dev",
         "status": "DRAFT", "source_findings": ["F-tester-002"]},
    ]  # fmt: skip
    saved = _saved(case_dir, identity, [APPROVED, draft], records,
                   report_findings="F-tester-001")  # fmt: skip
    assert "relay[.]example[.]dev; stage[.]example[.]dev." in saved


def test_the_full_json_report_keeps_its_iocs_live_and_the_text_report_doesnt(  # noqa: F811
    case_dir, identity  # noqa: F811
):  # fmt: skip
    """JSON is input for tools: --full --save keeps the IOCs as stored, while a
    text report saved from the same case has them defanged."""
    saved = _saved(case_dir, identity, [APPROVED], full=True)
    assert json.loads(saved)["approved_findings"][0]["title"].startswith(
        "C2 at evil.com (see"
    )
    assert "http://bad.example.com/x.php" in saved and "hxxp" not in saved
    text = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    assert "C2 at evil[.]com (see" in text


def test_a_name_an_approved_finding_only_mentions_stays_live(case_dir, identity):  # noqa: F811
    """download.vendor.com is in the finding's text, not among its IOCs."""
    saved = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    assert (
        "tool from download.vendor.com;" in saved and "download[.]vendor" not in saved
    )


NESTED = {
    "id": "F-tester-003", "status": "APPROVED", "title": "C2 at evil13.example.com",
    "observation": "Beacon to evil13.example.com.", "interpretation": "i",
    "confidence": "HIGH",
    "iocs": [{"type": "domain", "value": "evil13[[.]]example.com"},
             {"type": "url", "value": "hxxp://user[[@]]evil14[[[.]]]example.com/a"},
             {"type": "email-addr", "value": "user[[@]]evil15.example.com"}],
}  # fmt: skip
NESTED_STORED = [  # the records record_finding stores for them, refanged
    {"id": "I-tester-003", "type": "domain-name", "value": "evil13.example.com",
     "status": "APPROVED", "source_findings": ["F-tester-003"]},
    {"id": "I-tester-004", "type": "url", "value": "http://user@evil14.example.com/a",
     "status": "APPROVED", "source_findings": ["F-tester-003"]},
]  # fmt: skip


def test_the_ioc_report_writes_an_ioc_given_in_nested_brackets_defanged(  # noqa: F811
    case_dir, identity  # noqa: F811
):  # fmt: skip
    saved = _saved(case_dir, identity, [NESTED], NESTED_STORED, ioc=True)
    assert "evil13[.]example[.]com" in saved
    assert "hxxp://user@evil14[.]example[.]com/a" in saved
    assert "evil13.example.com" not in saved and "evil14.example.com" not in saved


def test_the_findings_report_writes_an_ioc_given_in_nested_brackets_defanged(  # noqa: F811
    case_dir, identity  # noqa: F811
):  # fmt: skip
    """Its IOC field is shown as given: the nested forms stay as they are."""
    saved = _saved(case_dir, identity, [NESTED], NESTED_STORED,
                   report_findings="F-tester-003")  # fmt: skip
    assert "Beacon to evil13[.]example[.]com." in saved
    assert "C2 at evil13[.]example[.]com" in saved
    assert "evil13[[.]]example.com" in saved and "user[[@]]evil15.example.com" in saved
    assert "hxxp://user[[@]]evil14[[[.]]]example.com/a" in saved
    assert "evil13.example.com" not in saved and "evil14.example.com" not in saved


HXXP_IN_A_NAME = {
    "id": "F-tester-004", "status": "APPROVED", "title": "t",
    "observation": ("Payload at https://safe.example.com/hxxp/payload from "
                    "hxxp.example.com."),
    "interpretation": "i", "confidence": "HIGH",
    "iocs": [{"type": "url", "value": "https://safe.example.com/hxxp/payload"},
             {"type": "domain", "value": "hxxp.example.com"}],
}  # fmt: skip
HXXP_STORED = [  # the records record_finding stores for them (hxxp made http anywhere)
    {"id": "I-tester-005", "type": "url", "value": "https://safe.example.com/http/payload",
     "status": "APPROVED", "source_findings": ["F-tester-004"]},
    {"id": "I-tester-006", "type": "domain-name", "value": "http.example.com",
     "status": "APPROVED", "source_findings": ["F-tester-004"]},
]  # fmt: skip


def test_an_ioc_with_hxxp_outside_its_scheme_is_written_defanged(case_dir, identity):  # noqa: F811
    saved = _saved(case_dir, identity, [HXXP_IN_A_NAME], HXXP_STORED,
                   report_findings="F-tester-004")  # fmt: skip
    assert (
        "Payload at hxxps://safe[.]example[.]com/hxxp/payload from "
        "hxxp[.]example[.]com." in saved
    )
    assert "https://safe.example.com" not in saved and "hxxp.example.com" not in saved


def test_the_ioc_report_writes_them_and_their_records_defanged(case_dir, identity):  # noqa: F811
    saved = _saved(case_dir, identity, [HXXP_IN_A_NAME], HXXP_STORED, ioc=True)
    assert "hxxps://safe[.]example[.]com/http/payload" in saved
    assert "http[.]example[.]com" in saved
    assert "https://safe.example.com" not in saved and "http.example.com" not in saved
