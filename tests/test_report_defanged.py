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


def test_only_an_approved_findings_typed_iocs_are_defanged(case_dir, identity):  # noqa: F811
    """A .dev name isn't one the text extractor finds: a case IOC record typed
    as a domain decides it, and only when an approved finding cites it."""
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
    assert "relay.example.dev; stage[.]example[.]dev." in saved


def test_the_full_json_report_is_saved_defanged(case_dir, identity):  # noqa: F811
    saved = _saved(case_dir, identity, [APPROVED], full=True)
    assert json.loads(saved)["approved_findings"][0]["title"].startswith(
        "C2 at evil[.]com (see"
    )


def test_a_name_an_approved_finding_only_mentions_stays_live(case_dir, identity):  # noqa: F811
    """download.vendor.com is in the finding's text, not among its IOCs."""
    saved = _saved(case_dir, identity, [APPROVED], report_findings="F-tester-001")
    assert (
        "tool from download.vendor.com;" in saved and "download[.]vendor" not in saved
    )
