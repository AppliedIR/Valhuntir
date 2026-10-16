"""The IOCs `vhir review --iocs` and the reports list: every value a finding's
iocs holds, a plain string too, under one label each, and once. A value with
no type takes the type of the case's IOC record for it, else the pattern that
matches all of it, else "Unknown". Values only a finding's text names come
last, in one group. `vhir report --ioc`, `--full`'s JSON `iocs` and the
executive summary's counts list the same groups."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands.report import _extract_all_iocs
from vhir_cli.commands.review import _extract_iocs_from_findings
from vhir_cli.display import one_line
from vhir_cli.ioc_groups import LABELS, TEXT_ONLY, ioc_groups, ioc_key

from .signing import sign_approved
from .test_finding_iocs_and_tabs_shown import SID, UNC, _cli, case  # noqa: F401

FIXTURE = Path(__file__).parent / "fixtures"
SHA = "AB" * 32
NOTE = "Seen on the host."


def _f(n, iocs=None, observation=NOTE, interpretation="", **extra):
    f = {"id": f"F-tester-{n:03d}", "status": "APPROVED", "title": f"t{n}",
         "observation": observation, "interpretation": interpretation, **extra}  # fmt: skip
    if iocs is not None:
        f["iocs"] = iocs
    return f


def _r(n, value, type_, status="APPROVED"):
    return {"id": f"IOC-tester-{n:03d}", "value": value, "type": type_,
            "status": status, "source_findings": ["F-tester-001"]}  # fmt: skip


# The examiner's dry-run case: two approved findings and their nine records,
# then a finding that names defanged and host:port values, and their records
DRY_RUN = json.loads((FIXTURE / "ioc_lists_dry_run_case.json").read_text())
DRY_RUN_LIST = {
    "Domain": ["evil2[.]com", "evil[.]com"],
    "File": [UNC],
    "IPv4": ["172.16.30.23", "172.16.5.21", "172.16.6.12", "172.16.6.14",
             "172.16.6.18", "172.16.7.15", "203.0.113.7:8443"],
    "Unknown": [SID],
    "user-account": ["tdungan"],
    TEXT_ONLY: ["172.16.6.11", "C:\\Windows\\system32\\cmd.exe"],
}  # fmt: skip

F1 = _f(1, ["172.16.6.12", UNC, {"value": "tdungan", "type": "user-account"}, SID],
        observation="Logon from 172.16.6.12 mapped \\\\172.16.6.12\\c$\\Users as tdungan.",
        interpretation="Admin share access.")  # fmt: skip
F3 = _f(3, [{"value": "203.0.113.7", "type": "ipv4-addr"}],
        observation="Beacon to 203.0.113.7 every 60 s.", interpretation="C2.")  # fmt: skip

# name -> (findings, records, the list every view gives)
SHAPES = {
    "dry-run-case": (DRY_RUN["findings"], DRY_RUN["records"], DRY_RUN_LIST),
    "strings-no-records": (
        [F1, F3], [],
        {"IPv4": ["172.16.6.12", "203.0.113.7"], "Unknown": [SID, UNC],
         "user-account": ["tdungan"]},
    ),
    "strings-with-records": (
        [F1, F3], DRY_RUN["records"],
        {"File": [UNC], "IPv4": ["172.16.6.12", "203.0.113.7"], "Unknown": [SID],
         "user-account": ["tdungan"]},
    ),
    "type-null": ([_f(1, [{"value": "10.1.2.3", "type": None}])], [], {"IPv4": ["10.1.2.3"]}),
    "type-missing": ([_f(1, [{"value": "evil.com"}])], [], {"Domain": ["evil.com"]}),
    "type-empty": ([_f(1, [{"value": SHA, "type": ""}])], [], {"SHA256": [SHA]}),
    "type-blank": ([_f(1, [{"value": "a" * 32, "type": "  "}])], [], {"MD5": ["a" * 32]}),
    "type-null-record": (
        [_f(1, [{"value": "tdungan", "type": None}])], [_r(1, "tdungan", "user-account")],
        {"user-account": ["tdungan"]},
    ),
    "type-list": ([_f(1, [{"value": "10.1.2.3", "type": ["ipv4-addr"]}])], [],
                  {"['ipv4-addr']": ["10.1.2.3"]}),
    "type-int": ([_f(1, [{"value": "10.1.2.3", "type": 4}])], [], {"4": ["10.1.2.3"]}),
    "type-dict": ([_f(1, [{"value": "x", "type": {"a": 1}}])], [], {"{'a': 1}": ["x"]}),
    "type-mapped-any-case": ([_f(1, [{"value": "10.1.2.3", "type": " IPv4-ADDR "}])], [],
                             {"IPv4": ["10.1.2.3"]}),
    "type-shown-as-stored": ([_f(1, [{"value": "svc", "type": "User-Account"}])], [],
                             {"User-Account": ["svc"]}),
    "type-control-char": ([_f(1, [{"value": "x", "type": "evil\x1b[2J"}])], [],
                          {"evil\x1b[2J": ["x"]}),
    "string-record-type": ([_f(1, ["evil.com"])], [_r(1, "EVIL.com.", "url")], {"URL": ["evil.com"]}),
    "string-record-draft": ([_f(1, ["evil.com"])], [_r(1, "evil.com", "url", "DRAFT")],
                            {"URL": ["evil.com"]}),
    "string-record-no-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", "")], {"Domain": ["evil.com"]}),
    "string-record-null-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", None)],
                                {"Domain": ["evil.com"]}),
    "string-record-list-type": ([_f(1, ["evil.com"])], [_r(1, "evil.com", ["url"])],
                                {"['url']": ["evil.com"]}),
    "string-first-typed-record": (
        [_f(1, ["evil.com"])], [_r(1, "evil.com", ""), _r(2, "evil.com", "domain-name"),
                                _r(3, "evil.com", "url")],
        {"Domain": ["evil.com"]},
    ),
    "string-patterns": (
        [_f(1, ["10.9.8.7", SHA, "b" * 40, "c" * 32, "C:\\Temp\\x.exe", "bad.ru", "hello"])], [],
        {"Domain": ["bad.ru"], "File": ["C:\\Temp\\x.exe"], "IPv4": ["10.9.8.7"],
         "MD5": ["c" * 32], "SHA1": ["b" * 40], "SHA256": [SHA], "Unknown": ["hello"]},
    ),
    "string-defanged-record": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil[.]com"]},
    ),
    "string-ip-port-record": (
        [_f(1, ["203.0.113.7:8443"], observation="Beacon to 203.0.113.7:8443.")],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7:8443"]},
    ),
    "typed-defanged-in-text": (
        [_f(1, [{"value": "evil2[.]com", "type": "domain-name"}], observation="Beacon to evil2.com.")],
        [], {"Domain": ["evil2[.]com"]},
    ),
    "typed-ip-port-in-text": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}], observation="Beacon to 203.0.113.7.")],
        [], {"IPv4": ["203.0.113.7:8443"]},
    ),
    "defanged-recorded-and-text-not-recorded": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com, then bad[.]ru.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil[.]com"], TEXT_ONLY: ["bad.ru"]},
    ),
    "domain-keeps-its-port": (
        [_f(1, ["evil.com:443"], observation="Beacon to evil.com:443.")],
        [_r(1, "evil.com:443", "unknown")], {"Unknown": ["evil.com:443"], TEXT_ONLY: ["evil.com"]},
    ),
    "ip-port-typed-other-than-ipv4-addr-keeps-it": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4"}], observation="Beacon to 203.0.113.7.")],
        [], {"IPv4": ["203.0.113.7:8443"], TEXT_ONLY: ["203.0.113.7"]},
    ),
    "first-label-kept": (
        [_f(1, [{"value": "1.2.3.4", "type": "ipv4-addr"}]),
         _f(2, [{"value": "1.2.3.4", "type": "domain"}])], [],
        {"IPv4": ["1.2.3.4"]},
    ),
    "hash-any-case-once": ([_f(1, [SHA]), _f(2, [SHA.lower()])], [], {"SHA256": [SHA]}),
    "name-trailing-dot-once": ([_f(1, ["Evil.com."]), _f(2, ["evil.com"])], [],
                               {"Unknown": ["Evil.com."]}),
    "path-any-case-once": ([_f(1, [UNC]), _f(2, [UNC.upper()])], [], {"Unknown": [UNC]}),
    "text-only-last": (
        [_f(1, [{"value": "svc", "type": "user-account"}], observation="Beacon to 8.8.4.4.")], [],
        {"user-account": ["svc"], TEXT_ONLY: ["8.8.4.4"]},
    ),
    "text-already-listed": ([_f(1, ["8.8.4.4"], observation="Beacon to 8.8.4.4.")], [],
                            {"IPv4": ["8.8.4.4"]}),
    "text-listed-by-a-later-finding": (
        [_f(1, observation="Beacon to evil.com."),
         _f(2, [{"value": "EVIL.COM", "type": "url"}])], [],
        {"URL": ["EVIL.COM"]},
    ),
    "text-only-once": (
        [_f(1, observation=f"{SHA} then {SHA.lower()}", interpretation="via Bad.com and bad.com")],
        [], {TEXT_ONLY: [SHA.lower(), "bad.com"]},
    ),
    "text-local-addresses-left-out": (
        [_f(1, observation="Bound 0.0.0.0, then 127.0.0.1 and 255.255.255.255; beacon to 10.9.8.7.")],
        [], {TEXT_ONLY: ["10.9.8.7"]},
    ),
    "dict-form": ([_f(1, {"IPv4": ["1.2.3.4"], "": ["evil.com"], "url": "http://x.io/a"})], [],
                  {"Domain": ["evil.com"], "IPv4": ["1.2.3.4"], "URL": ["http://x.io/a"]}),
    "empty-values-left-out": (
        [_f(1, [None, "", "  ", {"value": None, "type": "ip"}, {"type": "ip"}, 5, ["x"]])], [], {},
    ),
    "value-not-a-string": ([_f(1, [{"value": 445, "type": "port"}])], [], {"port": ["445"]}),
    "stored-type-is-the-text-label": (
        [_f(1, [{"value": "x", "type": TEXT_ONLY}], observation="to 8.8.4.4")], [],
        {TEXT_ONLY: ["8.8.4.4", "x"]},
    ),
    "text-path-sentence-punctuation": (
        [_f(1, ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
            observation="Removed C:\\Windows\\System32\\SRLUpdate.exe. The task ran "
                        '"C:\\Windows\\System32\\STUN.exe", then (C:\\Temp\\a.exe) and '
                        "'C:\\Temp\\b.exe'; C:\\Temp\\c.exe: done")], [],
        {"File": ["C:\\Windows\\System32\\SRLUpdate.exe", "C:\\Windows\\System32\\STUN.exe"],
         TEXT_ONLY: ["C:\\Temp\\a.exe", "C:\\Temp\\b.exe", "C:\\Temp\\c.exe"]},
    ),
    "path-really-ending-in-a-dot": (
        [_f(1, ["C:\\Temp\\odd."], observation="Wrote C:\\Temp\\odd. and left.")], [],
        {"File": ["C:\\Temp\\odd."]},
    ),
    "text-path-closed-parens-kept": (
        [_f(1, observation="Ran C:\\Temp\\copy(1) and (see C:\\Temp\\x(2).exe)")], [],
        {TEXT_ONLY: ["C:\\Temp\\copy(1)", "C:\\Temp\\x(2).exe"]},
    ),
    "no-iocs": ([_f(1)], [], {}),
}  # fmt: skip


# --- the list --------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(SHAPES))
def test_each_extractor_lists_the_shape(shape):
    findings, records, want = SHAPES[shape]
    for got in (
        ioc_groups(findings, records),
        _extract_all_iocs(findings, records),
        _extract_iocs_from_findings(findings, records),
    ):
        assert got == want
        assert list(got) == list(want)  # labels sorted, the text-only group last


@pytest.mark.parametrize("stored", list(LABELS))
def test_each_stored_type_reads_as_its_label(stored):
    got = ioc_groups([_f(1, [{"value": "v", "type": stored}])], [])
    assert got == {LABELS[stored]: ["v"]}


@pytest.mark.parametrize(
    "value, key",
    [(SHA, SHA.lower()), (" " + "C" * 40 + " ", "c" * 40), ("Evil.COM.", "evil.com"),
     ("10.1.2.3", "10.1.2.3"), (UNC.upper(), UNC.lower()), ("Tdungan", "Tdungan"),
     ("evil[.]com", "evil.com"), ("hxxp://Evil[.]com/a", "http://evil.com/a"),
     ("user[@]evil.com", "user@evil.com"), (" 203.0.113.7:8443 ", "203.0.113.7"),
     ("203[.]0[.]113[.]7:8443", "203.0.113.7"), ("10.0.0.1/24", "10.0.0.1/24"),
     ("300.1.1.1:80", "300.1.1.1:80"), ("evil.com:443", "evil.com:443")],
)  # fmt: skip
def test_values_compare_as_forensic_mcp_records_them(value, key):
    assert ioc_key(value) == key


@pytest.mark.parametrize(
    "type_, key",
    [("ipv4-addr", "203.0.113.7"), (None, "203.0.113.7"), ("", "203.0.113.7"),
     ("ipv4", "203.0.113.7:8443"), ("domain-name", "203.0.113.7:8443"),
     (["ipv4-addr"], "203.0.113.7:8443")],
)  # fmt: skip
def test_an_ipv4_loses_its_port_as_forensic_mcp_types_it(type_, key):
    assert ioc_key("203.0.113.7:8443", type_) == key


def test_the_findings_and_records_are_left_as_they_were():
    findings, records, _ = SHAPES["dry-run-case"]
    before = json.dumps([findings, records])
    ioc_groups(findings, records)
    assert json.dumps([findings, records]) == before


# --- each view -------------------------------------------------------------------


def _review(groups):
    if not groups:
        return "No IOCs found in findings."
    rows = [f"  {one_line(k) + ':':<10} {', '.join(one_line(v) for v in vs)}"
            for k, vs in groups.items()]  # fmt: skip
    return "\n".join(["=== IOCs from Approved Findings ===", *rows]) + "\n"


def _report_ioc(groups):
    if not groups:
        return "No IOCs found in approved findings."
    rows = ["IOC REPORT (Approved Findings Only)", "=" * 50]
    for k, vs in groups.items():
        rows += [f"\n  {one_line(k)} ({len(vs)}):", *(f"    {one_line(v)}" for v in vs)]
    total = sum(len(v) for v in groups.values())
    return "\n".join([*rows, f"\nTotal: {total} IOCs across {len(groups)} types"])


def _summary(groups):
    total = sum(len(v) for v in groups.values())
    rows = [f"IOCs (from approved findings): {total}"]
    rows += [f"  {one_line(k)}: {len(vs)}" for k, vs in groups.items()]
    return "\n".join([*rows, "", "Open TODOs:"])


def _case_with(case, findings, records):  # noqa: F811
    save_timeline(case, [])
    save_findings(case, json.loads(json.dumps(findings)))
    (case / "iocs.json").write_text(json.dumps(records))
    sign_approved(case)


@pytest.mark.parametrize("shape", list(SHAPES))
def test_review_iocs_lists_the_shape(shape, case, monkeypatch, capsys):  # noqa: F811
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert out.rstrip("\n").endswith(_review(want).rstrip("\n")), out


@pytest.mark.parametrize("shape", list(SHAPES))
def test_report_ioc_lists_the_shape(shape, case, monkeypatch, capsys):  # noqa: F811
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert _report_ioc(want) in out, out


@pytest.mark.parametrize("shape", list(SHAPES))
def test_report_full_json_lists_the_shape(shape, case, monkeypatch, capsys):  # noqa: F811
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["report", "--full"])
    got = json.loads(out[out.index("{") :])["iocs"]
    assert got == want
    assert list(got) == list(want)


@pytest.mark.parametrize("shape", list(SHAPES))
def test_the_executive_summary_counts_the_shape(shape, case, monkeypatch, capsys):  # noqa: F811
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["report", "--executive-summary"])
    assert _summary(want) in out, out


def test_review_iocs_lists_a_draft_finding_s_strings(case, monkeypatch, capsys):  # noqa: F811
    _case_with(case, [{**F1, "status": "DRAFT"}], DRY_RUN["records"])
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert "=== IOCs from Draft Findings (unverified) ===" in out
    assert f"  {'File:':<10} {UNC}" in out and f"  {'Unknown:':<10} {SID}" in out


def test_a_saved_ioc_report_lists_the_strings(case, monkeypatch, capsys):  # noqa: F811
    findings, records, _ = SHAPES["dry-run-case"]
    _case_with(case, findings, records)
    _cli(monkeypatch, capsys, ["report", "--ioc", "--save", "iocs.txt"])
    saved = (case / "reports" / "iocs.txt").read_text()
    assert f"  {TEXT_ONLY} (2):" in saved
    unc = UNC.replace("172.16.6.12", "172[.]16[.]6[.]12")  # its IP defanged too
    assert f"  File (1):\n    {unc}" in saved and f"  Unknown (1):\n    {SID}" in saved
    assert "172[.]16[.]6[.]12" in saved and "172.16.6.12" not in saved
    assert "  Domain (2):\n    evil2[.]com\n    evil[.]com\n" in saved
    assert "    203[.]0[.]113[.]7:8443\n" in saved
    assert "Total: 14 IOCs across 6 types" in saved
