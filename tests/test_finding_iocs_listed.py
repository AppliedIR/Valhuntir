"""The IOCs `vhir review --iocs` and the reports list: the case's IOC records,
each under its type's label, as the Portal lists them. `review --iocs` groups
the records by each one's own status; `report --ioc`, `--full`'s JSON `iocs`
and the executive summary list the approved records. A record with no type
takes the text pattern that matches all of its value, else "Unknown". Last,
in one group, the values the findings name, in their iocs or their text, that
no record of the case holds, whatever its status."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vhir_cli import ioc_groups as grouping
from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands.report import _extract_all_iocs
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
    "Domain": ["evil.com", "evil2.com"],
    "File": [UNC],
    "IPv4": ["192.0.2.30", "192.0.2.51", "192.0.2.62", "192.0.2.64",
             "192.0.2.68", "192.0.2.75", "203.0.113.7"],
    "Unknown": [SID],
    "user-account": ["jdoe"],
    TEXT_ONLY: ["192.0.2.61", "C:\\Windows\\system32\\cmd.exe"],
}  # fmt: skip

F1 = _f(1, ["192.0.2.62", UNC, {"value": "jdoe", "type": "user-account"}, SID],
        observation="Logon from 192.0.2.62 mapped \\\\192.0.2.62\\c$\\Users as jdoe.",
        interpretation="Admin share access.")  # fmt: skip
F3 = _f(3, [{"value": "203.0.113.7", "type": "ipv4-addr"}],
        observation="Beacon to 203.0.113.7 every 60 s.", interpretation="C2.")  # fmt: skip

# name -> (findings, records, the list the reports give). Every record here is
# APPROVED, so `review --iocs` gives the same list under "Approved IOCs".
SHAPES = {
    "dry-run-case": (DRY_RUN["findings"], DRY_RUN["records"], DRY_RUN_LIST),
    "no-records": (
        [F1, F3], [],
        {TEXT_ONLY: ["192.0.2.62", "203.0.113.7", SID, UNC, "jdoe"]},
    ),
    "some-records": (
        [F1, F3], [_r(1, UNC, "file:path"), _r(2, "203.0.113.7", "ipv4-addr")],
        {"File": [UNC], "IPv4": ["203.0.113.7"], TEXT_ONLY: ["192.0.2.62", SID, "jdoe"]},
    ),
    # a record's type
    "type-null": ([], [_r(1, "10.1.2.3", None)], {"IPv4": ["10.1.2.3"]}),
    "type-missing": ([], [{"id": "IOC-tester-001", "value": "evil.com", "status": "APPROVED"}],
                     {"Domain": ["evil.com"]}),
    "type-empty": ([], [_r(1, SHA, "")], {"SHA256": [SHA]}),
    "type-blank": ([], [_r(1, "a" * 32, "  ")], {"MD5": ["a" * 32]}),
    "type-none-matches": ([], [_r(1, "hello", None)], {"Unknown": ["hello"]}),
    "type-list": ([], [_r(1, "10.1.2.3", ["ipv4-addr"])], {"['ipv4-addr']": ["10.1.2.3"]}),
    "type-int": ([], [_r(1, "10.1.2.3", 4)], {"4": ["10.1.2.3"]}),
    "type-dict": ([], [_r(1, "x", {"a": 1})], {"{'a': 1}": ["x"]}),
    "type-mapped-any-case": ([], [_r(1, "10.1.2.3", " IPv4-ADDR ")], {"IPv4": ["10.1.2.3"]}),
    "type-shown-as-stored": ([], [_r(1, "svc", "User-Account")], {"User-Account": ["svc"]}),
    "type-control-char": ([], [_r(1, "x", "evil\x1b[2J")], {"evil\x1b[2J": ["x"]}),
    "type-unknown": ([], [_r(1, SID, "unknown")], {"Unknown": [SID]}),
    "patterns": (
        [], [_r(i, v, None) for i, v in enumerate(
            ["10.9.8.7", SHA, "b" * 40, "c" * 32, "C:\\Temp\\x.exe", "bad.ru", "hello"])],
        {"Domain": ["bad.ru"], "File": ["C:\\Temp\\x.exe"], "IPv4": ["10.9.8.7"],
         "MD5": ["c" * 32], "SHA1": ["b" * 40], "SHA256": [SHA], "Unknown": ["hello"]},
    ),
    # a record's value
    "each-record-listed": (
        [], [_r(1, "10.1.2.3", "ipv4-addr"), _r(2, "10.1.2.4", "ipv4-addr")],
        {"IPv4": ["10.1.2.3", "10.1.2.4"]},
    ),
    "value-not-a-string": ([], [_r(1, 445, "port")], {"port": ["445"]}),
    "value-shown-as-stored": ([], [_r(1, "evil[.]com", "domain-name")], {"Domain": ["evil[.]com"]}),
    "empty-values-left-out": (
        [], [_r(1, None, "unknown"), _r(2, "", "unknown"), _r(3, "  ", "unknown"),
             {"id": "IOC-tester-004", "type": "unknown", "status": "APPROVED"}],
        {},
    ),
    # values no record holds
    "recorded-defanged": (
        [_f(1, ["evil[.]com"], observation="Beacon to evil[.]com.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"]},
    ),
    "recorded-ip-port": (
        [_f(1, ["203.0.113.7:8443"], observation="Beacon to 203.0.113.7:8443.")],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7"]},
    ),
    "recorded-typed-ip-port": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4-addr"}])],
        [_r(1, "203.0.113.7", "ipv4-addr")], {"IPv4": ["203.0.113.7"]},
    ),
    "recorded-any-case": (
        [_f(1, [SHA.lower(), UNC.upper(), "Evil.COM."])],
        [_r(1, SHA, "sha256"), _r(2, UNC, "file:path"), _r(3, "evil.com", "domain-name")],
        {"Domain": ["evil.com"], "File": [UNC], "SHA256": [SHA]},
    ),
    "ip-port-typed-other-than-ipv4-addr-keeps-it": (
        [_f(1, [{"value": "203.0.113.7:8443", "type": "ipv4"}], observation="Beacon to 203.0.113.7.")],
        [_r(1, "203.0.113.7", "ipv4-addr")],
        {"IPv4": ["203.0.113.7"], TEXT_ONLY: ["203.0.113.7:8443"]},
    ),
    "domain-keeps-its-port": (
        [_f(1, ["evil.com:443"], observation="Beacon to evil.com:443.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"], TEXT_ONLY: ["evil.com:443"]},
    ),
    "dict-form-keys-untyped": (
        [_f(1, {"IPv4": ["203.0.113.7:8443"], "domain-name": "198.51.100.9:80"})],
        [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "198.51.100.9", "ipv4-addr")],
        {"IPv4": ["198.51.100.9", "203.0.113.7"]},
    ),
    "dict-form-not-recorded": (
        [_f(1, {"IPv4": ["1.2.3.4"], "": ["evil.com"], "url": "http://x.io/a"})], [],
        {TEXT_ONLY: ["1.2.3.4", "evil.com", "http://x.io/a"]},
    ),
    "record-value-not-a-string-matches": (
        [_f(1, ["445"])], [_r(1, 445, "port")], {"port": ["445"]},
    ),
    "not-recorded-once-as-first-written": (
        [_f(1, ["Evil.com."]), _f(2, ["evil.com", {"value": "EVIL.COM", "type": "url"}])], [],
        {TEXT_ONLY: ["Evil.com."]},
    ),
    "not-recorded-value-not-a-string": (
        [_f(1, [{"value": 445, "type": "port"}])], [], {TEXT_ONLY: ["445"]},
    ),
    "not-recorded-empty-left-out": (
        [_f(1, [None, "", "  ", {"value": None, "type": "ip"}, {"type": "ip"}, 5, ["x"]])], [], {},
    ),
    # a finding's IOC typed null, as a list or as a number, and its record
    "finding-ioc-type-null": (
        [_f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"}, {"value": "jdoe", "type": None}])],
        [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "jdoe", None)],
        {"IPv4": ["203.0.113.7"], "Unknown": ["jdoe"]},
    ),
    "finding-ioc-type-list": (
        [_f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"},
                {"value": "jdoe", "type": ["user-account"]}])],
        [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "jdoe", ["user-account"])],
        {"IPv4": ["203.0.113.7"], "['user-account']": ["jdoe"]},
    ),
    "finding-ioc-type-int": (
        [_f(1, [{"value": "203.0.113.7", "type": "ipv4-addr"}, {"value": "jdoe", "type": 7}])],
        [_r(1, "203.0.113.7", "ipv4-addr"), _r(2, "jdoe", 7)],
        {"7": ["jdoe"], "IPv4": ["203.0.113.7"]},
    ),
    "finding-ioc-odd-types-not-recorded": (
        [_f(1, [{"value": "10.0.0.1", "type": None}, {"value": "10.0.0.2", "type": ["ip"]},
                {"value": "10.0.0.3", "type": 7}])],
        [], {TEXT_ONLY: ["10.0.0.1", "10.0.0.2", "10.0.0.3"]},
    ),
    "text-recorded": (
        [_f(1, observation="Beacon to evil[.]com and 8.8.4.4.")],
        [_r(1, "evil.com", "domain-name")], {"Domain": ["evil.com"], TEXT_ONLY: ["8.8.4.4"]},
    ),
    "text-only-once": (
        [_f(1, observation=f"{SHA} then {SHA.lower()}", interpretation="via Bad.com and bad.com")],
        [], {TEXT_ONLY: [SHA.lower(), "bad.com"]},
    ),
    "text-local-addresses-left-out": (
        [_f(1, observation="Bound 0.0.0.0, then 127.0.0.1 and 255.255.255.255; beacon to 10.9.8.7.")],
        [], {TEXT_ONLY: ["10.9.8.7"]},
    ),
    "text-path-sentence-punctuation": (
        [_f(1, ["C:\\Windows\\System32\\AppUpdate.exe", "C:\\Windows\\System32\\Helper.exe"],
            observation="Removed C:\\Windows\\System32\\AppUpdate.exe. The task ran "
                        '"C:\\Windows\\System32\\Helper.exe", then (C:\\Temp\\a.exe) and '
                        "'C:\\Temp\\b.exe'; C:\\Temp\\c.exe: done")],
        [_r(1, "C:\\Windows\\System32\\AppUpdate.exe", "file:path"),
         _r(2, "C:\\Windows\\System32\\Helper.exe", "file:path")],
        {"File": ["C:\\Windows\\System32\\AppUpdate.exe", "C:\\Windows\\System32\\Helper.exe"],
         TEXT_ONLY: ["C:\\Temp\\a.exe", "C:\\Temp\\b.exe", "C:\\Temp\\c.exe"]},
    ),
    "path-really-ending-in-a-dot": (
        [_f(1, ["C:\\Temp\\odd."], observation="Wrote C:\\Temp\\odd. and left.")],
        [_r(1, "C:\\Temp\\odd.", "file:path")], {"File": ["C:\\Temp\\odd."]},
    ),
    "text-path-closed-parens-kept": (
        [_f(1, observation="Ran C:\\Temp\\copy(1) and (see C:\\Temp\\x(2).exe)")], [],
        {TEXT_ONLY: ["C:\\Temp\\copy(1)", "C:\\Temp\\x(2).exe"]},
    ),
    "stored-type-is-the-text-label": (
        [_f(1, observation="to 8.8.4.4")], [_r(1, "x", TEXT_ONLY)],
        {TEXT_ONLY: ["8.8.4.4", "x"]},
    ),
    "no-iocs": ([_f(1)], [], {}),
}  # fmt: skip


# --- the list --------------------------------------------------------------------


@pytest.mark.parametrize("shape", list(SHAPES))
def test_each_extractor_lists_the_shape(shape):
    findings, records, want = SHAPES[shape]
    for got in (ioc_groups(findings, records), _extract_all_iocs(findings, records)):
        assert got == want
        assert list(got) == list(want)  # labels sorted, the text-only group last


@pytest.mark.parametrize("stored", list(LABELS))
def test_each_stored_type_reads_as_its_label(stored):
    assert grouping.record_groups([_r(1, "v", stored)]) == {LABELS[stored]: ["v"]}


@pytest.mark.parametrize(
    "records",
    [[None, "x", 5, ["x"]], [{"id": "IOC-tester-001", "type": "ipv4-addr"}], []],
)
def test_entries_with_no_value_are_left_out(records):
    assert grouping.record_groups(records) == {}


@pytest.mark.parametrize("status", ["DRAFT", "REJECTED", None, "", "approved", "OTHER"])
def test_a_value_any_record_holds_is_recorded_whatever_its_status(status):
    """The values a view's findings name are checked against every record of
    the case, not only the records the view lists."""
    record = {**_r(1, "evil.com", "domain-name"), "status": status}
    finding = _f(1, ["evil[.]com"], observation="Beacon to evil.com.")
    assert grouping.not_recorded([finding], [record]) == []
    assert ioc_groups([finding], [], [record]) == {}


@pytest.mark.parametrize(
    "record, status",
    [({"status": "APPROVED"}, "APPROVED"), ({"status": "draft"}, "DRAFT"),
     ({"status": None}, "DRAFT"), ({"status": ""}, "DRAFT"), ({}, "DRAFT"),
     ({"status": "Rejected"}, "REJECTED"), ({"status": 5}, "5")],
)  # fmt: skip
def test_a_record_s_status_reads_as_the_portal_reads_it(record, status):
    assert grouping.record_status(record) == status


@pytest.mark.parametrize(
    "value, key",
    [(SHA, SHA.lower()), (" " + "C" * 40 + " ", "c" * 40), ("Evil.COM.", "evil.com"),
     ("10.1.2.3", "10.1.2.3"), (UNC.upper(), UNC.lower()), ("Jdoe", "Jdoe"),
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
    """`review --iocs` for records that are all APPROVED."""
    groups = dict(groups)
    rest = groups.pop(TEXT_ONLY, [])
    rows = [f"  {one_line(k) + ':':<10} {', '.join(one_line(v) for v in vs)}"
            for k, vs in groups.items()]  # fmt: skip
    out = ["=== Approved IOCs ===", *rows] if rows else ["IOC records: none"]
    if rest:
        out += ["", f"=== {TEXT_ONLY} ===", f"  {', '.join(one_line(v) for v in rest)}"]
    return "\n".join(out) + "\n"


def _report_ioc(groups):
    records = {k: vs for k, vs in groups.items() if k != TEXT_ONLY}
    rows = ["IOC REPORT (Approved IOCs Only)", "=" * 50]
    for k, vs in groups.items():
        rows += [f"\n  {one_line(k)} ({len(vs)}):", *(f"    {one_line(v)}" for v in vs)]
    if not records:
        rows.insert(2, "\n  Approved IOC records: none")
    total = sum(len(v) for v in records.values())
    return "\n".join(
        [*rows, f"\nTotal: {total} IOC records across {len(records)} types"]
    )


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


# A record stored with the text group's own name as its type is one of the
# records `review --iocs` lists; the reports merge it into that group
REVIEW_SHAPES = [s for s in SHAPES if s != "stored-type-is-the-text-label"]


@pytest.mark.parametrize("shape", REVIEW_SHAPES)
def test_review_iocs_lists_the_shape(shape, case, monkeypatch, capsys):  # noqa: F811
    findings, records, want = SHAPES[shape]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert out.rstrip("\n").endswith(_review(want).rstrip("\n")), out


def test_review_iocs_lists_a_record_typed_as_the_text_group(case, monkeypatch, capsys):  # noqa: F811
    findings, records, _ = SHAPES["stored-type-is-the-text-label"]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert f"=== Approved IOCs ===\n  {TEXT_ONLY}: x\n" in out
    assert out.endswith(f"\n=== {TEXT_ONLY} ===\n  8.8.4.4\n")


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


@pytest.mark.parametrize("type_", [None, ["user-account"], 7])
def test_review_iocs_lists_a_draft_record_with_an_odd_type(
    type_,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    finding = _f(1, [{"value": "jdoe", "type": type_}], status="DRAFT")
    _case_with(case, [finding], [_r(1, "jdoe", type_, "DRAFT")])
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    label = "Unknown" if type_ is None else str(type_)
    assert out.endswith(
        f"=== Draft IOCs (unverified) ===\n  {label + ':':<10} jdoe\n"
    ), out


# --- each record's status ---------------------------------------------------------

STATUS_RECORDS = [
    _r(1, "10.0.0.1", "ipv4-addr"),
    _r(2, "evil.com", "domain-name", "DRAFT"),
    _r(3, "10.0.0.3", "ipv4-addr", "REJECTED"),
    {**_r(4, "10.0.0.4", "ipv4-addr"), "status": None},
    _r(5, "10.0.0.5", "ipv4-addr", "draft"),
    _r(6, "10.0.0.6", "ipv4-addr", "HELD"),
]
STATUS_FINDINGS = [
    _f(1, ["10.0.0.1"], observation="Beacon to evil[.]com and 10.0.0.9."),
    _f(2, ["10.0.0.3", "10.0.0.8"], status="DRAFT"),
]


def test_review_iocs_lists_each_record_under_its_own_status(case, monkeypatch, capsys):  # noqa: F811
    """Every record, whatever its status, as the Portal lists them; a record
    with no status is DRAFT. The values no record holds come from every
    finding."""
    _case_with(case, STATUS_FINDINGS, STATUS_RECORDS)
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert out.endswith(
        "\n=== Approved IOCs ===\n"
        f"  {'IPv4:':<10} 10.0.0.1\n"
        "\n=== Draft IOCs (unverified) ===\n"
        f"  {'Domain:':<10} evil.com\n"
        f"  {'IPv4:':<10} 10.0.0.4, 10.0.0.5\n"
        "\n=== Rejected IOCs ===\n"
        f"  {'IPv4:':<10} 10.0.0.3\n"
        "\n=== HELD IOCs ===\n"
        f"  {'IPv4:':<10} 10.0.0.6\n"
        f"\n=== {TEXT_ONLY} ===\n"
        "  10.0.0.8, 10.0.0.9\n"
    ), out


def test_report_ioc_lists_the_approved_records(case, monkeypatch, capsys):  # noqa: F811
    """Only the approved records are listed; a value a draft or rejected
    record holds is recorded, so it is not in the text group."""
    _case_with(case, STATUS_FINDINGS, STATUS_RECORDS)
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert _report_ioc({"IPv4": ["10.0.0.1"], TEXT_ONLY: ["10.0.0.9"]}) in out, out


def test_a_value_recorded_from_a_draft_finding_is_never_not_recorded(
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    findings = [_f(1, observation="Beacon to evil.com."),
                _f(2, ["evil[.]com"], status="DRAFT")]  # fmt: skip
    records = [
        {
            **_r(1, "evil.com", "domain-name", "DRAFT"),
            "source_findings": ["F-tester-002"],
        }
    ]
    _case_with(case, findings, records)
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert TEXT_ONLY not in out and "evil" not in out, out
    assert "Approved IOC records: none" in out
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert TEXT_ONLY not in out
    assert f"=== Draft IOCs (unverified) ===\n  {'Domain:':<10} evil.com\n" in out


def test_no_records_prints_none(case, monkeypatch, capsys):  # noqa: F811
    _case_with(case, [_f(1)], [])
    assert _cli(monkeypatch, capsys, ["review", "--iocs"]) == "IOC records: none\n"
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert (
        "\n  Approved IOC records: none\n\nTotal: 0 IOC records across 0 types" in out
    )


def test_no_empty_label_is_printed(case, monkeypatch, capsys):  # noqa: F811
    """A record with no value is left out, and its label with it."""
    records = [
        _r(1, "", "unknown"),
        _r(2, None, "unknown"),
        _r(3, "10.0.0.1", "ipv4-addr"),
    ]
    _case_with(case, [], records)
    for argv in (["review", "--iocs"], ["report", "--ioc"]):
        out = _cli(monkeypatch, capsys, argv)
        assert "Unknown" not in out and "10.0.0.1" in out, out


def test_a_saved_ioc_report_lists_the_records(case, monkeypatch, capsys):  # noqa: F811
    findings, records, _ = SHAPES["dry-run-case"]
    _case_with(case, findings, records)
    _cli(monkeypatch, capsys, ["report", "--ioc", "--save", "iocs.txt"])
    saved = (case / "reports" / "iocs.txt").read_text()
    assert f"  {TEXT_ONLY} (2):" in saved
    unc = UNC.replace("192.0.2.62", "192[.]0[.]2[.]62")  # its IP defanged too
    assert f"  File (1):\n    {unc}" in saved and f"  Unknown (1):\n    {SID}" in saved
    assert "192[.]0[.]2[.]62" in saved and "192.0.2.62" not in saved
    assert "  Domain (2):\n    evil[.]com\n    evil2[.]com\n" in saved
    assert "    203[.]0[.]113[.]7\n" in saved
    assert "Total: 12 IOC records across 5 types" in saved


SIGNED = [_r(n, f"10.0.0.{n}", "ipv4-addr") for n in range(1, 6)]
SIGNED += [_r(6, "evil.com", "domain-name")]


def test_the_signed_approved_records_are_printed_and_counted(case, monkeypatch, capsys):  # noqa: F811
    _case_with(case, [_f(1)], SIGNED)
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    ips = [f"10.0.0.{n}" for n in range(1, 6)]
    assert _report_ioc({"Domain": ["evil.com"], "IPv4": ips}) in out, out
    assert out.count("Total: 6 IOC records across 2 types") == 1


def test_approved_records_no_signature_verifies_are_not_reported(
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    """Approved in iocs.json but never signed: the report lists only what
    verifies, while `review --iocs` still lists them as the Portal does."""
    save_timeline(case, [])
    save_findings(case, [_f(1)])
    (case / "iocs.json").write_text(json.dumps(SIGNED))
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert "\n  Approved IOC records: none\n" in out and "10.0.0.1" not in out, out
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    ips = ", ".join(f"10.0.0.{n}" for n in range(1, 6))
    assert out == (
        f"\n=== Approved IOCs ===\n  {'Domain:':<10} evil.com\n  {'IPv4:':<10} {ips}\n"
    ), out
