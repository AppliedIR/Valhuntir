"""The readers label a record's stored type from the IOC table.

Every spelling the table accepts, in its own form and in case and separator
variants, reads as its id's label. A spelling the table refuses reads as
stored. Records stored before the table keep their bytes.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from pathlib import Path

import pytest

from vhir_cli import ioc_groups as grouping

from .test_finding_iocs_and_tabs_shown import _cli, case  # noqa: F401
from .test_finding_iocs_listed import _case_with, _f, _r, _report_ioc, _review

TABLE = Path(__file__).with_name("ioc_vocabulary.json")
DATA = json.loads(TABLE.read_text())
LABEL = {id_: label for _, id_, label in DATA["ids"]}
SPELLINGS = [(id_, id_) for id_ in LABEL]
SPELLINGS += [
    (alias, id_) for id_, aliases in DATA["aliases"].items() for alias in aliases
]


def _forms(s):
    sep = s.replace("-", "_") if "-" in s else s[:1] + "_" + s[1:]
    return {
        "own": s,
        "case": s.upper(),
        "sep": sep,
        "case+sep": " " + s.upper().replace("-", "_") + " ",
    }


ROWS = [
    (form, typed, LABEL[id_])
    for s, id_ in SPELLINGS
    for form, typed in _forms(s).items()
]


@pytest.mark.parametrize(("form", "typed", "label"), ROWS)
def test_each_accepted_spelling_reads_as_its_label(form, typed, label):
    assert grouping.record_groups([_r(1, "v", typed)]) == {label: ["v"]}


@pytest.mark.parametrize("typed", DATA["refused"])
def test_a_refused_spelling_reads_as_stored(typed):
    assert grouping.record_groups([_r(1, "v", typed)]) == {typed: ["v"]}


def _all_spellings():
    records, want = [], {}
    for n, (s, id_) in enumerate(SPELLINGS):
        for form in ("own", "sep"):
            value = f"value-{form}-{n:03d}"
            records.append(_r(len(records) + 1, value, _forms(s)[form]))
            want.setdefault(LABEL[id_], []).append(value)
    return records, {k: sorted(want[k]) for k in sorted(want)}


def test_review_iocs_lists_every_spelling_under_its_label(case, monkeypatch, capsys):  # noqa: F811
    records, want = _all_spellings()
    _case_with(case, [], records)
    out = _cli(monkeypatch, capsys, ["review", "--iocs"])
    assert out.rstrip("\n").endswith(_review(want).rstrip("\n")), out


def test_report_ioc_lists_every_spelling_under_its_label(case, monkeypatch, capsys):  # noqa: F811
    records, want = _all_spellings()
    _case_with(case, [_f(1)], records)
    out = _cli(monkeypatch, capsys, ["report", "--ioc"])
    assert _report_ioc(want) in out, out


# Records stored before the table, under spellings a case holds: each reads
# as its id's label, the two the table refuses read as stored
OLD = [
    ("file_name", "dropper.dll", "File name"),
    ("account", "CORP\\jdoe", "Account"),
    ("other", "opaque-marker-7", "Unknown"),
    ("url_path", "/admin/shell.aspx", "URL path"),
    ("email-subject", "Invoice overdue", "Email subject"),
    ("imphash", "f34d5f2d4577ed6d9ceec516c1f5a744", "Imphash"),
    ("named-pipe", "\\\\.\\pipe\\msagent_7f", "Named pipe"),
    ("hash", "0123456789abcdef0123456789abcdef", "hash"),
    ("path", "/var/tmp/.x/run", "path"),
]
OLD_LIST = {}
for _, value, label in OLD:
    OLD_LIST.setdefault(label, []).append(value)
OLD_LIST = {k: sorted(OLD_LIST[k]) for k in sorted(OLD_LIST)}


@pytest.mark.parametrize("argv", [["review", "--iocs"], ["report", "--ioc"]])
def test_old_records_read_by_label_and_keep_bytes(argv, case, monkeypatch, capsys):  # noqa: F811
    records = [_r(n, value, typed) for n, (typed, value, _) in enumerate(OLD, 1)]
    _case_with(case, [_f(1)], records)
    before = (case / "iocs.json").read_bytes()
    out = _cli(monkeypatch, capsys, argv)
    want = (
        _review(OLD_LIST).rstrip("\n") if argv[0] == "review" else _report_ioc(OLD_LIST)
    )
    assert want in out, out
    assert (case / "iocs.json").read_bytes() == before


# One host cited three ways no record holds: bare, with its port, and with its
# port under "unknown". The not-recorded list shows it once, as the bare address.
A, B, C = (
    ("10.20.30.41", None),
    ("10.20.30.41:443", None),
    ("10.20.30.41:443", "unknown"),
)
ORDERS = list(itertools.permutations([A, B, C]))


def _cited(order):
    findings = [_f(n, [{"value": v, "type": t} if t else v], observation="", interpretation="")
                for n, (v, t) in enumerate(order, 1)]  # fmt: skip
    return [
        v for v in grouping.not_recorded(findings, []) if v.startswith("10.20.30.41")
    ]


@pytest.mark.parametrize(
    "order", ORDERS, ids=lambda o: " ".join(f"{v}/{t}" for v, t in o)
)
def test_one_host_cited_three_ways_is_listed_once(order):
    assert len(_cited(order)) == 1


@pytest.mark.parametrize(
    "order", ORDERS, ids=lambda o: " ".join(f"{v}/{t}" for v, t in o)
)
def test_the_host_listed_is_the_bare_address(order):
    assert _cited(order) == ["10.20.30.41"]


def test_the_table_beside_these_tests_is_forensic_mcps_byte_for_byte():
    digest = hashlib.sha256(TABLE.read_bytes()).hexdigest()
    assert digest == "5d1a68b3f17dcc2949b40e126fdbb98959cbe057b4b0615c96cc2d830af26c77"
