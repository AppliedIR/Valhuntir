"""Replacements (5b.4's table): in every cell of the stop matrix, each table
line whose source file can't be read prints its one replacement,
`<label>: unreadable (see above)`, once on stdout, in place of all of that
line's head lines; and no line drawn from a damaged file prints its empty form,
on stdout or stderr. Two readings of "its empty form": the table's head lines,
and the lines the healthy twin (the same case before the damage, in the same
mode) prints for that line. In --full, the keys drawn from a damaged file are
null. A cell that raises fails."""

from __future__ import annotations

import json
import re
from collections import Counter

import pytest

from tests.test_report_stop_matrix import (
    CELLS,
    DEEP,
    MODES,
    TWO,
    _fixture,
    _run,
    _spoil,
)

U = "unreadable (see above)"
F, T, IO, D = "findings.json", "timeline.json", "iocs.json", "todos.json"
TEXT = [m for m in MODES if m != "full"]

# the table: (mode, its sources, the replacement, the label its head lines
# start at, and the head lines, as full-line patterns)
ROWS = [
    ("timeline", {T}, f"Timeline: {U}", None,
     [r"No timeline events found\.", r"Total: \d+ events", r"ID +Status +Timestamp +Description"]),
    ("findings", {F}, f"Findings: {U}", None,
     [r"No matching findings\.", r"Not found: .*", r"  \[.*\] .*", r"  Status: .*"]),
    ("ioc", {F, IO}, f"IOC records: {U}", None,
     [r" *Approved IOC records: .*", r"Total: .*", r"  .* \(\d+\):"]),
    ("executive_summary", {F}, f"Findings: {U}", "Findings:", [r"Findings:"]),
    ("executive_summary", {T}, f"Timeline Events: {U}", "Timeline Events:",
     [r"Timeline Events:"]),
    ("executive_summary", {F, IO}, f"IOCs (from approved findings): {U}",
     "IOCs (from approved findings):", [r"IOCs \(from approved findings\): (\d+|withheld.*)"]),
    ("executive_summary", {D}, f"Open TODOs: {U}", "Open TODOs:", [r"Open TODOs: \d+"]),
    ("status_brief", {D}, f"Open TODOs: {U}", "Open TODOs:", [r"Open TODOs: \d+"]),
    ("status_brief", {F}, f"Findings: {U}", "Findings:", [r"Findings: \d+ \(.*\)"]),
    ("status_brief", {T}, f"Timeline: {U}", "Timeline:", [r"Timeline: \d+ \(.*\)"]),
    ("executive_summary", {F, T}, f"Approved (verified): {U}", "Approved (verified):",
     [r"Approved \(verified\): (\d+ findings.*|withheld.*)"]),
    *[(m, {F}, f"Approved findings: {U}", "PROVENANCE",
       [r"No approved, verified findings\.", r"Approved findings: withheld.*"]) for m in TEXT],
]  # fmt: skip
# --full: (sources, key path)
NULL_KEYS = [
    ({F}, ("summary", "total_findings")),
    ({F}, ("summary", "finding_status")),
    ({T}, ("summary", "total_timeline_events")),
    ({T}, ("summary", "timeline_status")),
    ({D}, ("summary", "open_todos")),
    ({F, IO}, ("iocs",)),
]


def _report(out, header):
    """stdout's lines from the report's first line to VERIFICATION, after the
    `header` non-empty lines of the stop header and remediation."""
    lines = out.splitlines()
    cut = lines.index("VERIFICATION") if "VERIFICATION" in lines else len(lines)
    seen, start = 0, 0
    while seen < header and start < cut:
        seen += bool(lines[start].strip())
        start += 1
    return lines[start:cut]


def _section(out, header, mode, label):
    """The non-empty lines of a row's part of the report: PROVENANCE's lines
    after its underline; a label's block (executive summary) or line (status
    brief); or a whole-body mode's lines after its title."""
    lines = out.splitlines()
    if label == "PROVENANCE":
        p = lines.index("PROVENANCE") if "PROVENANCE" in lines else len(lines)
        return [x for x in lines[p + 2 :] if x.strip()]
    body = _report(out, header)
    if mode == "executive_summary":
        blocks, cur = [], []
        for x in [*body, ""]:
            if x.strip():
                cur.append(x)
            elif cur:
                blocks.append(cur)
                cur = []
        return [x for b in blocks if b[0].startswith(label) for x in b]
    if mode == "status_brief":
        return [x for x in body if x.startswith(label)]
    lines = [x for x in body if x.strip()]
    return lines[2:] if mode == "ioc" else lines  # after its title and underline


def _json(out):
    """stdout is the JSON --full prints, and nothing else."""
    return json.loads(out)


def _get(body, path):
    for k in path:
        body = body[k]
    return body


def _replaced(res, twin, mode, bad):
    assert twin["raised"] is None and twin["rc"] == 0, (
        twin["raised"],
        twin["err"][-400:],
    )
    assert res["raised"] is None, res["raised"]
    assert "Traceback" not in res["out"] + res["err"], (res["out"] + res["err"])[-800:]
    if mode == "full":
        body, healthy = _json(res["out"]), _json(twin["out"])
        for src, path in NULL_KEYS:
            if src & bad:
                assert _get(healthy, path) is not None, (path, "null in the twin")
                assert _get(body, path) is None, (path, _get(body, path))
        return
    rows = [r for r in ROWS if r[0] == mode and r[1] & bad]
    out, every = (
        res["out"].splitlines(),
        res["out"].splitlines() + res["err"].splitlines(),
    )
    header = 2 * len(bad)
    # each replacement once, on stdout, in place of all of its row's lines
    for _, _, want, label, _ in rows:
        assert out.count(want) == 1, (
            want,
            out.count(want),
            _report(res["out"], header),
        )
        got = _section(res["out"], header, mode, label)
        assert got == [want], (label, got)
    # reading 1: the table's head lines, in every stream
    printed = [(x, p) for _, _, _, _, ps in rows for p in ps for x in every
               if re.fullmatch(p, x)]  # fmt: skip
    assert printed == [], printed
    # reading 2: the lines the twin prints for each row, less those it prints
    # again outside the damaged rows
    theirs = Counter(
        x for x in twin["out"].splitlines() + twin["err"].splitlines() if x.strip()
    )
    rowed = Counter()
    for _, _, want, label, _ in rows:
        mine = _section(twin["out"], 0, mode, label)
        assert mine and want not in mine, (label, mine)
        rowed.update(mine)
    elsewhere = theirs - rowed
    mine = Counter(x for x in every if x.strip())
    kept = [x for x in rowed if mine[x] > elsewhere[x]]
    assert kept == [], kept


@pytest.mark.parametrize("kind,name,form,mode,save", CELLS)
def test_each_line_from_the_damaged_file_prints_its_replacement(
    tmp_path, monkeypatch, kind, name, form, mode, save
):
    case = _fixture(kind, tmp_path, monkeypatch)
    twin = _run(case, mode, False)
    _spoil(case / name, form)
    _replaced(_run(case, mode, save), twin, mode, {name})


@pytest.mark.parametrize("save", (False, True), ids=("show", "save"))
@pytest.mark.parametrize("kind", ("draft", "signed"))
@pytest.mark.parametrize("cell", TWO)
def test_two_damaged_files_each_print_their_replacements(
    tmp_path, monkeypatch, cell, kind, save
):
    mode, damaged = TWO[cell]
    case = _fixture(kind, tmp_path, monkeypatch)
    twin = _run(case, mode, False)
    for name, form in damaged:
        _spoil(case / name, form)
    _replaced(_run(case, mode, save), twin, mode, {n for n, _ in damaged})


@pytest.mark.parametrize("save", (False, True), ids=("show", "save"))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", ("draft", "signed"))
@pytest.mark.parametrize("name", (F, T))
def test_a_500_deep_list_prints_the_replacements(
    tmp_path, monkeypatch, name, kind, mode, save
):
    case = _fixture(kind, tmp_path, monkeypatch)
    twin = _run(case, mode, False)
    _spoil(case / name, DEEP)
    _replaced(_run(case, mode, save), twin, mode, {name})


def test_the_table_is_the_specs():
    """A control on the table above: 5b.4's rows (its TODO row once per mode), PROVENANCE's in each
    text mode, and no replacement matches a head line of its own row (reading
    1 would then fail on the replacement itself)."""
    assert len(ROWS) == 11 + len(TEXT)
    assert {m for m, _, want, *_ in ROWS if want == f"Approved findings: {U}"} == set(
        TEXT
    )
    assert [
        (want, p) for _, _, want, _, ps in ROWS for p in ps if re.fullmatch(p, want)
    ] == []
