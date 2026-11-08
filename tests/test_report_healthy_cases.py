"""Healthy cases report as they always have: in each of the six report modes,
shown and saved, on a populated DRAFT case, on a signed case whose items are
approved, on a case whose record files are all `[]` with no approval records,
and on a case just made by `case init`. Nothing raises, no header names a
file, no line says `withheld` or `unreadable`, the save is never refused, it
exits as it always has, the mode prints its own lines and the verification
and provenance blocks, and a save writes the report while a display writes
nothing. `--findings` asked for a finding a case doesn't hold says so on
stderr, exits 1 and saves nothing, as it always has.

An empty timeline differs from before in two ways, each its own test: its
"No timeline events found." is followed by the verification and provenance
blocks, and `--timeline --save` writes the report."""

from __future__ import annotations

import json

import pytest
import yaml

from tests.test_report_save_refused import FINDING, PRIOR
from tests.test_report_stop_matrix import FILES, MODES, _fixture, _lines, _run
from vhir_cli import main

WITHHELD = "withheld: the case fails verification (see below)"
SHAPES = ("draft", "signed", "empty", "fresh")
EMPTY_CASE, FRESH_CASE = "INC-2026-EMPTY", "INC-2026-FRESH"
NO_EVENTS = "No timeline events found."
# what each shape holds: case id, findings and timeline by status, approved
# findings and events, approvals shown, open todos
HOLDS = {
    "draft": ("INC-2026-STOP", {"DRAFT": 1}, {"DRAFT": 1}, 0, 0, 0, 1),
    "signed": ("INC-2026-REFUSE", {"APPROVED": 1}, {"APPROVED": 1}, 1, 1, 3, 1),
    "empty": (EMPTY_CASE, {}, {}, 0, 0, 0, 0),
    "fresh": (FRESH_CASE, {}, {}, 0, 0, 0, 0),
}


def _prior_reports(case):
    for mode in MODES:
        (case / "reports" / f"{mode}.txt").write_bytes(PRIOR)
    return case


def _empty_case(tmp_path, monkeypatch):
    """Every record file `[]`, nothing signed, no approval records."""
    case = tmp_path / EMPTY_CASE
    case.mkdir()
    for name in ("reports", "audit"):
        (case / name).mkdir()
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    meta = {"case_id": EMPTY_CASE, "name": "Empty", "status": "open",
            "created": "2026-10-08T00:00:00Z", "examiner": "tester"}  # fmt: skip
    (case / "CASE.yaml").write_text(yaml.dump(meta))
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    for name in FILES:
        (case / name).write_text("[]")
    return _prior_reports(case)


def _fresh_case(tmp_path, monkeypatch):
    """A case as `case init` makes it, with HOME a folder of the test's own."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    data = main._case_init_data(name="Fresh", examiner="tester",
                                cases_dir=str(tmp_path / "cases"), case_id=FRESH_CASE)  # fmt: skip
    case = tmp_path / "cases" / FRESH_CASE
    assert str(data["case_dir"]) == str(case), data
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    return _prior_reports(case)


def _shape(shape, tmp_path, monkeypatch):
    if shape in ("draft", "signed"):
        return _fixture(shape, tmp_path, monkeypatch)
    return (_empty_case if shape == "empty" else _fresh_case)(tmp_path, monkeypatch)


def _parts(counts):
    return ", ".join(f"{s} {c}" for s, c in sorted(counts.items()))


def _expected(shape, mode, saved):
    """The lines `mode` prints on `shape`, in order (`saved`: the file's)."""
    case_id, f, t, af, at, _, todos = HOLDS[shape]
    nf, nt = sum(f.values()), sum(t.values())
    if mode == "timeline":
        return ["Total: 1 events"] if nt else [NO_EVENTS]
    if mode == "findings":
        title = FINDING["title"] if shape == "signed" else "Beacon"
        status = "APPROVED" if shape == "signed" else "DRAFT"
        return [f"  [{FINDING['id']}] {title}", f"  Status:       {status}"]
    if mode == "ioc":
        if shape != "signed":
            return [
                "  Approved IOC records: none",
                "Total: 0 IOC records across 0 types",
            ]
        value = [] if saved else ["    c2.example.net"]  # a saved one is defanged
        return [*value, "Total: 1 IOC records across 1 types"]
    if mode == "executive_summary":
        return [
            "Findings:", f"  Total: {nf}", *(f"  {s}: {c}" for s, c in sorted(f.items())),
            "Timeline Events:", f"  Total: {nt}",
            *(f"  {s}: {c}" for s, c in sorted(t.items())),
            f"Approved (verified): {af} findings, {at} timeline events; not verified: 0",
            *([] if shape == "signed" else ["IOCs (from approved findings): 0"]),
            f"Open TODOs: {todos}",
        ]  # fmt: skip
    return [f"Case {case_id}: open", f"Findings: {nf} ({_parts(f)})",
            f"Timeline: {nt} ({_parts(t)})", f"Open TODOs: {todos}"]  # fmt: skip


def _in_order(want, lines):
    at = 0
    for w in want:
        assert w in lines[at:], (w, lines)
        at = lines.index(w, at) + 1


def _blocks(shape, lines):
    """The verification block, then the provenance block."""
    approvals = HOLDS[shape][5]
    shown = [x for x in lines if x.startswith("Approvals shown as approved: ")]
    assert shown and shown[0].startswith(f"Approvals shown as approved: {approvals} ")
    prov = (f"[{FINDING['id']}] {FINDING['title']}" if shape == "signed"
            else "No approved, verified findings.")  # fmt: skip
    _in_order(["VERIFICATION", "PROVENANCE", prov], lines)
    assert not [x for x in lines if x.startswith("Case-level: ")], lines
    assert "Not verified, so not shown as approved:" not in lines


def _healthy(res):
    """Nothing raised, and no header, withheld, unreadable or refusal line."""
    assert res["raised"] is None, res["raised"]
    both = res["out"] + res["err"]
    assert "Traceback" not in both, both[-800:]
    assert WITHHELD not in both and "unreadable (see above)" not in both, both[-800:]
    assert "not saved" not in both.lower(), res["err"]
    for line in _lines(both):
        assert not any(line.startswith(f"{n} ") for n in FILES), line


def _full(res, shape):
    body, _ = json.JSONDecoder().raw_decode(res["out"].lstrip())
    case_id, f, t, af, at, _, todos = HOLDS[shape]
    want = {"total_findings": sum(f.values()), "approved_findings": af,
            "total_timeline_events": sum(t.values()), "approved_timeline_events": at,
            "finding_status": f, "timeline_status": t, "open_todos": todos}  # fmt: skip
    assert {k: body["summary"][k] for k in want} == want, body["summary"]
    assert body["case"]["case_id"] == case_id
    assert "unreadable" not in body and "approved_view_withheld" not in body
    assert "verification" in body
    return body


CELLS = [
    pytest.param(shape, mode, save, id=f"{shape}-{mode}-{'save' if save else 'show'}")
    for shape in SHAPES
    for mode in MODES
    for save in (False, True)
]


@pytest.mark.parametrize("shape,mode,save", CELLS)
def test_a_healthy_case_reports_as_before(tmp_path, monkeypatch, shape, mode, save):
    case = _shape(shape, tmp_path, monkeypatch)
    res = _run(case, mode, save)
    _healthy(res)
    name = f"{mode}.txt"
    others = {k: v for k, v in res["after"].items() if k != name}
    assert others == {k: v for k, v in res["before"].items() if k != name}
    if mode == "findings" and shape in ("empty", "fresh"):  # no finding to report
        assert res["rc"] == 1, res["rc"]
        assert f"Not found: {FINDING['id']}" in res["err"].splitlines(), res["err"]
        assert "No matching findings." in res["err"].splitlines(), res["err"]
        assert "VERIFICATION" not in res["out"].splitlines(), res["out"]
        assert res["after"] == res["before"], "reports/ changed"
        return
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    saved = (case / "reports" / name).read_text() if save else None
    if not save:  # a display writes nothing, its own report file included
        assert res["after"] == res["before"], "a display wrote reports/"
    if mode == "full":
        _full(res, shape)
        if save:
            assert res["after"][name] != res["before"][name], "not saved"
            _full({"out": saved}, shape)
        return
    lines = _lines(res["out"])
    _in_order(_expected(shape, mode, False), lines)
    if mode == "timeline" and shape in ("empty", "fresh"):
        return  # the block after it, and what a save does, are the next tests
    _blocks(shape, lines)
    if save:
        assert res["after"][name] != res["before"][name], "not saved"
        assert "Saved to:" in res["out"] + res["err"]
        saved_lines = _lines(saved)
        _in_order(_expected(shape, mode, True), saved_lines)
        _blocks(shape, saved_lines)
    else:
        assert "Saved to:" not in res["out"] + res["err"]


EMPTY = [
    pytest.param(shape, save, id=f"{shape}-{'save' if save else 'show'}")
    for shape in ("empty", "fresh")
    for save in (False, True)
]


@pytest.mark.parametrize("shape,save", EMPTY)
def test_an_empty_timeline_is_followed_by_the_blocks(
    tmp_path, monkeypatch, shape, save
):
    case = _shape(shape, tmp_path, monkeypatch)
    res = _run(case, "timeline", save)
    _healthy(res)
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    lines = _lines(res["out"])
    assert NO_EVENTS in lines, res["out"]
    _blocks(shape, lines[lines.index(NO_EVENTS) + 1 :])


@pytest.mark.parametrize("shape", ("empty", "fresh"))
def test_an_empty_timeline_saves(tmp_path, monkeypatch, shape):
    case = _shape(shape, tmp_path, monkeypatch)
    res = _run(case, "timeline", True)
    _healthy(res)
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    assert res["after"]["timeline.txt"] != res["before"]["timeline.txt"], "not saved"
    assert "Saved to:" in res["out"] + res["err"]
    saved = _lines((case / "reports" / "timeline.txt").read_text())
    assert NO_EVENTS in saved, saved
    _blocks(shape, saved[saved.index(NO_EVENTS) + 1 :])
