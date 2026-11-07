"""A report on a case whose approved view is blanked (verify's case-level
failures are non-empty) prints each line the blanked view empties as
`<label>: withheld: the case fails verification (see below)`, never its empty
form: --ioc's "Approved IOC records" and "Total", the executive summary's
"Approved (verified)" and "IOCs (from approved findings)", and PROVENANCE's
"Approved findings". --full carries `"approved_view_withheld": true`.

Fixture (i) holds one cell per measured case-level code, on a signed case and,
for DUPLICATE_ID and MALFORMED_RECORD, on a DRAFT case. Fixtures (ii) and
(iii) are item-level: an item drops to not verified, the view isn't blanked,
and no withheld line appears; the verified items are counted and shown, the
dropped one isn't. Every cell asserts the codes verify emits for it first, so
a cell's class is measured, not assumed. In all of them, in every mode, shown
and saved: no header, rc 0, and --save writes. The one exception is --findings
on the signed case whose findings.json is []: the lookup miss exits 1 and
saves nothing, as at head.

A saved text report on a failing case has every IOC record's value defanged,
and so does one whose only holder of a value is verify's own read."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import traceback

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests import signing
from tests.signing import sign_approved, with_checks
from tests.test_report_save_refused import (
    CASE,
    EVENT,
    FINDING,
    IDENTITY,
    IOC,
    PRIOR,
    VALUE,
    _args,
)
from tests.test_report_save_refused import _case as _signed_case
from tests.test_report_stop_matrix import _draft_case
from vhir_cli import case_io, keys, ledger
from vhir_cli.case_io import signed_text
from vhir_cli.commands import report as rep
from vhir_cli.ledger_verify import approved_view, verify_case

W = "withheld: the case fails verification (see below)"
MODES = ("timeline", "findings", "ioc", "executive_summary", "status_brief", "full")
TEXT = MODES[:-1]
TODO = {"todo_id": "TODO-tester-001", "status": "open", "description": "Pull logs"}
AT = "2026-10-08T10:00:00+00:00"
DEFANGED = VALUE.replace(".", "[.]")
B_ONLY = "b-only.example.org"
WITHHELD_LINES = {  # mode: the lines the blanked view empties, label and spaces kept
    "ioc": [f"  Approved IOC records: {W}", f"Total: {W}", f"Approved findings: {W}"],
    "executive_summary": [f"Approved (verified): {W}",
                          f"IOCs (from approved findings): {W}",
                          f"Approved findings: {W}"],
    "findings": [f"Approved findings: {W}"],
    "timeline": [f"Approved findings: {W}"],
    "status_brief": [f"Approved findings: {W}"],
}  # fmt: skip
EMPTY_FORMS = ("Approved IOC records: none", "Total: 0 IOC records across 0 types",
               "Approved (verified): 0 findings", "IOCs (from approved findings): 0",
               "No approved, verified findings.")  # fmt: skip
HEADER_FILES = ("findings.json ", "timeline.json ", "iocs.json ", "todos.json ")


# --- building the cases -----------------------------------------------------
def _writable(path):
    if path.exists():
        path.chmod(0o644)


def _rewrite(path, fn):
    _writable(path)
    path.write_text(json.dumps(fn(json.loads(path.read_text())), indent=2))


def _chain():
    path = ledger.chain_path(CASE)
    assert path.is_file(), path
    return path


def _put_lines(path, lines):
    _writable(path)
    path.write_text("".join(x + "\n" for x in lines))


def _edit_line(i, fn, key=None):
    """Line i of the box chain, changed by fn; re-signed with `key` if given."""
    lines = _chain().read_text().splitlines()
    obj = json.loads(lines[i])
    fn(obj)
    lines[i] = (ledger.sign_body(ledger.body_of(obj), key) if key
                else ledger.canonical(obj).decode("ascii"))  # fmt: skip
    _put_lines(_chain(), lines)


def _flip(obj):
    obj["sig"] = ("B" if obj["sig"][0] == "A" else "A") + obj["sig"][1:]


def _key(case):
    return signing._KEYS[(str(case), "tester")]


def _sign(case, key, kind, item):
    """One approve line for `item`, signed with `key`."""
    d = [{"item_id": item["id"], "type": kind, "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(item, kind)}]  # fmt: skip
    pub = keys.b64(keys.public_raw(key))
    bodies = ledger.prepare(CASE, [with_checks(x) for x in d], "tester", pub, "cli", AT)
    with ledger.case_lock(CASE) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


def _record(case, name, item_id):
    return next(i for i in json.loads((case / name).read_text()) if i["id"] == item_id)


def _resigned(tmp_path, monkeypatch):
    """The signed case with its chain made again by one sign_approved: line 1
    F-tester-001, line 2 T-tester-001, line 3 IOC-tester-001, one key."""
    case = _signed_case(tmp_path, monkeypatch)
    aside = tmp_path / "aside"
    aside.mkdir()
    os.rename(_chain(), aside / _chain().name)
    sign_approved(case)
    lines = [json.loads(x) for x in _chain().read_text().splitlines()]
    assert [x["item_id"] for x in lines] == [FINDING["id"], EVENT["id"], IOC["id"]]
    return case


def _two_approved(tmp_path, monkeypatch):
    """_signed_case's shape with two approved findings, both signed."""
    case = _signed_case(tmp_path, monkeypatch)
    second = dict(FINDING, id="F-tester-002", title="Second beacon",
                  observation=f"also beacons to {VALUE}")  # fmt: skip
    path = case / "findings.json"
    _writable(path)
    path.write_text(json.dumps([dict(FINDING, iocs=[]), second], indent=2))
    _writable(case / "iocs.json")
    (case / "iocs.json").write_text("[]")
    aside = tmp_path / "aside"
    aside.mkdir()
    os.rename(_chain(), aside / _chain().name)
    sign_approved(case)
    return case


def _never_signed(tmp_path, monkeypatch):
    """_signed_case's files, never signed: no chain and no key for the case."""
    case = tmp_path / CASE
    for name in ("reports", "audit"):
        (case / name).mkdir(parents=True)
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    meta = {"case_id": CASE, "name": "Refuse", "status": "open",
            "created": "2026-10-08T00:00:00Z", "examiner": "tester"}  # fmt: skip
    (case / "CASE.yaml").write_text(yaml.dump(meta))
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    (case / "todos.json").write_text("[]")
    (case / "timeline.json").write_text(json.dumps([EVENT]))
    (case / "findings.json").write_text(json.dumps([FINDING]))
    (case / "iocs.json").write_text(json.dumps([IOC]))
    assert not ledger.chain_path(CASE).exists(), ledger.chain_path(CASE)
    return case


def cb_middle(case):
    _edit_line(1, lambda o: o.update(mode=o["mode"] + "x"))


def ccd(case):
    lines = _chain().read_text().splitlines()
    cid = ledger.chain_id(ledger.body_of(json.loads(lines[0])))
    obj = json.loads(lines[2])
    obj["at"] = "2026-10-08T10:00:01+00:00"
    lines[2] = ledger.sign_body(ledger.body_of(obj), _key(case))
    copies = case / "ledger" / "chains"
    copies.mkdir(parents=True, exist_ok=True)
    _put_lines(copies / f"{cid}.jsonl", lines)


def dup_same_file(case):
    _rewrite(case / "findings.json", lambda d: d + [dict(d[0])])


def item_missing(name):
    def change(case):
        _writable(case / name)
        (case / name).write_text("[]")

    return change


def key_second(case):
    ev = json.loads((case / "timeline.json").read_text())[0]
    key = Ed25519PrivateKey.generate()
    pub = keys.b64(keys.public_raw(key))
    d = [{"item_id": ev["id"], "type": "timeline", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(ev, "timeline")}]  # fmt: skip
    bodies = ledger.prepare(CASE, [with_checks(x) for x in d], "tester", pub, "cli",
                            ev.get("approved_at") or AT)  # fmt: skip
    with ledger.case_lock(CASE) as lock:
        ledger.commit(lock, bodies, [ledger.sign_body(b, key) for b in bodies], pub)


def ledger_gone(case):
    aside = case.parent / "aside"
    aside.mkdir()
    os.rename(_chain(), aside / _chain().name)


def mal_noid(case):
    _rewrite(case / "findings.json",
             lambda d: d + [{"status": "APPROVED", "title": "no id", "observation": "o"}])  # fmt: skip


def unparseable(case):
    lines = _chain().read_text().splitlines()
    _put_lines(_chain(), lines[:2] + ["{not json"])


def tampered_line(case):
    _sign(case, _key(case), "finding", _record(case, "findings.json", FINDING["id"]))
    _edit_line(0, _flip)


def draft_dup(case):
    _rewrite(case / "findings.json", lambda d: d + [dict(d[0])])


def draft_mal_noid(case):
    _rewrite(case / "findings.json",
             lambda d: d + [{"status": "APPROVED", "title": "no id"}])  # fmt: skip


def tamper_second(case):
    def change(d):
        assert [x["id"] for x in d] == ["F-tester-001", "F-tester-002"], d
        d[1]["observation"] += " (altered after approval)"
        return d

    _rewrite(case / "findings.json", change)


def tamper_single(case):
    def change(d):
        d[0]["observation"] += " (altered after approval)"
        return d

    _rewrite(case / "findings.json", change)


def body_last(case):
    _edit_line(2, lambda o: o.update(mode=o["mode"] + "x"))


def sig_middle(case):
    _edit_line(1, _flip)


def no_line(case):
    _rewrite(case / "findings.json",
             lambda d: d + [dict(d[0], id="F-tester-009", title="Unsigned")])  # fmt: skip


BUILD = {"signed": _signed_case, "resigned": _resigned, "draft": _draft_case,
         "two": _two_approved, "never_signed": _never_signed}  # fmt: skip
CASE_LEVEL = {  # cell: (how the case is built, the change, the codes verify emits)
    "CB_middle": ("resigned", cb_middle, ["CHAIN_BROKEN"]),
    "CCD": ("resigned", ccd, ["CHAIN_COPY_DIVERGED"]),
    "DUP_same_file": ("signed", dup_same_file, ["DUPLICATE_ID"]),
    "ITEM_MISSING_ioc": ("signed", item_missing("iocs.json"), ["ITEM_MISSING"]),
    "ITEM_MISSING_event": ("signed", item_missing("timeline.json"), ["ITEM_MISSING"]),
    "ITEM_MISSING_findings": ("resigned", item_missing("findings.json"),
                              ["ITEM_MISSING"]),
    "KEY_second_key": ("signed", key_second, ["KEY_CHANGED"]),
    "LEDGER_gone": ("signed", ledger_gone, ["LEDGER_MISSING"]),
    "LEDGER_never": ("never_signed", lambda case: None, ["LEDGER_MISSING"]),
    "MAL_noid": ("signed", mal_noid, ["MALFORMED_RECORD"]),
    "UNPARSEABLE": ("resigned", unparseable, ["UNPARSEABLE_LINE"]),
    "TAMPERED_LINE": ("resigned", tampered_line, ["TAMPERED_LINE"]),
    "DRAFT_DUP": ("draft", draft_dup, ["DUPLICATE_ID"]),
    "DRAFT_MAL_noid": ("draft", draft_mal_noid, ["MALFORMED_RECORD"]),
}  # fmt: skip
ITEM_LEVEL = {  # cell: (build, change, not verified, shown findings, events, IOCs)
    "TAMPER_one_of_two": ("two", tamper_second,
                          [("F-tester-002", "ALTERED_AFTER_APPROVAL")],
                          ["F-tester-001"], ["T-tester-001"], []),
    "BODY_last": ("resigned", body_last, [("IOC-tester-001", "TAMPERED")],
                  ["F-tester-001"], ["T-tester-001"], []),
    "SIG_middle": ("resigned", sig_middle, [("T-tester-001", "TAMPERED")],
                   ["F-tester-001"], [], ["IOC-tester-001"]),
    "NO_LINE": ("resigned", no_line, [("F-tester-009", "APPROVED_NO_LINE")],
                ["F-tester-001"], ["T-tester-001"], ["IOC-tester-001"]),
    "TAMPER_single": ("signed", tamper_single,  # fixture (iii)
                      [("F-tester-001", "ALTERED_AFTER_APPROVAL")],
                      [], ["T-tester-001"], ["IOC-tester-001"]),
}  # fmt: skip
TITLES = {"F-tester-001": FINDING["title"], "F-tester-002": "Second beacon"}


def _fixture(build, change, tmp_path, monkeypatch):
    """The case built and changed, with an open todo and a prior report under
    each mode's name."""
    case = BUILD[build](tmp_path, monkeypatch)
    change(case)
    _writable(case / "todos.json")
    (case / "todos.json").write_text(json.dumps([TODO]))
    for mode in MODES:
        (case / "reports" / f"{mode}.txt").write_bytes(PRIOR)
    return case


# --- running a report -------------------------------------------------------
def _listing(case):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((case / "reports").iterdir())}  # fmt: skip


def _run(case, mode, save, **kw):
    """How `vhir report` in `mode` ended, its streams, reports/ before and
    after, and the saved text (None when the name holds the prior report)."""
    before = _listing(case)
    out, err, rc, raised = io.StringIO(), io.StringIO(), 0, None
    name = f"{mode}.txt"
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rep.cmd_report(_args(mode, save=name if save else None, **kw), IDENTITY)
        except SystemExit as e:
            rc = e.code
        except Exception as e:  # noqa: BLE001  (shown in the assertion's message)
            raised = "".join(traceback.format_exception(type(e), e, e.__traceback__))
    saved = (case / "reports" / name).read_bytes()
    return {"rc": rc, "raised": raised, "out": out.getvalue(), "err": err.getvalue(),
            "before": before, "after": _listing(case),
            "saved": None if saved == PRIOR else saved.decode()}  # fmt: skip


def _texts(res):
    """Each stream, and the saved text if one was written."""
    texts = {"out": res["out"], "err": res["err"]}
    if res["saved"] is not None:
        texts["saved"] = res["saved"]
    return texts


def _ran(res, mode, save):
    """No header, no traceback, rc 0; --save writes, and the display doesn't."""
    assert res["raised"] is None, res["raised"]
    for where, text in _texts(res).items():
        assert "Traceback" not in text, (where, text[-800:])
        assert "unreadable (see above)" not in text, (where, text[-800:])
        header = [x for x in text.splitlines() if x.startswith(HEADER_FILES)]
        assert header == [], (where, header)
    assert "Report not saved:" not in res["err"], res["err"]
    assert res["rc"] == 0, (res["rc"], res["err"][-400:])
    if save:
        assert res["saved"] is not None, "--save didn't write"
    else:
        assert res["after"] == res["before"], "reports/ changed without --save"


def _json(out):
    """stdout is the JSON --full prints, and nothing else."""
    return json.loads(out)


def _withheld_lines(text):
    return [x for x in text.splitlines() if x.endswith(f": {W}")]


# --- fixture (i): the view is blanked ---------------------------------------
def _measured_case_level(case, codes):
    result = verify_case(case)
    assert sorted({c for c, _ in result.failures}) == codes, result.failures
    view = approved_view(case)
    assert [view[k] for k in ("findings", "timeline", "iocs")] == [[], [], []]


@pytest.mark.parametrize("save", [False, True], ids=["display", "save"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cell", sorted(CASE_LEVEL))
def test_a_blanked_view_prints_withheld(tmp_path, monkeypatch, cell, mode, save):
    build, change, codes = CASE_LEVEL[cell]
    case = _fixture(build, change, tmp_path, monkeypatch)
    _measured_case_level(case, codes)
    res = _run(case, mode, save)
    if cell == "ITEM_MISSING_findings" and mode == "findings":
        # the lookup miss on an empty findings.json, as at head
        assert res["raised"] is None, res["raised"]
        assert (res["rc"], res["out"]) == (1, ""), (res["rc"], res["out"][-400:])
        assert res["err"].splitlines() == ["Not found: F-tester-001",
                                           "No matching findings."], res["err"]  # fmt: skip
        assert res["after"] == res["before"], "reports/ changed"
        return
    _ran(res, mode, save)
    if mode == "full":
        for where, text in _texts(res).items():
            assert _withheld_lines(text) == [], (where, _withheld_lines(text))
        assert _json(res["out"]).get("approved_view_withheld") is True
        if save:
            assert json.loads(res["saved"]).get("approved_view_withheld") is True
        return
    expected = WITHHELD_LINES[mode]
    assert _withheld_lines(res["err"]) == [], res["err"]
    for where in ("out", "saved") if save else ("out",):
        text = res[where]
        assert sorted(_withheld_lines(text)) == sorted(expected), (where, text[-1500:])
        for line in expected:
            assert text.splitlines().count(line) == 1, (where, line)
        for empty in EMPTY_FORMS:
            assert empty not in text, (where, empty, text[-1500:])


@pytest.mark.parametrize("mode", TEXT)
@pytest.mark.parametrize("cell", sorted(CASE_LEVEL))
def test_a_failing_case_saves_its_iocs_defanged(tmp_path, monkeypatch, cell, mode):
    """VALUE is an IOC record's value and is named in the finding and the
    event. The saved text holds it defanged only."""
    if cell == "ITEM_MISSING_ioc":
        pytest.skip("its iocs.json is []: no record holds VALUE, only text names it")
    if cell == "ITEM_MISSING_findings" and mode == "findings":
        pytest.skip("the lookup miss saves nothing (the withheld test asserts it)")
    build, change, codes = CASE_LEVEL[cell]
    case = _fixture(build, change, tmp_path, monkeypatch)
    _measured_case_level(case, codes)
    res = _run(case, mode, True)
    _ran(res, mode, True)
    assert res["saved"].count(VALUE) == 0, res["saved"][-1500:]
    if mode == "findings":  # control: the report prints the value
        assert DEFANGED in res["saved"], res["saved"][-1500:]


# --- fixtures (ii) and (iii): an item drops, the view isn't blanked ---------
@pytest.mark.parametrize("save", [False, True], ids=["display", "save"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cell", sorted(ITEM_LEVEL))
def test_an_item_level_failure_prints_no_withheld(
    tmp_path, monkeypatch, cell, mode, save
):
    build, change, dropped, shown_f, shown_t, shown_i = ITEM_LEVEL[cell]
    case = _fixture(build, change, tmp_path, monkeypatch)
    assert verify_case(case).failures == []
    view = approved_view(case)
    assert [(x.get("id"), x["status"]) for x in view["not_verified"]] == dropped
    shown = [[i["id"] for i in view[k]] for k in ("findings", "timeline", "iocs")]
    assert shown == [shown_f, shown_t, shown_i], shown
    res = _run(case, mode, save)
    _ran(res, mode, save)
    for where, text in _texts(res).items():
        assert _withheld_lines(text) == [], (where, _withheld_lines(text))
    if mode == "full":
        body = _json(res["out"])
        assert "approved_view_withheld" not in body, sorted(body)
        got = [[i["id"] for i in body[k]]
               for k in ("approved_findings", "approved_timeline", "approved_iocs")]  # fmt: skip
        assert got == [shown_f, shown_t, shown_i], got
        return
    for where in ("out", "saved") if save else ("out",):
        lines = res[where].splitlines()
        for fid in shown_f:  # PROVENANCE names each verified finding
            assert f"[{fid}] {TITLES[fid]}" in lines, (where, fid)
        for fid, _ in dropped:
            assert not [x for x in lines if x.startswith(f"[{fid}]")], (where, fid)
        assert ("No approved, verified findings." in lines) == (not shown_f), where
        if mode == "executive_summary":
            counted = (f"Approved (verified): {len(shown_f)} findings, "
                       f"{len(shown_t)} timeline events; not verified: {len(dropped)}")  # fmt: skip
            assert counted in lines, (where, res[where][-1500:])
        if mode == "ioc":
            none = "  Approved IOC records: none"
            assert (none in lines) == (not shown_i), (where, res[where][-1500:])


# --- a value only verify's read holds ---------------------------------------
# held only by verify's read, in a record the view leaves out
C_ONLY = "c-only.example.net"
STATES = {  # state: (the record verify reads, what's signed for it, its expected status)
    "altered": (dict(IOC, id="IOC-tester-003", value=C_ONLY, approved_at=AT),
                dict(IOC, id="IOC-tester-003", value="c-old.example.net", approved_at=AT),
                "ALTERED_AFTER_APPROVAL"),
    "draft": ({k: v for k, v in dict(IOC, id="IOC-tester-003", value=C_ONLY,
                                     status="DRAFT").items()
               if k not in ("manually_reviewed", "approved_by", "approved_at")},
              None, "DRAFT"),
}  # fmt: skip


@pytest.mark.parametrize("state", sorted(STATES))
@pytest.mark.parametrize("mode", TEXT)
def test_a_value_only_verify_read_holds_is_defanged(tmp_path, monkeypatch, mode, state):
    """verify's read of iocs.json holds a signed IOC record of B_ONLY, and
    IOC-tester-003 of C_ONLY, that the file on disk doesn't (the state an edit
    between two reads leaves). IOC-tester-003 is in verify's records but not
    in the approved view: APPROVED and edited after signing, or DRAFT. The
    finding F-tester-002 names B_ONLY in its text and C_ONLY in its title,
    which every saved report's PROVENANCE prints. The saved text holds each
    defanged only, on every route."""
    third, signed, status = STATES[state]
    case = _signed_case(tmp_path, monkeypatch)
    second = dict(FINDING, id="F-tester-002", title=f"Second beacon to {C_ONLY}",
                  observation=f"beacons to {B_ONLY}", approved_by="tester",
                  approved_at=AT)  # fmt: skip
    _sign(case, _key(case), "finding", second)
    _rewrite(case / "findings.json", lambda d: d + [second])
    # approved_at as `_sign` signs it, or verify calls the record altered
    rec = dict(IOC, id="IOC-tester-002", value=B_ONLY, source_findings=[second["id"]],
               approved_at=AT)  # fmt: skip
    _sign(case, _key(case), "ioc", rec)
    if signed is not None:
        _sign(case, _key(case), "ioc", signed)
    verify_sees = json.dumps([IOC, rec, third]).encode()
    on_disk = (case / "iocs.json").read_text()
    assert B_ONLY not in on_disk and C_ONLY not in on_disk, on_disk
    real, hits = case_io.read_case_document, []

    def patched(path, *a, **kw):
        if sys._getframe(1).f_code.co_name == "_items" and path.name == "iocs.json":
            hits.append(path)
            return verify_sees
        return real(path, *a, **kw)

    monkeypatch.setattr(case_io, "read_case_document", patched)
    view = approved_view(case)
    result = view["result"]
    assert hits, "verify's read wasn't patched"
    assert result.failures == [], result.failures
    assert [i["id"] for i in view["iocs"]] == [IOC["id"], rec["id"]]
    # precondition: in verify's records, out of the view, with its own status
    read = [i for k, i in result.records if k == "iocs" and i.get("id") == third["id"]]
    assert read == [third], result.records
    assert C_ONLY not in [i.get("value") for i in view["iocs"]], view["iocs"]
    nv = [x["status"] for x in view["not_verified"] if x.get("id") == third["id"]]
    if status == "DRAFT":  # the view skips a record that isn't APPROVED
        assert (third["status"], nv) == ("DRAFT", []), view["not_verified"]
    else:
        assert nv == [status], view["not_verified"]
    kw = {"report_findings": second["id"]} if mode == "findings" else {}
    res = _run(case, mode, True, **kw)
    _ran(res, mode, True)
    assert res["saved"].count(B_ONLY) == 0, res["saved"][-1500:]
    assert res["saved"].count(C_ONLY) == 0, res["saved"][-1500:]
    # control: PROVENANCE prints the title, so C_ONLY is in every saved text
    title = f"[{second['id']}] Second beacon to {C_ONLY.replace('.', '[.]')}"
    assert title in res["saved"].splitlines(), res["saved"][-1500:]
    if mode in ("findings", "ioc"):  # control: the report prints B_ONLY
        assert B_ONLY.replace(".", "[.]") in res["saved"], res["saved"][-1500:]
