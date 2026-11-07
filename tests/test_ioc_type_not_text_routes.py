"""An IOC type that isn't text (None, 5, a list) or is empty raises nothing on
any route that reads IOC types: `vhir report --ioc`, `--executive-summary`
and `--full` with --save on a DRAFT record, an approved record and an approved
finding's own iocs; `vhir approve` of a finding citing a DRAFT record (the
cascade); `vhir review --findings --verify` and `vhir review --iocs` on the
cascade case; and `vhir report --timeline`, `--findings` and `--status-brief`
with --save on it. Each route exits 0 with no Traceback, as it does today.
A list type holding a network type (["domain-name"]) is network: a saved text
report holds its value defanged, never live (--full saves JSON, live by
design). An empty type gives the same outcome as no type."""

from __future__ import annotations

import json
import sys
import traceback

import pytest

from vhir_cli import approval_auth, ioc_types, ledger

from .signing import PASSPHRASE, enrol

F, IOC = "F-steve-001", "IOC-steve-001"
EVENT = {"id": "T-steve-001", "status": "DRAFT", "timestamp": "2026-10-08T09:00:00Z",
         "description": "Beacon seen"}  # fmt: skip
TYPES = {"None": None, "5": 5, "list-domain-name": ["domain-name"]}
REPORTS = {"ioc": "--ioc", "exec": "--executive-summary", "full": "--full"}
CASCADE = {
    "approve": ("approve", F),
    "verify": ("review", "--findings", "--verify"),
    "review-iocs": ("review", "--iocs"),
    "timeline": ("report", "--timeline", "--save", "r7.txt"),
    "findings": ("report", "--findings", F, "--save", "r7.txt"),
    "status-brief": ("report", "--status-brief", "--save", "r7.txt"),
}
# routes whose saved text report shows the value: the 5a rows assert it there first
SHOWN = {("ioc", "rec-approved"), ("ioc", "list-approved"), ("findings", "cascade")}


def _guarded(t):
    """Today's canonical, used only while a fixture is built, so a tree with
    its type check removed gets the same case."""
    return ioc_types._BY_FOLD.get(ioc_types._fold(t)) if isinstance(t, str) else None


def _case(root, monkeypatch, case_id, finding_iocs, records, timeline=()):
    d = root / case_id
    d.mkdir()
    for name in ("reports", "audit"):
        (d / name).mkdir()
    (d / "CASE.yaml").write_text(
        f"case_id: {case_id}\nname: Types\nstatus: open\nexaminer: steve\n"
    )
    f = {"id": F, "title": "Beacon", "observation": "o", "interpretation": "i",
         "confidence": "LOW", "status": "DRAFT", "iocs": finding_iocs}  # fmt: skip
    (d / "findings.json").write_text(json.dumps([f]))
    (d / "timeline.json").write_text(json.dumps(list(timeline)))
    (d / "todos.json").write_text("[]")
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    (d / "iocs.json").write_text(json.dumps(records))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "steve")
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", root / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    enrol("steve")
    return d


def _record(t, v):
    return {"id": IOC, "value": v, "type": t, "category": "network", "description": "",
            "status": "DRAFT", "source_findings": [F], "manually_reviewed": False,
            "tags": [], "mitre_techniques": []}  # fmt: skip


def _vhir(monkeypatch, capsys, *argv) -> dict:
    from vhir_cli.main import main

    monkeypatch.setattr("builtins.input", lambda p="": "")
    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    raised = None
    try:
        main()
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:  # noqa: BLE001  (shown in the assertion's message)
        rc = "raised"
        raised = (
            f"{type(e).__name__}: {e} at {traceback.extract_tb(e.__traceback__)[-1]}"
        )
    out = capsys.readouterr()
    return {"rc": rc, "raised": raised, "text": out.out + out.err, "stdout": out.out}


def _signed(case_id):
    return [[o["item_id"], o["decision"], o.get("coupled_from")]
            for _, _, o in ledger.read_lines(ledger.chain_path(case_id)) if o]  # fmt: skip


def _status(d, name, item_id):
    return {x["id"]: x for x in json.loads((d / name).read_text())}.get(
        item_id, {}
    ).get("status")


def _approve_built(monkeypatch, capsys, *ids):
    with monkeypatch.context() as m:
        m.setattr(ioc_types, "canonical", _guarded)
        b = _vhir(monkeypatch, capsys, "approve", *ids)
    if b["rc"] != 0 or b["raised"]:
        pytest.fail(f"fixture: approve {ids} rc {b['rc']} {b['raised']}")


def _run(root, monkeypatch, capsys, case_id, route, fixture, t, v) -> dict:
    """Build the fixture, run the route; its outcome."""
    if fixture == "list-approved":
        d = _case(root, monkeypatch, case_id, [{"value": v, "type": t}], [])
        _approve_built(monkeypatch, capsys, F)
    elif fixture in ("rec-draft", "rec-approved"):
        d = _case(
            root, monkeypatch, case_id, [], [dict(_record(t, v), source_findings=[])]
        )
        if fixture == "rec-approved":
            _approve_built(monkeypatch, capsys, IOC)
    else:  # the cascade: the finding cites the value, a DRAFT record holds it
        # `report --timeline` saves only a case with an event: the timeline route gets
        # one, approved (signed) with the finding
        events = [EVENT] if route == "timeline" else []
        d = _case(
            root, monkeypatch, case_id, [{"value": v, "type": t}], [_record(t, v)],
            events,
        )  # fmt: skip
        if route != "approve":
            _approve_built(monkeypatch, capsys, F, *(e["id"] for e in events))
            if [IOC, "approve", F] not in _signed(case_id):
                pytest.fail(f"fixture: no cascade line in {_signed(case_id)}")
            for e in events:
                if _status(d, "timeline.json", e["id"]) != "APPROVED":
                    pytest.fail(f"fixture: {e['id']} isn't approved")
    argv = (
        ("report", REPORTS[route], "--save", "r7.txt")
        if route in REPORTS
        else CASCADE[route]
    )
    res = _vhir(monkeypatch, capsys, *argv)
    saved = d / "reports" / "r7.txt"
    res["saved"] = saved.read_text() if saved.exists() else None
    res["saves"] = "--save" in argv
    if route == "approve":
        res["cascade"] = (
            _signed(case_id),
            _status(d, "findings.json", F),
            _status(d, "iocs.json", IOC),
        )
    if route == "verify":
        res["cascade_unsupported"] = "CASCADE_UNSUPPORTED" in res["text"]
    return res


def _ran_clean(res):
    assert res["raised"] is None, f"raised {res['raised']}"
    assert "Traceback" not in res["text"], res["text"][-800:]
    assert res["rc"] == 0, f"rc {res['rc']}: {res['text'][-400:]}"
    if res["saves"]:
        assert res["saved"] is not None, "the report wasn't saved"


ROUTES = [
    (r, fx) for r in REPORTS for fx in ("rec-draft", "rec-approved", "list-approved")
]
ROUTES += [(r, "cascade") for r in CASCADE]


@pytest.mark.parametrize("route,fixture", ROUTES, ids=lambda x: str(x))
@pytest.mark.parametrize("tname", list(TYPES))
def test_route_raises_nothing(tmp_path, monkeypatch, capsys, tname, route, fixture):
    t, v = TYPES[tname], f"t7-{tname}.example.com"
    res = _run(tmp_path, monkeypatch, capsys, "C-9", route, fixture, t, v)
    _ran_clean(res)
    if route == "approve":
        signed, finding, ioc = res["cascade"]
        assert [F, "approve", None] in signed and [IOC, "approve", F] in signed, signed
        assert (finding, ioc) == ("APPROVED", "APPROVED")
    if route == "verify":
        assert not res["cascade_unsupported"], res["text"][-800:]
    if tname == "list-domain-name" and res["saves"] and route != "full":
        body = res["saved"]
        if (route, fixture) in SHOWN:
            assert v in body or v.replace(".", "[.]") in body, (
                "the value isn't in the saved report"
            )
        assert v not in body, f"{v} is live in the saved report"


@pytest.mark.parametrize("route,fixture", ROUTES, ids=lambda x: str(x))
def test_an_empty_type_is_no_type(tmp_path, monkeypatch, capsys, route, fixture):
    v = "t7-twin.example.com"
    got = {}
    for name, t in (("empty", ""), ("none", None)):
        root = tmp_path / name
        root.mkdir()
        got[name] = _run(root, monkeypatch, capsys, f"C-9{name}", route, fixture, t, v)
    _ran_clean(got["none"])
    _ran_clean(got["empty"])

    def outcome(r):
        body = r["saved"] or ""
        return {"rc": r["rc"], "saved": r["saved"] is not None, "live": body.count(v),
                "defanged": body.count(v.replace(".", "[.]")), "shown": r["stdout"].count(v),
                "cascade": r.get("cascade", (None,))[1:], "unsupported": r.get("cascade_unsupported")}  # fmt: skip

    assert outcome(got["empty"]) == outcome(got["none"])
