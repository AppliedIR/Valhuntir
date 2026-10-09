"""The checks an approval runs before it is signed, and the v4 line that
signs them.

The case is the 7z example: `mem.7z` registered by the AI, `7z x` extracts
`sample2.raw`, vol reads sample 2, and a draft finding cites vol with the
chain from the 7z (each link with its audit line's SHA-256). Approvals go
through each CLI path with the passphrase and the terminal answer patched.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import sys
import types
from pathlib import Path

import pytest
import yaml

from vhir_cli import approval_auth, approval_checks, keys, ledger
from vhir_cli.case_io import compute_content_hash, load_findings, signed_text
from vhir_cli.commands import approve as A
from vhir_cli.commands.evidence import register_evidence_data
from vhir_cli.ledger_verify import approved_view, verification_block, verify_case

from . import signing
from .signing import PASSPHRASE, enrol

CASE_ID = "INC-2610"
FID = "F-analyst1-001"
IDENT = {"examiner": "analyst1", "os_user": "rig", "analyst": "analyst1"}
REASON = "Checked by hand: the 7z was re-copied from the original media"


def sha(b: bytes | str) -> str:
    return hashlib.sha256(b.encode() if isinstance(b, str) else b).hexdigest()


def _line(**fields) -> str:
    base = {"mcp": "sift-mcp", "tool": "run_command", "examiner": "analyst1",
            "case_id": CASE_ID}  # fmt: skip
    return json.dumps({**base, **fields})


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = Path(os.path.realpath(tmp_path)) / CASE_ID
    for sub in ("evidence", "extractions", "audit"):
        (d / sub).mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": CASE_ID, "status": "open"}))
    (d / "timeline.json").write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "analyst1")
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)

    z = d / "evidence" / "mem.7z"
    z.write_bytes(b"7z archive bytes " * 100)
    zsha = register_evidence_data(d, str(z), "analyst1", registered_via="mcp")["sha256"]
    s2 = d / "extractions" / "sift-analyst1-001" / "sample2.raw"
    s2.parent.mkdir(parents=True)
    s2.write_bytes(b"memory sample 2 " * 50)
    out = d / "extractions" / "sift-analyst1-002" / "pslist.txt"
    out.parent.mkdir(parents=True)
    out.write_text("PID 4242 evil.exe\n")
    s2sha, outsha = sha(s2.read_bytes()), sha(out.read_bytes())
    x_line = _line(ts="2026-10-09T00:00:00Z", audit_id="sift-analyst1-001",
                   params={"command": f"7z x {z} -o{s2.parent}"})  # fmt: skip
    run_line = _line(ts="2026-10-09T00:00:10Z", audit_id="sift-analyst1-002",
                     params={"command": f"vol -f {s2} windows.pslist"})  # fmt: skip
    (d / "audit" / "sift-mcp.jsonl").write_text(x_line + "\n" + run_line + "\n")

    finding = {
        "id": FID, "status": "DRAFT", "title": "evil.exe ran",
        "observation": "PID 4242 evil.exe", "interpretation": "suspicious",
        "confidence": "MEDIUM", "type": "finding", "created_by": "analyst1",
        "examiner": "analyst1", "audit_ids": ["sift-analyst1-002"],
        "provenance": "MCP", "provenance_grade": "FULL", "provenance_schema": 2,
        "source_evidence": str(z),
        "artifacts": [{
            "source": "pslist", "extraction": "vol pslist", "content": "PID 4242 evil.exe",
            "audit_id": "sift-analyst1-002", "provenance_grade": "FULL",
            "provenance_reason": "",
            "provenance_root": {"path": str(z), "sha256": zsha, "label": "AI-registered"},
            "provenance_chain": [
                {"method": "registered-path", "audit_id": "sift-analyst1-001",
                 "entry_sha256": sha(x_line), "from": {"path": str(z), "sha256": zsha},
                 "to": {"path": str(s2), "sha256": s2sha}},
                {"method": "hash+place", "audit_id": "sift-analyst1-002",
                 "entry_sha256": sha(run_line), "from": {"path": str(s2), "sha256": s2sha},
                 "to": {"path": str(out), "sha256": outsha}},
            ],
        }],
    }  # fmt: skip
    _save(d, finding)
    enrol("analyst1")
    return d


def _finding(d: Path) -> dict:
    return json.loads((d / "findings.json").read_text())[0]


def _save(d: Path, finding: dict) -> None:
    finding["content_hash"] = compute_content_hash(finding)
    p = d / "findings.json"
    if p.exists():
        p.chmod(0o644)
    p.write_text(json.dumps([finding], indent=2))


def change_root(d: Path) -> None:
    with open(d / "evidence" / "mem.7z", "ab") as f:
        f.write(b"tampered")


def status(d: Path) -> str:
    return load_findings(d)[0]["status"]


def last_line() -> dict:
    return ledger.read_lines(ledger.chain_path(CASE_ID))[-1][2]


def verdict(d: Path, item_id: str = FID):
    r = verify_case(d)
    return next((v.status for v in r.items if v.item_id == item_id), None), r


ROUTES = ["ids", "interactive", "review"]


def run(route, d, capsys, monkeypatch, reason: str | None = ""):
    """Approve the finding through one CLI path, the terminal answering
    `reason` (None: no terminal). Returns (what was printed before the
    passphrase, everything printed)."""
    seen = []

    def typed(prompt=""):
        seen.append(capsys.readouterr().out)
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", typed)
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda prompt="": reason)
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    cfg = d.parent / "config.yaml"
    try:
        if route == "ids":
            A._approve_specific(d, [FID], IDENT, cfg)
        elif route == "interactive":
            A._interactive_review(d, IDENT, cfg)
        else:
            (d / "pending-reviews.json").write_text(json.dumps({"case_id": CASE_ID, "items": [
                {"id": FID, "type": "finding", "action": "approve", "staged_by": "analyst1"}
            ]}))  # fmt: skip
            A._review_mode(d, IDENT, cfg)
    except SystemExit:
        pass
    rest = capsys.readouterr()
    before = seen[0] if seen else ""
    return before, "".join(seen) + rest.out + rest.err


# --- The line: v4, view 2 ------------------------------------------------------


def _sign_v3(d: Path, monkeypatch) -> None:
    """The finding approved and signed as 0.6.4's predecessor signed it: a v3,
    view 1 line with no checks."""
    f = _finding(d)
    f.update(status="APPROVED", approved_by="analyst1", approved_at=signing.AT)
    _save(d, f)
    key = signing._KEYS.setdefault(
        (str(d), "old"), signing.Ed25519PrivateKey.generate()
    )
    pub = keys.b64(keys.public_raw(key))
    with monkeypatch.context() as m:
        m.setattr(ledger, "VERSION", 3)
        m.setattr(ledger, "VIEW", 1)
        (body,) = ledger.prepare(
            CASE_ID, [_v3_decision(f)], "analyst1", pub, "cli", signing.AT
        )
    del body["checks"]
    with ledger.case_lock(CASE_ID) as lock:
        ledger.commit(lock, [body], [ledger.sign_body(body, key)], pub)


def _v3_decision(f: dict) -> dict:
    return {"item_id": FID, "type": "finding", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(f, "finding", view=1),
          "checks": signing.NOT_CHECKED}  # fmt: skip


def test_a_chain_of_v3_lines_still_verifies(case, monkeypatch):
    _sign_v3(case, monkeypatch)
    o = last_line()
    assert (o["v"], o["view"], "checks" in o) == (3, 1, False)
    v, r = verdict(case)
    assert v == "VALID", r.failures


def _second_finding(d: Path) -> None:
    fs = json.loads((d / "findings.json").read_text())
    f2 = copy.deepcopy(fs[0])
    f2.update(id="F-analyst1-002", status="DRAFT")
    for k in ("approved_by", "approved_at"):
        f2.pop(k, None)
    f2["content_hash"] = compute_content_hash(f2)
    (d / "findings.json").chmod(0o644)
    (d / "findings.json").write_text(json.dumps(fs + [f2], indent=2))


def test_a_v4_line_after_v3_lines_verifies_with_both(case, monkeypatch):
    _sign_v3(case, monkeypatch)
    _second_finding(case)
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda p="": "")
    A._approve_specific(case, ["F-analyst1-002"], IDENT, case.parent / "c.yaml")
    lines = [o for _, _, o in ledger.read_lines(ledger.chain_path(CASE_ID))]
    assert [(o["v"], o["view"]) for o in lines] == [(3, 1), (4, 2)]
    r = verify_case(case)
    got = {v.item_id: v.status for v in r.items}
    assert got == {FID: "VALID", "F-analyst1-002": "VALID"}, r.failures


def test_a_new_approval_line_is_v4_view_2_and_carries_its_checks(
    case, capsys, monkeypatch
):
    run("ids", case, capsys, monkeypatch)
    o = last_line()
    assert (o["v"], o["view"]) == (4, 2)
    assert o["checks"]["result"] == "ok" and "approval_override_reason" not in o
    assert [(i["check"], i["status"]) for i in o["checks"]["items"]] == [
        ("ENTRY", "ok"), ("ENTRY", "ok"), ("ROOT", "ok"),
    ]  # fmt: skip


@pytest.mark.parametrize("field,value", [
    ("source_evidence", "/elsewhere/other.raw"),
    ("provenance", "SHELL"),
    ("examiner_modifications", {"interpretation": {"original": "x", "modified": "y"}}),
    ("artifacts", []),
])  # fmt: skip
def test_view_2_signs_the_provenance_fields(case, capsys, monkeypatch, field, value):
    run("ids", case, capsys, monkeypatch)
    assert status(case) == "APPROVED"
    f = _finding(case)
    f[field] = value
    (case / "findings.json").chmod(0o644)
    (case / "findings.json").write_text(json.dumps([f]))
    v, _ = verdict(case)
    assert v == "ALTERED_AFTER_APPROVAL", field


def _line_with(case, monkeypatch, **fields) -> None:
    """A signed v4 approval line of the finding, its body with `fields`."""
    f = _finding(case)
    f.update(status="APPROVED", approved_by="analyst1", approved_at=signing.AT)
    _save(case, f)
    key = signing._KEYS.setdefault(
        (str(case), "lines"), signing.Ed25519PrivateKey.generate()
    )
    pub = keys.b64(keys.public_raw(key))
    d0 = {"item_id": FID, "type": "finding", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(f, "finding"), "checks": signing.NOT_CHECKED}  # fmt: skip
    (body,) = ledger.prepare(CASE_ID, [d0], "analyst1", pub, "cli", signing.AT)
    body.update(fields)
    with ledger.case_lock(CASE_ID) as lock:
        ledger.commit(lock, [body], [ledger.sign_body(body, key)], pub)


@pytest.mark.parametrize("field,value", [
    ("checks", "failed"),
    ("checks", {"result": "not-applicable", "detail": 7, "items": []}),
    ("approval_override_reason", 12),
])  # fmt: skip
def test_a_line_with_checks_or_a_reason_of_the_wrong_type_is_malformed(
    case, monkeypatch, field, value
):
    _line_with(case, monkeypatch, **{field: value})
    r = verify_case(case)
    assert any(c == "MALFORMED_LINE" and repr(field) in m for c, m in r.failures)
    assert r.exit_code == 2


def _decision(**kw) -> dict:
    return {"item_id": FID, "type": "finding", "decision": "approve",
            "status_after": "APPROVED", "coupled_from": None,
            "content_snapshot": "{}", **kw}  # fmt: skip


FAILED = {"result": "failed", "items": [{"check": "ROOT", "status": "failed",
          "subject": "mem.7z", "detail": "changed", "code": "ROOT_CHANGED"}]}  # fmt: skip


@pytest.mark.parametrize("decision,match", [
    (_decision(checks=FAILED), "approval_override_reason"),
    (_decision(checks=FAILED, approval_override_reason="  "), "approval_override_reason"),
    (_decision(), "checks"),
    (_decision(checks={"result": "maybe", "items": []}), "checks"),
    (_decision(checks=signing.NOT_CHECKED, approval_override_reason=REASON),
     "approval_override_reason"),
    (_decision(decision="reject", status_after="REJECTED", checks=signing.NOT_CHECKED),
     "checks"),
    ({**_decision(checks=signing.NOT_CHECKED), "coupled_from": "F-analyst1-009"}, "checks"),
    ({**_decision(type="ioc"), "approval_override_reason": REASON},
     "approval_override_reason"),
])  # fmt: skip
def test_prepare_refuses_a_wrong_combination_naming_the_field(case, decision, match):
    pub = keys.b64(keys.public_raw(signing.Ed25519PrivateKey.generate()))
    with pytest.raises(ValueError, match=match):
        ledger.prepare(CASE_ID, [decision], "analyst1", pub, "cli", signing.AT)


def test_a_reattest_line_carries_no_checks(case, monkeypatch):
    from .signing import approve_under_0_6

    approve_under_0_6(case, {FID}, "analyst1", signing.AT)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    A._reattest(case, [FID], IDENT, case.parent / "c.yaml")
    o = last_line()
    assert o["decision"] == "reattest" and "checks" not in o
    assert "approval_override_reason" not in o


# --- The checks hold an approval, on every path ----------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_a_root_changed_since_registration_holds_the_approval(
    case, capsys, monkeypatch, route
):
    change_root(case)
    _, out = run(route, case, capsys, monkeypatch, reason="")
    assert status(case) == "DRAFT" and "ROOT_CHANGED" in out
    assert not ledger.chain_path(CASE_ID).exists() or not ledger.read_lines(
        ledger.chain_path(CASE_ID)
    )


@pytest.mark.parametrize("route", ROUTES)
def test_without_a_terminal_a_failed_check_leaves_it_draft(
    case, capsys, monkeypatch, route
):
    change_root(case)
    _, out = run(route, case, capsys, monkeypatch, reason=None)
    assert status(case) == "DRAFT" and "left DRAFT" in out


@pytest.mark.parametrize("route", ROUTES)
def test_a_typed_reason_approves_and_is_signed_with_the_failed_check(
    case, capsys, monkeypatch, route
):
    change_root(case)
    run(route, case, capsys, monkeypatch, reason=REASON)
    o = last_line()
    assert status(case) == "APPROVED"
    assert o["approval_override_reason"] == REASON
    assert o["checks"]["result"] == "failed"
    assert approval_checks.failed_codes(o["checks"]) == ["ROOT_CHANGED"]
    v, r = verdict(case)
    assert (v, r.exit_code) == ("VALID", 0), r.failures
    item = next(i for i in r.items if i.item_id == FID)
    assert item.approval_override_reason == REASON
    assert item.label == f"approved with override: {REASON}"


def test_the_override_reason_is_printed_in_the_verification_block(
    case, capsys, monkeypatch
):
    change_root(case)
    run("ids", case, capsys, monkeypatch, reason=REASON)
    view = approved_view(case)
    assert view["overrides"] == {FID: REASON}
    assert view["checks"][FID]["result"] == "failed"
    text = "\n".join(verification_block(view))
    assert FID in text and REASON in text


def test_an_edited_audit_line_holds_the_approval(case, capsys, monkeypatch):
    p = case / "audit" / "sift-mcp.jsonl"
    p.write_text(p.read_text().replace("windows.pslist", "windows.psscan"))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ENTRY_CHANGED" in out


def test_a_missing_or_doubled_audit_line_holds_the_approval(case, capsys, monkeypatch):
    p = case / "audit" / "sift-mcp.jsonl"
    first, second = p.read_text().splitlines()
    p.write_text(second + "\n")
    (case / "audit" / "other.jsonl").write_text(second + "\n")
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT"
    assert "ENTRY_MISSING sift-analyst1-001" in out
    assert "ENTRY_DUPLICATE sift-analyst1-002" in out


def test_a_root_registered_again_with_another_hash_holds_the_approval(
    case, capsys, monkeypatch
):
    change_root(case)
    register_evidence_data(case, str(case / "evidence" / "mem.7z"), "analyst1",
                           force_reregister=True)  # fmt: skip
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ROOT_REREGISTERED" in out


def test_a_root_no_longer_registered_holds_the_approval(case, capsys, monkeypatch):
    (case / "evidence.json").write_text(json.dumps({"files": []}))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ROOT_UNREGISTERED" in out


def test_a_root_that_is_gone_holds_the_approval(case, capsys, monkeypatch):
    (case / "evidence" / "mem.7z").unlink()
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ROOT_CHANGED" in out and "missing" in out


def test_a_root_too_big_to_hash_again_fails_unread(case, capsys, monkeypatch):
    change_root(case)
    monkeypatch.setattr(approval_checks, "INLINE_LIMIT", 10)
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # never called
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "stat changed; not re-hashed" in out


def test_a_root_that_isn_t_a_regular_file_is_refused_unread(case):
    os.mkfifo(case / "evidence" / "pipe")
    with pytest.raises(ValueError, match="not a regular file"):
        approval_checks.file_sha256(case / "evidence" / "pipe")


# --- A folder root -------------------------------------------------------------


def _kape(case) -> Path:
    kape = case / "evidence" / "kape"
    kape.mkdir()
    evtx = kape / "Security.evtx"
    evtx.write_bytes(b"ElfFile evtx bytes " * 40)
    (kape / "System.evtx").write_bytes(b"ElfFile system " * 40)
    entry = register_evidence_data(case, str(kape), "analyst1")
    f = _finding(case)
    a = f["artifacts"][0]
    row_sha = sha(evtx.read_bytes())
    a["provenance_root"] = {"path": str(evtx), "sha256": row_sha,
                            "label": "examiner-registered", "folder": str(kape)}  # fmt: skip
    a["provenance_chain"] = a["provenance_chain"][1:]
    a["provenance_chain"][0]["from"] = {"path": str(evtx), "sha256": row_sha}
    f["source_evidence"] = str(evtx)
    _save(case, f)
    return Path(entry["path"])


def test_a_file_on_a_folder_manifest_row_unchanged_is_ok_without_a_read(
    case, capsys, monkeypatch
):
    _kape(case)
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # never called
    run("ids", case, capsys, monkeypatch)
    o = last_line()
    root = next(i for i in o["checks"]["items"] if i["check"] == "ROOT")
    assert (
        status(case) == "APPROVED" and root["detail"] == "unchanged (stat fields equal)"
    )


def test_a_file_on_a_folder_manifest_row_changed_holds_the_approval(
    case, capsys, monkeypatch
):
    _kape(case)
    with open(case / "evidence" / "kape" / "Security.evtx", "ab") as f:
        f.write(b"tampered")
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ROOT_CHANGED" in out


def test_a_file_touched_but_unchanged_on_a_manifest_row_is_hashed_again_and_ok(
    case, capsys, monkeypatch
):
    _kape(case)
    os.utime(case / "evidence" / "kape" / "Security.evtx", ns=(1, 1))
    run("ids", case, capsys, monkeypatch)
    root = next(i for i in last_line()["checks"]["items"] if i["check"] == "ROOT")
    assert status(case) == "APPROVED" and root["detail"] == "unchanged (hashed again)"


def _folder_root(case, kape: Path) -> None:
    entry = json.loads((case / "evidence.json").read_text())["files"][-1]
    f = _finding(case)
    f["artifacts"][0]["provenance_root"] = {
        "path": str(kape), "sha256": entry["manifest_sha256"], "label": "examiner-registered"
    }  # fmt: skip
    _save(case, f)


def test_a_folder_root_is_checked_by_its_manifest(case, capsys, monkeypatch):
    kape = _kape(case)
    _folder_root(case, kape)
    run("ids", case, capsys, monkeypatch)
    root = next(i for i in last_line()["checks"]["items"] if i["check"] == "ROOT")
    assert status(case) == "APPROVED" and root["detail"] == "manifest unchanged"


def test_a_folder_root_whose_manifest_changed_holds_the_approval(
    case, capsys, monkeypatch
):
    kape = _kape(case)
    _folder_root(case, kape)
    m = (
        case
        / json.loads((case / "evidence.json").read_text())["files"][-1]["manifest_path"]
    )
    m.write_text(m.read_text().replace("Security", "Securitx"))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "ROOT_CHANGED" in out


# --- A cited document ----------------------------------------------------------


DOC = {"_index": "case-inc-2610-evtx", "_id": "d1"}
SOURCE = {"event": {"code": "4688"}, "process": {"name": "evil.exe"}}


def _query_link(case, recorded: str) -> None:
    q_line = _line(ts="2026-10-09T00:00:30Z", mcp="opensearch-mcp", tool="idx_search",
                   audit_id="opensearch-analyst1-001",
                   params={"result_docs": [{**DOC, "content_hash": recorded}]})  # fmt: skip
    (case / "audit" / "opensearch-mcp.jsonl").write_text(q_line + "\n")
    f = _finding(case)
    f["artifacts"].append({
        "source": "evtx", "extraction": "idx_search", "content": "4688 evil.exe",
        "audit_id": "opensearch-analyst1-001", "provenance_grade": "FULL",
        "provenance_root": f["artifacts"][0]["provenance_root"],
        "provenance_chain": [{"method": "recorded-id", "audit_id": "opensearch-analyst1-001",
                              "entry_sha256": sha(q_line),
                              "document": {**DOC, "content_hash": recorded}}],
    })  # fmt: skip
    _save(case, f)


def _opensearch(monkeypatch, client) -> None:
    pkg = types.ModuleType("opensearch_mcp")
    cli = types.ModuleType("opensearch_mcp.client")
    cli.get_client = lambda *a, **k: client
    pkg.client = cli
    pkg.__spec__ = types.SimpleNamespace(name="opensearch_mcp")
    monkeypatch.setitem(sys.modules, "opensearch_mcp", pkg)
    monkeypatch.setitem(sys.modules, "opensearch_mcp.client", cli)
    monkeypatch.setattr("importlib.util.find_spec", lambda name, *a: object())


class Stub:
    def __init__(self, source=None, error=None):
        self.source, self.error, self.calls = source, error, []

    def get(self, index, id, **kw):
        self.calls.append((index, id, kw.get("request_timeout")))
        if self.error:
            raise self.error
        return {"_index": index, "_id": id, "found": True, "_source": self.source}


@pytest.fixture
def content_hash():
    return pytest.importorskip("sift_common.content_hash").content_hash


def test_a_cited_document_unchanged_is_ok(case, capsys, monkeypatch, content_hash):
    _query_link(case, content_hash(SOURCE))
    stub = Stub(SOURCE)
    _opensearch(monkeypatch, stub)
    run("ids", case, capsys, monkeypatch)
    doc = next(i for i in last_line()["checks"]["items"] if i["check"] == "DOC")
    assert status(case) == "APPROVED" and doc["detail"] == "unchanged"
    assert stub.calls == [(DOC["_index"], DOC["_id"], approval_checks.DOC_TIMEOUT)]


def test_a_cited_document_changed_holds_the_approval(
    case, capsys, monkeypatch, content_hash
):
    _query_link(case, content_hash(SOURCE))
    _opensearch(monkeypatch, Stub({**SOURCE, "process": {"name": "notepad.exe"}}))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "DOC_CHANGED" in out


def test_a_cited_document_gone_holds_the_approval(case, capsys, monkeypatch):
    _query_link(case, "0" * 64)
    pytest.importorskip("sift_common.content_hash")

    class NotFoundError(Exception):
        status_code = 404

    _opensearch(monkeypatch, Stub(error=NotFoundError()))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "DOC_MISSING" in out


def test_opensearch_unreachable_is_a_failed_check(case, capsys, monkeypatch):
    _query_link(case, "0" * 64)
    pytest.importorskip("sift_common.content_hash")
    _opensearch(monkeypatch, Stub(error=ConnectionError("connection refused")))
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "DOC_UNREACHABLE" in out
    assert "couldn't verify: OpenSearch unreachable" in out


def test_without_the_sift_stack_a_cited_document_is_unverified(
    case, capsys, monkeypatch
):
    _query_link(case, "0" * 64)
    monkeypatch.setitem(sys.modules, "sift_common.content_hash", None)
    _, out = run("ids", case, capsys, monkeypatch)
    assert status(case) == "DRAFT" and "couldn't verify: OpenSearch unreachable" in out


def test_a_document_with_no_recorded_hash_isn_t_fetched(case, capsys, monkeypatch):
    _query_link(case, "")
    stub = Stub(error=AssertionError("fetched"))
    _opensearch(monkeypatch, stub)
    run("ids", case, capsys, monkeypatch)
    doc = next(i for i in last_line()["checks"]["items"] if i["check"] == "DOC")
    assert status(case) == "APPROVED" and stub.calls == []
    assert doc["detail"] == "no content hash was recorded; not compared"


# --- What is shown before the passphrase, for each grade on each path -------------


def _grade(case, grade: str) -> dict:
    """The finding as the chain resolver stores each grade; IMPORTED as an
    import leaves it, and legacy as 0.6.3 did."""
    f = _finding(case)
    a = f["artifacts"][0]
    if grade == "legacy":
        for k in ("provenance_schema", "provenance_grade"):
            f.pop(k)
        f["artifacts"] = []
    elif grade == "IMPORTED":
        f["imported_from"] = {"case_id": "INC-OTHER", "examiner": "alice",
                              "exported_at": "2026-10-08T12:00:00Z"}  # fmt: skip
        for link in a["provenance_chain"]:
            link["audit_id"] = link["audit_id"].replace("analyst1", "alice")
    elif grade != "FULL":
        f["provenance_grade"] = a["provenance_grade"] = grade
        a["provenance_reason"] = {
            "DECLARED": "input named by the AI, not found in the command",
            "AMBIGUOUS": "two registered files have this hash",
            "BROKEN": "no recorded origin: made outside recorded tools",
            "CITED-UNVERIFIED": "no audit entry is cited",
        }[grade]
        if grade == "DECLARED":
            a["provenance_chain"][-1]["method"] = "declared"
        else:  # no root reached
            a["provenance_root"] = None
            a["provenance_chain"] = (
                a["provenance_chain"][1:] if grade == "BROKEN" else []
            )
            if grade == "AMBIGUOUS":
                a["provenance_candidates"] = [{"path": "/a", "sha256": "1" * 64}]
            if grade == "BROKEN":
                a["provenance_break"] = {"kind": "no-recorded-origin"}
    _save(case, f)
    return f


GRADES = ["FULL", "DECLARED", "AMBIGUOUS", "BROKEN", "CITED-UNVERIFIED",
          "IMPORTED", "legacy"]  # fmt: skip


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("grade", GRADES)
def test_each_grade_on_each_path_is_shown_then_approved_without_an_override(
    case, capsys, monkeypatch, route, grade
):
    f = _grade(case, grade)
    asked = []
    before, _ = run(route, case, capsys, monkeypatch, reason=None)
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda p="": asked.append(p))
    o = last_line()
    assert status(case) == "APPROVED" and asked == []
    assert "approval_override_reason" not in o
    expected = "not-applicable" if grade in ("IMPORTED", "legacy") else "ok"
    assert o["checks"]["result"] == expected
    z = str(case / "evidence" / "mem.7z")
    if grade in ("FULL", "DECLARED"):
        assert f"Root: {z}" in before and "AI-registered" in before
    else:
        assert "Root: " not in before
    if grade == "IMPORTED":
        assert o["checks"]["detail"].startswith(
            "chain lives in case INC-OTHER (imported from alice, exported "
        )
        assert "chain lives in case INC-OTHER" in before
    elif grade == "legacy":
        assert "recorded before 0.6.4" in before and "detail" not in o["checks"]
    else:
        assert f"Provenance: {grade}" in before
    reason = (f["artifacts"] or [{}])[0].get("provenance_reason")
    if grade not in ("FULL", "IMPORTED", "legacy"):
        assert reason in before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("grade", ["FULL", "DECLARED"])
def test_each_grade_with_a_root_holds_on_each_path_when_it_changed(
    case, capsys, monkeypatch, route, grade
):
    _grade(case, grade)
    change_root(case)
    before, out = run(route, case, capsys, monkeypatch, reason="")
    assert status(case) == "DRAFT"
    assert "Check failed: ROOT_CHANGED" in out


def test_an_imported_item_s_foreign_audit_ids_aren_t_checked(case, capsys, monkeypatch):
    _grade(case, "IMPORTED")
    change_root(case)  # its chain lives in the other case
    run("ids", case, capsys, monkeypatch, reason=None)
    o = last_line()
    assert status(case) == "APPROVED" and o["checks"]["items"] == []


def test_an_import_with_empty_origin_fields_names_them_as_unknown(case):
    f = _grade(case, "IMPORTED")
    f["imported_from"] = {"case_id": "", "examiner": "", "exported_at": ""}
    checks = approval_checks.check_item(case, f, "finding")
    assert checks["detail"] == "chain lives in case ? (imported from ?, exported ?)"


def test_a_timeline_event_s_approval_is_not_applicable(case, capsys, monkeypatch):
    (case / "findings.json").write_text("[]")
    (case / "timeline.json").write_text(json.dumps([{
        "id": "T-analyst1-001", "timestamp": "2026-10-01T00:00:00Z",
        "description": "evil.exe ran", "status": "DRAFT"}]))  # fmt: skip
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda p="": None)
    A._approve_specific(case, ["T-analyst1-001"], IDENT, case.parent / "c.yaml")
    o = last_line()
    assert (o["type"], o["checks"]) == ("timeline", signing.NOT_CHECKED)


def test_the_checks_are_the_same_text_on_every_run(case):
    _kape(case)
    f = _finding(case)
    one = approval_checks.check_item(case, f, "finding")
    two = approval_checks.check_item(case, copy.deepcopy(f), "finding")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
    assert not any(k in json.dumps(one) for k in ("_at", "time"))


# --- The reason comes only from the terminal -------------------------------------


def test_the_reason_is_never_read_from_stdin(monkeypatch):
    def no_tty(path, *a, **k):
        raise OSError("no terminal")

    monkeypatch.setattr("builtins.open", no_tty)
    monkeypatch.setattr(sys, "stdin", io.StringIO(REASON + "\n"))
    assert approval_auth.read_tty_line("why? ") is None
    assert sys.stdin.read() == REASON + "\n"


def test_a_pending_review_entry_can_t_supply_the_reason(case, capsys, monkeypatch):
    change_root(case)
    (case / "pending-reviews.json").write_text(json.dumps({"case_id": CASE_ID, "items": [
        {"id": FID, "type": "finding", "action": "approve", "staged_by": "analyst1",
         "approval_override_reason": REASON, "reason": REASON}
    ]}))  # fmt: skip
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda p="": None)
    A._review_mode(case, IDENT, case.parent / "c.yaml")
    assert status(case) == "DRAFT"
    assert "a check failed and no reason was typed" in capsys.readouterr().out


# --- Documented ----------------------------------------------------------------


def test_the_security_doc_states_view_2_and_the_override():
    doc = Path(__file__).resolve().parents[1] / "docs" / "security.md"
    text = doc.read_text()
    assert "view 2" in text and "override reason" in text.lower()
    assert "pseudo-terminal" in text


@pytest.mark.parametrize("route", ROUTES)
def test_a_query_logged_before_0_6_4_is_shown_so_before_the_passphrase(
    case, capsys, monkeypatch, route
):
    f = _finding(case)
    f["provenance_grade"] = "BROKEN"
    f["artifacts"][0].update(
        provenance_grade="BROKEN",
        provenance_root=None,
        provenance_chain=[],
        provenance_reason="recorded before 0.6.4: q-1 records no results to follow",
        provenance_break={"kind": "recorded-before-0.6.4"},
    )
    _save(case, f)
    before, _ = run(route, case, capsys, monkeypatch, reason=None)
    # (the review path also lists every stored field as written)
    assert "Provenance: recorded before 0.6.4" in before
    assert "Provenance: BROKEN" not in before
    assert "[1] recorded before 0.6.4: q-1 records no results to follow" in before
    assert status(case) == "APPROVED"
