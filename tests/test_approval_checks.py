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
import pickle
import re
import resource
import select
import signal
import sys
import types
from pathlib import Path

import pytest
import yaml

from vhir_cli import approval_auth, approval_checks, keys, ledger
from vhir_cli.case_io import (
    compute_content_hash,
    load_findings,
    load_withdrawals,
    signed_text,
)
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


def run(route, d, capsys, monkeypatch, reason: str | None = "", ids=(FID,)):
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
            A._approve_specific(d, list(ids), IDENT, cfg)
        elif route == "interactive":
            A._interactive_review(d, IDENT, cfg)
        else:
            (d / "pending-reviews.json").write_text(json.dumps({"case_id": CASE_ID, "items": [
                {"id": i, "type": "finding", "action": "approve", "staged_by": "analyst1"}
                for i in ids]}))  # fmt: skip
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


@pytest.mark.parametrize("route", ROUTES)
def test_each_path_reads_the_audit_trail_once_to_show_and_once_to_sign(
    case, capsys, monkeypatch, route
):
    """However many items: one read for what is shown, one under the lock."""
    _second_finding(case)
    made, real = [], approval_checks.audit_lines
    monkeypatch.setattr(approval_checks, "audit_lines",
                        lambda c, w=None: made.append(sorted(w)) or real(c, w))  # fmt: skip
    run(route, case, capsys, monkeypatch, ids=(FID, "F-analyst1-002"))
    got = {f["id"]: f["status"] for f in load_findings(case)}
    assert got == {FID: "APPROVED", "F-analyst1-002": "APPROVED"}
    assert made == [["sift-analyst1-001", "sift-analyst1-002"]] * 2


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
    assert view["overrides"] == {FID: [REASON]}
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


def _legacy_entry(case) -> None:
    """The registry as before stat fields were recorded at registration."""
    reg = json.loads((case / "evidence.json").read_text())
    for e in reg["files"]:
        for k in approval_checks._STAT_KEYS:
            e.pop(k, None)
    (case / "evidence.json").write_text(json.dumps(reg))


def test_an_unchanged_root_over_1_gib_registered_without_stat_fields_is_ok(
    case, capsys, monkeypatch
):
    """The commonest evidence (an image or a memory dump) registered before
    stat fields were kept: hashed once, before the passphrase, then trusted
    by its stat fields."""
    z = case / "evidence" / "mem.7z"
    with open(z, "r+b") as f:  # sparse: 1 GiB + 4 KiB, cheap to make
        f.truncate((1 << 30) + 4096)
    sha = approval_checks.file_sha256(z)
    reg = json.loads((case / "evidence.json").read_text())
    reg["files"][0]["sha256"] = sha
    (case / "evidence.json").write_text(json.dumps(reg))
    _legacy_entry(case)
    f = _finding(case)
    f["artifacts"][0]["provenance_root"]["sha256"] = sha
    _save(case, f)
    before, _ = run("ids", case, capsys, monkeypatch, reason=None)
    root = next(i for i in last_line()["checks"]["items"] if i["check"] == "ROOT")
    assert status(case) == "APPROVED" and root["status"] == "ok"
    assert f"Hashing {z} (1.1 GB) once to verify it" in before
    seen = json.loads((case / approval_checks.VERIFIED).read_text())[str(z)]
    assert seen["sha256"] == sha and seen["stat"] == approval_checks._stat_key(z.stat())
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # never read again
    again = approval_checks.check_item(case, f, "finding")
    assert [i["status"] for i in again["items"] if i["check"] == "ROOT"] == ["ok"]


def _wait_for_hashing():
    import threading

    for t in threading.enumerate():
        if t.name == "approval-root-hash":
            t.join(timeout=30)


def test_in_the_background_a_large_root_is_not_yet_verified_then_ok(case, monkeypatch):
    _legacy_entry(case)
    monkeypatch.setattr(approval_checks, "INLINE_LIMIT", 10)
    f = _finding(case)
    first = approval_checks.check_item(case, f, "finding", background=True)
    (root,) = [i for i in first["items"] if i["check"] == "ROOT"]
    assert (root["code"], root["detail"]) == (
        "ROOT_UNVERIFIED",
        "not yet verified (hashing)",
    )
    assert first["result"] == "failed"
    _wait_for_hashing()
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # trusted now
    then = approval_checks.check_item(case, f, "finding", background=True)
    assert then["result"] == "ok"


def test_in_the_background_a_changed_large_root_is_then_changed(case, monkeypatch):
    _legacy_entry(case)
    change_root(case)
    monkeypatch.setattr(approval_checks, "INLINE_LIMIT", 10)
    f = _finding(case)
    first = approval_checks.check_item(case, f, "finding", background=True)
    assert approval_checks.failed_codes(first) == ["ROOT_UNVERIFIED"]
    _wait_for_hashing()
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # hashed once only
    then = approval_checks.check_item(case, f, "finding", background=True)
    assert approval_checks.failed_codes(then) == ["ROOT_CHANGED"]


def test_a_root_without_stat_fields_unchanged_is_ok_not_changed(
    case, capsys, monkeypatch
):
    _legacy_entry(case)
    run("ids", case, capsys, monkeypatch, reason=None)
    root = next(i for i in last_line()["checks"]["items"] if i["check"] == "ROOT")
    assert status(case) == "APPROVED" and root["detail"] == "unchanged (hashed again)"


def test_a_root_that_changes_while_it_is_read_is_not_verified(case, monkeypatch):
    _legacy_entry(case)
    real = approval_checks.file_sha256

    def touched(path):
        out = real(path)
        os.utime(path, ns=(5, 5))
        return out

    monkeypatch.setattr(approval_checks, "file_sha256", touched)
    checks = approval_checks.check_item(case, _finding(case), "finding")
    (root,) = [i for i in checks["items"] if i["check"] == "ROOT"]
    assert (
        root["code"] == "ROOT_UNVERIFIED"
        and "changed while it was read" in root["detail"]
    )
    assert not (case / approval_checks.VERIFIED).exists()


def test_a_recorded_hash_vouches_only_for_the_stat_fields_it_was_taken_with(
    case, monkeypatch
):
    _legacy_entry(case)
    approval_checks.check_item(case, _finding(case), "finding")  # hashed and kept
    change_root(case)
    checks = approval_checks.check_item(case, _finding(case), "finding")
    assert approval_checks.failed_codes(checks) == ["ROOT_CHANGED"]


@pytest.mark.parametrize("route", ROUTES)
def test_every_root_of_an_artifact_is_checked_and_shown(
    case, capsys, monkeypatch, route
):
    other = case / "evidence" / "second.raw"
    other.write_bytes(b"a second input " * 40)
    osha = register_evidence_data(case, str(other), "analyst1")["sha256"]
    f = _finding(case)
    a = f["artifacts"][0]
    a["provenance_roots"] = [
        a["provenance_root"],
        {"path": str(other), "sha256": osha, "label": "examiner-registered"},
    ]
    _save(case, f)
    with open(other, "ab") as fh:
        fh.write(b"changed")
    _, out = run(route, case, capsys, monkeypatch, reason="")
    assert status(case) == "DRAFT"
    assert f"Check failed: ROOT_CHANGED {other}" in out
    assert f"Root: {other} " in out and f"Root: {case / 'evidence' / 'mem.7z'} " in out


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
    # once when the checks are shown, once more under the case lock before signing
    assert stub.calls == [(DOC["_index"], DOC["_id"], approval_checks.DOC_TIMEOUT)] * 2


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


def test_an_edit_after_an_override_keeps_it_and_every_reason_is_listed(
    case, capsys, monkeypatch
):
    change_root(case)
    run("ids", case, capsys, monkeypatch, reason=REASON)
    f = _finding(case)
    (case / "pending-reviews.json").write_text(json.dumps({"case_id": CASE_ID, "items": [
        {"id": FID, "type": "finding", "action": "edit", "staged_by": "analyst1",
         "modifications": {"interpretation": {"original": f["interpretation"],
                                              "modified": "edited after approval"}}}
    ]}))  # fmt: skip
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    A._review_mode(case, IDENT, case.parent / "config.yaml")
    assert last_line()["decision"] == "edit"
    v, r = verdict(case)
    item = next(i for i in r.items if i.item_id == FID)
    assert v == "VALID" and item.label == f"approved with override: {REASON}"
    view = approved_view(case)
    assert view["overrides"] == {FID: [REASON]}
    assert view["checks"][FID]["result"] == "failed"
    assert f"  {FID}: {REASON}" in verification_block(view)


def test_every_override_reason_is_kept_oldest_first(case, capsys, monkeypatch):
    change_root(case)
    run("ids", case, capsys, monkeypatch, reason=REASON)
    # a second approval of the same item, with another failed check and reason
    data = keys.load("analyst1")
    entry = keys.active(data)
    kek = keys.derive_kek(PASSPHRASE, data["salt_ledger"])
    private = keys.unwrap(
        {
            "wrapped_private": entry["wrapped_private"],
            "public_key": entry["public_key"],
        },
        kek,
        "analyst1",
    )
    second = {"result": "failed", "items": [{"check": "ENTRY", "status": "failed",
              "subject": "sift-analyst1-002", "detail": "x", "code": "ENTRY_CHANGED"}]}  # fmt: skip
    d0 = {"item_id": FID, "type": "finding", "decision": "approve",
          "status_after": "APPROVED", "coupled_from": None,
          "content_snapshot": signed_text(_finding(case), "finding"),
          "checks": second, "approval_override_reason": "the second reason"}  # fmt: skip
    from vhir_cli.case_io import load_case_meta

    uuid = load_case_meta(case).get("case_uuid")
    (body,) = ledger.prepare(
        CASE_ID,
        [d0],
        "analyst1",
        entry["public_key"],
        "cli",
        signing.AT,
        case_uuid=uuid,
    )
    with ledger.case_lock(CASE_ID) as lock:
        ledger.commit(
            lock, [body], [ledger.sign_body(body, private)], entry["public_key"]
        )
    f = _finding(case)
    f.update(approved_at=signing.AT, approved_by="analyst1")  # as the save stamps it
    _save(case, f)
    v, _ = verdict(case)
    assert v == "VALID"
    view = approved_view(case)
    assert view["overrides"] == {FID: [REASON, "the second reason"]}
    assert view["labels"][FID] == "approved with override: the second reason"
    block = verification_block(view)
    assert block.index(f"  {FID}: {REASON}") < block.index(
        f"  {FID}: the second reason"
    )


def test_a_root_registered_with_its_stat_fields_is_trusted_without_a_read(
    case, capsys, monkeypatch
):
    """Registration records size, times, device and inode: an unchanged root
    over 1 GiB is ok with no read, and no "not yet verified"."""
    big = case / "evidence" / "disk.raw"
    with open(big, "wb") as f:
        f.truncate((1 << 30) + 4096)
    entry = register_evidence_data(case, str(big), "analyst1")
    if "st_ino" not in entry:
        pytest.skip("this vhir's registration records no stat fields")
    f = _finding(case)
    f["artifacts"][0]["provenance_root"] = {
        "path": str(big), "sha256": entry["sha256"], "label": "examiner-registered"
    }  # fmt: skip
    _save(case, f)
    monkeypatch.setattr(approval_checks, "file_sha256", None)  # never read
    for background in (False, True):
        checks = approval_checks.check_item(case, f, "finding", background=background)
        (root,) = [i for i in checks["items"] if i["subject"] == str(big)]
        assert (root["status"], root["detail"]) == (
            "ok",
            "unchanged (stat fields equal)",
        )


def test_a_background_hash_that_fails_says_so_then_is_asked_for_again(
    case, monkeypatch
):
    _legacy_entry(case)
    monkeypatch.setattr(approval_checks, "INLINE_LIMIT", 10)
    real = approval_checks.file_sha256

    def locked(path):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(approval_checks, "file_sha256", locked)
    f = _finding(case)

    def root_detail():
        checks = approval_checks.check_item(case, f, "finding", background=True)
        (root,) = [i for i in checks["items"] if i["check"] == "ROOT"]
        return root["status"], root["detail"]

    assert root_detail() == ("failed", "not yet verified (hashing)")
    _wait_for_hashing()
    failed = ("failed", "not verified: hashing failed: [Errno 13] Permission denied")
    assert root_detail() == failed
    assert root_detail() == failed  # the same while a plan's commit may follow
    monkeypatch.setattr(approval_checks, "FAILED_HOLD", -1)
    monkeypatch.setattr(approval_checks, "file_sha256", real)
    assert root_detail() == ("failed", "not yet verified (hashing)")  # asked again
    _wait_for_hashing()
    assert root_detail()[0] == "ok"


class _Line:
    def __init__(self, name, chain, seq):
        self.name, self.chain, self.seq = name, chain, seq


def test_approvals_follow_the_ledger_s_order_in_a_merged_history():
    """C precedes A (A's chain referenced C's); B is concurrent with both.
    The latest is one no other approval follows: never C."""
    from vhir_cli.ledger_verify import in_ledger_order

    a, b, c = _Line("A", "x", 2), _Line("B", "y", 1), _Line("C", "z", 1)
    before = lambda p, q: (p, q) == (c, a)  # noqa: E731
    out = in_ledger_order([a, b, c], before)
    assert out.index(c) < out.index(a) and out[-1] is not c
    assert [ln.name for ln in in_ledger_order([c, b, a], before)] == [
        ln.name for ln in out
    ]  # the same whatever order they arrive in


def test_the_json_report_keeps_every_override_reason(case, capsys, monkeypatch):
    from argparse import Namespace

    from vhir_cli.commands.report import cmd_report

    change_root(case)
    run("ids", case, capsys, monkeypatch, reason=REASON)
    args = {"case": None, "full": True, "executive_summary": False,
            "report_timeline": False, "from_date": None, "to_date": None, "ioc": False,
            "report_findings": None, "status_brief": False, "save": None}  # fmt: skip
    cmd_report(Namespace(**args), {"examiner": "analyst1"})
    out = capsys.readouterr().out
    report, _ = json.JSONDecoder().raw_decode(out[out.index("{") :])
    assert report["verification"]["overrides"] == {FID: [REASON]}


# --- Audit logs the checks can't read --------------------------------------
# A log the approval checks can't read (mode 000, a FIFO, a dangling link) or
# an `audit/` they can't list could hold another entry for a chained id: the
# approval names each one, signs nothing and takes no override. A held FIFO
# never blocks the withdrawal count. Under the case lock the CLI runs the
# checks again; an item whose checks changed after they were shown isn't signed.

_NON_ROOT_POSIX = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="FIFOs are POSIX, and mode 000 doesn't stop root",
)


def M(why: str) -> str:
    denied = re.findall(r"(?:^|, )([^,(]+) \(Permission denied\)", why)
    return (
        f"The approval checks couldn't read {why}: an entry there could change their "
        "result. Nothing was signed, and nothing in audit/ was changed: audit logs "
        "are evidence and stay as they are."
        + (f" Check the permissions of {', '.join(denied)}, then approve again."
           if denied else "")
    )  # fmt: skip


def _within(fn, timeout=8.0):
    """What `fn` returns in a forked child, or ("blocked",) if it doesn't
    within `timeout` (the child is then killed)."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        try:
            with open("/proc/self/statm") as f:
                size = int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
            resource.setrlimit(resource.RLIMIT_AS, (size + (1 << 30), size + (1 << 30)))
            out = ("ok", fn())
        except BaseException as e:  # noqa: BLE001 - reported to the parent
            out = ("raised", f"{type(e).__name__}: {e}")
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    try:
        ready, _, _ = select.select([r], [], [], timeout)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            return ("blocked",)
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        return pickle.loads(data)
    finally:
        os.close(r)
        os.waitpid(pid, 0)


@pytest.fixture
def held():
    fds: list[int] = []

    def hold(path, payload: bytes = b""):
        """`path` as a FIFO another process holds open, with `payload` in it."""
        path.unlink(missing_ok=True)
        os.mkfifo(path)
        fd = os.open(path, os.O_RDWR)
        if payload:
            os.write(fd, payload)
        fds.append(fd)

    yield hold
    for fd in fds:
        os.close(fd)


def _duplicate(d) -> bytes:
    """A second line for the chain's second entry, in another log."""
    first, second = (d / "audit" / "sift-mcp.jsonl").read_text().splitlines()
    return (second + "\n").encode()


def _lines() -> int:
    path = ledger.chain_path(CASE_ID)
    return len(ledger.read_lines(path)) if path.exists() else 0


# --------------------------------------------------------------------------
# audit_lines


@_NON_ROOT_POSIX
def test_audit_lines_names_every_log_it_cant_read(case, held):
    (case / "audit" / "claude-code.jsonl").write_text('{"audit_id": "claude-x"}\n')
    os.chmod(case / "audit" / "claude-code.jsonl", 0)
    held(case / "audit" / "wintools-mcp.jsonl", _duplicate(case))
    assert _within(lambda: approval_checks.audit_lines(case)) == (
        "raised",
        "AuditUnreadable: "
        + M("audit/claude-code.jsonl (Permission denied), "
            "audit/wintools-mcp.jsonl (not a regular file)"),
    )  # fmt: skip


@_NON_ROOT_POSIX
@pytest.mark.parametrize("mode", [0o000, 0o311], ids=["mode-000", "mode-0311"])
def test_an_audit_folder_that_cant_be_listed_is_named(case, mode):
    os.chmod(case / "audit", mode)
    try:
        got = _within(lambda: approval_checks.audit_lines(case))
    finally:
        os.chmod(case / "audit", 0o755)
    assert got == ("raised", "AuditUnreadable: " + M("audit/ (Permission denied)"))


@_NON_ROOT_POSIX
def test_a_missing_folder_and_an_empty_log_read_as_before(case):
    (case / "audit" / "empty.jsonl").write_text("")
    trail = approval_checks.audit_lines(case)
    assert sorted(trail) == ["sift-analyst1-001", "sift-analyst1-002"]
    for log in (case / "audit").iterdir():
        log.unlink()
    (case / "audit").rmdir()
    assert approval_checks.audit_lines(case) == {}


# --------------------------------------------------------------------------
# vhir approve, through main()


def _approve_main(monkeypatch, capsys):
    from vhir_cli.main import main

    monkeypatch.setattr(
        approval_auth, "read_tty_line", lambda prompt="": "approve anyway"
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    monkeypatch.setattr(sys, "argv", ["vhir", "approve", FID])
    with pytest.raises(SystemExit) as e:
        main()
    return e.value.code, capsys.readouterr()


@_NON_ROOT_POSIX
@pytest.mark.parametrize(
    "setup,why",
    [
        ("dup-mode000", "audit/wintools-mcp.jsonl (Permission denied)"),
        ("cited-mode000", "audit/sift-mcp.jsonl (Permission denied)"),
        ("dangling", "audit/wintools-mcp.jsonl (a symbolic link)"),
        ("folder-mode000", "audit/ (Permission denied)"),
    ],
)
def test_vhir_approve_refuses_when_a_log_cant_be_read(
    case, monkeypatch, capsys, setup, why
):
    log = case / "audit" / "wintools-mcp.jsonl"
    if setup == "dup-mode000":
        log.write_bytes(_duplicate(case))
        os.chmod(log, 0)
    elif setup == "cited-mode000":
        os.chmod(case / "audit" / "sift-mcp.jsonl", 0)
    elif setup == "dangling":
        log.symlink_to(case / "audit" / "gone.jsonl")
    else:
        os.chmod(case / "audit", 0)
    try:
        code, out = _approve_main(monkeypatch, capsys)
    finally:
        os.chmod(case / "audit", 0o755)
    assert code == 1
    assert f"Error: {M(why)}" in out.err.splitlines()
    assert _lines() == 0 and status(case) == "DRAFT"


@_NON_ROOT_POSIX
def test_a_readable_duplicate_is_still_a_failed_check_that_can_be_overridden(
    case, monkeypatch, capsys
):
    (case / "audit" / "wintools-mcp.jsonl").write_bytes(_duplicate(case))
    _, out = run("ids", case, capsys, monkeypatch, reason="")
    assert "ENTRY_DUPLICATE sift-analyst1-002" in out and status(case) == "DRAFT"


# --------------------------------------------------------------------------
# under the lock, after the passphrase


def _at_the_passphrase(monkeypatch, change):
    def typed(prompt=""):
        change()
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", typed)


@_NON_ROOT_POSIX
def test_a_log_made_unreadable_while_the_passphrase_is_typed_signs_nothing(
    case, monkeypatch, capsys
):
    log = case / "audit" / "wintools-mcp.jsonl"

    def change():
        log.write_bytes(_duplicate(case))
        os.chmod(log, 0)

    monkeypatch.setattr(approval_auth, "read_tty_line", lambda prompt="": "")
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    _at_the_passphrase(monkeypatch, change)
    from vhir_cli.commands import approve as A

    with pytest.raises(SystemExit) as e:
        A._approve_specific(case, [FID], {"examiner": "analyst1", "os_user": "rig",
                                          "analyst": "analyst1"}, case.parent / "c.yaml")  # fmt: skip
    err = capsys.readouterr().err
    assert e.value.code == 1
    why = M("audit/wintools-mcp.jsonl (Permission denied)")
    assert f"The commit couldn't go ahead: {why}" in err
    assert "Nothing was signed. Your 1 decision(s) and TODO(s) were saved, unsigned, to " \
           "pending-reviews.json" in err  # fmt: skip
    assert _lines() == 0 and status(case) == "DRAFT"
    pending = json.loads((case / "pending-reviews.json").read_text())
    assert [i["id"] for i in pending["items"]] == [FID]


@_NON_ROOT_POSIX
def test_checks_that_change_while_the_passphrase_is_typed_discard_the_decision(
    case, monkeypatch, capsys
):
    """A readable duplicate appears after the checks were shown as ok."""
    log = case / "audit" / "wintools-mcp.jsonl"
    monkeypatch.setattr(approval_auth, "read_tty_line", lambda prompt="": "")
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    _at_the_passphrase(monkeypatch, lambda: log.write_bytes(_duplicate(case)))
    from vhir_cli.commands import approve as A

    with pytest.raises(SystemExit) as e:
        A._approve_specific(case, [FID], {"examiner": "analyst1", "os_user": "rig",
                                          "analyst": "analyst1"}, case.parent / "c.yaml")  # fmt: skip
    out = capsys.readouterr()
    text = out.out + out.err
    assert e.value.code == 1
    assert (
        f"  DISCARDED: {FID}: its approval checks changed after you saw them; your "
        "approve decision on it was not signed or saved. Review it again."
    ) in text.splitlines()
    assert "1 decision(s) were discarded, as listed above" in text
    assert _lines() == 0 and status(case) == "DRAFT"


# --------------------------------------------------------------------------
# the withdrawal count


@_NON_ROOT_POSIX
@pytest.mark.parametrize("which", ["audit log", "approvals.jsonl"])
def test_the_withdrawal_count_doesnt_wait_on_a_held_fifo(case, held, which):
    path = case / (
        "audit/wintools-mcp.jsonl" if which == "audit log" else "approvals.jsonl"
    )
    held(path, b'{"tool": "record_finding"}\n')
    assert _within(lambda: load_withdrawals(case)) == ("ok", [])
