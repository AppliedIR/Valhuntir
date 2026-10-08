"""`verify_case`: the one verdict on a case's signed decisions.

Each row builds a case and a signed chain with the real ledger code (keys in
memory, the chain under tmp), then changes one thing the way a file write
could, and checks the verdict and the exit code. Exit 0 needs no anchors;
with them the output says `anchored`. A failure anywhere exits 2.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vhir_cli import keys, ledger, verification
from vhir_cli.case_io import signed_text
from vhir_cli.ledger_verify import (
    NOT_ANCHORED,
    Head,
    Pin,
    approved_view,
    parse_head,
    parse_pin,
    render,
    verify_case,
)

AT = "2026-10-08T10:00:00+00:00"
AT2 = "2026-10-08T11:00:00+00:00"


class Examiner:
    def __init__(self, name: str):
        self.name = name
        self.key = Ed25519PrivateKey.generate()
        self.pub = keys.b64(keys.public_raw(self.key))
        self.fp = keys.fingerprint(keys.public_raw(self.key))

    def pin(self, chain=None, first=1, last=None) -> Pin:
        return Pin(self.name, self.fp, chain, first, last)


@pytest.fixture
def steve():
    return Examiner("steve")


@pytest.fixture
def case(tmp_path):
    d = tmp_path / "C1"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C1\nstatus: open\n")
    ledger.LEDGER_DIR.mkdir(parents=True)
    _save(d, findings=[], timeline=[], iocs=[])
    return d


def _save(d: Path, **files):
    for name, items in files.items():
        (d / f"{name}.json").write_text(json.dumps(items))


def _load(d: Path, name: str) -> list[dict]:
    return json.loads((d / f"{name}.json").read_text())


def _finding(n=1, **kw):
    return {"id": f"F-steve-{n:03d}", "title": f"Finding {n}", "observation": "seen",
            "status": "DRAFT", **kw}  # fmt: skip


def _sign(d, ex: Examiner, decisions, *, at=AT, case_id="C1", retired=None, prior=None):
    """Sign `decisions` [(item, type, decision, status_after, coupled_from)] and
    apply them to the items, as a writer would."""
    ds = [
        {"item_id": item["id"], "type": t, "decision": dec, "status_after": after,
         "coupled_from": cf, "content_snapshot": signed_text(item, t)}
        for item, t, dec, after, cf in decisions
    ]  # fmt: skip
    bodies = ledger.prepare(
        case_id, ds, ex.name, ex.pub, "cli", at, retired=retired, prior_chains=prior
    )
    lines = [ledger.sign_body(b, ex.key) for b in bodies]
    with ledger.case_lock(case_id) as lock:
        head = ledger.commit(lock, bodies, lines, ex.pub)
    return head, bodies


def _approve(d, ex, finding, at=AT):
    """Approve `finding` (a dict in findings.json) as a writer would."""
    findings = _load(d, "findings")
    head, _ = _sign(d, ex, [(finding, "finding", "approve", "APPROVED", None)], at=at)
    for f in findings:
        if f["id"] == finding["id"]:
            f.update(status="APPROVED", approved_by=ex.name, approved_at=at)
    _save(d, findings=findings)
    return head


def _head_arg(head) -> Head:
    return Head(head[0], head[1])


def _chain_lines(case_id="C1") -> list[str]:
    return ledger.chain_path(case_id).read_text().splitlines()


def _write_chain(lines, case_id="C1"):
    ledger.chain_path(case_id).write_text("".join(x + "\n" for x in lines))


def _status(result, item_id):
    return result.verdict(item_id).status


# --- A clean case, with and without anchors -------------------------------


def test_a_clean_case_exits_0_without_anchors_and_says_so(case, steve):
    f = _finding()
    _save(case, findings=[f])
    head = _approve(case, steve, f)
    result = verify_case(case)
    assert _status(result, "F-steve-001") == "VALID" and result.exit_code == 0
    out = render(result)
    assert NOT_ANCHORED in out
    assert steve.fp in out and f"seq {head[0]} sha256:{head[1]}" in out
    assert "anchored\n" not in out


def test_with_every_key_pinned_and_the_last_head_it_says_anchored(case, steve):
    f = _finding()
    _save(case, findings=[f])
    head = _approve(case, steve, f)
    result = verify_case(
        case, expect_heads=[_head_arg(head)], expect_keys=[steve.pin()]
    )
    assert result.exit_code == 0 and result.anchored
    assert "\nanchored\n" in render(result) and NOT_ANCHORED not in render(result)


@pytest.mark.parametrize("given", ["keys only", "head only"])
def test_one_anchor_alone_exits_0_and_names_what_is_missing(case, steve, given):
    f = _finding()
    _save(case, findings=[f])
    head = _approve(case, steve, f)
    kw = (
        {"expect_keys": [steve.pin()]}
        if given == "keys only"
        else {"expect_heads": [_head_arg(head)]}
    )
    result = verify_case(case, **kw)
    assert result.exit_code == 0 and not result.anchored
    missing = " ".join(result.missing)
    assert ("no head for chain" in missing) == (given == "keys only")
    assert ("no key list for examiner steve" in missing) == (given == "head only")


def test_an_older_head_exits_0_and_lists_the_lines_after_it(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    old = _approve(case, steve, f1)
    new = _approve(case, steve, f2)
    result = verify_case(case, expect_heads=[_head_arg(old)], expect_keys=[steve.pin()])
    assert result.exit_code == 0 and not result.anchored
    assert "1 lines after your head" in "\n".join(result.after_head)
    assert "F-steve-002 approve by steve" in "\n".join(result.after_head)
    later = verify_case(case, expect_heads=[_head_arg(new)], expect_keys=[steve.pin()])
    assert later.anchored


def test_a_wrong_pin_is_key_not_pinned(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    result = verify_case(case, expect_keys=[Examiner("steve").pin()])
    assert _status(result, "F-steve-001") == "KEY_NOT_PINNED" and result.exit_code == 2


# --- Changes to the chain -------------------------------------------------------


def _three(case, steve):
    fs = [_finding(n) for n in (1, 2, 3)]
    _save(case, findings=fs)
    heads = [_approve(case, steve, f) for f in fs]
    return heads


def test_a_deleted_line_breaks_the_chain(case, steve):
    _three(case, steve)
    lines = _chain_lines()
    _write_chain([lines[0], lines[2]])
    result = verify_case(case)
    assert (
        any(c == "CHAIN_BROKEN" for c, _ in result.failures) and result.exit_code == 2
    )
    assert _status(result, "F-steve-003") == "CHAIN_BROKEN"


def test_a_dropped_last_line_is_caught_by_the_recorded_head(case, steve):
    heads = _three(case, steve)
    _write_chain(_chain_lines()[:2])
    result = verify_case(case, expect_heads=[_head_arg(heads[2])])
    assert (
        any(c == "HEAD_MISMATCH" for c, _ in result.failures) and result.exit_code == 2
    )


def test_an_edited_time_breaks_the_signature(case, steve):
    _three(case, steve)
    lines = _chain_lines()
    last = json.loads(lines[2])
    last["at"] = AT2
    _write_chain(lines[:2] + [json.dumps(last)])
    assert _status(verify_case(case), "F-steve-003") == "TAMPERED"


def test_a_changed_signature_on_an_earlier_line_is_tampered_line(case, steve):
    """Finding 1 is decided again, so its first line is history: a bad signature
    there is a case-level failure, and deciding again doesn't clear it."""
    _three(case, steve)
    approved = _load(case, "findings")[0]
    _sign(case, steve, [(approved, "finding", "edit", "APPROVED", None)], at=AT2)
    findings = _load(case, "findings")
    findings[0]["approved_at"] = AT2
    _save(case, findings=findings)
    assert verify_case(case).exit_code == 0
    lines = _chain_lines()
    first = json.loads(lines[0])
    sig = bytearray(base64.b64decode(first["sig"]))
    sig[0] ^= 1
    first["sig"] = base64.b64encode(bytes(sig)).decode()
    _write_chain([json.dumps(first)] + lines[1:])
    result = verify_case(case)
    assert (
        any(c == "TAMPERED_LINE" for c, _ in result.failures) and result.exit_code == 2
    )
    assert _status(result, "F-steve-001") == "VALID"  # its latest line is fine


def test_another_case_s_chain_is_wrong_case(case, steve, tmp_path):
    other = tmp_path / "C2"
    other.mkdir()
    (other / "CASE.yaml").write_text("case_id: C2\n")
    f = _finding()
    _save(other, findings=[f], timeline=[], iocs=[])
    _sign(other, steve, [(f, "finding", "approve", "APPROVED", None)], case_id="C2")
    ledger.chain_path("C1").write_text(ledger.chain_path("C2").read_text())
    _save(
        case, findings=[dict(f, status="APPROVED", approved_by="steve", approved_at=AT)]
    )
    result = verify_case(case)
    assert any(c == "WRONG_CASE" for c, _ in result.failures) and result.exit_code == 2


def test_a_head_with_no_ledger_is_head_mismatch(case):
    result = verify_case(case, expect_heads=[Head(1, "ab" * 32)])
    assert (
        any(c == "HEAD_MISMATCH" for c, _ in result.failures) and result.exit_code == 2
    )


def test_an_approved_item_with_no_line_and_no_ledger(case):
    _save(
        case,
        findings=[_finding(status="APPROVED", approved_by="steve", approved_at=AT)],
    )
    result = verify_case(case)
    assert _status(result, "F-steve-001") == "APPROVED_NO_LINE"
    assert (
        any(c == "LEDGER_MISSING" for c, _ in result.failures) and result.exit_code == 2
    )


def test_a_garbage_line_is_unparseable(case, steve):
    _three(case, steve)
    lines = _chain_lines()
    _write_chain(lines[:1] + ["not json"] + lines[1:])
    result = verify_case(case)
    assert (
        any(c == "UNPARSEABLE_LINE" for c, _ in result.failures)
        and result.exit_code == 2
    )


def test_every_body_carries_view_1_and_changing_it_breaks_the_signature(case, steve):
    _three(case, steve)
    lines = _chain_lines()
    assert all(json.loads(x)["view"] == 1 for x in lines)
    last = json.loads(lines[2])
    last["view"] = 0
    _write_chain(lines[:2] + [json.dumps(last)])
    assert _status(verify_case(case), "F-steve-003") == "TAMPERED"


# --- Decisions and status ----------------------------------------------------------


def test_a_rejected_item_set_back_to_approved_is_revoked(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    approved = _load(case, "findings")[0]
    _sign(case, steve, [(approved, "finding", "reject", "REJECTED", None)], at=AT2)
    _save(case, findings=[approved])  # a file write: the original approved_* stand
    result = verify_case(case)
    assert _status(result, "F-steve-001") == "REVOKED" and result.exit_code == 2


def test_an_approved_item_demoted_without_a_decision_is_unsigned_status(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    _save(case, findings=[dict(_load(case, "findings")[0], status="DRAFT")])
    assert _status(verify_case(case), "F-steve-001") == "UNSIGNED_STATUS"


def test_changed_content_or_approver_is_altered_after_approval(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    item = _load(case, "findings")[0]
    _save(case, findings=[dict(item, observation="changed")])
    altered = verify_case(case)
    assert _status(altered, "F-steve-001") == "ALTERED_AFTER_APPROVAL"
    assert "observation" in altered.verdict("F-steve-001").label
    _save(case, findings=[dict(item, approved_by="eve")])
    assert _status(verify_case(case), "F-steve-001") == "ALTERED_AFTER_APPROVAL"


def test_an_ioc_s_derived_fields_don_t_alter_it(case, steve):
    ioc = {"id": "IOC-steve-001", "value": "10.0.0.5", "type": "ipv4-addr", "status": "DRAFT",
           "confidence": "LOW", "sightings": [], "source_findings": []}  # fmt: skip
    _save(case, iocs=[ioc])
    _sign(case, steve, [(ioc, "ioc", "approve", "APPROVED", None)])
    later = dict(ioc, status="APPROVED", approved_by="steve", approved_at=AT, confidence="HIGH",
                 sightings=[{"host": "WKS01"}], source_findings=["F-steve-009"],
                 mitre_techniques=["T1071"])  # fmt: skip
    _save(case, iocs=[later])
    assert _status(verify_case(case), "IOC-steve-001") == "VALID"
    _save(case, iocs=[dict(later, description="changed")])
    assert _status(verify_case(case), "IOC-steve-001") == "ALTERED_AFTER_APPROVAL"


# --- Keys: a change, a retirement -----------------------------------------------------------------------


def test_a_key_change_fails_unless_the_new_key_is_pinned(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    new = Examiner("steve")
    _approve(case, new, f2)
    result = verify_case(case)
    assert any(c == "KEY_CHANGED" for c, _ in result.failures) and result.exit_code == 2
    assert "Key changed at seq 2 without the previous key's signature" in render(result)
    pinned = verify_case(case, expect_keys=[steve.pin(), new.pin()])
    assert pinned.exit_code == 0


def test_a_retired_key_signing_after_its_supersedes_record_fails(case, steve):
    f1, f2, f3 = _finding(1), _finding(2), _finding(3)
    _save(case, findings=[f1, f2, f3])
    _approve(case, steve, f1)
    new = Examiner("steve")
    _, (body,) = _sign(
        case, new, [(f2, "finding", "approve", "APPROVED", None)], retired=[steve.fp]
    )
    assert body["supersedes"] == [steve.fp]
    _approve(case, steve, f3)  # the old key signs again
    findings = _load(case, "findings")
    findings[1].update(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=findings)
    result = verify_case(case, expect_keys=[steve.pin(), new.pin()])
    assert _status(result, "F-steve-003") == "RETIRED_KEY_USE" and result.exit_code == 2


# --- 0.6 lines ---------------------------------------------------------------


def _legacy_line(item, approved_by="steve", approved_at=AT, kind="finding") -> str:
    return json.dumps({"finding_id": item["id"], "type": kind, "hmac": "00", "hmac_version": 2,
                       "content_snapshot": signed_text(item, kind, 0), "approved_by": approved_by,
                       "approved_at": approved_at, "case_id": "C1"})  # fmt: skip


def _legacy(lines: list[str]):
    verification.VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)
    path = verification.VERIFICATION_DIR / "C1.jsonl"
    path.write_text("".join(x + "\n" for x in lines))
    return path


def test_a_0_6_approval_is_approved_under_0_6_and_exits_0(case):
    f = _finding(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=[f])
    _legacy([_legacy_line(f)])
    result = verify_case(case)
    assert (
        _status(result, "F-steve-001") == "APPROVED_UNDER_0_6" and result.exit_code == 0
    )
    assert "approved under 0.6 (before signing)" in render(result)


def test_a_0_6_item_changed_since_is_altered(case):
    f = _finding(status="APPROVED", approved_by="steve", approved_at=AT)
    _legacy([_legacy_line(f)])
    _save(case, findings=[dict(f, observation="changed")])
    assert _status(verify_case(case), "F-steve-001") == "ALTERED_AFTER_APPROVAL"


def test_after_genesis_a_new_0_6_line_and_a_changed_prefix_fail(case, steve):
    old = _finding(1, status="APPROVED", approved_by="steve", approved_at=AT)
    path = _legacy([_legacy_line(old)])
    fresh = _finding(2)
    _save(case, findings=[old, fresh])
    _approve(case, steve, fresh)  # genesis freezes the 0.6 file
    late = _finding(3, status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=_load(case, "findings") + [late])
    path.write_text(path.read_text() + _legacy_line(late) + "\n")
    result = verify_case(case)
    assert _status(result, "F-steve-001") == "APPROVED_UNDER_0_6"
    assert _status(result, "F-steve-003") == "LEGACY_AFTER_GENESIS"
    assert _status(result, "F-steve-002") == "VALID"
    path.write_text(path.read_text().replace('"hmac": "00"', '"hmac": "01"', 1))
    altered = verify_case(case)
    assert _status(altered, "F-steve-001") == "PREFIX_ALTERED"
    assert _status(altered, "F-steve-002") == "VALID"
    assert any("PREFIX_ALTERED" in n for n in altered.notices)


def test_a_0_6_line_for_a_missing_item_is_informational(case):
    _legacy([_legacy_line(_finding(9))])
    result = verify_case(case)
    assert result.exit_code == 0 and any("ITEM_MISSING" in n for n in result.notices)


def test_a_reattested_0_6_approval_is_valid_with_both_dates(case, steve):
    f = _finding(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=[f])
    _legacy([_legacy_line(f)])
    _sign(case, steve, [(f, "finding", "reattest", "APPROVED", None)], at=AT2)
    _save(case, findings=[dict(f, reattested_by="steve", reattested_at=AT2)])
    result = verify_case(case)
    v = result.verdict("F-steve-001")
    assert (
        v.status == "VALID"
        and "re-attested" in v.label
        and "legacy approval by steve" in v.label
    )
    _save(
        case,
        findings=[dict(f, approved_by="eve", reattested_by="steve", reattested_at=AT2)],
    )
    assert _status(verify_case(case), "F-steve-001") == "ALTERED_AFTER_APPROVAL"


# --- Cascades ---------------------------------------------------------------------


def test_a_timeline_cascade_is_valid_only_through_the_signed_link(case, steve):
    f = _finding(timeline_event_id="T-steve-001")
    t = {
        "id": "T-steve-001",
        "description": "x",
        "auto_created_from": f["id"],
        "status": "DRAFT",
    }
    _save(case, findings=[f], timeline=[t])
    _sign(case, steve, [(f, "finding", "approve", "APPROVED", None),
                        (t, "timeline", "approve", "APPROVED", f["id"])])  # fmt: skip
    _save(
        case,
        findings=[dict(f, status="APPROVED", approved_by="steve", approved_at=AT)],
        timeline=[dict(t, status="APPROVED", approved_by="steve", approved_at=AT)],
    )
    v = verify_case(case).verdict("T-steve-001")
    assert v.status == "VALID" and v.label == "cascade from F-steve-001"


def test_a_cascade_without_its_link_is_unsupported(case, steve):
    f = _finding()  # no timeline_event_id
    t = {
        "id": "T-steve-001",
        "description": "x",
        "auto_created_from": f["id"],
        "status": "DRAFT",
    }
    _save(case, findings=[f], timeline=[t])
    _sign(case, steve, [(f, "finding", "approve", "APPROVED", None),
                        (t, "timeline", "approve", "APPROVED", f["id"])])  # fmt: skip
    _save(
        case,
        findings=[dict(f, status="APPROVED", approved_by="steve", approved_at=AT)],
        timeline=[dict(t, status="APPROVED", approved_by="steve", approved_at=AT)],
    )
    assert _status(verify_case(case), "T-steve-001") == "CASCADE_UNSUPPORTED"


def test_an_ioc_cascade_needs_its_value_in_the_source_s_signed_iocs(case, steve):
    f = _finding(iocs={"IPv4": ["10.0.0.5:8443"]})
    good = {
        "id": "IOC-steve-001",
        "value": "10.0.0.5",
        "type": "ipv4-addr",
        "status": "DRAFT",
    }
    bad = {
        "id": "IOC-steve-002",
        "value": "evil.example",
        "type": "domain",
        "status": "DRAFT",
    }
    _save(case, findings=[f], iocs=[good, bad])
    _sign(case, steve, [(f, "finding", "approve", "APPROVED", None),
                        (good, "ioc", "approve", "APPROVED", f["id"]),
                        (bad, "ioc", "approve", "APPROVED", f["id"])])  # fmt: skip
    done = {"status": "APPROVED", "approved_by": "steve", "approved_at": AT}
    _save(
        case, findings=[dict(f, **done)], iocs=[dict(good, **done), dict(bad, **done)]
    )
    result = verify_case(case)
    assert _status(result, "IOC-steve-001") == "VALID"
    assert _status(result, "IOC-steve-002") == "CASCADE_UNSUPPORTED"


# --- Several chains ----------------------------------------------------------


def _copy_dir(case) -> Path:
    d = case / "ledger" / "chains"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_a_stale_prefix_copy_is_the_same_chain(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    cid = ledger.chain_id(ledger.body_of(json.loads(_chain_lines()[0])))
    (_copy_dir(case) / f"{cid}.jsonl").write_text(ledger.chain_path("C1").read_text())
    head = _approve(case, steve, f2)  # the box chain grows past the copy
    result = verify_case(
        case, expect_heads=[_head_arg(head)], expect_keys=[steve.pin()]
    )
    assert result.exit_code == 0 and result.anchored and len(result.chains) == 1


def test_copies_that_differ_are_chain_copy_diverged(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    cid = ledger.chain_id(ledger.body_of(json.loads(_chain_lines()[0])))
    copy = _copy_dir(case) / f"{cid}.jsonl"
    copy.write_text(ledger.chain_path("C1").read_text())
    _approve(case, steve, f2)
    other = Examiner("steve")
    body = ledger.prepare("C1", [{"item_id": "F-steve-002", "type": "finding", "decision": "reject",
                                  "status_after": "REJECTED", "coupled_from": None,
                                  "content_snapshot": "{}"}], "steve", other.pub, "cli", AT,
                          head=(1, ledger.body_hash(json.loads(_chain_lines()[0]))))  # fmt: skip
    copy.write_text(copy.read_text() + ledger.sign_body(body[0], other.key) + "\n")
    result = verify_case(case)
    assert (
        any(c == "CHAIN_COPY_DIVERGED" for c, _ in result.failures)
        and result.exit_code == 2
    )


def test_a_reference_to_a_missing_chain_or_head(case, steve):
    f = _finding()
    _save(case, findings=[f])
    ref = [{"chain_id": "0123456789abcdef", "head_seq": 3, "head_hash": "ab" * 32}]
    _sign(case, steve, [(f, "finding", "approve", "APPROVED", None)], prior=ref)
    _save(
        case, findings=[dict(f, status="APPROVED", approved_by="steve", approved_at=AT)]
    )
    result = verify_case(case)
    assert (
        any(c == "CHAIN_MISSING" for c, _ in result.failures) and result.exit_code == 2
    )
    missing = verify_case(case, expect_heads=[Head(1, "ab" * 32, "fedcba9876543210")])
    assert any(
        c == "CHAIN_MISSING" and "--expect-head" in m for c, m in missing.failures
    )


# --- Usage, the command, and the report view -------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "steve=SHA256:short",
        "Steve=SHA256:" + "A" * 43,
        "steve=SHA256:" + "A" * 43 + ":5-2",
    ],
)
def test_a_malformed_pin_is_a_usage_error(text):
    from vhir_cli.ledger_verify import UsageError

    with pytest.raises(UsageError):
        parse_pin(text)


def test_pins_and_heads_parse():
    fp = "SHA256:" + "A" * 43
    assert parse_pin(f"steve={fp}") == Pin("steve", fp)
    assert parse_pin(f"steve={fp}:0123456789abcdef@1-41") == Pin(
        "steve", fp, "0123456789abcdef", 1, 41
    )
    assert parse_pin(f"steve={fp}:42-") == Pin("steve", fp, None, 42, None)
    assert parse_head("7:" + "c" * 64) == Head(7, "c" * 64)


def test_review_verify_asks_for_nothing_and_exits_with_the_verdict(
    case, steve, monkeypatch, capsys
):
    from argparse import Namespace

    from vhir_cli import approval_auth
    from vhir_cli.commands.review import cmd_review

    def no_prompt(*a, **k):
        raise AssertionError("verify asked for a password")

    monkeypatch.setattr(approval_auth, "getpass_prompt", no_prompt)
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    args = Namespace(
        case=None,
        verify=True,
        mine=False,
        expect_key=None,
        expect_head=None,
        ledger=None,
    )
    with pytest.raises(SystemExit) as e:
        cmd_review(args, {"examiner": "steve"})
    assert e.value.code == 0 and "VALID" in capsys.readouterr().out
    _save(case, findings=[dict(_load(case, "findings")[0], observation="changed")])
    with pytest.raises(SystemExit) as e:
        cmd_review(args, {"examiner": "steve"})
    assert e.value.code == 2


@pytest.mark.parametrize(
    "argv",
    [["review", "--findings", "--verify", "--expect-key", "bad"],
     ["review", "--findings", "--verify", "--expcet-key", "x"],
     ["review", "--findings", "--verify", "--expect-head"]],
    ids=["malformed pin", "misspelt option", "missing value"],
)  # fmt: skip
def test_usage_errors_exit_5(case, argv, monkeypatch):
    import sys

    from vhir_cli import main as cli

    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 5


def test_review_never_exits_3_or_4():
    src = (Path(__file__).parents[1] / "src/vhir_cli/commands/review.py").read_text()
    src += (Path(__file__).parents[1] / "src/vhir_cli/ledger_verify.py").read_text()
    for code in ("exit(3)", "exit(4)"):
        assert code not in src


def test_the_report_view_shows_only_verified_approvals(case, steve):
    good, old, forged = (
        _finding(1),
        _finding(2, status="APPROVED", approved_by="steve", approved_at=AT),
        _finding(3),
    )
    _save(case, findings=[good, old, forged])
    _legacy([_legacy_line(old)])
    _approve(case, steve, good)
    findings = _load(case, "findings")
    findings[2].update(
        status="APPROVED", approved_by="steve", approved_at=AT
    )  # no decision
    _save(case, findings=findings)
    view = approved_view(case)
    assert [f["id"] for f in view["findings"]] == ["F-steve-001", "F-steve-002"]
    assert view["labels"]["F-steve-002"] == "approved under 0.6 (before signing)"
    assert view["not_verified"] == [{"id": "F-steve-003", "status": "APPROVED_NO_LINE"}]


def test_case_text_is_printed_through_the_display_rule(case, steve):
    f = _finding(n=1)
    f["id"] = "F-steve-001"
    _save(case, findings=[f])
    _approve(case, steve, f)
    findings = _load(case, "findings")
    findings[0]["observation"] = "x\x1b[2J"  # altered, and its label names the field
    _save(case, findings=findings)
    out = render(verify_case(case))
    assert "\x1b" not in out


# --- vhir report: the verified approvals and the block ------------------


def _report(case, monkeypatch, capsys, **flags):
    from argparse import Namespace

    from vhir_cli.commands.report import cmd_report

    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    base = dict(case=None, full=False, executive_summary=False, report_timeline=False,
                from_date=None, to_date=None, ioc=False, report_findings=None,
                status_brief=False, save=None)  # fmt: skip
    cmd_report(Namespace(**{**base, **flags}), {"examiner": "steve"})
    return capsys.readouterr().out


def _forged_and_signed(case, steve):
    good, forged = _finding(1), _finding(2)
    event = {"id": "T-steve-001", "timestamp": "2026-10-01T00:00:00Z", "description": "e",
             "status": "DRAFT"}  # fmt: skip
    _save(case, findings=[good, forged], timeline=[event])
    head = _approve(case, steve, good)
    findings = _load(case, "findings")
    findings[1].update(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=findings)
    return head


@pytest.mark.parametrize(
    "flags",
    [{"executive_summary": True}, {"report_timeline": True}, {"status_brief": True},
     {"report_findings": "F-steve-001,F-steve-002"}],
    ids=["executive", "timeline", "status", "findings"],
)  # fmt: skip
def test_every_text_report_ends_with_the_keys_heads_and_not_verified(
    case, steve, monkeypatch, capsys, flags
):
    head = _forged_and_signed(case, steve)
    out = _report(case, monkeypatch, capsys, **flags)
    block = out[out.index("VERIFICATION") :]
    assert NOT_ANCHORED in block and steve.fp in block
    assert f"seq {head[0]} sha256:{head[1]}" in block
    assert "F-steve-002 APPROVED_NO_LINE" in block
    assert "derived, not signed" in block


def test_a_saved_report_carries_the_block_too(case, steve, monkeypatch, capsys):
    _forged_and_signed(case, steve)
    _report(case, monkeypatch, capsys, status_brief=True, save="brief.txt")
    saved = (case / "reports" / "brief.txt").read_text()
    assert NOT_ANCHORED in saved and steve.fp in saved


def test_the_full_report_counts_only_verified_approvals(
    case, steve, monkeypatch, capsys
):
    _forged_and_signed(case, steve)
    data = json.loads(_report(case, monkeypatch, capsys, full=True))
    assert [f["id"] for f in data["approved_findings"]] == ["F-steve-001"]
    v = data["verification"]
    assert v["not_verified"] == [{"id": "F-steve-002", "status": "APPROVED_NO_LINE"}]
    (key,) = v["keys"]
    assert key["fingerprint"] == steve.fp and key["public_key"] == steve.pub
    assert (key["first_seq"], key["last_seq"]) == (1, 1)
    assert v["not_anchored"] == NOT_ANCHORED and v["heads"]


def test_the_ioc_report_lists_only_verified_findings_iocs(
    case, steve, monkeypatch, capsys
):
    good = _finding(1, iocs={"IPv4": ["10.0.0.5"]})
    forged = _finding(2, iocs={"IPv4": ["10.9.9.9"]})
    _save(case, findings=[good, forged])
    _approve(case, steve, good)
    findings = _load(case, "findings")
    findings[1].update(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=findings)
    out = _report(case, monkeypatch, capsys, ioc=True)
    assert "10.0.0.5" in out and "10.9.9.9" not in out.split("VERIFICATION")[0]


def test_a_pin_s_range_bounds_the_seqs_it_covers(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    _approve(case, steve, f2)
    result = verify_case(case, expect_keys=[steve.pin(first=1, last=1)])
    assert _status(result, "F-steve-001") == "VALID"
    assert _status(result, "F-steve-002") == "KEY_NOT_PINNED" and result.exit_code == 2
    assert verify_case(case, expect_keys=[steve.pin(first=1)]).exit_code == 0


# --- Rules on non-latest lines and across chains --------------------------


def _edit_again(case, ex, item_id, at=AT2):
    item = next(f for f in _load(case, "findings") if f["id"] == item_id)
    _sign(case, ex, [(item, "finding", "edit", "APPROVED", None)], at=at)
    findings = _load(case, "findings")
    for f in findings:
        if f["id"] == item_id:
            f["approved_at"] = at
    _save(case, findings=findings)


def test_an_unpinned_key_on_an_earlier_line_is_case_level(case, steve):
    f = _finding()
    _save(case, findings=[f])
    other = Examiner("steve")
    _approve(case, other, f)  # signed with a key steve's pins don't list
    _edit_again(case, steve, f["id"])  # decided again with the pinned key
    result = verify_case(case, expect_keys=[steve.pin()])
    assert _status(result, "F-steve-001") == "VALID"
    assert any(c == "KEY_NOT_PINNED" and "seq 1" in m for c, m in result.failures)
    assert result.exit_code == 2


def test_a_retired_key_on_an_earlier_line_of_another_item_is_case_level(case, steve):
    f1, f2, f3 = _finding(1), _finding(2), _finding(3)
    _save(case, findings=[f1, f2, f3])
    _approve(case, steve, f1)
    new = Examiner("steve")
    _, (body,) = _sign(
        case, new, [(f2, "finding", "approve", "APPROVED", None)], retired=[steve.fp]
    )
    _approve(case, steve, f3)  # the retired key signs
    findings = _load(case, "findings")
    findings[1].update(status="APPROVED", approved_by="steve", approved_at=AT)
    _save(case, findings=findings)
    _edit_again(case, new, "F-steve-003")  # finding 3 decided again with the new key
    result = verify_case(case, expect_keys=[steve.pin(), new.pin()])
    assert _status(result, "F-steve-003") == "VALID"
    assert (
        any(c == "RETIRED_KEY_USE" for c, _ in result.failures)
        and result.exit_code == 2
    )


def test_a_signed_line_for_a_missing_item_fails(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    _save(case, findings=[])
    result = verify_case(case)
    assert (
        any(c == "ITEM_MISSING" for c, _ in result.failures) and result.exit_code == 2
    )


def test_a_0_6_line_on_an_item_with_signed_lines_is_ignored(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    path = _legacy([])
    path.write_text(_legacy_line(dict(f, title="0.6 text")) + "\n")  # after genesis
    assert _status(verify_case(case), "F-steve-001") == "VALID"


def test_two_chains_deciding_one_item_differently_without_a_reference_fork(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    box = _chain_lines()
    other = Examiner("steve")
    # A second box's chain for the same case: its own genesis, rejecting finding 1.
    approved = _load(case, "findings")[0]
    body = ledger.prepare("C1", [{"item_id": f["id"], "type": "finding", "decision": "reject",
                                  "status_after": "REJECTED", "coupled_from": None,
                                  "content_snapshot": signed_text(approved, "finding")}],
                          "steve", other.pub, "cli", AT2, head=(0, ledger.genesis_prev("C1")))  # fmt: skip
    body[0]["seq"], body[0]["prev"] = 1, ledger.genesis_prev("C1")
    body[0]["genesis"] = {
        "legacy_sha256": hashlib.sha256(b"").hexdigest(),
        "legacy_bytes": 0,
    }
    line = ledger.sign_body(body[0], other.key)
    cid = ledger.chain_id(body[0])
    (_copy_dir(case) / f"{cid}.jsonl").write_text(line + "\n")
    result = verify_case(case, expect_keys=[steve.pin(), other.pin()])
    assert len(result.chains) == 2 and box
    assert _status(result, "F-steve-001") == "CHAIN_FORK" and result.exit_code == 2


def test_a_reference_to_a_head_the_named_chain_doesn_t_hold(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    cid = ledger.chain_id(ledger.body_of(json.loads(_chain_lines()[0])))
    copy = _copy_dir(case) / f"{cid}.jsonl"
    copy.write_text(ledger.chain_path("C1").read_text())
    ref = [{"chain_id": cid, "head_seq": 7, "head_hash": "ab" * 32}]
    _sign(case, steve, [(f2, "finding", "approve", "APPROVED", None)], prior=ref)
    result = verify_case(case)
    assert any(
        c == "HEAD_MISMATCH" and "references chain" in m for c, m in result.failures
    )


# --- What a file write alone must not produce -------------------------------------------------


def test_a_0_6_line_added_to_the_close_copy_after_signing_began_fails(case, steve):
    f1, forged = (
        _finding(1),
        _finding(3, status="APPROVED", approved_by="steve", approved_at=AT),
    )
    _save(case, findings=[f1])
    _approve(case, steve, f1)  # signing begins (an empty 0.6 file)
    _save(case, findings=_load(case, "findings") + [forged])
    (case / "verification.jsonl").write_text(_legacy_line(forged) + "\n")
    result = verify_case(case)
    assert (
        _status(result, "F-steve-003") == "LEGACY_AFTER_GENESIS"
        and result.exit_code == 2
    )
    assert "F-steve-003" not in [f["id"] for f in approved_view(case)["findings"]]


def test_anchor_a_close_copy_of_the_frozen_0_6_file_still_verifies(case, steve):
    old = _finding(1, status="APPROVED", approved_by="steve", approved_at=AT)
    box = _legacy([_legacy_line(old)])
    fresh = _finding(2)
    _save(case, findings=[old, fresh])
    _approve(case, steve, fresh)  # genesis freezes the 0.6 file
    (case / "verification.jsonl").write_bytes(box.read_bytes())  # 0.6 close's copy
    box.unlink()  # verified from the case's copy alone
    result = verify_case(case)
    assert (
        _status(result, "F-steve-001") == "APPROVED_UNDER_0_6" and result.exit_code == 0
    )


def test_a_second_record_with_a_signed_id_fails_the_case(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    signed = _load(case, "findings")[0]
    _save(case, findings=[dict(signed, title="FORGED"), signed])
    result = verify_case(case)
    assert (
        any(c == "DUPLICATE_ID" for c, _ in result.failures) and result.exit_code == 2
    )
    assert approved_view(case)["findings"] == []


def test_a_finding_reusing_a_signed_timeline_id_fails_the_case(case, steve):
    t = {
        "id": "T-steve-001",
        "timestamp": "2026-10-01T00:00:00Z",
        "description": "e",
        "status": "DRAFT",
    }
    _save(case, timeline=[t])
    _sign(case, steve, [(t, "timeline", "approve", "APPROVED", None)])
    _save(case, timeline=[dict(t, status="APPROVED", approved_by="steve", approved_at=AT)],
          findings=[_finding(status="APPROVED", approved_by="steve", approved_at=AT,
                             id="T-steve-001", title="FORGED")])  # fmt: skip
    result = verify_case(case)
    assert (
        any(c == "DUPLICATE_ID" for c, _ in result.failures) and result.exit_code == 2
    )
    assert approved_view(case)["findings"] == []


def test_nothing_is_shown_as_approved_while_the_case_fails(case, steve):
    _three(case, steve)
    lines = _chain_lines()
    approved = _load(case, "findings")[0]
    _sign(case, steve, [(approved, "finding", "edit", "APPROVED", None)], at=AT2)
    findings = _load(case, "findings")
    findings[0]["approved_at"] = AT2
    _save(case, findings=findings)
    lines = _chain_lines()
    first = json.loads(lines[0])
    first["sig"] = base64.b64encode(b"\0" * 64).decode()
    _write_chain(
        [json.dumps(first)] + lines[1:]
    )  # a bad signature on a non-latest line
    view = approved_view(case)
    assert view["findings"] == [] and {n["status"] for n in view["not_verified"]} == {
        "CASE_FAILURE"
    }


def _parallel_chain(case, ex: Examiner, item):
    """A second chain, written by file alone under `ex`'s key, approving `item`."""
    body = ledger.prepare("C1", [{"item_id": item["id"], "type": "finding", "decision": "approve",
                                  "status_after": "APPROVED", "coupled_from": None,
                                  "content_snapshot": signed_text(item, "finding")}],
                          ex.name, ex.pub, "cli", AT, head=(0, ledger.genesis_prev("C1")))  # fmt: skip
    body[0]["genesis"] = {
        "legacy_sha256": hashlib.sha256(b"").hexdigest(),
        "legacy_bytes": 0,
    }
    cid = ledger.chain_id(body[0])
    (_copy_dir(case) / f"{cid}.jsonl").write_text(
        ledger.sign_body(body[0], ex.key) + "\n"
    )
    findings = _load(case, "findings")
    for f in findings:
        if f["id"] == item["id"]:
            f.update(status="APPROVED", approved_by=ex.name, approved_at=AT)
    _save(case, findings=findings)


def test_a_parallel_chain_under_another_key_for_the_same_examiner_fails_unless_both_are_pinned(
    case, steve
):
    f1, forged = _finding(1), _finding(2)
    _save(case, findings=[f1, forged])
    _approve(case, steve, f1)
    other = Examiner("steve")
    _parallel_chain(case, other, forged)
    result = verify_case(case)
    assert any(c == "KEY_CHANGED" for c, _ in result.failures) and result.exit_code == 2
    assert "Key changed at seq 1 without the previous key's signature" in render(result)
    assert verify_case(case, expect_keys=[steve.pin(), other.pin()]).exit_code == 0


@pytest.mark.parametrize(
    "name", ["st\u0435ve", "Steve", "steve\u200b"], ids=["cyrillic", "upper", "zwsp"]
)
def test_a_line_whose_examiner_breaks_the_name_rule_is_malformed(case, steve, name):
    f1, forged = _finding(1), _finding(2)
    _save(case, findings=[f1, forged])
    _approve(case, steve, f1)
    _parallel_chain(case, Examiner(name), forged)  # a look-alike of steve
    result = verify_case(case)
    assert (
        any(c == "MALFORMED_LINE" and "'examiner'" in m for c, m in result.failures)
        and result.exit_code == 2
    )
    assert approved_view(case)["findings"] == []


def test_a_long_chain_beside_a_second_chain_is_ordered_without_recursion(case, steve):
    fs = [_finding(n) for n in range(1, 1101)]
    _save(case, findings=fs)
    _sign(case, steve, [(f, "finding", "approve", "APPROVED", None) for f in fs])
    done = [dict(f, status="APPROVED", approved_by="steve", approved_at=AT) for f in fs]
    _save(case, findings=done)
    last = fs[-1]
    body = ledger.prepare("C1", [{"item_id": last["id"], "type": "finding", "decision": "approve",
                                  "status_after": "APPROVED", "coupled_from": None,
                                  "content_snapshot": signed_text(last, "finding")}],
                          "steve", steve.pub, "cli", AT, head=(0, ledger.genesis_prev("C1")))  # fmt: skip
    body[0]["genesis"] = {
        "legacy_sha256": hashlib.sha256(b"").hexdigest(),
        "legacy_bytes": 0,
    }
    cid = ledger.chain_id(body[0])
    (_copy_dir(case) / f"{cid}.jsonl").write_text(
        ledger.sign_body(body[0], steve.key) + "\n"
    )
    result = verify_case(case)
    assert len(result.chains) == 2 and result.exit_code == 0
    assert _status(result, last["id"]) == "VALID"


@pytest.mark.parametrize(
    "field, value", [("seq", "2"), ("view", []), ("prior_chains", [7])]
)
def test_a_line_with_a_wrongly_typed_field_is_malformed_not_a_crash(
    case, steve, field, value
):
    _three(case, steve)
    lines = _chain_lines()
    second = json.loads(lines[1])
    second[field] = value
    _write_chain([lines[0], json.dumps(second), lines[2]])
    result = verify_case(case)
    assert (
        any(c == "MALFORMED_LINE" for c, _ in result.failures) and result.exit_code == 2
    )
    render(result)  # and it renders


def test_diverged_copies_are_judged_on_the_copy_whose_lines_verify(case, steve):
    f1, f2 = _finding(1), _finding(2)
    _save(case, findings=[f1, f2])
    _approve(case, steve, f1)
    _approve(case, steve, f2)
    good = _chain_lines()
    cid = ledger.chain_id(ledger.body_of(json.loads(good[0])))
    (_copy_dir(case) / f"{cid}.jsonl").write_text("".join(x + "\n" for x in good))
    bad = json.loads(good[1])
    bad["sig"] = base64.b64encode(b"\1" * 64).decode()
    _write_chain([good[0], json.dumps(bad)])  # the box copy's line 2 was altered
    result = verify_case(case)
    assert any(c == "CHAIN_COPY_DIVERGED" for c, _ in result.failures)
    assert _status(result, "F-steve-002") == "VALID"  # judged on the copy that verifies


def test_a_moved_case_beside_the_new_box_s_own_0_6_file_verifies(case, steve):
    old = _finding(1, status="APPROVED", approved_by="steve", approved_at=AT)
    box = _legacy([_legacy_line(old)])
    frozen = box.read_bytes()
    fresh = _finding(2)
    _save(case, findings=[old, fresh])
    _approve(case, steve, fresh)
    cid = verify_case(case).chains[0].chain_id
    # the case moved to another box, with its chain and its frozen 0.6 copy
    ledger.chain_path("C1").rename(_copy_dir(case) / f"{cid}.jsonl")
    (case / "ledger" / f"legacy-{cid}.jsonl").write_bytes(frozen)
    box.write_bytes(b'{"note": "this box\'s own older 0.6 file"}\n' + frozen)
    result = verify_case(case)
    assert (
        _status(result, "F-steve-001") == "APPROVED_UNDER_0_6" and result.exit_code == 0
    )


def test_the_report_judges_the_records_verify_read(case, steve, monkeypatch):
    import vhir_cli.ledger_verify as lv

    f = _finding()
    _save(case, findings=[f])
    _sign(case, steve, [(f, "finding", "reject", "REJECTED", None)])
    _save(case, findings=[dict(f, status="REJECTED")])
    real = lv.verify_case

    def then_flipped(*a, **k):  # a write landing just after verify read the files
        result = real(*a, **k)
        _save(
            case,
            findings=[dict(f, status="APPROVED", approved_by="steve", approved_at=AT)],
        )
        return result

    monkeypatch.setattr(lv, "verify_case", then_flipped)
    view = approved_view(case)
    assert view["findings"] == [] and view["not_verified"] == []


def test_an_entry_that_is_not_a_record_fails_and_the_report_still_renders(case, steve):
    f = _finding()
    _save(case, findings=[f])
    _approve(case, steve, f)
    _save(case, findings=_load(case, "findings") + ["stray"])
    result = verify_case(case)
    assert (
        any(c == "MALFORMED_RECORD" for c, _ in result.failures)
        and result.exit_code == 2
    )
    view = approved_view(case)
    assert view["findings"] == [] and view["not_verified"] == [
        {"id": "F-steve-001", "status": "CASE_FAILURE"}
    ]


def test_an_approved_record_with_no_verdict_and_no_duplicate_is_no_signed_line(case):
    _save(case, findings=[_finding(status="APPROVED", approved_by="steve", approved_at=AT,
                                   id="")])  # fmt: skip
    assert approved_view(case)["not_verified"] == [
        {"id": "", "status": "NO_SIGNED_LINE"}
    ]
