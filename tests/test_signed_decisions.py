"""Every CLI decision is signed, and what the writer signs, verify accepts.

The real approve, reject, re-attest and review paths run on a scratch case
with an enrolled examiner; the verdict is the real `verify_case`. A failure
the passphrase prompt can't fix saves the decisions unsigned, and the
activity log is best effort: it never undoes or stops a signed decision.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from vhir_cli import approval_auth, keys, ledger
from vhir_cli.commands import approve as A
from vhir_cli.commands import reject as RJ
from vhir_cli.ledger_verify import approved_view, verify_case

from .signing import PASSPHRASE, approve_under_0_6, enrol

IDENT = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}
NOW = "2026-10-08T09:00:00+00:00"


def _items():
    f = {"id": "F-steve-001", "title": "PsExec", "observation": "o", "interpretation": "i",
         "confidence": "MEDIUM", "status": "DRAFT", "timeline_event_id": "T-steve-001",
         "iocs": ["10.0.0.7"]}  # fmt: skip
    x = {"id": "F-steve-002", "title": "Other", "observation": "o", "interpretation": "i",
         "confidence": "LOW", "status": "DRAFT"}  # fmt: skip
    t = {"id": "T-steve-001", "timestamp": "2026-10-01T00:00:00Z", "description": "PsExec",
         "auto_created_from": "F-steve-001", "status": "DRAFT"}  # fmt: skip
    ioc = {"id": "IOC-steve-001", "value": "10.0.0.7", "type": "ipv4", "category": "network",
           "description": "", "status": "DRAFT", "source_findings": ["F-steve-001"],
           "manually_reviewed": False, "tags": [], "mitre_techniques": []}  # fmt: skip
    return f, x, t, ioc


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-9"
    d.mkdir()
    (d / "CASE.yaml").write_text("case_id: C-9\nstatus: open\n")
    f, x, t, ioc = _items()
    (d / "findings.json").write_text(json.dumps([f, x]))
    (d / "timeline.json").write_text(json.dumps([t]))
    (d / "iocs.json").write_text(json.dumps([ioc]))
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setattr(approval_auth, "_LOCKOUT_FILE", tmp_path / "lockout")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    enrol("steve")
    return d


def _status(d, name, item_id):
    return {x["id"]: x for x in json.loads((d / name).read_text())}[item_id]["status"]


def _signed(case_id="C-9"):
    return [
        (o["item_id"], o["decision"])
        for _, _, o in ledger.read_lines(ledger.chain_path(case_id))
        if o
    ]


def _run(fn):
    try:
        fn()
    except SystemExit as e:
        return e.code
    return 0


# --- What the writer signs, verify accepts -----------------------------------------


def test_approve_and_reject_with_their_cascades_all_verify(case):
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg", decision="reject",
                        reason="noise")  # fmt: skip
    assert _signed() == [
        ("F-steve-001", "approve"), ("T-steve-001", "approve"),
        ("IOC-steve-001", "approve"), ("F-steve-002", "reject"),
    ]  # fmt: skip
    result = verify_case(case)
    assert {v.item_id: v.status for v in result.items} == {
        "F-steve-001": "VALID", "T-steve-001": "VALID",
        "IOC-steve-001": "VALID", "F-steve-002": "VALID",
    }  # fmt: skip
    assert result.exit_code == 0
    view = approved_view(case)
    assert [x["id"] for x in view["findings"]] == ["F-steve-001"]
    assert [x["id"] for x in view["timeline"]] == ["T-steve-001"]
    assert [x["id"] for x in view["iocs"]] == ["IOC-steve-001"]


def test_rejecting_an_approved_finding_and_an_ioc_is_signed(case):
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    args = Namespace(ids=["F-steve-001", "IOC-steve-001"], reason="wrong host", case=None,
                     review=False, analyst=None)  # fmt: skip
    RJ.cmd_reject(args, IDENT)
    assert _status(case, "findings.json", "F-steve-001") == "REJECTED"
    assert _status(case, "iocs.json", "IOC-steve-001") == "REJECTED"
    assert ("F-steve-001", "reject") in _signed() and (
        "IOC-steve-001",
        "reject",
    ) in _signed()
    assert verify_case(case).exit_code == 0


def test_the_prompt_comes_last_after_every_cascade_is_listed(case, monkeypatch, capsys):
    prompts = []

    def typed(prompt=""):
        prompts.append((prompt, capsys.readouterr().out))
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", typed)
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    ((prompt, before),) = prompts
    assert prompt == "Password to sign 3 decisions (1 direct, 2 cascaded): "
    assert "cascade from F-steve-001: approve" in before
    assert before.rstrip().endswith(
        "To be signed: F-steve-001, T-steve-001, IOC-steve-001"
    )


def test_show_signed_prints_the_signed_view(case, capsys):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg", show_signed=True)
    assert '  Signed view: {"confidence": "LOW"' in capsys.readouterr().out


# --- A prompt that can't succeed saves the work unsigned -------------------------------


def test_used_up_attempts_save_the_decisions_unsigned(case, monkeypatch, capsys):
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": "wrong")
    code = _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg",
                                            note="checked the logs"))  # fmt: skip
    assert code == 1 and _signed() == []
    assert _status(case, "findings.json", "F-steve-002") == "DRAFT"
    (entry,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert (entry["id"], entry["action"], entry["staged_by"]) == (
        "F-steve-002",
        "approve",
        "steve",
    )
    assert entry["note"] == "checked the logs"
    assert entry["saved_unsigned"]["reason"] == "attempts"
    assert "saved, unsigned, to pending-reviews.json" in capsys.readouterr().err


def test_a_key_that_won_t_unwrap_saves_the_decisions_and_isn_t_a_failed_attempt(case):
    data = keys.load("steve")
    keys.active(data)["wrapped_private"] = keys.b64(
        b"\0" * 60
    )  # the verifier still matches
    keys.save("steve", data)
    code = _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
    assert code == 1 and _signed() == []
    (entry,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert entry["saved_unsigned"]["reason"] == "KEY_UNWRAP_FAILED"
    assert approval_auth._recent_failure_count("steve") == 0


def test_saved_decisions_are_signed_by_review_once_the_prompt_succeeds(
    case, monkeypatch
):
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": "wrong")
    _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
    approval_auth._clear_failures("steve")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    A._review_mode(case, IDENT, case / "cfg")
    assert _signed() == [("F-steve-002", "approve")]
    assert json.loads((case / "pending-reviews.json").read_text())["items"] == []


# --- The activity log is best effort ---------------------------------------------------


def test_a_failing_activity_log_never_stops_a_signed_decision(
    case, monkeypatch, capsys
):
    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr("vhir_cli.decide.write_approval_log", broken)
    code = _run(lambda: A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg"))
    assert code == 0
    assert _status(case, "findings.json", "F-steve-001") == "APPROVED"
    assert _status(case, "timeline.json", "T-steve-001") == "APPROVED"
    assert len(_signed()) == 3 and verify_case(case).exit_code == 0
    err = capsys.readouterr().err
    assert (
        "activity log (approvals.jsonl, unsigned) wasn't written for: F-steve-001"
        in err
    )
    assert "The signed decisions stand." in err


# --- Re-attest ---------------------------------------------------------------------------


def test_reattest_signs_a_0_6_approval_and_one_with_no_record(case, monkeypatch):
    approve_under_0_6(case, {"F-steve-002"}, "steve", NOW)
    findings = json.loads((case / "findings.json").read_text())
    findings[0].update(
        status="APPROVED", approved_by="eve", approved_at=NOW
    )  # no record
    (case / "findings.json").write_text(json.dumps(findings))
    before = {v.item_id: v.status for v in verify_case(case).items}
    assert before == {
        "F-steve-001": "APPROVED_NO_LINE",
        "F-steve-002": "APPROVED_UNDER_0_6",
    }
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    A.cmd_approve(
        Namespace(case=None, ids=[], review=False, reattest=True, all=True), IDENT
    )
    result = verify_case(case)
    assert {v.item_id: v.status for v in result.items} == {
        "F-steve-001": "VALID", "F-steve-002": "VALID"
    }  # fmt: skip
    labels = {v.item_id: v.label for v in result.items}
    assert "legacy approval by steve" in labels["F-steve-002"]
    stored = {x["id"]: x for x in json.loads((case / "findings.json").read_text())}
    assert stored["F-steve-001"]["approved_by"] == "steve"  # the re-attester, now
    assert stored["F-steve-002"]["approved_by"] == "steve"
    assert result.exit_code == 0


def test_reattest_refuses_an_item_that_already_has_a_signed_approval(case, capsys):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    A.cmd_approve(
        Namespace(
            case=None, ids=["F-steve-002"], review=False, reattest=True, all=False
        ),
        IDENT,
    )
    assert "F-steve-002: not re-attestable (VALID)" in capsys.readouterr().err
    assert _signed() == [("F-steve-002", "approve")]


# --- Review: whose entries are signed -------------------------------------------------------


def _delta(case, *entries):
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-9", "items": list(entries)})
    )


def test_review_signs_your_entries_and_asks_about_anyone_else_s(
    case, monkeypatch, capsys
):
    _delta(
        case,
        {
            "id": "F-steve-002",
            "type": "finding",
            "action": "approve",
            "staged_by": "steve",
        },
        {
            "id": "F-steve-001",
            "type": "finding",
            "action": "reject",
            "staged_by": "alice",
        },
    )
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "n")
    A._review_mode(case, IDENT, case / "cfg")
    assert asked == ["  Include F-steve-001 and sign as steve? [y/N] "]
    assert _signed() == [("F-steve-002", "approve")]
    assert "Staged by alice; not included unless you say so" in capsys.readouterr().out
    left = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert [e["staged_by"] for e in left] == [
        "alice"
    ]  # only the signed entry is removed


def test_review_refuses_one_item_selected_twice(case, capsys):
    _delta(
        case,
        {
            "id": "F-steve-002",
            "type": "finding",
            "action": "approve",
            "staged_by": "steve",
        },
        {
            "id": "F-steve-002",
            "type": "finding",
            "action": "reject",
            "staged_by": "steve",
        },
    )
    assert _run(lambda: A._review_mode(case, IDENT, case / "cfg")) == 1
    assert "DUPLICATE_ITEM: F-steve-002 selected twice; nothing was signed." in (
        capsys.readouterr().err
    )
    assert _signed() == []


def test_a_review_file_left_by_0_6_is_merged_and_kept(case, monkeypatch):
    (case / "pending-reviews.processing").write_text(
        json.dumps(
            {"items": [{"id": "F-steve-002", "type": "finding", "action": "approve"}]}
        )
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")  # include it
    A._review_mode(case, IDENT, case / "cfg")
    assert _signed() == [("F-steve-002", "approve")]
    assert not (case / "pending-reviews.processing").exists()
    assert len(list(case.glob("pending-reviews.processing.merged-*"))) == 1


# --- The other writers of the case files -------------------------------------------------------


def test_import_takes_the_case_lock_and_keeps_a_rejected_item(case, monkeypatch):
    from vhir_cli.case_io import import_bundle

    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg", decision="reject")
    real, held = ledger.case_lock, []

    def recording(case_id, *a, **k):
        held.append(case_id)
        return real(case_id, *a, **k)

    monkeypatch.setattr(ledger, "case_lock", recording)
    result = import_bundle(
        case,
        {
            "findings": [
                {
                    "id": "F-steve-002",
                    "title": "replaced",
                    "modified_at": "2099-01-01T00:00:00+00:00",
                }
            ]
        },
    )
    assert held == ["C-9"] and result["findings"]["protected"] == 1  # fmt: skip
    assert _status(case, "findings.json", "F-steve-002") == "REJECTED"


def test_migrate_refuses_a_case_with_signed_decisions(case, capsys):
    from vhir_cli.commands.migrate import cmd_migrate

    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    (case / "examiners" / "steve").mkdir(parents=True)
    before = (case / "findings.json").read_bytes()
    code = _run(lambda: cmd_migrate(Namespace(case=None, examiner="steve"), IDENT))
    assert code == 1 and (case / "findings.json").read_bytes() == before
    assert "has signed decisions" in capsys.readouterr().err


# --- A 0.6 credential is upgraded inline at the first signed decision ----------------------------


def test_a_short_0_6_password_is_replaced_inline_and_the_decision_signed(
    case, monkeypatch, capsys
):
    import hashlib

    keys.keys_path("steve").unlink()  # this examiner has only the 0.6 credential
    salt = bytes(range(32))
    approval_auth._PASSWORDS_DIR.mkdir(parents=True, exist_ok=True)
    (approval_auth._PASSWORDS_DIR / "steve.json").write_text(json.dumps({
        "hash": hashlib.pbkdf2_hmac("sha256", b"abc12", salt, 600_000).hex(),
        "salt": salt.hex()}))  # fmt: skip
    answers = iter(["abc12", "plum orbit lantern 2026", "plum orbit lantern 2026",
                    "plum orbit lantern 2026"])  # fmt: skip
    prompts = []
    monkeypatch.setattr(approval_auth, "getpass_prompt",
                        lambda p="": prompts.append(p) or next(answers))  # fmt: skip
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg", note="kept")
    assert prompts[-1].startswith("Your new passphrase to sign 1 decisions")
    assert _signed() == [("F-steve-002", "approve")]
    assert verify_case(case).exit_code == 0
    stored = {x["id"]: x for x in json.loads((case / "findings.json").read_text())}
    assert "kept" in [
        n.get("note") for n in stored["F-steve-002"].get("examiner_notes", [])
    ]
