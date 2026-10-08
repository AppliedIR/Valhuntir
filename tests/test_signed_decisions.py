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
    # the 0.6 password and the new passphrase twice, before the item; then the final prompt
    assert prompts[:3] == ["0.6 password for steve: ", "New passphrase: ",
                           "Confirm new passphrase: "]  # fmt: skip
    assert len(prompts) == 4
    assert prompts[-1].startswith("Your new passphrase to sign 1 decisions")
    assert _signed() == [("F-steve-002", "approve")]
    assert verify_case(case).exit_code == 0
    stored = {x["id"]: x for x in json.loads((case / "findings.json").read_text())}
    assert "kept" in [
        n.get("note") for n in stored["F-steve-002"].get("examiner_notes", [])
    ]


# --- A cascaded IOC never aborts the audit trail ---------------------------------------


def test_a_cascaded_ioc_without_a_content_hash_writes_every_line_and_log_entry(case):
    """The IOC record forensic-mcp writes carries no content_hash; reading it
    raised KeyError and aborted the audit trail before anything was written."""
    assert "content_hash" not in json.loads((case / "iocs.json").read_text())[0]
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    assert [i for i, _ in _signed()] == ["F-steve-001", "T-steve-001", "IOC-steve-001"]
    log = [json.loads(x) for x in (case / "approvals.jsonl").read_text().splitlines()]
    assert [(e["item_id"], e["action"]) for e in log] == [
        ("F-steve-001", "APPROVED"), ("T-steve-001", "APPROVED"),
        ("IOC-steve-001", "APPROVED"),
    ]  # fmt: skip
    assert log[2]["coupled_from"] == "F-steve-001"


# --- The checks that can fail run before any item is shown -------------------------------------


def _break(case, problem):
    if problem == "no credential":
        keys.keys_path("steve").unlink()
    elif problem == "lockout":
        for _ in range(approval_auth._MAX_PASSWORD_ATTEMPTS):
            approval_auth._record_failure("steve")
    else:
        keys.keys_path("steve").write_text('{"schema": 3}')


def _path(case, path, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    if path == "ids":
        return lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    if path == "interactive":
        return lambda: A._interactive_review(case, IDENT, case / "cfg")
    if path == "review":
        (case / "pending-reviews.json").write_text(json.dumps({"case_id": "C-9", "items": [
            {"id": "F-steve-002", "type": "finding", "action": "approve", "staged_by": "steve"}
        ]}))  # fmt: skip
        return lambda: A._review_mode(case, IDENT, case / "cfg")
    if path == "reattest":
        approve_under_0_6(case, {"F-steve-002"}, "steve", NOW)
        return lambda: A.cmd_approve(
            Namespace(
                case=None, ids=["F-steve-002"], review=False, reattest=True, all=False
            ),
            IDENT,
        )
    return lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg",
                                       decision="reject")  # fmt: skip


@pytest.mark.parametrize("problem", ["no credential", "lockout", "invalid keys file"])
@pytest.mark.parametrize("path", ["ids", "interactive", "review", "reattest", "reject"])
def test_every_path_refuses_before_the_first_item_is_shown(
    case, monkeypatch, capsys, path, problem
):
    run = _path(case, path, monkeypatch)
    _break(case, problem)
    asked = []
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": asked.append(p))
    assert _run(run) == 1
    out = capsys.readouterr().out
    assert "Other" not in out and "F-steve-002]" not in out  # nothing displayed
    assert asked == [] and _signed() == []


def test_with_nothing_to_decide_nothing_is_checked_or_prompted(
    case, monkeypatch, capsys
):
    keys.keys_path("steve").unlink()  # no credential either
    asked = []
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": asked.append(p))
    A._approve_specific(case, ["F-nobody-001"], IDENT, case / "cfg")
    out = capsys.readouterr()
    assert "No items to approve." in out.out and "--upgrade-key" in out.out
    assert asked == [] and "No passphrase" not in out.err


def test_ctrl_c_at_the_final_prompt_signs_and_saves_nothing(case, monkeypatch, capsys):
    def interrupt(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr(approval_auth, "getpass_prompt", interrupt)
    assert (
        _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
        == 1
    )
    assert "Nothing was signed and nothing was saved." in capsys.readouterr().err
    assert _signed() == [] and not (case / "pending-reviews.json").exists()
    assert _status(case, "findings.json", "F-steve-002") == "DRAFT"


def test_a_cascaded_ioc_is_shown_with_its_signed_fields_before_the_prompt(case, capsys):
    A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    out = capsys.readouterr().out
    shown = out[out.index("decided with them") : out.index("To be signed")]
    for line in ("[IOC-steve-001]  10.0.0.7", "Value: 10.0.0.7", "Type: ipv4",
                 "Category: network", "Tags:",
                 "Sources, sightings, confidence, MITRE: derived, not signed",
                 "cascade from F-steve-001: approve"):  # fmt: skip
        assert line in shown, line


def test_an_unsigned_save_carries_what_was_shown(case, monkeypatch):
    from vhir_cli.case_io import compute_content_hash

    shown = json.loads((case / "findings.json").read_text())[1]
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": "wrong")
    _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg",
                                     decision="reject", reason="noise"))  # fmt: skip
    (entry,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert entry["type"] == "finding" and entry["action"] == "reject"
    assert entry["rejection_reason"] == "noise"
    assert entry["content_hash_at_review"] == compute_content_hash(shown)
    assert set(entry["saved_unsigned"]) == {"at", "reason"}


# --- What is displayed is what is signed ------------------------------------------------


def test_a_staged_edit_is_shown_as_it_will_be_signed(case, monkeypatch, capsys):
    (case / "pending-reviews.json").write_text(json.dumps({"case_id": "C-9", "items": [{
        "id": "F-steve-002", "type": "finding", "action": "approve", "staged_by": "steve",
        "modifications": {
            "title": {"original": "Other", "modified": "REPLACED-TITLE"},
            "context": {"original": None, "modified": "NEW-CONTEXT"},
        },
    }]}))  # fmt: skip
    A._review_mode(case, IDENT, case / "cfg", show_signed=True)
    out = capsys.readouterr().out
    assert "- Other" in out and "+ REPLACED-TITLE" in out and "+ NEW-CONTEXT" in out
    assert '"title": "REPLACED-TITLE"' in out  # --show-signed: the body signed
    (line,) = [o for _, _, o in ledger.read_lines(ledger.chain_path("C-9")) if o]
    snap = json.loads(line["content_snapshot"])
    assert (snap["title"], snap["context"]) == ("REPLACED-TITLE", "NEW-CONTEXT")


def test_a_staged_timestamp_edit_is_shown_before_it_is_signed(case, capsys):
    (case / "pending-reviews.json").write_text(json.dumps({"case_id": "C-9", "items": [{
        "id": "T-steve-001", "type": "timeline", "action": "approve", "staged_by": "steve",
        "modifications": {"timestamp": {"original": "2026-10-01T00:00:00Z",
                                        "modified": "2026-09-30T23:00:00Z"}},
    }]}))  # fmt: skip
    A._review_mode(case, IDENT, case / "cfg")
    out = capsys.readouterr().out
    assert "- 2026-10-01T00:00:00Z" in out and "+ 2026-09-30T23:00:00Z" in out


# --- Review removes exactly the entries it signed ---------------------------------------


def test_a_discarded_review_entry_stays_and_another_examiner_s_is_untouched(
    case, monkeypatch, capsys
):
    alice = {
        "id": "F-steve-001",
        "type": "finding",
        "action": "approve",
        "staged_by": "alice",
    }
    mine = {
        "id": "F-steve-002",
        "type": "finding",
        "action": "approve",
        "staged_by": "steve",
    }
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-9", "items": [alice, mine]})
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")  # include alice's

    def change_both_then_type(prompt=""):
        fs = json.loads((case / "findings.json").read_text())
        for f in fs:
            f["observation"] = "changed by someone else"
        (case / "findings.json").write_text(json.dumps(fs))
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", change_both_then_type)
    assert _run(lambda: A._review_mode(case, IDENT, case / "cfg")) == 1
    assert _signed() == []
    left = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert [e["staged_by"] for e in left] == ["alice", "steve"]
    assert left[0] == alice  # another examiner's entry: byte for byte
    assert "review_again" in left[1]


# --- The commit writes only the decision onto the reloaded record ---------------------------


def test_fields_written_during_the_prompt_survive_an_approve(case, monkeypatch):
    def add_provenance_then_type(prompt=""):
        fs = json.loads((case / "findings.json").read_text())
        fs[1]["provenance"] = {"summary": "MCP"}
        fs[1]["examiner_notes"] = [{"note": "from the portal"}]
        (case / "findings.json").write_text(json.dumps(fs))
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", add_provenance_then_type)
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg", note="mine")
    f = {x["id"]: x for x in json.loads((case / "findings.json").read_text())}[
        "F-steve-002"
    ]
    assert f["status"] == "APPROVED" and f["provenance"] == {"summary": "MCP"}
    assert [n.get("note") for n in f["examiner_notes"]] == ["from the portal", "mine"]
    assert verify_case(case).exit_code == 0


def test_an_ioc_s_sightings_added_during_the_prompt_survive_its_reject(
    case, monkeypatch
):
    def add_sighting_then_type(prompt=""):
        iocs = json.loads((case / "iocs.json").read_text())
        iocs[0]["sightings"] = [{"host": "h1"}, {"host": "h2"}]
        iocs[0]["source_findings"] = ["F-steve-001", "F-steve-002"]
        (case / "iocs.json").write_text(json.dumps(iocs))
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", add_sighting_then_type)
    A._approve_specific(case, ["IOC-steve-001"], IDENT, case / "cfg", decision="reject")
    ioc = json.loads((case / "iocs.json").read_text())[0]
    assert ioc["status"] == "REJECTED" and len(ioc["sightings"]) == 2
    assert ioc["source_findings"] == ["F-steve-001", "F-steve-002"]


# --- No loss on any exit path -------------------------------------------------------------------


def _todo_session(case, monkeypatch):
    """Interactive: approve F-steve-001, a TODO on F-steve-002, quit."""
    replies = iter(["a", "t", "check the other host", "", "high", "q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))
    return lambda: A._interactive_review(case, IDENT, case / "cfg")


def _todos(case):
    p = case / "todos.json"
    return json.loads(p.read_text()) if p.exists() else []


def test_a_todo_is_created_when_a_decision_is_discarded(case, monkeypatch):
    run = _todo_session(case, monkeypatch)

    def change_then_type(prompt=""):
        fs = json.loads((case / "findings.json").read_text())
        fs[0]["title"] = "changed"
        (case / "findings.json").write_text(json.dumps(fs))
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", change_then_type)
    assert _run(run) == 1 and _signed() == []
    assert [t["description"] for t in _todos(case)] == ["check the other host"]


def test_a_todo_is_saved_with_the_decisions_when_nothing_can_be_signed(
    case, monkeypatch
):
    run = _todo_session(case, monkeypatch)
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": "wrong")
    assert _run(run) == 1 and _todos(case) == []
    saved = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert [(e["id"], e["action"]) for e in saved] == [
        ("F-steve-001", "approve"), ("F-steve-002", "todo")
    ]  # fmt: skip
    assert saved[1]["todo_description"] == "check the other host"
    approval_auth._clear_failures("steve")
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": PASSPHRASE)
    A._review_mode(
        case, IDENT, case / "cfg"
    )  # --review creates it and signs F-steve-001
    assert [t["description"] for t in _todos(case)] == ["check the other host"]
    assert _signed() == [("F-steve-001", "approve"), ("T-steve-001", "approve"),
                         ("IOC-steve-001", "approve")]  # fmt: skip


@pytest.mark.parametrize(
    "failure", ["keys file damaged", "a non-record entry", "no lock folder"]
)
def test_an_error_after_the_review_saves_the_decisions_and_never_tracebacks(
    case, monkeypatch, capsys, failure
):
    def at_prompt(prompt=""):
        if failure == "keys file damaged":
            keys.keys_path("steve").write_text('{"schema": 3}')
        elif failure == "a non-record entry":
            fs = json.loads((case / "findings.json").read_text())
            (case / "findings.json").write_text(json.dumps(fs + [None]))
        else:
            monkeypatch.setattr(ledger, "case_lock", _missing_lock_dir)
        return PASSPHRASE

    monkeypatch.setattr(approval_auth, "getpass_prompt", at_prompt)
    code = _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
    err = capsys.readouterr().err
    if (
        failure == "a non-record entry"
    ):  # ignored, never a crash: the decision is signed
        assert code == 0 and _signed() == [("F-steve-002", "approve")]
        return
    assert code == 1 and _signed() == [] and "Traceback" not in err
    (entry,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert entry["id"] == "F-steve-002" and "saved, unsigned" in err


def _missing_lock_dir(case_id, *a, **k):
    raise ledger.LockDirMissing(
        "the case lock directory is missing; run `vhir update` to create it"
    )


def test_a_corrupt_pending_file_is_set_aside_not_overwritten(case, monkeypatch, capsys):
    path = case / "pending-reviews.json"
    path.write_text('{"items": [{"id": "F-steve-001", "staged_by": "bob"}, junk')
    before = path.read_bytes()
    monkeypatch.setattr(approval_auth, "getpass_prompt", lambda p="": "wrong")
    _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
    (aside,) = case.glob("pending-reviews.json.corrupt-*")
    assert aside.read_bytes() == before
    assert [e["id"] for e in json.loads(path.read_text())["items"]] == ["F-steve-002"]
    assert "set aside, unchanged" in capsys.readouterr().err


def test_an_id_named_twice_is_signed_once(case):
    A._approve_specific(case, ["F-steve-002", "F-steve-002"], IDENT, case / "cfg")
    assert _signed() == [("F-steve-002", "approve")]


# --- What a failure leaves (CR's five probes) -----------------------------------------


class _FaultyOs:
    """The os module as ledger.py sees it, with one call made to fail."""

    def __init__(self, fail_on: str, error: BaseException, writes_before: int = 0):
        import os as real

        self._os, self._fail_on, self._error = real, fail_on, error
        self._writes_before = writes_before

    def __getattr__(self, name):
        if name == "fdopen" and self._fail_on == "write":
            real = self._os.fdopen

            def fdopen(*a, **k):
                f = real(*a, **k)
                left = [self._writes_before]
                write = f.write

                def failing(text):
                    if left[0] <= 0:
                        raise self._error
                    left[0] -= 1
                    return write(text)

                f.write = failing
                return f

            return fdopen
        if name == self._fail_on:

            def fail(*a, **k):
                raise self._error

            return fail
        return getattr(self._os, name)


def _chain_bytes(case_id="C-9"):
    path = ledger.chain_path(case_id)
    return path.read_bytes() if path.exists() else b""


@pytest.mark.parametrize("where", ["fsync", "write"])
def test_a_write_that_fails_part_way_leaves_the_chain_as_it_was(
    case, monkeypatch, capsys, where
):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")  # one line before
    before = _chain_bytes()
    # approving F-steve-001 writes three lines (its event and IOC cascade);
    # the write fails after the first, or at the fsync
    monkeypatch.setattr(
        ledger, "os", _FaultyOs(where, OSError("disk full"), writes_before=2)
    )
    code = _run(lambda: A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg"))
    assert code == 1 and _chain_bytes() == before  # cut back: no part of it left
    for name, item_id in (("findings.json", "F-steve-001"), ("timeline.json", "T-steve-001"),
                          ("iocs.json", "IOC-steve-001")):  # fmt: skip
        assert _status(case, name, item_id) == "DRAFT"
    (entry,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert entry["id"] == "F-steve-001"  # kept; its cascades are planned again
    assert "Nothing was signed" in capsys.readouterr().err
    import os as real_os

    monkeypatch.setattr(
        ledger, "os", real_os
    )  # only this patch: the box stays redirected
    assert verify_case(case).exit_code == 0


def test_ctrl_c_inside_the_write_leaves_the_chain_as_it_was(case, monkeypatch):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    before = _chain_bytes()
    monkeypatch.setattr(ledger, "os", _FaultyOs("fsync", KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        A._approve_specific(case, ["F-steve-001"], IDENT, case / "cfg")
    assert _chain_bytes() == before


def test_a_write_that_can_t_be_cut_back_says_so(case, monkeypatch, capsys):
    import builtins

    real_open = builtins.open

    def no_truncate(path, mode="r", *a, **k):
        if mode == "r+b":
            raise PermissionError("read-only")
        return real_open(path, mode, *a, **k)

    monkeypatch.setattr(ledger, "os", _FaultyOs("fsync", OSError("disk full")))
    monkeypatch.setattr(builtins, "open", no_truncate)
    code = _run(lambda: A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg"))
    monkeypatch.setattr(builtins, "open", real_open)
    assert code == 1
    assert "couldn't be cut back" in capsys.readouterr().err


def test_a_saved_todo_survives_a_later_saved_decision_for_the_same_item(case):
    from vhir_cli.decide import Decision, save_unsigned

    f = json.loads((case / "findings.json").read_text())[1]
    save_unsigned(case, "steve", [], "attempts",
                  [{"description": "check", "related_findings": ["F-steve-002"]}])  # fmt: skip
    save_unsigned(case, "steve", [Decision(f, "finding", "approve", "APPROVED", loaded=f)],
                  "attempts")  # fmt: skip
    items = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert [(e["id"], e["action"]) for e in items] == [
        ("F-steve-002", "todo"), ("F-steve-002", "approve")
    ]  # fmt: skip


def test_a_todo_that_can_t_be_written_is_kept_and_the_exit_is_1(
    case, monkeypatch, capsys
):
    replies = iter(["a", "t", "check the other host", "", "high", "q"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(replies))

    def broken(*a, **k):
        raise OSError("todos.json is read-only")

    monkeypatch.setattr(A, "_create_todos", broken)
    assert _run(lambda: A._interactive_review(case, IDENT, case / "cfg")) == 1
    assert ("F-steve-001", "approve") in _signed()  # the signed decisions stand
    (todo,) = json.loads((case / "pending-reviews.json").read_text())["items"]
    assert (todo["id"], todo["action"]) == ("F-steve-002", "todo")
    err = capsys.readouterr().err
    assert "Your TODOs weren't created" in err and "Nothing was signed" not in err
