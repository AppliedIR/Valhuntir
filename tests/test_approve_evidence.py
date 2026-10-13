"""The examiner sees a finding's evidence before the password prompt.

`vhir approve` (interactive) and `vhir approve --review` asked for the
password, and took each decision, without ever printing a finding's
artifacts or the timeline events approved with it. Both now print them for
every pending item before the prompt; interactive decisions then show a
short header. `vhir approve <IDs>` is unchanged.

Artifact text is evidence and the finding's text is the model's, so both
print escaped, and content lines carry a gutter.
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands.approve import _display_item, cmd_approve

from .signing import PASSPHRASE, enrol

IDENT = {"examiner": "analyst1", "os_user": "u", "examiner_source": "flag"}
ESC = "\x1b]0;owned\x07\x1b[2J"
ARTIFACTS = [
    {
        "source": "/cases/C-1/evidence/Security.evtx",
        "extraction": "EvtxECmd -f Security.evtx",
        "audit_id": "sift-tester-20261007-001",
        "content": "4624 logon type 10\nfrom 10.0.0.99",
    },
    {
        "source": "/cases/C-1/evidence/PSExec.pf",
        "extraction": "PECmd -f PSEXESVC.EXE-1.pf",
        "audit_id": "sift-tester-20261007-002",
        "content": "PSEXESVC.EXE run count 3\nlast run 2026-10-01 03:12",
    },
]


def _finding(fid="F-tester-001", **extra):
    item = {
        "id": fid,
        "status": "DRAFT",
        "title": "PsExec lateral movement",
        "confidence": "MEDIUM",
        "observation": "PSEXESVC ran on wkstn05",
        "interpretation": "Remote execution",
        "type": "finding",
        "audit_ids": ["sift-tester-20261007-001"],
        "staged": "2026-10-07T12:00:00Z",
        "modified_at": "2026-10-07T12:00:00Z",
        "created_by": "tester",
        "artifacts": ARTIFACTS,
        "timeline_event_id": "T-tester-001",  # the signed link to its event
    }
    item.update(extra)
    return item


EVENT = {
    "id": "T-tester-001",
    "status": "DRAFT",
    "timestamp": "2026-10-01T03:12:00Z",
    "description": "PSEXESVC service installed",
    "auto_created_from": "F-tester-001",
    "staged": "2026-10-07T12:00:00Z",
    "created_by": "tester",
}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    (d / "evidence.json").write_text('{"files": []}')
    (d / "todos.json").write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    enrol("analyst1")
    return d


class _Prompt(BaseException):  # not an error: the tail keeps work on any Exception
    pass


def _until_prompt(monkeypatch, capsys, args) -> str:
    """Everything printed before the passphrase prompt (asked last, after
    every item is approved at its own prompt)."""

    def prompt(*a, **k):
        raise _Prompt

    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", prompt)
    monkeypatch.setattr("builtins.input", lambda prompt="": "a")
    with pytest.raises(_Prompt):
        cmd_approve(args, IDENT)
    return capsys.readouterr().out


def _stage(case, findings, events=(), review=None):
    save_findings(case, findings)
    save_timeline(case, list(events))
    if review is not None:
        (case / "pending-reviews.json").write_text(
            json.dumps({"case_id": "C-1", "items": review})
        )


INTERACTIVE = Namespace(case=None, ids=[], review=False)
REVIEW = Namespace(case=None, ids=[], review=True)
APPROVE = [
    {
        "id": "F-tester-001",
        "type": "finding",
        "action": "approve",
        "staged_by": "analyst1",
    }
]


def _artifact_lines_present(out: str) -> None:
    for art in ARTIFACTS:
        for field in ("source", "extraction", "audit_id"):
            assert art[field] in out, (field, out)
        for line in art["content"].split("\n"):
            assert f"│ {line}" in out, (line, out)


def test_review_shows_every_artifact_before_the_prompt(case, monkeypatch, capsys):
    _stage(case, [_finding()], review=APPROVE)
    _artifact_lines_present(_until_prompt(monkeypatch, capsys, REVIEW))


def test_review_shows_the_events_approved_with_it(case, monkeypatch, capsys):
    _stage(case, [_finding()], [EVENT], review=APPROVE)
    out = _until_prompt(monkeypatch, capsys, REVIEW)
    assert "T-tester-001" in out and "PSEXESVC service installed" in out
    assert "2026-10-01T03:12:00Z" in out


def test_a_review_reject_shows_its_signed_artifacts_but_no_approved_events(
    case, monkeypatch, capsys
):
    """What is displayed is what is signed: a reject signs the finding's
    artifacts too; only an approve lists the events approved with it."""
    reject = [
        {
            "id": "F-tester-001",
            "type": "finding",
            "action": "reject",
            "staged_by": "analyst1",
        }
    ]
    _stage(case, [_finding()], [EVENT], review=reject)
    out = _until_prompt(monkeypatch, capsys, REVIEW)
    assert "approved with it" not in out
    _artifact_lines_present(out)


def test_interactive_shows_every_item_s_evidence_before_the_prompt(
    case, monkeypatch, capsys
):
    _stage(case, [_finding()], [EVENT])
    out = _until_prompt(monkeypatch, capsys, INTERACTIVE)
    _artifact_lines_present(out)
    assert "PSEXESVC ran on wkstn05" in out  # the observation too


def test_interactive_findings_only_shows_the_events_approved_with_it(
    case, monkeypatch, capsys
):
    _stage(case, [_finding()], [EVENT])
    args = Namespace(case=None, ids=[], review=False, findings_only=True)
    out = _until_prompt(monkeypatch, capsys, args)
    assert "Timeline events approved with it" in out
    assert "[T-tester-001] 2026-10-01T03:12:00Z  PSEXESVC service installed" in out


def test_each_interactive_decision_shows_a_short_header(case, monkeypatch, capsys):
    _stage(case, [_finding()])
    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", lambda *a: PASSPHRASE)
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    cmd_approve(INTERACTIVE, IDENT)
    out = capsys.readouterr().out
    after = out.split("── [F-tester-001]", 1)[1]
    assert after.startswith("  PsExec lateral movement — 2 artifact(s)")
    assert "│ 4624 logon type 10" not in after  # not shown twice


@pytest.mark.parametrize("args", [INTERACTIVE, REVIEW], ids=["interactive", "review"])
def test_control_sequences_in_evidence_print_escaped(case, monkeypatch, capsys, args):
    art = {**ARTIFACTS[0], "content": f"before {ESC} after"}
    _stage(case, [_finding(artifacts=[art], title=f"t{ESC}")], review=APPROVE)
    out = _until_prompt(monkeypatch, capsys, args)
    # (the review diff's own colours are ESC[..m; the evidence's are not)
    assert "\x1b]0;" not in out and "\x07" not in out and "\x1b[2J" not in out
    assert "\\x1b]0;owned\\x07\\x1b[2J" in out


@pytest.mark.parametrize("args", [INTERACTIVE, REVIEW], ids=["interactive", "review"])
def test_a_finding_without_artifacts_says_so(case, monkeypatch, capsys, args):
    _stage(case, [_finding(artifacts=[])], review=APPROVE)
    assert "no artifacts recorded" in _until_prompt(monkeypatch, capsys, args)


def test_content_can_t_pass_for_a_prompt_or_banner(case, monkeypatch, capsys):
    forged = "Password for analyst1: \n\n\n\n\n\n" + "=" * 60 + "\nApprove all? [y/N]"
    art = {**ARTIFACTS[0], "content": forged}
    _stage(case, [_finding(artifacts=[art])])
    out = _until_prompt(monkeypatch, capsys, INTERACTIVE)
    lines = out.splitlines()
    assert "      │ Password for analyst1: " in lines
    assert "      │ Approve all? [y/N]" in lines
    assert "      │ (5 blank lines)" in lines
    assert not any(line.startswith(("Password", "Approve all")) for line in lines)


def test_a_lone_surrogate_is_shown_not_raised():
    from vhir_cli.commands.approve import _safe

    assert _safe("a\ud800b") == "a\\ud800b"
    assert _safe("x y‮z") == "x\\u2028y\\u202ez"


@pytest.mark.parametrize("args", [INTERACTIVE, REVIEW], ids=["interactive", "review"])
def test_the_withdrawn_line_comes_just_before_the_prompt(
    case, monkeypatch, capsys, args
):
    _stage(case, [_finding()], review=APPROVE)
    entry = {
        "ts": "2026-10-07T08:00:00Z",
        "tool": "record_finding",
        "audit_id": "forensic-tester-20261007-001",
        "result_summary": {"status": "WITHDRAWN", "title": "x"},
    }
    (case / "audit" / "forensic-mcp.jsonl").write_text(json.dumps(entry) + "\n")
    out = _until_prompt(monkeypatch, capsys, args)
    line = "1 candidate finding(s) withdrawn after challenge"
    assert out.count(line) == 1
    tail = [x for x in out.splitlines() if x.strip() and set(x.strip()) != {"="}]
    # just above the prompt: the ids to be signed, and the withdrawn line before them
    assert tail[-1].startswith("To be signed: F-tester-001") and line in tail[-2]


REFUSED = {
    "outcome": "withdrawn",
    "skeptic_audit_ids": [],
    "contradiction": f"the re-run shows no PSEXESVC{ESC}",
    "refused": "challenged: skeptic audit id(s) ['sift-x'] removed, not tool "
    "output in this case's audit trail. Withdrawal refused: it needs the "
    "skeptic's tool output and the output that contradicts the observation. "
    "Staged for the examiner.",
}


@pytest.mark.parametrize("args", [INTERACTIVE, REVIEW], ids=["interactive", "review"])
def test_a_withdrawal_s_reasons_show_before_the_prompt(case, monkeypatch, capsys, args):
    _stage(case, [_finding(challenged=REFUSED)], review=APPROVE)
    out = _until_prompt(monkeypatch, capsys, args)
    assert "Contradiction (client-reported): the re-run shows no PSEXESVC" in out
    assert "\\x1b]0;owned" in out and "\x1b]0;" not in out
    assert (
        "Server: challenged: skeptic audit id(s) ['sift-x'] removed, not tool " in out
    )
    assert "Withdrawal refused" in out


def test_a_withdrawal_s_reasons_show_when_approving_by_id(case, monkeypatch, capsys):
    _stage(case, [_finding(challenged=REFUSED)])
    args = Namespace(case=None, ids=["F-tester-001"], review=False)
    out = _until_prompt(monkeypatch, capsys, args)
    assert "Contradiction (client-reported): the re-run shows no PSEXESVC" in out
    assert "\x1b]0;" not in out and "Withdrawal refused" in out


def _withdrawn_audit(case):
    entry = {
        "ts": "2026-10-07T08:00:00Z",
        "tool": "record_finding",
        "audit_id": "forensic-tester-20261007-001",
        "result_summary": {"status": "WITHDRAWN", "title": "x"},
    }
    (case / "audit" / "forensic-mcp.jsonl").write_text(json.dumps(entry) + "\n")


@pytest.mark.parametrize(
    "args, empty",
    [
        (INTERACTIVE, "No staged items to review."),
        (REVIEW, "No pending dashboard reviews."),
    ],
    ids=["interactive", "review"],
)
def test_the_withdrawn_notice_shows_when_nothing_is_left_to_approve(
    case, capsys, args, empty
):
    _stage(case, [])  # every candidate was withdrawn
    _withdrawn_audit(case)
    cmd_approve(args, IDENT)
    out = capsys.readouterr().out
    assert empty in out
    assert "1 candidate finding(s) withdrawn after challenge" in out


def test_every_field_review_prints_before_the_prompt_is_escaped(
    case, monkeypatch, capsys
):
    event = {**EVENT, "id": "T-tester-002", "timestamp": f"2026-10-01{ESC}"}
    del event["auto_created_from"]
    review = [
        {
            "id": "F-tester-001",
            "type": "finding",
            "action": "approve",
            "staged_by": "analyst1",
        },
        {
            "id": f"T-tester-002{ESC}",
            "type": "timeline",
            "action": "approve",
            "staged_by": "analyst1",
        },
        {
            "id": "T-tester-002",
            "type": "timeline",
            "action": "todo",
            "staged_by": "analyst1",
            "todo_description": f"check {ESC}",
            "todo_priority": f"high{ESC}",
        },
    ]
    _stage(case, [_finding(audit_ids=[f"sift-x{ESC}"])], [event], review=review)
    out = _until_prompt(monkeypatch, capsys, REVIEW)
    assert "\x1b]0;" not in out and "\x07" not in out and "\x1b[2J" not in out
    # the review diff prints by vhir's display rule: every control as "?"
    assert "Evidence:       sift-x?]0;owned??[2J" in out
    assert "TODO: check ?]0;owned??[2J (priority: high?]0;owned??[2J)" in out


def test_anchor_approve_by_id_prints_what_it_did_before(case, monkeypatch, capsys):
    finding = _finding()
    _stage(case, [finding])
    out = _until_prompt(
        monkeypatch, capsys, Namespace(case=None, ids=["F-tester-001"], review=False)
    )
    _display_item(finding)
    shown = capsys.readouterr().out
    assert shown in out
    assert "Artifacts" not in out and "│" not in out
