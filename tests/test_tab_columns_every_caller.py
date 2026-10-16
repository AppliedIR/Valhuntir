"""A TAB in text from the case keeps its column in every view and message that
prints it inline, not only the finding views: each one shows it as spaces,
never as "?", "\\x09" or a raw TAB. These are the prints no other test reaches:
the TODO and evidence lists, an unreadable approvals log, a registered
folder's note, `vhir exec`'s refused audit write, the review-mode diff and
its refusals, and the commit's lines that keep the examiner's work."""

from __future__ import annotations

import contextlib
import errno
import json
import sys
from argparse import Namespace

import pytest
import yaml

from vhir_cli import decide
from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands import approve, audit_cmd, evidence, execute
from vhir_cli.commands.approve import cmd_approve
from vhir_cli.decide import Decision

from .signing import enrol

T = "\t"  # a TAB, as stored
IDENT = {"examiner": "analyst1", "os_user": "u", "examiner_source": "flag"}


def _shown(text: str) -> str:
    """`text` as a view shows it when it starts its own printed value."""
    return text.expandtabs()


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    (d / "evidence.json").write_text('{"files": []}')
    (d / "todos.json").write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _cli(monkeypatch, capsys, argv):
    from vhir_cli import main as m

    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    code = None
    try:
        m.main()
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr()
    return code, out.out, out.err


def _clean(text: str) -> None:
    assert "\t" not in text and "?" not in text and "\\x09" not in text, text


# ---------------------------------------------------------------- vhir review


def test_todo_list_keeps_tab_columns(case, monkeypatch, capsys):
    (case / "todos.json").write_text(json.dumps([{
        "todo_id": "TODO-tester-001", "status": "open", "priority": "high",
        "assignee": "an\tal", "description": "check\trd01",
        "notes": [{"by": "te\tst", "note": "see\tnetscan"}],
    }]))  # fmt: skip
    code, out, _ = _cli(monkeypatch, capsys, ["review", "--todos"])
    assert code in (None, 0)
    _clean(out)
    row = next(ln for ln in out.split("\n") if ln.startswith("TODO-tester-001"))
    assert _shown("an\tal") in row and row.endswith(_shown("check\trd01")), row
    note = f"  TODO-tester-001: [{_shown(f'te{T}st')}] {_shown(f'see{T}netscan')}"
    assert note in out.split("\n"), out


def test_evidence_list_keeps_tab_columns(case, monkeypatch, capsys):
    (case / "evidence.json").write_text(json.dumps({"files": [{
        "path": "/e/rd\t01.mem", "sha256": "ab", "registered_at": "t",
        "registered_by": "tester", "description": "line one\tcol\nline two",
    }]}))  # fmt: skip
    (case / "evidence_access.jsonl").write_text(
        json.dumps(
            {"ts": "t", "action": "reg\tister", "path": "/e/x", "examiner": "tester"}
        )
        + "\n"
    )
    code, out, _ = _cli(monkeypatch, capsys, ["review", "--evidence"])
    assert code in (None, 0)
    _clean(out)
    lines = out.split("\n")
    assert f"  {_shown(f'/e/rd{T}01.mem')}" in lines, out
    assert f"    Description: {_shown(f'line one{T}col')}" in lines, out
    assert f"{' ' * 17}line two" in lines, out
    assert f"  t | {_shown(f'reg{T}ister')} | /e/x | tester" in lines, out


def test_unreadable_approvals_log_reason_keeps_tab_column(case, monkeypatch, capsys):
    (case / "approvals.jsonl").write_text("")
    real = audit_cmd.iter_jsonl_entries

    def entries(path, *a, **k):
        if path.name == "approvals.jsonl":
            raise OSError(errno.EIO, "I/O\terror")
        return real(path, *a, **k)

    monkeypatch.setattr(audit_cmd, "iter_jsonl_entries", entries)
    code, out, _ = _cli(monkeypatch, capsys, ["review", "--withdrawn"])
    assert code == 1
    line = f"Couldn't read {_shown(f'approvals.jsonl (I/O{T}error)')}: a candidate"
    assert line in out, out
    assert "\t" not in out and "I/O?error" not in out


# ---------------------------------------------------------------- evidence, exec


def test_registered_folder_note_keeps_tab_column(case, monkeypatch, capsys):
    monkeypatch.setattr(evidence, "require_tty_confirmation", lambda *a, **k: True)
    monkeypatch.setattr(evidence, "_log_evidence_action", lambda *a, **k: None)
    monkeypatch.setattr(evidence, "register_evidence_data", lambda **k: {
        "path": "/e/f", "kind": "folder", "file_count": 2, "manifest_path": "m.json",
        "manifest_sha256": "ab", "derivation_note": "made from\tthe image",
    })  # fmt: skip
    args = Namespace(case=None, path="/e/f", description="", force_reregister=False)
    evidence.cmd_register_evidence(args, IDENT)
    out = capsys.readouterr().out
    assert f"  WARNING: {_shown(f'made from{T}the image')}" in out.split("\n"), out
    _clean(out)


def test_exec_refused_audit_write_reason_keeps_tab_column(case, monkeypatch, capsys):
    monkeypatch.setattr(execute, "require_tty_confirmation", lambda *a, **k: True)

    def no_space(*a, **k):
        raise OSError(errno.ENOSPC, "No space\tleft")

    monkeypatch.setattr(execute, "_next_audit_id", no_space)
    args = Namespace(case=None, cmd=["--", "true"], purpose="p")
    with pytest.raises(SystemExit) as e:
        execute.cmd_exec(args, IDENT)
    assert e.value.code == 1
    err = capsys.readouterr().err
    log = case / "audit" / "cli-exec.jsonl"
    assert f"entry ({_shown(f'{log}: No space{T}left')}). " in err, err
    assert "\t" not in err and "space?left" not in err


# ---------------------------------------------------------------- approve


def test_non_record_artifact_keeps_tab_column():
    lines = approve._artifact_lines({"artifacts": ["col1\tcol2\x1b"]})
    assert lines[1] == f"    1. {_shown(f'col1{T}col2')}\\x1b", lines


def _diff(capsys, item, entry):
    approve._render_terminal_diff(item, entry)
    return capsys.readouterr().out


def test_review_diff_alternative_keeps_tab_column(capsys):
    item = {"id": "F-tester-001", "status": "DRAFT", "title": "t",
            "observation": "o", "alternatives": ["first\tsecond"]}  # fmt: skip
    out = _diff(capsys, item, {"id": "F-tester-001", "action": "approve"})
    assert f"  Alternative:    {_shown(f'first{T}second')}" in out.split("\n"), out
    assert "\t" not in out and "first?second" not in out


def test_review_diff_event_source_keeps_tab_column(capsys):
    item = {"id": "T-tester-001", "status": "DRAFT", "timestamp": "2026-10-16T08:00:00Z",
            "description": "d", "source": "vol\tnetscan"}  # fmt: skip
    out = _diff(capsys, item, {"id": "T-tester-001", "action": "approve"})
    assert f"  Source:        {_shown(f'vol{T}netscan')}" in out.split("\n"), out
    assert "\t" not in out and "vol?netscan" not in out


@pytest.fixture
def review_case(case, monkeypatch):
    enrol("analyst1")
    save_timeline(case, [])
    save_findings(case, [])
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    return case


def _review(monkeypatch, capsys):
    def prompt(*a, **k):
        raise AssertionError("no passphrase prompt here")

    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", prompt)
    code = None
    try:
        cmd_approve(Namespace(case=None, ids=[], review=True), IDENT)
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr()
    return code, out.out, out.err


def test_review_other_case_id_keeps_tab_column(review_case, monkeypatch, capsys):
    (review_case / "pending-reviews.json").write_text(json.dumps({
        "case_id": "C-\t9", "items": [{"id": "F-tester-001", "type": "finding",
                                       "action": "approve", "staged_by": "analyst1"}],
    }))  # fmt: skip
    code, _, err = _review(monkeypatch, capsys)
    assert code == 1
    assert (
        f"Error: Delta case_id ({_shown(f'C-{T}9')}) does not match active case (C-1)."
        in err
    )
    assert "\t" not in err and "C-?9" not in err


def test_review_own_entry_line_keeps_tab_column(review_case, monkeypatch, capsys):
    entry = {"id": "F-\tx", "type": "finding", "action": "approve"}
    (review_case / "pending-reviews.json").write_text(json.dumps({
        "case_id": "C-1",
        "items": [{**entry, "staged_by": "other"}, {**entry, "staged_by": "analyst1"}],
    }))  # fmt: skip
    _, out, _ = _review(monkeypatch, capsys)
    assert f"  You have your own entry for {_shown(f'F-{T}x')}; not offered." in out, (
        out
    )
    assert "F-?x" not in out


# ---------------------------------------------------------------- the commit


def _decision(item_id="F-a\tb", **k):
    return Decision({"id": item_id}, "finding", "approve", "APPROVED", **k)


def test_unsigned_save_failure_keeps_tab_columns(case, monkeypatch, capsys):
    def fails(*a, **k):
        raise OSError("disk\tfull")

    monkeypatch.setattr(decide, "save_unsigned", fails)
    with pytest.raises(SystemExit):
        decide._kept_unsigned(
            case, "analyst1", [_decision()], [], "why", "Lead", "after"
        )
    err = capsys.readouterr().err
    assert (
        f"(OSError: {_shown(f'disk{T}full')}). Decide them again: {_shown(f'F-a{T}b')}"
        in err
    ), err
    assert "\t" not in err and "?" not in err


def test_unsigned_save_notes_keep_tab_columns(case, monkeypatch, capsys):
    monkeypatch.setattr(decide, "save_unsigned", lambda *a, **k: (["x\ty"], ["l\tm"]))
    with pytest.raises(SystemExit):
        decide._kept_unsigned(
            case, "analyst1", [_decision()], [], "why", "Lead", "after"
        )
    lines = capsys.readouterr().err.split("\n")
    assert f"  not saved: {_shown(f'x{T}y')}" in lines, lines
    assert f"  {_shown(f'l{T}m')}" in lines, lines


def test_passphrase_prompt_failure_keeps_tab_column(case, monkeypatch, capsys):
    def damaged(*a, **k):
        raise ValueError("keys\tfile damaged")

    monkeypatch.setattr(decide.credentials, "unlock", damaged)
    monkeypatch.setattr(decide, "save_unsigned", lambda *a, **k: ([], []))
    with pytest.raises(SystemExit):
        decide.sign_and_commit(case, {"examiner": "analyst1"}, [_decision()], [])
    err = capsys.readouterr().err
    assert (
        f"The passphrase prompt couldn't go ahead: {_shown(f'keys{T}file damaged')}"
        in err
    )
    assert "\t" not in err and "keys?file" not in err


def test_todos_kept_nowhere_keeps_tab_columns(case, monkeypatch, capsys):
    @contextlib.contextmanager
    def lock(case_id, on_wait=None):
        yield None

    def todos_down(todos):
        raise RuntimeError("todos\tdown")

    def fails(*a, **k):
        raise OSError("full\tdisk")

    monkeypatch.setattr(decide.credentials, "unlock", lambda *a, **k: ("priv", "pub"))
    monkeypatch.setattr(decide.ledger, "case_lock", lock)
    monkeypatch.setattr(decide, "save_unsigned", fails)
    todo = {"description": "d", "related_findings": ["F-tester-001"]}
    with pytest.raises(SystemExit) as e:
        decide.sign_and_commit(
            case, {"examiner": "analyst1"}, [], [], todos=[todo], make_todos=todos_down
        )
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert (
        f"Your TODOs weren't created ({_shown(f'todos{T}down')}); they couldn't be saved "
        f"either ({_shown(f'full{T}disk')}); add them again." in err
    ), err
    assert "\t" not in err and "?" not in err


def test_cascade_not_shown_keeps_tab_columns(monkeypatch):
    new = Decision(
        {"id": "T-\t1"}, "timeline", "approve", "APPROVED", coupled_from="F-\t2"
    )
    monkeypatch.setattr(decide, "cascades", lambda *a, **k: [new])
    lists = {"finding": [], "timeline": [], "ioc": []}
    signed, discarded = decide._still_as_shown(lists, [], [], ())
    assert signed == []
    assert discarded == [
        f"  NOT SIGNED: {_shown(f'T-{T}1')} would now be decided with {_shown(f'F-{T}2')}, "
        "but it wasn't shown to you; it is left as it is."
    ]
