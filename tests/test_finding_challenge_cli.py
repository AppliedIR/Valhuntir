"""At approval the examiner sees a finding's alternatives and challenge, and how
many candidates were withdrawn after challenge, and can open them.

`vhir approve` showed neither field, its editor left the alternatives out, a
portal edit of them was approved without being applied, and nothing counted
or listed a withdrawal. The hashes cover both fields; an import keeps the
alternatives but not a challenge, whose skeptic ids belong to another case's
audit trail.
"""

from __future__ import annotations

import json
import re
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

import vhir_cli.commands.approve as approve_mod
from vhir_cli.case_io import (
    HASH_EXCLUDE_KEYS,
    compute_content_hash,
    hmac_text,
    import_bundle,
    load_findings,
)
from vhir_cli.commands.approve import _apply_edit, _display_item, cmd_approve
from vhir_cli.commands.review import cmd_review
from vhir_cli.main import build_parser

from .signing import PASSPHRASE, enrol

IDENT = {"examiner": "analyst1", "os_user": "u", "examiner_source": "flag"}
ALTERNATIVES = [
    {"explanation": "An admin's test", "status": "open"},
    {
        "explanation": "A renamed backup tool",
        "status": "ruled_out",
        "evidence": "sigcheck: unsigned",
        "audit_ids": ["sift-tester-20261007-002"],
    },
]
STANDS = {"outcome": "stands", "skeptic_audit_ids": ["sift-tester-20261007-002"]}


def _finding(**extra):
    item = {
        "id": "F-tester-001",
        "status": "DRAFT",
        "title": "Mimikatz run",
        "confidence": "MEDIUM",
        "observation": "Prefetch shows MIMIKATZ.EXE",
        "interpretation": "Credential dumping",
        "type": "finding",
        "audit_ids": ["ev-tester-20261007-001"],
        "staged": "2026-10-07T12:00:00Z",
        "modified_at": "2026-10-07T12:00:00Z",
        "created_by": "tester",
    }
    item.update(extra)
    return item


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
    monkeypatch.setattr(
        "vhir_cli.approval_auth.getpass_prompt", lambda p="": PASSPHRASE
    )
    return d


# --- the approval display ---------------------------------------------------


def test_a_finding_shows_its_challenge_under_its_title_then_its_alternatives(capsys):
    _display_item(_finding(alternatives=ALTERNATIVES, challenged=STANDS))
    lines = capsys.readouterr().out.splitlines()
    challenge = (
        "  Challenged (client-reported): stands — skeptic: sift-tester-20261007-002"
    )
    title = next(i for i, line in enumerate(lines) if "[F-tester-001]" in line)
    assert lines[title + 1] == challenge  # which finding it is, then its challenge
    out = "\n".join(lines)
    assert out.index(challenge) < out.index("Observation:")
    assert "Alternative: [open] An admin's test" in out
    assert (
        "Alternative: [ruled out] A renamed backup tool — sigcheck: unsigned "
        "(audit: sift-tester-20261007-002)"
    ) in out


@pytest.mark.parametrize(
    "challenged, line",
    [
        (None, "Not challenged"),
        (
            {"outcome": "revised", "skeptic_audit_ids": ["s-1"]},
            "Challenged (client-reported): revised after challenge — skeptic: s-1",
        ),
        (
            {"outcome": "withdrawn", "skeptic_audit_ids": []},
            "Challenged (client-reported): withdrawn, not applied, staged for your "
            "decision — skeptic: none",
        ),
        (
            {"outcome": "withdrawn", "skeptic_audit_ids": ["s-1", "s-2"]},
            "Challenged (client-reported): withdrawn, not applied, staged for your "
            "decision — skeptic: s-1, s-2",
        ),
    ],
    ids=["absent", "revised", "withdrawal without ids", "withdrawal with ids"],
)
def test_the_challenge_line(capsys, challenged, line):
    item = _finding() if challenged is None else _finding(challenged=challenged)
    _display_item(item)
    lines = capsys.readouterr().out.splitlines()
    title = next(i for i, text in enumerate(lines) if "[F-tester-001]" in text)
    assert lines[title + 1] == f"  {line}"


def test_an_examiners_own_shape_of_alternative_is_shown_as_text(capsys):
    _display_item(_finding(alternatives=["could be an admin", {"explanation": "x"}]))
    out = capsys.readouterr().out
    assert "Alternative: could be an admin" in out
    assert "Alternative: [open] x" in out


def test_anchor_a_timeline_event_shows_neither(capsys):
    _display_item(
        {"id": "T-tester-001", "timestamp": "2026-10-01", "description": "event"}
    )
    out = capsys.readouterr().out
    assert "challenge" not in out.lower() and "Alternative" not in out


# --- editing ---------------------------------------------------------------


def test_the_editor_shows_the_alternatives_and_an_edit_is_tracked(
    tmp_path, monkeypatch
):
    seen = tmp_path / "seen.yaml"
    editor = tmp_path / "edit.py"
    editor.write_text(
        "import sys, yaml, shutil\n"
        f"shutil.copy(sys.argv[1], {str(seen)!r})\n"
        "d = yaml.safe_load(open(sys.argv[1]))\n"
        "d['alternatives'] = d['alternatives'][:1]\n"
        "yaml.safe_dump(d, open(sys.argv[1], 'w'))\n"
    )
    wrapper = tmp_path / "edit.sh"
    wrapper.write_text(f'#!/bin/sh\nexec python3 {editor} "$1"\n')
    wrapper.chmod(0o755)
    monkeypatch.setenv("EDITOR", str(wrapper))
    item = _finding(alternatives=ALTERNATIVES)
    before = compute_content_hash(item)
    _apply_edit(item, IDENT)
    assert yaml.safe_load(seen.read_text())["alternatives"] == ALTERNATIVES
    assert item["alternatives"] == ALTERNATIVES[:1]
    assert item["examiner_modifications"]["alternatives"]["original"] == ALTERNATIVES
    assert compute_content_hash(item) != before


@pytest.mark.parametrize("action", ["approve", "edit"])
def test_a_portal_edit_of_the_alternatives_is_applied_by_review(
    case, monkeypatch, capsys, action
):
    (case / "findings.json").write_text(
        json.dumps([_finding(alternatives=ALTERNATIVES)])
    )
    (case / "timeline.json").write_text("[]")
    entry = {
        "id": "F-tester-001",
        "type": "finding",
        "action": action,
        "modifications": {
            "alternatives": {"original": ALTERNATIVES, "modified": ALTERNATIVES[1:]}
        },
    }
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-1", "items": [entry]})
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    approve_mod._review_mode(case, IDENT, Path("cfg"))
    out = capsys.readouterr().out
    assert "- [open] An admin's test" in out
    (finding,) = load_findings(case)
    assert finding["alternatives"] == ALTERNATIVES[1:]
    assert (
        finding["examiner_modifications"]["alternatives"]["modified"]
        == (ALTERNATIVES[1:])
    )


# --- withdrawals ---------------------------------------------------------------


def _withdrawal(audit_id, ts, title):
    return {
        "ts": ts,
        "tool": "record_finding",
        "audit_id": audit_id,
        "examiner": "tester",
        "params": {"finding": {"title": title}},
        "result_summary": {
            "status": "WITHDRAWN",
            "title": title,
            "observation": "Prefetch shows MIMIKATZ.EXE",
            "contradiction": "PECmd re-run: no such prefetch file",
            "skeptic_audit_ids": ["sift-tester-20261007-002"],
        },
    }


def _two_withdrawals(case):
    lines = [
        _withdrawal("forensic-tester-20261007-001", "2026-10-07T08:00:00Z", "first"),
        _withdrawal("forensic-tester-20261007-001", "2026-10-07T08:00:00Z", "first"),
        _withdrawal("forensic-tester-20261007-001", "2026-10-07T09:00:00Z", "second"),
        {"tool": "record_finding", "result_summary": {"status": "STAGED"}},
    ]
    (case / "audit" / "forensic-mcp.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in lines)
    )
    skeptic = {
        "ts": "2026-10-07T07:59:00Z",
        "tool": "run_command",
        "audit_id": "sift-tester-20261007-002",
        "params": {"command": "PECmd -d /prefetch"},
    }
    (case / "audit" / "sift-mcp.jsonl").write_text(json.dumps(skeptic) + "\n")


@pytest.mark.parametrize("mode", ["ids", "review", "interactive"])
def test_approve_prints_the_withdrawal_count_once_in_every_mode(
    case, monkeypatch, capsys, mode
):
    _two_withdrawals(case)
    seen = []

    def mode_run(*a, withdrawn_line="", **k):
        if withdrawn_line:  # interactive and review print it before the prompt
            print(withdrawn_line)
        seen.append(withdrawn_line)

    monkeypatch.setattr(approve_mod, "_approve_specific", lambda *a, **k: None)
    monkeypatch.setattr(approve_mod, "_review_mode", mode_run)
    monkeypatch.setattr(approve_mod, "_interactive_review", mode_run)
    args = Namespace(
        case=None,
        ids=["F-tester-001"] if mode == "ids" else [],
        review=mode == "review",
    )
    cmd_approve(args, IDENT)
    out = capsys.readouterr().out
    line = (
        "2 candidate finding(s) withdrawn after challenge — `vhir review --withdrawn`"
    )
    assert out.count(line) == 1


def test_anchor_approve_prints_no_count_without_withdrawals(case, monkeypatch, capsys):
    monkeypatch.setattr(approve_mod, "_interactive_review", lambda *a, **k: None)
    cmd_approve(Namespace(case=None, ids=[], review=False), IDENT)
    assert "withdrawn" not in capsys.readouterr().out


def test_review_withdrawn_lists_each_with_the_skeptics_evidence(case, capsys):
    _two_withdrawals(case)
    args = build_parser().parse_args(["review", "--withdrawn"])
    cmd_review(args, IDENT)
    out = capsys.readouterr().out
    assert "2 candidate finding(s) withdrawn after challenge" in out
    assert out.index("Title:         first") < out.index("Title:         second")
    assert out.count("Contradiction: PECmd re-run: no such prefetch file") == 2
    assert out.count("run_command(command=PECmd -d /prefetch)") == 2


def test_review_withdrawn_says_when_there_are_none(case, capsys):
    cmd_review(build_parser().parse_args(["review", "--withdrawn"]), IDENT)
    assert "No candidate findings withdrawn" in capsys.readouterr().out


# --- integrity ---------------------------------------------------------------


@pytest.mark.parametrize("key", ["alternatives", "challenged"])
def test_the_hash_and_the_signed_text_cover_the_new_keys(key):
    assert key not in HASH_EXCLUDE_KEYS
    plain = _finding()
    with_key = _finding(**{key: ALTERNATIVES if key == "alternatives" else STANDS})
    assert compute_content_hash(plain) != compute_content_hash(with_key)
    assert hmac_text(plain) != hmac_text(with_key)


def test_an_import_keeps_the_alternatives_but_not_the_challenge(case):
    incoming = _finding(alternatives=ALTERNATIVES, challenged=STANDS)
    import_bundle(case, {"findings": [incoming]})
    (merged,) = load_findings(case)
    assert merged["alternatives"] == ALTERNATIVES
    assert "challenged" not in merged


def test_an_alternative_of_any_status_shape_renders(capsys):
    _display_item(
        _finding(
            alternatives=[
                {"explanation": "a", "status": ["ruled_out"]},
                {"explanation": "b", "status": {"x": 1}},
            ]
        )
    )
    out = capsys.readouterr().out
    assert "Alternative: [['ruled out']] a" in out
    assert "Alternative: [{'x': 1}] b" in out


@pytest.mark.parametrize(
    "damage",
    [b"null\n", b'{"tool": "record_finding", "ts": 7}\n{"ts": "x"}\n', b"\xff\xfe\n"],
    ids=["a null line", "an int ts", "invalid utf-8"],
)
def test_a_damaged_audit_line_does_not_block_approval(
    case, monkeypatch, capsys, damage
):
    (case / "audit" / "forensic-mcp.jsonl").write_bytes(damage)
    ran = []
    monkeypatch.setattr(
        approve_mod, "_interactive_review", lambda *a, **k: ran.append(1)
    )
    cmd_approve(Namespace(case=None, ids=[], review=False), IDENT)
    captured = capsys.readouterr()
    assert ran == [1]
    assert "withdrawn candidates not counted" in captured.err


@pytest.mark.parametrize(
    "damage",
    [b"null\n", b'{"tool": "record_finding", "ts": 7}\n{"ts": "x"}\n', b"\xff\xfe\n"],
    ids=["a null line", "an int ts", "invalid utf-8"],
)
def test_review_withdrawn_says_a_damaged_audit_line_stopped_the_read(
    case, capsys, damage
):
    real = [
        _withdrawal("forensic-tester-20261007-001", "2026-10-07T08:00:00Z", "one"),
        _withdrawal("forensic-tester-20261007-002", "2026-10-07T09:00:00Z", "two"),
    ]
    lines = b"".join(json.dumps(e).encode() + b"\n" for e in real)
    (case / "audit" / "forensic-mcp.jsonl").write_bytes(lines + damage)
    with pytest.raises(SystemExit) as exited:
        cmd_review(build_parser().parse_args(["review", "--withdrawn"]), IDENT)
    out = capsys.readouterr().out
    assert exited.value.code not in (0, None)
    assert "Withdrawn candidates couldn't be read: " in out
    assert "No candidate findings withdrawn" not in out


def test_a_title_can_t_hide_the_challenge_line_under_it(capsys):
    """Escape sequences and line breaks in a title are shown as "?"."""
    title = "Benign\x1b[8m\rNot challenged\x9b2K\nmore"
    _display_item(_finding(title=title, challenged=STANDS))
    lines = capsys.readouterr().out.splitlines()
    (line,) = [i for i, text in enumerate(lines) if "[F-tester-001]" in text]
    assert lines[line] == "  [F-tester-001]  Benign?[8m?Not challenged?2K?more"
    assert lines[line + 1].startswith("  Challenged (client-reported): stands")


def test_review_shows_the_challenge_under_the_title(capsys):
    from vhir_cli.commands.approve import _render_terminal_diff

    _render_terminal_diff(
        _finding(challenged=STANDS), {"id": "F-tester-001", "action": "approve"}
    )
    lines = capsys.readouterr().out.splitlines()
    (title,) = [i for i, text in enumerate(lines) if text.startswith("  Title:")]
    assert lines[title + 1].startswith("  Challenged (client-reported): stands")


def test_an_escape_in_any_field_can_t_rewrite_the_challenge_line(capsys):
    """An interpretation (or any other field) carrying cursor-up and erase-line
    is shown with "?" for its control characters, so no line above changes."""
    item = _finding(
        challenged=STANDS,
        interpretation="benign\x1b[3A\x1b[2KNot challenged",
        observation="seen\r\x9b1A",
        confidence="LOW\x1b[8m",
    )
    _display_item(item)
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x9b" not in out and "\r" not in out
    assert "  Interpretation: benign?[3A?[2KNot challenged" in out.splitlines()
    assert "  Challenged (client-reported): stands" in out


def test_review_shows_a_control_character_title_escaped(capsys):
    from vhir_cli.commands.approve import _render_terminal_diff

    item = _finding(title="Benign\x1b[8m\rNot challenged", challenged=STANDS)
    entry = {"id": "F-tester-001", "action": "approve", "note": "ok\x1b[1A"}
    _render_terminal_diff(item, entry)
    lines = capsys.readouterr().out.splitlines()
    (title,) = [i for i, text in enumerate(lines) if text.startswith("  Title:")]
    assert lines[title] == "  Title:          Benign?[8m?Not challenged"
    assert lines[title + 1].startswith("  Challenged (client-reported): stands")
    assert any("Note: ok?[1A" in text for text in lines)


def _review_output(case, monkeypatch, capsys, finding_id, action):
    """`vhir approve --review` on one challenged finding, stopped at the password."""
    finding = _finding(challenged=STANDS)
    finding.update(id=finding_id, content_hash="now")
    (case / "findings.json").write_text(json.dumps([finding]))
    (case / "timeline.json").write_text("[]")
    entry = {"id": finding_id, "type": "finding", "action": action}
    entry["content_hash_at_review"] = "then"  # changed since: a stale warning
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-1", "items": [entry]})
    )

    def decline(*a):  # the examiner stops at the passphrase prompt
        raise SystemExit(1)

    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", decline)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")  # include it
    try:
        approve_mod._review_mode(case, IDENT, Path("cfg"))
    except SystemExit:
        pass
    return capsys.readouterr().out


@pytest.mark.parametrize(
    "finding_id, action",
    [("F-tester-001", "approve\x1b[2J"), ("F-tester-001\x1b[2J", "approve")],
    ids=["the delta's action", "a stale id"],
)
def test_a_review_file_can_t_clear_the_challenge_line(
    case, monkeypatch, capsys, finding_id, action
):
    """The portal's review file is written outside vhir: its values are escaped."""
    out = _review_output(case, monkeypatch, capsys, finding_id, action)
    assert "\x1b[2J" not in out
    assert "?[2J" in out
    assert "Challenged (client-reported): stands" in out
    assert "changed after you reviewed it" in out  # stale: refused, not signed


def test_a_multi_line_interpretation_keeps_its_lines(capsys):
    _display_item(_finding(interpretation="Credential dumping\nthen lateral movement"))
    lines = capsys.readouterr().out.splitlines()
    at = lines.index("  Interpretation: Credential dumping")
    assert (
        lines[at + 1] == " " * 18 + "then lateral movement"
    )  # indented under the field


def test_a_carriage_return_can_t_overwrite_a_line(capsys):
    _display_item(_finding(interpretation="benign\rNot challenged", challenged=STANDS))
    out = capsys.readouterr().out
    assert "\r" not in out
    assert "  Interpretation: benign?Not challenged" in out.splitlines()


def test_a_multi_line_timeline_description_keeps_its_lines(capsys):
    _display_item(
        {
            "id": "T-tester-001",
            "timestamp": "2023-01-29T08:00:00Z",
            "description": "Logon from WKS01\nthen RDP\x1b[2J to SRV01",
        }
    )
    lines = capsys.readouterr().out.splitlines()
    at = lines.index("  Description: Logon from WKS01")
    assert lines[at + 1] == " " * 15 + "then RDP?[2J to SRV01"


def test_multi_line_fields_in_a_review_diff_keep_their_lines(capsys):
    from vhir_cli.commands.approve import _render_terminal_diff

    entry = {
        "id": "F-tester-001",
        "action": "edit",
        "modifications": {
            "interpretation": {"original": "one\ntwo", "modified": "three\nfour\x1b[1A"}
        },
    }
    _render_terminal_diff(_finding(interpretation="one\ntwo"), entry)
    # vhir's own colour codes aside, each value keeps its line break,
    # indented under the value
    out = re.sub(r"\x1b\[\d+m", "", capsys.readouterr().out)
    pad = " " * (len("  Interpretation:") + 2)
    assert f"- one\n{pad}two" in out
    assert f"+ three\n{pad}four?[1A" in out


def test_skipped_ids_and_reasons_are_escaped(case, monkeypatch, capsys):
    """An id not in the case and a changed field's name both come from the
    review file, and are printed in the skipped list."""
    (case / "findings.json").write_text(json.dumps([_finding()]))
    (case / "timeline.json").write_text("[]")
    items = [
        {"id": "F-ghost\x1b[2J", "type": "finding", "action": "approve"},
        {
            "id": "F-tester-001",
            "type": "finding",
            "action": "edit",
            "modifications": {
                "interp\x1b[2J": {"original": "not this", "modified": "x"}
            },
        },
    ]
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-1", "items": items})
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    approve_mod._review_mode(case, IDENT, Path("cfg"))
    out = capsys.readouterr().out
    assert "\x1b[2J" not in out
    assert "    F-ghost?[2J: not found" in out.splitlines()
    assert (
        "    F-tester-001: field 'interp?[2J' changed since review" in out.splitlines()
    )


def test_a_todo_description_is_shown_by_the_same_rule(case, capsys):
    approve_mod._create_todos(
        case, [{"description": "Check WKS01\nand SRV01\x1b[2J"}], {"examiner": "tester"}
    )
    lines = capsys.readouterr().out.splitlines()
    at = lines.index("  Created TODO-tester-001: Check WKS01")
    assert lines[at + 1] == " " * len("  Created TODO-tester-001: ") + "and SRV01?[2J"
