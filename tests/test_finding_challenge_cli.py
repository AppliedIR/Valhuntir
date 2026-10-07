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
    return d


# --- the approval display ---------------------------------------------------


def test_a_finding_shows_its_challenge_first_then_its_alternatives(capsys):
    _display_item(_finding(alternatives=ALTERNATIVES, challenged=STANDS))
    out = capsys.readouterr().out
    challenge = (
        "Challenged (client-reported): stands — skeptic: sift-tester-20261007-002"
    )
    assert out.index(challenge) < out.index("[F-tester-001]")
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
            "Challenged (client-reported): withdrawal refused, no contradicting "
            "output cited — staged for your decision",
        ),
    ],
    ids=["absent", "revised", "refused withdrawal"],
)
def test_the_challenge_line(capsys, challenged, line):
    item = _finding() if challenged is None else _finding(challenged=challenged)
    _display_item(item)
    out = capsys.readouterr().out
    assert line in out
    assert out.index(line) < out.index("[F-tester-001]")


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
    monkeypatch.setattr(approve_mod, "require_confirmation", lambda *a: ("p", "p"))
    monkeypatch.setattr(approve_mod, "_write_verification_entries", lambda *a, **k: [])
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
    for name in ("_approve_specific", "_review_mode", "_interactive_review"):
        monkeypatch.setattr(approve_mod, name, lambda *a, **k: None)
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
