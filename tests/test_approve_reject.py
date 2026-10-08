"""Tests for approve and reject commands (hardened with mandatory password)."""

import json
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from vhir_cli.case_io import (
    load_approval_log,
    load_findings,
    load_timeline,
    load_todos,
    save_findings,
    save_timeline,
)
from vhir_cli.commands.approve import _approve_specific, cmd_approve
from vhir_cli.commands.reject import cmd_reject

from .signing import enrol


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    """Create a minimal flat case directory structure."""
    case_id = "INC-2026-TEST"
    case_path = tmp_path / case_id
    case_path.mkdir()

    meta = {"case_id": case_id, "name": "Test", "status": "open"}
    with open(case_path / "CASE.yaml", "w") as f:
        yaml.dump(meta, f)

    with open(case_path / "evidence.json", "w") as f:
        json.dump({"files": []}, f)

    with open(case_path / "todos.json", "w") as f:
        json.dump([], f)

    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case_path))
    return case_path


@pytest.fixture
def identity():
    return {
        "os_user": "testuser",
        "examiner": "analyst1",
        "examiner_source": "flag",
        "analyst": "analyst1",
        "analyst_source": "flag",
    }


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".vhir" / "config.yaml"


@pytest.fixture(autouse=True)
def isolate_passwords_dir(tmp_path, monkeypatch):
    """Point _PASSWORDS_DIR to temp dir so tests never touch /var/lib/vhir/."""
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    return d


@pytest.fixture
def pw_config(config_path):
    """Enrol analyst1 (passphrase testpass1) and return config_path."""
    enrol("analyst1")
    return config_path


@pytest.fixture(autouse=True)
def isolate_lockout_file(tmp_path, monkeypatch):
    """Point lockout file to temp dir to avoid cross-test contamination."""
    lockout = tmp_path / ".password_lockout"
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", lockout)
    yield lockout
    if lockout.exists():
        lockout.unlink()


@pytest.fixture
def staged_finding(case_dir):
    """Stage a DRAFT finding."""
    findings = [
        {
            "id": "F-tester-001",
            "status": "DRAFT",
            "title": "Suspicious process",
            "confidence": "MEDIUM",
            "audit_ids": ["ev-001"],
            "observation": "svchost from cmd",
            "interpretation": "unusual",
            "confidence_justification": "single source",
            "type": "finding",
            "staged": "2026-02-19T12:00:00Z",
            "created_by": "steve",
        }
    ]
    save_findings(case_dir, findings)
    return findings


@pytest.fixture
def staged_timeline(case_dir):
    """Stage a DRAFT timeline event."""
    events = [
        {
            "id": "T-tester-001",
            "status": "DRAFT",
            "timestamp": "2026-02-19T10:00:00Z",
            "description": "First lateral movement",
            "staged": "2026-02-19T12:00:00Z",
            "created_by": "jane",
        }
    ]
    save_timeline(case_dir, events)
    return events


class TestApproveSpecific:
    def test_approve_finding(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["approved_by"] == "analyst1"

    def test_approve_timeline_event(
        self, case_dir, identity, staged_timeline, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["T-tester-001"], identity, pw_config)
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_approve_nonexistent_id(
        self, case_dir, identity, staged_finding, capsys, pw_config
    ):
        _approve_specific(case_dir, ["F-999"], identity, pw_config)
        captured = capsys.readouterr()
        assert "not found or not DRAFT" in captured.err

    def test_approve_already_approved(
        self, case_dir, identity, staged_finding, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_approval_log_written(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(case_dir, ["F-tester-001"], identity, pw_config)
        log = load_approval_log(case_dir)
        assert len(log) == 1
        assert log[0]["item_id"] == "F-tester-001"
        assert log[0]["action"] == "APPROVED"
        assert log[0]["examiner"] == "analyst1"
        assert log[0]["mode"] == "cli"

    def test_no_password_configured_exits(
        self, case_dir, identity, staged_finding, config_path, capsys
    ):
        """Approval without password configured exits with setup instructions."""
        with pytest.raises(SystemExit):
            _approve_specific(case_dir, ["F-tester-001"], identity, config_path)
        captured = capsys.readouterr()
        assert "No passphrase configured" in captured.err

    def test_approve_with_note(self, case_dir, identity, staged_finding, pw_config):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(
                case_dir,
                ["F-tester-001"],
                identity,
                pw_config,
                note="Correct finding, classify as generic.",
            )
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert len(findings[0]["examiner_notes"]) == 1
        assert (
            findings[0]["examiner_notes"][0]["note"]
            == "Correct finding, classify as generic."
        )

    def test_approve_with_interpretation_override(
        self, case_dir, identity, staged_finding, pw_config
    ):
        with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
            _approve_specific(
                case_dir,
                ["F-tester-001"],
                identity,
                pw_config,
                interpretation="Process masquerading confirmed",
            )
        findings = load_findings(case_dir)
        assert findings[0]["interpretation"] == "Process masquerading confirmed"
        assert "interpretation" in findings[0]["examiner_modifications"]
        assert (
            findings[0]["examiner_modifications"]["interpretation"]["original"]
            == "unusual"
        )


class TestApproveInteractive:
    def test_no_drafts(self, case_dir, identity, capsys, monkeypatch):
        save_findings(case_dir, [])
        save_timeline(case_dir, [])
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("vhir_cli.commands.approve.Path.home", return_value=case_dir.parent):
            cmd_approve(args, identity)
        captured = capsys.readouterr()
        assert "No staged items" in captured.out

    def test_interactive_approve_all(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"

    def test_interactive_note(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["n", "Good finding"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        assert findings[0]["examiner_notes"][0]["note"] == "Good finding"

    def test_interactive_reject(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["r", "Bad evidence"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Bad evidence"

    def test_interactive_skip(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["s"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"

    def test_interactive_todo(
        self, case_dir, identity, staged_finding, pw_config, capsys
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=False,
            timeline_only=False,
        )
        with patch(
            "builtins.input",
            side_effect=["t", "Verify with net logs", "jane", "high"],
        ):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        # Finding stays DRAFT
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"
        # TODO created
        todos = load_todos(case_dir)
        assert len(todos) == 1
        assert todos[0]["description"] == "Verify with net logs"
        assert todos[0]["assignee"] == "jane"
        assert todos[0]["related_findings"] == ["F-tester-001"]

    def test_by_filter(
        self,
        case_dir,
        identity,
        staged_finding,
        staged_timeline,
        pw_config,
        capsys,
    ):
        """Filter by creator — only jane's items shown."""
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by="jane",
            findings_only=False,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        # Only T-tester-001 (by jane) approved, F-tester-001 (by steve) stays DRAFT
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "DRAFT"
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "APPROVED"

    def test_findings_only(
        self,
        case_dir,
        identity,
        staged_finding,
        staged_timeline,
        pw_config,
        capsys,
    ):
        args = Namespace(
            ids=[],
            case=None,
            analyst=None,
            note=None,
            edit=False,
            interpretation=None,
            by=None,
            findings_only=True,
            timeline_only=False,
        )
        with patch("builtins.input", side_effect=["a"]):
            with patch(
                "vhir_cli.commands.approve.Path.home",
                return_value=case_dir.parent,
            ):
                with patch(
                    "vhir_cli.approval_auth.getpass_prompt",
                    return_value="testpass1",
                ):
                    cmd_approve(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "APPROVED"
        timeline = load_timeline(case_dir)
        assert timeline[0]["status"] == "DRAFT"  # Not reviewed


class TestReject:
    def test_reject_finding(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(
            ids=["F-tester-001"],
            reason="Insufficient evidence",
            case=None,
            analyst=None,
        )
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        assert findings[0]["rejection_reason"] == "Insufficient evidence"
        assert findings[0]["rejected_by"] == "analyst1"
        assert isinstance(findings[0]["rejected_by"], str)

    def test_reject_writes_log(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(
            ids=["F-tester-001"], reason="Bad data", case=None, analyst=None
        )
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        log = load_approval_log(case_dir)
        assert log[0]["action"] == "REJECTED"
        assert log[0]["reason"] == "Bad data"
        assert log[0]["mode"] == "cli"

    def test_reject_nonexistent(
        self, case_dir, identity, staged_finding, capsys, pw_config
    ):
        args = Namespace(ids=["F-999"], reason="nope", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            cmd_reject(args, identity)
        captured = capsys.readouterr()
        assert "not found or already rejected" in captured.err

    def test_reject_no_reason(self, case_dir, identity, staged_finding, pw_config):
        args = Namespace(ids=["F-tester-001"], reason="", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                return_value="testpass1",
            ):
                cmd_reject(args, identity)
        findings = load_findings(case_dir)
        assert findings[0]["status"] == "REJECTED"
        log = load_approval_log(case_dir)
        assert "reason" not in log[0]

    def test_reject_preserves_concurrent_finding(
        self, case_dir, identity, staged_finding, pw_config
    ):
        """A finding added between display and confirmation survives rejection."""

        def add_finding_then_type(prompt=""):
            # Simulate an MCP write happening during the passphrase prompt
            findings = load_findings(case_dir)
            findings.append(
                {
                    "id": "F-tester-002",
                    "status": "DRAFT",
                    "title": "Concurrent finding",
                    "staged": "2026-02-19T13:00:00Z",
                    "created_by": "mcp",
                }
            )
            save_findings(case_dir, findings)
            return "testpass1"

        args = Namespace(ids=["F-tester-001"], reason="bad", case=None, analyst=None)
        with patch("vhir_cli.commands.reject.Path.home", return_value=case_dir.parent):
            with patch(
                "vhir_cli.approval_auth.getpass_prompt",
                side_effect=add_finding_then_type,
            ):
                cmd_reject(args, identity)

        # F-tester-001 should be REJECTED, F-tester-002 should survive as DRAFT
        findings = load_findings(case_dir)
        assert len(findings) == 2
        f001 = next(f for f in findings if f["id"] == "F-tester-001")
        f002 = next(f for f in findings if f["id"] == "F-tester-002")
        assert f001["status"] == "REJECTED"
        assert f002["status"] == "DRAFT"


# --- approve saves what's on disk after the wait, not what it read before ----
# All three modes read findings/timeline (review mode: iocs too) before the
# password prompt, $EDITOR or the per-item prompts, then wrote those lists
# back: anything forensic-mcp staged meanwhile was deleted. The concurrent
# writer here writes what record_finding writes: a finding, its auto event
# and an IOC.

from vhir_cli import ledger  # noqa: E402
from vhir_cli.commands import approve as approve_mod  # noqa: E402

from .signing import PASSPHRASE  # noqa: E402

_NOW = "2026-01-01T00:00:00+00:00"
_CORRUPT = '{"broken": '
_IDENT = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}


def _f(fid, title, tid, iocs=()):
    return {
        "id": fid,
        "title": title,
        "observation": "obs",
        "interpretation": "interp",
        "confidence": "MEDIUM",
        "type": "finding",
        "status": "DRAFT",
        "staged": _NOW,
        "modified_at": _NOW,
        "created_by": "steve",
        "examiner": "steve",
        "timeline_event_id": tid,
        "iocs": list(iocs),
        "content_hash": "x",
    }


def _t(tid, fid=None, desc="event"):
    t = {
        "id": tid,
        "timestamp": "2026-01-01T00:00:00Z",
        "description": desc,
        "status": "DRAFT",
        "staged": _NOW,
        "modified_at": _NOW,
        "created_by": "steve",
        "examiner": "steve",
        "content_hash": "y",
    }
    if fid:
        t["auto_created_from"] = fid
        t["related_findings"] = [fid]
    return t


def _ioc(iid, value, fid):
    """The record forensic-mcp's record_finding writes for a new IOC."""
    return {
        "id": iid,
        "value": value,
        "type": "ipv4",
        "category": "network",
        "description": "",
        "status": "DRAFT",
        "confidence": "MEDIUM",
        "source_findings": [fid],
        "sightings": [{"host": "", "finding_id": fid}],
        "mitre_techniques": [],
        "tags": [],
        "manually_reviewed": False,
        "examiner": "steve",
        "created_at": _NOW,
        "modified_at": _NOW,
        "content_hash": "z",
    }


def _write(path, data):
    if path.exists():
        path.chmod(0o644)
    path.write_text(json.dumps(data))


def _stage_concurrently(case):
    """What record_finding writes for a new finding; returns the records."""
    recs = {
        "F": _f("F-steve-002", "Staged during wait", "T-steve-003", ["10.9.9.9"]),
        "T": _t("T-steve-003", "F-steve-002", "Staged during wait"),
        "I": _ioc("IOC-steve-002", "10.9.9.9", "F-steve-002"),
    }
    for name, key in (
        ("findings.json", "F"),
        ("timeline.json", "T"),
        ("iocs.json", "I"),
    ):
        path = case / name
        _write(path, json.loads(path.read_text()) + [recs[key]])
    return recs


STAGE_SCRIPT = """
import json, sys
from pathlib import Path
case = Path(sys.argv[1])
recs = json.loads(sys.argv[2])
for name, key in (("findings.json", "F"), ("timeline.json", "T"), ("iocs.json", "I")):
    p = case / name
    p.chmod(0o644)
    p.write_text(json.dumps(json.loads(p.read_text()) + [recs[key]]))
"""


@pytest.fixture
def wait_case(tmp_path, monkeypatch):
    """F1 with its auto event T1 and IOC-1, plus a manual event TM."""
    case = tmp_path / "K-case"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: K-case\nstatus: open\n")
    (case / "findings.json").write_text(
        json.dumps([_f("F-steve-001", "First", "T-steve-001", ["10.1.2.3"])])
    )
    (case / "timeline.json").write_text(
        json.dumps(
            [
                _t("T-steve-001", "F-steve-001", "First"),
                _t("T-steve-002", desc="manual"),
            ]
        )
    )
    (case / "iocs.json").write_text(
        json.dumps([_ioc("IOC-steve-001", "10.1.2.3", "F-steve-001")])
    )
    return case


def _run(case, monkeypatch, mode, hook, *, ids=("F-steve-001",), answers=(), **kw):
    """Runs a mode with `hook` during the wait (at the passphrase prompt; in
    the interactive mode, at the first per-item prompt); returns (exit code,
    the ids the ledger signed)."""
    enrol("steve")
    state = {"first": True}

    def passphrase(prompt=""):
        if mode != "int" and state["first"]:
            state["first"] = False
            hook()
        return PASSPHRASE

    replies = iter(answers)

    def ask(prompt=""):
        if state["first"]:
            state["first"] = False
            hook()
        return next(replies, "q")

    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", passphrase)
    monkeypatch.setattr("builtins.input", ask)
    code = 0
    try:
        if mode == "ids":
            approve_mod._approve_specific(case, list(ids), _IDENT, Path("cfg"), **kw)
        elif mode == "rev-saved":
            approve_mod._review_mode(case, _IDENT, Path("cfg"))
        elif mode == "rev":
            (case / "pending-reviews.json").write_text(
                json.dumps(
                    {
                        "case_id": "K-case",
                        "items": [
                            {"id": i, "action": "approve", "staged_by": "steve"}
                            for i in ids
                        ],
                    }
                )
            )
            approve_mod._review_mode(case, _IDENT, Path("cfg"))
        else:
            approve_mod._interactive_review(case, _IDENT, Path("cfg"))
    except SystemExit as e:
        code = e.code
    lines = ledger.read_lines(ledger.chain_path("K-case"))
    return code, [obj["item_id"] for _, _, obj in lines if obj]


def _on_disk(case):
    def by_id(name):
        p = case / name
        return {x["id"]: x for x in json.loads(p.read_text())} if p.exists() else {}

    return by_id("findings.json"), by_id("timeline.json"), by_id("iocs.json")


def _concurrent_kept(case, recs, *, ioc):
    F, T, iocs = _on_disk(case)
    ok = F.get("F-steve-002") == recs["F"] and T.get("T-steve-003") == recs["T"]
    return ok and (iocs.get("IOC-steve-002") == recs["I"] if ioc else True)


@pytest.mark.parametrize(
    "mode,answers,ioc",
    [("ids", (), False), ("rev", (), True), ("int", ("a", "s"), False)],
    ids=["ids", "review", "interactive"],
)
def test_records_staged_during_the_wait_are_kept(
    wait_case, monkeypatch, mode, answers, ioc
):
    recs = {}
    _run(
        wait_case,
        monkeypatch,
        mode,
        lambda: recs.update(_stage_concurrently(wait_case)),
        answers=answers,
    )
    assert _concurrent_kept(wait_case, recs, ioc=ioc)
    assert _on_disk(wait_case)[0]["F-steve-001"]["status"] == "APPROVED"


def test_records_staged_while_editor_is_open_are_kept(wait_case, monkeypatch, tmp_path):
    recs = {
        "F": _f("F-steve-002", "Staged during wait", "T-steve-003", ["10.9.9.9"]),
        "T": _t("T-steve-003", "F-steve-002", "Staged during wait"),
        "I": _ioc("IOC-steve-002", "10.9.9.9", "F-steve-002"),
    }
    script = tmp_path / "stage.py"
    script.write_text(STAGE_SCRIPT)
    editor = tmp_path / "editor.sh"
    editor.write_text(
        f"#!/bin/sh\n{sys.executable} {script} {wait_case} '{json.dumps(recs)}'\n"
    )
    editor.chmod(0o755)
    monkeypatch.setenv("EDITOR", str(editor))
    _run(wait_case, monkeypatch, "ids", lambda: None, edit=True)
    assert _concurrent_kept(wait_case, recs, ioc=False)


def _vanish(case):
    _write(case / "findings.json", [])


@pytest.mark.parametrize(
    "mode,answers",
    [("ids", ()), ("int", ("a", "s")), ("rev", ())],
    ids=["ids", "int", "rev"],
)
def test_an_item_deleted_during_the_wait_is_discarded_loudly_not_written_back(
    wait_case, monkeypatch, capsys, mode, answers
):
    """Under the case lock the files are read again; an item shown and since
    gone has its own decision discarded, loudly. Its cascades go with it."""
    rc, signed = _run(
        wait_case, monkeypatch, mode, lambda: _vanish(wait_case), answers=answers
    )
    err = capsys.readouterr().err
    assert "DISCARDED: F-steve-001 was changed or deleted after you saw it" in err
    assert rc == 1 and signed == []
    F, T, _ = _on_disk(wait_case)
    assert F == {} and T["T-steve-001"]["status"] == "DRAFT"


def test_one_of_three_items_edited_during_the_prompt_is_discarded_the_others_signed(
    wait_case, monkeypatch, capsys
):
    _write(wait_case / "findings.json",
           [_f(f"F-steve-00{n}", f"Finding {n}", None) for n in (1, 2, 3)])  # fmt: skip

    def edit_second():
        fs = json.loads((wait_case / "findings.json").read_text())
        fs[1]["title"] = "edited by someone else"
        _write(wait_case / "findings.json", fs)

    ids = ("F-steve-001", "F-steve-002", "F-steve-003")
    rc, signed = _run(wait_case, monkeypatch, "ids", edit_second, ids=ids)
    err = capsys.readouterr().err
    assert "DISCARDED: F-steve-002" in err and "1 decision(s) were discarded" in err
    assert rc == 1 and sorted(signed) == ["F-steve-001", "F-steve-003"]
    F = _on_disk(wait_case)[0]
    assert [F[i]["status"] for i in ids] == ["APPROVED", "DRAFT", "APPROVED"]
    assert F["F-steve-002"]["title"] == "edited by someone else"  # not overwritten


def test_note_and_interpretation_are_saved_with_the_concurrent_records(
    wait_case, monkeypatch
):
    recs = {}
    _run(
        wait_case,
        monkeypatch,
        "ids",
        lambda: recs.update(_stage_concurrently(wait_case)),
        note="EXAMINER-NOTE",
        interpretation="EXAMINER-INTERP",
    )
    f = _on_disk(wait_case)[0]["F-steve-001"]
    assert "EXAMINER-NOTE" in [n.get("note") for n in f.get("examiner_notes", [])]
    assert f["interpretation"] == "EXAMINER-INTERP" and _concurrent_kept(
        wait_case, recs, ioc=False
    )


def test_an_edit_is_saved_with_the_concurrent_records(wait_case, monkeypatch, tmp_path):
    editor = tmp_path / "edit.sh"
    editor.write_text(
        "#!/bin/sh\nsed -i 's/^title: .*/title: EXAMINER-EDITED-TITLE/' \"$1\"\n"
    )
    editor.chmod(0o755)
    monkeypatch.setenv("EDITOR", str(editor))
    recs = {}
    _run(
        wait_case,
        monkeypatch,
        "ids",
        lambda: recs.update(_stage_concurrently(wait_case)),
        edit=True,
    )
    assert _on_disk(wait_case)[0]["F-steve-001"]["title"] == "EXAMINER-EDITED-TITLE"
    assert _concurrent_kept(wait_case, recs, ioc=False)


def test_an_interactive_note_is_saved_with_the_concurrent_records(
    wait_case, monkeypatch
):
    recs = {}
    _run(
        wait_case,
        monkeypatch,
        "int",
        lambda: recs.update(_stage_concurrently(wait_case)),
        answers=("n", "INT-NOTE", "s"),
    )
    f = _on_disk(wait_case)[0]["F-steve-001"]
    assert "INT-NOTE" in [n.get("note") for n in f.get("examiner_notes", [])]
    assert f["status"] == "APPROVED" and _concurrent_kept(wait_case, recs, ioc=False)


@pytest.mark.parametrize(
    "mode,answers", [("ids", ()), ("int", ("s", "s", "a"))], ids=["ids", "interactive"]
)
def test_a_manual_event_is_approved_and_signed_with_the_concurrent_records(
    wait_case, monkeypatch, mode, answers
):
    recs = {}
    _, signed = _run(
        wait_case,
        monkeypatch,
        mode,
        lambda: recs.update(_stage_concurrently(wait_case)),
        ids=("T-steve-002",),
        answers=answers,
    )
    assert _on_disk(wait_case)[1]["T-steve-002"]["status"] == "APPROVED"
    assert "T-steve-002" in signed and _concurrent_kept(wait_case, recs, ioc=False)


def _corrupt(case, name):
    p = case / name
    p.chmod(0o644)
    p.write_text(_CORRUPT)


@pytest.mark.parametrize("name", ["findings.json", "timeline.json"])
@pytest.mark.parametrize(
    "mode,answers",
    [("ids", ()), ("int", ("a", "s")), ("rev", ())],
    ids=["ids", "int", "rev"],
)
def test_a_file_corrupted_during_the_wait_saves_the_decisions_and_signs_nothing(
    wait_case, monkeypatch, capsys, mode, answers, name
):
    good = (wait_case / name).read_text()
    rc, signed = _run(
        wait_case, monkeypatch, mode, lambda: _corrupt(wait_case, name), answers=answers
    )
    err = capsys.readouterr().err
    assert rc == 1 and signed == []
    assert f"{name} couldn't be read as case data. Nothing was signed" in err
    assert (wait_case / name).read_text() == _CORRUPT  # never saved over
    saved = json.loads((wait_case / "pending-reviews.json").read_text())["items"]
    assert [(e["id"], e["action"]) for e in saved] == [("F-steve-001", "approve")]
    assert saved[0]["saved_unsigned"]["reason"] == "case file unreadable"
    # repaired, the next `vhir approve` points at them and --review signs them
    _write(wait_case / name, json.loads(good))
    monkeypatch.setenv("VHIR_CASE_DIR", str(wait_case))
    monkeypatch.setattr("builtins.input", lambda prompt="": "q")
    approve_mod.cmd_approve(Namespace(case=None, ids=[], review=False), _IDENT)
    assert (
        "1 of your decision(s) were saved unsigned (case file unreadable)"
        in capsys.readouterr().out
    )
    _, signed = _run(wait_case, monkeypatch, "rev-saved", lambda: None)
    assert "F-steve-001" in signed
    assert _on_disk(wait_case)[0]["F-steve-001"]["status"] == "APPROVED"


@pytest.mark.parametrize(
    "mode,answers,signs",
    [
        ("ids", (), ["F-steve-001", "IOC-steve-001", "T-steve-001"]),
        ("rev", (), ["F-steve-001", "IOC-steve-001", "T-steve-001"]),
        # T-steve-001 is skipped at its own prompt: a skipped item is never cascaded
        ("int", ("a", "s"), ["F-steve-001", "IOC-steve-001"]),
    ],
    ids=["ids", "rev", "int"],
)
def test_without_a_concurrent_write_the_outcome_is_unchanged(
    wait_case, monkeypatch, mode, answers, signs
):
    _, signed = _run(wait_case, monkeypatch, mode, lambda: None, answers=answers)
    F, T, iocs = _on_disk(wait_case)
    assert F["F-steve-001"]["status"] == "APPROVED"
    assert iocs["IOC-steve-001"]["status"] == "APPROVED"
    assert T["T-steve-001"]["status"] == (
        "APPROVED" if "T-steve-001" in signs else "DRAFT"
    )
    assert T["T-steve-002"]["status"] == "DRAFT"
    assert sorted(signed) == signs
