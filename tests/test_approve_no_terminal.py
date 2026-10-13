"""An approve or reject with no examiner at a terminal saves nothing, and the
examiner is told at the next approve and review.

An AI's shell, or a pipe, has no /dev/tty: the passphrase prompt can't open
it. The decisions used to be saved unsigned into pending-reviews.json, as if
the examiner had made them. Now nothing is saved: one audit line records the
attempt, and `vhir approve`, `vhir review` and the Portal count the attempts.
A human at a terminal whose signing fails (a wrong passphrase, a lockout)
keeps today's unsigned save.

Each run is the real `vhir` CLI in a new session (setsid, stdin /dev/null),
so /dev/tty can't be opened; its keys, ledger and password folders are this
test's scratch folders.
"""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace

import pytest
import yaml

from vhir_cli import approval_auth, keys, ledger, verification
from vhir_cli.case_io import save_findings, save_timeline

from .signing import enrol

RUNNER = """
import json, sys
from pathlib import Path
from vhir_cli import approval_auth, keys, ledger, verification
cfg = json.loads(sys.argv[1])
keys.KEYS_DIR = Path(cfg["keys"])
ledger.LEDGER_DIR = Path(cfg["ledger"])
verification.VERIFICATION_DIR = Path(cfg["verification"])
approval_auth._PASSWORDS_DIR = Path(cfg["passwords"])
approval_auth._maybe_migrate_pin_dir = lambda: None
sys.argv = ["vhir", *cfg["argv"]]
from vhir_cli.main import main
main()
"""
PENDING = {"case_id": "C-1", "items": [
    {"id": "F-tester-002", "type": "finding", "action": "approve", "staged_by": "someone"}]}  # fmt: skip


def _finding(fid):
    return {"id": fid, "status": "DRAFT", "title": "t", "observation": "o",
            "interpretation": "i", "confidence": "LOW", "type": "finding",
            "audit_ids": [], "created_by": "tester", "staged": "2026-10-13T00:00:00Z"}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    (d / "evidence.json").write_text('{"files": []}')
    (d / "todos.json").write_text("[]")
    save_findings(d, [_finding("F-tester-001"), _finding("F-tester-002")])
    save_timeline(d, [])
    (d / "pending-reviews.json").write_text(json.dumps(PENDING))
    enrol("tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _vhir(tmp_path, *argv, stdin=subprocess.DEVNULL):
    """The CLI with no controlling terminal; this test's state folders."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    cfg = {"keys": str(keys.KEYS_DIR), "ledger": str(ledger.LEDGER_DIR),
           "verification": str(verification.VERIFICATION_DIR),
           "passwords": str(approval_auth._PASSWORDS_DIR), "argv": list(argv)}  # fmt: skip
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "VHIR_EXAMINER": "tester",
           "VHIR_CASE_DIR": str(tmp_path / "C-1"), "PYTHONPATH": ":".join(sys.path)}  # fmt: skip
    return subprocess.run([sys.executable, "-c", RUNNER, json.dumps(cfg)], env=env,
                          stdin=stdin, capture_output=True, text=True, timeout=120,
                          start_new_session=True)  # fmt: skip


def _notices(case) -> list[dict]:
    f = case / "audit" / "cli-approve.jsonl"
    return (
        [json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []
    )


@pytest.mark.parametrize(
    "argv, stdin, action",
    [(["approve", "F-tester-001"], subprocess.DEVNULL, "approve"),
     (["reject", "F-tester-001", "--reason", "wrong host"], subprocess.DEVNULL, "reject"),
     (["approve"], "piped", "approve")],
    ids=["approve ids", "reject ids", "interactive approve, stdin piped"],
)  # fmt: skip
def test_with_no_terminal_nothing_is_saved_and_one_notice_is_written(
    case, tmp_path, argv, stdin, action
):
    before = {
        n: (case / n).read_bytes() for n in ("pending-reviews.json", "findings.json")
    }
    if stdin == "piped":  # approve each item it offers, as a pipe would
        feed = tmp_path / "answers"
        feed.write_text("a\n" * 10)
        with open(feed) as f:
            r = _vhir(tmp_path, *argv, stdin=f)
    else:
        r = _vhir(tmp_path, *argv, stdin=stdin)
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert (
        "Approving and rejecting need the examiner at a terminal (/dev/tty isn't "
        "available). Nothing was signed or saved." in r.stderr
    ), r.stderr
    for name, data in before.items():
        assert (case / name).read_bytes() == data, name
    (notice,) = _notices(case)
    assert notice["tool"] == action and notice["examiner"] == "tester"
    assert "F-tester-001" in notice["params"]["ids"]
    assert notice["result_summary"] == {
        "status": "NO_TERMINAL",
        "reason": "no terminal",
    }
    assert "audit_id" not in notice


def test_the_next_approve_and_review_count_the_refused_attempts(case, tmp_path, capsys):
    assert _vhir(tmp_path, "approve", "F-tester-001").returncode == 1
    assert _vhir(tmp_path, "reject", "F-tester-001").returncode == 1
    from vhir_cli.case_io import no_terminal_line

    line = no_terminal_line(case)
    assert line.startswith(
        "  2 approve/reject attempt(s) refused: no terminal (latest "
    )
    assert line.endswith("F-tester-001) — not you? see `vhir audit`")
    from vhir_cli.commands.review import cmd_review

    cmd_review(Namespace(case=None), {"examiner": "tester"})
    assert line in capsys.readouterr().out
    from vhir_cli.commands.approve import cmd_approve

    try:  # it then stops at the unknown id; the line comes first
        cmd_approve(
            Namespace(case=None, ids=["F-nope"], review=False), {"examiner": "tester"}
        )
    except SystemExit:
        pass
    assert capsys.readouterr().out.startswith(line + "\n")


def test_a_case_with_no_refused_attempts_prints_no_line(case):
    from vhir_cli.case_io import no_terminal_line

    assert no_terminal_line(case) == ""
