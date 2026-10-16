"""`vhir case close` asks for confirmation; with no terminal to answer it, the case
stays open and the examiner is told to run it in a terminal.

Each run is the real `vhir` CLI in a child process; its stdin is /dev/null (no
answer) or a pipe carrying "y". Its keys, ledger and verification folders are
this test's scratch folders.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest
import yaml

RUNNER = """
import json, sys
from pathlib import Path
from vhir_cli import keys, ledger, verification
cfg = json.loads(sys.argv[1])
keys.KEYS_DIR = Path(cfg["keys"])
ledger.LEDGER_DIR = Path(cfg["ledger"])
verification.VERIFICATION_DIR = Path(cfg["verification"])
sys.argv = ["vhir", *cfg["argv"]]
from vhir_cli.main import main
main()
"""
NOT_CLOSED = (
    "Not closed: `vhir case close` asks for confirmation; run it in a terminal."
)


@pytest.fixture
def cases(tmp_path):
    root = tmp_path / "cases"
    d = root / "C-5"
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-5", "status": "open"}))
    (d / "findings.json").write_text("[]")
    (d / "timeline.json").write_text("[]")
    return root


def _close(tmp_path, cases, stdin):
    store = tmp_path / "store"
    (store / "ledger").mkdir(parents=True, exist_ok=True)  # a store this box can see
    cfg = {name: str(store / name) for name in ("keys", "ledger", "verification")}
    cfg["argv"] = ["case", "close", "C-5"]
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "VHIR_CASES_DIR": str(cases),
           "VHIR_EXAMINER": "steve"}  # fmt: skip
    return subprocess.run(
        [sys.executable, "-c", RUNNER, json.dumps(cfg)],
        input=stdin,
        stdin=None if stdin is not None else subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def _status(cases):
    return yaml.safe_load((cases / "C-5" / "CASE.yaml").read_text())["status"]


def test_with_no_answer_the_case_stays_open_and_says_why(tmp_path, cases):
    run = _close(tmp_path, cases, None)
    assert run.returncode == 1, (run.stdout, run.stderr)
    assert NOT_CLOSED in run.stderr and "Traceback" not in run.stderr, run.stderr
    assert "EOFError" not in run.stdout + run.stderr
    assert _status(cases) == "open"
    assert not (cases / "C-5" / "ledger").exists()


def test_a_piped_y_closes_the_case(tmp_path, cases):
    run = _close(tmp_path, cases, "y\n")
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert NOT_CLOSED not in run.stdout + run.stderr
    assert _status(cases) == "closed"


def test_a_piped_n_cancels_as_before(tmp_path, cases):
    run = _close(tmp_path, cases, "n\n")
    assert run.returncode == 0, (run.stdout, run.stderr)
    assert "Cancelled." in run.stdout and NOT_CLOSED not in run.stdout + run.stderr
    assert _status(cases) == "open"
