"""vhir exec runs a command only when its audit entry can be written to the
case's own log, and says so when a write after the run fails."""

import json
import os
import resource
import subprocess
import sys

import pytest

from vhir_cli.case_io import KEPT

# cmd_exec in a child: confirmed at a fake terminal, subprocess.run faked (it
# only leaves a marker), so no command runs and rlimits stay in the child
CHILD = r"""
import os, subprocess, sys
from pathlib import Path
if os.environ.get("STDOUT_CLOSED"):  # a reader that stopped early (| head)
    r, w = os.pipe(); os.close(r); os.dup2(w, 1)
from unittest.mock import MagicMock, patch
from vhir_cli.commands import execute
tty = MagicMock(); tty.readline.return_value = "y\n"
def run(cmd, **kw):
    Path(sys.argv[2]).write_text("ran")
    size = os.environ.get("STDOUT_SIZE")  # with a closed stdout: past the buffer, short or none
    out = {"big": "r/r 5-128-1:\tfile-one.txt\n" * 1000, "short": "x" * 30, "empty": ""}.get(
        size, "r/r 5-128-1:\tfile-one.txt\n")
    return subprocess.CompletedProcess(cmd, 0, out, "")
class A: cmd = ["fakefls", "-r", "image.dd"]; purpose = "triage"; case = None
with patch("vhir_cli.approval_auth.open", return_value=tty), patch.object(execute.subprocess, "run", run):
    execute.cmd_exec(A(), {"examiner": "tester"})
"""
PRIOR = '{"audit_id": "cliexec-tester-20000101-001", "tool": "exec"}\n'
NOT_RUN = "Not run: vhir exec can't write this command's audit entry ({}: {}). {}"
WRITABLE = (
    "Check the permissions of the case's audit/ folder and log, then run it again."
)
ADVICE = {  # the log's shape -> the step the refusal gives for it: never to change the log
    "Permission denied": WRITABLE,
    "not a regular file": KEPT,
    "a symbolic link": KEPT,
    "another name links to it": KEPT,
}  # fmt: skip
RAN = "WARNING: the command ran, but its audit entry couldn't be written ({}: {}), so it is not in the case's audit trail."


def _exec(case, fsize=None, stdout_closed=""):
    mark = case.parent / "ran"
    mark.unlink(missing_ok=True)

    def limits():  # bounded memory always; a file-size limit when asked
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
        if fsize is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))

    env = {**os.environ, "VHIR_CASE_DIR": str(case), "PYTHONDONTWRITEBYTECODE": "1"}
    if stdout_closed:
        env["STDOUT_CLOSED"], env["STDOUT_SIZE"] = "1", stdout_closed
    p = subprocess.run([sys.executable, "-c", CHILD, "-", str(mark)], env=env, timeout=20,
                       capture_output=True, text=True, preexec_fn=limits)  # fmt: skip
    # the prompt has no newline
    last = p.stderr.strip().splitlines()[-1].removeprefix("Execute? [y/N]: ")
    return p.returncode, p.stdout, last, mark.exists()


@pytest.fixture
def case(tmp_path):
    (tmp_path / "case" / "audit").mkdir(parents=True)
    (tmp_path / "case" / "evidence").mkdir()
    yield tmp_path / "case"
    for p in (tmp_path / "case", tmp_path / "case" / "audit"):
        if p.is_dir():
            p.chmod(0o755)


def _log(case):
    return case / "audit" / "cli-exec.jsonl"


def _prior(case, mode=None):
    _log(case).write_text(PRIOR)
    if mode is not None:
        _log(case).chmod(mode)


def _no_audit(case):
    (case / "audit").rmdir()
    case.chmod(0o555)


REFUSED = {
    "audit folder read-only": (lambda c: (c / "audit").chmod(0o555), "Permission denied"),
    "log read-only": (lambda c: _prior(c, 0o444), "Permission denied"),
    "log write-only": (lambda c: _prior(c, 0o200), "Permission denied"),
    "no audit folder, case read-only": (_no_audit, "Permission denied"),
    "log is /dev/zero": (lambda c: _log(c).symlink_to("/dev/zero"), "a symbolic link"),
    "log is a FIFO": (lambda c: os.mkfifo(_log(c)), "not a regular file"),
    "log links out of the case": (
        lambda c: (_log(c).symlink_to(c.parent / "out.jsonl"), (c.parent / "out.jsonl").write_text(PRIOR)),
        "a symbolic link"),
    "log is a dangling link": (lambda c: _log(c).symlink_to(c.parent / "nowhere.jsonl"), "a symbolic link"),
    "log is a hard link to evidence": (
        lambda c: ((c / "evidence" / "disk.img").write_text("disk\n" * 4),
                   os.link(c / "evidence" / "disk.img", _log(c))),
        "another name links to it"),
}  # fmt: skip


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
@pytest.mark.parametrize("shape", list(REFUSED))
def test_a_log_it_cant_write_to_refuses_the_run_by_name(case, shape):
    setup, why = REFUSED[shape]
    setup(case)
    before = {p.name: p.read_bytes() for p in (case.parent, case / "evidence") for p in p.iterdir()
              if p.is_file()}  # fmt: skip
    rc, out, err, ran = _exec(case)
    assert (rc, ran) == (1, False)
    assert err == NOT_RUN.format(_log(case), why, ADVICE[why])  # fmt: skip
    assert "Audit ID" not in out
    assert not (case.parent / "nowhere.jsonl").exists()
    assert before == {p.name: p.read_bytes() for p in (case.parent, case / "evidence") for p in p.iterdir()
                      if p.is_file() and p.name != "ran"}  # fmt: skip


@pytest.mark.parametrize("room", [0, 20])  # refused outright, or a short write
def test_a_failed_write_after_the_run_is_loud_and_leaves_the_log_as_it_was(case, room):
    _prior(case)
    rc, out, err, ran = _exec(case, fsize=len(PRIOR) + room)
    assert (rc, ran) == (1, True)
    assert err == RAN.format(_log(case), "File too large")
    assert "file-one.txt" in out and "Audit ID" not in out
    assert _log(case).read_text() == PRIOR
    rc, out, err, ran = _exec(case)  # the next run's entry stands alone, with a new id
    ids = [json.loads(line)["audit_id"] for line in _log(case).read_text().splitlines()]
    assert rc == 0 and len(ids) == len(set(ids)) == 2
    assert out.strip().splitlines()[-1] == f"Audit ID: {ids[-1]}"


def test_an_audit_folder_that_links_to_another_case_refuses_the_run(case):
    """The folder is checked too, not only the log: an entry never lands in
    another case's trail."""
    other = case.parent / "other" / "audit"
    other.mkdir(parents=True)
    (other / "cli-exec.jsonl").write_text(PRIOR)
    (case / "audit").rmdir()
    (case / "audit").symlink_to(other)
    rc, out, err, ran = _exec(case)
    assert (rc, ran) == (1, False)
    link = "a symbolic link"
    assert err == NOT_RUN.format(_log(case), link, ADVICE[link])
    assert (other / "cli-exec.jsonl").read_text() == PRIOR


@pytest.mark.parametrize("size", ["big", "short", "empty"])
def test_a_reader_that_stops_early_still_hears_the_write_failed(case, size):
    """The output goes to a pipe its reader closed (| head): past stdout's
    buffer, or short enough to sit in it, or none. The warning on stderr
    still says the entry wasn't written, and the exit is 1."""
    _prior(case)
    rc, _, err, ran = _exec(case, fsize=len(PRIOR), stdout_closed=size)
    assert (rc, ran) == (1, True)
    assert err == RAN.format(_log(case), "File too large")
    assert _log(case).read_text() == PRIOR
