"""A case data file that isn't a regular file is refused unread.

`evidence.json` as a FIFO: `vhir evidence list` and `verify` exit 1 with
"Failed to read evidence registry: <path> isn't a regular file ..." instead of
waiting for a writer. The case loaders (findings, timeline, todos, IOCs)
refuse a FIFO or a link to /dev/zero with CaseFileNotRegular, an OSError, rather
than blocking or reading without end. Each call runs in a forked child with a
hard join timeout and its address space capped.
"""

from __future__ import annotations

import contextlib
import io
import os
import pickle
import resource
import select
import signal
import stat
import sys

import pytest

from vhir_cli import case_io
from vhir_cli.commands.evidence import cmd_list_evidence, cmd_verify_evidence

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs are POSIX")


def _within(fn, timeout=8.0):
    """What `fn` returns in a forked child, or ("blocked",) if it doesn't
    within `timeout` (the child is then killed). The child's address space is
    capped at its size plus 1 GiB."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:  # the child: answer through the pipe, then exit at once
        os.close(r)
        try:
            with open("/proc/self/statm") as f:
                size = int(f.read().split()[0]) * os.sysconf("SC_PAGE_SIZE")
            resource.setrlimit(resource.RLIMIT_AS, (size + (1 << 30), size + (1 << 30)))
            out = ("ok", fn())
        except BaseException as e:  # noqa: BLE001 - reported to the parent
            out = ("raised", f"{type(e).__name__}: {e}")
        os.write(w, pickle.dumps(out))
        os._exit(0)
    os.close(w)
    try:
        ready, _, _ = select.select([r], [], [], timeout)
        if not ready:
            os.kill(pid, signal.SIGKILL)
            return ("blocked",)
        data = b""
        while chunk := os.read(r, 65536):
            data += chunk
        return pickle.loads(data)
    finally:
        os.close(r)
        os.waitpid(pid, 0)


class _Args:
    case = None


IDENTITY = {"os_user": "t", "examiner": "t", "examiner_source": "flag"}


def _cli(cmd):
    """The command's exit code and stderr, run in the child."""

    def run():
        err = io.StringIO()
        code = 0
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            try:
                cmd(_Args(), IDENTITY)
            except SystemExit as e:
                code = e.code
        return code, err.getvalue()

    return _within(run)


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path))
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence.json").write_text('{"files": []}')
    return tmp_path


@pytest.mark.parametrize(
    "cmd", [cmd_list_evidence, cmd_verify_evidence], ids=["list", "verify"]
)
def test_a_fifo_registry_gives_the_cli_an_error_at_once(case_dir, cmd):
    reg = case_dir / "evidence.json"
    reg.unlink()
    os.mkfifo(reg)
    assert _cli(cmd) == (
        "ok",
        (
            1,
            f"Failed to read evidence registry: {reg} isn't a regular file (a named "
            "pipe, socket or device). Put the case's own file back, then try again.\n",
        ),
    )
    assert stat.S_ISFIFO(os.lstat(reg).st_mode)


LOADERS = [
    (case_io.load_findings, "findings.json"),
    (case_io.load_timeline, "timeline.json"),
    (case_io.load_todos, "todos.json"),
    (case_io.load_iocs, "iocs.json"),
]


@pytest.mark.parametrize("how", ["fifo", "dev zero"])
@pytest.mark.parametrize("load,name", LOADERS, ids=[n for _, n in LOADERS])
def test_a_case_file_that_isnt_regular_is_refused_by_its_loader(
    tmp_path, load, name, how
):
    path = tmp_path / name
    if how == "fifo":
        os.mkfifo(path)
    else:
        path.symlink_to("/dev/zero")
    assert _within(lambda: load(tmp_path)) == (
        "raised",
        f"CaseFileNotRegular: {path} isn't a regular file (a named pipe, socket or "
        "device). Put the case's own file back, then try again.",
    )


@pytest.mark.parametrize("load,name", LOADERS, ids=[n for _, n in LOADERS])
def test_a_regular_case_file_still_loads(tmp_path, load, name):
    (tmp_path / name).write_text('[{"id": "x"}]')
    assert _within(lambda: load(tmp_path)) == ("ok", [{"id": "x"}])
