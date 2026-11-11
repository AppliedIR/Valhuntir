"""`vhir setup join-code` asks the gateway for a code only once /health passes.

After a rebind that restarted the gateway, join-code waits for /health on one
240 s budget (vhir_cli.gateway.wait_for_health). With no rebind to do, it
checks /health once. A restart that failed, or a gateway that never passes,
ends the run with exit 1, a reason, a fix and the line that says to run
join-code again; no code is requested. A declined rebind and a failed
gateway.yaml write go on to the request as before: the gateway itself is
unchanged.

/health is the stand-in from tests/health_stand_in.py, on its own clock. The
old 10-try loop's urlopen is refused and its sleeps are recorded, so no row
dials a port or sleeps for real on any tree. Values are synthetic.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
import urllib.request
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml

from tests import health_stand_in
from tests.health_stand_in import T0
from vhir_cli.commands import join

TOKEN = "vhir_gw_" + "1" * 24
RERUN = "Then run `vhir setup join-code` again."
RESTART_FAILED_FIX = (
    "If the gateway runs as a service: systemctl --user status vhir-gateway,"
    " fix what it shows, then run vhir setup join-code. If you start it by hand: stop it,"
    " run ~/.vhir/start-gateway.sh, then run vhir setup join-code."
)
REFUSED_REASON = "nothing answered on port 4508 (refused)"
REFUSED_FIX = "start the gateway: systemctl --user restart vhir-gateway"
HINT = "run /mcp in each (or restart it)"


def _passes_after(seconds):
    def answer(h):
        return (
            health_stand_in.PASS if h.waited() >= seconds else ConnectionRefusedError()
        )

    return answer


class _Requests:
    """The requests module: each post is recorded with the stand-in's clock."""

    exceptions = SimpleNamespace(ConnectionError=ConnectionError)

    def __init__(self) -> None:
        self.posts: list[tuple[str, float]] = []

    def post(self, url, **kw):
        self.posts.append((url, health_stand_in.current().now))
        return MagicMock(status_code=200, json=lambda: {"code": "EXAMPLE-0000"})


def _join_code(
    tmp_path,
    monkeypatch,
    capsys,
    *,
    host="127.0.0.1",
    answer="y",
    restart=0,
    health=health_stand_in.PASS,
    write_fails=False,
):
    """Run cmd_setup_join_code; `restart` is the rebind restart's exit status,
    or the exception it raises; `health` is what /health gives."""
    gw = tmp_path / ".vhir" / "gateway.yaml"
    gw.parent.mkdir()
    gw.write_text(
        yaml.dump(
            {
                "gateway": {"host": host, "port": 4508},
                "api_keys": {TOKEN: {"examiner": "jdoe", "role": "lead"}},
            },
            sort_keys=False,
        )
    )
    h = health_stand_in.current()
    h.answer = health
    requests = _Requests()
    cmds, prompts, slept, done = [], [], [], []

    def run(cmd, **kw):
        cmds.append(cmd)
        if cmd[:3] == ["systemctl", "--user", "restart"] and isinstance(
            restart, BaseException
        ):
            raise restart
        failed = cmd[:3] == ["systemctl", "--user", "restart"] and restart != 0
        return MagicMock(
            returncode=restart if failed else 0,
            stdout="",
            stderr="Job for vhir-gateway.service failed." if failed else "",
        )

    def ask(prompt=""):
        prompts.append(prompt)
        return answer

    def refused(*a, **kw):
        raise ConnectionRefusedError("refused")

    real_open = os.open

    def os_open(path, *a, **kw):
        if write_fails and str(path) == str(gw):
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, *a, **kw)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VHIR_STATIC_IP_SETTLED", "1")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "requests", requests)
    monkeypatch.setattr(join, "_get_local_gateway_token", lambda: TOKEN)
    monkeypatch.setattr(join, "_find_ca_cert", lambda: None)
    monkeypatch.setattr(join, "_post_join_code_setup", lambda *a: done.append(a))
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("builtins.input", ask)
    monkeypatch.setattr(urllib.request, "urlopen", refused)
    monkeypatch.setattr(time, "sleep", slept.append)
    monkeypatch.setattr(os, "open", os_open)
    rc = None
    try:
        join.cmd_setup_join_code(
            SimpleNamespace(revoke=False, expires=None, name=None), {}
        )
    except SystemExit as e:
        rc = e.code
    out, err = capsys.readouterr()
    return SimpleNamespace(
        rc=rc,
        out=out,
        err=err,
        posts=requests.posts,
        done=done,
        cmds=cmds,
        prompts=prompts,
        slept=slept,
        health=h,
        yaml=yaml.safe_load(gw.read_text()),
    )


def _restarts(run):
    return [c for c in run.cmds if c[:3] == ["systemctl", "--user", "restart"]]


# --- a rebind that restarted the gateway -------------------------------------


def test_the_code_is_requested_after_health_passes(tmp_path, monkeypatch, capsys):
    run = _join_code(tmp_path, monkeypatch, capsys, health=_passes_after(20))
    assert run.rc is None, run.err
    assert len(run.posts) == 1, run.posts
    # the request comes after the pass, on the stand-in's clock: no real sleep
    assert run.posts[0][1] >= T0 + 20, (run.posts, run.health.calls)
    assert all(at < T0 + 20 for _, _, at in run.health.calls[:-1])
    assert run.slept == [], run.slept
    assert len(_restarts(run)) == 1
    assert "Gateway now listening on 0.0.0.0:4508 (all interfaces)." in run.out
    assert HINT in run.out
    assert len(run.done) == 1


def test_health_that_never_passes_ends_with_the_rerun_line(
    tmp_path, monkeypatch, capsys
):
    run = _join_code(tmp_path, monkeypatch, capsys, health=ConnectionRefusedError())
    assert run.rc == 1, run.out + run.err
    assert run.posts == [], run.posts
    assert REFUSED_REASON in run.err and REFUSED_FIX in run.err, run.err
    assert RERUN in run.err, run.err
    assert len(run.health.calls) > 1
    assert all(at < T0 + 240 for _, _, at in run.health.calls)
    assert run.health.waited() <= 240
    assert HINT not in run.out + run.err
    assert run.done == []


@pytest.mark.parametrize(
    "restart",
    [
        1,
        FileNotFoundError(2, "No such file or directory", "systemctl"),
        subprocess.TimeoutExpired(["systemctl"], 15),
    ],
    ids=["rc-1", "no-systemctl", "timeout"],
)
def test_a_failed_restart_names_join_code_in_both_fixes(
    tmp_path, monkeypatch, capsys, restart
):
    run = _join_code(tmp_path, monkeypatch, capsys, restart=restart)
    assert run.rc == 1, run.out + run.err
    assert run.posts == [], run.posts
    assert " failed (" in run.out + run.err
    assert RESTART_FAILED_FIX in run.err, run.err
    assert "vhir update" not in run.out + run.err
    assert run.health.calls == []  # no wait after a failed restart
    assert run.yaml["gateway"]["host"] == "0.0.0.0"  # the rerun has no rebind
    assert HINT not in run.out + run.err
    assert run.done == []


@pytest.mark.parametrize(
    "ends",
    [
        dict(health=ConnectionRefusedError()),
        dict(restart=1),
        dict(host="0.0.0.0", health=ConnectionRefusedError()),
    ],
    ids=["health-never-passes", "restart-failed", "no-rebind-nothing-answering"],
)
def test_every_command_the_failure_text_names_is_one_the_cli_takes(
    tmp_path, monkeypatch, capsys, ends
):
    from vhir_cli.main import build_parser

    run = _join_code(tmp_path, monkeypatch, capsys, **ends)
    assert run.rc == 1, run.out + run.err
    named = set(re.findall(r"\bvhir(?: --?[a-z][a-z-]*| [a-z][a-z-]*)+", run.err))
    assert any("join-code" in command for command in named), run.err
    for command in sorted(named):
        try:
            build_parser().parse_args(command.split()[1:])
        except SystemExit:
            pytest.fail(f"the text names `{command}`, which the CLI refuses")


# --- no rebind to do -----------------------------------------------------------


def test_no_rebind_and_nothing_answering_ends_with_the_rerun_line(
    tmp_path, monkeypatch, capsys
):
    run = _join_code(
        tmp_path, monkeypatch, capsys, host="0.0.0.0", health=ConnectionRefusedError()
    )
    assert run.rc == 1, run.out + run.err
    assert run.posts == [], run.posts
    assert len(run.health.calls) == 1  # one call, no wait
    assert REFUSED_REASON in run.err and RERUN in run.err, run.err
    assert run.prompts == [] and _restarts(run) == []
    assert run.done == []


def test_no_rebind_and_health_up_requests_the_code_at_once(
    tmp_path, monkeypatch, capsys
):
    run = _join_code(tmp_path, monkeypatch, capsys, host="0.0.0.0")
    assert len(run.health.calls) == 1, run.health.calls
    assert run.health.slept == [] and run.slept == []
    assert run.rc is None, run.err
    assert len(run.posts) == 1
    assert run.prompts == [] and _restarts(run) == []
    assert len(run.done) == 1


# --- unchanged: a declined rebind, a failed write -----------------------------


def test_a_declined_rebind_requests_the_code_as_before(tmp_path, monkeypatch, capsys):
    run = _join_code(tmp_path, monkeypatch, capsys, answer="n")
    assert "Skipped. To rebind manually" in run.err
    assert run.rc is None, run.err
    assert len(run.posts) == 1
    assert _restarts(run) == [] and run.health.calls == []
    assert run.yaml["gateway"]["host"] == "127.0.0.1"
    assert len(run.done) == 1


def test_a_failed_yaml_write_requests_the_code_as_before(tmp_path, monkeypatch, capsys):
    run = _join_code(tmp_path, monkeypatch, capsys, write_fails=True)
    assert "Failed to update gateway.yaml: " in run.err
    assert run.rc is None, run.err
    assert len(run.posts) == 1
    assert _restarts(run) == [] and run.health.calls == []
    assert run.yaml["gateway"]["host"] == "127.0.0.1"
    assert len(run.done) == 1
