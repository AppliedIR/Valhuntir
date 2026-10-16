"""A gateway restart that outlasts its 60 s timeout is reported from the
gateway's state, not as a traceback.

systemd carries on with a restart its systemctl client gave up on, so the
gateway may be up by then: `is-active` says whether it is."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tests import test_update
from vhir_cli.commands.update import cmd_update

manifest_dir = test_update.manifest_dir


def _run(state):
    """subprocess.run whose gateway restart times out; is-active answers `state`."""

    def run(cmd, **kwargs):
        result = MagicMock(returncode=0, stdout="0", stderr="stubbed")
        if cmd[:2] == ["uv", "--version"]:
            result.stdout = "uv 0.12.20"
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif cmd[-2:] == ["restart", "vhir-gateway"]:
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        elif cmd[-2:] == ["is-active", "vhir-gateway"]:
            if isinstance(state, BaseException):
                raise state
            result.stdout = state + "\n"
            result.returncode = 0 if state == "active" else 3
        return result

    return run


def _update(home, state):
    with (
        patch("pathlib.Path.home", return_value=home),
        patch("subprocess.run", side_effect=_run(state)),
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test") as smoke,
        patch("time.sleep"),
    ):
        cmd_update(test_update._make_args(), {})
    return smoke


def test_a_slow_restart_that_came_up_is_done(manifest_dir, capsys):
    smoke = _update(manifest_dir[0], "active")
    out = capsys.readouterr().out
    assert "Restarting gateway... done" in out
    assert smoke.called


def test_a_slow_restart_still_starting_says_so(manifest_dir, capsys):
    smoke = _update(manifest_dir[0], "activating")
    out = capsys.readouterr().out
    assert "failed (no answer in 60 s; the gateway is activating)" in out
    # A gateway started by hand has no systemd unit to restart; the hint also
    # names the manual launcher so that user isn't left at a dead end.
    assert "~/.vhir/start-gateway.sh" in out
    # A hand-started gateway must be stopped before relaunch —
    # start-gateway.sh is a bare exec that would collide on the port otherwise —
    # so "stop" comes before the launcher in the hint.
    assert "stop it, then run ~/.vhir/start-gateway.sh" in out
    assert "Skipping connectivity test" in out and not smoke.called


@pytest.mark.parametrize(
    "state",
    [
        "",
        subprocess.TimeoutExpired(["systemctl"], 10),
        FileNotFoundError("systemctl"),
        PermissionError("systemctl"),
    ],
    ids=["empty", "timeout", "not-found", "permission"],
)
def test_no_state_from_is_active_reads_unknown(manifest_dir, capsys, state):
    smoke = _update(manifest_dir[0], state)
    out = capsys.readouterr().out
    assert "failed (no answer in 60 s; the gateway is unknown)" in out
    assert "Skipping connectivity test" in out and not smoke.called
