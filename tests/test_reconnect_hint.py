"""After vhir restarts the gateway, it says open Claude Code sessions must reconnect.

A gateway restart drops every running Claude Code session's tool connections,
and they don't come back until /mcp is run in the session or it restarts.
`vhir join` (rebinding for remote access) and `vhir update` restart the
gateway; each now says so after a restart that succeeded, and says nothing
more after one that failed (each already prints its own error).
"""

from __future__ import annotations

import contextlib
from unittest.mock import MagicMock, patch

import pytest
import yaml

from tests import test_update
from vhir_cli.commands import join
from vhir_cli.commands.update import cmd_update

HINT = (
    "Open Claude Code sessions lose their tool connections when the gateway "
    "restarts: run /mcp in each (or restart it)."
)


def _run(code):
    """subprocess.run answering `code` for the gateway restart, 0 otherwise."""

    def run(cmd, **kwargs):
        result = MagicMock(returncode=0, stdout="0", stderr="stubbed")
        if cmd[:2] == ["uv", "--version"]:
            result.stdout = "uv 0.12.20"
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif cmd[-2:] == ["restart", "vhir-gateway"]:
            result.returncode = code
        return result

    return run


class TestJoin:
    @pytest.fixture
    def home(self, tmp_path):
        gw = tmp_path / ".vhir" / "gateway.yaml"
        gw.parent.mkdir()
        gw.write_text(yaml.dump({"gateway": {"host": "127.0.0.1", "port": 4508}}))
        return tmp_path

    def _rebind(self, home, code, health):
        with (
            patch("pathlib.Path.home", return_value=home),
            patch("builtins.input", return_value="y"),
            patch("subprocess.run", side_effect=_run(code)),
            patch("time.sleep"),
            patch("urllib.request.urlopen", side_effect=health),
        ):
            join._ensure_remote_binding()

    def test_a_restart_that_came_back_healthy_says_to_reconnect(self, home, capsys):
        ok = contextlib.nullcontext(MagicMock(status=200))
        self._rebind(home, 0, lambda *a, **k: ok)
        out = capsys.readouterr().out
        assert "Gateway now listening on 0.0.0.0:4508" in out and HINT in out

    def test_a_failed_restart_says_nothing_more(self, home, capsys):
        self._rebind(home, 1, lambda *a, **k: pytest.fail("health checked"))
        captured = capsys.readouterr()
        assert "failed: stubbed" in captured.err
        assert HINT not in captured.out + captured.err

    def test_a_gateway_that_didn_t_come_back_healthy_says_nothing_more(
        self, home, capsys
    ):
        self._rebind(home, 0, OSError("refused"))
        captured = capsys.readouterr()
        assert "did not become healthy" in captured.err
        assert HINT not in captured.out + captured.err


manifest_dir = test_update.manifest_dir  # the update tests' install layout


class TestUpdate:
    def _update(self, home, code, no_restart=False):
        with (
            patch("pathlib.Path.home", return_value=home),
            patch("subprocess.run", side_effect=_run(code)),
            patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
            patch("vhir_cli.commands.setup._run_connectivity_test"),
            patch("time.sleep"),
        ):
            cmd_update(test_update._make_args(no_restart=no_restart), {})

    def test_a_restart_that_succeeded_says_to_reconnect(self, manifest_dir, capsys):
        self._update(manifest_dir[0], 0)
        out = capsys.readouterr().out
        assert "Restarting gateway... done" in out and HINT in out

    def test_a_failed_restart_says_nothing_more(self, manifest_dir, capsys):
        self._update(manifest_dir[0], 1)
        out = capsys.readouterr().out
        assert "failed (stubbed)" in out and HINT not in out

    def test_no_restart_says_nothing(self, manifest_dir, capsys):
        self._update(manifest_dir[0], 0, no_restart=True)
        assert HINT not in capsys.readouterr().out
