"""Tests for vhir setup command."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from vhir_cli.commands.setup import cmd_setup

# -- Fixtures --


def _identity():
    return {"os_user": "testuser", "analyst": "analyst1", "analyst_source": "flag"}


# -- cmd_setup routing --


class TestCmdSetup:
    def test_bare_setup_exits(self):
        """'vhir setup' with no subcommand exits with error."""
        import pytest

        args = MagicMock()
        args.setup_action = None

        with pytest.raises(SystemExit):
            cmd_setup(args, _identity())

    def test_setup_test_runs(self, capsys):
        args = MagicMock()
        args.setup_action = "test"

        health_resp = json.dumps(
            {
                "status": "ok",
                "backends": {
                    "forensic-mcp": {"status": "ok", "tools": 15},
                    "sift-mcp": {"status": "ok", "tools": 6},
                },
                "tools_count": 21,
            }
        ).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = health_resp
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            cmd_setup(args, _identity())

        output = capsys.readouterr().out
        assert "Connectivity Test" in output
        assert "forensic-mcp" in output
        assert "OK" in output

    def test_setup_test_gateway_offline(self, capsys):
        args = MagicMock()
        args.setup_action = "test"

        import urllib.error

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            cmd_setup(args, _identity())

        output = capsys.readouterr().out
        assert "OFFLINE" in output
