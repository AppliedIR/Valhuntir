"""Tests for vhir service subcommand."""

import argparse
from pathlib import Path
from unittest.mock import patch

import pytest

from vhir_cli.commands.service import (
    _resolve_gateway,
    _service_action,
    _service_status,
    cmd_service,
)


class TestResolveGateway:
    def _make_args(self, **kwargs):
        defaults = {"gateway": None, "token": None}
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_args_take_priority(self):
        args = self._make_args(gateway="https://custom:4508", token="tok")
        url, token, _ssl = _resolve_gateway(args)
        assert url == "https://custom:4508"
        assert token == "tok"

    def test_env_vars(self, monkeypatch):
        monkeypatch.setenv("VHIR_GATEWAY_URL", "https://env-host:4508")
        monkeypatch.setenv("VHIR_GATEWAY_TOKEN", "env_tok")
        args = self._make_args()
        url, token, _ssl = _resolve_gateway(args)
        assert url == "https://env-host:4508"
        assert token == "env_tok"

    def test_config_file_token(self, tmp_path, monkeypatch):
        """Token resolved from config.yaml, URL from gateway.yaml."""
        import yaml

        config_dir = tmp_path / ".vhir"
        config_dir.mkdir()
        # config.yaml provides token only (URL comes from gateway.yaml)
        (config_dir / "config.yaml").write_text(yaml.dump({"gateway_token": "cfg_tok"}))
        # gateway.yaml provides URL
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"gateway": {"host": "0.0.0.0", "port": 9999}})
        )
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.delenv("VHIR_GATEWAY_URL", raising=False)
        monkeypatch.delenv("VHIR_GATEWAY_TOKEN", raising=False)
        args = self._make_args()
        url, token, _ssl = _resolve_gateway(args)
        assert url == "http://127.0.0.1:9999"
        assert token == "cfg_tok"

    def test_fallback_localhost(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.delenv("VHIR_GATEWAY_URL", raising=False)
        monkeypatch.delenv("VHIR_GATEWAY_TOKEN", raising=False)
        args = self._make_args()
        url, token, _ssl = _resolve_gateway(args)
        assert url == "http://127.0.0.1:4508"
        assert token is None

    def test_trailing_slash_stripped(self):
        args = self._make_args(gateway="https://host:4508/")
        url, _, _ssl = _resolve_gateway(args)
        assert not url.endswith("/")


class TestServiceStatus:
    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_status_prints_table(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = {
            "services": [
                {
                    "name": "forensic-mcp",
                    "started": True,
                    "type": "stdio",
                    "health": {"status": "ok"},
                },
                {
                    "name": "sift-mcp",
                    "started": False,
                    "type": "stdio",
                    "health": {"status": "stopped"},
                },
            ],
            "count": 2,
        }
        args = argparse.Namespace(gateway=None, token=None, service_action="status")
        _service_status(args)
        out = capsys.readouterr().out
        assert "forensic-mcp" in out
        assert "running" in out
        assert "stopped" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_status_unreachable_exits(self, mock_resolve, mock_api):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = None
        args = argparse.Namespace(gateway=None, token=None, service_action="status")
        with pytest.raises(SystemExit):
            _service_status(args)


class TestServiceAction:
    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_start_service(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", "tok", None)
        mock_api.return_value = {"status": "started", "name": "forensic-mcp"}
        args = argparse.Namespace(gateway=None, token=None, backend_name="forensic-mcp")
        _service_action(args, "start")
        out = capsys.readouterr().out
        assert "forensic-mcp" in out
        assert "started" in out
        mock_api.assert_called_once_with(
            "http://localhost:4508/api/v1/services/forensic-mcp/start",
            "tok",
            method="POST",
            ssl_context=None,
        )

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_stop_service(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = {"status": "stopped", "name": "sift-mcp"}
        args = argparse.Namespace(gateway=None, token=None, backend_name="sift-mcp")
        _service_action(args, "stop")
        out = capsys.readouterr().out
        assert "sift-mcp" in out
        assert "stopped" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_restart_service(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = {"status": "restarted", "name": "forensic-mcp"}
        args = argparse.Namespace(gateway=None, token=None, backend_name="forensic-mcp")
        _service_action(args, "restart")
        out = capsys.readouterr().out
        assert "restarted" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_unknown_backend_error(self, mock_resolve, mock_api):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = {"error": "Unknown backend: nope"}
        args = argparse.Namespace(gateway=None, token=None, backend_name="nope")
        with pytest.raises(SystemExit):
            _service_action(args, "start")

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_unreachable_gateway_exits(self, mock_resolve, mock_api):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = None
        args = argparse.Namespace(gateway=None, token=None, backend_name="forensic-mcp")
        with pytest.raises(SystemExit):
            _service_action(args, "start")


class TestCmdService:
    def test_no_action_exits(self):
        args = argparse.Namespace(service_action=None, gateway=None, token=None)
        with pytest.raises(SystemExit):
            cmd_service(args, {"examiner": "test"})

    @patch("vhir_cli.commands.service._service_status")
    def test_routes_to_status(self, mock_status):
        args = argparse.Namespace(service_action="status", gateway=None, token=None)
        cmd_service(args, {"examiner": "test"})
        mock_status.assert_called_once_with(args)

    @patch("vhir_cli.commands.service._service_action")
    def test_routes_to_start(self, mock_action):
        args = argparse.Namespace(
            service_action="start", gateway=None, token=None, backend_name="b1"
        )
        cmd_service(args, {"examiner": "test"})
        mock_action.assert_called_once_with(args, "start")


class TestBulkServiceAction:
    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_stop_all_backends(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", "tok", None)
        mock_api.side_effect = [
            # First call: GET /api/v1/services
            {
                "services": [
                    {"name": "forensic-mcp", "started": True},
                    {"name": "sift-mcp", "started": True},
                ]
            },
            # Per-backend POST calls
            {"status": "stopped", "name": "forensic-mcp"},
            {"status": "stopped", "name": "sift-mcp"},
        ]
        args = argparse.Namespace(gateway=None, token=None, backend_name=None)
        _service_action(args, "stop")
        out = capsys.readouterr().out
        assert "forensic-mcp: stopped" in out
        assert "sift-mcp: stopped" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_start_all_backends(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.side_effect = [
            {"services": [{"name": "forensic-mcp"}, {"name": "sift-mcp"}]},
            {"status": "started"},
            {"status": "started"},
        ]
        args = argparse.Namespace(gateway=None, token=None, backend_name=None)
        _service_action(args, "start")
        out = capsys.readouterr().out
        assert "forensic-mcp: started" in out
        assert "sift-mcp: started" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_bulk_no_services_found(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.return_value = {"services": []}
        args = argparse.Namespace(gateway=None, token=None, backend_name=None)
        _service_action(args, "stop")
        out = capsys.readouterr().out
        assert "No services found" in out

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_bulk_partial_failure_exits(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", None, None)
        mock_api.side_effect = [
            {"services": [{"name": "forensic-mcp"}, {"name": "sift-mcp"}]},
            {"status": "stopped"},
            {"error": "already stopped"},
        ]
        args = argparse.Namespace(gateway=None, token=None, backend_name=None)
        with pytest.raises(SystemExit):
            _service_action(args, "stop")

    @patch("vhir_cli.commands.service._api_request")
    @patch("vhir_cli.commands.service._resolve_gateway")
    def test_single_backend_still_works(self, mock_resolve, mock_api, capsys):
        mock_resolve.return_value = ("http://localhost:4508", "tok", None)
        mock_api.return_value = {"status": "restarted", "name": "forensic-mcp"}
        args = argparse.Namespace(gateway=None, token=None, backend_name="forensic-mcp")
        _service_action(args, "restart")
        out = capsys.readouterr().out
        assert "forensic-mcp: restarted" in out
