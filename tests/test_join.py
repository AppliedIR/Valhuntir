"""Tests for aiir join and aiir setup join-code commands."""

import sys
from unittest.mock import MagicMock, patch

import yaml

from aiir_cli.commands.join import (
    _get_local_gateway_token,
    _get_local_gateway_url,
    _write_config,
    derive_smb_password,
)


# Create a mock requests module for tests
def _make_mock_requests(status_code=200, json_data=None):
    """Create a mock requests module with a preset response."""
    mock_mod = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = json_data or {}
    mock_mod.post.return_value = mock_resp
    mock_mod.exceptions = MagicMock()
    mock_mod.exceptions.ConnectionError = ConnectionError
    mock_mod.exceptions.SSLError = Exception
    return mock_mod


class TestWriteConfig:
    def test_writes_config(self, tmp_path, monkeypatch):
        """Verify ~/.aiir/config.yaml written with gateway_url and token."""
        monkeypatch.setattr("aiir_cli.commands.join.Path.home", lambda: tmp_path)
        _write_config("https://10.0.0.5:4508", "aiir_gw_abc123")

        config_path = tmp_path / ".aiir" / "config.yaml"
        assert config_path.exists()
        config = yaml.safe_load(config_path.read_text())
        assert config["gateway_url"] == "https://10.0.0.5:4508"
        assert config["gateway_token"] == "aiir_gw_abc123"

    def test_preserves_existing_fields(self, tmp_path, monkeypatch):
        """Existing config fields are preserved when writing gateway credentials."""
        monkeypatch.setattr("aiir_cli.commands.join.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir(parents=True)
        config_path = config_dir / "config.yaml"
        config_path.write_text(yaml.dump({"examiner": "steve"}))

        _write_config("https://10.0.0.5:4508", "aiir_gw_abc123")

        config = yaml.safe_load(config_path.read_text())
        assert config["examiner"] == "steve"
        assert config["gateway_url"] == "https://10.0.0.5:4508"


class TestWintoolsJoinNoGatewayToken:
    """Verify _write_config is NOT called when gateway_token is absent (wintools join)."""

    def test_write_config_not_called_without_gateway_token(self, tmp_path, monkeypatch):
        """Wintools join response omits gateway_token — _write_config must be skipped."""
        args = MagicMock()
        args.sift = "10.0.0.5:4508"
        args.code = "ABCD-EFGH"
        args.wintools = False
        args.ca_cert = None
        args.skip_setup = True

        json_data = {
            "gateway_url": "https://10.0.0.5:4508",
            "backends": ["forensic-mcp", "sift-mcp", "wintools-mcp"],
            "examiner": "win-forensics",
            "wintools_registered": True,
            "restart_required": True,
        }

        mock_requests = _make_mock_requests(200, json_data)
        write_config_mock = MagicMock()

        with (
            patch.dict(sys.modules, {"requests": mock_requests}),
            patch("aiir_cli.commands.join._detect_wintools", return_value=False),
            patch("aiir_cli.commands.join._find_ca_cert", return_value=None),
            patch("aiir_cli.commands.join._write_config", write_config_mock),
        ):
            import importlib

            import aiir_cli.commands.join as join_mod

            importlib.reload(join_mod)
            join_mod.cmd_join(args, {"examiner": "tester"})

        write_config_mock.assert_not_called()


class TestUrlNormalization:
    def _run_join(self, sift_url, json_data=None):
        """Helper to run cmd_join with mocked requests and return the POST URL."""
        args = MagicMock()
        args.sift = sift_url
        args.code = "ABCD-EFGH"
        args.wintools = False
        args.ca_cert = None
        args.skip_setup = True

        if json_data is None:
            json_data = {
                "gateway_url": f"https://{sift_url}",
                "gateway_token": "aiir_gw_test",
                "backends": ["forensic-mcp", "sift-mcp"],
                "examiner": "tester",
            }

        mock_requests = _make_mock_requests(200, json_data)

        with patch.dict(sys.modules, {"requests": mock_requests}):
            # Need to reimport to pick up the patched requests
            import importlib

            import aiir_cli.commands.join as join_mod

            importlib.reload(join_mod)
            join_mod._detect_wintools = lambda: False
            join_mod._find_ca_cert = lambda: None
            join_mod._write_config = lambda *a, **kw: None
            join_mod.cmd_join(args, {"examiner": "tester"})

        return mock_requests.post.call_args[0][0]

    def test_bare_ip_gets_https_and_port(self):
        """Bare IP → https://IP:4508."""
        url = self._run_join("10.0.0.5")
        assert url == "https://10.0.0.5:4508/api/v1/setup/join"

    def test_ip_with_port(self):
        """IP:port → https://IP:port."""
        url = self._run_join("10.0.0.5:9999")
        assert url == "https://10.0.0.5:9999/api/v1/setup/join"

    def test_full_url_preserved(self):
        """Full https:// URL is preserved."""
        url = self._run_join("https://sift.lab:4508")
        assert url == "https://sift.lab:4508/api/v1/setup/join"


class TestJoinCodeCommand:
    def test_prints_instructions(self, capsys):
        """Verify output format includes code and setup-windows instruction."""
        args = MagicMock()
        args.expires = 2

        mock_requests = _make_mock_requests(
            200,
            {
                "code": "ABCD-EFGH",
                "expires_hours": 2,
                "instructions": "aiir join --sift 10.0.0.5:4508 --code ABCD-EFGH",
            },
        )

        with patch.dict(sys.modules, {"requests": mock_requests}):
            import importlib

            import aiir_cli.commands.join as join_mod

            importlib.reload(join_mod)
            join_mod._ensure_static_ip = lambda: "10.0.0.5"
            join_mod._ensure_remote_binding = lambda: None
            join_mod._get_local_gateway_url = lambda: "http://127.0.0.1:4508"
            join_mod._get_local_gateway_token = lambda: "aiir_gw_test"
            join_mod._setup_samba_share = lambda code: "10.0.0.20"
            join_mod._setup_firewall = lambda ip: None
            join_mod.cmd_setup_join_code(args, {"examiner": "steve"})

        captured = capsys.readouterr()
        assert "ABCD-EFGH" in captured.out
        assert "setup-windows.ps1" in captured.out
        assert "expires in 2 hours" in captured.out


class TestDeriveSMBPassword:
    def test_known_vector(self):
        """PBKDF2 test vector: ABCD-EFGH → 0a6e4700953ead036c7468173fccf1be."""
        assert derive_smb_password("ABCD-EFGH") == "0a6e4700953ead036c7468173fccf1be"

    def test_deterministic(self):
        """Same input always produces same output."""
        assert derive_smb_password("TEST-CODE") == derive_smb_password("TEST-CODE")

    def test_different_inputs(self):
        """Different inputs produce different passwords."""
        assert derive_smb_password("AAAA-BBBB") != derive_smb_password("CCCC-DDDD")

    def test_length(self):
        """Output is exactly 32 hex characters."""
        result = derive_smb_password("SOME-CODE")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)


class TestGetLocalConfig:
    def test_get_gateway_url_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        assert _get_local_gateway_url() == "http://127.0.0.1:4508"

    def test_get_gateway_url_from_gateway_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"gateway": {"host": "0.0.0.0", "port": 9999}})
        )
        assert _get_local_gateway_url() == "http://127.0.0.1:9999"

    def test_get_gateway_url_tls(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.yaml").write_text(
            yaml.dump(
                {
                    "gateway": {
                        "host": "0.0.0.0",
                        "port": 4508,
                        "tls": {"certfile": "/path/to/cert.pem"},
                    }
                }
            )
        )
        assert _get_local_gateway_url() == "https://127.0.0.1:4508"

    def test_get_gateway_token_from_gateway_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.commands.join.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir(parents=True)
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"api_keys": {"aiir_gw_mytoken": {"examiner": "steve"}}})
        )
        assert _get_local_gateway_token() == "aiir_gw_mytoken"

    def test_get_gateway_token_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.commands.join.Path.home", lambda: tmp_path)
        assert _get_local_gateway_token() is None
