"""Tests for vhir setup client command."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from vhir_cli.commands.client_setup import (
    _MSLEARN_MCP,
    _claude_mcp_add,
    _cmd_setup_client_remote,
    _ensure_mcp_path,
    _format_server_entry,
    _is_sift,
    _merge_and_write,
    _merge_settings,
    _normalise_url,
    _read_local_token,
    _remove_forensic_settings,
    _remove_vhir_mcp_entries,
    _save_gateway_config,
    _wizard_client,
    cmd_setup_client,
)


class TestNormaliseUrl:
    def test_bare_ip(self):
        assert _normalise_url("192.168.1.20", 4624) == "http://192.168.1.20:4624"

    def test_ip_with_port(self):
        assert _normalise_url("10.0.0.1:9999", 4624) == "http://10.0.0.1:9999"

    def test_full_http_url(self):
        assert _normalise_url("http://10.0.0.1:4624", 4624) == "http://10.0.0.1:4624"

    def test_https_url(self):
        assert (
            _normalise_url("https://example.com:443", 4624) == "https://example.com:443"
        )

    def test_empty(self):
        assert _normalise_url("", 4624) == ""


class TestEnsureMcpPath:
    def test_adds_mcp(self):
        assert _ensure_mcp_path("http://127.0.0.1:4508") == "http://127.0.0.1:4508/mcp"

    def test_already_has_mcp(self):
        assert (
            _ensure_mcp_path("http://127.0.0.1:4508/mcp") == "http://127.0.0.1:4508/mcp"
        )

    def test_trailing_slash_stripped(self):
        assert _ensure_mcp_path("http://127.0.0.1:4508/") == "http://127.0.0.1:4508/mcp"


class TestMergeAndWrite:
    def test_creates_new_file(self, tmp_path):
        path = tmp_path / "config.json"
        config = {
            "mcpServers": {
                "vhir": {"type": "streamable-http", "url": "http://localhost:4508/mcp"}
            }
        }
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert "vhir" in data["mcpServers"]
        assert data["mcpServers"]["vhir"]["type"] == "streamable-http"

    def test_preserves_existing_servers(self, tmp_path):
        path = tmp_path / "config.json"
        existing = {"mcpServers": {"custom": {"type": "stdio", "command": "test"}}}
        path.write_text(json.dumps(existing))

        config = {
            "mcpServers": {
                "vhir": {"type": "streamable-http", "url": "http://localhost:4508/mcp"}
            }
        }
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert "custom" in data["mcpServers"]
        assert "vhir" in data["mcpServers"]

    def test_overwrites_vhir_server(self, tmp_path):
        path = tmp_path / "config.json"
        existing = {
            "mcpServers": {
                "vhir": {"type": "streamable-http", "url": "http://old:4508/mcp"}
            }
        }
        path.write_text(json.dumps(existing))

        config = {
            "mcpServers": {
                "vhir": {"type": "streamable-http", "url": "http://new:4508/mcp"}
            }
        }
        _merge_and_write(path, config)
        data = json.loads(path.read_text())
        assert data["mcpServers"]["vhir"]["url"] == "http://new:4508/mcp"

    def test_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "subdir" / "deep" / "config.json"
        config = {
            "mcpServers": {"vhir": {"type": "streamable-http", "url": "http://x/mcp"}}
        }
        _merge_and_write(path, config)
        assert path.is_file()


class TestIsSift:
    def test_true_when_gateway_yaml_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        vhir_dir = tmp_path / ".vhir"
        vhir_dir.mkdir()
        (vhir_dir / "gateway.yaml").write_text("api_keys: {}")
        assert _is_sift() is True

    def test_false_when_no_gateway_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _is_sift() is False


class TestMergeSettings:
    def test_merges_permissions_deny(self, tmp_path):
        target = tmp_path / "settings.json"
        source = tmp_path / "source.json"

        existing = {
            "permissions": {
                "allow": ["Bash(ls)"],
                "deny": ["Bash(rm -rf *)"],
                "defaultMode": "ask",
            }
        }
        target.write_text(json.dumps(existing))

        incoming = {
            "permissions": {"deny": ["Bash(mkfs*)", "Bash(dd *)", "Bash(rm -rf *)"]}
        }
        source.write_text(json.dumps(incoming))

        _merge_settings(target, source)
        data = json.loads(target.read_text())

        # deny is merged (union, sorted, deduplicated)
        assert sorted(data["permissions"]["deny"]) == sorted(
            ["Bash(dd *)", "Bash(mkfs*)", "Bash(rm -rf *)"]
        )
        # allow and defaultMode preserved
        assert data["permissions"]["allow"] == ["Bash(ls)"]
        assert data["permissions"]["defaultMode"] == "ask"

    def test_merges_hooks_and_sandbox(self, tmp_path):
        target = tmp_path / "settings.json"
        source = tmp_path / "source.json"
        source.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PostToolUse": [
                            {
                                "matcher": "Bash",
                                "hooks": [{"type": "command", "command": "test.sh"}],
                            }
                        ]
                    },
                    "sandbox": {"enabled": True},
                }
            )
        )

        _merge_settings(target, source)
        data = json.loads(target.read_text())
        assert "PostToolUse" in data["hooks"]
        assert data["sandbox"]["enabled"] is True


class TestCmdSetupClient:
    def _make_args(self, **kwargs):
        """Build a namespace with defaults."""
        import argparse

        defaults = {
            "client": "claude-code",
            "sift": "http://127.0.0.1:4508",
            "windows": None,
            "windows_token": None,
            "remnux": None,
            "remnux_token": None,
            "examiner": "testuser",
            "no_mslearn": False,
            "yes": True,
            "uninstall": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def _isolate_home(self, monkeypatch, tmp_path):
        """Isolate Path.home() to tmp_path so _is_sift() returns False."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    def test_generates_claude_code_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / ".mcp.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())
        assert "vhir" in data["mcpServers"]
        assert data["mcpServers"]["vhir"]["url"] == "http://127.0.0.1:4508/mcp"
        assert data["mcpServers"]["vhir"]["type"] == "http"
        # Zeltser included by default
        assert "zeltser-ir-writing" in data["mcpServers"]

    def test_mslearn_included_by_default(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "microsoft-learn" in data["mcpServers"]
        assert data["mcpServers"]["microsoft-learn"]["url"] == _MSLEARN_MCP["url"]
        assert data["mcpServers"]["microsoft-learn"]["type"] == "http"

    def test_no_mslearn_flag(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(no_mslearn=True)
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "microsoft-learn" not in data["mcpServers"]
        # Zeltser still present
        assert "zeltser-ir-writing" in data["mcpServers"]

    @patch(
        "vhir_cli.commands.client_setup._prompt_windows_token", return_value="wt_tok"
    )
    def test_windows_endpoint(self, mock_prompt, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(windows="192.168.1.20:4624")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "wintools-mcp" in data["mcpServers"]
        win = data["mcpServers"]["wintools-mcp"]
        assert win["url"] == "https://192.168.1.20:4624/mcp"
        assert win["headers"] == {"Authorization": "Bearer wt_tok"}

    @patch("vhir_cli.commands.client_setup._test_remnux_connection")
    def test_remnux_endpoint(self, mock_test, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(remnux="10.0.0.5", remnux_token="test_token_123")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "remnux-mcp" in data["mcpServers"]
        assert data["mcpServers"]["remnux-mcp"]["url"] == "http://10.0.0.5:3000/mcp"
        assert data["mcpServers"]["remnux-mcp"]["headers"] == {
            "Authorization": "Bearer test_token_123"
        }
        mock_test.assert_called_once_with("http://10.0.0.5:3000", "test_token_123")

    def test_claude_desktop_config(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        # Redirect home to tmp_path so we don't write to real home
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        args = self._make_args(client="claude-desktop")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / ".config" / "claude" / "claude_desktop_config.json"
        assert config_path.is_file()

    def test_merge_preserves_existing(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        # Pre-existing config
        existing = {
            "mcpServers": {"my-custom-mcp": {"type": "stdio", "command": "test"}}
        }
        (tmp_path / ".mcp.json").write_text(json.dumps(existing))

        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "my-custom-mcp" in data["mcpServers"]
        assert "vhir" in data["mcpServers"]

    def test_sift_writes_global_claude_json(self, tmp_path, monkeypatch):
        """On SIFT without claude CLI, MCP servers go to ~/.claude.json."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        # Force JSON write path (no claude CLI)
        monkeypatch.setattr(
            "vhir_cli.commands.client_setup._claude_mcp_add_available",
            lambda: False,
        )
        # Create gateway.yaml to trigger SIFT detection
        vhir_dir = tmp_path / ".vhir"
        vhir_dir.mkdir()
        (vhir_dir / "gateway.yaml").write_text("api_keys: {}")

        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        # Should NOT have .mcp.json in cwd
        assert not (tmp_path / ".mcp.json").is_file()

        # Should have ~/.claude.json with type=http
        claude_json = tmp_path / ".claude.json"
        assert claude_json.is_file()
        data = json.loads(claude_json.read_text())
        assert "vhir" in data["mcpServers"]
        assert data["mcpServers"]["vhir"]["type"] == "http"

    @patch(
        "vhir_cli.commands.client_setup._prompt_windows_token", return_value="wt_tok"
    )
    def test_librechat_config(self, mock_prompt, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(client="librechat", windows="192.168.1.20:4624")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        config_path = tmp_path / "librechat_mcp.yaml"
        assert config_path.is_file()
        content = config_path.read_text()
        assert "mcpServers:" in content
        assert 'type: "streamable-http"' in content
        assert 'url: "http://127.0.0.1:4508/mcp"' in content
        assert 'url: "https://192.168.1.20:4624/mcp"' in content
        assert "timeout: 60000" in content
        assert "zeltser-ir-writing" in content
        assert "microsoft-learn" in content

    def test_librechat_has_server_instructions(self, tmp_path, monkeypatch):
        """Verify LibreChat YAML includes serverInstructions: true."""
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(client="librechat")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        content = (tmp_path / "librechat_mcp.yaml").read_text()
        assert "serverInstructions: true" in content

    def test_librechat_no_json_merge(self, tmp_path, monkeypatch):
        """LibreChat writes YAML, not JSON — no .mcp.json created."""
        monkeypatch.chdir(tmp_path)
        self._isolate_home(monkeypatch, tmp_path)
        args = self._make_args(client="librechat")
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        assert not (tmp_path / ".mcp.json").exists()
        assert (tmp_path / "librechat_mcp.yaml").is_file()


class TestWizardClient:
    def test_choice_3_maps_to_librechat(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "3")
        assert _wizard_client() == "librechat"

    def test_choice_4_maps_to_other(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "4")
        assert _wizard_client() == "other"

    def test_unrecognized_falls_back_to_other(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "99")
        assert _wizard_client() == "other"

    def test_empty_input_defaults_to_choice_1(self, monkeypatch):
        """Empty input uses prompt default '1', which maps to claude-code."""
        monkeypatch.setattr("builtins.input", lambda _: "")
        assert _wizard_client() == "claude-code"


class TestFormatServerEntry:
    def test_claude_code_with_token(self):
        entry = _format_server_entry("claude-code", "https://sift:4508/mcp", "tok123")
        assert entry["type"] == "streamable-http"
        assert entry["url"] == "https://sift:4508/mcp"
        assert entry["headers"]["Authorization"] == "Bearer tok123"

    def test_claude_desktop_uses_mcp_remote(self):
        with patch(
            "vhir_cli.commands.client_setup.shutil.which", return_value="/usr/bin/npx"
        ):
            entry = _format_server_entry(
                "claude-desktop", "https://sift:4508/mcp", "tok123"
            )
        assert entry["command"] == "npx"
        assert "mcp-remote" in entry["args"]
        assert "https://sift:4508/mcp" in entry["args"]
        assert entry["env"]["AUTH_HEADER"] == "Bearer tok123"

    def test_no_token(self):
        entry = _format_server_entry("claude-code", "https://sift:4508/mcp", None)
        assert entry["type"] == "streamable-http"
        assert "headers" not in entry

    def test_claude_desktop_requires_npx(self):
        """Verify SystemExit raised when npx is not installed."""
        with patch("vhir_cli.commands.client_setup.shutil.which", return_value=None):
            with pytest.raises(SystemExit, match="npx"):
                _format_server_entry(
                    "claude-desktop", "https://sift:4508/mcp", "tok123"
                )


class TestRemoteSetup:
    def _make_args(self, **kwargs):
        import argparse

        defaults = {
            "client": "claude-code",
            "sift": "https://sift.example.com:4508",
            "windows": None,
            "windows_token": None,
            "remnux": None,
            "remnux_token": None,
            "examiner": "testuser",
            "no_mslearn": True,
            "yes": True,
            "remote": True,
            "token": "vhir_gw_abc123",
            "uninstall": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @patch("vhir_cli.commands.client_setup._probe_health_with_auth")
    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._save_gateway_config")
    def test_remote_generates_per_backend_urls(
        self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [
            {"name": "forensic-mcp", "started": True, "type": "stdio"},
            {"name": "sift-mcp", "started": True, "type": "stdio"},
        ]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        config_path = tmp_path / ".mcp.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())

        # No aggregate — per-backend entries cover everything
        assert "vhir" not in data["mcpServers"]

        # Per-backend endpoints
        assert "forensic-mcp" in data["mcpServers"]
        assert (
            data["mcpServers"]["forensic-mcp"]["url"]
            == "https://sift.example.com:4508/mcp/forensic-mcp"
        )
        assert "sift-mcp" in data["mcpServers"]
        assert (
            data["mcpServers"]["sift-mcp"]["url"]
            == "https://sift.example.com:4508/mcp/sift-mcp"
        )

    @patch("vhir_cli.commands.client_setup._probe_health_with_auth")
    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._save_gateway_config")
    def test_remote_bearer_token_in_headers(
        self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args(token="secret_token_xyz")
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        for _name, entry in data["mcpServers"].items():
            if "headers" in entry:
                assert entry["headers"]["Authorization"] == "Bearer secret_token_xyz"

    @patch("vhir_cli.commands.client_setup._probe_health_with_auth")
    def test_remote_unreachable_gateway_exits(self, mock_probe, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_probe.return_value = None
        args = self._make_args()
        identity = {"examiner": "testuser"}
        with pytest.raises(SystemExit):
            _cmd_setup_client_remote(args, identity)

    @patch("vhir_cli.commands.client_setup._probe_health_with_auth")
    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._save_gateway_config")
    def test_remote_saves_gateway_config(
        self, mock_save, mock_discover, mock_probe, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)
        mock_save.assert_called_once_with(
            "https://sift.example.com:4508", "vhir_gw_abc123"
        )

    @patch("vhir_cli.commands.client_setup.shutil.which", return_value="/usr/bin/npx")
    @patch("vhir_cli.commands.client_setup._probe_health_with_auth")
    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._save_gateway_config")
    def test_remote_claude_desktop_uses_mcp_remote(
        self, mock_save, mock_discover, mock_probe, mock_which, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_probe.return_value = {"status": "ok"}
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args(client="claude-desktop")
        identity = {"examiner": "testuser"}
        _cmd_setup_client_remote(args, identity)

        config_path = tmp_path / ".config" / "claude" / "claude_desktop_config.json"
        assert config_path.is_file()
        data = json.loads(config_path.read_text())
        # Claude Desktop entries use mcp-remote bridge
        entry = data["mcpServers"]["forensic-mcp"]
        assert entry["command"] == "npx"
        assert "mcp-remote" in entry["args"]


class TestSaveGatewayConfig:
    def test_saves_to_config_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # Patch Path.home() to use tmp_path
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        _save_gateway_config("https://sift:4508", "tok123")
        import yaml

        config = yaml.safe_load((tmp_path / ".vhir" / "config.yaml").read_text())
        assert config["gateway_url"] == "https://sift:4508"
        assert config["gateway_token"] == "tok123"

    def test_preserves_existing_keys(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config_dir = tmp_path / ".vhir"
        config_dir.mkdir()
        import yaml

        (config_dir / "config.yaml").write_text(yaml.dump({"other_key": "value"}))
        _save_gateway_config("https://sift:4508", "tok")
        config = yaml.safe_load((config_dir / "config.yaml").read_text())
        assert config["other_key"] == "value"
        assert config["gateway_url"] == "https://sift:4508"


class TestReadLocalToken:
    def test_reads_token_from_gateway_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config_dir = tmp_path / ".vhir"
        config_dir.mkdir()
        import yaml

        gateway_config = {
            "api_keys": {
                "vhir_gw_abc123xyz": {"examiner": "default", "role": "lead"},
            },
        }
        (config_dir / "gateway.yaml").write_text(yaml.dump(gateway_config))
        assert _read_local_token() == "vhir_gw_abc123xyz"

    def test_no_gateway_yaml_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        assert _read_local_token() is None

    def test_empty_api_keys_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config_dir = tmp_path / ".vhir"
        config_dir.mkdir()
        import yaml

        (config_dir / "gateway.yaml").write_text(yaml.dump({"api_keys": {}}))
        assert _read_local_token() is None

    def test_no_api_keys_key_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        config_dir = tmp_path / ".vhir"
        config_dir.mkdir()
        import yaml

        (config_dir / "gateway.yaml").write_text(yaml.dump({"gateway": {"port": 4508}}))
        assert _read_local_token() is None


class TestLocalModeTokenThreading:
    def _make_args(self, **kwargs):
        import argparse

        defaults = {
            "client": "claude-code",
            "sift": "http://127.0.0.1:4508",
            "windows": None,
            "windows_token": None,
            "remnux": None,
            "examiner": "testuser",
            "no_mslearn": True,
            "yes": True,
            "uninstall": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._read_local_token")
    def test_local_mode_injects_token(
        self, mock_token, mock_discover, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_token.return_value = "vhir_gw_secret123"
        mock_discover.return_value = [
            {"name": "forensic-mcp", "started": True},
            {"name": "sift-mcp", "started": True},
        ]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        for name in ("forensic-mcp", "sift-mcp"):
            entry = data["mcpServers"][name]
            assert entry["headers"]["Authorization"] == "Bearer vhir_gw_secret123"

        # Verify token was passed to discover
        mock_discover.assert_called_once_with(
            "http://127.0.0.1:4508", "vhir_gw_secret123"
        )

    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._read_local_token")
    def test_local_mode_no_token_no_headers(
        self, mock_token, mock_discover, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_token.return_value = None
        mock_discover.return_value = [{"name": "forensic-mcp", "started": True}]
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        assert "headers" not in data["mcpServers"]["forensic-mcp"]

    @patch("vhir_cli.commands.client_setup._discover_services")
    @patch("vhir_cli.commands.client_setup._read_local_token")
    def test_local_mode_fallback_aggregate_gets_token(
        self, mock_token, mock_discover, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        mock_token.return_value = "vhir_gw_tok"
        mock_discover.return_value = None  # Discovery failed
        args = self._make_args()
        identity = {"examiner": "testuser"}
        cmd_setup_client(args, identity)

        data = json.loads((tmp_path / ".mcp.json").read_text())
        entry = data["mcpServers"]["vhir"]
        assert entry["headers"]["Authorization"] == "Bearer vhir_gw_tok"


class TestUninstallHelpers:
    def test_remove_vhir_mcp_entries(self, tmp_path):
        path = tmp_path / ".claude.json"
        data = {
            "mcpServers": {
                "forensic-mcp": {"type": "http", "url": "http://x/mcp/forensic-mcp"},
                "my-custom": {"type": "stdio", "command": "test"},
                "sift-mcp": {"type": "http", "url": "http://x/mcp/sift-mcp"},
            },
            "other_key": "preserved",
        }
        path.write_text(json.dumps(data))
        _remove_vhir_mcp_entries(path)

        result = json.loads(path.read_text())
        assert "my-custom" in result["mcpServers"]
        assert "forensic-mcp" not in result["mcpServers"]
        assert "sift-mcp" not in result["mcpServers"]
        assert result["other_key"] == "preserved"

    def test_remove_forensic_settings(self, tmp_path):
        path = tmp_path / "settings.json"
        data = {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "/path/forensic-audit.sh"}
                        ],
                    },
                    {
                        "matcher": "Write",
                        "hooks": [{"type": "command", "command": "other.sh"}],
                    },
                ],
                "UserPromptSubmit": [
                    {
                        "matcher": "",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "cat << 'EOF'\n<forensic-rules>stuff</forensic-rules>",
                            }
                        ],
                    },
                ],
            },
            "permissions": {
                "allow": ["Bash(ls)"],
                "deny": ["Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)", "Bash(custom)"],
                "defaultMode": "ask",
            },
            "sandbox": {"enabled": True},
        }
        path.write_text(json.dumps(data))
        _remove_forensic_settings(path)

        result = json.loads(path.read_text())
        # PostToolUse: forensic-audit entry removed, other preserved
        assert len(result["hooks"]["PostToolUse"]) == 1
        assert "other.sh" in result["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        # UserPromptSubmit: forensic-rules entry removed
        assert "UserPromptSubmit" not in result["hooks"]
        # permissions: forensic deny rules removed, custom + allow preserved
        assert result["permissions"]["deny"] == ["Bash(custom)"]
        assert result["permissions"]["allow"] == ["Bash(ls)"]
        assert result["permissions"]["defaultMode"] == "ask"
        # sandbox removed
        assert "sandbox" not in result


# ---------------------------------------------------------------------------
# Regression guard — `claude mcp add` argv order (CRITICAL, 2026-04-22)
#
# Test agent (2026-04-22) observed `vhir setup client --client=claude-code`
# silently wiping 10 of 11 existing MCP registrations on a SIFT with a
# pre-existing healthy ~/.claude.json. Root cause: Claude Code CLI 2.1.116's
# `-H / --header` option is variadic (commander.js). When `-H` precedes
# positional args, the parser consumes `<name>` and `<url>` as additional
# header values, leaving zero positionals — the CLI errors AND wipes.
# The pre-fix code appended `-H` flags BEFORE name+url. The fix reorders
# so positionals come first; these tests catch any future reorder.
# ---------------------------------------------------------------------------


class TestClaudeMcpAddArgvOrder:
    def test_positional_name_and_url_appear_before_any_header(self):
        """Regression: commander.js variadic `-H` eats name+url when
        headers precede positionals. Positional name+url MUST come first."""
        captured = {}

        def fake_run(cmd, **kwargs):
            # The remove-first call has a different shape; skip it.
            if cmd[:3] == ["claude", "mcp", "remove"]:
                result = type("R", (), {"returncode": 0, "stderr": b""})()
                return result
            captured["cmd"] = list(cmd)
            return type("R", (), {"returncode": 0, "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            _claude_mcp_add(
                "forensic-mcp",
                {
                    "url": "http://127.0.0.1:4508/mcp/forensic-mcp",
                    "headers": {"Authorization": "Bearer vhir_gw_abc"},
                },
            )

        cmd = captured["cmd"]
        # Find indices of name, url, and first -H.
        name_idx = cmd.index("forensic-mcp")
        url_idx = cmd.index("http://127.0.0.1:4508/mcp/forensic-mcp")
        h_idx = cmd.index("-H")
        assert name_idx < h_idx, (
            f"name ({name_idx}) must come BEFORE -H ({h_idx}) — "
            f"commander.js variadic -H eats positionals. cmd={cmd}"
        )
        assert url_idx < h_idx, (
            f"url ({url_idx}) must come BEFORE -H ({h_idx}). cmd={cmd}"
        )
        # Also: name and url adjacent (standard positional order).
        assert url_idx == name_idx + 1, (
            "url must immediately follow name in positional order"
        )

    def test_raises_runtime_error_on_cli_failure(self):
        """Silent-continue was the multiplier on the original bug
        (partial wipes with "Registered N servers" banner lying).
        Helper must raise so the caller can abort + restore snapshot."""

        def fake_run(cmd, **kwargs):
            if cmd[:3] == ["claude", "mcp", "remove"]:
                return type("R", (), {"returncode": 0, "stderr": b""})()
            # Simulate the post-2.1.116 variadic failure.
            return type(
                "R",
                (),
                {"returncode": 1, "stderr": b"error: missing required argument 'name'"},
            )()

        with patch("subprocess.run", side_effect=fake_run):
            with pytest.raises(
                RuntimeError, match="claude mcp add forensic-mcp failed"
            ):
                _claude_mcp_add(
                    "forensic-mcp",
                    {
                        "url": "http://127.0.0.1:4508/mcp/forensic-mcp",
                        "headers": {"Authorization": "Bearer vhir_gw_abc"},
                    },
                )

    def test_no_url_is_noop(self):
        """Entries without a url (e.g., stdio-only configs) are
        skipped silently — this predates the variadic fix and must
        continue working."""
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            return type("R", (), {"returncode": 0, "stderr": b""})()

        with patch("subprocess.run", side_effect=fake_run):
            _claude_mcp_add("some-stdio", {"headers": {}})
        assert calls == []  # no subprocess invocation at all
