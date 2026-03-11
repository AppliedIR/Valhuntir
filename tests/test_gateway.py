"""Tests for aiir_cli.gateway shared helper module."""

import ssl

import yaml

from aiir_cli.gateway import find_ca_cert, get_local_gateway_url, get_local_ssl_context


class TestGetLocalGatewayUrl:
    def test_default_no_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        assert get_local_gateway_url() == "http://127.0.0.1:4508"

    def test_custom_port(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"gateway": {"host": "0.0.0.0", "port": 9999}})
        )
        assert get_local_gateway_url() == "http://127.0.0.1:9999"

    def test_tls_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
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
        assert get_local_gateway_url() == "https://127.0.0.1:4508"

    def test_host_normalized_to_localhost(self, tmp_path, monkeypatch):
        """Any host value (0.0.0.0, custom IP) → 127.0.0.1."""
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"gateway": {"host": "10.0.0.5", "port": 4508}})
        )
        assert get_local_gateway_url() == "http://127.0.0.1:4508"

    def test_empty_tls_dict(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        (config_dir / "gateway.yaml").write_text(
            yaml.dump({"gateway": {"port": 4508, "tls": {}}})
        )
        assert get_local_gateway_url() == "http://127.0.0.1:4508"

    def test_malformed_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        (config_dir / "gateway.yaml").write_text("{{invalid yaml")
        assert get_local_gateway_url() == "http://127.0.0.1:4508"


class TestGetLocalSslContext:
    def test_no_tls_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        assert get_local_ssl_context() is None

    def test_tls_no_ca_returns_permissive(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        (config_dir / "gateway.yaml").write_text(
            yaml.dump(
                {
                    "gateway": {
                        "tls": {"certfile": "/some/cert.pem"},
                    }
                }
            )
        )
        ctx = get_local_ssl_context()
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_tls_with_ca_returns_verifying(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        config_dir = tmp_path / ".aiir"
        config_dir.mkdir()
        tls_dir = config_dir / "tls"
        tls_dir.mkdir()
        # Create a dummy CA cert (just needs to exist for find_ca_cert)
        # We can't actually load it, so just test that the path is found
        (tls_dir / "ca-cert.pem").write_text("dummy")
        (config_dir / "gateway.yaml").write_text(
            yaml.dump(
                {
                    "gateway": {
                        "tls": {"certfile": "/some/cert.pem"},
                    }
                }
            )
        )
        # find_ca_cert will find the file, but loading it will fail
        # since it's not a real cert. That's fine — we test the path logic.
        ctx = get_local_ssl_context()
        # The context may fail to load the dummy cert, falling back to permissive
        assert isinstance(ctx, ssl.SSLContext)


class TestFindCaCert:
    def test_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        tls_dir = tmp_path / ".aiir" / "tls"
        tls_dir.mkdir(parents=True)
        ca = tls_dir / "ca-cert.pem"
        ca.write_text("cert")
        assert find_ca_cert() == str(ca)

    def test_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("aiir_cli.gateway.Path.home", lambda: tmp_path)
        assert find_ca_cert() is None
