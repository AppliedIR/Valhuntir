"""Shared helpers for talking to the local ValiHuntIR gateway.

Reads ~/.vhir/gateway.yaml for host, port, and TLS config.
Always uses 127.0.0.1 for local access (even if host is 0.0.0.0).

config.yaml's gateway_url field is for remote clients only — written by
'vhir join' on remote machines, never read by local commands. F12 (rebind
not updating config.yaml) is moot because local commands use gateway.yaml.
"""

from __future__ import annotations

import ssl
from pathlib import Path


def _read_gateway_config() -> dict:
    """Load ~/.vhir/gateway.yaml, returning empty dict on failure."""
    import yaml

    gateway_config = Path.home() / ".vhir" / "gateway.yaml"
    if not gateway_config.exists():
        return {}
    try:
        with open(gateway_config) as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def get_local_gateway_url() -> str:
    """Build the local gateway URL from gateway.yaml config.

    Always returns http(s)://127.0.0.1:{port}. Checks gateway.tls.certfile
    to determine scheme. Falls back to http://127.0.0.1:4508.
    """
    config = _read_gateway_config()
    gw = config.get("gateway", {})
    if isinstance(gw, dict):
        port = gw.get("port", 4508)
        tls = gw.get("tls", {})
        scheme = "https" if isinstance(tls, dict) and tls.get("certfile") else "http"
        return f"{scheme}://127.0.0.1:{port}"
    return "http://127.0.0.1:4508"


def get_local_ssl_context() -> ssl.SSLContext | None:
    """Return an SSL context for local gateway connections, or None if no TLS.

    If TLS is configured (gateway.tls.certfile exists in gateway.yaml):
      - Loads ~/.vhir/tls/ca-cert.pem if present (proper verification)
      - Otherwise returns a permissive context (self-signed cert support)
    If no TLS, returns None (caller should not pass context to urlopen).
    """
    config = _read_gateway_config()
    gw = config.get("gateway", {})
    if not isinstance(gw, dict):
        return None
    tls = gw.get("tls", {})
    if not isinstance(tls, dict) or not tls.get("certfile"):
        return None

    ca = find_ca_cert()
    ctx = ssl.create_default_context()
    if ca:
        try:
            ctx.load_verify_locations(ca)
            return ctx
        except (ssl.SSLError, OSError):
            pass
    # No CA or CA failed to load — permissive context for self-signed
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def find_ca_cert() -> str | None:
    """Return ~/.vhir/tls/ca-cert.pem path if it exists, else None."""
    ca_path = Path.home() / ".vhir" / "tls" / "ca-cert.pem"
    if ca_path.exists():
        return str(ca_path)
    return None
