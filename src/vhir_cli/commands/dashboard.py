"""Open the Examiner Portal or legacy dashboard in a browser."""

from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

import yaml


def _open_url(args, identity: dict, path: str, label: str) -> None:
    """Open a gateway URL in the browser."""
    config_path = Path.home() / ".vhir" / "gateway.yaml"
    if not config_path.is_file():
        print(
            "Error: Gateway config not found (~/.vhir/gateway.yaml).\n"
            "Run `vhir setup client` to configure the gateway.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except (yaml.YAMLError, OSError) as e:
        print(f"Error: Cannot read gateway config: {e}", file=sys.stderr)
        sys.exit(1)

    gw = config.get("gateway", {})
    host = gw.get("host", "127.0.0.1")
    port = gw.get("port", 4508)
    tls = gw.get("tls", {})
    scheme = "https" if tls.get("certfile") else "http"

    if host == "0.0.0.0":
        host = "127.0.0.1"

    url = f"{scheme}://{host}:{port}{path}"

    # Append bearer token matching current examiner
    api_keys = config.get("api_keys", {})
    if isinstance(api_keys, dict) and api_keys:
        examiner = identity.get("examiner", "")
        token = None
        for key, info in api_keys.items():
            if isinstance(info, dict) and info.get("examiner") == examiner:
                token = key
                break
        if token is None:
            token = next(iter(api_keys))
        url += f"#token={token}"

    print(f"{label}: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        print("Could not open browser. Use the URL above.", file=sys.stderr)


def cmd_portal(args, identity: dict) -> None:
    """Open the Examiner Portal."""
    _open_url(args, identity, "/portal/", "Examiner Portal")


def cmd_dashboard(args, identity: dict) -> None:
    """Open the legacy dashboard (v1)."""
    _open_url(args, identity, "/dashboard/", "Dashboard")
