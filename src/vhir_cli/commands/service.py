"""Service management for the ValiHuntIR gateway.

Talks to the gateway's REST API to list, start, stop, and restart
backend services. Reads gateway URL and token from:
  1. CLI flags (--gateway, --token)
  2. Environment variables (VHIR_GATEWAY_URL, VHIR_GATEWAY_TOKEN)
  3. ~/.vhir/config.yaml (gateway_url, gateway_token)
  4. ~/.vhir/gateway.yaml (api_keys dict for token, gateway.port for URL)
  5. Fallback: http://127.0.0.1:4508
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path


def cmd_service(args, identity: dict) -> None:
    """Route to the appropriate service subcommand."""
    action = getattr(args, "service_action", None)
    if action == "status":
        _service_status(args)
    elif action in ("start", "stop", "restart"):
        _service_action(args, action)
    else:
        print("Usage: vhir service {status|start|stop|restart}", file=sys.stderr)
        sys.exit(1)


def _resolve_gateway(args) -> tuple[str, str | None, ssl.SSLContext | None]:
    """Resolve gateway URL, token, and SSL context.

    Resolution order: CLI flags > env vars > gateway.yaml > fallback.

    Returns:
        (url, token, ssl_context) tuple. Token and ssl_context may be None.
    """
    import os

    from vhir_cli.gateway import get_local_gateway_url, get_local_ssl_context

    url = getattr(args, "gateway", None)
    token = getattr(args, "token", None)

    if not url:
        url = os.environ.get("VHIR_GATEWAY_URL")
    if not token:
        token = os.environ.get("VHIR_GATEWAY_TOKEN")

    # Read token from config files if not already set
    if not token:
        for config_name in ("gateway.yaml", "config.yaml"):
            config = _load_config(config_name)
            if not config:
                continue
            api_keys = config.get("api_keys", {})
            if isinstance(api_keys, dict) and api_keys:
                token = next(iter(api_keys))
            if not token:
                token = config.get("gateway_token")
            if token:
                break

    if not url:
        url = get_local_gateway_url()

    ssl_ctx = get_local_ssl_context() if url.startswith("https") else None

    if not token:
        print(
            "Warning: No gateway token found. Check ~/.vhir/gateway.yaml",
            file=sys.stderr,
        )
    return url.rstrip("/"), token if token else None, ssl_ctx


def _load_config(filename: str = "config.yaml") -> dict:
    """Load ~/.vhir/{filename}, returning empty dict on failure."""
    config_file = Path.home() / ".vhir" / filename
    if not config_file.is_file():
        return {}
    try:
        import yaml

        return yaml.safe_load(config_file.read_text()) or {}
    except Exception:
        return {}


def _api_request(
    url: str,
    token: str | None,
    method: str = "GET",
    ssl_context: ssl.SSLContext | None = None,
) -> dict | None:
    """Make an HTTP request to the gateway API with optional auth.

    Returns:
        Parsed JSON dict on success, or None on failure.
    """
    try:
        req = urllib.request.Request(url, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        # POST requests need Content-Length
        if method == "POST":
            req.add_header("Content-Length", "0")
        kwargs = {"timeout": 10}
        if ssl_context is not None:
            kwargs["context"] = ssl_context
        with urllib.request.urlopen(req, **kwargs) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read())
            return body
        except Exception:
            pass
        print(f"ERROR: HTTP {e.code} from {url}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"ERROR: Cannot reach gateway at {url}: {e}", file=sys.stderr)
        return None


def _service_status(args) -> None:
    """GET /api/v1/services and display as a table."""
    url, token, ssl_ctx = _resolve_gateway(args)
    data = _api_request(f"{url}/api/v1/services", token, ssl_context=ssl_ctx)
    if data is None:
        sys.exit(1)

    if "error" in data:
        print(f"ERROR: {data['error']}", file=sys.stderr)
        sys.exit(1)

    services = data.get("services", [])
    if not services:
        print("No services found.")
        return

    print(f"{'Service':<25s} {'Status':<12s} {'Type':<10s} Health")
    print("-" * 60)
    for s in services:
        status = "running" if s.get("started") else "stopped"
        stype = s.get("type", "")
        health = s.get("health", {}).get("status", "")
        print(f"{s['name']:<25s} {status:<12s} {stype:<10s} {health}")


def _service_action(args, action: str) -> None:
    """POST /api/v1/services/{name}/{action}."""
    url, token, ssl_ctx = _resolve_gateway(args)
    name = getattr(args, "backend_name", None)

    if name:
        # Single backend
        data = _api_request(
            f"{url}/api/v1/services/{name}/{action}",
            token,
            method="POST",
            ssl_context=ssl_ctx,
        )
        if data is None:
            sys.exit(1)
        if "error" in data:
            print(f"ERROR: {data['error']}", file=sys.stderr)
            sys.exit(1)
        print(f"{name}: {data.get('status', 'unknown')}")
    else:
        # All backends: fetch list, then operate on each
        svc_data = _api_request(f"{url}/api/v1/services", token, ssl_context=ssl_ctx)
        if svc_data is None:
            sys.exit(1)
        services = svc_data.get("services", [])
        if not services:
            print("No services found.")
            return
        errors = 0
        for s in services:
            sname = s["name"]
            data = _api_request(
                f"{url}/api/v1/services/{sname}/{action}",
                token,
                method="POST",
                ssl_context=ssl_ctx,
            )
            if data and "error" not in data:
                print(f"{sname}: {data.get('status', 'unknown')}")
            else:
                err = data.get("error", "unknown error") if data else "no response"
                print(f"{sname}: FAILED ({err})", file=sys.stderr)
                errors += 1
        if errors:
            sys.exit(1)
