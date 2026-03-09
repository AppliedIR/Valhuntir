"""aiir join — exchange a join code for gateway credentials from a remote machine."""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path

import yaml


def cmd_join(args, identity: dict) -> None:
    """Join a SIFT gateway from a remote machine."""
    sift_url = args.sift
    code = args.code

    # Normalize URL
    if not sift_url.startswith("http"):
        sift_url = f"https://{sift_url}"
    # Add default port if not present
    parts = sift_url.split("//", 1)
    if len(parts) == 2 and ":" not in parts[1]:
        sift_url = f"{sift_url}:4508"

    # Detect if this is a wintools machine
    wintools_url = None
    wintools_token = None
    if getattr(args, "wintools", False) or _detect_wintools():
        wintools_url, wintools_token = _get_wintools_credentials()

    # TLS verification: use CA cert if available, otherwise skip (self-signed)
    ca_cert = getattr(args, "ca_cert", None) or _find_ca_cert()
    verify = ca_cert if ca_cert else False

    if not verify and sift_url.startswith("https"):
        print(
            "WARNING: TLS certificate verification disabled. "
            "Connection is encrypted but server identity is not verified. "
            "Use --ca-cert to specify a CA certificate.",
            file=sys.stderr,
        )

    # POST to /api/v1/setup/join
    try:
        import requests
    except ImportError:
        # Fall back to urllib if requests is not available
        _join_urllib(sift_url, code, wintools_url, wintools_token, verify, args)
        return

    try:
        resp = requests.post(
            f"{sift_url}/api/v1/setup/join",
            json={
                "code": code,
                "machine_type": "wintools" if wintools_url else "examiner",
                "hostname": socket.gethostname(),
                "wintools_url": wintools_url,
                "wintools_token": wintools_token,
            },
            verify=verify,
            timeout=30,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        print(f"Verify that the gateway is running at {sift_url}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.SSLError as e:
        print(f"TLS error: {e}", file=sys.stderr)
        print(
            "Try --ca-cert to specify the CA certificate, or check the gateway's TLS config",
            file=sys.stderr,
        )
        sys.exit(1)

    if resp.status_code != 200:
        try:
            error_msg = resp.json().get("error", "Unknown error")
        except (json.JSONDecodeError, ValueError):
            error_msg = resp.text
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    if data.get("gateway_token"):
        _write_config(data["gateway_url"], data["gateway_token"])

    print(f"Joined gateway at {data['gateway_url']}")
    print(f"Backends available: {', '.join(data.get('backends', []))}")

    if data.get("wintools_registered"):
        print("Windows wintools-mcp registered with gateway")
        if data.get("restart_required"):
            print(
                "Note: gateway restart may be needed to activate the wintools backend"
            )

    # Run aiir setup client to generate MCP config
    if not getattr(args, "skip_setup", False):
        print()
        print("Run 'aiir setup client --remote' to configure your LLM client.")


def cmd_setup_join_code(args, identity: dict) -> None:
    """Generate a join code on this SIFT machine.

    If the gateway is bound to localhost, prompts to rebind to 0.0.0.0
    so remote machines can connect, then restarts the gateway.
    """
    token = _get_local_gateway_token()

    if not token:
        print("No gateway token found. Is the gateway configured?", file=sys.stderr)
        print("Check ~/.aiir/gateway.yaml for api_keys", file=sys.stderr)
        sys.exit(1)

    # Check if gateway needs rebinding for remote access
    _ensure_remote_binding()

    gateway_url = _get_local_gateway_url()

    try:
        import requests
    except ImportError:
        _join_code_urllib(gateway_url, token, args)
        return

    expires = getattr(args, "expires", None) or 2
    ca = _find_ca_cert()
    verify = ca if ca else False
    if not verify and gateway_url.startswith("https"):
        print(
            "WARNING: TLS certificate verification disabled for join-code request. "
            "Use ~/.aiir/tls/ca-cert.pem to enable verification.",
            file=sys.stderr,
        )
    try:
        resp = requests.post(
            f"{gateway_url}/api/v1/setup/join-code",
            headers={"Authorization": f"Bearer {token}"},
            json={"expires_hours": expires},
            verify=verify,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        print(f"Failed to connect to local gateway: {e}", file=sys.stderr)
        print(f"Is the gateway running at {gateway_url}?", file=sys.stderr)
        sys.exit(1)

    if resp.status_code != 200:
        print(f"Failed to generate join code: {resp.text}", file=sys.stderr)
        sys.exit(1)

    data = resp.json()
    print(f"Join code: {data['code']} (expires in {data['expires_hours']} hours)")
    print()
    print("On the remote machine, run:")
    print(f"  {data['instructions']}")


def _join_urllib(sift_url, code, wintools_url, wintools_token, verify, args):
    """Fallback join implementation using urllib (no requests dependency)."""
    import ssl
    import urllib.request

    payload = json.dumps(
        {
            "code": code,
            "machine_type": "wintools" if wintools_url else "examiner",
            "hostname": socket.gethostname(),
            "wintools_url": wintools_url,
            "wintools_token": wintools_token,
        }
    ).encode("utf-8")

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx.load_verify_locations(verify)

    req = urllib.request.Request(
        f"{sift_url}/api/v1/setup/join",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            error_msg = json.loads(body).get("error", body)
        except (json.JSONDecodeError, ValueError):
            error_msg = body
        print(f"Join failed: {error_msg}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    if data.get("gateway_token"):
        _write_config(data["gateway_url"], data["gateway_token"])
    print(f"Joined gateway at {data['gateway_url']}")
    print(f"Backends available: {', '.join(data.get('backends', []))}")

    if data.get("wintools_registered"):
        print("Windows wintools-mcp registered with gateway")
        if data.get("restart_required"):
            print(
                "Note: gateway restart may be needed to activate the wintools backend"
            )

    if not getattr(args, "skip_setup", False):
        print()
        print("Run 'aiir setup client --remote' to configure your LLM client.")


def _join_code_urllib(gateway_url, token, args):
    """Fallback join-code implementation using urllib."""
    import ssl
    import urllib.request

    expires = getattr(args, "expires", None) or 2
    payload = json.dumps({"expires_hours": expires}).encode("utf-8")

    ca = _find_ca_cert()
    ctx = ssl.create_default_context()
    if not ca:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(ca)

    req = urllib.request.Request(
        f"{gateway_url}/api/v1/setup/join-code",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        print(f"Failed to generate join code: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Join code: {data['code']} (expires in {data['expires_hours']} hours)")
    print()
    print("On the remote machine, run:")
    print(f"  {data['instructions']}")


def _write_config(gateway_url: str, gateway_token: str) -> None:
    """Write gateway credentials to ~/.aiir/config.yaml."""
    config_dir = Path.home() / ".aiir"
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = config_dir / "config.yaml"

    # Load existing config to preserve other fields
    config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except (yaml.YAMLError, OSError):
            pass

    config["gateway_url"] = gateway_url
    config["gateway_token"] = gateway_token

    fd = os.open(str(config_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def _get_local_gateway_url() -> str:
    """Get the local gateway URL from config or default."""
    config_path = Path.home() / ".aiir" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            url = config.get("gateway_url")
            if url:
                return url
        except (yaml.YAMLError, OSError):
            pass
    return "http://127.0.0.1:4508"


def _get_local_gateway_token() -> str | None:
    """Get the first API key from the local gateway config."""
    # Try gateway.yaml first
    for config_name in ("gateway.yaml", "config.yaml"):
        config_path = Path.home() / ".aiir" / config_name
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
                # Check for api_keys dict
                api_keys = config.get("api_keys", {})
                if api_keys:
                    return next(iter(api_keys))
                # Check for gateway_token
                token = config.get("gateway_token")
                if token:
                    return token
            except (yaml.YAMLError, OSError):
                continue
    return None


def _detect_wintools() -> bool:
    """Detect if wintools-mcp is installed on this machine.

    Always returns False — use --wintools flag explicitly.
    Auto-detection removed because the wintools installer writes config to
    $InstallDir/config.yaml, not ~/.aiir/wintools.yaml.
    """
    return False


def _get_wintools_credentials() -> tuple[str | None, str | None]:
    """Get wintools URL and token if available."""
    wintools_config = Path.home() / ".aiir" / "wintools.yaml"
    if wintools_config.exists():
        try:
            with open(wintools_config) as f:
                config = yaml.safe_load(f) or {}
            url = config.get("url", "http://127.0.0.1:4624/mcp")
            token = config.get("token")
            return url, token
        except (yaml.YAMLError, OSError):
            pass
    return None, None


def _ensure_remote_binding() -> None:
    """Check if gateway is localhost-only and offer to rebind for remote access.

    Only acts when gateway.host is exactly '127.0.0.1' and no TLS is configured.
    Prompts the user, updates gateway.yaml, and restarts the gateway service.
    """
    import subprocess
    import time

    gateway_config = Path.home() / ".aiir" / "gateway.yaml"
    if not gateway_config.exists():
        return

    try:
        with open(gateway_config) as f:
            config = yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return

    gw = config.get("gateway", {})
    if not isinstance(gw, dict):
        return

    # Only rebind if bound to localhost; don't touch 0.0.0.0, custom IPs, or TLS
    if gw.get("host") != "127.0.0.1":
        return
    if gw.get("tls"):
        return

    print("The gateway is bound to 127.0.0.1 (localhost only).")
    print("Remote machines cannot connect until it binds to 0.0.0.0.")
    print()
    answer = input("Rebind gateway to 0.0.0.0 and restart? [Y/n] ").strip().lower()
    if answer in ("n", "no"):
        print(
            "Skipped. To rebind manually, edit ~/.aiir/gateway.yaml "
            "and restart the gateway.",
            file=sys.stderr,
        )
        return

    # Update gateway.yaml atomically
    config["gateway"]["host"] = "0.0.0.0"
    try:
        fd = os.open(str(gateway_config), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except OSError as e:
        print(f"Failed to update gateway.yaml: {e}", file=sys.stderr)
        return

    # Restart gateway via systemd
    print("Restarting gateway...", end="", flush=True)
    try:
        result = subprocess.run(
            ["systemctl", "--user", "restart", "aiir-gateway"],
            timeout=15,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f" failed: {result.stderr.strip()}", file=sys.stderr)
            print(
                "Try manually: systemctl --user restart aiir-gateway",
                file=sys.stderr,
            )
            return
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f" failed: {e}", file=sys.stderr)
        return

    # Wait for gateway to become healthy
    port = gw.get("port", 4508)
    health_url = f"http://127.0.0.1:{port}/health"
    for _attempt in range(10):
        time.sleep(1)
        try:
            import urllib.request

            with urllib.request.urlopen(health_url, timeout=3) as resp:
                if resp.status == 200:
                    print(" done.")
                    print(f"Gateway now listening on 0.0.0.0:{port} (all interfaces).")
                    return
        except OSError:
            print(".", end="", flush=True)

    print(" gateway did not become healthy in time.", file=sys.stderr)
    print("Check: systemctl --user status aiir-gateway", file=sys.stderr)


def _find_ca_cert() -> str | None:
    """Find CA certificate for TLS verification."""
    ca_path = Path.home() / ".aiir" / "tls" / "ca-cert.pem"
    if ca_path.exists():
        return str(ca_path)
    return None
