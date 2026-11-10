"""Shared helpers for talking to the local Valhuntir gateway.

Reads ~/.vhir/gateway.yaml for host, port, and TLS config.
Always uses 127.0.0.1 for local access (even if host is 0.0.0.0).

config.yaml's gateway_url field is for remote clients only — written by
'vhir join' on remote machines, never read by local commands. F12 (rebind
not updating config.yaml) is moot because local commands use gateway.yaml.
"""

from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from vhir_cli.update_handover import hand_over_older_update

# Said after vhir restarts the gateway: a running Claude Code session's tool
# connections don't come back by themselves
RECONNECT_HINT = (
    "Open Claude Code sessions lose their tool connections when the gateway "
    "restarts: run /mcp in each (or restart it)."
)


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

    On 0.6.0-0.6.2 an older vhir update may reach the new code first here
    (its connectivity test, after the gateway restart).
    """
    hand_over_older_update()
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


def get_local_gateway_cert_sha256() -> str | None:
    """SHA-256 (64 lowercase hex) of the first certificate's DER in
    gateway.tls.certfile, the certificate the gateway presents. The Windows
    installer pins it. None when the gateway has no TLS (the same test as
    get_local_ssl_context). Raises OSError or ValueError when the file can't
    be read or holds no certificate."""
    import hashlib
    import re

    gw = _read_gateway_config().get("gateway", {})
    tls = gw.get("tls", {}) if isinstance(gw, dict) else {}
    if not isinstance(tls, dict) or not tls.get("certfile"):
        return None
    certfile = str(tls["certfile"])
    pem = Path(certfile).read_text(encoding="ascii", errors="replace")
    first = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S
    )
    if not first:
        raise ValueError(f"no certificate in {certfile}")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(first.group(0))).hexdigest()


def find_ca_cert() -> str | None:
    """Return ~/.vhir/tls/ca-cert.pem path if it exists, else None."""
    ca_path = Path.home() / ".vhir" / "tls" / "ca-cert.pem"
    if ca_path.exists():
        return str(ca_path)
    return None


def local_gateway_ca_cert() -> str | None:
    """Absolute path of the gateway CA a local client must trust, or None.

    Returns ~/.vhir/tls/ca-cert.pem when the local gateway is configured for
    TLS (gateway.tls.certfile) and that CA file exists. This is exactly
    get_local_ssl_context's own precondition, exposed so a local client can
    be told which CA to trust; a client that doesn't trust it fails every
    gateway connection with UNABLE_TO_VERIFY_LEAF_SIGNATURE.
    """
    config = _read_gateway_config()
    gw = config.get("gateway", {})
    if not isinstance(gw, dict):
        return None
    tls = gw.get("tls", {})
    if not isinstance(tls, dict) or not tls.get("certfile"):
        return None
    return find_ca_cert()


# --- waiting for the gateway's /health (update Step 8, join-code) ------------

DEADLINE = 240.0  # one owner for vhir; setup-sift.sh GW_WAIT_BOUND is a pinned copy
CALL_CAP = 15.0  # setup-sift.sh's --max-time 15; /health may take 10 s per backend
POLL = 2.0
RESTART_FIX = "systemctl --user restart vhir-gateway"
# One text for every failed restart: rc != 0, a timeout that left it inactive,
# and no systemctl (a box with systemctl but no user bus also returns rc != 0)
RESTART_FAILED_FIX = (
    "If the gateway runs as a service: systemctl --user status vhir-gateway,"
    " fix what it shows, then run {rerun}. If you start it by hand: stop it,"
    " run ~/.vhir/start-gateway.sh, then run {hand_rerun}."
)
# "::1" and "::" aren't here: asyncio sets IPV6_V6ONLY, so 127.0.0.1 can't reach them
_ALL_OR_LOOPBACK = (None, "", "127.0.0.1", "localhost", "0.0.0.0")


class Deadline:
    """One budget of monotonic time for a caller's whole wait."""

    def __init__(self, seconds: float) -> None:
        self.seconds, self.end = seconds, time.monotonic() + seconds

    def left(self) -> float:
        return self.end - time.monotonic()


@dataclass
class HealthAnswer:
    ok: bool
    reason: str = ""
    fix: str = ""
    backends: dict | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None  # a 3xx is the answer


def _transport(url, timeout, context):
    """(status, body); raises what the dial raised. No proxy: it is local."""
    handlers = [urllib.request.ProxyHandler({}), _NoRedirect()]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    try:
        with urllib.request.build_opener(*handlers).open(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        if isinstance(e.reason, BaseException):
            raise e.reason from e
        raise OSError(str(e.reason)) from e


def _health(send, url, context, timeout, port, host) -> HealthAnswer:
    """One GET /health (unauthenticated: no bearer is sent)."""
    fix = f"start the gateway: {RESTART_FIX}"
    try:
        status, body = send(url, timeout, context)
    except ssl.SSLError as e:
        why = f"the gateway's TLS didn't match: {e}"
        fix = "check gateway.tls in ~/.vhir/gateway.yaml and the CA vhir trusts"
    except (ConnectionRefusedError, TimeoutError) as e:
        late = isinstance(e, TimeoutError)
        why = f"nothing answered on port {port} ("
        why += "didn't answer in time)" if late else "refused)"
        if host not in _ALL_OR_LOOPBACK:
            why = f"the gateway is set to listen only on {host}, and local"
            why += " clients dial 127.0.0.1"
            fix = "set gateway.host in ~/.vhir/gateway.yaml to 127.0.0.1 or"
            fix += f" 0.0.0.0, then: {RESTART_FIX}"
    except (OSError, http.client.HTTPException) as e:
        why = f"couldn't reach the gateway: {e}"
    else:
        try:
            data = json.loads(body) if status == 200 else None
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict) and data.get("status") in ("ok", "degraded"):
            b = data.get("backends")
            return HealthAnswer(True, backends=b if isinstance(b, dict) else None)
        why = f"something on port {port} answered /health, but not as the"
        why += " Valhuntir gateway"
        fix = f"find what holds port {port} (ss -ltnp), stop it, then: {RESTART_FIX}"
        if status != 200:
            why = f"the gateway answered /health with HTTP {status}"
            fix = "systemctl --user status vhir-gateway"
    return HealthAnswer(False, why, fix)


def wait_for_health(
    budget: Deadline, *, transport=None, once=False, until=None
) -> HealthAnswer:
    """Poll /health every POLL s until a pass (HTTP 200, a JSON object whose
    status is "ok" or "degraded") or the budget is spent; returns the last
    answer. once: one call. until(backends) on a pass: True done, False stop,
    None keep polling (the last pass is returned if time runs out)."""
    gw = _read_gateway_config().get("gateway")
    gw = gw if isinstance(gw, dict) else {}
    port, host = gw.get("port", 4508), gw.get("host")
    url, context = get_local_gateway_url() + "/health", get_local_ssl_context()
    answer = HealthAnswer(False, "no time was left to check the gateway", RESTART_FIX)
    shown = 0
    while (left := budget.left()) > 0:
        answer = _health(
            transport or _transport, url, context, min(CALL_CAP, left), port, host
        )
        if answer.ok and (until is None or until(answer.backends) is not None):
            return answer
        left = budget.left()
        if once or left <= 0:
            return answer
        if (waited := int(budget.seconds - left)) // 10 > shown:
            shown = waited // 10
            print(f"  waiting for the gateway ({waited} of {budget.seconds:.0f} s)")
        time.sleep(min(POLL, left))
    return answer
