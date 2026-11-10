"""Which servers `vhir setup client --client=open-webui` sends a token to when
it asks each backend for its instructions, through local setup and --remote.

An entry on the gateway setup discovered from (the same parsed scheme, host
and port, never the same name or a string prefix) is checked as discovery
checked the gateway. Any other entry is checked by whose server it is:
wintools-mcp by the pin its join left in gateway.yaml, everything else, REMnux
included, by the system store. Every row's gateway has TLS set and no CA file.

Servers are stand-ins over TLS on loopback with throwaway certs, HOME is
isolated, and every value is synthetic.
"""

from __future__ import annotations

import argparse
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from vhir_cli.commands import client_setup as cs

from .test_wintools_join_code_cli import _cert

GW_TOKEN = "vhir_gw_" + "d" * 24
WT_TOKEN = "vhir_wt_" + "e" * 24
RX_TOKEN = "remnux-token-" + "f" * 12


def _says(who: str) -> str:
    return f"Instructions from the {who} stand-in."


class Server:
    """A TLS stand-in on 127.0.0.1 that answers initialize with its own line
    and records the Authorization header of each request past the handshake."""

    def __init__(self, folder: Path, who: str, port: int = 0):
        folder.mkdir()
        self.cert = _cert(folder)
        self.bearers: list[str] = []
        me = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                me.bearers.append(self.headers.get("Authorization", ""))
                result = {"instructions": _says(who)}
                data = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data.encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*self.cert)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _servers_sharing_a_prefix(tmp_path: Path) -> tuple[Server, Server]:
    """(gateway, other): the other's URL starts with the gateway's whole URL,
    e.g. https://127.0.0.1:45081 and https://127.0.0.1:4508."""
    for attempt in range(50):
        other = Server(tmp_path / f"other-{attempt}", "other")
        try:
            gateway = Server(tmp_path / f"gw-{attempt}", "gateway", other.port // 10)
        except OSError:  # that port is taken here: try another pair
            other.close()
            continue
        assert other.url.startswith(gateway.url) and other.url != gateway.url
        return gateway, other
    raise AssertionError("no free pair of ports sharing a prefix")


# row: (where the other server is, its name, its certificate, what happens)
#   where: "own-port" | "prefix-port" (its URL starts with the gateway's) |
#          "on-gateway" (a backend the gateway serves) | "bad-port"
#   cert:  "rogue" (self-signed, trusted by nothing) | "pinned" (the join's
#          pin in gateway.yaml) | "system-store" (trusted by SSL_CERT_FILE) |
#          "pin-gone" (the join's pin names a file that isn't there, and the
#          system store trusts the server, so only the refusal keeps it back)
ROWS = {
    "wintools-direct-with-a-rogue-cert-is-refused": (
        "own-port",
        "wintools-mcp",
        "rogue",
        "refused",
    ),
    "wintools-direct-with-an-unusable-pin-sends-nothing": (
        "own-port",
        "wintools-mcp",
        "pin-gone",
        "refused",
    ),
    "wintools-direct-with-the-pinned-cert-is-sent": (
        "own-port",
        "wintools-mcp",
        "pinned",
        "sent",
    ),
    "wintools-served-by-the-gateway-is-sent": (
        "on-gateway",
        "wintools-mcp",
        "rogue",
        "sent",
    ),
    "a-url-extending-the-gateways-is-refused": (
        "prefix-port",
        "wintools-mcp",
        "rogue",
        "refused",
    ),
    "remnux-with-a-rogue-cert-is-refused": (
        "own-port",
        "remnux-mcp",
        "rogue",
        "refused",
    ),
    "remnux-trusted-by-the-system-store-is-sent": (
        "own-port",
        "remnux-mcp",
        "system-store",
        "sent",
    ),
    "a-port-out-of-range-is-listed-as-missing": (
        "bad-port",
        "wintools-mcp",
        "rogue",
        "missing",
    ),
}


def _local(gateway: str, flags: dict) -> None:
    args = argparse.Namespace(
        client="open-webui", sift=gateway, examiner="tester", no_mslearn=True,
        yes=True, uninstall=False, add_remnux=None, remote=False,
        windows=flags.get("windows"), windows_token=flags.get("windows_token"),
        remnux=flags.get("remnux"), remnux_token=flags.get("remnux_token"),
    )  # fmt: skip
    cs.cmd_setup_client(args, {"examiner": "tester"})


def _remote(gateway: str, flags: dict) -> None:
    args = argparse.Namespace(
        client="open-webui", sift=gateway, token=GW_TOKEN, examiner="tester",
        no_mslearn=True, yes=True, uninstall=False, add_remnux=None, remote=True,
        windows=flags.get("windows"), windows_token=flags.get("windows_token"),
        remnux=flags.get("remnux"), remnux_token=flags.get("remnux_token"),
    )  # fmt: skip
    cs.cmd_setup_client(args, {"examiner": "tester"})


# the two call sites that write the Open WebUI files
CALLERS = {"local": _local, "remote": _remote}


@pytest.mark.parametrize("caller", CALLERS)
@pytest.mark.parametrize("row", ROWS)
def test_the_instructions_request_trusts_only_the_servers_own_check(
    tmp_path, monkeypatch, capsys, row, caller
):
    where, name, cert, want = ROWS[row]
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    if where == "prefix-port":
        gateway, other = _servers_sharing_a_prefix(tmp_path)
    else:
        gateway = Server(tmp_path / "gw", "gateway")
        other = Server(tmp_path / "other", "other")
    try:
        doc = {
            "gateway": {"tls": {"certfile": gateway.cert[0]}},
            "api_keys": {GW_TOKEN: {"examiner": "tester"}},
        }
        pin = {"pinned": other.cert[0], "pin-gone": str(tmp_path / "gone.pem")}
        if cert in pin:
            doc["backends"] = {
                "wintools-mcp": {"url": f"{other.url}/mcp", "tls_cert": pin[cert]}
            }
        (home / ".vhir" / "gateway.yaml").write_text(yaml.safe_dump(doc))
        if cert in ("system-store", "pin-gone"):
            monkeypatch.setenv("SSL_CERT_FILE", other.cert[0])
        served = ["forensic-mcp"] + (["wintools-mcp"] if where == "on-gateway" else [])
        monkeypatch.setattr(
            cs,
            "_discover_services",
            lambda url, token: [{"name": n, "started": True} for n in served],
        )
        monkeypatch.setattr(
            cs, "_probe_health_with_auth", lambda u, t: {"status": "ok"}
        )
        url = "https://127.0.0.1:99999" if where == "bad-port" else other.url
        token = WT_TOKEN if name == "wintools-mcp" else RX_TOKEN
        flags = {}
        if where != "on-gateway":
            key = "windows" if name == "wintools-mcp" else "remnux"
            flags = {key: url, f"{key}_token": token}
        CALLERS[caller](gateway.url, flags)
    finally:
        gateway.close()
        other.close()
    out = capsys.readouterr()
    prompt = (home / "openwebui-system-prompt.md").read_text()
    note = [ln for ln in out.out.splitlines() if "their instructions aren't" in ln]
    # the gateway answers as discovery found it, with its own token only
    assert f"## forensic-mcp\n\n{_says('gateway')}" in prompt
    assert set(gateway.bearers) == {f"Bearer {GW_TOKEN}"}
    assert f"Bearer {GW_TOKEN}" not in other.bearers
    if want == "sent":
        who = "gateway" if where == "on-gateway" else "other"
        assert f"## {name}\n\n{_says(who)}" in prompt
        if who == "other":
            assert f"Bearer {token}" in other.bearers
        assert note == [] or name not in note[0]
        return
    assert other.bearers == []  # nothing reached the other server
    assert f"## {name}" not in prompt
    assert len(note) == 1 and name in note[0]
    assert "Traceback" not in out.err
    if cert == "pin-gone":  # nothing went out, and the examiner is told why
        assert "the instructions request wasn't sent to wintools-mcp" in out.err


def test_a_port_out_of_range_matches_no_gateway_and_gets_the_system_store(
    tmp_path, monkeypatch
):
    # the gateway's own check here would verify nothing: TLS set, no CA file
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "gateway.yaml").write_text(
        yaml.safe_dump({"gateway": {"tls": {"certfile": "/nonexistent/gw.pem"}}})
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    gw = "https://127.0.0.1:4508"
    # an entry on the gateway's own origin gets that check, verifying nothing
    assert cs._instructions_context("forensic-mcp", f"{gw}/mcp/x", gw).verify_mode == (
        ssl.CERT_NONE
    )
    ctx = cs._instructions_context("remnux-mcp", "https://127.0.0.1:99999/mcp", gw)
    assert (ctx.verify_mode, ctx.check_hostname) == (ssl.CERT_REQUIRED, True)
