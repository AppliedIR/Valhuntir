"""A client keeps a gateway address that answers.

After a join, the gateway reports its own address (gateway_url), built from its
default-route IP. Behind NAT with a forwarded port that address doesn't answer
from the examiner's machine, and every backend failed with Connection refused.
Each client script now probes a reported address that differs from the one the
examiner joined through. If it answers, it's kept, as before. If it doesn't,
the entered address is written and one line names both.

Only the join block of each script runs, in a scratch HOME, against a TLS
stand-in gateway on loopback whose certificate names 127.0.0.1 only.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.request

import pytest

from .test_client_scripts_no_loss import (
    LINUX,
    MAC,
    PWSH,
    WIN,
    _bash,
    _between,
    _bin,
    _pwsh,
)
from .test_wintools_join_code_cli import StandIn

CODE = "RIGCODE1"
SH_TOOLS = [
    "curl",
    "sed",
    "tr",
    "grep",
    "hostname",
    "mkdir",
    "chmod",
    "cat",
    "head",
    "cut",
]
STUBS = 'header() { :; }; err() { echo "ERR $*"; }\n'
# What each join block prints on a join with no CA, as before the probe.
UNCHANGED = {
    "linux": (
        "WARN Using insecure TLS (no CA cert). Use --ca-cert for production.\n"
        "INFO Joining gateway at {url}...\n"
        "OK Joined gateway\n"
        "INFO Token: vhir_gw_0000...\n"
        "OK Credentials saved to {config}\n"
    ),
    "macos": (
        "INFO Joining gateway at {url}...\n"
        "WARN Using insecure TLS (no CA cert found).\n"
        "OK Joined gateway\n"
    ),
    "windows": "[INFO] Joining gateway at {url}...\n[OK] Joined gateway\n",
}
CLIENTS = [
    "linux",
    "macos",
    pytest.param(
        "windows", marks=pytest.mark.skipif(not PWSH, reason="pwsh not installed")
    ),
]


def _gateway(tmp_path, reported):
    """The stand-in: the join reports ``reported`` (None: its own address);
    anything else answers 200."""
    box: dict = {}

    def answer(method, path, headers):
        if path == "/api/v1/setup/join":
            return 200, {
                "status": "joined",
                "gateway_token": "vhir_gw_" + "0" * 24,
                "gateway_url": reported or box["gw"].url,
                "backends": ["forensic-mcp", "sift-mcp"],
            }
        return 200, {"status": "ok"}

    box["gw"] = StandIn(tmp_path, answer)
    return box["gw"]


def _closed_port():
    """A bound socket that doesn't listen: a connection to it is refused."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    return s


def _silent_port():
    """A listener whose backlog is full: a new connection's SYN is dropped, so
    a connect neither succeeds nor is refused. Returns the sockets to hold."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(0)
    held = [s]
    for _ in range(4):
        c = socket.socket()
        c.setblocking(False)
        try:
            c.connect(s.getsockname())
        except BlockingIOError:
            pass
        held.append(c)
    time.sleep(0.3)
    t = socket.socket()
    t.settimeout(1)
    try:
        t.connect(s.getsockname())
        silent = False
    except TimeoutError:
        silent = True
    finally:
        t.close()
    assert silent, "the full-backlog listener answered; no silent address here"
    return held


def _join(client, tmp_path, entered):
    """Run the client's join block; return (rc, output, written gateway_url)."""
    home = tmp_path / "home"
    home.mkdir()
    if client == "windows":
        block = _between(WIN, "# Join Gateway", "# Restrict config.yaml")
        body = f"$Sift = '{entered}'\n$Code = '{CODE}'\n" + block
        rc, out = _pwsh(home, body, tmp_path / "appdata")
    else:
        text, start, end = {
            "linux": (LINUX, "# ---- Phase 2: Join ----", "# ---- Phase 3: Examiner"),
            "macos": (MAC, "# Join Gateway", "# ---- Examiner Identity ----"),
        }[client]
        rc, out = _bash(
            text,
            STUBS + _between(text, start, end),
            home,
            _bin(tmp_path, SH_TOOLS),
            SIFT_URL=entered,
            JOIN_CODE=CODE,
            CA_CERT="",
        )
    config = home / ".vhir" / "config.yaml"
    m = re.search(r'^gateway_url: "(.*)"', config.read_text("utf-8-sig"), re.M)
    return rc, out, m.group(1) if m else None


def _naming_both(out, a, b):
    """Output lines naming both addresses (a port isn't read as a prefix)."""
    a_, b_ = (re.compile(re.escape(u) + r"(?![\d.])") for u in (a, b))
    return [ln for ln in out.splitlines() if a_.search(ln) and b_.search(ln)]


def _unchanged(client, tmp_path, entered):
    """The lines the join block printed before the probe."""
    config = tmp_path / "home" / ".vhir" / "config.yaml"
    return UNCHANGED[client].format(url=entered, config=config).splitlines()


def _fell_back(client, tmp_path, out, reported, entered):
    """One line names both addresses, and the rest is the output from before."""
    both = _naming_both(out, reported, entered)
    assert len(both) == 1, out
    rest = [ln for ln in out.splitlines() if ln != both[0]]
    assert rest == _unchanged(client, tmp_path, entered), out


@pytest.mark.parametrize("client", CLIENTS)
def test_a_reported_address_that_does_not_answer_gives_way_to_the_entered_one(
    client, tmp_path
):
    """The NAT shape: the gateway reports an address nothing answers on. The
    entered address is written, and one line names both."""
    closed = _closed_port()
    reported = f"https://127.0.0.1:{closed.getsockname()[1]}"
    gw = _gateway(tmp_path, reported)
    try:
        rc, out, written = _join(client, tmp_path, gw.url)
    finally:
        gw.close()
        closed.close()
    assert rc == 0, out
    assert written == gw.url, out
    _fell_back(client, tmp_path, out, reported, gw.url)


@pytest.mark.parametrize("client", CLIENTS)
def test_a_reported_address_that_is_silent_gives_way_within_the_probe_limit(
    client, tmp_path
):
    """The reported address drops the connection attempt instead of refusing
    it. The probe gives up after its own 5 seconds, not the join's 30-second
    curl limit, and the entered address is written. The bound is 5 seconds
    plus 10 for the join and the shell's start."""
    held = _silent_port()
    reported = f"https://127.0.0.1:{held[0].getsockname()[1]}"
    gw = _gateway(tmp_path, reported)
    try:
        start = time.monotonic()
        rc, out, written = _join(client, tmp_path, gw.url)
        took = time.monotonic() - start
    finally:
        gw.close()
        for s in held:
            s.close()
    assert rc == 0, out
    assert written == gw.url, out
    _fell_back(client, tmp_path, out, reported, gw.url)
    assert took < 15, f"{took:.1f}s\n{out}"


@pytest.mark.parametrize("client", CLIENTS)
def test_a_reported_address_that_answers_is_kept(client, tmp_path):
    """The twin for the keep branch: the reported address differs from the
    entered one and answers, so it's kept with no line. The stand-in's
    certificate names only 127.0.0.1, so the written address must verify where
    the entered name (localhost) wouldn't."""
    gw = _gateway(tmp_path, None)
    port = gw.server.server_address[1]
    entered = f"https://localhost:{port}"
    try:
        rc, out, written = _join(client, tmp_path, entered)
        verify = ssl.create_default_context(cafile=gw.cert[0])
        with urllib.request.urlopen(f"{written}/health", context=verify, timeout=5):
            pass
    finally:
        gw.close()
    assert rc == 0, out
    assert written == gw.url, out
    assert out.splitlines() == _unchanged(client, tmp_path, entered), out


@pytest.mark.parametrize("client", CLIENTS)
def test_a_reported_address_equal_to_the_entered_one_is_not_probed(client, tmp_path):
    """The flat-LAN shape: nothing differs, so nothing is probed and the output
    is the same as before."""
    gw = _gateway(tmp_path, None)
    try:
        rc, out, written = _join(client, tmp_path, gw.url)
    finally:
        gw.close()
    assert rc == 0, out
    assert written == gw.url, out
    assert gw.requests == [("POST", "/api/v1/setup/join")]
    assert out.splitlines() == _unchanged(client, tmp_path, gw.url), out
