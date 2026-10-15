"""What `vhir setup join-code` and case preparation tell the examiner about
wintools, and what they leave on disk.

Each row runs the real function with an isolated HOME, stand-in groups, and
`sudo`/`systemctl` stand-ins first on PATH whose calls are recorded: none may
run. Network rows talk to a stand-in server over TLS on loopback, pinned to a
throwaway cert. Values are synthetic.
"""

from __future__ import annotations

import argparse
import datetime
import grp
import ipaddress
import json
import os
import ssl
import stat
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from vhir_cli import main
from vhir_cli.commands import join

OWNER = "vhir_gw_" + "a" * 24
STUB = '#!/bin/sh\necho "$0 $*" >> "{log}"\nexit 1\n'


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An isolated HOME, with sudo and systemctl stand-ins that record."""
    home = tmp_path / "home"
    (home / ".vhir" / "tls").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    assert Path.home() == home
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name in ("sudo", "systemctl"):
        (stubs / name).write_text(STUB.format(log=tmp_path / "calls.log"))
        (stubs / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{stubs}:{os.environ.get('PATH', '')}")
    yield home
    calls = tmp_path / "calls.log"
    assert not calls.exists(), calls.read_text()


def _groups(monkeypatch, gids: dict[str, int], member_of=()):
    """Stand-in group database; this process is in ``member_of`` only."""
    monkeypatch.setattr(
        grp,
        "getgrnam",
        lambda name: types.SimpleNamespace(gr_gid=gids[name]),
    )
    monkeypatch.setattr(os, "getgroups", lambda: [os.getegid(), *member_of])


def _case(home: Path) -> Path:
    case = home / "cases" / "CASE-1"
    (case / "extractions").mkdir(parents=True)
    (case / "audit").mkdir()
    return case


def _samba(home: Path, **doc) -> None:
    (home / ".vhir" / "samba.yaml").write_text(yaml.safe_dump(doc))


def test_a_box_on_the_old_share_without_the_group_makes_nothing_and_names_the_fix(
    home, monkeypatch
):
    _groups(monkeypatch, {"sift": 2222})  # not a member, as a running gateway
    chowned = []

    def fchown(fd, uid, gid):  # as the kernel: only a group this process is in
        if gid != os.getegid() and gid not in os.getgroups():
            raise PermissionError(1, "Operation not permitted")
        chowned.append(gid)

    monkeypatch.setattr(os, "fchown", fchown)
    _samba(home, share_name="cases", force_user="examiner")
    case = _case(home)
    warning = main._set_case_wintools_permissions(case) or ""
    assert f"Group permissions not applied to {case / 'extractions' / 'wintools'}" in (
        warning
    )
    assert "vhir setup join-code" in warning and "Log out" not in warning
    assert not (case / "extractions" / "wintools").exists()
    assert not (case / "audit" / "wintools-mcp.jsonl").exists()
    assert chowned == []


def test_a_box_on_vhirs_own_share_needs_no_extra_group(home, monkeypatch):
    own = os.getegid()  # the share's group: the installer's own primary group
    _groups(monkeypatch, {"examiner": own, "sift": 2222})
    _samba(
        home,
        share_name=join.SHARE_NAME,
        force_user="examiner",
        force_group="examiner",
    )
    case = _case(home)
    assert main._set_case_wintools_permissions(case) is None
    folder = case / "extractions" / "wintools"
    audit = case / "audit" / "wintools-mcp.jsonl"
    assert (stat.S_IMODE(folder.stat().st_mode), folder.stat().st_gid) == (0o2775, own)
    assert (stat.S_IMODE(audit.stat().st_mode), audit.stat().st_gid) == (0o664, own)


def _cert(folder: Path) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stand-in")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = folder / "stand-in.pem", folder / "stand-in.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


class StandIn:
    """A TLS server on loopback answering every request with ``answer(method,
    path, headers)`` -> (status, body dict); it records each request."""

    def __init__(self, folder: Path, answer):
        self.cert = _cert(folder)
        self.requests: list[tuple[str, str]] = []
        stand_in = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self):
                stand_in.requests.append((self.command, self.path))
                status, body = answer(self.command, self.path, self.headers)
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = _reply

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*self.cert)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def test_a_refused_smb_credential_push_says_what_wintools_answered(
    home, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(time, "sleep", lambda s: None)
    wintools = StandIn(
        tmp_path,
        lambda m, p, h: (
            503,
            {"error": "Credentials saved but SMB session failed: System error 86"},
        ),
    )
    try:
        pin = home / ".vhir" / "tls" / "wintools-cert.pem"
        pin.write_text(Path(wintools.cert[0]).read_text())
        entry = {"url": f"{wintools.url}/mcp", "bearer_token": "vhir_wt_" + "c" * 24}
        (home / ".vhir" / "gateway.yaml").write_text(
            yaml.safe_dump({"backends": {"wintools-mcp": entry}})
        )
        join._push_smb_credentials("pw")
    finally:
        wintools.close()
    assert wintools.requests == [("POST", "/config/update-smb")] * 3
    err = capsys.readouterr().err
    assert "HTTP 503" in err and "SMB session failed: System error 86" in err
    assert "didn't confirm the new SMB credentials" in err
    assert "Run the Windows installer with this join code" in err


def test_the_join_code_printout_gives_the_unattended_form_and_the_client_step(
    home, monkeypatch, capsys
):
    samba = []
    monkeypatch.setattr(join, "_setup_samba_share", lambda code: samba.append(code))
    monkeypatch.setattr(join, "_setup_firewall", lambda ip: None)
    monkeypatch.setattr(
        join, "_get_local_gateway_url", lambda: "https://127.0.0.1:4508"
    )
    join._post_join_code_setup({"code": "ABCD-EFGH", "expires_hours": 2}, "192.0.2.5")
    out = capsys.readouterr().out
    lines = out.splitlines()
    first = next(i for i, x in enumerate(lines) if "setup-windows.ps1 -JoinCode" in x)
    assert "-NonInteractive -AcknowledgeSecurityHole" in lines[first + 1]
    assert (
        "When the installer has finished: run 'vhir setup client' on each examiner "
        "machine, then /mcp in Claude Code" in out
    )
    assert samba == ["ABCD-EFGH"]


def _fail(message):
    def step(arg):
        raise RuntimeError(message)

    return step


@pytest.mark.parametrize(
    "share, firewall, reason",
    [
        (
            _fail("smbd restart failed"),
            lambda ip: None,
            "Samba share setup failed: smbd restart failed",
        ),
        (
            lambda code: "192.0.2.20",
            _fail("ufw not found"),
            "Firewall setup failed: ufw not found",
        ),
    ],
    ids=["share", "firewall"],
)
def test_a_failed_setup_step_shows_no_join_code_and_exits_nonzero(
    home, monkeypatch, capsys, share, firewall, reason
):
    monkeypatch.setattr(join, "_setup_samba_share", share)
    monkeypatch.setattr(join, "_setup_firewall", firewall)
    monkeypatch.setattr(
        join, "_get_local_gateway_url", lambda: "https://127.0.0.1:4508"
    )
    with pytest.raises(SystemExit) as stop:
        join._post_join_code_setup(
            {"code": "ABCD-EFGH", "expires_hours": 2}, "192.0.2.5"
        )
    assert stop.value.code not in (0, None)
    out, err = capsys.readouterr()
    assert out == ""
    assert "ABCD-EFGH" not in err
    assert reason in err and "No join code was shown" in err
    assert "run 'vhir setup join-code' again" in err


@pytest.mark.parametrize("status", [200, 403])
def test_join_code_revoke_ends_unused_codes_and_does_nothing_else(
    home, tmp_path, monkeypatch, capsys, status
):
    def answer(method, path, headers):
        if headers.get("Authorization") != f"Bearer {OWNER}":
            return 401, {"error": "no key"}
        if status != 200:
            return status, {"error": "Only the gateway owner can revoke join codes"}
        return 200, {"revoked": 2}

    gateway = StandIn(tmp_path, answer)
    others = []
    for step in (
        "_ensure_static_ip",
        "_ensure_remote_binding",
        "_post_join_code_setup",
        "_setup_samba_share",
    ):
        monkeypatch.setattr(join, step, lambda *a, _s=step: others.append(_s))
    monkeypatch.setattr(join, "_get_local_gateway_token", lambda: OWNER)
    monkeypatch.setattr(join, "_get_local_gateway_url", lambda: gateway.url)
    monkeypatch.setattr(join, "_find_ca_cert", lambda: gateway.cert[0])
    args = argparse.Namespace(revoke=True, expires=None, name=None)
    try:
        if status == 200:
            join.cmd_setup_join_code(args, {})
        else:
            with pytest.raises(SystemExit) as e:
                join.cmd_setup_join_code(args, {})
            assert e.value.code == 1
    finally:
        gateway.close()
    assert gateway.requests == [("DELETE", "/api/v1/setup/join-code")]
    assert others == []
    captured = capsys.readouterr()
    if status == 200:
        assert "Ended 2 unused join codes." in captured.out
    else:
        assert "Failed to revoke join codes" in captured.err


def test_the_revoke_option_is_on_the_join_code_command():
    args = main.build_parser().parse_args(["setup", "join-code", "--revoke"])
    assert args.revoke is True
    args = main.build_parser().parse_args(["setup", "join-code"])
    assert args.revoke is False


def test_an_error_body_that_cannot_be_read_still_retries_and_warns(
    home, monkeypatch, capsys
):
    import io
    import urllib.error
    import urllib.request

    monkeypatch.setattr(time, "sleep", lambda s: None)
    (home / ".vhir" / "gateway.yaml").write_text(
        yaml.safe_dump(
            {
                "backends": {
                    "wintools-mcp": {
                        "url": "http://192.0.2.9:4624/mcp",
                        "bearer_token": "vhir_wt_" + "c" * 24,
                    }
                }
            }
        )  # fmt: skip
    )
    tries = []

    class Stalled(io.BytesIO):
        def read(self, *a):
            raise TimeoutError("timed out")

    def refuse(req, **kw):
        tries.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, Stalled())

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    join._push_smb_credentials("pw")
    assert len(tries) == 3
    err = capsys.readouterr().err
    assert "HTTP 503: (its body couldn't be read: timed out)" in err
    assert "didn't confirm the new SMB credentials" in err
