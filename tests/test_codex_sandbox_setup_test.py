"""`vhir setup test` in Codex's no-network sandbox.

Codex sets CODEX_SANDBOX_NETWORK_DISABLED=1 in its sandboxed shell, and the
sandbox refuses an AF_INET socket with EPERM. With both, setup test checked
bwrap (a nested network namespace fails there), blamed AppArmor and advised a
reboot on a kernel restricting user namespaces, printed the userns notice from
inside Codex's working sandbox, and waited about a minute for a gateway it
can't reach before printing OFFLINE. Now it prints one Sandbox line, the
Codex controls state and the SIFT tools warning, and stops. The variable alone,
or a refused socket alone, changes nothing. Every row runs with the kernel's
userns restriction both off and on (a stand-in for the sysctl).
"""

from __future__ import annotations

import errno
import json
import time
import types
import urllib.error

import pytest

from vhir_cli.commands import codex_controls as cc
from vhir_cli.commands import setup

VAR = "CODEX_SANDBOX_NETWORK_DISABLED"
FALSE_LINES = ("OFFLINE", "AppArmor", "reboot", "docker")


class _Sock:
    def close(self):
        pass


def _socket(outcome):
    def make(*a, **k):
        if outcome == "allowed":
            return _Sock()
        code = errno.EPERM if outcome == "EPERM" else errno.EACCES
        raise OSError(code, "refused")

    return make


@pytest.fixture(params=["0", "1"], ids=["sysctl0", "sysctl1"])
def box(request, tmp_path, monkeypatch):
    """A box set up for Codex with our requirements file, the userns sysctl at
    0 or 1, bwrap failing as it does in Codex's sandbox, and no gateway."""
    sysctl = request.param
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "manifest.json").write_text(json.dumps({"clients": ["codex"]}))
    monkeypatch.setattr(cc.Path, "home", staticmethod(lambda: home))
    req = tmp_path / "etc-codex" / "requirements.toml"
    req.parent.mkdir()
    req.write_text(cc.MARKER + "\n")
    monkeypatch.setattr(cc, "REQUIREMENTS", req)
    monkeypatch.setattr(cc, "USERNS", tmp_path / "userns")
    cc.USERNS.write_text(sysctl + "\n")
    seen = types.SimpleNamespace(run=[], urlopen=0, sleep=0, snapshots=0)

    def run(cmd, **k):
        seen.run.append(list(cmd))
        if cmd[0] == "sysctl":
            out = (
                sysctl
                if cmd[-1] == "kernel.apparmor_restrict_unprivileged_userns"
                else "1"
            )
            return types.SimpleNamespace(returncode=0, stdout=out + "\n", stderr="")
        if cmd[0].endswith("bwrap"):
            err = "bwrap: loopback: Failed to create NETLINK_ROUTE socket: Operation not permitted"
            return types.SimpleNamespace(returncode=1, stdout="", stderr=err)
        if cmd[0] == "systemd-detect-virt":
            return types.SimpleNamespace(returncode=1, stdout="none\n", stderr="")
        return types.SimpleNamespace(returncode=0, stdout="6.8.0-generic\n", stderr="")

    def urlopen(*a, **k):
        seen.urlopen += 1
        raise urllib.error.URLError(OSError(errno.EPERM, "Operation not permitted"))

    def sleep(s):
        seen.sleep += 1

    def resolve(*a, **k):
        seen.snapshots += 1
        return None

    monkeypatch.setattr("subprocess.run", run)
    monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr(time, "sleep", sleep)
    monkeypatch.setattr(
        "vhir_cli.commands.update._resolve_opensearch_mcp_repo", resolve
    )
    monkeypatch.setattr(
        "vhir_cli.sift_tools.warning", lambda: "Hayabusa missing: stand-in"
    )
    monkeypatch.setattr(
        "vhir_cli.gateway.get_local_gateway_url", lambda: "http://127.0.0.1:4508"
    )
    monkeypatch.setattr("vhir_cli.gateway.get_local_ssl_context", lambda: None)
    seen.sysctl = sysctl
    return seen


@pytest.mark.parametrize("outcome", ["EPERM", "EACCES", "allowed"])
@pytest.mark.parametrize("var", [None, "1", "0", "true"])
def test_the_predicate_needs_the_variable_and_a_socket_refused_with_eperm(
    box, monkeypatch, var, outcome
):
    if var is None:
        monkeypatch.delenv(VAR, raising=False)
    else:
        monkeypatch.setenv(VAR, var)
    monkeypatch.setattr("socket.socket", _socket(outcome))
    assert cc.in_codex_sandbox() is (var == "1" and outcome == "EPERM")


def test_the_variable_with_a_real_socket_outside_a_sandbox_is_not_codex(
    box, monkeypatch
):
    monkeypatch.setenv(VAR, "1")
    assert cc.in_codex_sandbox() is False


def test_in_codex_s_sandbox_setup_test_prints_one_sandbox_line_and_stops(
    box, monkeypatch, capsys
):
    monkeypatch.setenv(VAR, "1")
    monkeypatch.setattr("socket.socket", _socket("EPERM"))
    t0 = time.monotonic()
    setup._run_connectivity_test()
    took = time.monotonic() - t0
    out = capsys.readouterr().out
    sandbox = [ln for ln in out.splitlines() if "Codex's sandbox" in ln]
    assert len(sandbox) == 1 and "no network" in sandbox[0]
    assert "MCP tools in this session are the gateway check" in sandbox[0]
    for word in FALSE_LINES:
        assert word not in out, word
    assert "bwrap:" not in out and "socat:" not in out and "Gateway:" not in out
    assert "can't start" not in out  # the userns notice
    assert "Managed requirements: in effect" in out
    assert "WARNING: Hayabusa missing: stand-in" in out
    assert not [c for c in box.run if c[0].endswith("bwrap") or c[0] == "sysctl"]
    assert (box.urlopen, box.sleep, box.snapshots) == (0, 0, 0)
    assert took <= 10


@pytest.mark.parametrize("var, outcome", [("1", "allowed"), (None, "EPERM")])
def test_outside_codex_s_sandbox_setup_test_checks_everything_as_before(
    box, monkeypatch, capsys, var, outcome
):
    if var is None:
        monkeypatch.delenv(VAR, raising=False)
    else:
        monkeypatch.setenv(VAR, var)
    monkeypatch.setattr("socket.socket", _socket(outcome))
    setup._run_connectivity_test()
    out = capsys.readouterr().out
    assert "this shell has no network" not in out
    assert [c for c in box.run if c[0].endswith("bwrap")]
    assert "socat: OK" in out and box.snapshots == 1
    assert box.urlopen == 30 and "Gateway: OFFLINE" in out
    assert ("AppArmor" in out) is (box.sysctl == "1")
    assert ("can't start" in out) is (box.sysctl == "1")


def test_the_userns_notice_is_never_in_the_state_lines_in_codex_s_sandbox(
    box, monkeypatch
):
    monkeypatch.setenv(VAR, "1")
    monkeypatch.setattr("socket.socket", _socket("EPERM"))
    assert not [ln for ln in cc.state_lines() if "can't start" in ln]
    monkeypatch.setattr("socket.socket", _socket("allowed"))
    notice = [ln for ln in cc.state_lines() if "can't start" in ln]
    assert len(notice) == (1 if box.sysctl == "1" else 0)
