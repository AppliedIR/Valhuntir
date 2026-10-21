"""A wintools box whose smb.conf lost vhir's include says so, with the fix.

A SIFT update (its salt highstate) rewrites /etc/samba/smb.conf without the
`include = /etc/samba/smb.conf.d/vhir-cases.conf` line join setup added, so
Samba stops serving the share and every Windows tool falls back to Plaso.
`vhir setup test` (and `vhir update`, which runs it) and CLI init, activate
and reopen now print a warning with the two fix lines. Only a line of its own
counts as the include. Every command is recorded, none run.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import types
import urllib.error
import urllib.request

import pytest
import yaml

from vhir_cli import case_copies, main
from vhir_cli.commands import codex_controls, join, setup, update

INCLUDE = "include = /etc/samba/smb.conf.d/vhir-cases.conf"
FIX = (
    "printf '\\ninclude = /etc/samba/smb.conf.d/vhir-cases.conf\\n'"
    " | sudo tee -a /etc/samba/smb.conf"
)
RELOAD = "sudo smbcontrol smbd reload-config"
WARNING = (
    "Samba isn't serving the wintools share: /etc/samba/smb.conf has no "
    f"'{INCLUDE}' line. A SIFT update rewrites /etc/samba/smb.conf; until the "
    "line is back, Windows tools fall back to Plaso. Fix:\n"
    f"      {FIX}\n"
    f"      {RELOAD}"
)
OK = "OK (/etc/samba/smb.conf includes the wintools share)"

# the demo VM's smb.conf after the SIFT update: SIFT's own shares, no include
SALT = (
    "[global]\n   workgroup = WORKGROUP\n   map to guest = bad user\n\n"
    "[cases]\n   path = /cases\n   read only = yes\n\n"
    "[mnt]\n   path = /mnt\n   read only = yes\n"
)

SHAPES = {
    "absent": (SALT, "warn"),
    "present": (SALT + INCLUDE + "\n", "ok"),
    "present-indented": (SALT + "   " + INCLUDE + "   \n", "ok"),
    "present-no-final-newline": (SALT + INCLUDE, "ok"),
    "hash-comment": (SALT + "# " + INCLUDE + "\n", "warn"),
    "semicolon-comment": (SALT + ";" + INCLUDE + "\n", "warn"),
    "glued": (SALT.rstrip("\n") + INCLUDE + "\n", "warn"),
    "in-a-value": (SALT + "   comment = " + INCLUDE + "\n", "warn"),
}


@pytest.fixture
def conf(tmp_path, monkeypatch):
    """smb.conf at a scratch path; the test writes it, or leaves it missing."""
    path = tmp_path / "smb.conf"
    monkeypatch.setattr(join, "SMB_CONF", str(path), raising=False)  # red on base
    return path


@pytest.fixture
def joined(tmp_path, monkeypatch):
    """A HOME on a box joined to wintools."""
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "samba.yaml").write_text(
        yaml.dump({"share_name": join.SHARE_NAME, "wintools_ip": "192.0.2.7"})
    )
    return tmp_path


def _check(conf):
    kind, text = join.samba_include_check()
    return kind, text.replace(str(conf), "/etc/samba/smb.conf")


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_only_an_include_on_its_own_line_counts(conf, shape):
    text, expected = SHAPES[shape]
    conf.write_text(text)
    kind, said = _check(conf)
    assert kind == expected
    assert said == (WARNING if expected == "warn" else OK)


def test_a_missing_smb_conf_gives_the_warning(conf):
    assert _check(conf) == ("warn", WARNING)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-000 file")
def test_an_unreadable_smb_conf_is_not_checked(conf):
    conf.write_text(SALT)
    conf.chmod(0)
    try:
        kind, said = _check(conf)
    finally:
        conf.chmod(0o644)
    assert (kind, said) == (
        "unknown",
        "couldn't check /etc/samba/smb.conf: Permission denied",
    )


def test_the_printed_fix_line_adds_an_include_that_counts(conf):
    """The fix line run as printed (tee writing to scratch) on a file with no
    final newline: the include lands on a line of its own."""
    conf.write_text(SALT.rstrip("\n"))
    cmd = FIX.replace("sudo tee -a /etc/samba/smb.conf", f"cat >> '{conf}'")
    subprocess.run(["sh", "-c", cmd], check=True)
    assert join.has_vhir_include(conf.read_text())
    assert conf.read_text() == SALT.rstrip("\n") + "\n" + INCLUDE + "\n"


# --- vhir setup test (vhir update runs the same test) ---


def _offline_box(monkeypatch):
    """Not in Codex's sandbox, no bwrap, no opensearch-mcp, no gateway."""
    monkeypatch.setattr(codex_controls, "in_codex_sandbox", lambda: False)
    monkeypatch.setattr("shutil.which", lambda name: None)
    monkeypatch.setattr(setup, "_print_codex_controls", lambda: None)

    def no_repo(_):
        raise FileNotFoundError("none")

    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", no_repo)

    def refused(*a, **k):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", refused)
    monkeypatch.setattr("time.sleep", lambda s: None)
    monkeypatch.setattr(
        "vhir_cli.gateway.get_local_gateway_url", lambda: "http://192.0.2.1:4508"
    )
    monkeypatch.setattr("vhir_cli.gateway.get_local_ssl_context", lambda: None)


def _codex_box(monkeypatch):
    monkeypatch.setattr(codex_controls, "in_codex_sandbox", lambda: True)
    monkeypatch.setattr(setup, "_print_codex_controls", lambda: None)
    monkeypatch.setattr(setup, "_print_sift_tools_warning", lambda: None)


BRANCHES = {"codex-sandbox": _codex_box, "gateway-offline": _offline_box}


@pytest.mark.parametrize("branch", sorted(BRANCHES))
def test_setup_test_warns_in_every_branch(joined, conf, monkeypatch, capsys, branch):
    conf.write_text(SALT)
    BRANCHES[branch](monkeypatch)
    setup._run_connectivity_test(sift_tools=False)
    out = capsys.readouterr().out.replace(str(conf), "/etc/samba/smb.conf")
    assert f"\n  Samba: WARNING: {WARNING}\n" in out
    if branch == "gateway-offline":
        assert "Gateway: OFFLINE" in out
    else:
        assert "Codex's sandbox" in out


def test_setup_test_says_ok_when_the_include_is_there(
    joined, conf, monkeypatch, capsys
):
    conf.write_text(SALT + INCLUDE + "\n")
    _codex_box(monkeypatch)
    setup._run_connectivity_test(sift_tools=False)
    out = capsys.readouterr().out.replace(str(conf), "/etc/samba/smb.conf")
    assert f"\n  Samba: {OK}\n" in out
    assert "WARNING" not in out


def test_setup_test_says_it_couldnt_check(joined, conf, monkeypatch, capsys):
    conf.mkdir()  # read_text raises IsADirectoryError: an OSError, not missing
    _codex_box(monkeypatch)
    setup._run_connectivity_test(sift_tools=False)
    out = capsys.readouterr().out.replace(str(conf), "/etc/samba/smb.conf")
    assert "\n  Samba: couldn't check /etc/samba/smb.conf: Is a directory\n" in out
    assert "WARNING" not in out


@pytest.mark.parametrize("samba_yaml", [None, "wintools_ip: 192.0.2.7\n"])
def test_setup_test_on_a_box_not_joined_says_nothing_about_samba(
    tmp_path, conf, monkeypatch, capsys, samba_yaml
):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    if samba_yaml:  # samba.yaml with no share_name isn't a join
        (tmp_path / ".vhir" / "samba.yaml").write_text(samba_yaml)
    conf.write_text(SALT)
    _codex_box(monkeypatch)
    setup._run_connectivity_test(sift_tools=False)
    assert "Samba" not in capsys.readouterr().out


# --- CLI init, activate, reopen and close ---


@pytest.fixture
def cli(joined, conf, monkeypatch):
    """Commands recorded; the case's share already where activate puts it."""
    ran = []

    def run(cmd, **kw):
        ran.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(main, "_set_case_wintools_permissions", lambda p: None)
    monkeypatch.setattr(join, "notify_wintools_case_activated", lambda c: True)
    monkeypatch.setattr(join, "notify_wintools_case_deactivated", lambda: True)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setenv("VHIR_CASES_DIR", str(joined / "cases"))  # close, reopen
    conf.write_text(SALT)
    return types.SimpleNamespace(home=joined, ran=ran, conf=conf)


def _args(cli, **kw):
    return argparse.Namespace(cases_dir=str(cli.home / "cases"), **kw)


def _init(cli, case_id="CASE-C"):
    main._case_init(
        _args(cli, name="c", case_id=case_id, description=""), {"examiner": "tester"}
    )


def _err(capsys, cli):
    return capsys.readouterr().err.replace(str(cli.conf), "/etc/samba/smb.conf")


def test_init_warns_on_stderr(cli, capsys):
    _init(cli)
    assert f"WARNING: {WARNING}\n" in _err(capsys, cli)


def test_activating_the_case_already_active_warns_on_stderr(cli, capsys):
    """The usual case after a SIFT update: the share already points at the case,
    so the repoint is a no-op, and the warning still prints."""
    _init(cli)
    capsys.readouterr()
    cli.ran.clear()
    main._case_activate(_args(cli, case_id="CASE-C"), {"examiner": "tester"})
    assert f"WARNING: {WARNING}\n" in _err(capsys, cli)
    assert not [c for c in cli.ran if c[:2] == ["sudo", "tee"]]  # the no-op ran


def test_activate_with_the_include_there_says_nothing(cli, capsys):
    cli.conf.write_text(SALT + INCLUDE + "\n")
    _init(cli)
    main._case_activate(_args(cli, case_id="CASE-C"), {"examiner": "tester"})
    assert "Samba" not in _err(capsys, cli)


def test_close_says_nothing_and_reopen_warns(cli, monkeypatch, capsys):
    _init(cli)
    capsys.readouterr()
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    monkeypatch.setattr(case_copies, "write_case_copies", lambda c, d: {"copies": []})
    monkeypatch.setattr(case_copies, "summary_lines", lambda c, copied: [])
    main._case_close(_args(cli, case_id="CASE-C", summary=""), {"examiner": "tester"})
    closed = capsys.readouterr()
    assert "Samba" not in closed.out + closed.err
    assert (
        yaml.safe_load((cli.home / "cases" / "CASE-C" / "CASE.yaml").read_text())[
            "status"
        ]
        == "closed"
    )
    main._case_reopen(_args(cli, case_id="CASE-C"), {"examiner": "tester"})
    assert f"WARNING: {WARNING}\n" in _err(capsys, cli)


# --- join setup shares the predicate ---


@pytest.mark.parametrize("shape", ["hash-comment", "semicolon-comment", "glued"])
def test_join_setup_appends_the_include_when_only_a_lookalike_is_there(
    tmp_path, monkeypatch, shape
):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    ran = []

    def run(cmd, **kw):
        ran.append((cmd, kw.get("input")))
        if cmd == ["sudo", "cat", "/etc/samba/smb.conf"]:
            return subprocess.CompletedProcess(cmd, 0, SHAPES[shape][0], "")
        out = "" if kw.get("text") else b""
        return subprocess.CompletedProcess(cmd, 0, out, out)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(join, "_push_smb_credentials", lambda c: None)
    monkeypatch.setattr(join, "_get_sift_ip", lambda: None)
    monkeypatch.setattr(join, "private_primary_group", lambda user: "examiner")
    monkeypatch.setattr(
        join, "_ask", lambda prompt, no_terminal, assume=False: "10.0.0.20"
    )
    join._setup_samba_share("CODE-ONE")
    appended = [i for c, i in ran if c == ["sudo", "tee", "-a", "/etc/samba/smb.conf"]]
    assert appended == [f"\n{INCLUDE}\n".encode()]


def test_join_setup_leaves_an_include_on_its_own_line(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    ran = []

    def run(cmd, **kw):
        ran.append(cmd)
        if cmd == ["sudo", "cat", "/etc/samba/smb.conf"]:
            return subprocess.CompletedProcess(cmd, 0, SALT + "  " + INCLUDE + "\n", "")
        out = "" if kw.get("text") else b""
        return subprocess.CompletedProcess(cmd, 0, out, out)

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(join, "_push_smb_credentials", lambda c: None)
    monkeypatch.setattr(join, "_get_sift_ip", lambda: None)
    monkeypatch.setattr(join, "private_primary_group", lambda user: "examiner")
    monkeypatch.setattr(
        join, "_ask", lambda prompt, no_terminal, assume=False: "10.0.0.20"
    )
    join._setup_samba_share("CODE-ONE")
    assert not [
        c for c in ran if c[:2] == ["sudo", "tee"] and "/etc/samba/smb.conf" in c
    ]
