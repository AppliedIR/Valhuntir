"""Codex's managed layer: installed with consent (sudo), the exact commands
printed without it, an administrator's own requirements file never changed,
our file recognised by its marker and updated when the product changes, and
its state read back (on / an admin's file / off after the opt-out / absent).
A restricted-userns kernel gets a notice. /etc/codex and /proc are stand-in
folders and `sudo install` a recording stand-in; nothing is installed."""

from __future__ import annotations

import shutil
import types

import pytest

from vhir_cli.commands import client_setup as cs
from vhir_cli.commands import codex_controls as cc

TEMPLATE = (
    "# managed-by: valhuntir\n"
    'allowed_sandbox_modes = ["read-only", "workspace-write"]\n'
    "[permissions.filesystem]\n"
    'deny_read = ["/var/lib/vhir", "{home}/.vhir/gateway.yaml"]\n'
    "[[hooks.PreToolUse]]\n"
    'matcher = "^Bash$"\n'
    "[[hooks.PreToolUse.hooks]]\n"
    'type = "command"\n'
    'command = "{hooks}/case-data-guard.sh --client codex"\n'
)


@pytest.fixture
def box(tmp_path, monkeypatch):
    assets = tmp_path / "sift-mcp" / "claude-code"
    for _, rel in cc.HOOKS:
        (assets / rel).parent.mkdir(parents=True, exist_ok=True)
        (assets / rel).write_text(f"#!/bin/bash\n# {rel}\n")
    (tmp_path / "sift-mcp" / "codex").mkdir()
    (tmp_path / "sift-mcp" / "codex" / "requirements.toml").write_text(TEMPLATE)
    monkeypatch.setattr(cs, "_find_claude_code_assets", lambda: assets)
    etc = tmp_path / "etc-codex"
    monkeypatch.setattr(cc, "REQUIREMENTS", etc / "requirements.toml")
    monkeypatch.setattr(cc, "HOOKS_DIR", etc / "vhir-hooks")
    monkeypatch.setattr(cc, "USERNS", tmp_path / "userns")
    home = tmp_path / "home"
    monkeypatch.setattr(cc.Path, "home", staticmethod(lambda: home))
    ran = []

    def fake_run(cmd, timeout=None):
        ran.append(cmd)
        if "-d" in cmd:
            (etc / "vhir-hooks").mkdir(parents=True, exist_ok=True)
        else:
            shutil.copy(cmd[-2], cmd[-1])
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(cc.subprocess, "run", fake_run)
    tty = {"on": False, "answer": "n"}
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: tty["on"]))
    monkeypatch.setattr("builtins.input", lambda p="": tty["answer"])
    return types.SimpleNamespace(etc=etc, home=home, ran=ran, tty=tty, assets=assets)


def test_with_consent_it_installs_root_owned_copies(box):
    assert cc.deploy_codex_controls(consent=True) == "installed"
    req = cc.REQUIREMENTS.read_text()
    assert cc.ours(req) and f"{box.home}/.vhir/gateway.yaml" in req
    assert f"{cc.HOOKS_DIR}/case-data-guard.sh --client codex" in req
    assert sorted(p.name for p in cc.HOOKS_DIR.iterdir()) == sorted(
        n for n, _ in cc.HOOKS
    )
    assert all(c[:2] == ["sudo", "install"] for c in box.ran)
    assert all(
        c[c.index("-o") : c.index("-o") + 4] == ["-o", "root", "-g", "root"]
        for c in box.ran
    )
    assert cc.codex_controls_state(["codex"]) == "on"


def test_without_a_terminal_the_commands_are_printed_and_nothing_runs(box, capsys):
    assert cc.deploy_codex_controls() == "printed"
    out = capsys.readouterr().out
    assert box.ran == [] and not cc.REQUIREMENTS.exists()
    assert f"sudo install -d -m 0755 -o root -g root {cc.HOOKS_DIR}" in out
    assert f"sudo tee {cc.REQUIREMENTS}" in out and "# managed-by: valhuntir" in out


def test_declined_on_a_terminal_nothing_runs(box):
    box.tty.update(on=True, answer="n")
    assert cc.deploy_codex_controls() == "printed" and box.ran == []


def test_accepted_on_a_terminal_it_installs(box, capsys):
    box.tty.update(on=True, answer="y")
    assert cc.deploy_codex_controls() == "installed"
    assert "applies to every Codex session on this machine" in capsys.readouterr().out


def test_an_administrators_own_file_is_never_changed(box, capsys):
    box.etc.mkdir()
    cc.REQUIREMENTS.write_text('allowed_sandbox_modes = ["danger-full-access"]\n')
    before = cc.REQUIREMENTS.read_bytes()
    assert cc.deploy_codex_controls(consent=True) == "admin-file"
    out = capsys.readouterr().out
    assert cc.REQUIREMENTS.read_bytes() == before and box.ran == []
    assert "Codex controls NOT in effect" in out and "# managed-by: valhuntir" in out
    assert cc.codex_controls_state(["codex"]) == "admin-file"


def test_ours_unchanged_is_left_and_a_product_change_updates_it(box):
    cc.deploy_codex_controls(consent=True)
    box.ran.clear()
    assert cc.deploy_codex_controls(consent=True) == "unchanged" and box.ran == []
    (box.assets / "shared/hooks/forensic-audit.sh").write_text("#!/bin/bash\n# v2\n")
    assert cc.deploy_codex_controls(consent=True) == "updated"
    assert (cc.HOOKS_DIR / "forensic-audit.sh").read_text().endswith("# v2\n")


def test_the_opt_out_reads_as_codex_controls_off(box):
    assert cc.codex_controls_state(["claude-code"]) == "absent"
    cc.deploy_codex_controls(consent=True)
    cc.REQUIREMENTS.rename(
        cc.REQUIREMENTS.with_name("requirements.toml.off")
    )  # the documented move
    assert cc.codex_controls_state(["claude-code", "codex"]) == "off"


def test_a_restricted_userns_kernel_gets_the_notice(box, capsys):
    cc.USERNS.write_text("1\n")
    cc.deploy_codex_controls(consent=False)
    assert (
        "Codex's sandbox can't start and its shell commands will fail"
        in capsys.readouterr().out
    )
    cc.USERNS.write_text("0\n")
    cc.deploy_codex_controls(consent=False)
    assert "can't start" not in capsys.readouterr().out
