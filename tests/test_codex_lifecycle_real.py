"""The client lifecycle on a box set up for Codex, with the real functions:
`vhir update` with a Claude Desktop manifest, `vhir update` for Codex,
`--add-remnux` reaching Codex's profile, and uninstall removing Codex's
files and the managed requirements. The box is test_codex_setup's (a SIFT
box under tmp_path; /etc/codex a stand-in folder, sudo a recording stand-in).
"""

from __future__ import annotations

import json

from vhir_cli.commands import client_setup as cs
from vhir_cli.commands import codex_controls as cc
from vhir_cli.commands import update

from .test_codex_setup import BACKENDS, _args, _profile, _setup, box  # noqa: F401


def test_update_with_a_claude_desktop_manifest_says_so_and_deploys_nothing(box, capsys):  # noqa: F811
    box.manifest.write_text(
        json.dumps({"version": "0.6.3", "client": "claude-desktop"})
    )
    assert update._redeploy_clients(json.loads(box.manifest.read_text())) == [
        "claude-desktop"
    ]
    out = capsys.readouterr().out
    assert cs.DESKTOP_DROPPED in out
    assert not box.profile.exists() and box.sudo == []


def test_update_for_codex_rebuilds_its_profile_and_keeps_its_controls(box, capsys):  # noqa: F811
    _setup()  # -y: the profile, the skills and the managed requirements
    installed = cc.REQUIREMENTS.read_text()
    BACKENDS.append("report-mcp")
    try:
        capsys.readouterr()
        update._redeploy_clients(json.loads(box.manifest.read_text()))
    finally:
        BACKENDS.remove("report-mcp")
    out = capsys.readouterr().out
    assert "report-mcp" in _profile(box)["mcp_servers"]  # found again on the gateway
    assert cc.REQUIREMENTS.read_text() == installed  # unchanged, not reinstalled
    assert "Managed requirements: Codex's shell" in out


def test_add_remnux_reaches_codexs_profile(box, monkeypatch):  # noqa: F811
    _setup()
    monkeypatch.setattr(cs, "_test_remnux_connection", lambda *a: None)
    cs._cmd_add_remnux(_args(add_remnux="10.0.0.30:3000", remnux_token="tok"))
    entry = _profile(box)["mcp_servers"]["remnux-mcp"]
    assert entry["url"].startswith("http://10.0.0.30:3000")
    assert "remnux-mcp" in json.dumps(_profile(box))


def test_uninstall_removes_codexs_files_and_its_managed_requirements(
    box,  # noqa: F811
    monkeypatch,
    capsys,
):
    _setup()
    assert box.profile.exists() and cc.REQUIREMENTS.exists()
    skills = box.home / ".agents" / "skills" / "vhir-welcome"
    assert skills.is_dir()
    asked = []
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda q: asked.append(q) or True)
    cc.uninstall_codex_step(cs._prompt_yn_strict)
    # the Codex files with their list, then the managed requirements: once each
    assert asked == ["  Remove them?", "      Remove?"]
    assert "[Codex] Managed requirements" in capsys.readouterr().out
    assert not box.profile.exists() and not skills.exists()
    assert not cc.REQUIREMENTS.exists() and not cc.HOOKS_DIR.exists()
    assert ["sudo", "rm", "-f", str(cc.REQUIREMENTS)] in box.sudo


def test_add_remnux_with_the_gateway_down_says_it_wasnt_added(box, monkeypatch, capsys):  # noqa: F811
    _setup()
    box.gateway["up"] = False  # the profile is kept as it is
    monkeypatch.setattr(cs, "_test_remnux_connection", lambda *a: None)
    capsys.readouterr()
    cs._cmd_add_remnux(_args(add_remnux="10.0.0.30:3000", remnux_token="tok"))
    out = capsys.readouterr().out
    assert "remnux-mcp was NOT added to Codex's profile (kept)" in out
    assert "Added remnux-mcp" not in out and "Restart Codex" not in out
    assert "remnux-mcp" not in _profile(box)["mcp_servers"]
