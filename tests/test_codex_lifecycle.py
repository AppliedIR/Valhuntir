"""`vhir update` redeploys each client the box was set up for: Claude Code's
controls, and Codex's profile, skills and managed requirements; an older
manifest's single client still works, and a Claude Desktop one gets the
migration message and nothing redeployed. Uninstall removes Codex's files
and, after one question, the managed requirements (never an
administrator's own file). The client setup calls are recording stand-ins."""

from __future__ import annotations

import types

import pytest

from vhir_cli.commands import client_setup as cs
from vhir_cli.commands import codex_controls as cc
from vhir_cli.commands import update

from .test_codex_controls import box  # noqa: F401 (a fixture)

DEPLOY = cc.deploy_codex_controls  # the real one: the `calls` fixture replaces it


@pytest.fixture
def calls(monkeypatch):
    got = []
    monkeypatch.setattr(
        cs, "_deploy_claude_code_assets", lambda *a, **k: got.append("claude-code")
    )
    monkeypatch.setattr(
        cs,
        "deploy_codex_assets",
        lambda *a, **k: got.append("codex-assets"),
        raising=False,
    )
    monkeypatch.setattr(
        cc, "deploy_codex_controls", lambda *a, **k: got.append("codex-controls")
    )
    monkeypatch.setattr(
        cs, "DESKTOP_DROPPED", "Claude Desktop is no longer supported.", raising=False
    )
    monkeypatch.setattr(
        cs, "_uninstall_codex", lambda: got.append("codex-uninstall"), raising=False
    )
    return got


def test_update_redeploys_every_client_set_up(box, calls):  # noqa: F811
    box.etc.mkdir()
    cc.REQUIREMENTS.write_text(cc.MARKER + "\n")  # ours, as installed
    assert update._redeploy_clients({"clients": ["claude-code", "codex"]}) == [
        "claude-code",
        "codex",
    ]
    assert calls == ["claude-code", "codex-assets", "codex-controls"]


def test_update_prints_each_clients_controls_block(box, calls, capsys):  # noqa: F811
    DEPLOY(consent=True)  # our file and hooks, as written
    update._redeploy_clients({"clients": ["claude-code", "codex", "open-webui"]})
    out = capsys.readouterr().out
    assert out.count("Controls (as deployed now):") == 3
    assert "Managed requirements: Codex's shell" in out  # Codex's, fully applied
    assert "MCP-only: the server-side controls only" in out


def test_after_the_opt_out_update_says_so_and_offers_nothing(box, calls, capsys):  # noqa: F811
    update._redeploy_clients({"clients": ["codex"]})  # no requirements file: moved away
    out = capsys.readouterr().out
    assert "codex-controls" not in calls and box.ran == []
    assert "CODEX CONTROLS OFF" in out and "vhir setup client --client=codex" in out
    assert (
        f"NOT in effect: CODEX CONTROLS OFF: {cc.REQUIREMENTS} isn't installed" in out
    )


def test_an_older_manifest_with_one_client_still_redeploys_it(calls):
    update._redeploy_clients({"client": "claude-code"})
    assert calls == ["claude-code"]


def test_a_claude_desktop_manifest_gets_the_message_and_nothing_else(calls, capsys):
    update._redeploy_clients({"client": "claude-desktop"})
    assert (
        calls == []
        and "Claude Desktop is no longer supported." in capsys.readouterr().out
    )


def test_uninstall_removes_codex_and_its_managed_requirements(box, calls, monkeypatch):  # noqa: F811
    import json

    box.etc.mkdir()
    cc.REQUIREMENTS.write_text(cc.MARKER + "\n")  # ours, as installed
    (box.home / ".vhir").mkdir(parents=True)
    (box.home / ".vhir" / "manifest.json").write_text(
        json.dumps({"clients": ["codex"]})
    )
    removed = []
    monkeypatch.setattr(
        cc.subprocess,
        "run",
        lambda cmd, timeout=None: (
            removed.append(cmd),
            types.SimpleNamespace(returncode=0),
        )[1],
    )
    cc.uninstall_codex_step(lambda q: True)
    assert "codex-uninstall" in calls
    assert ["sudo", "rm", "-f", str(cc.REQUIREMENTS)] in removed
    assert ["sudo", "rm", "-rf", str(cc.HOOKS_DIR)] in removed


def test_uninstall_declined_keeps_the_managed_requirements(box, calls):  # noqa: F811
    import json

    (box.home / ".vhir").mkdir(parents=True)
    (box.home / ".vhir" / "manifest.json").write_text(
        json.dumps({"clients": ["codex"]})
    )
    box.etc.mkdir()
    cc.REQUIREMENTS.write_text(cc.MARKER + "\n")  # ours, as installed
    asked = []
    cc.uninstall_codex_step(lambda q: asked.append(q) or False)
    assert len(asked) == 1  # the requirements' one question (the files ask their own)
    assert cc.REQUIREMENTS.exists()


def test_an_administrators_requirements_file_is_never_removed(box):  # noqa: F811
    box.etc.mkdir()
    cc.REQUIREMENTS.write_text("allowed_sandbox_modes = []\n")
    assert cc.remove_codex_controls(consent=True) == "admin-file"
    assert cc.REQUIREMENTS.exists()


def test_add_remnux_reaches_codexs_profile(box, monkeypatch, capsys):  # noqa: F811
    import argparse
    import json

    (box.home / ".vhir").mkdir(parents=True)
    (box.home / ".vhir" / "manifest.json").write_text(
        json.dumps({"clients": ["codex"]})
    )
    monkeypatch.setenv("HOME", str(box.home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: box.home))
    got = []
    monkeypatch.setattr(
        cs,
        "deploy_codex_assets",
        lambda **k: (got.append(k), "updated")[1],
        raising=False,
    )
    monkeypatch.setattr(cs, "_test_remnux_connection", lambda *a: None)
    args = argparse.Namespace(
        add_remnux="10.0.0.30:3000", remnux=None, remnux_token="tok", yes=True
    )
    cs._cmd_add_remnux(args)
    (call,) = got
    entry = call["extra"]["remnux-mcp"]
    assert (
        entry["url"].startswith("http")
        and "3000" in entry["url"]
        and "type" not in entry
    )
    assert entry["headers"] == {"Authorization": "Bearer tok"}
    assert "Restart Codex" in capsys.readouterr().out


def test_update_shows_a_declined_change_as_the_file_holds_it(
    box,  # noqa: F811
    calls,
    monkeypatch,
    capsys,
):
    box.home.mkdir(parents=True, exist_ok=True)
    mine = box.home / "settings.json"
    mine.write_text('{"sandbox": {"enabled": true, "failIfUnavailable": true}}')
    monkeypatch.setattr(
        cs, "_deploy_claude_code_assets", lambda *a, **k: (mine, "kept")
    )
    update._redeploy_clients({"clients": ["claude-code"]})
    out = capsys.readouterr().out
    assert f"Forensic controls NOT applied to {mine}" in out
    assert f"NOT in effect: Valhuntir's controls aren't fully applied in {mine}" in out
    rows = ("Deny rules", "Sandbox", "Audit", "Case-data guard", "Start-up check")
    assert not [r for r in rows if f"    {r}:" in out]
