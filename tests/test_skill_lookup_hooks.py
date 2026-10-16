"""Wherever vhir writes forensic-audit.sh's hook entries, a "Skill"
PostToolUse entry runs it too, so Claude Code logs each skill load to the
lookups log: SIFT's settings merge, and each remote
script's settings, fresh or merged into an existing file. The merges key a
hook by matcher and command: the Skill entry runs the same script as the
Bash one, and keying by command alone never added it to an existing file.
Only the scripts' own blocks run, in a scratch HOME; values are synthetic."""

from __future__ import annotations

import json
import shutil

import pytest

from vhir_cli.commands import client_setup as cs

from .test_client_scripts_no_loss import (
    LINUX,
    MAC,
    PWSH,
    SH_TOOLS,
    _bash,
    _bin,
    _pwsh,
    _settings_block,
)
from .test_remote_settings_union import _win_settings_block

HOOK = "forensic-audit.sh"


def _post(settings: dict) -> list[tuple[str, str]]:
    return [
        (e.get("matcher", ""), h["command"].rsplit("/", 1)[-1])
        for e in settings["hooks"]["PostToolUse"]
        for h in e["hooks"]
    ]


def _heredoc(script: str, deploy: str) -> dict:
    start = script.index("SETTINGS_CONTENT=$(cat << SETTINGS\n") + len(
        "SETTINGS_CONTENT=$(cat << SETTINGS\n"
    )
    end = script.index("\nSETTINGS\n)", start)
    return json.loads(script[start:end].replace("$DEPLOY_DIR", deploy))


@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
def test_a_fresh_remote_settings_runs_the_hook_for_bash_and_skill(script):
    assert _post(_heredoc(script, "/proj")) == [("Bash", HOOK), ("Skill", HOOK)]


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 not installed")
@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
def test_a_rerun_adds_the_skill_entry_to_an_existing_file_once(tmp_path, script):
    settings = tmp_path / "settings.json"
    bash_only = {"hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": f"/proj/.claude/hooks/{HOOK}"}]},
    ]}}  # fmt: skip
    settings.write_text(json.dumps(bash_only))
    incoming = json.dumps(_heredoc(script, "/proj"))
    for _ in range(2):  # a second run adds nothing
        rc, out = _bash(
            script, _settings_block(script), tmp_path, _bin(tmp_path, SH_TOOLS + ["python3"]),
            SETTINGS_FILE=str(settings), SETTINGS_CONTENT=incoming,
        )  # fmt: skip
        assert rc == 0, out
        assert _post(json.loads(settings.read_text())) == [
            ("Bash", HOOK),
            ("Skill", HOOK),
        ]


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_adds_the_skill_entry_fresh_and_to_an_existing_file_once(tmp_path):
    claude = tmp_path / "proj" / ".claude"
    claude.mkdir(parents=True)
    settings = claude / "settings.json"
    hook = (claude / "hooks" / HOOK).as_posix()
    body = (
        f"$deployDir = '{tmp_path / 'proj'}'\n$claudeDir = '{claude}'\n"
        f"$settingsPath = '{settings}'\n$hookPath = '{claude / 'hooks' / HOOK}'\n"
        + _win_settings_block()
    )
    rc, out = _pwsh(tmp_path, body, tmp_path / "appdata")  # fresh
    assert rc == 0, out
    assert _post(json.loads(settings.read_text())) == [("Bash", HOOK), ("Skill", HOOK)]

    bash_only = {"hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": hook}]},
    ]}}  # fmt: skip
    settings.write_text(json.dumps(bash_only))
    for _ in range(2):  # merged into an existing file, then a re-run
        rc, out = _pwsh(tmp_path, body, tmp_path / "appdata")
        assert rc == 0, out
        assert _post(json.loads(settings.read_text())) == [
            ("Bash", HOOK),
            ("Skill", HOOK),
        ]


def test_sift_s_settings_merge_adds_the_skill_entry_to_an_existing_file(tmp_path):
    """SIFT merges sift-mcp's full/settings.json, which now carries the Skill
    entry, into ~/.claude/settings.json: a (matcher, script) pair it lacks is
    appended, so no code change is needed there."""
    hooks = tmp_path / "hooks"
    target = tmp_path / "settings.json"
    target.write_text(json.dumps({"hooks": {"PostToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": f"{hooks}/{HOOK}"}]},
    ]}}))  # fmt: skip
    source = tmp_path / "full-settings.json"
    source.write_text(json.dumps({"hooks": {"PostToolUse": [
        {"matcher": m, "hooks": [{"type": "command", "command": f"$CLAUDE_PROJECT_DIR/.claude/hooks/{HOOK}"}]}
        for m in ("Bash", "Skill")
    ]}}))  # fmt: skip
    merged = cs._merged_settings(target, source, hooks)
    assert _post(merged) == [("Bash", HOOK), ("Skill", HOOK)]
