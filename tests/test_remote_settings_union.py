"""A remote client script's re-run keeps the user's own sandbox entries and
adds vhir's: every list is a union. Linux and macOS replaced the sandbox
block's lists with vhir's, dropping the user's; Windows added the block only
when there was none, so new entries never arrived. Each script's deny list
also carries the home and host rules in the folder-relative form a project
deployment uses (no Codex paths: Codex isn't set up remotely). Only the
scripts' own blocks run, in a scratch HOME; values are synthetic."""

from __future__ import annotations

import json
import shutil

import pytest

from .test_client_scripts_no_loss import (
    LINUX,
    MAC,
    PWSH,
    SH_TOOLS,
    WIN,
    _bash,
    _bin,
    _pwsh,
    _settings_block,
)

USER = {
    "sandbox": {
        "enabled": True,
        "filesystem": {"denyWrite": ["/home/me/keep"], "denyRead": ["/home/me/secret"]},
    }
}
NEW_RULES = [
    "Edit(**/.claude/skills/**)",
    "Edit(**/.claude/agents/**)",
    "Edit(**/host-observations.jsonl)",
    "Edit(**/host-decisions.jsonl)",
    "Edit(**/host-ops.json)",
    "Edit(**/host-dictionary.yaml)",
    "Edit(**/.vhir/case-paths.json)",
]


def _deny(text):
    if '"deny": [' in text:
        i = text.index('"deny": [')
        return text[i : text.index("]", i)]
    i = text.index("deny = @(")
    return text[i : text.index("\n        )", i)]


@pytest.mark.parametrize("script", [LINUX, MAC, WIN], ids=["linux", "macos", "windows"])
def test_each_script_carries_the_home_and_host_rules_without_codex(script):
    deny = _deny(script)
    assert all(f'"{r}"' in deny for r in NEW_RULES)
    assert ".codex" not in deny and ".agents" not in deny


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 not installed")
@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
def test_a_rerun_keeps_the_users_sandbox_lists(tmp_path, script):
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps(USER))
    incoming = {
        "sandbox": {
            "enabled": True,
            "filesystem": {"denyWrite": ["~/.vhir/gateway.yaml"]},
        }
    }
    rc, out = _bash(
        script, _settings_block(script), tmp_path, _bin(tmp_path, SH_TOOLS + ["python3"]),
        SETTINGS_FILE=str(settings), SETTINGS_CONTENT=json.dumps(incoming),
    )  # fmt: skip
    assert rc == 0, out
    fs = json.loads(settings.read_text())["sandbox"]["filesystem"]
    assert fs["denyWrite"] == ["/home/me/keep", "~/.vhir/gateway.yaml"]
    assert fs["denyRead"] == ["/home/me/secret"]


def _win_settings_block():
    start = WIN.index("$settingsObj = @{")
    end = WIN.index("# ---- Fetch assets from GitHub ----", start)
    merge = WIN[
        WIN.index("function Merge-Union") : WIN.index("# A user's file is backed up")
    ]
    return merge + WIN[start:end]


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_a_windows_rerun_keeps_the_users_sandbox_lists_and_adds_vhirs(tmp_path):
    claude = tmp_path / "proj" / ".claude"
    claude.mkdir(parents=True)
    settings = claude / "settings.json"
    settings.write_text(json.dumps(USER))
    body = (
        f"$deployDir = '{tmp_path / 'proj'}'\n$claudeDir = '{claude}'\n"
        f"$settingsPath = '{settings}'\n$hookPath = '{claude / 'hooks' / 'forensic-audit.sh'}'\n"
        + _win_settings_block()
    )
    rc, out = _pwsh(tmp_path, body, tmp_path / "appdata")
    assert rc == 0, out
    data = json.loads(settings.read_text())
    fs = data["sandbox"]["filesystem"]
    assert (
        fs["denyWrite"][0] == "/home/me/keep"
        and "~/.vhir/gateway.yaml" in fs["denyWrite"]
    )
    assert fs["denyRead"] == ["/home/me/secret"]
    assert set(NEW_RULES) <= set(data["permissions"]["deny"])
