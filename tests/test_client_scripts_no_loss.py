"""The remote client scripts never silently replace a user's file.

Claude Desktop's config was written over whole: a user's other servers and
preferences were lost, with no backup. The workspace .mcp.json and settings.json
were replaced without a backup when python3 was missing, when the existing file
couldn't be parsed, or by the Windows merge's catch. Now the Desktop config is
merged (vhir's entries replace same-named ones), an unparseable one is left with
the entries to add by hand, and every write that changes a user's file is
preceded by a backup that keeps its mode, with the command that restores it.

Only blocks of the scripts run, in a scratch HOME/APPDATA. prompt_yn_strict is a
stub; PATH holds only what each block needs.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MAC = (REPO / "setup-client-macos.sh").read_text()
LINUX = (REPO / "setup-client-linux.sh").read_text()
WIN = (REPO / "setup-client-windows.ps1").read_text()

GENERATED = {
    "mcpServers": {
        "forensic-mcp": {
            "command": "npx",
            "args": ["mcp-remote", "https://g/mcp/forensic-mcp"],
        },
        "zeltser-ir-writing": {
            "command": "npx",
            "args": ["mcp-remote", "https://z/mcp"],
        },
        "microsoft-learn": {"command": "npx", "args": ["mcp-remote", "https://m/mcp"]},
    }
}
DEEP = {"a": {"b": {"c": {"d": {"e": {"f": {"g": "deep"}}}}}}}
USER = {
    "globalShortcut": "Ctrl+Space",
    "preferences": DEEP,
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "server-filesystem", "/Users/u"],
        },
        "forensic-mcp": {"command": "npx", "args": ["mcp-remote", "https://old/mcp/x"]},
    },
}
TRUNCATED = '{"mcpServers": {"x": '


def _between(text, start, end):
    i = text.index(start)
    return text[i : text.index(end, i)]


def _helpers(text):
    """The script's own backup_file and replace_file."""
    if "replace_file() {" not in text:
        return ""  # an older script: its blocks don't call them
    start = text.index("# A user's file is backed up")
    return text[start : text.index("\n}\n", text.index("replace_file() {")) + 3]


def _bin(tmp_path, tools):
    """A PATH holding only these tools (no python3 unless asked)."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    for t in tools:
        if not (d / t).exists():
            (d / t).symlink_to(shutil.which(t))
    return str(d)


SH_TOOLS = ["cat", "cp", "cmp", "date", "rm", "mkdir"]
PROLOGUE = (
    "set -euo pipefail\nRED=; GREEN=; YELLOW=; BLUE=; BOLD=; NC=\n"
    'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }\n'
    "prompt_yn_strict() { return 0; }\n"
)


def _bash(script_text, block, home, path, **env):
    """Run the block from a file (its text can name /var/lib/vhir, which the
    suite's guard refuses in an argv)."""
    run = Path(home) / f"block-{len(list(Path(home).glob('block-*')))}.sh"
    run.write_text(PROLOGUE + _helpers(script_text) + block)
    p = subprocess.run(
        ["/bin/bash", str(run)],
        env={"HOME": str(home), "PATH": path, **env},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, p.stdout + p.stderr


def _undo(out):
    return [
        ln.strip()[len("To undo: ") :] for ln in out.splitlines() if "To undo: " in ln
    ]


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


# --- Claude Desktop config (macOS: node; Windows: pwsh) -----------------------

MAC_DESKTOP = _between(
    MAC,
    '            CONFIG_DIR="$HOME/Library/Application Support/Claude"',
    "\n        fi\n        ;;",
)


def _mac_desktop(tmp_path, content, tools=("node",)):
    home = tmp_path / "home"
    cfg = (
        home
        / "Library"
        / "Application Support"
        / "Claude"
        / "claude_desktop_config.json"
    )
    cfg.parent.mkdir(parents=True)
    if content is not None:
        cfg.write_text(content)
        cfg.chmod(0o600)
    path = _bin(tmp_path, SH_TOOLS + list(tools))
    rc, out = _bash(
        MAC, MAC_DESKTOP, home, path, MCP_JSON_STDIO=json.dumps(GENERATED, indent=2)
    )
    return rc, out, cfg


def _check_merged(cfg, before, out):
    data = json.loads(cfg.read_text())
    assert {k: v for k, v in data.items() if k != "mcpServers"} == {
        k: v for k, v in USER.items() if k != "mcpServers"
    }  # by value, 7 deep
    assert data["mcpServers"]["filesystem"] == USER["mcpServers"]["filesystem"]
    assert data["mcpServers"]["forensic-mcp"] == GENERATED["mcpServers"]["forensic-mcp"]
    (bak,) = [p for p in cfg.parent.iterdir() if ".vhir-backup-" in p.name]
    assert bak.read_bytes() == before
    return bak


@pytest.mark.parametrize("python3", [True, False], ids=["python3", "no python3"])
def test_mac_desktop_config_is_merged_backed_up_and_restorable(tmp_path, python3):
    tools = ("node", "python3") if python3 else ("node",)
    rc, out, cfg = _mac_desktop(tmp_path, json.dumps(USER, indent=2), tools)
    before = json.dumps(USER, indent=2).encode()
    assert rc == 0, out
    bak = _check_merged(cfg, before, out)
    assert _mode(bak) == 0o600 and _mode(cfg) == 0o600
    (line,) = _undo(out)
    subprocess.run(["/bin/bash", "-c", line], check=True)  # the path has a space
    assert cfg.read_bytes() == before


def test_mac_unparseable_desktop_config_is_left_with_the_entries_to_add(tmp_path):
    rc, out, cfg = _mac_desktop(tmp_path, TRUNCATED)
    assert rc == 0 and cfg.read_text() == TRUNCATED
    assert "isn't valid JSON: NOT changed" in out and '"forensic-mcp"' in out
    assert sorted(p.name for p in cfg.parent.iterdir()) == [cfg.name]


@pytest.mark.parametrize("content", [None, ""], ids=["absent", "empty"])
def test_anchor_absent_or_empty_desktop_config_is_written(tmp_path, content):
    rc, out, cfg = _mac_desktop(tmp_path, content)
    assert rc == 0 and "Written:" in out
    assert json.loads(cfg.read_text()) == GENERATED
    if content is None:
        assert _mode(cfg) == 0o600


PWSH = shutil.which("pwsh")
WIN_DESKTOP = _between(
    WIN,
    '            $claudeDir2 = Join-Path $env:APPDATA "Claude"',
    '\n        }\n    }\n    "librechat"',
)


def _win_helpers():
    if "function Set-UserFile" not in WIN:  # an older script
        return "\n".join(
            ln for ln in WIN.splitlines() if ln.startswith("function Write-")
        )
    start = WIN.index("# A user's file is backed up")
    end = WIN.index("\n}\n", WIN.index("function Set-UserFile")) + 3
    writes = "\n".join(
        ln for ln in WIN.splitlines() if ln.startswith("function Write-")
    )
    return writes + "\n" + WIN[start:end]


def _pwsh(tmp_path, body, appdata):
    script = tmp_path / "run.ps1"
    script.write_text(_win_helpers() + "\n" + body)
    p = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        env={
            "HOME": str(tmp_path),
            "PATH": os.environ["PATH"],
            "APPDATA": str(appdata),
        },
        capture_output=True,
        text=True,
        timeout=120,
    )
    return p.returncode, p.stdout + p.stderr


def _win_desktop(tmp_path, content):
    appdata = tmp_path / "App Data"  # a space
    cfg = appdata / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    if content is not None:
        cfg.write_text(content)
    servers = json.dumps(GENERATED["mcpServers"])
    body = (
        f"$mcpServersStdio = @{{}}\n"
        f"($('{servers}') | ConvertFrom-Json -AsHashtable).GetEnumerator() |"
        " ForEach-Object { $mcpServersStdio[$_.Key] = $_.Value }\n"
        "$mcpConfigStdio = @{ mcpServers = $mcpServersStdio }\n" + WIN_DESKTOP
    )
    rc, out = _pwsh(tmp_path, body, appdata)
    return rc, out, cfg


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_win_desktop_config_is_merged_backed_up_and_restorable(tmp_path):
    before = json.dumps(USER, indent=2)
    rc, out, cfg = _win_desktop(tmp_path, before)
    assert rc == 0, out
    _check_merged(cfg, before.encode(), out)
    (line,) = _undo(out)
    subprocess.run([PWSH, "-NoProfile", "-Command", line], check=True)
    assert cfg.read_bytes() == before.encode()


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_win_unparseable_desktop_config_is_left(tmp_path):
    rc, out, cfg = _win_desktop(tmp_path, TRUNCATED)
    assert rc == 0 and cfg.read_text() == TRUNCATED, out
    assert "isn't valid JSON: NOT changed" in out and "forensic-mcp" in out
    assert sorted(p.name for p in cfg.parent.iterdir()) == [cfg.name]


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_win_a_failed_backup_leaves_the_file(tmp_path):
    """A copy that fails (non-terminating, as Copy-Item's errors are) stops the
    write: no "Backed up", no undo line, the original byte-unchanged."""
    before = json.dumps(USER, indent=2)
    appdata = tmp_path / "App Data"
    cfg = appdata / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(before)
    servers = json.dumps(GENERATED["mcpServers"])
    body = (
        "function Copy-Item { [CmdletBinding()] param($LiteralPath, $Destination)"
        ' Write-Error "disk full" }\n'
        f"$mcpServersStdio = @{{}}\n"
        f"($('{servers}') | ConvertFrom-Json -AsHashtable).GetEnumerator() |"
        " ForEach-Object { $mcpServersStdio[$_.Key] = $_.Value }\n"
        "$mcpConfigStdio = @{ mcpServers = $mcpServersStdio }\n" + WIN_DESKTOP
    )
    rc, out = _pwsh(tmp_path, body, appdata)
    assert cfg.read_text() == before, out
    assert "disk full" in out and "NOT changed" in out
    assert "Backed up" not in out and "To undo" not in out and "Merged" not in out
    assert sorted(p.name for p in cfg.parent.iterdir()) == [cfg.name]


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_win_a_failed_staging_write_leaves_the_file(tmp_path):
    """A staging write that fails (non-terminating) with an older staging file
    in place: nothing installed, the file byte-unchanged, the old one gone."""
    before = json.dumps(USER, indent=2)
    appdata = tmp_path / "App Data"
    cfg = appdata / "Claude" / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(before)
    (cfg.parent / (cfg.name + ".vhir-new")).write_text('{"STALE": true}')
    servers = json.dumps(GENERATED["mcpServers"])
    body = (
        "function Set-Content { [CmdletBinding()] param("
        "[Parameter(ValueFromPipeline)]$Value, $LiteralPath, $Encoding)"
        ' Write-Error "disk full" }\n'
        f"$mcpServersStdio = @{{}}\n"
        f"($('{servers}') | ConvertFrom-Json -AsHashtable).GetEnumerator() |"
        " ForEach-Object { $mcpServersStdio[$_.Key] = $_.Value }\n"
        "$mcpConfigStdio = @{ mcpServers = $mcpServersStdio }\n" + WIN_DESKTOP
    )
    rc, out = _pwsh(tmp_path, body, appdata)
    assert cfg.read_text() == before, out
    assert "disk full" in out and "NOT changed" in out
    assert "Backed up" not in out and "Merged" not in out
    assert sorted(p.name for p in cfg.parent.iterdir()) == [cfg.name]
    rc, out = _pwsh(
        tmp_path,
        "function Set-Content { [CmdletBinding()] param("
        "[Parameter(ValueFromPipeline)]$Value, $LiteralPath, $Encoding)"
        ' Write-Error "disk full" }\n'
        f"Write-Output \"returned=$(Set-UserFile '{cfg}' 'x')\"",
        appdata,
    )
    assert "returned=False" in out and cfg.read_text() == before, out


# --- The workspace .mcp.json and settings.json --------------------------------


def _settings_block(text):
    start = text.index('if [[ -f "$SETTINGS_FILE" ]] && command -v python3')
    end = text.index('ok "settings.json (hooks + permissions + sandbox)"', start)
    return text[text.rindex("\n", 0, start) + 1 : text.index("fi\n", end) + 3]


INCOMING = {
    "hooks": {},
    "permissions": {"deny": ["Bash(x)"]},
    "sandbox": {"enabled": True},
}


def _restored(out, path, before):
    (line,) = _undo(out)
    subprocess.run(["/bin/bash", "-c", line], check=True)
    return path.read_bytes() == before


@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
def test_a_changed_workspace_mcp_json_is_backed_up(tmp_path, script):
    deploy = tmp_path / "vhir"
    deploy.mkdir()
    cfg = deploy / ".mcp.json"
    cfg.write_text('{"mcpServers": {"mine": {}}}\n')
    cfg.chmod(0o600)
    before = cfg.read_bytes()
    block = _between(
        script,
        '        CONFIG_FILE="$DEPLOY_DIR/.mcp.json"',
        '        ok "Written: $CONFIG_FILE"',
    )
    rc, out = _bash(
        script,
        block,
        tmp_path,
        _bin(tmp_path, SH_TOOLS),
        DEPLOY_DIR=str(deploy),
        MCP_JSON='{"mcpServers": {}}',
    )
    assert rc == 0, out
    (bak,) = deploy.glob(".mcp.json.vhir-backup-*")
    assert bak.read_bytes() == before and _mode(bak) == 0o600 and _mode(cfg) == 0o600
    assert _restored(out, cfg, before)


@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
@pytest.mark.parametrize(
    "existing,python3,said",
    [
        ('{"hooks": {}, "mine": 1}\n', False, "settings.json (replaced)"),
        ('{"hooks": {', True, "wasn't valid JSON: replaced"),
        ('{"hooks": {}, "mine": 1}\n', True, "settings.json (merged)"),
    ],
    ids=["no python3", "unparseable", "merged"],
)
def test_settings_writes_are_backed_up(tmp_path, script, existing, python3, said):
    settings = tmp_path / "settings.json"
    settings.write_text(existing)
    settings.chmod(0o600)
    before = settings.read_bytes()
    path = _bin(tmp_path, SH_TOOLS + (["python3"] if python3 else []))
    rc, out = _bash(
        script,
        _settings_block(script),
        tmp_path,
        path,
        SETTINGS_FILE=str(settings),
        SETTINGS_CONTENT=json.dumps(INCOMING),
    )
    assert rc == 0, out
    assert said in out and ("merged" in out) is (said == "settings.json (merged)")
    (bak,) = tmp_path.glob("settings.json.vhir-backup-*")
    assert bak.read_bytes() == before and _mode(bak) == 0o600
    assert not (tmp_path / "settings.json.vhir-new").exists()
    assert _restored(out, settings, before)


@pytest.mark.parametrize("script", [MAC, LINUX], ids=["macos", "linux"])
@pytest.mark.parametrize(
    "how",
    ["stale staging file", "stale, python3 exits 0 unwritten", "killed mid-write"],
)
def test_a_failed_merge_leaves_settings(tmp_path, script, how):
    """Only this run's merge output is installed: a staging file left by an
    interrupted earlier run, or a partial one from a killed merge, never is."""
    settings = tmp_path / "settings.json"
    settings.write_text("[1]\n")  # valid JSON, not an object: the merge fails
    before = settings.read_bytes()
    staging = tmp_path / "settings.json.vhir-new"
    path = _bin(tmp_path, SH_TOOLS + ["python3"])
    stub = {
        "stale, python3 exits 0 unwritten": "exit 0",  # a broken shim
        "killed mid-write": 'printf \'{"hoo\' > "$SETTINGS_FILE.vhir-new"; kill -9 $$',
    }.get(how)
    if how.startswith("stale"):
        staging.write_text('{"stale": 1}\n')
    if stub:
        python3 = Path(path) / "python3"
        python3.unlink()
        python3.write_text(f"#!/bin/bash\n{stub}\n")
        python3.chmod(0o755)
    rc, out = _bash(
        script,
        _settings_block(script),
        tmp_path,
        path,
        SETTINGS_FILE=str(settings),
        SETTINGS_CONTENT=json.dumps(INCOMING),
    )
    assert rc == 0, out
    assert settings.read_bytes() == before, out
    assert "settings.json (merged)" not in out and "NOT changed" in out
    assert not staging.exists() and not list(tmp_path.glob("*.vhir-backup-*"))


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_win_settings_catch_backs_up_before_replacing(tmp_path):
    settings = tmp_path / "settings.json"
    settings.write_text('{"hooks": {')  # the merge throws: the catch replaces it
    before = settings.read_bytes()
    block = _between(WIN, "if (Test-Path $settingsPath) {", "\n} else {")
    body = (
        f"$settingsPath = '{settings}'\n"
        "$settingsObj = [pscustomobject]@{ hooks = [pscustomobject]@{} }\n"
        + block
        + "\n}\n"
    )
    rc, out = _pwsh(tmp_path, body, tmp_path)
    assert rc == 0 and "settings.json (replaced)" in out, out
    (bak,) = tmp_path.glob("settings.json.vhir-backup-*")
    assert bak.read_bytes() == before
    (line,) = _undo(out)
    subprocess.run([PWSH, "-NoProfile", "-Command", line], check=True)
    assert settings.read_bytes() == before


# --- Uninstall backs the Desktop config up before removing it -----------------


@pytest.mark.parametrize(
    "script,rel",
    [(MAC, "Library/Application Support/Claude"), (LINUX, ".config/claude")],
    ids=["macos", "linux"],
)
def test_uninstall_backs_up_the_desktop_config(tmp_path, script, rel):
    cfg = tmp_path / rel / "claude_desktop_config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps(USER))
    cfg.chmod(0o600)
    before = cfg.read_bytes()
    block = _between(
        script,
        "    CLAUDE_DESKTOP_CFG=",
        '\n    echo ""\n    echo "Uninstall complete."',
    )
    rc, out = _bash(script, block, tmp_path, _bin(tmp_path, SH_TOOLS))  # "y" (stub)
    assert rc == 0 and not cfg.exists(), out
    assert _restored(out, cfg, before)
