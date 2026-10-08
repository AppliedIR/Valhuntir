"""The remote client scripts fetch the skills and the skeptic's agent.

Each script reads sift-mcp's `skills/MANIFEST` and fetches every file it lists
into `~/vhir/.claude/skills/`, and the finding skeptic's agent into
`~/vhir/.claude/agents/`. A listed path that could leave the skills folder is
refused. The tool reference is a skill now: no script fetches
TOOL_REFERENCE.md. Only the fetch blocks run, against a local stand-in for
GitHub, in a scratch HOME.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
SCRIPTS = {
    "linux": (REPO / "setup-client-linux.sh").read_text(),
    "macos": (REPO / "setup-client-macos.sh").read_text(),
}
WIN = (REPO / "setup-client-windows.ps1").read_text()
PWSH = shutil.which("pwsh")
RAW = "https://raw.example/AppliedIR"

FILES = {
    "vhir-playbooks/SKILL.md": "playbooks\n",
    "vhir-playbooks/references/usb_activity.md": "usb\n",
    "finding-skeptic/SKILL.md": "skeptic\n",
}
AGENT = "---\nname: finding-skeptic\n---\n\npart\n"

# A curl that serves $GITHUB_RAW/sift-mcp/main/<rel> from $SERVE/<rel>
CURL = r"""#!/bin/bash
out=; url=
while [ $# -gt 0 ]; do
    case "$1" in -o) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
src="$SERVE/${url#*/sift-mcp/main/}"
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then cat "$src" > "$out"; else cat "$src"; fi
"""
PROLOGUE = (
    "set -euo pipefail\n"
    'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }\n'
    f'GITHUB_RAW="{RAW}"; DEPLOY_DIR="$HOME/vhir"; ERRORS=0\n'
)


def _serve(tmp_path, manifest_lines):
    serve = tmp_path / "serve"
    for rel, text in FILES.items():
        (serve / "skills" / rel).parent.mkdir(parents=True, exist_ok=True)
        (serve / "skills" / rel).write_text(text)
    (serve / "skills" / "MANIFEST").write_text(
        "# listed\n" + "".join(f"{ln}\n" for ln in manifest_lines)
    )
    (serve / "agents" / "finding-skeptic").mkdir(parents=True)
    (serve / "agents" / "finding-skeptic" / "claude.md").write_text(AGENT)
    return serve


def _function(text):
    start = text.index("fetch_skills() {")
    start = text.rindex("\n", 0, start) + 1
    return text[start : text.index("\n}\n", start) + 3]


def _block(text):
    """The shared fetch_skills function and the Claude block that calls it."""
    start = text.index("# Skills and the finding skeptic's agent\n")
    start = text.rindex("\n", 0, start) + 1
    m = re.compile(r"^ *fi\n", re.M).search(
        text, text.index('ok "finding-skeptic agent"', start)
    )
    return _function(text) + text[start : m.end()]


def _run_sh(tmp_path, script, serve):
    home = tmp_path / "home"
    home.mkdir()
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "curl").write_text(CURL)
    (bin_ / "curl").chmod(0o755)
    for tool in ("cat", "mkdir", "dirname"):
        (bin_ / tool).symlink_to(shutil.which(tool))
    run = home / "block.sh"
    run.write_text(PROLOGUE + _block(SCRIPTS[script]) + 'echo "ERRORS=$ERRORS"\n')
    p = subprocess.run(
        ["/bin/bash", str(run)],
        env={"HOME": str(home), "PATH": str(bin_), "SERVE": str(serve)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    return p.returncode, p.stdout + p.stderr, home / "vhir" / ".claude"


def _tree(folder):
    return {
        str(p.relative_to(folder)): p.read_text()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_every_listed_skill_and_the_agent_are_fetched_into_the_project(
    tmp_path, script
):
    rc, out, claude = _run_sh(tmp_path, script, _serve(tmp_path, FILES))
    assert rc == 0, out
    assert _tree(claude / "skills") == FILES
    assert (claude / "agents" / "finding-skeptic.md").read_text() == AGENT
    assert "OK 3 skill files" in out and "ERRORS=0" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
@pytest.mark.parametrize("bad", ["../../.bashrc", "/etc/passwd", "a b/SKILL.md"])
def test_a_listed_path_that_could_leave_the_skills_folder_is_refused(
    tmp_path, script, bad
):
    rc, out, claude = _run_sh(tmp_path, script, _serve(tmp_path, [bad, *FILES]))
    assert rc == 0, out
    assert f"WARN Skipped an unexpected skills path: {bad}" in out
    assert "ERRORS=1" in out and _tree(claude / "skills") == FILES
    assert not (tmp_path / "home" / ".bashrc").exists()


@pytest.mark.parametrize("text", [*SCRIPTS.values(), WIN], ids=[*SCRIPTS, "windows"])
def test_no_script_fetches_the_tool_reference_any_more(text):
    assert "claude-code/full/TOOL_REFERENCE.md" not in text


def _win_function():
    start = WIN.index("function Fetch-Skills {")
    return WIN[start : WIN.index("\n}\n", start) + 3]


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_fetches_every_listed_skill_and_refuses_a_path_outside(tmp_path):
    serve = _serve(tmp_path, ["..\\..\\evil.md", *FILES])
    block = (
        _win_function()
        + WIN[
            WIN.index("# Skills: every file skills/MANIFEST lists") : WIN.index(
                "# Note: forensic-audit.sh"
            )
        ]
    )
    deploy = tmp_path / "vhir"
    stub = (
        'function Write-Info($m) { Write-Host "INFO $m" }\n'
        'function Write-Ok($m) { Write-Host "OK $m" }\n'
        'function Write-Warn($m) { Write-Host "WARN $m" }\n'
        "function Invoke-WebRequest {\n"
        "    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)\n"
        f"    $src = Join-Path '{serve}' ($Uri -replace '^.*/sift-mcp/main/', '')\n"
        "    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw 'not found' }\n"
        "    if ($OutFile) { Copy-Item -LiteralPath $src -Destination $OutFile; return }\n"
        "    return @{ Content = [IO.File]::ReadAllText($src) }\n"
        "}\n"
        f"$githubRaw = '{RAW}'\n$deployDir = '{deploy}'\n$errors = 0\n"
    )
    script = tmp_path / "run.ps1"
    script.write_text(stub + block + '\nWrite-Host "ERRORS=$errors"\n')
    p = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = p.stdout + p.stderr
    assert p.returncode == 0, out
    skills = deploy / ".claude" / "skills"
    got = {
        str(f.relative_to(skills)).replace("\\", "/"): f.read_text()
        for f in skills.rglob("*")
        if f.is_file()
    }
    assert got == FILES
    assert "WARN Skipped an unexpected skills path: ..\\..\\evil.md" in out
    assert "OK 3 skill files" in out and "ERRORS=1" in out
    assert not (tmp_path / "evil.md").exists()
