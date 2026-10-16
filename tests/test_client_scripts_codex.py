"""The Linux and macOS client scripts set up Codex on the examiner's machine.

They write Valhuntir's Codex profile, `~/.codex/valhuntir.config.toml` (0600),
as `vhir setup client --remote --client=codex` does: every backend with its
bearer token and no tool prompt, the sandbox and approval defaults, no folder
instruction files, and developer_instructions = the AGENTS.md core, the
forensic discipline, the Codex overlay and the remote fragment, fetched from
sift-mcp. The skills go to `~/.agents/skills/` and the skeptic's agent to
`~/.codex/agents/`. `~/.codex/config.toml` is never written; a re-run shows
the change, token hidden, and keeps a backup. Uninstall removes only vhir's
Codex files. Only these blocks run, against a local stand-in for GitHub, in a
scratch HOME.
"""

from __future__ import annotations

import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from vhir_cli.commands import client_setup as cs

tomllib = pytest.importorskip("tomllib")

REPO = Path(__file__).parent.parent
SCRIPTS = {
    "linux": (REPO / "setup-client-linux.sh").read_text(),
    "macos": (REPO / "setup-client-macos.sh").read_text(),
}
TOKEN = "vhir_gw_" + "ab" * 12
PARTS = {
    "AGENTS.md": "# Valhuntir core\n\nEvidence guides theory.\n",
    "claude-code/full/FORENSIC_DISCIPLINE.md": "# Forensic Discipline\n\nShow it.\n",
    "codex/OVERLAY.md": "## Codex\n\nUse codex -p valhuntir.\n",
    "codex/REMOTE.md": "## On the examiner's machine\n\nNot in the case audit.\n",
}
SKILL = "---\nname: vhir-welcome\ndescription: w\n---\n\nwelcome\n"
AGENT = 'name = "finding-skeptic"\n'
CURL = r"""#!/bin/bash
out=; url=
while [ $# -gt 0 ]; do
    case "$1" in -o) out=$2; shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
src="$SERVE/${url#*/sift-mcp/main/}"
[ -f "$src" ] || exit 22
if [ -n "$out" ]; then cat "$src" > "$out"; else cat "$src"; fi
"""
TOOLS = ["cat", "mkdir", "dirname", "mktemp", "rm", "cmp", "diff", "sed", "chmod",
         "grep", "date", "cp", "printf", "readlink", "tail"]  # fmt: skip
PROLOGUE = (
    "set -euo pipefail\nRED=; GREEN=; YELLOW=; BLUE=; BOLD=; NC=\n"
    'info() { echo "INFO $*"; }; ok() { echo "OK $*"; }; warn() { echo "WARN $*"; }\n'
    'header() { echo "== $*"; }\nprompt_yn_strict() { return 0; }\n'
)


def _helpers(text):
    start = text.index("# A user's file is backed up")
    end = text.index("\n}\n", text.index("replace_file() {")) + 3
    parts = [text[start:end]]
    for fn in ("fetch_skills() {", "set_gateway_ca() {"):
        f = text.rindex("\n", 0, text.index(fn)) + 1
        parts.append(text[f : text.index("\n}\n", f) + 3])
    return "".join(parts)


def _codex_block(text):
    start = text.index("# ---- Codex: Valhuntir's profile")
    end = re.compile(r"^fi\n", re.M).search(text, text.index("Codex file(s) could not"))
    return text[start : end.end()]


def _claude_block(text):
    start = text.index("# ---- Claude Code: the gateway's CA ----")
    end = re.compile(r"^fi\n", re.M).search(text, start)
    return text[start : end.end()]


def _uninstall_block(text):
    start = text.index("    # Codex: Valhuntir's profile, skills and agent")
    ca = text.find("    # The gateway's CA lines (Codex's and Claude Code's)", start)
    if ca != -1:
        return text[start : text.index("\n    done\n", ca) + 10]
    return text[start : text.index("\n    fi\n\n", start) + 7]


@pytest.fixture
def run(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    serve = tmp_path / "serve"
    for rel, body in {
        **PARTS,
        "skills/MANIFEST": "# listed\nvhir-welcome/SKILL.md\n",
        "skills/vhir-welcome/SKILL.md": SKILL,
        "agents/finding-skeptic/codex.toml": AGENT,
    }.items():
        (serve / rel).parent.mkdir(parents=True, exist_ok=True)
        (serve / rel).write_text(body)
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "curl").write_text(CURL)
    (bin_ / "curl").chmod(0o755)
    for t in TOOLS:
        if shutil.which(t):
            (bin_ / t).symlink_to(shutil.which(t))

    def go(script, body, extra=None):
        f = home / f"block-{len(list(home.glob('block-*')))}.sh"
        f.write_text(PROLOGUE + _helpers(SCRIPTS[script]) + body)
        p = subprocess.run(
            ["/bin/bash", str(f)],
            env={"HOME": str(home), "PATH": str(bin_), "SERVE": str(serve)}
            | (extra or {}),
            capture_output=True,
            text=True,
            timeout=60,
            cwd=home,
        )
        return p.returncode, p.stdout + p.stderr

    def setup(script, url="https://sift.example:4508", rc="", ca="", extra=None):
        env = (
            f'CLIENT=codex\nGATEWAY_URL="{url}"\n'
            f'GATEWAY_TOKEN="{TOKEN}"\nBACKENDS="forensic-mcp\ncase-mcp"\n'
            f"SHELL_RC={shlex.quote(rc)}\nCA_CERT={shlex.quote(ca)}\n"
        )
        return go(script, env + _codex_block(SCRIPTS[script]), extra)

    def claude(script, url="https://sift.example:4508", rc="", ca="", extra=None):
        env = (
            f'CLIENT=claude-code\nGATEWAY_URL="{url}"\n'
            f"SHELL_RC={shlex.quote(rc)}\nCA_CERT={shlex.quote(ca)}\n"
        )
        return go(script, env + _claude_block(SCRIPTS[script]), extra)

    def uninstall(script):
        return go(script, _uninstall_block(SCRIPTS[script]))

    return types_ns(
        home=home, serve=serve, setup=setup, claude=claude, uninstall=uninstall
    )


def types_ns(**kw):
    import types

    return types.SimpleNamespace(**kw)


def _profile(home):
    return home / ".codex" / "valhuntir.config.toml"


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_script_writes_the_profile_as_the_cli_does(run, script):
    rc, out = run.setup(script)
    assert rc == 0, out
    path = _profile(run.home)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    p = tomllib.loads(path.read_text())
    assert p["sandbox_mode"] == "workspace-write"
    assert p["approval_policy"] == "on-request"
    assert p["project_doc_max_bytes"] == 0
    assert p["mcp_servers"]["case-mcp"] == {
        "url": "https://sift.example:4508/mcp/case-mcp",
        "http_headers": {"Authorization": f"Bearer {TOKEN}"},
        "default_tools_approval_mode": "approve",
    }
    assert "default_tools_approval_mode" not in p["mcp_servers"]["microsoft-learn"]
    # the same instructions the CLI writes from the same files
    cli = tomllib.loads(
        cs._codex_profile_text(
            {}, "\n\n".join(t.strip() for t in PARTS.values()) + "\n", []
        )
    )
    assert p["developer_instructions"] == cli["developer_instructions"]
    assert TOKEN not in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_script_deploys_the_skills_and_the_agent_for_codex(run, script):
    rc, out = run.setup(script)
    assert rc == 0, out
    assert (run.home / ".agents/skills/vhir-welcome/SKILL.md").read_text() == SKILL
    assert (run.home / ".codex/agents/finding-skeptic.toml").read_text() == AGENT


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_config_toml_is_never_written_and_a_wide_sandbox_is_named(run, script):
    cfg = run.home / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_bytes(b'sandbox_mode = "danger-full-access"\n')
    rc, out = run.setup(script)
    assert rc == 0, out
    assert cfg.read_bytes() == b'sandbox_mode = "danger-full-access"\n'
    assert "danger-full-access" in out and "vhir doesn't edit that file" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_a_re_run_shows_the_change_without_the_token_and_keeps_a_backup(run, script):
    run.setup(script)
    (run.serve / "codex/REMOTE.md").write_text(PARTS["codex/REMOTE.md"] + "\nMore.\n")
    rc, out = run.setup(script)
    assert rc == 0, out
    assert f"Changes to {_profile(run.home)}" in out and "+More." in out
    assert TOKEN not in out
    (bak,) = _profile(run.home).parent.glob("valhuntir.config.toml.vhir-backup-*")
    assert "More." not in bak.read_text() and "More." in _profile(run.home).read_text()
    assert stat.S_IMODE(_profile(run.home).stat().st_mode) == 0o600


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_without_the_instructions_the_profile_isn_t_written(run, script):
    (run.serve / "codex/REMOTE.md").unlink()
    rc, out = run.setup(script)
    assert rc == 0, out
    assert not _profile(run.home).exists()
    assert "couldn't be fetched" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_uninstall_removes_only_vhir_s_codex_files(run, script):
    run.setup(script)
    cfg = run.home / ".codex" / "config.toml"
    cfg.write_bytes(b'model = "gpt"\n')
    mine = run.home / ".agents" / "skills" / "my-notes"
    mine.mkdir()
    rc, out = run.uninstall(script)
    assert rc == 0, out
    assert not _profile(run.home).exists()
    assert not (run.home / ".agents/skills/vhir-welcome").exists()
    assert not (run.home / ".codex/agents/finding-skeptic.toml").exists()
    assert cfg.read_bytes() == b'model = "gpt"\n' and mine.is_dir()


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_script_offers_codex_and_prints_the_start_folder_and_limits(script):
    text = SCRIPTS[script]
    assert '2) CLIENT="codex" ;;' in text
    assert "cd ~/vhir && codex -p valhuntir" in text
    assert "aren't in the case" in text and "user-switchable" in text


# --- Codex's CA on a TLS gateway ----------------------------------------------

MARK = "  # vhir-gateway-ca"


def _ca(home):
    ca = home / ".vhir" / "tls" / "ca-cert.pem"
    ca.parent.mkdir(parents=True, exist_ok=True)
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    return ca


def _ca_lines(rc):
    return [ln for ln in rc.read_text().splitlines() if ln.endswith(MARK)]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_an_https_gateway_has_codex_trust_its_ca_from_the_shell_profile(run, script):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias ll='ls -l'")  # no final newline
    code, out = run.setup(script, rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == (
        f"alias ll='ls -l'\nexport CODEX_CA_CERTIFICATE={ca}{MARK}\n"
    )
    assert f"export CODEX_CA_CERTIFICATE={ca}" in out
    # a re-run keeps one line; a stale path is replaced
    run.setup(script, rc=str(rc))
    assert _ca_lines(rc) == [f"export CODEX_CA_CERTIFICATE={ca}{MARK}"]
    rc.write_text(f"export CODEX_CA_CERTIFICATE=/old/ca.pem{MARK}\nalias x=y\n")
    run.setup(script, rc=str(rc))
    assert rc.read_text() == f"alias x=y\nexport CODEX_CA_CERTIFICATE={ca}{MARK}\n"


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_ca_line_quotes_a_path_with_spaces(run, script):
    home = run.home
    ca = _ca(home)
    rc = home / ".bashrc"
    rc.write_text("")
    if script == "linux":
        odd = home / "my certs" / "ca $x.pem"
        odd.parent.mkdir()
        odd.write_text("x")
        run.setup(script, rc=str(rc), ca=str(odd))
        ca = odd
    else:
        run.setup(script, rc=str(rc))
    (line,) = _ca_lines(rc)
    p = subprocess.run(
        ["/bin/bash", "-c", f'{line}\nprintf %s "$CODEX_CA_CERTIFICATE"'],
        capture_output=True,
        text=True,
    )
    assert p.stdout == str(ca)


def test_linux_takes_the_join_s_ca_cert_and_makes_it_absolute(run):
    _ca(run.home)
    mine = run.home / "sift-ca.pem"
    mine.write_text("x")
    rc = run.home / ".bashrc"
    rc.write_text("")
    code, out = run.setup("linux", rc=str(rc), ca="sift-ca.pem")
    assert code == 0, out
    assert _ca_lines(rc) == [f"export CODEX_CA_CERTIFICATE={mine}{MARK}"]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_an_http_gateway_leaves_the_profile_alone(run, script):
    _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.setup(script, url="http://sift.example:4508", rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n" and "CODEX_CA" not in out


@pytest.mark.parametrize("var", ["CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"])
@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_a_bundle_the_user_set_is_named_and_not_overridden(run, script, var):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.setup(script, rc=str(rc), extra={var: "/etc/corp-bundle.pem"})
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n"
    assert f"WARN {var} is set to /etc/corp-bundle.pem" in out and str(ca) in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_vhir_s_own_value_in_the_environment_still_updates_the_line(run, script):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text(f"export CODEX_CA_CERTIFICATE=/old/ca.pem{MARK}\n")
    code, out = run.setup(
        script, rc=str(rc), extra={"CODEX_CA_CERTIFICATE": "/old/ca.pem"}
    )
    assert code == 0, out
    assert _ca_lines(rc) == [f"export CODEX_CA_CERTIFICATE={ca}{MARK}"]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_without_the_ca_here_the_script_says_how_to_get_it(run, script):
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.setup(script, rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n"
    assert "WARN The gateway uses https" in out and "ca-cert.pem" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_without_a_shell_profile_the_script_prints_the_start_line(run, script):
    ca = _ca(run.home)
    code, out = run.setup(script, rc="")
    assert code == 0, out
    assert f"CODEX_CA_CERTIFICATE={ca} codex -p valhuntir" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_uninstall_removes_the_ca_line_from_either_profile(run, script):
    for name in (".bashrc", ".zshrc"):
        (run.home / name).write_text(
            f"alias x=y\nexport CODEX_CA_CERTIFICATE=/a/ca.pem{MARK}\nexport P=1\n"
        )
    code, out = run.uninstall(script)
    assert code == 0, out
    for name in (".bashrc", ".zshrc"):
        assert (run.home / name).read_text() == "alias x=y\nexport P=1\n"


# --- Claude Code's CA on a TLS gateway --------------------------------------------


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_an_https_gateway_has_claude_code_trust_its_ca_from_the_shell_profile(
    run, script
):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.claude(script, rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == f"alias x=y\nexport NODE_EXTRA_CA_CERTS={ca}{MARK}\n"
    assert f"export NODE_EXTRA_CA_CERTS={ca}" in out
    run.claude(script, rc=str(rc))
    assert _ca_lines(rc) == [f"export NODE_EXTRA_CA_CERTS={ca}{MARK}"]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_codex_s_and_claude_code_s_ca_lines_live_side_by_side(run, script):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text(f"export NODE_EXTRA_CA_CERTS=/old/ca.pem{MARK}\n")
    run.setup(script, rc=str(rc))
    run.claude(script, rc=str(rc))
    run.setup(script, rc=str(rc))
    assert _ca_lines(rc) == [
        f"export CODEX_CA_CERTIFICATE={ca}{MARK}",
        f"export NODE_EXTRA_CA_CERTS={ca}{MARK}",
    ]


def test_linux_gives_claude_code_the_join_s_ca_cert(run):
    _ca(run.home)
    mine = run.home / "sift-ca.pem"
    mine.write_text("x")
    rc = run.home / ".bashrc"
    rc.write_text("")
    code, out = run.claude("linux", rc=str(rc), ca="sift-ca.pem")
    assert code == 0, out
    assert _ca_lines(rc) == [f"export NODE_EXTRA_CA_CERTS={mine}{MARK}"]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_claude_code_on_an_http_gateway_leaves_the_profile_alone(run, script):
    _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.claude(script, url="http://sift.example:4508", rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n" and "NODE_EXTRA" not in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_claude_code_s_own_extra_ca_is_named_and_not_overridden(run, script):
    ca = _ca(run.home)
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.claude(
        script, rc=str(rc), extra={"NODE_EXTRA_CA_CERTS": "/etc/corp.pem"}
    )
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n"
    assert "WARN NODE_EXTRA_CA_CERTS is set to /etc/corp.pem" in out
    assert str(ca) in out and "Claude Code" in out
    # Codex's fallback is not Claude Code's
    code, out = run.claude(script, rc=str(rc), extra={"SSL_CERT_FILE": "/e/b.pem"})
    assert _ca_lines(rc) == [f"export NODE_EXTRA_CA_CERTS={ca}{MARK}"]


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_claude_code_without_the_ca_or_a_profile_is_told_what_to_do(run, script):
    rc = run.home / ".bashrc"
    rc.write_text("alias x=y\n")
    code, out = run.claude(script, rc=str(rc))
    assert code == 0, out
    assert rc.read_text() == "alias x=y\n"
    assert "WARN The gateway uses https. If Claude Code can't connect" in out
    ca = _ca(run.home)
    code, out = run.claude(script, rc="")
    assert code == 0, out
    assert f"NODE_EXTRA_CA_CERTS={ca} claude" in out


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_uninstall_removes_both_clients_ca_lines(run, script):
    rc = run.home / ".bashrc"
    rc.write_text(
        f"alias x=y\nexport CODEX_CA_CERTIFICATE=/a/ca.pem{MARK}\n"
        f"export NODE_EXTRA_CA_CERTS=/a/ca.pem{MARK}\nexport P=1\n"
    )
    code, out = run.uninstall(script)
    assert code == 0, out
    assert rc.read_text() == "alias x=y\nexport P=1\n"


@pytest.mark.parametrize("script", sorted(SCRIPTS))
def test_the_claude_code_branch_sets_its_ca(script):
    text = SCRIPTS[script]
    block = _claude_block(text)
    assert 'set_gateway_ca NODE_EXTRA_CA_CERTS "Claude Code" claude' in block
    # after the settings are written, before the summary
    assert text.index("# ---- Claude Code: the gateway's CA") > text.index(
        "<< 'PYMERGE'"
    )
    assert text.index("# ---- Claude Code: the gateway's CA") < text.index(
        'header "Setup Complete"'
    )


# --- Windows (pwsh) ---------------------------------------------------------------

WIN = (REPO / "setup-client-windows.ps1").read_text()
PWSH = shutil.which("pwsh")


def _win_part(start, end_marker):
    i = WIN.index(start)
    return WIN[i : WIN.index(end_marker, i)]


def _win_run(tmp_path, body, serve):
    stub = (
        'function Write-Info($m) { Write-Host "INFO $m" }\n'
        'function Write-Ok($m) { Write-Host "OK $m" }\n'
        'function Write-Warn($m) { Write-Host "WARN $m" }\n'
        "function Prompt-YN-Strict($m) { return $true }\n"
        "function Invoke-WebRequest {\n"
        "    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing)\n"
        f"    $src = Join-Path '{serve}' ($Uri -replace '^.*/sift-mcp/main/', '')\n"
        "    if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw 'not found' }\n"
        "    if ($OutFile) { Copy-Item -LiteralPath $src -Destination $OutFile; return }\n"
        "    return @{ Content = [IO.File]::ReadAllText($src) }\n"
        "}\n"
    )
    helpers = _win_part("function Backup-UserFile {", "# Write new text over a file")
    fetch = _win_part("function Fetch-Skills {", "\n}\n") + "\n}\n"
    script = tmp_path / f"run-{len(list(tmp_path.glob('run-*')))}.ps1"
    script.write_text(stub + helpers + fetch + body)
    p = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(script)],
        env={"HOME": str(tmp_path / "home"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    return p.returncode, p.stdout + p.stderr


@pytest.fixture
def win(run, tmp_path):
    codex = _win_part("# ---- Codex: Valhuntir's profile", "# ---- Claude Code assets")
    env = (
        '$clientType = "codex"\n$gatewayUrl = "https://sift.example:4508"\n'
        f'$gatewayToken = "{TOKEN}"\n$backends = @("forensic-mcp", "case-mcp")\n'
    )
    uninstall = _win_part(
        "    # Codex: Valhuntir's profile, skills and agent", "\n    $casesDir"
    )
    uninstall = uninstall[: uninstall.rindex("\n    }\n") + 7]
    return types_ns(
        home=run.home,
        serve=run.serve,
        setup=lambda: _win_run(tmp_path, env + codex, run.serve),
        uninstall=lambda: _win_run(tmp_path, uninstall, run.serve),
    )


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_writes_the_profile_as_the_cli_does_without_a_bom(win):
    rc, out = win.setup()
    assert rc == 0, out
    raw = _profile(win.home).read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    p = tomllib.loads(raw.decode())
    assert p["mcp_servers"]["forensic-mcp"]["http_headers"] == {
        "Authorization": f"Bearer {TOKEN}"
    }
    cli = tomllib.loads(
        cs._codex_profile_text(
            {}, "\n\n".join(t.strip() for t in PARTS.values()) + "\n", []
        )
    )
    assert p["developer_instructions"] == cli["developer_instructions"]
    assert (win.home / ".agents/skills/vhir-welcome/SKILL.md").read_text() == SKILL
    assert (win.home / ".codex/agents/finding-skeptic.toml").read_text() == AGENT
    assert TOKEN not in out


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_re_run_shows_the_change_without_the_token_and_keeps_a_backup(win):
    win.setup()
    (win.serve / "codex/REMOTE.md").write_text(PARTS["codex/REMOTE.md"] + "\nMore.\n")
    rc, out = win.setup()
    assert rc == 0, out
    assert "+More." in out and TOKEN not in out
    (bak,) = _profile(win.home).parent.glob("valhuntir.config.toml.vhir-backup-*")
    assert "More." not in bak.read_text()


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_uninstall_removes_only_vhir_s_codex_files(win):
    win.setup()
    cfg = win.home / ".codex" / "config.toml"
    cfg.write_bytes(b'model = "gpt"\n')
    mine = win.home / ".agents" / "skills" / "my-notes"
    mine.mkdir()
    rc, out = win.uninstall()
    assert rc == 0, out
    assert not _profile(win.home).exists()
    assert not (win.home / ".agents/skills/vhir-welcome").exists()
    assert cfg.read_bytes() == b'model = "gpt"\n' and mine.is_dir()


def test_windows_offers_codex_and_prints_the_limits():
    assert '"2" { "codex" }' in WIN
    assert "codex -p valhuntir" in WIN and "user-switchable" in WIN


def _win_codex(tmp_path, run, url, extra_env=None):
    codex = _win_part("# ---- Codex: Valhuntir's profile", "# ---- Claude Code assets")
    env = (
        f'$clientType = "codex"\n$gatewayUrl = "{url}"\n'
        f'$gatewayToken = "{TOKEN}"\n$backends = @("forensic-mcp", "case-mcp")\n'
    )
    pre = "".join(f"$env:{k} = '{v}'\n" for k, v in (extra_env or {}).items())
    return _win_run(tmp_path, pre + env + codex, run.serve)


def _win_claude(tmp_path, run, url, extra_env=None):
    block = _win_part("# ---- Claude Code: the gateway's CA", "# =====")
    env = f'$clientType = "claude-code"\n$gatewayUrl = "{url}"\n'
    pre = "".join(f"$env:{k} = '{v}'\n" for k, v in (extra_env or {}).items())
    return _win_run(tmp_path, pre + env + block, run.serve)


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_tells_how_claude_code_trusts_an_https_gateway(run, tmp_path):
    rc, out = _win_claude(tmp_path, run, "https://sift.example:4508")
    assert rc == 0, out
    assert "WARN The gateway uses https. For Claude Code to connect" in out
    assert "SetEnvironmentVariable('NODE_EXTRA_CA_CERTS'" in out
    rc, out = _win_claude(tmp_path, run, "http://sift.example:4508")
    assert rc == 0, out
    assert "NODE_EXTRA_CA_CERTS" not in out
    rc, out = _win_claude(
        tmp_path, run, "https://sift.example:4508", {"NODE_EXTRA_CA_CERTS": "C:/a.pem"}
    )
    assert rc == 0, out
    assert "NODE_EXTRA_CA_CERTS" not in out


@pytest.mark.skipif(not PWSH, reason="pwsh not installed")
def test_windows_tells_how_codex_trusts_an_https_gateway(run, tmp_path):
    rc, out = _win_codex(tmp_path, run, "https://sift.example:4508")
    assert rc == 0, out
    assert "WARN The gateway uses https" in out
    assert "SetEnvironmentVariable('CODEX_CA_CERTIFICATE'" in out
    rc, out = _win_codex(tmp_path, run, "http://sift.example:4508")
    assert rc == 0, out
    assert "CODEX_CA_CERTIFICATE" not in out
    rc, out = _win_codex(
        tmp_path,
        run,
        "https://sift.example:4508",
        {"CODEX_CA_CERTIFICATE": "C:/ca.pem"},
    )
    assert rc == 0, out
    assert "CODEX_CA_CERTIFICATE" not in out
