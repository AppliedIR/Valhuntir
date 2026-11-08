"""K17: every client control deploys from manifest["source"], on any install dir.

`vhir setup client` and Step 5 of `vhir update` both deploy the controls through
_deploy_claude_code_assets: settings.json (the audit hook and the deny rules),
the hooks, CLAUDE.md, the rules (FORENSIC_DISCIPLINE.md and AGENTS.md) and the
skills; the update also writes Codex's profile. The checkout they deploy from is
the one the install recorded in manifest["source"]. A sift-mcp installed with
--install-dir somewhere other than ~/.vhir/src, ~/vhir or /opt/vhir used to get
"Hook and settings deployment skipped" and none of its controls; a different
checkout at ~/.vhir/src/sift-mcp or at gateway.yaml's sift_mcp_dir used to be
deployed in its place.

Layouts, each with the pulled checkout at ~/alt/src/sift-mcp, recorded in the
manifest:
  skip:                  nothing at any other dir; gateway.yaml has no
                         sift_mcp_dir, as the installer writes it
  decoy_at_vhir_src:     another checkout at ~/.vhir/src/sift-mcp
  decoy_at_sift_mcp_dir: another checkout that gateway.yaml's sift_mcp_dir names
Every deployed file is compared with the pulled checkout's bytes, and no file
may carry the other checkout's marker. Everything is under tmp_path: a scratch
HOME, no terminal; the gateway's backends are stubbed for the update and
unreachable for setup client."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import types
from pathlib import Path

import pytest

import vhir_cli
from tests.stub_check import stub, stub_check  # noqa: F401 (the fixture)
from vhir_cli.commands import client_setup as cs
from vhir_cli.commands import codex_controls as cc
from vhir_cli.commands import update as upd

tomllib = pytest.importorskip("tomllib")

PULLED, DECOY = "the pulled checkout", "a decoy checkout"
HOOKS = ("forensic-audit.sh", "case-dir-check.sh", "case-data-guard.sh")
SKIP_LINES = ("Hook and settings deployment skipped", "Skill deployment skipped")
TOKEN = "vhir_gw_" + "cd" * 12
BACKENDS = ["forensic-mcp", "case-mcp", "sift-mcp"]
_REAL_FIND_SPEC = importlib.util.find_spec


def _git(repo, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )


def _deny(marker):
    return f"Read(**/{marker.replace(' ', '-')})"


def _checkout(path, marker):
    """A sift-mcp checkout whose every control names marker."""
    full = path / "claude-code" / "full"
    (full / "hooks").mkdir(parents=True)
    (path / "claude-code" / "shared").mkdir()
    settings = {
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "$CLAUDE_PROJECT_DIR/forensic-audit.sh",
                        }
                    ],
                }
            ]
        },
        "permissions": {"deny": [_deny(marker)]},
    }
    (full / "settings.json").write_text(json.dumps(settings, indent=2))
    for hook in HOOKS:
        (full / "hooks" / hook).write_text(f"#!/bin/bash\n# {hook} of {marker}\n")
    (full / "CLAUDE.md").write_text(f"# CLAUDE.md of {marker}\n")
    (full / "FORENSIC_DISCIPLINE.md").write_text(f"# Discipline of {marker}\n")
    (path / "skills" / "k17-skill").mkdir(parents=True)
    (path / "skills" / "k17-skill" / "SKILL.md").write_text(f"# Skill of {marker}\n")
    (path / "codex").mkdir()
    (path / "codex" / "OVERLAY.md").write_text(f"## Codex\n\nOverlay of {marker}.\n")
    (path / "AGENTS.md").write_text(f"# Valhuntir core\n\nCheckout: {marker}\n")
    _git(path, "init", "-q")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "v1")
    return path


@pytest.fixture
def bed(tmp_path, monkeypatch, stub_check):  # noqa: F811 (the fixture)
    """A SIFT box with no controls deployed yet: HOME and the cwd (no AGENTS.md)
    under tmp_path, no terminal."""
    home, cwd = tmp_path / "home", tmp_path / "cwd"
    (home / ".vhir").mkdir(parents=True)
    (home / ".claude").mkdir()
    cwd.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", lambda p="": "")
    pulled = _checkout(home / "alt" / "src" / "sift-mcp", PULLED)

    def run(layout, entry):
        """Lay the box out, then deploy through entry ("update" or "setup")."""
        assert not Path("/opt/vhir").exists(), "this row needs no /opt/vhir"
        assert not (home / "vhir").exists()
        gateway = "gateway:\n  port: 4508\n"
        if layout == "decoy_at_vhir_src":
            _checkout(home / ".vhir" / "src" / "sift-mcp", DECOY)
        elif layout == "decoy_at_sift_mcp_dir":
            decoy = _checkout(tmp_path / "other" / "sift-mcp", DECOY)
            gateway += f"sift_mcp_dir: {decoy}\n"
        else:
            assert layout == "skip"
            assert not (home / ".vhir" / "src").exists()
        (home / ".vhir" / "gateway.yaml").write_text(gateway)
        clients = ["claude-code", "codex"] if entry == "update" else ["claude-code"]
        manifest = {
            "version": vhir_cli.__version__,
            "source": str(pulled),
            "clients": clients,
        }
        (home / ".vhir" / "manifest.json").write_text(json.dumps(manifest))
        if entry == "update":
            monkeypatch.setattr(
                cc, "REQUIREMENTS", tmp_path / "etc-codex" / "requirements.toml"
            )
            monkeypatch.setattr(  # this suite's venv may hold opensearch-mcp
                importlib.util,
                "find_spec",
                lambda name, *a, **kw: (
                    None
                    if name == "opensearch_mcp"
                    else _REAL_FIND_SPEC(name, *a, **kw)
                ),
            )
            stub(monkeypatch, cs, "_read_local_token", lambda: TOKEN)
            stub(
                monkeypatch,
                cs,
                "_discover_services",
                lambda url, token: [{"name": n, "started": True} for n in BACKENDS],
            )
            stub(monkeypatch, cc, "codex_controls_state", lambda *a, **kw: "off")
            stub(monkeypatch, cc, "state_lines", lambda *a, **kw: [])
            upd._redeploy_clients(manifest)
        else:
            assert entry == "setup"
            monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
            args = types.SimpleNamespace(
                client="claude-code",
                sift="http://127.0.0.1:9",  # nothing listens: never a live gateway
                windows=None,
                windows_token=None,
                remnux=None,
                remnux_token=None,
                examiner="steve",
                no_mslearn=True,
                yes=True,
                uninstall=False,
            )
            cs.cmd_setup_client(args, {"examiner": "steve"})

    return types.SimpleNamespace(home=home, pulled=pulled, run=run)


def _same(deployed, source):
    assert deployed.is_file(), f"{deployed} was not deployed"
    text = deployed.read_text()
    assert DECOY not in text, (deployed, text)
    assert deployed.read_bytes() == source.read_bytes(), (deployed, text)


def _check(bed, output, out):
    home, full = bed.home, bed.pulled / "claude-code" / "full"
    if output == "no_skip_line":
        assert not [s for s in SKIP_LINES if s in out], out
    elif output == "settings":
        path = home / ".claude" / "settings.json"
        assert path.is_file(), out
        data = json.loads(path.read_text())
        deny = data.get("permissions", {}).get("deny", [])
        assert _deny(PULLED) in deny and _deny(DECOY) not in deny, deny
        bash = [
            h["command"]
            for e in data.get("hooks", {}).get("PostToolUse", [])
            if e.get("matcher") == "Bash"
            for h in e.get("hooks", [])
        ]
        assert any(c.endswith("forensic-audit.sh") for c in bash), data
    elif output == "hooks":
        for hook in HOOKS:
            _same(home / ".vhir" / "hooks" / hook, full / "hooks" / hook)
    elif output == "claude_md":
        _same(home / ".claude" / "CLAUDE.md", full / "CLAUDE.md")
    elif output == "discipline":
        _same(
            home / ".claude" / "rules" / "FORENSIC_DISCIPLINE.md",
            full / "FORENSIC_DISCIPLINE.md",
        )
    elif output == "agents_rule":
        _same(home / ".claude" / "rules" / "AGENTS.md", bed.pulled / "AGENTS.md")
    elif output == "skills":
        _same(
            home / ".claude" / "skills" / "k17-skill" / "SKILL.md",
            bed.pulled / "skills" / "k17-skill" / "SKILL.md",
        )
    else:
        assert output == "codex"
        profile = home / ".codex" / "valhuntir.config.toml"
        assert profile.is_file(), out
        text = tomllib.loads(profile.read_text())["developer_instructions"]
        assert f"Checkout: {PULLED}" in text.splitlines(), text
        assert DECOY not in text, text


LAYOUTS = ("skip", "decoy_at_vhir_src", "decoy_at_sift_mcp_dir")
CONTROLS = ("settings", "hooks", "claude_md", "discipline", "agents_rule", "skills")
ROWS = [
    (layout, entry, output)
    for layout in LAYOUTS
    for entry in ("update", "setup")
    for output in (
        *(("no_skip_line",) if layout == "skip" else ()),
        *CONTROLS,
        *(("codex",) if entry == "update" else ()),
    )
]


@pytest.mark.parametrize("layout,entry,output", ROWS, ids=["-".join(r) for r in ROWS])
def test_k17_controls_deploy_from_manifest_source(bed, capsys, layout, entry, output):
    bed.run(layout, entry)
    _check(bed, output, capsys.readouterr().out)


def test_k17_source_without_assets_skips_and_never_falls_back(bed, capsys):
    """The checkout manifest["source"] names exists but has no claude-code/,
    and a complete checkout sits at ~/.vhir/src/sift-mcp: the assets are
    skipped, with the note, and nothing is deployed from the other checkout.
    Taking the assets from it would split them from the AGENTS.md of the
    recorded checkout."""
    import shutil

    shutil.rmtree(bed.pulled / "claude-code")
    assert bed.pulled.is_dir() and (bed.pulled / "AGENTS.md").is_file()
    bed.run("decoy_at_vhir_src", "setup")
    out = capsys.readouterr().out
    assert "Hook and settings deployment skipped" in out, out
    hooks = bed.home / ".vhir" / "hooks"
    assert not [h for h in HOOKS if (hooks / h).exists()], sorted(hooks.iterdir())
    deployed = [p for p in (bed.home / ".claude").rglob("*") if p.is_file()]
    assert not [p for p in deployed if DECOY in p.read_text(errors="replace")], [
        str(p) for p in deployed
    ]
