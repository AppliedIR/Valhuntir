"""`vhir setup client --client=codex` on the SIFT box.

It writes Valhuntir's Codex profile, `~/.codex/valhuntir.config.toml` (0600),
which `codex -p valhuntir` reads: every backend with its bearer token and no
tool prompt, the sandbox and approval defaults, no folder instruction files,
and developer_instructions = the AGENTS.md core, the forensic discipline and
the Codex overlay. It deploys the skills to `~/.agents/skills/` and the
skeptic's agent to `~/.codex/agents/`. The user's `~/.codex/config.toml` is
never written. Off the SIFT box (without --remote) Codex is refused.
Everything here is under tmp_path; no gateway is reached.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import types

import pytest

from vhir_cli.commands import client_setup as cs

tomllib = pytest.importorskip("tomllib")

TOKEN = "vhir_gw_" + "ab" * 12
AGENTS = "# Valhuntir core\n\nEvidence guides theory.\n"
FD = "# Forensic Discipline\n\nShow the evidence.\n"
OVERLAY = "## Codex\n\nStart with codex -p valhuntir.\n"
SKILL = "---\nname: vhir-welcome\ndescription: w\n---\n\nwelcome\n"
CODEX_AGENT = 'name = "finding-skeptic"\n'
BACKENDS = ["forensic-mcp", "case-mcp", "sift-mcp"]


def _git(repo, *args):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A SIFT box: a sift-mcp checkout, gateway.yaml, a manifest, and a
    gateway that serves BACKENDS (stubbed)."""
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    repo = tmp_path / "sift-mcp"
    full = repo / "claude-code" / "full"
    full.mkdir(parents=True)
    (repo / "claude-code" / "shared").mkdir()
    (full / "FORENSIC_DISCIPLINE.md").write_text(FD)
    (repo / "AGENTS.md").write_text(AGENTS)
    (repo / "codex").mkdir()
    (repo / "codex" / "OVERLAY.md").write_text(OVERLAY)
    (repo / "skills" / "vhir-welcome").mkdir(parents=True)
    (repo / "skills" / "vhir-welcome" / "SKILL.md").write_text(SKILL)
    (repo / "agents" / "finding-skeptic").mkdir(parents=True)
    (repo / "agents" / "finding-skeptic" / "codex.toml").write_text(CODEX_AGENT)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1")
    (home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {repo}\n")
    manifest = home / ".vhir" / "manifest.json"
    manifest.write_text(json.dumps({"version": "0.6.4"}))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr(cs, "_read_local_token", lambda: TOKEN)
    gateway = {"up": True}
    monkeypatch.setattr(
        cs,
        "_discover_services",
        lambda url, token: (
            [{"name": n, "started": True} for n in BACKENDS] if gateway["up"] else None
        ),
    )
    monkeypatch.setattr(cs, "_USERNS_SYSCTL", tmp_path / "no-such-sysctl")
    # this suite's venv may hold opensearch-mcp; the profile rows don't depend on it
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    return types.SimpleNamespace(
        home=home,
        repo=repo,
        manifest=manifest,
        gateway=gateway,
        profile=home / ".codex" / "valhuntir.config.toml",
        config=home / ".codex" / "config.toml",
    )


def _args(**kw):
    base = {
        "client": "codex",
        "sift": "http://127.0.0.1:4508",
        "windows": None,
        "windows_token": None,
        "remnux": None,
        "remnux_token": None,
        "examiner": "steve",
        "no_mslearn": False,
        "no_zeltser": False,
        "yes": True,
        "uninstall": False,
        "ask_user_files": False,
    }
    base.update(kw)
    return argparse.Namespace(**base)


def _setup(**kw):
    cs.cmd_setup_client(_args(**kw), {"examiner": "steve"})


def _profile(box):
    return tomllib.loads(box.profile.read_text())


# --- C.1 ------------------------------------------------------------------------


def test_the_cli_accepts_codex_as_a_client():
    from vhir_cli.main import build_parser

    args = build_parser().parse_args(["setup", "client", "--client", "codex"])
    assert args.client == "codex"


def test_off_the_sift_box_codex_is_refused_with_the_way_to_set_it_up(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: tmp_path))
    with pytest.raises(SystemExit) as e:
        _setup()
    assert e.value.code == 1
    assert cs.CODEX_OFF_SIFT in capsys.readouterr().err
    assert not (tmp_path / ".codex").exists()


def test_the_wizard_offers_codex(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "5")
    assert cs._wizard_client() == "codex"


# --- C.2: the profile -------------------------------------------------------------


def test_the_profile_holds_every_backend_with_its_token_and_no_tool_prompt(box, capsys):
    _setup()
    assert box.profile.stat().st_mode & 0o777 == 0o600
    p = _profile(box)
    assert p["sandbox_mode"] == "workspace-write"
    assert p["approval_policy"] == "on-request"
    assert p["project_doc_max_bytes"] == 0
    for name in BACKENDS:
        assert p["mcp_servers"][name] == {
            "url": f"http://127.0.0.1:4508/mcp/{name}",
            "http_headers": {"Authorization": f"Bearer {TOKEN}"},
            "default_tools_approval_mode": "approve",
        }
    # the internet services keep Codex's prompt
    assert "default_tools_approval_mode" not in p["mcp_servers"]["zeltser-ir-writing"]
    out = capsys.readouterr().out
    assert "cd <case folder> && codex -p valhuntir" in out
    assert TOKEN not in out


def test_the_instructions_are_the_core_the_discipline_and_the_overlay(box):
    _setup()
    assert _profile(box)["developer_instructions"] == (
        AGENTS.strip() + "\n\n" + FD.strip() + "\n\n" + OVERLAY.strip() + "\n"
    )


def test_the_skills_and_the_skeptic_agent_are_deployed_for_codex(box):
    _setup()
    assert (
        box.home / ".agents" / "skills" / "vhir-welcome" / "SKILL.md"
    ).read_text() == SKILL
    agent = box.home / ".codex" / "agents" / "finding-skeptic.toml"
    assert agent.read_text() == CODEX_AGENT


def test_config_toml_is_never_written_and_a_refused_value_is_named(box, capsys):
    box.config.parent.mkdir(parents=True)
    text = 'model = "gpt"\nsandbox_mode = "danger-full-access"\n\n[tui]\nx = 1\n'
    box.config.write_text(text)
    _setup()
    assert box.config.read_text() == text
    out = capsys.readouterr().out
    assert 'sets sandbox_mode = "danger-full-access"' in out
    assert "vhir doesn't edit that file" in out


def test_an_allowed_config_toml_is_not_named(box, capsys):
    box.config.parent.mkdir(parents=True)
    box.config.write_text('sandbox_mode = "read-only"\napproval_policy = "never"\n')
    _setup()
    assert "managed Codex settings refuse" not in capsys.readouterr().out


def test_the_client_is_recorded_once_in_setup_order(box):
    box.manifest.write_text(json.dumps({"version": "0.6.4", "client": "claude-code"}))
    _setup()
    _setup()
    manifest = json.loads(box.manifest.read_text())
    assert manifest["clients"] == ["claude-code", "codex"]
    assert manifest["client"] == "codex" and manifest["version"] == "0.6.4"


def test_a_restricted_userns_box_gets_the_sandbox_notice(box, tmp_path, capsys):
    sysctl = tmp_path / "userns"
    sysctl.write_text("1\n")
    cs._USERNS_SYSCTL = sysctl  # restored by the fixture's monkeypatch
    _setup()
    assert cs.CODEX_USERNS_NOTICE in capsys.readouterr().out


# --- C.2: protecting the profile ------------------------------------------------


def test_a_profile_vhir_wrote_last_is_updated_and_recorded(box, capsys):
    _setup()
    BACKENDS.append("report-mcp")
    try:
        capsys.readouterr()
        _setup()
    finally:
        BACKENDS.remove("report-mcp")
    assert "report-mcp" in _profile(box)["mcp_servers"]
    assert f"Updated:   {box.profile}" in capsys.readouterr().out
    recorded = json.loads(box.manifest.read_text())["codex_profile_sha256"]
    assert recorded == hashlib.sha256(box.profile.read_bytes()).hexdigest()


def test_a_profile_the_user_edited_is_kept_and_its_diff_hides_the_token(
    box, capsys, monkeypatch
):
    _setup()
    edited = box.profile.read_text() + '\n[mcp_servers.mine]\nurl = "http://x"\n'
    box.profile.write_text(edited)
    BACKENDS.append("report-mcp")
    try:
        capsys.readouterr()
        _setup(ask_user_files=True)  # asks instead of -y applying; no terminal
    finally:
        BACKENDS.remove("report-mcp")
    out = capsys.readouterr().out
    assert box.profile.read_text() == edited  # no terminal: kept
    assert "vhir would change" in out and TOKEN not in out and "vhir_gw_…" in out


def test_with_y_an_edited_profile_is_backed_up_replaced_and_kept_private(box):
    _setup()
    box.profile.write_text(box.profile.read_text() + "# my note\n")
    _setup()  # -y
    assert "# my note" not in box.profile.read_text()
    assert box.profile.stat().st_mode & 0o777 == 0o600
    (bak,) = box.profile.parent.glob("valhuntir.config.toml.vhir-backup-*")
    assert "# my note" in bak.read_text()


# --- update: rebuilt from the box -------------------------------------------------


def test_update_rebuilds_the_backends_and_keeps_a_direct_wintools_entry(box):
    _setup(windows="192.0.2.5:4624", windows_token="vhir_wt_" + "cd" * 12)
    assert "wintools-mcp" in _profile(box)["mcp_servers"]
    BACKENDS.append("report-mcp")
    try:
        assert cs.deploy_codex_assets() == "updated"
    finally:
        BACKENDS.remove("report-mcp")
    servers = _profile(box)["mcp_servers"]
    assert "report-mcp" in servers and "wintools-mcp" in servers
    assert servers["wintools-mcp"]["url"].startswith("https://192.0.2.5:4624")


def test_update_with_the_gateway_down_keeps_the_profile_and_says_so(box, capsys):
    _setup()
    before = box.profile.read_bytes()
    box.gateway["up"] = False
    capsys.readouterr()
    assert cs.deploy_codex_assets() == "kept"
    assert box.profile.read_bytes() == before
    assert "the gateway can't be reached" in capsys.readouterr().out


def test_update_drops_a_backend_the_gateway_no_longer_serves(box):
    BACKENDS.append("report-mcp")
    try:
        _setup()
    finally:
        BACKENDS.remove("report-mcp")
    assert cs.deploy_codex_assets() == "updated"
    assert "report-mcp" not in _profile(box)["mcp_servers"]
