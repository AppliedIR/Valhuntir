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
import shutil
import subprocess
import types
from pathlib import Path

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
REQUIREMENTS = (
    "# managed-by: valhuntir\n"
    'allowed_sandbox_modes = ["read-only", "workspace-write"]\n'
    'deny_read = ["/var/lib/vhir", "{home}/.vhir/gateway.yaml"]\n'
    "[[hooks.PreToolUse]]\n"
    'matcher = "^Bash$"\n'
    "[[hooks.PreToolUse.hooks]]\n"
    'type = "command"\n'
    'command = "{hooks}/case-data-guard.sh --client codex"\n'
)


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
    # Codex's managed layer: the requirements template and the hooks it installs
    (repo / "codex" / "requirements.toml").write_text(REQUIREMENTS)
    for hook in (
        "shared/hooks/case-data-guard.sh",
        "shared/hooks/forensic-audit.sh",
        "shared/hooks/codex-stdin-capture.sh",
        "full/hooks/case-dir-check.sh",
        "shared/hooks/codex-skeptic-tools.sh",
    ):
        (repo / "claude-code" / hook).parent.mkdir(parents=True, exist_ok=True)
        (repo / "claude-code" / hook).write_text(f"#!/bin/bash\n# {hook}\n")  # fmt: skip
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
    # /etc/codex is a stand-in folder, and sudo a recording stand-in that does
    # what install and rm would: nothing outside tmp_path is touched
    from vhir_cli.commands import codex_controls as cc

    etc = tmp_path / "etc-codex"
    monkeypatch.setattr(cc, "REQUIREMENTS", etc / "requirements.toml")
    monkeypatch.setattr(cc, "HOOKS_DIR", etc / "vhir-hooks")
    monkeypatch.setattr(cc, "USERNS", tmp_path / "no-such-sysctl")
    sudo = []

    def fake_run(cmd, timeout=None):
        sudo.append(cmd)
        if cmd[1] == "install" and "-d" in cmd:
            cc.HOOKS_DIR.mkdir(parents=True, exist_ok=True)
        elif cmd[1] == "install":
            shutil.copy(cmd[-2], cmd[-1])
        elif cmd[1] == "rm":
            target = Path(cmd[-1])
            if target.is_dir():
                shutil.rmtree(target)
            elif target.exists():
                target.unlink()
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(cc.subprocess, "run", fake_run)
    # this suite's venv may hold opensearch-mcp; the profile rows don't depend on it
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    return types.SimpleNamespace(
        home=home,
        repo=repo,
        manifest=manifest,
        gateway=gateway,
        profile=home / ".codex" / "valhuntir.config.toml",
        config=home / ".codex" / "config.toml",
        etc=etc,
        sudo=sudo,
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
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert cs._wizard_client() == "codex"


# --- C.2: the profile -------------------------------------------------------------


def test_the_profile_holds_every_backend_with_its_token_and_no_tool_prompt(box, capsys):
    _setup()
    assert box.profile.stat().st_mode & 0o777 == 0o600
    p = _profile(box)
    assert p["sandbox_mode"] == "workspace-write"
    assert p["approval_policy"] == "on-request"
    assert p["web_search"] == "disabled"  # hosted tools fire no hooks
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
    assert "replace with their own (the workspace, ~/.vhir read-only)" in out
    assert "stops with an error" not in out  # Codex replaces it: measured, no error
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


def test_setup_with_y_installs_codexs_managed_requirements_and_says_so(box, capsys):
    from vhir_cli.commands import codex_controls as cc

    _setup()  # -y
    out = capsys.readouterr().out
    assert cc.ours(cc.REQUIREMENTS.read_text())
    assert f"{box.home}/.vhir/gateway.yaml" in cc.REQUIREMENTS.read_text()
    assert all(c[:2] == ["sudo", "install"] for c in box.sudo)
    assert "Managed requirements: Codex's shell" in out  # the block reads it as on


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


def test_a_remnux_entry_added_later_is_kept_by_every_update(box):
    """`--add-remnux` passes the entry as extra; a later update (servers None)
    keeps its section, and a new extra of the same name replaces it."""
    _setup()
    remnux = {
        "url": "http://192.0.2.9:3000/mcp",
        "headers": {"Authorization": "Bearer r1"},
    }
    assert cs.deploy_codex_assets(extra={"remnux-mcp": remnux}) == "updated"
    assert _profile(box)["mcp_servers"]["remnux-mcp"]["url"] == remnux["url"]
    cs.deploy_codex_assets()
    assert _profile(box)["mcp_servers"]["remnux-mcp"]["http_headers"] == {
        "Authorization": "Bearer r1"
    }
    cs.deploy_codex_assets(
        extra={"remnux-mcp": {**remnux, "url": "http://192.0.2.9:4000/mcp"}}
    )
    servers = _profile(box)["mcp_servers"]
    assert servers["remnux-mcp"]["url"] == "http://192.0.2.9:4000/mcp"
    assert box.profile.read_text().count("[mcp_servers.remnux-mcp]") == 1


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


# --- Remote Codex (another machine): fetched from sift-mcp on GitHub ----------------

REMOTE = "## Codex on the examiner's machine\n\nNot in the case audit.\n"
SERVED = {
    "skills/MANIFEST": "# listed\nvhir-welcome/SKILL.md\n",
    "skills/vhir-welcome/SKILL.md": SKILL,
    "agents/finding-skeptic/codex.toml": CODEX_AGENT,
    "AGENTS.md": AGENTS,
    "claude-code/full/FORENSIC_DISCIPLINE.md": FD,
    "codex/OVERLAY.md": OVERLAY,
    "codex/REMOTE.md": REMOTE,
}


@pytest.fixture
def laptop(tmp_path, monkeypatch):
    home = tmp_path / "laptop"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(home)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    served = dict(SERVED)
    fetched = []

    def fetch(rel):
        fetched.append(rel)
        return served[rel].encode() if rel in served else None

    monkeypatch.setattr(cs, "_fetch_raw", fetch)
    monkeypatch.setattr(cs, "_probe_health_with_auth", lambda u, t: {"status": "ok"})
    monkeypatch.setattr(
        cs,
        "_discover_services",
        lambda url, token: [{"name": n, "started": True} for n in BACKENDS],
    )
    return types.SimpleNamespace(
        home=home,
        served=served,
        fetched=fetched,
        profile=home / ".codex" / "valhuntir.config.toml",
        config=home / ".codex" / "config.toml",
    )


def _remote(**kw):
    _setup(remote=True, sift="https://sift.example:4508", token=TOKEN, **kw)


def test_remote_codex_writes_the_profile_and_prints_the_limits(laptop, capsys):
    _remote()
    p = tomllib.loads(laptop.profile.read_text())
    assert laptop.profile.stat().st_mode & 0o777 == 0o600
    # no managed requirements here: the profile's own lines are the controls
    assert p["sandbox_mode"] == "workspace-write" and p["web_search"] == "disabled"
    assert p["mcp_servers"]["forensic-mcp"] == {
        "url": "https://sift.example:4508/mcp/forensic-mcp",
        "http_headers": {"Authorization": f"Bearer {TOKEN}"},
        "default_tools_approval_mode": "approve",
    }
    assert (
        p["developer_instructions"]
        == "\n\n".join(x.strip() for x in (AGENTS, FD, OVERLAY, REMOTE)) + "\n"
    )
    out = capsys.readouterr().out
    assert cs.CODEX_REMOTE_LIMITS in out and "cd ~/vhir && codex -p valhuntir" in out
    assert (laptop.home / "vhir").is_dir() and TOKEN not in out


def test_remote_codex_deploys_the_fetched_skills_and_agent(laptop):
    _remote()
    skill = laptop.home / ".agents" / "skills" / "vhir-welcome" / "SKILL.md"
    assert skill.read_text() == SKILL
    agent = laptop.home / ".codex" / "agents" / "finding-skeptic.toml"
    assert agent.read_text() == CODEX_AGENT


def test_remote_codex_never_writes_config_toml(laptop):
    laptop.config.parent.mkdir(parents=True)
    laptop.config.write_bytes(b'model = "gpt"\n')
    _remote()
    assert laptop.config.read_bytes() == b'model = "gpt"\n'


def test_a_remote_re_run_shows_the_diff_and_keeps_a_backup(laptop, capsys):
    _remote()
    laptop.served["codex/REMOTE.md"] = REMOTE + "\nOne more line.\n"
    capsys.readouterr()
    _remote()  # -y
    out = capsys.readouterr().out
    assert "vhir would change" in out and "+One more line." in out
    assert TOKEN not in out
    (bak,) = laptop.profile.parent.glob("valhuntir.config.toml.vhir-backup-*")
    assert "One more line." not in bak.read_text()
    assert "One more line." in laptop.profile.read_text()


def test_a_listed_skill_path_that_could_leave_the_skills_folder_is_refused(
    laptop, capsys
):
    laptop.served["skills/MANIFEST"] = "../../.bashrc\nvhir-welcome/SKILL.md\n"
    laptop.served["skills/../../.bashrc"] = "evil\n"
    _remote()
    assert "skipped an unexpected skills path: ../../.bashrc" in capsys.readouterr().out
    assert "skills/../../.bashrc" not in laptop.fetched
    assert not (laptop.home / ".bashrc").exists()


def test_without_the_instructions_the_profile_isn_t_written(laptop, capsys):
    del laptop.served["codex/REMOTE.md"]
    _remote()
    assert not laptop.profile.exists()
    assert "couldn't be fetched" in capsys.readouterr().out


def test_remote_codex_is_recorded_as_a_client(laptop):
    (laptop.home / ".vhir").mkdir(exist_ok=True)
    manifest = laptop.home / ".vhir" / "manifest.json"
    manifest.write_text("{}")
    _remote()
    assert json.loads(manifest.read_text())["clients"] == ["codex"]


def test_no_remote_block_claims_every_bash_command_is_captured():
    from pathlib import Path

    repo = Path(cs.__file__).resolve().parents[3]
    for f in [
        Path(cs.__file__),
        *(repo / n for n in ("setup-client-linux.sh", "setup-client-macos.sh")),
        repo / "setup-client-windows.ps1",
    ]:
        text = f.read_text()
        assert "captures all Bash" not in text and "(audit logging," not in text, f
        if f.suffix != ".py":
            assert "aren't in the case audit" in text, f


def test_off_sift_claude_code_says_its_shell_isn_t_in_the_case_audit(
    laptop, monkeypatch, capsys
):
    monkeypatch.setattr(
        cs,
        "_deploy_claude_code_assets",
        lambda project_dir=None: (laptop.home / ".claude" / "settings.json", "new"),
    )
    # even with every control in the laptop's settings as shipped
    monkeypatch.setattr(cs, "settings_applied", lambda path: (True, False))
    _remote(client="claude-code")
    out = capsys.readouterr().out
    assert "aren't in the case audit; these settings are user-switchable" in out
    # the block claims nothing of Claude Code's here: there is no case
    assert "recorded in the active case" not in out
    rows = ("Deny rules", "Sandbox", "Audit", "Case-data guard", "Start-up check")
    assert not [r for r in rows if f"    {r}:" in out], out
    assert "    Signed approvals:" in out  # the gateway's, which hold


def test_uninstall_removes_only_the_profile_and_vhir_s_skills_and_agent(
    laptop, monkeypatch
):
    _remote()
    laptop.config.write_bytes(b'model = "gpt"\n')
    mine = laptop.home / ".agents" / "skills" / "my-notes"
    mine.mkdir()
    (mine / "SKILL.md").write_text("mine\n")
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: True)
    cs._uninstall_project()
    assert not laptop.profile.exists()
    assert not (laptop.home / ".agents" / "skills" / "vhir-welcome").exists()
    assert not (laptop.home / ".codex" / "agents" / "finding-skeptic.toml").exists()
    assert laptop.config.read_bytes() == b'model = "gpt"\n'
    assert (mine / "SKILL.md").read_text() == "mine\n"


@pytest.mark.parametrize(
    "line,secret",
    [
        (f'http_headers = {{ Authorization = "Bearer {TOKEN}" }}', TOKEN[8:]),
        ('http_headers = { Authorization = "Bearer remnux-s3cr3t-T0k" }', "s3cr3t"),
    ],
    ids=["gateway", "remnux"],
)
def test_the_profile_diff_hides_every_bearer_token(line, secret):
    shown = cs._redact_tokens(line)
    assert secret not in shown and "Bearer " in shown and "…" in shown


def test_uninstall_unlinks_a_linked_skill_folder_and_keeps_its_target(
    laptop, monkeypatch
):
    _remote()
    target = laptop.home / "elsewhere" / "vhir-mine"
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text("kept\n")
    link = laptop.home / ".agents" / "skills" / "vhir-linked"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: True)
    cs._uninstall_project()
    assert not link.exists() and not link.is_symlink()
    assert (target / "SKILL.md").read_text() == "kept\n"


# --- Codex's CA on a TLS gateway ------------------------------------------------

MARK = "  # vhir-codex-ca"


@pytest.fixture
def tls_box(box, monkeypatch):
    """The SIFT box with its gateway on TLS, and the user's ~/.bashrc."""
    for var in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    gw = box.home / ".vhir" / "gateway.yaml"
    gw.write_text(gw.read_text() + "gateway:\n  tls:\n    certfile: cert.pem\n")
    box.ca = box.home / ".vhir" / "tls" / "ca-cert.pem"
    box.ca.parent.mkdir()
    box.ca.write_text("-----BEGIN CERTIFICATE-----\n")
    box.rc = box.home / ".bashrc"
    box.rc.write_text("alias ll='ls -l'")  # no final newline
    return box


def _tls_setup(**kw):
    _setup(sift="https://127.0.0.1:4508", **kw)


def _ca_lines(rc):
    return [x for x in rc.read_text().splitlines() if x.endswith(MARK)]


def test_a_tls_gateway_has_codex_trust_its_ca_from_the_shell_profile(tls_box, capsys):
    tls_box.rc.chmod(0o600)
    _tls_setup()
    assert tls_box.rc.read_text() == (
        f"alias ll='ls -l'\nexport CODEX_CA_CERTIFICATE={tls_box.ca}{MARK}\n"
    )
    assert tls_box.rc.stat().st_mode & 0o777 == 0o600
    out = capsys.readouterr().out
    assert f"export CODEX_CA_CERTIFICATE={tls_box.ca}" in out
    # a re-run changes nothing and says nothing
    _tls_setup()
    assert _ca_lines(tls_box.rc) == [f"export CODEX_CA_CERTIFICATE={tls_box.ca}{MARK}"]
    assert "Codex CA:" not in capsys.readouterr().out


def test_a_stale_ca_line_is_replaced_even_when_the_shell_exported_it(
    tls_box, monkeypatch
):
    tls_box.rc.write_text(f"export CODEX_CA_CERTIFICATE=/old/ca.pem{MARK}\nalias x=y\n")
    monkeypatch.setenv("CODEX_CA_CERTIFICATE", "/old/ca.pem")
    _tls_setup()
    assert tls_box.rc.read_text() == (
        f"alias x=y\nexport CODEX_CA_CERTIFICATE={tls_box.ca}{MARK}\n"
    )


def test_vhir_update_adds_the_ca_line_to_an_existing_install(tls_box):
    tls_box.ca.unlink()
    _tls_setup()
    assert _ca_lines(tls_box.rc) == []
    tls_box.ca.write_text("-----BEGIN CERTIFICATE-----\n")
    assert cs.deploy_codex_assets() == "unchanged"
    assert _ca_lines(tls_box.rc) == [f"export CODEX_CA_CERTIFICATE={tls_box.ca}{MARK}"]


@pytest.mark.parametrize("var", ["CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"])
def test_a_bundle_the_user_set_is_named_and_not_overridden(
    tls_box, monkeypatch, capsys, var
):
    monkeypatch.setenv(var, "/etc/corp-bundle.pem")
    _tls_setup()
    assert tls_box.rc.read_text() == "alias ll='ls -l'"
    out = capsys.readouterr().out
    assert f"{var} is set to /etc/corp-bundle.pem" in out and str(tls_box.ca) in out


def test_without_a_shell_profile_the_start_line_is_printed(tls_box, capsys):
    tls_box.rc.unlink()
    _tls_setup()
    assert not tls_box.rc.exists()
    out = capsys.readouterr().out
    assert f"CODEX_CA_CERTIFICATE={tls_box.ca} codex -p valhuntir" in out


def test_a_linked_shell_profile_is_written_through_its_link(tls_box):
    real = tls_box.home / "dotfiles" / "bashrc"
    real.parent.mkdir()
    real.write_text("alias x=y\n")
    tls_box.rc.unlink()
    tls_box.rc.symlink_to(real)
    _tls_setup()
    assert tls_box.rc.is_symlink()
    assert (
        real.read_text()
        == f"alias x=y\nexport CODEX_CA_CERTIFICATE={tls_box.ca}{MARK}\n"
    )


def test_an_http_gateway_leaves_the_shell_profile_alone(box, capsys):
    rc = box.home / ".bashrc"
    rc.write_text("alias x=y\n")
    _setup(windows="192.0.2.5:4624", windows_token="vhir_wt_" + "cd" * 12)
    assert rc.read_text() == "alias x=y\n"
    assert "CODEX_CA" not in capsys.readouterr().out


def test_remote_codex_trusts_the_ca_copied_from_the_sift(laptop, monkeypatch, capsys):
    for var in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    rc = laptop.home / ".bashrc"
    rc.write_text("alias x=y\n")
    _remote()
    assert rc.read_text() == "alias x=y\n"
    assert "copy the SIFT's ~/.vhir/tls/ca-cert.pem" in capsys.readouterr().out
    ca = laptop.home / ".vhir" / "tls" / "ca-cert.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    _remote()
    assert _ca_lines(rc) == [f"export CODEX_CA_CERTIFICATE={ca}{MARK}"]


def test_uninstall_removes_the_ca_line_and_keeps_the_rest(laptop, monkeypatch):
    for var in ("CODEX_CA_CERTIFICATE", "SSL_CERT_FILE"):
        monkeypatch.delenv(var, raising=False)
    ca = laptop.home / ".vhir" / "tls" / "ca-cert.pem"
    ca.parent.mkdir(parents=True)
    ca.write_text("x")
    rc = laptop.home / ".bashrc"
    rc.write_text("alias x=y\n")
    _remote()
    # the line as an earlier setup wrote it, then a line of the user's
    rc.write_text(f"alias x=y\nexport CODEX_CA_CERTIFICATE={ca}{MARK}\nexport P=1\n")
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: True)
    cs._uninstall_project()
    assert rc.read_text() == "alias x=y\nexport P=1\n"
