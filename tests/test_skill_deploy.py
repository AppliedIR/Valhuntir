"""On SIFT, setup and update deploy the skills and the skeptic's agent.

Every folder in sift-mcp's `skills/` goes to `~/.claude/skills/`, and
`agents/finding-skeptic/claude.md` to `~/.claude/agents/finding-skeptic.md`,
file by file: a version vhir shipped is updated, and an edited one isn't
overwritten without consent. `~/.claude/rules/TOOL_REFERENCE.md` retires (a
shipped copy is removed; an edited one is kept with a notice), and
`~/.claude/commands/welcome.md` becomes a pointer to the vhir-welcome skill. The user's own
skills are never touched. Everything here is under tmp_path.
"""

from __future__ import annotations

import json
import subprocess
import types

import pytest

from vhir_cli.commands import client_setup as cs

SKILLS = {
    "vhir-welcome/SKILL.md": "---\nname: vhir-welcome\ndescription: w\n---\n\nwelcome\n",
    "vhir-playbooks/SKILL.md": "---\nname: vhir-playbooks\ndescription: p\n---\n\nidx\n",
    "vhir-playbooks/references/lateral.md": "# Lateral movement\n",
    "finding-skeptic/SKILL.md": "---\nname: finding-skeptic\ndescription: s\n---\n\nx\n",
}
AGENT = "---\nname: finding-skeptic\ndescription: s\ntools: mcp__a__b\n---\n\npart\n"
TR_V1, TR_V2 = "tool reference v1\n", "tool reference v2\n"
WELCOME_V1 = "welcome command v1\n"
POINTER = "Run the `vhir-welcome` skill now.\n"


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
    """A SIFT box whose sift-mcp checkout once shipped commands/welcome.md
    and an older TOOL_REFERENCE.md, and now ships skills and agents."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    repo = tmp_path / "sift-mcp"
    full = repo / "claude-code" / "full"
    (full / "commands").mkdir(parents=True)
    (repo / "claude-code" / "shared").mkdir()
    (full / "TOOL_REFERENCE.md").write_text(TR_V1)
    (full / "commands" / "welcome.md").write_text(WELCOME_V1)
    (full / "settings.json").write_text(json.dumps({"permissions": {"deny": []}}))
    (full / "CLAUDE.md").write_text("PRODUCT CLAUDE.md\n")
    (full / "FORENSIC_DISCIPLINE.md").write_text("discipline\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1")
    (full / "commands" / "welcome.md").write_text(POINTER)
    (full / "TOOL_REFERENCE.md").write_text(TR_V2)
    for rel, text in SKILLS.items():
        (repo / "skills" / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / "skills" / rel).write_text(text)
    (repo / "agents" / "finding-skeptic").mkdir(parents=True)
    (repo / "agents" / "finding-skeptic" / "claude.md").write_text(AGENT)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v2")
    (home / ".vhir").mkdir()
    (home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {repo}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    claude = home / ".claude"
    return types.SimpleNamespace(
        home=home,
        repo=repo,
        skills=claude / "skills",
        agent=claude / "agents" / "finding-skeptic.md",
        tr=claude / "rules" / "TOOL_REFERENCE.md",
        welcome=claude / "commands" / "welcome.md",
        run=cs._deploy_claude_code_assets,
    )


def _tree(folder):
    return {
        str(p.relative_to(folder)): p.read_text()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def test_every_skill_and_the_skeptic_agent_are_deployed_equal_to_the_source(box):
    box.run()
    assert _tree(box.skills) == SKILLS
    assert box.agent.read_text() == AGENT
    assert not box.tr.exists() and box.welcome.read_text() == POINTER


def test_a_skill_from_an_older_release_is_updated_and_an_edited_one_kept(box, capsys):
    box.run()
    welcome = box.skills / "vhir-welcome" / "SKILL.md"
    playbooks = box.skills / "vhir-playbooks" / "SKILL.md"
    new = SKILLS["vhir-welcome/SKILL.md"].replace("welcome\n", "welcome v3\n")
    (box.repo / "skills" / "vhir-welcome" / "SKILL.md").write_text(new)
    _git(box.repo, "commit", "-q", "-am", "v3")
    playbooks.write_text("my own edit\n")
    capsys.readouterr()
    box.run()
    out = capsys.readouterr().out
    assert welcome.read_text() == new
    assert f"Updated:   {welcome} (an earlier version vhir shipped)" in out
    assert playbooks.read_text() == "my own edit\n"  # no terminal: kept


def test_the_user_s_own_skills_and_agents_are_left_alone(box):
    mine = box.skills / "my-notes" / "SKILL.md"
    mine.parent.mkdir(parents=True)
    mine.write_text("---\nname: my-notes\ndescription: mine\n---\n")
    other = box.agent.with_name("my-agent.md")
    other.parent.mkdir(parents=True, exist_ok=True)
    other.write_text("mine\n")
    box.run()
    assert mine.read_text().endswith("description: mine\n---\n")
    assert other.read_text() == "mine\n"


@pytest.mark.parametrize("which", ["tr"])
def test_a_retired_file_vhir_shipped_is_removed(box, capsys, which):
    path = getattr(box, which)
    path.parent.mkdir(parents=True)
    path.write_text(TR_V1 if which == "tr" else WELCOME_V1)  # an older release's
    box.run()
    assert not path.exists()
    skill = "vhir-tool-reference" if which == "tr" else "vhir-welcome"
    assert f"Removed:   {path} (now the {skill} skill)" in capsys.readouterr().out


@pytest.mark.parametrize("which", ["tr"])
def test_a_retired_file_with_the_user_s_edits_is_kept_with_a_notice(box, capsys, which):
    path = getattr(box, which)
    path.parent.mkdir(parents=True)
    path.write_text("my own notes\n")
    box.run()
    assert path.read_text() == "my own notes\n"
    out = capsys.readouterr().out
    assert f"Kept:      {path}: it differs from every version vhir shipped" in out
    assert "vhir no longer uses it" in out


def test_the_audit_hooks_route_table_and_sidecar_are_deployed_beside_them(box):
    hooks = box.repo / "claude-code" / "shared" / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    (hooks / "mcp-route.py").write_text("# sidecar\n")
    (hooks / "mcp-routes.tsv").write_text("vol\tsift-mcp run_command\tvol3\n")
    box.run()
    deployed = box.home / ".vhir" / "hooks"
    assert (deployed / "mcp-route.py").read_text() == "# sidecar\n"
    assert (deployed / "mcp-routes.tsv").read_text().startswith("vol\t")


def test_an_old_welcome_command_becomes_the_pointer_and_an_edited_one_is_kept(
    box, capsys
):
    box.welcome.parent.mkdir(parents=True)
    box.welcome.write_text(WELCOME_V1)  # an older release's
    box.run()
    assert box.welcome.read_text() == POINTER
    assert f"Updated:   {box.welcome}" in capsys.readouterr().out
    box.welcome.write_text("my own welcome\n")
    box.run()  # no terminal: kept
    assert box.welcome.read_text() == "my own welcome\n"
