"""Off SIFT (no gateway.yaml), `vhir setup client --client=claude-code`
deploys into the project's .claude/: with a sift-mcp checkout present, that
includes every skill under .claude/skills/ and the skeptic's agent at
.claude/agents/finding-skeptic.md, as SIFT does under ~/.claude/. Uninstall
removes them and leaves the user's own skills and agents alone. Everything
here is under tmp_path.
"""

from __future__ import annotations

import fnmatch
import json
import types

import pytest

from vhir_cli.commands import client_setup as cs

from .test_skill_deploy import AGENT, SKILLS, _git, _tree


@pytest.fixture
def laptop(tmp_path, monkeypatch):
    """A machine without SIFT, with a sift-mcp checkout where vhir looks."""
    home = tmp_path / "home"
    repo = home / ".vhir" / "src" / "sift-mcp"
    full = repo / "claude-code" / "full"
    full.mkdir(parents=True)
    (repo / "claude-code" / "shared").mkdir()
    (full / "settings.json").write_text(json.dumps({"permissions": {"deny": []}}))
    (full / "CLAUDE.md").write_text("PRODUCT CLAUDE.md\n")
    for rel, text in SKILLS.items():
        (repo / "skills" / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / "skills" / rel).write_text(text)
    (repo / "agents" / "finding-skeptic").mkdir(parents=True)
    (repo / "agents" / "finding-skeptic" / "claude.md").write_text(AGENT)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1")
    project = tmp_path / "case-work"
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(project)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert not cs._is_sift()
    claude = project / ".claude"
    return types.SimpleNamespace(
        home=home,
        project=project,
        skills=claude / "skills",
        agent=claude / "agents" / "finding-skeptic.md",
    )


def test_the_project_gets_every_skill_and_the_skeptic_agent(laptop):
    cs._deploy_claude_code_assets(laptop.project)
    assert _tree(laptop.skills) == SKILLS
    assert laptop.agent.read_text() == AGENT
    # nothing under the user's own ~/.claude
    assert not (laptop.home / ".claude" / "skills").exists()
    assert not (laptop.home / ".claude" / "agents").exists()


def test_a_second_setup_leaves_them_as_they_are(laptop):
    cs._deploy_claude_code_assets(laptop.project)
    cs._deploy_claude_code_assets(laptop.project)
    assert _tree(laptop.skills) == SKILLS
    assert laptop.agent.read_text() == AGENT


def _deployed(laptop):
    """The skills and agent as a setup left them (planted, so the uninstall
    rows don't rest on the deploy)."""
    for rel, text in SKILLS.items():
        (laptop.skills / rel).parent.mkdir(parents=True, exist_ok=True)
        (laptop.skills / rel).write_text(text)
    laptop.agent.parent.mkdir(parents=True, exist_ok=True)
    laptop.agent.write_text(AGENT)


def test_uninstall_removes_them_and_keeps_the_user_s_own(laptop, monkeypatch):
    _deployed(laptop)
    mine = laptop.skills / "my-notes"
    mine.mkdir()
    (mine / "SKILL.md").write_text("mine\n")
    my_agent = laptop.agent.parent / "my-agent.md"
    my_agent.write_text("mine\n")
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: True)
    cs._uninstall_project()
    assert sorted(p.name for p in laptop.skills.iterdir()) == ["my-notes"]
    assert not laptop.agent.exists()
    assert (mine / "SKILL.md").read_text() == "mine\n"
    assert my_agent.read_text() == "mine\n"


def test_uninstall_asks_first_and_a_no_keeps_them(laptop, monkeypatch):
    _deployed(laptop)
    asked = []
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: asked.append(m) or False)
    cs._uninstall_project()
    assert asked
    assert _tree(laptop.skills) == SKILLS and laptop.agent.read_text() == AGENT


RULES = ["Edit(/.claude/skills/**)", "Edit(/.claude/agents/**)"]


def _denied(deny, project, path) -> bool:
    """Whether a project-root rule ("/x" in a project settings file is
    <project>/x) covers path; a path outside the project has no such match."""
    try:
        rel = path.relative_to(project).as_posix()
    except ValueError:
        return False
    return any(
        fnmatch.fnmatch(rel, r[len("Edit(/") : -1])
        for r in deny
        if r.startswith("Edit(/") and not r.startswith("Edit(//")
    )


def _project_deny(laptop):
    settings = json.loads((laptop.project / ".claude" / "settings.json").read_text())
    return settings["permissions"]["deny"]


def test_the_project_settings_deny_edits_to_its_skills_and_the_skeptic_agent(laptop):
    """The product settings protect ~/.claude/skills and
    agents, not a project's copies, so the AI could edit the procedures or
    the skeptic's tool limits. The rules are anchored at the project's root."""
    cs._deploy_claude_code_assets(laptop.project)
    deny = _project_deny(laptop)
    assert [r for r in deny if r in RULES] == RULES
    for path in (laptop.skills / "vhir-playbooks" / "SKILL.md", laptop.agent):
        assert _denied(deny, laptop.project, path), path


def test_the_rules_leave_a_claude_folder_elsewhere_alone(laptop):
    """Only the project's own copies: not a .claude/skills under a subfolder
    or in another folder (a "**/" rule would reach both)."""
    cs._deploy_claude_code_assets(laptop.project)
    deny = _project_deny(laptop)
    assert [r for r in deny if r in RULES] == RULES
    assert not any(r.startswith("Edit(**/") for r in deny), deny
    for path in (
        laptop.project / "notes" / ".claude" / "skills" / "mine" / "SKILL.md",
        laptop.project.parent / "other" / ".claude" / "skills" / "mine" / "SKILL.md",
        laptop.project.parent / "other" / ".claude" / "agents" / "mine.md",
    ):
        assert not _denied(deny, laptop.project, path), path


def test_on_sift_the_user_settings_get_neither_rule(laptop):
    """SIFT protects ~/.claude/skills and agents with the product's own
    rules; the project-root rules are for a project's copies only."""
    repo = laptop.home / ".vhir" / "src" / "sift-mcp"
    (laptop.home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {repo}\n")
    assert cs._is_sift()
    cs._deploy_claude_code_assets(laptop.project)
    settings = json.loads((laptop.home / ".claude" / "settings.json").read_text())
    deny = settings["permissions"]["deny"]
    assert not [r for r in deny if r in RULES or r.startswith("Edit(**/.claude/")]
    assert not (laptop.project / ".claude" / "settings.json").exists()


def test_uninstall_removes_both_rules_and_keeps_the_user_s_own(laptop, monkeypatch):
    settings = laptop.project / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({"permissions": {"deny": ["Bash(my-own *)", *RULES]}})
    )
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda m: True)
    cs._uninstall_project()
    assert json.loads(settings.read_text())["permissions"]["deny"] == ["Bash(my-own *)"]
