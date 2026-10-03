"""vhir never changes a file the user may have edited without asking.

`vhir update` and `vhir setup client` merged the product settings into
~/.claude/settings.json (flipping the user's sandbox.enabled), overwrote
~/.claude/CLAUDE.md, the rules, commands and hooks, and wiped an unparseable
settings.json: no prompt, no backup. Now an unchanged file isn't touched; a
change is shown and asked about on a terminal (default No), with a backup
first; without a terminal nothing changes. A product file still at a version
vhir shipped is updated with a notice. Everything here is under tmp_path.
"""

from __future__ import annotations

import json
import os
import subprocess
import types

import pytest

from vhir_cli.commands import client_setup as cs

TEMPLATE = {
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
    "permissions": {"allow": ["mcp__vhir__*"], "deny": ["Edit(**/findings.json)"]},
    "sandbox": {"enabled": True, "allowUnsandboxedCommands": False},
}
USER = {
    "model": "opus",
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "Write",
                "hooks": [{"type": "command", "command": "/opt/myhooks/notify.sh"}],
            }
        ]
    },
    "permissions": {"allow": ["Bash(git status)"], "deny": ["Read(~/.ssh/**)"]},
    "sandbox": {"enabled": False, "allowUnsandboxedCommands": True},
}
HOOK_V1 = "#!/bin/bash\n# v1\n"
HOOK_V2 = "#!/bin/bash\n# v2\n"


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
    """A SIFT box: HOME, a gateway.yaml, and the claude-code assets in a git
    checkout whose history holds two versions of case-dir-check.sh."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    repo = tmp_path / "sift-mcp"
    full = repo / "claude-code" / "full"
    (full / "hooks").mkdir(parents=True)
    (full / "commands").mkdir()
    (repo / "claude-code" / "shared").mkdir()
    (full / "hooks" / "case-dir-check.sh").write_text(HOOK_V1)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v1")
    (full / "hooks" / "case-dir-check.sh").write_text(HOOK_V2)
    (full / "hooks" / "forensic-audit.sh").write_text("#!/bin/bash\n# audit\n")
    (full / "settings.json").write_text(json.dumps(TEMPLATE, indent=2))
    (full / "CLAUDE.md").write_text("PRODUCT CLAUDE.md\n")
    (full / "FORENSIC_DISCIPLINE.md").write_text("discipline\n")
    (full / "commands" / "welcome.md").write_text("welcome\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "v2")
    (home / ".vhir").mkdir()
    (home / ".vhir" / "gateway.yaml").write_text(f"sift_mcp_dir: {repo}\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: home))
    monkeypatch.chdir(tmp_path)

    def run(answer=None):
        """Deploy as `vhir update` does: answer=None is no terminal."""
        tty = answer is not None
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: tty))
        asked = []
        monkeypatch.setattr("builtins.input", lambda p="": (asked.append(p), answer)[1])
        return cs._deploy_claude_code_assets(), asked

    settings = home / ".claude" / "settings.json"
    return types.SimpleNamespace(home=home, repo=repo, run=run, settings=settings)


def _pin(path):
    """A hard link: a later replace leaves the pin on the old inode."""
    pin = path.with_name(path.name + ".pin")
    os.link(path, pin)
    return lambda: os.path.samefile(path, pin)


def _write_user(path):
    path.write_text(json.dumps(USER, indent=2))
    return path.read_bytes()


# --- No terminal, a user-customised file ------------------------------------


def test_without_a_terminal_nothing_changes_and_it_says_so(box, capsys):
    before = _write_user(box.settings)
    same = _pin(box.settings)
    result, asked = box.run()
    out = capsys.readouterr().out
    assert box.settings.read_bytes() == before and same() and not asked
    assert "would change" in out and '"enabled"' in out and "vhir update" in out
    assert "Merged:" not in out and "NOT applied" in out
    assert result == (box.settings, "kept")


# --- On a terminal -----------------------------------------------------------


def test_answering_no_keeps_the_file(box):
    before = _write_user(box.settings)
    _, asked = box.run("n")
    assert box.settings.read_bytes() == before
    assert any("[y/N]" in p for p in asked)


def test_answering_yes_applies_after_a_backup(box, capsys):
    before = _write_user(box.settings)
    result, _ = box.run("y")
    out = capsys.readouterr().out
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True
    baks = list(box.settings.parent.glob("settings.json.vhir-backup-*"))
    assert len(baks) == 1 and baks[0].read_bytes() == before and str(baks[0]) in out
    assert result[1] == "written"


# --- Fresh, already deployed, order or format only ---------------------------


@pytest.mark.parametrize("answer", [None, "n"], ids=["no-terminal", "terminal"])
def test_anchor_a_fresh_box_gets_the_template(box, answer):
    box.run(answer)
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True


def test_a_deployed_file_is_left_alone(box):
    box.run()
    before = box.settings.read_bytes()
    same = _pin(box.settings)
    _, asked = box.run("n")
    assert box.settings.read_bytes() == before and same() and not asked


def test_a_symlinked_settings_file_stays_a_symlink(box):
    box.run()
    real = box.home / "dotfiles" / "settings.json"
    real.parent.mkdir()
    box.settings.rename(real)
    box.settings.symlink_to(real)
    box.run()
    assert box.settings.is_symlink()


def test_a_yes_writes_through_a_symlink(box):
    real = box.home / "dotfiles" / "settings.json"
    real.parent.mkdir()
    _write_user(real)
    box.settings.symlink_to(real)
    box.run("y")
    assert (
        box.settings.is_symlink() and json.loads(real.read_text())["sandbox"]["enabled"]
    )


def test_order_or_format_only_differences_are_not_changes(box):
    box.run()
    d = json.loads(box.settings.read_text())
    # first, where sorting would move it: only the order and the indent differ
    d["permissions"]["allow"].insert(0, "mcp__zz-user-server__*")
    box.settings.write_text(json.dumps(d, indent=4) + "\n")
    before = box.settings.read_bytes()
    _, asked = box.run("n")
    assert box.settings.read_bytes() == before and not asked


# --- Unparseable -------------------------------------------------------------


@pytest.mark.parametrize("answer", [None, "y"], ids=["no-terminal", "terminal-yes"])
def test_an_unparseable_file_is_never_wiped(box, answer, capsys):
    box.settings.write_text('{"model": "opus", "permissions": {"deny": ["x"],},}\n')
    before = box.settings.read_bytes()
    box.run(answer)
    assert (
        box.settings.read_bytes() == before
        and "isn't valid JSON" in capsys.readouterr().out
    )


# --- Product-named files -----------------------------------------------------


def test_a_users_claude_md_survives_runs_without_a_terminal(box):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_text("MY OWN GLOBAL INSTRUCTIONS\n")
    box.run()
    box.run()
    assert md.read_text() == "MY OWN GLOBAL INSTRUCTIONS\n"


def test_a_yes_keeps_the_users_claude_md_as_md_bak(box):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_text("MINE\n")
    box.run("y")
    assert md.read_text() == "PRODUCT CLAUDE.md\n"
    assert md.with_suffix(".md.bak").read_text() == "MINE\n"
    assert not [
        p for p in md.parent.iterdir() if p.name.endswith(".md") and "backup" in p.name
    ]


def test_a_locally_edited_hook_is_kept(box, capsys):
    hook = box.home / ".vhir" / "hooks" / "case-dir-check.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text("#!/bin/bash\n# corrected locally\n")
    box.run()
    assert "corrected locally" in hook.read_text()


def test_a_hook_at_an_older_shipped_version_is_updated(box, capsys):
    hook = box.home / ".vhir" / "hooks" / "case-dir-check.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text(HOOK_V1)
    _, asked = box.run()
    assert hook.read_text() == HOOK_V2 and not asked
    assert "Updated:" in capsys.readouterr().out and os.access(hook, os.X_OK)


def test_rules_and_commands_the_user_wrote_are_kept(box):
    welcome = box.home / ".claude" / "commands" / "welcome.md"
    welcome.parent.mkdir(parents=True)
    welcome.write_text("my own welcome\n")
    box.run()
    assert welcome.read_text() == "my own welcome\n"


# --- 1621.5: uninstall leaves a CLAUDE.md vhir didn't ship ------------------


def test_uninstall_keeps_a_claude_md_vhir_did_not_ship(box, capsys):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_text("MINE\n")
    cs._remove_claude_md(md, "")
    assert md.read_text() == "MINE\n" and "Kept" in capsys.readouterr().out


def test_uninstall_removes_a_shipped_claude_md_and_restores_the_backup(box):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_text("PRODUCT CLAUDE.md\n")
    md.with_suffix(".md.bak").write_text("MINE\n")
    cs._remove_claude_md(md, "")
    assert md.read_text() == "MINE\n" and not md.with_suffix(".md.bak").exists()


def test_the_default_answer_is_no(box):
    before = _write_user(box.settings)
    box.run("")
    assert box.settings.read_bytes() == before
