"""Claude Code's controls block says its controls are on only when the
settings file holds every control the shipped template sets, as shipped:
merging the template in would change nothing. Otherwise one line says they
aren't fully applied, and no row of Claude Code's claims protection. The box
is a stand-in SIFT (see test_user_settings_guard); the template has the
shipped shape."""

from __future__ import annotations

import json

import pytest

from vhir_cli import controls
from vhir_cli.commands import client_setup as cs

from .test_user_settings_guard import box  # noqa: F401 (a fixture)

_HOOK = "$CLAUDE_PROJECT_DIR/.claude/hooks/{}"
SHIPPED = {
    "permissions": {
        "deny": ["Edit(**/findings.json)", "Read(//var/lib/vhir/**)", "Edit(//var/lib/vhir/**)"]
    },
    "sandbox": {
        "enabled": True,
        "allowUnsandboxedCommands": False,
        "failIfUnavailable": True,
        "filesystem": {"denyWrite": ["~/.vhir/hooks"], "denyRead": ["/var/lib/vhir"]},
    },
    "hooks": {
        event: [{"matcher": matcher,
                 "hooks": [{"type": "command", "command": _HOOK.format(script)}]}]
        for event, matcher, script in (
            ("SessionStart", "", "case-dir-check.sh"),
            ("PreToolUse", "Bash", "case-data-guard.sh"),
            ("PostToolUse", "Bash", "forensic-audit.sh"),
            ("PostToolUseFailure", "Bash", "forensic-audit.sh"),
            ("PermissionDenied", "Bash", "forensic-audit.sh"),
        )
    },
}  # fmt: skip
CLIENT_ROWS = ("Deny rules", "Sandbox", "Audit", "Case-data guard", "Start-up check")


def _shipped(box):  # noqa: F811
    (box.repo / "claude-code" / "full" / "settings.json").write_text(
        json.dumps(SHIPPED)
    )


def _block(box, capsys):  # noqa: F811
    capsys.readouterr()
    controls.print_block("claude-code", box.settings)
    return capsys.readouterr().out


def _deployed(box):  # noqa: F811
    """The settings as setup writes them on a SIFT box (hooks from ~/.vhir/hooks)."""
    _shipped(box)
    box.settings.unlink(missing_ok=True)
    box.run()
    return json.loads(box.settings.read_text())


def test_the_template_as_deployed_reads_as_the_full_block(box, capsys):  # noqa: F811
    _deployed(box)
    assert cs.settings_applied(box.settings) == (True, False)
    out = _block(box, capsys)
    assert all(f"    {r}: " in out for r in CLIENT_ROWS) and "NOT in effect" not in out


def test_a_kept_0_6_3_settings_file_reads_not_fully_applied(box, capsys):  # noqa: F811
    """Single-slash store rules, a sandbox with no failIfUnavailable and no
    denyRead, and no hook for failed or refused commands."""
    _shipped(box)
    old = json.loads(json.dumps(SHIPPED))
    old["permissions"]["deny"] = ["Edit(**/findings.json)", "Read(/var/lib/vhir/**)"]
    old["sandbox"] = {"enabled": True, "allowUnsandboxedCommands": False}
    for event in ("PostToolUseFailure", "PermissionDenied"):
        del old["hooks"][event]
    box.settings.write_text(json.dumps(old))
    assert box.run(answer="n")[0][1] == "kept"
    out = _block(box, capsys)
    assert (
        f"NOT in effect: Valhuntir's controls aren't fully applied in {box.settings} "
        "(declined or edited); run vhir setup client to apply them." in out
    )
    assert not [r for r in CLIENT_ROWS if f"    {r}:" in out], out


def test_each_missing_control_alone_is_not_fully_applied(box):  # noqa: F811
    full = _deployed(box)
    cuts = {
        "a hook's matcher": lambda s: s["hooks"]["PreToolUse"][0].update(
            matcher="Edit"
        ),
        "a hook event": lambda s: s["hooks"].pop("PermissionDenied"),
        "a deny rule": lambda s: s["permissions"]["deny"].pop(),
        "denyRead": lambda s: s["sandbox"]["filesystem"].pop("denyRead"),
        "the sandbox": lambda s: s["sandbox"].update(enabled=False),
    }
    for what, cut in cuts.items():
        edited = json.loads(json.dumps(full))
        cut(edited)
        box.settings.write_text(json.dumps(edited))
        assert cs.settings_applied(box.settings) == (False, False), what


def test_a_users_own_rules_and_hooks_beside_ours_are_still_fully_applied(box):  # noqa: F811
    full = _deployed(box)
    full["permissions"]["deny"].append("Read(~/.ssh/**)")
    full["hooks"]["PostToolUse"].append(
        {
            "matcher": "Write",
            "hooks": [{"type": "command", "command": "/opt/notify.sh"}],
        }
    )
    full["model"] = "opus"
    box.settings.write_text(json.dumps(full))
    assert cs.settings_applied(box.settings) == (True, False)


def test_the_sandbox_turned_off_by_the_phrase_reads_sandbox_off(box, capsys):  # noqa: F811
    full = _deployed(box)
    full["sandbox"]["failIfUnavailable"] = False
    box.settings.write_text(json.dumps(full))
    assert cs.settings_applied(box.settings) == (True, True)
    assert "    Sandbox: SANDBOX OFF" in _block(box, capsys)


def test_no_settings_file_is_not_applied(box, capsys):  # noqa: F811
    _shipped(box)
    box.settings.unlink(missing_ok=True)
    assert cs.settings_applied(box.settings) == (False, False)
    assert "aren't fully applied" in _block(box, capsys)


def test_uninstall_leaves_no_hook_pointing_into_vhir_hooks(box):  # noqa: F811
    """Every forensic hook of the shipped settings, under every event, is
    removed: none may call a script the uninstall then deletes. A user's own
    hook stays, even in an entry beside ours."""
    full = _deployed(box)
    full.setdefault("hooks", {}).setdefault("UserPromptSubmit", []).append(
        {
            "hooks": [
                {"type": "command", "command": "cat << 'EOF'\n<forensic-rules>\nEOF"}
            ]
        }
    )
    mine = {"type": "command", "command": "/opt/notify.sh"}
    full["hooks"]["PostToolUse"].append({"matcher": "Write", "hooks": [mine]})
    full["hooks"]["PermissionDenied"][0]["hooks"].append(dict(mine))  # beside ours
    box.settings.write_text(json.dumps(full))
    assert str(box.home / ".vhir" / "hooks") in box.settings.read_text()  # deployed so
    cs._remove_forensic_settings(box.settings)
    text = box.settings.read_text()
    assert ".vhir/hooks" not in text and "forensic-rules" not in text
    left = json.loads(text)["hooks"]
    assert left == {
        "PostToolUse": [{"matcher": "Write", "hooks": [mine]}],
        "PermissionDenied": [{"matcher": "Bash", "hooks": [mine]}],
    }


def _claude_copies(home):
    skills, agents = home / ".claude" / "skills", home / ".claude" / "agents"
    for name in ("vhir-welcome", "vhir-playbooks", "finding-skeptic", "my-own"):
        (skills / name).mkdir(parents=True, exist_ok=True)
        (skills / name / "SKILL.md").write_text(f"# {name}\n")
    agents.mkdir(parents=True, exist_ok=True)
    (agents / "finding-skeptic.md").write_text("skeptic\n")
    (agents / "my-agent.md").write_text("mine\n")
    return skills, agents


def test_uninstall_offers_claude_codes_skills_and_agent_and_keeps_the_users(
    box,  # noqa: F811
    monkeypatch,
    capsys,
):
    skills, agents = _claude_copies(box.home)
    asked = []
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda q: asked.append(q) or True)
    cs._uninstall_claude_copies()
    out = capsys.readouterr().out
    assert (
        asked == ["  Remove them?"] and "Claude Code skills and agent to remove" in out
    )
    assert sorted(p.name for p in skills.iterdir()) == ["my-own"]
    assert sorted(p.name for p in agents.iterdir()) == ["my-agent.md"]


def test_declined_the_claude_code_copies_stay(box, monkeypatch):  # noqa: F811
    skills, agents = _claude_copies(box.home)
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda q: False)
    cs._uninstall_claude_copies()
    assert len(list(skills.iterdir())) == 4 and (agents / "finding-skeptic.md").exists()


def test_the_sift_uninstall_offers_claude_codes_copies(box, monkeypatch):  # noqa: F811
    skills, agents = _claude_copies(box.home)
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda q: True)
    monkeypatch.setattr(
        cs, "_remove_vhir_mcp_entries", lambda *a, **k: None, raising=False
    )
    from vhir_cli.commands import codex_controls as cc

    etc = box.home / "etc-codex"  # never the host's /etc/codex
    monkeypatch.setattr(cc, "REQUIREMENTS", etc / "requirements.toml")
    monkeypatch.setattr(cc, "HOOKS_DIR", etc / "vhir-hooks")
    try:
        cs._uninstall_sift()
    except SystemExit:
        pass
    assert sorted(p.name for p in skills.iterdir()) == ["my-own"]
    assert not (agents / "finding-skeptic.md").exists()


def test_a_declined_change_is_said_once_by_setup_and_once_by_update(
    box,  # noqa: F811
    monkeypatch,
    capsys,
):
    full = _deployed(box)
    full["permissions"]["deny"].pop()  # a change the examiner then declines
    box.settings.write_text(json.dumps(full))
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
    monkeypatch.setattr(cs, "_merge_and_write", lambda path, config: None)
    capsys.readouterr()
    cs._generate_config("claude-code", {}, "steve")  # no terminal: kept
    assert capsys.readouterr().out.count("Forensic controls NOT applied") == 1
    from vhir_cli.commands import update

    update._redeploy_clients({"clients": ["claude-code"]})
    assert capsys.readouterr().out.count("Forensic controls NOT applied") == 1


def _uninstall_sift_in(home, monkeypatch, answer):
    """Run the SIFT uninstall under `home`, answering every question `answer`;
    the questions asked are returned."""
    asked = []
    monkeypatch.setattr(cs, "_prompt_yn_strict", lambda q: asked.append(q) or answer)
    monkeypatch.setattr(
        cs, "_remove_vhir_mcp_entries", lambda *a, **k: None, raising=False
    )
    from vhir_cli.commands import codex_controls as cc

    etc = home / "etc-codex"  # never the host's /etc/codex
    monkeypatch.setattr(cc, "REQUIREMENTS", etc / "requirements.toml")
    monkeypatch.setattr(cc, "HOOKS_DIR", etc / "vhir-hooks")
    try:
        cs._uninstall_sift()
    except SystemExit:
        pass
    return asked


def test_the_discipline_docs_step_lists_the_welcome_command_it_removes(
    box,  # noqa: F811
    monkeypatch,
    capsys,
):
    welcome = box.home / ".claude" / "commands" / "welcome.md"
    welcome.parent.mkdir(parents=True, exist_ok=True)
    welcome.write_text("welcome\n")  # with no other discipline doc left
    capsys.readouterr()
    _uninstall_sift_in(box.home, monkeypatch, True)
    out = capsys.readouterr().out
    step = out[out.index("[4] Discipline docs") :]
    assert str(welcome) in step.split("Removed discipline docs.")[0]
    assert not welcome.exists()


def test_declined_the_welcome_command_stays(box, monkeypatch):  # noqa: F811
    welcome = box.home / ".claude" / "commands" / "welcome.md"
    welcome.parent.mkdir(parents=True, exist_ok=True)
    welcome.write_text("welcome\n")
    _uninstall_sift_in(box.home, monkeypatch, False)
    assert welcome.read_text() == "welcome\n"


# The hooks of sift-mcp's shipped templates, as they are in
# claude-code/full/settings.json and claude-code/lite/settings.json
FULL_TEMPLATE_HOOKS = json.loads(
    '{"SessionStart": [{"matcher": "", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/case-dir-check.sh"}]}], "UserPromptSubmit": [{"matcher": "", "hooks": [{"type": "command", "command": "cat << \'EOF\'\\n<forensic-rules>\\nPLAN before 3+ steps | EVIDENCE for claims | APPROVAL before conclusions\\nRECORD actions via forensic-mcp | NO DELETE without approval\\n</forensic-rules>\\nEOF"}]}], "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/case-data-guard.sh"}]}], "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh"}]}], "PostToolUseFailure": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh"}]}], "PermissionDenied": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh"}]}]}'
)
LITE_TEMPLATE_HOOKS = json.loads(
    '{"UserPromptSubmit": [{"matcher": "", "hooks": [{"type": "command", "command": "cat << \'EOF\'\\n<forensic-rules>\\nPLAN before 3+ steps (display numbered checklist BEFORE any tool call) | APPROVAL before conclusions\\nEVIDENCE FORMAT: Source | Extraction | Content | Observation | Interpretation | Confidence | Ask human\\nRECORD actions in ACTIONS.md | NO DELETE without approval\\n</forensic-rules>\\nEOF"}]}], "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/hooks/forensic-audit.sh"}]}]}'
)
# Other forms our hooks have been written in: setup-client-*.sh's absolute
# path, a quoted path, a redirect after the script, arguments, and the braced
# variable
OTHER_FORMS = (
    "/home/u/vhir/.claude/hooks/forensic-audit.sh",
    "${CLAUDE_PROJECT_DIR}/.claude/hooks/forensic-audit.sh",
    "${CLAUDE_PROJECT_DIR}/hooks/forensic-audit.sh",
    '"$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh"',
    "$CLAUDE_PROJECT_DIR/.claude/hooks/forensic-audit.sh>/dev/null",
    "'$CLAUDE_PROJECT_DIR/hooks/case-dir-check.sh' 2>&1",
    "bash $CLAUDE_PROJECT_DIR/.claude/hooks/case-data-guard.sh --strict",
)
USERS_OWN = (
    "/opt/notify.sh",
    "python3 /p/.claude/hooks/run.py --dir /tmp/",
    "/opt/my-forensic-audit.sh",
    "/opt/forensic-audit.sh.bak",
    # a script with one of our names, outside the places setup puts ours
    "/opt/team/case-data-guard.sh",
    "/opt/team/hooks/forensic-audit.sh",
    "bash 'case-dir-check.sh'",
    '"/home/u/scripts/forensic-audit.sh" >/dev/null',
)


def _with_users_own(hooks):
    """`hooks` with each of the user's own commands beside ours, and alone."""
    hooks = json.loads(json.dumps(hooks))
    mine = [{"type": "command", "command": c} for c in USERS_OWN]
    hooks["PostToolUse"][0]["hooks"] += mine
    hooks.setdefault("Stop", []).append({"hooks": list(mine)})
    return hooks


@pytest.mark.parametrize(
    "template", [FULL_TEMPLATE_HOOKS, LITE_TEMPLATE_HOOKS], ids=["full", "lite"]
)
def test_uninstall_removes_every_hook_of_a_shipped_template(box, template):  # noqa: F811
    box.settings.write_text(json.dumps({"hooks": _with_users_own(template)}))
    cs._remove_forensic_settings(box.settings)
    left = json.loads(box.settings.read_text())["hooks"]
    mine = [{"type": "command", "command": c} for c in USERS_OWN]
    assert left == {
        "PostToolUse": [{"matcher": "Bash", "hooks": mine}],
        "Stop": [{"hooks": mine}],
    }


@pytest.mark.parametrize("command", OTHER_FORMS)
def test_uninstall_removes_our_hook_however_its_path_is_written(box, command):  # noqa: F811
    hooks = {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}
    box.settings.write_text(json.dumps({"hooks": _with_users_own(hooks), "x": 1}))
    cs._remove_forensic_settings(box.settings)
    left = json.loads(box.settings.read_text())
    assert command not in json.dumps(left) and left["x"] == 1
    assert [h["command"] for h in left["hooks"]["PostToolUse"][0]["hooks"]] == list(
        USERS_OWN
    )


def test_a_users_hook_ending_in_a_slash_is_kept_and_the_uninstall_goes_on(box):  # noqa: F811
    mine = {"type": "command", "command": "python3 /p/.claude/hooks/run.py --dir /tmp/"}
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [mine]}]}}
    box.settings.write_text(json.dumps(settings))
    cs._remove_forensic_settings(box.settings)
    assert json.loads(box.settings.read_text()) == settings


@pytest.mark.parametrize("command", USERS_OWN[-4:])
def test_a_users_script_with_one_of_our_names_elsewhere_is_kept(box, command):  # noqa: F811
    mine = {"type": "command", "command": command}
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [mine]}]}}
    box.settings.write_text(json.dumps(settings))
    cs._remove_forensic_settings(box.settings)
    assert json.loads(box.settings.read_text()) == settings
