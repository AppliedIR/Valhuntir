"""Claude Code's controls block says its controls are on only when the
settings file holds every control the shipped template sets, as shipped:
merging the template in would change nothing. Otherwise one line says they
aren't fully applied, and no row of Claude Code's claims protection. The box
is a stand-in SIFT (see test_user_settings_guard); the template has the
shipped shape."""

from __future__ import annotations

import json

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
