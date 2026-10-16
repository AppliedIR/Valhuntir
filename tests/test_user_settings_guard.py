"""vhir never changes a file the user may have edited without asking.

`vhir update` and `vhir setup client` merged the product settings into
~/.claude/settings.json (flipping the user's sandbox.enabled), overwrote
~/.claude/CLAUDE.md, the rules, commands and hooks, and wiped an unparseable
settings.json: no prompt, no backup. Now an unchanged file isn't touched; a
change is shown and asked about on a terminal (default Yes; n/no keeps), with
a backup first; without a terminal nothing changes. A product file still at a version
vhir shipped is updated with a notice. Everything here is under tmp_path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
def box(tmp_path, monkeypatch, request):
    """A SIFT box: HOME, a gateway.yaml, and the claude-code assets in a git
    checkout whose history holds two versions of case-dir-check.sh."""
    home = tmp_path / getattr(request, "param", "home")
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
    assert "Merged:" not in out  # setup and update then say NOT applied, once
    assert result == (box.settings, "kept")


# --- On a terminal -----------------------------------------------------------


def test_answering_no_keeps_the_file(box):
    before = _write_user(box.settings)
    _, asked = box.run("n")
    assert box.settings.read_bytes() == before
    assert any("[Y/n]" in p for p in asked)


def test_a_mistyped_refusal_keeps_the_file_and_writes_no_backup(box):
    before = _write_user(box.settings)
    _, asked = box.run("nope")
    assert box.settings.read_bytes() == before
    assert not list(box.settings.parent.glob("settings.json.vhir-backup-*"))
    assert any("[Y/n]" in p for p in asked)


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


def test_the_default_answer_is_yes(box):
    # Enter applies the change (keeping a backup of the old file).
    before = _write_user(box.settings)
    result, _ = box.run("")
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True
    baks = list(box.settings.parent.glob("settings.json.vhir-backup-*"))
    assert len(baks) == 1 and baks[0].read_bytes() == before
    assert result[1] == "written"


# --- CORRECTION 1 -------------------------------------------------------------


def test_a_planted_temp_symlink_is_not_followed(box):
    _write_user(box.settings)
    victim = box.home / "victim.txt"
    victim.write_text("precious\n")
    (box.settings.parent / ".settings.json.vhir-tmp").symlink_to(victim)
    box.run("y")
    assert victim.read_text() == "precious\n" and not box.settings.is_symlink()
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True


def _with_deprecated_hook(box):
    hook = box.home / ".vhir" / "hooks" / "pre-bash-guard.sh"
    hook.parent.mkdir(parents=True)
    hook.write_text("#!/bin/bash\n")
    data = json.loads(json.dumps(USER))
    data["hooks"]["PreToolUse"] = [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": str(hook)}]}
    ]
    box.settings.write_text(json.dumps(data, indent=2))
    return hook


def test_a_hook_kept_settings_still_run_is_not_deleted(box):
    hook = _with_deprecated_hook(box)
    box.run()  # no terminal: the settings are kept
    assert "pre-bash-guard.sh" in box.settings.read_text() and hook.is_file()


def test_anchor_the_hook_goes_once_the_settings_drop_it(box):
    hook = _with_deprecated_hook(box)
    box.run("y")
    assert "pre-bash-guard.sh" not in box.settings.read_text() and not hook.exists()


def test_uninstall_without_the_assets_keeps_claude_md(box, monkeypatch, capsys):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_text("PRODUCT CLAUDE.md\n")
    monkeypatch.setattr(cs, "_find_claude_code_assets", lambda: None)
    cs._remove_claude_md(md, "")
    assert md.is_file() and "Kept" in capsys.readouterr().out


def test_a_claude_md_that_isnt_utf8_is_kept_and_the_rest_deploys(box, capsys):
    md = box.home / ".claude" / "CLAUDE.md"
    md.write_bytes(b"caf\xe9\n")
    box.run()
    assert (
        md.read_bytes() == b"caf\xe9\n"
        and "can't be compared as text" in capsys.readouterr().out
    )
    assert (box.home / ".claude" / "rules" / "FORENSIC_DISCIPLINE.md").is_file()


# --- ~/.claude.json ----------------------------------------------------------
# Valhuntir's own MCP entries are still registered without a prompt, but with
# a timestamped backup first and a notice of exactly what changed; the
# fallback never overwrites an unparseable file.

SERVERS = {
    "vhir": {
        "type": "http",
        "url": "http://127.0.0.1:4508/mcp/vhir",
        "headers": {"A": "1"},
    },
    "mslearn": {"type": "http", "url": "https://learn.example/mcp"},
}


@pytest.fixture
def claude_json(box, monkeypatch):
    path = box.home / ".claude.json"
    monkeypatch.setattr(
        cs, "_deploy_claude_code_assets", lambda project_dir=None, remote_ca=None: None
    )
    calls = []

    def fake_add(name, entry):  # what `claude mcp add -s user` stores
        calls.append(name)
        data = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(data.get("mcpServers"), dict):  # as the real CLI does
            data["mcpServers"] = {}
        data["mcpServers"][name] = {
            k: entry[k] for k in ("type", "url", "headers") if k in entry
        }
        path.write_text(json.dumps(data))

    monkeypatch.setattr(cs, "_claude_mcp_add", fake_add)

    def setup(cli=True):
        monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: cli)
        cs._generate_config("claude-code", json.loads(json.dumps(SERVERS)), "steve")

    return types.SimpleNamespace(path=path, setup=setup, calls=calls)


def _backups(path):
    return sorted(path.parent.glob(path.name + ".vhir-backup-*"))


@pytest.mark.parametrize("cli", [True, False], ids=["claude-cli", "fallback"])
def test_a_backup_and_a_notice_before_changing_claude_json(claude_json, capsys, cli):
    edited = dict(
        SERVERS["vhir"], url="http://10.0.0.9:4508/mcp/vhir"
    )  # the user's edit
    claude_json.path.write_text(
        json.dumps({"projects": {"x": 1}, "mcpServers": {"vhir": edited}})
    )
    before = claude_json.path.read_bytes()
    claude_json.setup(cli)
    out = capsys.readouterr().out
    baks = _backups(claude_json.path)
    assert len(baks) == 1 and baks[0].read_bytes() == before and str(baks[0]) in out
    assert "entries added: mslearn" in out and "entries updated: vhir" in out
    data = json.loads(claude_json.path.read_text())
    assert data["mcpServers"]["vhir"]["url"] == SERVERS["vhir"]["url"]  # still updated
    assert data["projects"] == {"x": 1}


def test_the_fallback_never_overwrites_an_unparseable_claude_json(claude_json, capsys):
    claude_json.path.write_text('{"projects": {"x": 1},}')
    before = claude_json.path.read_bytes()
    claude_json.setup(cli=False)
    assert claude_json.path.read_bytes() == before
    assert "isn't valid JSON" in capsys.readouterr().err


def test_nothing_to_change_means_no_write_and_no_backup(claude_json):
    claude_json.setup()
    claude_json.calls.clear()
    before = claude_json.path.read_bytes()
    claude_json.setup()
    assert claude_json.path.read_bytes() == before and not claude_json.calls
    assert _backups(claude_json.path) == []


def test_the_fallback_keeps_fields_the_user_added_to_an_unchanged_entry(claude_json):
    mine = dict(SERVERS["mslearn"], oauth={"client": "mine"})
    claude_json.path.write_text(json.dumps({"mcpServers": {"mslearn": mine}}))
    claude_json.setup(cli=False)
    data = json.loads(claude_json.path.read_text())["mcpServers"]
    assert data["mslearn"]["oauth"] == {"client": "mine"} and "vhir" in data


@pytest.mark.parametrize("cli", [True, False], ids=["claude-cli", "fallback"])
def test_a_null_entry_is_replaced_with_a_notice(claude_json, capsys, cli):
    claude_json.path.write_text(json.dumps({"mcpServers": {"vhir": None}}))
    claude_json.setup(cli)
    data = json.loads(claude_json.path.read_text())["mcpServers"]
    assert data["vhir"]["url"] == SERVERS["vhir"]["url"]
    assert "entries updated: vhir" in capsys.readouterr().out


@pytest.mark.parametrize("status,claims", [("kept", False), ("written", True)])
def test_setup_claims_global_controls_only_when_applied(
    box, monkeypatch, capsys, status, claims
):
    monkeypatch.setattr(
        cs,
        "_deploy_claude_code_assets",
        lambda project_dir=None, remote_ca=None: (box.settings, status),
    )
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
    monkeypatch.setattr(cs, "_merge_and_write", lambda path, config: None)
    cs._generate_config("claude-code", {}, "steve")
    out = capsys.readouterr().out
    assert ("Forensic controls deployed globally." in out) is claims
    assert ("Forensic controls NOT applied" in out) is not claims
    # the block reads the file itself: here there is none, so no row claims it
    assert f"Valhuntir's controls aren't fully applied in {box.settings}" in out
    assert "    Deny rules:" not in out


def test_a_null_mcpservers_map_is_registered_into_not_a_crash(claude_json, capsys):
    claude_json.path.write_text(json.dumps({"projects": {}, "mcpServers": None}))
    claude_json.setup(cli=True)
    out = capsys.readouterr().out
    assert "entries added: vhir" in out and len(_backups(claude_json.path)) == 1
    assert json.loads(claude_json.path.read_text())["mcpServers"]["vhir"]["url"]


def test_a_stdio_entry_does_not_back_up_and_announce_on_every_run(claude_json, capsys):
    stdio = {"opensearch-mcp": {"command": "/x/opensearch-mcp", "args": []}}
    claude_json.setup(cli=True)
    capsys.readouterr()
    for _ in range(2):
        cs._generate_config(
            "claude-code", {**json.loads(json.dumps(SERVERS)), **stdio}, "s"
        )
    assert (
        _backups(claude_json.path) == []
        and "entries added" not in capsys.readouterr().out
    )


# --- `vhir setup client -y` applies, with a backup, an alert and
# an undo block printed at exit; --ask-user-files keeps asking ----------------


def _setup_args(**kw):
    import argparse

    base = dict(
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
    return argparse.Namespace(**{**base, **kw})


@pytest.fixture
def setup(box, monkeypatch):
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)

    def run(answer=None, **kw):
        tty = answer is not None
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: tty))
        asked = []
        monkeypatch.setattr("builtins.input", lambda p="": (asked.append(p), answer)[1])
        cs.cmd_setup_client(_setup_args(**kw), {"examiner": "steve"})
        return asked

    return run


def _undo_lines(out):
    return [ln.strip() for ln in out.splitlines() if ln.strip().startswith("cp -p ")]


def test_y_applies_with_a_backup_an_alert_and_a_working_undo(box, setup, capsys):
    before = _write_user(box.settings)
    asked = setup()  # -y, no terminal
    cap = capsys.readouterr()
    data = json.loads(box.settings.read_text())
    assert data["sandbox"]["enabled"] is True and not asked
    assert "Read(~/.ssh/**)" in data["permissions"]["deny"]  # the user's own rule kept
    (bak,) = box.settings.parent.glob("settings.json.vhir-backup-*")
    assert bak.read_bytes() == before
    assert f"*** -y: vhir CHANGED {box.settings}" in cap.err
    assert "not inside a Claude session" in cap.out
    undo = [ln for ln in _undo_lines(cap.out) if str(box.settings) in ln]
    assert len(undo) == 1
    subprocess.run(undo[0], shell=True, check=True)
    assert box.settings.read_bytes() == before  # the undo restores it exactly


def test_the_undo_block_prints_even_after_an_error(box, setup, monkeypatch, capsys):
    _write_user(box.settings)

    def boom(*a, **k):
        raise RuntimeError("late failure")

    real = cs._deploy_claude_code_assets
    monkeypatch.setattr(
        cs,
        "_deploy_claude_code_assets",
        lambda p=None, remote_ca=None: (real(p, remote_ca=remote_ca), boom())[0],
    )
    with pytest.raises(RuntimeError):
        setup()
    assert cs._APPLIED is None  # reset even after the error
    assert [
        ln for ln in _undo_lines(capsys.readouterr().out) if str(box.settings) in ln
    ]


def test_ask_user_files_asks_on_a_terminal_even_with_y(box, setup, capsys):
    before = _write_user(box.settings)
    asked = setup("n", ask_user_files=True)
    assert box.settings.read_bytes() == before and any("[Y/n]" in p for p in asked)
    assert not _undo_lines(capsys.readouterr().out)


def test_ask_user_files_without_a_terminal_keeps_the_file(box, setup):
    before = _write_user(box.settings)
    setup(ask_user_files=True)
    assert box.settings.read_bytes() == before


def test_anchor_vhir_update_without_a_terminal_still_keeps(box, capsys):
    before = _write_user(box.settings)
    result, _ = box.run()  # _deploy_claude_code_assets alone, as `vhir update` calls it
    assert box.settings.read_bytes() == before and result[1] == "kept"


def test_anchor_a_fresh_file_is_created_with_no_undo_line(box, setup, capsys):
    setup()
    out = capsys.readouterr().out
    assert box.settings.is_file()
    assert not [ln for ln in _undo_lines(out) if str(box.settings) in ln]


def test_y_leaves_the_projects_agents_md_and_installs_the_product_rule(
    box, setup, monkeypatch
):
    (box.repo / "AGENTS.md").write_text("PRODUCT AGENTS\n")
    monkeypatch.setattr(  # where an install finds it: after the cwd candidate
        cs,
        "_AGENTS_MD_CANDIDATES",
        cs._AGENTS_MD_CANDIDATES + [lambda: box.repo / "AGENTS.md"],
    )
    project = box.home.parent / "AGENTS.md"  # the cwd: some repo's own file
    project.write_text("SOME REPO'S AGENT INSTRUCTIONS\n")
    setup()
    assert project.read_text() == "SOME REPO'S AGENT INSTRUCTIONS\n"
    rule = box.home / ".claude" / "rules" / "AGENTS.md"
    assert rule.read_text() == "PRODUCT AGENTS\n"


@pytest.mark.parametrize("box", ["my home"], indirect=True)
def test_the_undo_works_with_a_space_in_the_path(box, setup, capsys):
    before = _write_user(box.settings)
    setup()
    (undo,) = [
        ln for ln in _undo_lines(capsys.readouterr().out) if "settings.json" in ln
    ]
    subprocess.run(undo, shell=True, check=True)
    assert box.settings.read_bytes() == before


def test_the_y_flag_is_reset_after_setup(box, setup):
    setup()
    assert cs._APPLIED is None
    before = _write_user(box.settings)
    box.run()  # a later deploy without -y, no terminal: keeps
    assert box.settings.read_bytes() == before


def test_the_claude_json_backup_is_in_the_undo_block(box, setup, capsys):
    path = box.home / ".claude.json"
    path.write_text(json.dumps({"projects": {"x": 1}, "mcpServers": {"old": {}}}))
    before = path.read_bytes()
    setup()  # -y, no terminal; the fallback registers the MCP entries
    assert path.read_bytes() != before
    out = capsys.readouterr().out
    lines = [ln.strip() for ln in out.splitlines()]
    (undo,) = [
        ln for ln in lines if ln.startswith("cp -p ") and ln.endswith(".claude.json")
    ]
    note = lines[lines.index(undo) - 1]
    assert note.startswith("#") and "Claude Code" in note and "close" in note
    subprocess.run(undo, shell=True, check=True)
    assert path.read_bytes() == before


# --- -y's undo also restores the deprecated hook it removed -------------------


def test_y_undo_also_restores_the_deprecated_hook(box, setup, capsys):
    hook = _with_deprecated_hook(box)
    hook.chmod(0o755)
    before = box.settings.read_bytes(), hook.read_bytes()
    setup(sift="http://127.0.0.1:9")  # -y, no terminal; no gateway
    assert not hook.exists()
    for ln in _undo_lines(capsys.readouterr().out):
        subprocess.run(ln, shell=True, check=True)
    assert (box.settings.read_bytes(), hook.read_bytes()) == before
    assert os.access(hook, os.X_OK)  # a backup that lost its mode can't run


def test_anchor_no_deprecated_hook_no_backup_and_no_undo_line(box, setup, capsys):
    setup(sift="http://127.0.0.1:9")
    out = capsys.readouterr().out
    assert "pre-bash-guard" not in out
    assert not list(box.home.rglob("pre-bash-guard.sh*"))


def _tls_box(box):
    """Make `box`'s local gateway use TLS with a CA present, keeping
    sift_mcp_dir so the claude-code assets are still found. Returns the CA's
    absolute path (what a local client must trust)."""
    (box.home / ".vhir" / "gateway.yaml").write_text(
        f"sift_mcp_dir: {box.repo}\n"
        "gateway:\n  port: 4508\n  tls:\n    certfile: /x/server-cert.pem\n"
    )
    ca = box.home / ".vhir" / "tls" / "ca-cert.pem"
    ca.parent.mkdir(parents=True, exist_ok=True)
    ca.write_text("dummy")
    return str(ca)


class TestLocalCaTrust:
    """A local Claude Code must trust the gateway's self-signed CA under a
    TLS (--remote) gateway, or every gateway MCP connection fails with
    UNABLE_TO_VERIFY_LEAF_SIGNATURE. The deploy adds env.NODE_EXTRA_CA_CERTS
    to settings.json when the local gateway uses TLS and the CA exists — but
    never over a NODE_EXTRA_CA_CERTS the user already set (which Claude Code
    honours and which overrides the process environment)."""

    def test_update_adds_ca_env_on_tls_box(self, box, monkeypatch):
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = _tls_box(box)
        box.run("y")  # the `vhir update` redeploy shape (no URL)
        data = json.loads(box.settings.read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == ca

    def test_setup_client_adds_ca_env_on_tls_box(self, box, monkeypatch):
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = _tls_box(box)
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr("builtins.input", lambda p="": "y")
        cs._deploy_claude_code_assets(box.home)  # the `vhir setup client` shape
        data = json.loads(box.settings.read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == ca

    def test_no_ca_env_on_http_box(self, box, monkeypatch):
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        box.run("y")  # box's default gateway.yaml has no tls block
        data = json.loads(box.settings.read_text())
        assert "NODE_EXTRA_CA_CERTS" not in data.get("env", {})

    def test_existing_settings_ca_kept_with_notice(self, box, monkeypatch, capsys):
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = _tls_box(box)
        box.settings.write_text(
            json.dumps({"env": {"NODE_EXTRA_CA_CERTS": "/corp/ca.pem"}})
        )
        capsys.readouterr()
        box.run("y")
        data = json.loads(box.settings.read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == "/corp/ca.pem" != ca
        out = capsys.readouterr().out
        assert "NODE_EXTRA_CA_CERTS" in out and ca in out

    def test_a_remote_project_gets_the_ca_it_was_given(self, box, monkeypatch):
        # off the SIFT: the project's settings.json, with the CA copied from it
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        monkeypatch.setattr(cs, "_is_sift", lambda: False)
        monkeypatch.setattr(
            cs, "_find_claude_code_assets", lambda: box.repo / "claude-code"
        )
        monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
        monkeypatch.setattr("builtins.input", lambda p="": "y")
        project = box.home / "vhir"
        project.mkdir()
        cs._deploy_claude_code_assets(project, remote_ca="/l/ca-cert.pem")
        data = json.loads((project / ".claude" / "settings.json").read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == "/l/ca-cert.pem"
        other = box.home / "other"
        other.mkdir()
        cs._deploy_claude_code_assets(other)  # no CA given: none added
        data = json.loads((other / ".claude" / "settings.json").read_text())
        assert "NODE_EXTRA_CA_CERTS" not in data.get("env", {})

    def test_process_env_ca_kept_with_notice(self, box, monkeypatch, capsys):
        ca = _tls_box(box)
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/proc/ca.pem")
        capsys.readouterr()
        box.run("y")
        data = json.loads(box.settings.read_text())
        assert "NODE_EXTRA_CA_CERTS" not in data.get("env", {})
        out = capsys.readouterr().out
        assert "/proc/ca.pem" in out and ca in out

    @pytest.mark.parametrize("bad", ["a-string", 7, [1, 2], None])
    def test_a_non_object_env_is_left_alone_with_a_note(
        self, box, monkeypatch, capsys, bad
    ):
        # A settings.json whose env isn't an object must not crash the deploy:
        # keep the file, add nothing, and tell the user to add the CA by hand.
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = _tls_box(box)
        box.settings.write_text(json.dumps({"env": bad}))
        capsys.readouterr()
        box.run("y")  # must not raise
        data = json.loads(box.settings.read_text())
        assert data["env"] == bad  # the user's env is untouched
        out = capsys.readouterr().out
        assert "isn't an object" in out and ca in out

    def test_settings_applied_ignores_the_ca_env_on_a_tls_box(self, box, monkeypatch):
        # Every control deployed, no CA env, then the gateway goes TLS: the CA
        # env is a connectivity convenience, not a control, so the box still
        # reads as fully applied (not a false "controls NOT in effect").
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        box.run("y")  # HTTP box: deploys every control, no CA env
        _tls_box(box)
        assert cs.settings_applied(box.settings) == (True, False)

    def test_an_empty_settings_value_is_kept_not_overwritten(
        self, box, monkeypatch, capsys
    ):
        # A deliberate "" blocks trust at runtime (settings win); presence, not
        # truthiness, so it is kept with a notice, never silently replaced.
        monkeypatch.delenv("NODE_EXTRA_CA_CERTS", raising=False)
        ca = _tls_box(box)
        box.settings.write_text(json.dumps({"env": {"NODE_EXTRA_CA_CERTS": ""}}))
        capsys.readouterr()
        box.run("y")
        data = json.loads(box.settings.read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == ""
        out = capsys.readouterr().out
        assert ca in out

    def test_a_shell_value_overridden_by_our_ca_prints_a_notice(
        self, box, monkeypatch, capsys
    ):
        # Our CA is in settings (wins at runtime); a different shell value is
        # silently overridden, so say so.
        ca = _tls_box(box)
        box.settings.write_text(json.dumps({"env": {"NODE_EXTRA_CA_CERTS": ca}}))
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/corp/bundle.pem")
        capsys.readouterr()
        box.run("y")
        data = json.loads(box.settings.read_text())
        assert data["env"]["NODE_EXTRA_CA_CERTS"] == ca
        out = capsys.readouterr().out
        assert "/corp/bundle.pem" in out

    def test_the_override_notice_names_removing_the_settings_entry(
        self, box, monkeypatch, capsys
    ):
        # Adding the gateway CA to the shell bundle alone can't restore that
        # bundle's trust: the settings entry still wins. The notice says so,
        # and gives the step that does: remove the settings.json entry.
        ca = _tls_box(box)
        box.settings.write_text(json.dumps({"env": {"NODE_EXTRA_CA_CERTS": ca}}))
        monkeypatch.setenv("NODE_EXTRA_CA_CERTS", "/corp/bundle.pem")
        capsys.readouterr()
        box.run("y")
        out = " ".join(capsys.readouterr().out.split())
        assert "overrides it" in out
        assert "remove the settings.json entry" in out
        assert "left unchanged" not in out


# --- The prompt says what the merge changes, before the diff -----------------

SUMMARY_SOURCE = {
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "$P/hooks/forensic-audit.sh"}],
            }
        ],
        "UserPromptSubmit": [
            {"hooks": [{"type": "command", "command": "cat << 'X'\nrules\nX"}]}
        ],
    },
    "permissions": {
        "deny": ["Edit(**/findings.json)", "Edit(//var/lib/vhir/**)", "Read(~/.x)"]
    },
    "sandbox": {
        "enabled": True,
        "allowUnsandboxedCommands": False,
        "failIfUnavailable": True,
    },
}
OLD_BASH = ["Bash(rm -rf *)", "Bash(mkfs*)", "Bash(dd *)"]
ON = {"enabled": True, "allowUnsandboxedCommands": False, "failIfUnavailable": True}


def _summary_box(box, user, source=SUMMARY_SOURCE):
    (box.repo / "claude-code" / "full" / "settings.json").write_text(
        json.dumps(source, indent=2)
    )
    box.settings.write_text(json.dumps(user, indent=2))
    return box.settings.read_bytes()


def _summary(out):
    """The summary lines: between the header and "The full change:"."""
    lines = out.splitlines()
    start = next(i for i, ln in enumerate(lines) if "vhir would change" in ln)
    end = lines.index("  The full change:")
    return [ln.strip() for ln in lines[start + 1 : end]]


def _merged_as_at_base(box):
    """What the merge writes, from the function this change leaves alone."""
    src = box.repo / "claude-code" / "full" / "settings.json"
    return cs._merged_settings(box.settings, src, box.home / ".vhir" / "hooks")


def test_the_prompt_says_what_changes_before_the_diff(box, capsys):
    user = {
        "permissions": {"deny": [*OLD_BASH, "Write(**/findings.json)", "Read(~/.y)"]},
        "sandbox": {"enabled": False},
    }
    _summary_box(box, user)
    _, asked = box.run("y")
    out = capsys.readouterr().out
    scope = "every Claude Code session of this account"
    assert _summary(out) == [
        f"- turns the Claude Code sandbox ON for {scope} (it is off now)",
        f"- sets sandbox.allowUnsandboxedCommands to false for {scope} (it is not "
        "set now): a command the sandbox blocks is refused, never run outside "
        "the sandbox",
        f"- sets sandbox.failIfUnavailable to true for {scope} (it is not set now):"
        " Claude Code fails when the sandbox can't start, instead of running "
        "without it",
        "- removes 4 old Valhuntir deny rules:",
        "Bash(rm -rf *): nothing replaces it",
        "Bash(mkfs*): nothing replaces it",
        "Bash(dd *): nothing replaces it",
        "Write(**/findings.json): Edit(**/findings.json) replaces it",
        "- adds 3 deny rules",
        "- adds the PostToolUse (Bash) hook forensic-audit.sh",
        "- adds the UserPromptSubmit hook \"cat << 'X'\"",
    ]
    # before the diff, and the diff is still all there
    assert out.index("turns the Claude Code sandbox ON") < out.index("--- current")
    assert '-    "enabled": false' in out and '+    "enabled": true' in out
    assert any("[Y/n]" in p for p in asked)
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True


def test_a_sandbox_already_on_gets_no_sandbox_line(box, capsys):
    _summary_box(box, {"sandbox": dict(ON), "permissions": {"deny": OLD_BASH[:1]}})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    assert not [ln for ln in got if "sandbox" in ln]
    assert "Bash(rm -rf *): nothing replaces it" in got  # there is a change to show


@pytest.mark.parametrize(
    ("key", "user_value", "says"),
    [
        ("enabled", False, "turns the Claude Code sandbox ON"),
        (
            "enabled",
            "yes",
            "sandbox ON for every Claude Code session of this "
            'account (it is "yes" now)',
        ),  # fmt: skip
        ("enabled", 1, "(it is 1 now)"),  # 1 is not true to Claude Code's JSON
        ("allowUnsandboxedCommands", True, "allowUnsandboxedCommands to false"),
        ("failIfUnavailable", False, "failIfUnavailable to true"),
    ],
)
def test_each_sandbox_key_that_changes_is_named_alone(
    box, capsys, key, user_value, says
):
    _summary_box(box, {"sandbox": {**ON, key: user_value}})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    (line,) = [ln for ln in got if "sandbox" in ln]
    assert says in line


@pytest.mark.parametrize(
    ("value", "says"),
    [
        (True, "a command the sandbox blocks may run outside the sandbox"),
        (False, "Claude Code runs without the sandbox when the sandbox can't start"),
        (None, "(it is true now)"),
    ],
)
def test_a_product_value_off_the_usual_is_named_too(box, capsys, value, says):
    key = "allowUnsandboxedCommands" if value is True else "failIfUnavailable"
    source = json.loads(json.dumps(SUMMARY_SOURCE))
    source["sandbox"][key] = value
    _summary_box(box, {"sandbox": dict(ON)}, source)
    box.run("y")
    (line,) = [ln for ln in _summary(capsys.readouterr().out) if "sandbox" in ln]
    assert says in line and f"sandbox.{key} to {json.dumps(value)}" in line


def test_a_product_that_turns_the_sandbox_off_says_off(box, capsys):
    source = json.loads(json.dumps(SUMMARY_SOURCE))
    source["sandbox"]["enabled"] = False
    _summary_box(box, {"sandbox": dict(ON)}, source)
    box.run("y")
    (line,) = [ln for ln in _summary(capsys.readouterr().out) if "sandbox" in ln]
    assert line == (
        "- turns the Claude Code sandbox OFF for every Claude Code session of "
        "this account (it is true now)"
    )


def test_a_rule_the_user_wrote_is_never_shown_as_removed(box, capsys):
    mine = ["Read(~/.ssh/**)", "Bash(rm -rf /*)", "Bash(dd*)", "Write(**/notes.json)"]
    _summary_box(box, {"sandbox": dict(ON), "permissions": {"deny": mine}})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    assert not [ln for ln in got if "remove" in ln or "replaces it" in ln]
    assert got[0] == "- adds 3 deny rules"
    assert json.loads(box.settings.read_text())["permissions"]["deny"][:4] == mine


def test_an_old_rule_the_product_still_ships_is_not_shown_as_removed(box, capsys):
    source = json.loads(json.dumps(SUMMARY_SOURCE))
    source["permissions"]["deny"].append("Bash(dd *)")
    _summary_box(box, {"sandbox": dict(ON), "permissions": {"deny": OLD_BASH}}, source)
    box.run("y")
    got = _summary(capsys.readouterr().out)
    assert "- removes 2 old Valhuntir deny rules:" in got
    assert not [ln for ln in got if ln.startswith("Bash(dd *)")]


@pytest.mark.parametrize(
    ("old", "by"),
    [
        ("Read(/var/lib/vhir/**)", None),  # no Read rule ships for it here
        ("Edit(/var/lib/vhir/**)", "Edit(//var/lib/vhir/**)"),
        ("Write(/var/lib/vhir/**)", "Edit(//var/lib/vhir/**)"),
        ("Write(**/findings.json)", "Edit(**/findings.json)"),
        ("Write(**/todos.json)", None),
    ],
)
def test_a_removed_rule_names_what_replaces_it(box, capsys, old, by):
    _summary_box(box, {"sandbox": dict(ON), "permissions": {"deny": [old]}})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    assert (
        f"{old}: {by} replaces it" in got
        if by
        else (f"{old}: nothing replaces it" in got)
    )


def test_hooks_moved_and_removed_are_named(box, capsys):
    hooks = {
        "PostToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "/old/forensic-audit.sh"}],
            }
        ],
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "/x/pre-bash-guard.sh"}],
            }
        ],
    }
    _summary_box(box, {"sandbox": dict(ON), "hooks": hooks})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    new = box.home / ".vhir" / "hooks" / "forensic-audit.sh"
    assert got[1:] == [
        f"- moves the PostToolUse (Bash) hook forensic-audit.sh to {new} "
        "(it runs /old/forensic-audit.sh now)",
        "- adds the UserPromptSubmit hook \"cat << 'X'\"",
        "- removes the PreToolUse (Bash) hook pre-bash-guard.sh",
    ]


@pytest.mark.parametrize(
    "old",
    [
        ("PostToolUse", "Edit", "/a/x.sh"),  # another matcher
        ("PreToolUse", "Bash", "/a/x.sh"),  # another event
        ("PostToolUse", "Bash", "/a/y.sh"),  # another script
    ],
)
def test_a_hook_is_moved_only_from_its_own_event_matcher_and_name(old):
    got = cs._hook_lines([old], [("PostToolUse", "Bash", "/b/x.sh")])
    assert got == [
        "adds the PostToolUse (Bash) hook x.sh",
        f"removes the {old[0]} ({old[1]}) hook {old[2][3:]}",
    ]


def test_y_prints_the_summary_and_merges_as_before(box, setup, capsys):
    user = {"permissions": {"deny": OLD_BASH}, "sandbox": {"enabled": False}}
    before = _summary_box(box, user)
    want = _merged_as_at_base(box)
    asked = setup()  # -y, no terminal
    cap = capsys.readouterr()
    assert not asked and "Bash(mkfs*): nothing replaces it" in _summary(cap.out)
    assert json.loads(box.settings.read_text()) == want
    (bak,) = box.settings.parent.glob("settings.json.vhir-backup-*")
    assert bak.read_bytes() == before
    assert f"*** -y: vhir CHANGED {box.settings}" in cap.err


def test_without_a_terminal_the_summary_prints_and_nothing_changes(box, capsys):
    before = _summary_box(box, {"sandbox": {"enabled": False}})
    result, asked = box.run()
    out = capsys.readouterr().out
    assert _summary(out)[0].startswith("- turns the Claude Code sandbox ON for")
    assert box.settings.read_bytes() == before and not asked
    assert f"Not changed: {box.settings}. To review and apply" in out
    assert result == (box.settings, "kept")


def test_no_summary_and_no_prompt_when_nothing_changes(box, capsys):
    _summary_box(box, {})
    box.run("y")
    capsys.readouterr()
    before = box.settings.read_bytes()
    _, asked = box.run("y")
    out = capsys.readouterr().out
    assert box.settings.read_bytes() == before and not asked
    assert "vhir would change" not in out and "The full change" not in out


def test_a_change_the_summary_has_no_line_for_shows_the_diff_alone(box, capsys):
    _summary_box(box, {})
    box.run("y")  # deployed as shipped
    source = json.loads(json.dumps(SUMMARY_SOURCE))
    source["permissions"]["allow"] = ["mcp__vhir__*"]
    _summary_box(box, json.loads(box.settings.read_text()), source)
    capsys.readouterr()
    box.run("y")
    out = capsys.readouterr().out
    assert "The full change" not in out and '+      "mcp__vhir__*"' in out


def test_a_project_file_names_the_projects_sessions(tmp_path, monkeypatch, capsys):
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    target = project / ".claude" / "settings.json"
    target.write_text(json.dumps({"sandbox": {"enabled": False}}))
    src = tmp_path / "settings.json"
    src.write_text(json.dumps(SUMMARY_SOURCE))
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: tmp_path / "home"))
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    assert cs._merge_settings(target, src, project_copies=True) == "kept"
    got = _summary(capsys.readouterr().out)
    assert got[0] == (
        f"- turns the Claude Code sandbox ON for the Claude Code sessions started "
        f"in {project} (it is off now)"
    )
    assert "- adds 5 deny rules" in got  # the product's 3 and the project copies' 2


def test_a_file_that_cant_be_read_again_gets_the_diff_alone(box, monkeypatch, capsys):
    _summary_box(box, {"sandbox": {"enabled": False}})
    real = cs.Path.read_text

    def read_text(self, *a, **k):  # the merge read it; the summary's read fails
        if self == box.settings and sys._getframe(1).f_code.co_name == (
            "_merge_settings"
        ):
            raise OSError("gone")
        return real(self, *a, **k)

    monkeypatch.setattr(cs.Path, "read_text", read_text)
    box.run("y")
    out = capsys.readouterr().out
    assert "The full change" not in out and '+    "enabled": true' in out
    assert json.loads(box.settings.read_text())["sandbox"]["enabled"] is True


@pytest.mark.parametrize(
    "current",
    [
        [],
        {"sandbox": "on", "permissions": [], "hooks": []},
        {"permissions": {"deny": "Bash(rm -rf *)"}, "hooks": {"X": "y"}},
        {"permissions": {"deny": [1, None, "Bash(mkfs*)"]}},
        {"hooks": {"X": [1, {"matcher": "m", "hooks": "h"}, {"hooks": [1, {}]}]}},
    ],
)
def test_odd_shapes_in_the_users_file_never_break_the_summary(current, tmp_path):
    merged = json.loads(json.dumps(SUMMARY_SOURCE))
    got = cs._settings_summary(tmp_path / "s.json", current, merged)
    assert "adds 3 deny rules" in got
    assert ("  Bash(mkfs*): nothing replaces it" in got) == (
        "[1, None, 'Bash(mkfs*)']" in str(current)
    )


def test_a_sandbox_the_user_never_set_reads_as_off(box, capsys):
    _summary_box(box, {})
    box.run("y")
    got = _summary(capsys.readouterr().out)
    assert got[0] == (
        "- turns the Claude Code sandbox ON for every Claude Code session of "
        "this account (it is off now)"
    )


def test_a_sandbox_key_the_product_leaves_out_gets_no_line(tmp_path):
    current = {"sandbox": {"failIfUnavailable": True, "enabled": 1}}
    assert cs._settings_summary(tmp_path / "s.json", current, {"sandbox": {}}) == []


def test_a_users_rule_the_merge_would_drop_is_not_called_valhuntir(tmp_path):
    current = {"permissions": {"deny": ["Bash(curl *)"]}}
    assert cs._settings_summary(tmp_path / "s.json", current, {}) == []


def test_a_hook_listed_twice_is_named_once(tmp_path):
    entry = {"matcher": "Bash", "hooks": [{"type": "command", "command": "/a/x.sh"}]}
    merged = {"hooks": {"PostToolUse": [entry, json.loads(json.dumps(entry))]}}
    got = cs._settings_summary(tmp_path / "s.json", {}, merged)
    assert got == ["adds the PostToolUse (Bash) hook x.sh"]


def test_a_long_inline_hook_is_named_by_its_first_40_characters():
    assert cs._hook_name("echo " + "x" * 60 + "\nmore") == '"echo ' + "x" * 35 + '"'
