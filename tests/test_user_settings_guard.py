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
    monkeypatch.setattr(cs, "_deploy_claude_code_assets", lambda project_dir=None: None)
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
        lambda project_dir=None: (box.settings, status),
    )
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
    monkeypatch.setattr(cs, "_merge_and_write", lambda path, config: None)
    cs._generate_config("claude-code", {}, "steve")
    out = capsys.readouterr().out
    assert ("Forensic controls deployed globally." in out) is claims
    assert ("will always apply" in out) is claims


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
        sift="http://127.0.0.1:4508",
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
        cs, "_deploy_claude_code_assets", lambda p=None: (real(p), boom())[0]
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
    assert box.settings.read_bytes() == before and any("[y/N]" in p for p in asked)
    assert not _undo_lines(capsys.readouterr().out)


def test_ask_user_files_without_a_terminal_keeps_the_file(box, setup):
    before = _write_user(box.settings)
    setup(ask_user_files=True)
    assert box.settings.read_bytes() == before


def test_anchor_vhir_update_without_a_terminal_still_keeps(box, capsys):
    before = _write_user(box.settings)
    box.run()  # _deploy_claude_code_assets alone, as `vhir update` calls it
    assert (
        box.settings.read_bytes() == before and "NOT applied" in capsys.readouterr().out
    )


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
