"""vhir update runs its steps after the install from the code it pulled, says
so loudly when it can't, and records an update that ran to the end, which
every other vhir command checks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests import test_update
from vhir_cli import __version__
from vhir_cli.commands.update import cmd_update

manifest_dir = test_update.manifest_dir
INCOMPLETE = "UPDATE INCOMPLETE: run `vhir update` again"


class Execd(Exception):
    """os.execv was called (a real one never returns)."""


def _run(heads, moves, calls):
    """subprocess.run: `git pull` moves a repo in `moves` to its new head."""

    def run(cmd, **kwargs):
        calls.append(cmd)
        result = MagicMock(returncode=0, stdout="0", stderr="")
        if cmd[:2] == ["uv", "--version"]:
            result.stdout = "uv 0.12.20"
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-parse", "HEAD"]:
            result.stdout = heads[Path(cmd[2]).name]
        elif cmd[:2] == ["git", "-C"] and cmd[3:5] == ["pull", "--ff-only"]:
            name = Path(cmd[2]).name
            heads[name] = moves.get(name, heads[name])
        return result

    return run


def _update(home, args, moves=(), execv=None):
    heads = {"sift-mcp": "s1", "vhir": "v1"}
    calls = []
    execv = execv or MagicMock(side_effect=Execd)
    with (
        patch("pathlib.Path.home", return_value=home),
        patch("subprocess.run", side_effect=_run(heads, dict(moves), calls)),
        patch("os.execv", execv),
        patch("vhir_cli.commands.update._ensure_password_dir") as step45,
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test"),
    ):
        try:
            cmd_update(args, {})
        except Execd:
            pass
    return calls, execv, step45


def _vhir_script(home):
    script = home / "venv" / "bin" / "vhir"
    script.write_text("#!/bin/sh\n")
    return script


def _args(**kw):
    args = test_update._make_args(**kw)
    args.after_pull = kw.get("after_pull")
    return args


def test_a_pull_that_changes_vhir_runs_the_rest_from_the_new_code(manifest_dir):
    home = manifest_dir[0]
    script = _vhir_script(home)
    _, execv, step45 = _update(home, _args(no_restart=True), moves={"vhir": "v2"})
    assert execv.call_count == 1
    exe, argv = execv.call_args.args
    assert exe == str(home / "venv" / "bin" / "python") and argv[0] == exe
    assert argv[1:4] == [str(script), "update", "--after-pull"]
    assert argv[5:] == ["--no-restart"]
    assert json.loads(argv[4])["pre_update_git"] == {"sift-mcp": "s1", "vhir": "v1"}
    assert not step45.called  # Steps 4.5-9 belong to the new process


def test_the_after_pull_option_parses():
    from vhir_cli.main import build_parser

    args = build_parser().parse_args(["update", "--after-pull", "{}", "--no-restart"])
    assert args.command == "update" and args.after_pull == "{}" and args.no_restart


def test_no_change_to_vhir_means_no_new_process(manifest_dir):
    home = manifest_dir[0]
    _vhir_script(home)
    _, execv, step45 = _update(home, _args(no_restart=True), moves={"sift-mcp": "s2"})
    assert not execv.called and step45.called


def test_after_pull_runs_only_steps_4_5_to_9(manifest_dir, capsys):
    home, manifest_path = manifest_dir
    _vhir_script(home)
    handoff = json.dumps(
        {"pre_update_git": {"sift-mcp": "s0", "vhir": "v0"}, "torch_record": ""}
    )
    calls, execv, step45 = _update(home, _args(no_restart=True, after_pull=handoff))
    joined = [" ".join(c) for c in calls]
    assert not [c for c in joined if " fetch " in c or " pull " in c or "install" in c]
    assert not [c for c in joined if c.startswith("uv self update")]
    assert not execv.called and step45.called
    manifest = json.loads(manifest_path.read_text())
    assert manifest["pre_update_git"] == {"sift-mcp": "s0", "vhir": "v0"}
    assert manifest["git"] == {"sift-mcp": "s1", "vhir": "v1"}
    assert "Updated to" in capsys.readouterr().out


def test_a_malformed_handoff_still_finishes_from_the_current_heads(manifest_dir):
    home, manifest_path = manifest_dir
    calls, execv, step45 = _update(home, _args(no_restart=True, after_pull="{not json"))
    assert not [c for c in calls if "fetch" in c] and step45.called
    assert json.loads(manifest_path.read_text())["pre_update_git"] == {
        "sift-mcp": "s1",
        "vhir": "v1",
    }


def test_a_failed_new_process_is_loud_and_nonzero(manifest_dir, capsys):
    home = manifest_dir[0]
    _vhir_script(home)
    execv = MagicMock(side_effect=OSError(8, "Exec format error"))
    with pytest.raises(SystemExit) as stop:
        _update(home, _args(no_restart=True), moves={"vhir": "v2"}, execv=execv)
    assert stop.value.code == 1
    assert INCOMPLETE in capsys.readouterr().err
    # Step 9's full record was never written, but the pre-pull record (version
    # "") stays, so every command keeps warning until a run finishes.
    state = json.loads((home / ".vhir" / "update-state.json").read_text())
    assert state["version"] == ""


def test_a_missing_vhir_script_is_loud_and_nonzero(manifest_dir, capsys):
    home = manifest_dir[0]
    with pytest.raises(SystemExit) as stop:
        _, execv, _ = _update(home, _args(no_restart=True), moves={"vhir": "v2"})
    assert stop.value.code == 1 and INCOMPLETE in capsys.readouterr().err


def test_a_finished_update_is_recorded(manifest_dir):
    home = manifest_dir[0]
    _update(home, _args(no_restart=True))
    state = json.loads((home / ".vhir" / "update-state.json").read_text())
    assert state["version"] == __version__ and state["vhir_commit"] == "v1"
    assert state["completed_at"]


def test_a_record_with_no_version_is_written_before_the_pull(manifest_dir):
    """Just before the pull, update records version "" (with the pre-pull vhir
    commit), so any stop before Step 9 keeps every command warning. RED at
    v0.6.4: nothing writes the record, so none exists at pull time."""
    home = manifest_dir[0]
    _vhir_script(home)
    rec = home / ".vhir" / "update-state.json"
    heads = {"sift-mcp": "s1", "vhir": "v1"}
    seen = {}

    def run(cmd, **kwargs):
        result = MagicMock(returncode=0, stdout="0", stderr="")
        if cmd[:2] == ["uv", "--version"]:
            result.stdout = "uv 0.12.20"
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif cmd[:2] == ["git", "-C"] and cmd[3:] == ["rev-parse", "HEAD"]:
            result.stdout = heads[Path(cmd[2]).name]
        elif cmd[:2] == ["git", "-C"] and cmd[3:5] == ["pull", "--ff-only"]:
            seen.setdefault(
                "at_pull", json.loads(rec.read_text()) if rec.exists() else None
            )
        return result

    with (
        patch("pathlib.Path.home", return_value=home),
        patch("subprocess.run", side_effect=run),
        patch("os.execv", MagicMock(side_effect=Execd)),
        patch("vhir_cli.commands.update._ensure_password_dir"),
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test"),
    ):
        try:
            cmd_update(_args(no_restart=True), {})
        except Execd:
            pass
    assert seen.get("at_pull") is not None, "no update-state.json at pull time"
    assert seen["at_pull"]["version"] == ""
    assert seen["at_pull"]["vhir_commit"] == "v1"


# Every other vhir command checks the record against the installed code.


def _manifest(home, **extra):
    manifest = {
        "version": "1.0",
        "installed_at": "2026-10-01T00:00:00+00:00",
        "packages": {"vhir-cli": {"module": "vhir_cli", "version": __version__}},
        "git": {"vhir": "v1"},
    }
    manifest.update(extra)
    (home / ".vhir").mkdir(exist_ok=True)
    (home / ".vhir" / "manifest.json").write_text(json.dumps(manifest))


def _state(home, **extra):
    state = {
        "version": __version__,
        "vhir_commit": "v1",
        "completed_at": "2026-10-02T00:00:00+00:00",
    }
    state.update(extra)
    (home / ".vhir" / "update-state.json").write_text(json.dumps(state))


def _vhir(home, *argv):
    from vhir_cli import main as main_mod

    with (
        patch("pathlib.Path.home", return_value=home),
        patch.object(sys, "argv", ["vhir", *argv]),
        patch.object(main_mod, "cmd_portal") as portal,
        patch.object(main_mod, "cmd_update") as update,
    ):
        main_mod.main()
    assert portal.called or update.called


def test_an_old_updater_run_is_warned_about(tmp_path, capsys):
    _manifest(tmp_path, updated_at="2026-10-03T00:00:00+00:00")
    _vhir(tmp_path, "portal")
    assert INCOMPLETE in capsys.readouterr().err


def test_a_record_of_another_commit_is_warned_about(tmp_path, capsys):
    _manifest(tmp_path, updated_at="2026-10-03T00:00:00+00:00", git={"vhir": "v2"})
    _state(tmp_path)
    _vhir(tmp_path, "portal")
    assert INCOMPLETE in capsys.readouterr().err


def test_a_fresh_install_is_not_warned_about(tmp_path, capsys):
    _manifest(tmp_path)
    _vhir(tmp_path, "portal")
    assert INCOMPLETE not in capsys.readouterr().err


def test_a_matching_record_is_not_warned_about(tmp_path, capsys):
    _manifest(tmp_path, updated_at="2026-10-02T00:00:00+00:00")
    _state(tmp_path)
    _vhir(tmp_path, "portal")
    assert INCOMPLETE not in capsys.readouterr().err


def test_a_reinstall_after_the_record_is_not_warned_about(tmp_path, capsys):
    _manifest(tmp_path)
    _state(tmp_path, version="0.6.1", completed_at="2026-09-01T00:00:00+00:00")
    _vhir(tmp_path, "portal")
    assert INCOMPLETE not in capsys.readouterr().err


def test_update_itself_is_not_warned_about(tmp_path, capsys):
    _manifest(tmp_path, updated_at="2026-10-03T00:00:00+00:00")
    _vhir(tmp_path, "update")
    assert INCOMPLETE not in capsys.readouterr().err


def test_config_is_not_warned_about(tmp_path, capsys):
    """setup-sift.sh runs `vhir config` mid-install, before it rewrites the
    manifest, so config must not warn either."""
    from vhir_cli import main as main_mod

    _manifest(tmp_path, updated_at="2026-10-03T00:00:00+00:00")
    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch.object(sys, "argv", ["vhir", "config"]),
        patch.object(main_mod, "cmd_config") as config,
    ):
        main_mod.main()
    assert config.called
    assert INCOMPLETE not in capsys.readouterr().err
