"""An older vhir's update (before 0.6.4.1) pulls this code and runs on in its
own process. The first new-code call it makes hands it over to this code's
`vhir update --after-pull`, which installs from the lock again and finishes
the update, so one `vhir update` ends on this release."""

from __future__ import annotations

import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from tests.test_update_reexec import _args, _update, _vhir_script, manifest_dir
from vhir_cli import __version__, update_handover

__all__ = ["manifest_dir"]
OLDER = '{"older_update": true}'


class Execd(BaseException):
    """os.execv was called (a real one never returns)."""


def _older_module(**attrs):
    """vhir_cli.commands.update as an older release loaded it."""
    module = types.ModuleType("vhir_cli.commands.update")
    for name, value in attrs.items():
        setattr(module, name, value)
    return module


@pytest.fixture
def older(tmp_path, monkeypatch):
    """A box mid-way through an older vhir's update: its update module is the
    loaded one, the manifest names the venv, and the venv has its vhir."""
    monkeypatch.setattr(update_handover, "_tried", False)
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "vhir").write_text("#!/bin/sh\n")
    (tmp_path / ".vhir").mkdir()
    (tmp_path / ".vhir" / "manifest.json").write_text(json.dumps({"venv": str(venv)}))
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setitem(sys.modules, "vhir_cli.commands.update", _older_module())
    return venv


def _hand_over(*argv, execv=None):
    execv = execv or MagicMock(side_effect=Execd)
    with patch.object(sys, "argv", ["vhir", *argv]), patch("os.execv", execv):
        try:
            update_handover.hand_over_older_update()
        except Execd:
            pass
    return execv


def test_an_older_update_is_handed_over_once(older):
    execv = _hand_over("update")
    python, script = str(older / "bin" / "python"), str(older / "bin" / "vhir")
    execv.assert_called_once_with(
        python, [python, script, "update", "--after-pull", OLDER]
    )


def test_a_v0_6_3_shaped_update_module_is_handed_over(older, monkeypatch):
    """0.6.0-0.6.4 have neither _reexec_after_pull nor _finish_update."""
    monkeypatch.setitem(
        sys.modules, "vhir_cli.commands.update", _older_module(cmd_update=print)
    )
    assert _hand_over("update").call_count == 1


def test_a_0_6_4_1_or_later_update_module_is_not_handed_over(older, monkeypatch):
    module = _older_module(_reexec_after_pull=print, _finish_update=print)
    monkeypatch.setitem(sys.modules, "vhir_cli.commands.update", module)
    assert not _hand_over("update").called


def test_this_release_update_module_is_not_handed_over(older, monkeypatch):
    from vhir_cli.commands import update

    monkeypatch.setitem(sys.modules, "vhir_cli.commands.update", update)
    assert not _hand_over("update").called


@pytest.mark.parametrize(
    "argv, flags",
    [
        (["update", "--no-restart"], ["--no-restart"]),
        (["update", "--no-r"], ["--no-restart"]),
        (["update", "--cpu"], ["--cpu"]),
        (["update", "--gpu", "--no-restart"], ["--no-restart", "--gpu"]),
        (["--case", "c1", "update"], []),
    ],
)
def test_the_update_options_carry_over(older, argv, flags):
    execv = _hand_over(*argv)
    assert execv.call_args.args[1][5:] == flags


@pytest.mark.parametrize(
    "argv",
    [
        ["update", "--check"],
        ["setup", "test"],
        ["gateway", "start"],
        ["service", "restart"],
        ["portal"],
        ["update", "--c"],  # ambiguous: the older vhir refused it too
        [],
    ],
)
def test_anything_but_an_update_is_not_handed_over(older, argv):
    assert not _hand_over(*argv).called


def test_no_update_module_loaded_is_not_handed_over(older, monkeypatch):
    monkeypatch.delitem(sys.modules, "vhir_cli.commands.update")
    assert not _hand_over("update").called


@pytest.mark.parametrize(
    "manifest", ["{not json", "[]", "{}", '{"venv": ""}', '{"venv": 7}']
)
def test_an_unreadable_manifest_is_not_handed_over(older, tmp_path, manifest):
    (tmp_path / ".vhir" / "manifest.json").write_text(manifest)
    assert not _hand_over("update").called


def test_a_missing_vhir_script_is_not_handed_over(older):
    (older / "bin" / "vhir").unlink()
    assert not _hand_over("update").called


def test_a_failed_exec_returns_once_and_is_said(older, capsys):
    execv = MagicMock(side_effect=OSError(8, "Exec format error"))
    _hand_over("update", execv=execv)
    _hand_over("update", execv=execv)  # the next guard does not try again
    assert execv.call_count == 1
    assert "Cannot start the new code" in capsys.readouterr().err


def test_an_unexpected_error_never_reaches_the_older_update(older, capsys):
    with patch.object(update_handover, "_update_args", side_effect=RuntimeError("x")):
        _hand_over("update")
    assert "Cannot start the new code: x" in capsys.readouterr().err


@pytest.mark.parametrize(
    "call",
    [
        "vhir_cli.commands.client_setup.ensure_signing_dirs",
        "vhir_cli.commands.client_setup._deploy_claude_code_assets",
        "vhir_cli.commands.client_setup.deploy_codex_assets",
        "vhir_cli.commands.client_setup._isolate_gateway_launchers",
        "vhir_cli.gateway.get_local_gateway_url",
    ],
)
def test_each_first_new_code_call_hands_over_first(older, call):
    """The first call an older update makes into this code, per release."""
    import importlib

    module_name, name = call.rsplit(".", 1)
    func = getattr(importlib.import_module(module_name), name)
    with patch.object(sys, "argv", ["vhir", "update"]):
        with patch("os.execv", MagicMock(side_effect=Execd)) as execv:
            with pytest.raises(Execd):
                func()
    assert execv.call_count == 1


def test_get_local_gateway_url_is_unchanged_outside_an_older_update(tmp_path):
    """setup test, gateway start and the rest still get the URL."""
    from vhir_cli.gateway import get_local_gateway_url

    for argv in (["setup", "test"], ["gateway", "start"], ["update"]):
        with (
            patch.object(sys, "argv", ["vhir", *argv]),
            patch("pathlib.Path.home", return_value=tmp_path),
            patch("os.execv") as execv,
        ):
            assert get_local_gateway_url() == "http://127.0.0.1:4508"
        assert not execv.called


# The new process: Step 4 again from the lock, then the rest.


def _manifest(manifest_path, **fields):
    manifest = json.loads(manifest_path.read_text())
    manifest.update(fields)
    manifest_path.write_text(json.dumps(manifest))


def _finish_older(home, **kw):
    """`vhir update --after-pull OLDER`; the run's heads are s1/v1. Returns
    the commands run and the update record as Step 4 started."""
    from vhir_cli.commands import update

    _vhir_script(home)
    seen = []
    state = home / ".vhir" / "update-state.json"
    real = update._install_packages

    def install(*a, **k):
        seen.append(json.loads(state.read_text()))
        return real(*a, **k)

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("builtins.input", side_effect=AssertionError("asked")) as asked,
        patch.object(update, "_install_packages", side_effect=install),
    ):
        calls, execv, step45 = _update(home, _args(after_pull=OLDER, **kw))
    assert len(seen) == 1 and not asked.called
    assert not execv.called and step45.called
    return calls, seen[0]


def test_an_older_update_installs_from_the_lock_again_and_finishes(manifest_dir):
    home, manifest_path = manifest_dir
    calls, at_install = _finish_older(home, no_restart=True)
    lock = str(home / ".vhir" / "src" / "sift-mcp" / "deps" / "vhir.lock")
    install = next(c for c in calls if c[:3] == ["uv", "pip", "install"])
    assert install[install.index("-c") + 1] == lock
    assert at_install["version"] == ""  # stopped from here on: the banner
    state = json.loads((home / ".vhir" / "update-state.json").read_text())
    assert state["version"] == __version__ and state["vhir_commit"] == "v1"
    joined = [" ".join(c) for c in calls]
    assert not [c for c in joined if " fetch " in c or " pull " in c]


def test_before_heads_from_the_older_step_6(manifest_dir):
    """Its Step 6 wrote the pulled heads to git: pre_update_git is the before."""
    home, manifest_path = manifest_dir
    before = {"sift-mcp": "s0", "vhir": "v0"}
    _manifest(
        manifest_path, git={"sift-mcp": "s1", "vhir": "v1"}, pre_update_git=before
    )
    _finish_older(home, no_restart=True)
    assert json.loads(manifest_path.read_text())["pre_update_git"] == before


def test_before_heads_when_the_older_step_6_did_not_write(manifest_dir):
    """Not reached or failed: git still holds the before; the stale
    pre_update_git (the update before's) is not used."""
    home, manifest_path = manifest_dir
    _manifest(
        manifest_path,
        git={"sift-mcp": "s0", "vhir": "v0"},
        pre_update_git={"sift-mcp": "OLD", "vhir": "OLD"},
    )
    _finish_older(home, no_restart=True)
    assert json.loads(manifest_path.read_text())["pre_update_git"] == {
        "sift-mcp": "s0",
        "vhir": "v0",
    }


def test_before_heads_with_no_git_record(manifest_dir):
    home, manifest_path = manifest_dir
    manifest = json.loads(manifest_path.read_text())
    del manifest["git"]
    manifest_path.write_text(json.dumps(manifest))
    _finish_older(home, no_restart=True)
    assert json.loads(manifest_path.read_text())["pre_update_git"] == {
        "sift-mcp": "s1",
        "vhir": "v1",
    }


def test_the_cpu_choice_carries_into_step_4(manifest_dir):
    home = manifest_dir[0]
    calls, _ = _finish_older(home, no_restart=True, cpu=True)
    install = next(c for c in calls if c[:3] == ["uv", "pip", "install"])
    assert install[install.index("-c") + 1].endswith("vhir-cpu.lock")
