"""A pending update makes every vhir command print why, and the fix.

Step 9 records the update pending, with the gateway check's reason and fix,
whenever the check doesn't pass. Every vhir command then prints that recorded
reason and fix on stderr (main._warn_if_update_incomplete), except update,
config, no command, --version and --help. Nothing prints once a later run
records the update complete, for a complete record whatever text it holds, or
once setup-sift.sh has run since the record (installed_at after completed_at).
The pending state comes from the real Step 9 (tests.test_update_lock._update,
the gateway check a stand-in that gives each row's answer), never a seeded file.
"""

from __future__ import annotations

import importlib.metadata
import json
import sys
from unittest.mock import patch

import pytest

from tests import test_update_lock
from tests.stub_check import stub_check  # noqa: F401 (the fixture)
from tests.test_update_gateway_state import FOREIGN, PASS, STALE_HEADS, UNKNOWN, _state
from tests.test_update_lock import _update
from vhir_cli import __version__
from vhir_cli import main as main_mod

box = test_update_lock.box  # the fixture: a scratch home with an install
BAR = "=" * 72
REAL_VERSION = importlib.metadata.version


def _installed(name):
    """The installed vhir-cli is this tree's version, so a finished update's
    record matches the code and only a pending one warns."""
    return __version__ if name == "vhir-cli" else REAL_VERSION(name)


def _pending(box, answer, **kw):
    """A real update run whose gateway check gives `answer`; its record."""
    with patch("importlib.metadata.version", side_effect=_installed):
        _update(box, gateway=answer, **kw)
    return _state(box)


def _vhir(box, capsys, *argv):
    """Run `vhir <argv>` with each command a stand-in; (stdout, stderr)."""
    capsys.readouterr()
    with (
        patch("pathlib.Path.home", return_value=box.home),
        patch.object(sys, "argv", ["vhir", *argv]),
        patch.object(main_mod, "cmd_portal"),
        patch.object(main_mod, "cmd_review"),
        patch.object(main_mod, "cmd_update"),
        patch.object(main_mod, "cmd_config"),
    ):
        try:
            main_mod.main()
        except SystemExit:
            pass
    out, err = capsys.readouterr()
    return out, err


# the answer, the run's flags, and the reason and fix Step 9 records for them
PENDING = {
    "foreign-listener": (FOREIGN, {"no_restart": False}, FOREIGN.reason, FOREIGN.fix),
    "check-unknown": (UNKNOWN, {"no_restart": False}, UNKNOWN.reason, ""),
    "no-restart-stale": (
        STALE_HEADS,
        {"no_restart": True},
        "restart the gateway",
        STALE_HEADS.fix,
    ),
}


@pytest.mark.parametrize("command", [["portal"], ["review"]], ids=["portal", "review"])
@pytest.mark.parametrize("case", list(PENDING), ids=list(PENDING))
def test_a_pending_update_makes_a_command_print_the_recorded_reason_and_fix(
    box, capsys, case, command
):
    answer, flags, reason, fix = PENDING[case]
    state = _pending(box, answer, **flags)
    out, err = _vhir(box, capsys, *command)
    assert reason and reason in err, (state, err)
    assert not fix or fix in err, (state, err)
    assert reason not in out, out


@pytest.mark.parametrize(
    "argv",
    [["update"], ["config"], [], ["--version"], ["--help"]],
    ids=["update", "config", "no-command", "version", "help"],
)
def test_update_config_no_command_version_and_help_print_no_reason(box, capsys, argv):
    _pending(box, FOREIGN, no_restart=False)
    out, err = _vhir(box, capsys, *argv)
    assert FOREIGN.reason not in out + err and FOREIGN.fix not in out + err, err


def test_a_re_run_that_records_complete_prints_nothing(box, capsys):
    _pending(box, FOREIGN, no_restart=False)
    state = _pending(box, PASS, no_restart=False)
    out, err = _vhir(box, capsys, "portal")
    assert FOREIGN.reason not in err and BAR not in err, (state, err)


def test_a_complete_record_with_a_reason_prints_nothing(box, capsys):
    vhir = box.home / ".vhir"
    manifest = json.loads((vhir / "manifest.json").read_text())
    manifest.update(
        installed_at="2026-10-01T00:00:00+00:00",
        updated_at="2026-10-02T00:00:00+00:00",
        git={"vhir": "v1"},
    )
    (vhir / "manifest.json").write_text(json.dumps(manifest))
    state = {
        "version": __version__,
        "vhir_commit": "v1",
        "status": "complete",
        "reason": "a reason left from an earlier run",
        "fix": "a fix left from an earlier run",
        "completed_at": "2026-10-02T00:00:00+00:00",
    }
    (vhir / "update-state.json").write_text(json.dumps(state))
    out, err = _vhir(box, capsys, "portal")
    assert state["reason"] not in err and BAR not in err, err


def test_a_pending_record_older_than_the_install_prints_nothing(box, capsys):
    state = _pending(box, FOREIGN, no_restart=False)
    path = box.home / ".vhir" / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest.pop("updated_at", None)  # setup-sift.sh writes a manifest without it
    manifest["installed_at"] = "9999-01-01T00:00:00+00:00"
    path.write_text(json.dumps(manifest))
    out, err = _vhir(box, capsys, "portal")
    assert FOREIGN.reason not in err and BAR not in err, (state, err)


def _commands():
    """Every top-level subcommand the parser has."""
    import argparse

    parser = main_mod.build_parser()
    (action,) = [
        a for a in parser._actions if isinstance(a, argparse._SubParsersAction)
    ]
    return sorted(action.choices)


@pytest.mark.parametrize("command", _commands())
def test_every_subcommand_help_prints_no_reason(box, capsys, command):
    _pending(box, FOREIGN, no_restart=False)
    out, err = _vhir(box, capsys, command, "--help")
    assert "usage:" in out, (out, err)  # the help printed: argparse exited first
    assert FOREIGN.reason not in out + err and FOREIGN.fix not in out + err, err
