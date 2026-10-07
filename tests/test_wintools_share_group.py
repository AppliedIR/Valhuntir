"""Sharing a case with wintools before the sift group applies to this process.

The installing user joins the sift group at `vhir setup join-code`, but a
process started before that can't give files to the group until the user
logs in again. Sharing the case still repoints the share and tells wintools,
and says the group step didn't apply. Every command is recorded, none run.
"""

from __future__ import annotations

import argparse
import grp
import os
import types

import pytest

from vhir_cli import main
from vhir_cli.commands import join


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


@pytest.fixture
def no_group(monkeypatch):
    """The sift group exists, but this process can't give files to it."""
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=4242)
    )

    def chown(path, uid, gid):
        raise PermissionError(1, "Operation not permitted", path)

    monkeypatch.setattr(os, "chown", chown)


def test_the_group_step_returns_a_warning_instead_of_raising(tmp_path, no_group):
    warning = main._set_case_wintools_permissions(tmp_path)
    assert "Group permissions not applied" in warning
    assert str(tmp_path / "extractions" / "wintools") in warning


def test_cli_init_shares_the_case_when_the_group_step_fails(
    home, no_group, monkeypatch, capsys
):
    shared = []
    monkeypatch.setattr(main, "_wintools_configured", lambda: True)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(
        join, "_repoint_samba_share", lambda p: shared.append(("repoint", p))
    )
    monkeypatch.setattr(
        join,
        "notify_wintools_case_activated",
        lambda c: shared.append(("notify", c)) or True,
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    args = argparse.Namespace(
        name="c", case_id="CASE-C", description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})
    assert shared == [("repoint", home / "cases" / "CASE-C"), ("notify", "CASE-C")]
    assert "Group permissions not applied" in capsys.readouterr().out
