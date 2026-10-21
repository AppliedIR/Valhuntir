"""`vhir case init` moves the wintools share to the new case, as activate does.

An AI runs `vhir case init` with no TTY. Asking "Share this case with
wintools?" there answered "n", so the share stayed on the last case and
wintools refused every path in the new one. Init now runs the activate
sequence with no question. Every command is recorded, none run.
"""

from __future__ import annotations

import argparse
import grp
import os
import subprocess
import types
from pathlib import Path

import pytest
import yaml

from vhir_cli import case_io, main
from vhir_cli.commands import join


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


@pytest.fixture
def no_group(monkeypatch):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=4242)
    )

    def chown(target, uid, gid):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchown", chown)


def _no_question(prompt=""):
    raise AssertionError(f"init asked: {prompt!r}")


def _init(home, case_id="CASE-C"):
    args = argparse.Namespace(
        name="c", case_id=case_id, description="", cases_dir=str(home / "cases")
    )
    main._case_init(args, {"examiner": "tester"})


@pytest.mark.parametrize(
    "isatty, answer",
    [(False, None), (True, ""), (True, "n")],
    ids=["no-tty", "tty-enter", "tty-n"],
)
def test_init_runs_the_activate_sequence_with_no_question(
    home, monkeypatch, isatty, answer
):
    calls = []
    monkeypatch.setattr(main, "_wintools_configured", lambda: True)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: isatty))
    monkeypatch.setattr("builtins.input", _no_question)
    monkeypatch.setattr(
        main,
        "_set_case_wintools_permissions",
        lambda p: calls.append(("permissions", p)),
    )
    monkeypatch.setattr(
        join, "_repoint_samba_share", lambda p: calls.append(("repoint", p))
    )
    monkeypatch.setattr(
        join,
        "notify_wintools_case_activated",
        lambda c: calls.append(("notify", c)) or True,
    )
    _init(home)
    case = home / "cases" / "CASE-C"
    assert calls == [("permissions", case), ("repoint", case), ("notify", "CASE-C")]


def test_init_leaves_the_share_alone_when_wintools_is_not_configured(home, monkeypatch):
    calls = []
    monkeypatch.setattr(main, "_wintools_configured", lambda: False)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", _no_question)
    monkeypatch.setattr(
        join, "_repoint_samba_share", lambda p: calls.append(("repoint", p))
    )
    monkeypatch.setattr(
        join,
        "notify_wintools_case_activated",
        lambda c: calls.append(("notify", c)) or True,
    )
    _init(home)
    assert calls == []


def test_init_leaves_the_share_alone_when_the_case_is_not_made_active(
    home, monkeypatch, capsys
):
    calls = []
    real_write = case_io._atomic_write

    def write(path, text):
        if Path(path).name == "active_case":
            raise OSError(28, "No space left on device")
        return real_write(path, text)

    monkeypatch.setattr(case_io, "_atomic_write", write)
    monkeypatch.setattr(main, "_wintools_configured", lambda: True)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", _no_question)
    monkeypatch.setattr(
        main, "_share_active_case", lambda p, c: calls.append(("share", p, c))
    )
    _init(home)
    assert calls == []
    assert "could not be made the active case" in capsys.readouterr().out


def test_init_and_activate_leave_the_same_share_state(home, no_group, monkeypatch):
    samba_yaml = home / ".vhir" / "samba.yaml"
    inactive = str(home / ".vhir" / "share-inactive")
    seed = {
        "share_name": join.SHARE_NAME,
        "force_user": "tester",
        "force_group": "tester",
        "wintools_ip": "192.0.2.7",
        "active_share_target": inactive,
    }
    conf = {}

    def run(cmd, **kw):
        if cmd[:2] == ["sudo", "tee"]:
            conf[cmd[2]] = kw["input"].decode()
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("builtins.input", _no_question)

    def state():
        return yaml.safe_load(samba_yaml.read_text()), dict(conf)

    samba_yaml.write_text(yaml.dump(seed))
    _init(home)
    after_init = state()

    samba_yaml.write_text(yaml.dump(seed))
    conf.clear()
    main._case_activate(
        argparse.Namespace(case_id="CASE-C", cases_dir=str(home / "cases")),
        {"examiner": "tester"},
    )
    after_activate = state()

    case = str(home / "cases" / "CASE-C")
    assert after_activate[0]["active_share_target"] == case
    assert f"path = {case}" in after_activate[1][join.SMB_CONF_PATH]
    assert after_init == after_activate
    assert (Path(case) / join.CASE_MARKER).read_text() == "CASE-C"
