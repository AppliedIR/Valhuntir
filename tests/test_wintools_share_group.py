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
import signal
import stat
import types
from pathlib import Path

import pytest
import yaml

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

    def chown(target, uid, gid):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "fchown", chown)


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


@pytest.fixture
def shared(home, monkeypatch):
    """A configured share whose repoint and notify are recorded."""
    calls = []
    monkeypatch.setattr(main, "_wintools_configured", lambda: True)
    monkeypatch.setattr(
        join, "_repoint_samba_share", lambda p: calls.append(("repoint", p))
    )
    monkeypatch.setattr(
        join,
        "notify_wintools_case_activated",
        lambda c: calls.append(("notify", c)) or True,
    )
    return calls


def _closed_case(home, case_id):
    data = main._case_init_data(
        name="c", examiner="tester", cases_dir=str(home / "cases"), case_id=case_id
    )
    return Path(data["case_dir"])


@pytest.mark.parametrize("command", ["activate", "reopen"])
def test_cli_activate_and_reopen_prepare_the_case_for_wintools(
    home, shared, no_group, capsys, command, monkeypatch
):
    monkeypatch.setenv("VHIR_CASES_DIR", str(home / "cases"))
    case_dir = _closed_case(home, "CASE-D")
    args = argparse.Namespace(case_id="CASE-D", cases_dir=str(home / "cases"))
    if command == "reopen":
        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text())
        meta["status"] = "closed"
        (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
        main._case_reopen(args, {"examiner": "tester"})
    else:
        main._case_activate(args, {"examiner": "tester"})
    assert shared == [("repoint", case_dir), ("notify", "CASE-D")]
    out = capsys.readouterr().out
    # the group step can't run in this process: nothing is half made, and the
    # warning names the step that works without a reboot
    assert "Group permissions not applied" in out and "vhir setup join-code" in out
    assert not (case_dir / "extractions" / "wintools").exists()


@pytest.mark.parametrize(
    "planted", ["audit/wintools-mcp.jsonl", "extractions/wintools"]
)
def test_a_link_planted_in_a_case_does_not_widen_what_it_points_at(
    tmp_path, monkeypatch, planted
):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    record = tmp_path / "findings.json"
    record.write_text("[]")
    record.chmod(0o600)
    link = tmp_path / planted
    link.parent.mkdir(parents=True)
    link.symlink_to(record if planted.endswith(".jsonl") else tmp_path / "evidence")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence").chmod(0o700)
    warning = main._set_case_wintools_permissions(tmp_path)
    assert "inside the case" in warning and "is not a" in warning
    assert record.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "evidence").stat().st_mode & 0o7777 == 0o700


def test_a_dangling_link_planted_for_the_audit_file_creates_nothing(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    outside = tmp_path / "outside" / "made.txt"
    outside.parent.mkdir()
    (tmp_path / "case" / "audit").mkdir(parents=True)
    (tmp_path / "case" / "audit" / "wintools-mcp.jsonl").symlink_to(outside)
    warning = main._set_case_wintools_permissions(tmp_path / "case")
    assert "Group permissions not applied" in warning
    assert not outside.exists()


def test_a_pipe_planted_for_the_audit_file_does_not_hang_activation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    (tmp_path / "audit").mkdir()
    os.mkfifo(tmp_path / "audit" / "wintools-mcp.jsonl")

    def hung(signum, frame):
        raise TimeoutError("the group step waited on a pipe")

    previous = signal.signal(signal.SIGALRM, hung)
    signal.alarm(5)
    try:
        warning = main._set_case_wintools_permissions(tmp_path)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert "is not a regular file inside the case" in warning


@pytest.mark.parametrize("folder", ["audit", "extractions"])
def test_a_case_folder_linked_outside_the_case_is_not_followed(
    tmp_path, monkeypatch, folder
):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "wintools-mcp.jsonl").write_text("")
    (outside / "wintools-mcp.jsonl").chmod(0o600)
    case = tmp_path / "case"
    case.mkdir()
    (case / folder).symlink_to(outside)
    warning = main._set_case_wintools_permissions(case)
    assert "leads outside the case" in warning
    assert (outside / "wintools-mcp.jsonl").stat().st_mode & 0o777 == 0o600
    assert not (outside / "wintools").exists()


def _seen_as_a_regular_file(monkeypatch, path):
    """`path` passes the check, as if it were swapped in just after it."""
    real_lstat = os.lstat

    def lstat(p, *a, **k):
        st = real_lstat(p, *a, **k)
        if os.fspath(p) == os.fspath(path):
            return os.stat_result((stat.S_IFREG | 0o644, *tuple(st)[1:]))
        return st

    monkeypatch.setattr(os, "lstat", lstat)


def test_a_pipe_swapped_in_after_the_check_does_not_hang_activation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    (tmp_path / "audit").mkdir()
    pipe = tmp_path / "audit" / "wintools-mcp.jsonl"
    os.mkfifo(pipe)
    _seen_as_a_regular_file(monkeypatch, pipe)

    def hung(signum, frame):
        raise TimeoutError("the group step waited on a pipe")

    previous = signal.signal(signal.SIGALRM, hung)
    signal.alarm(5)
    try:
        warning = main._set_case_wintools_permissions(tmp_path)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    assert "is not a regular file inside the case" in warning


def test_a_link_swapped_in_after_the_check_is_not_followed(tmp_path, monkeypatch):
    monkeypatch.setattr(
        grp, "getgrnam", lambda name: types.SimpleNamespace(gr_gid=os.getgid())
    )
    record = tmp_path / "findings.json"
    record.write_text("[]")
    record.chmod(0o600)
    (tmp_path / "audit").mkdir()
    link = tmp_path / "audit" / "wintools-mcp.jsonl"
    link.symlink_to(record)
    _seen_as_a_regular_file(monkeypatch, link)
    main._set_case_wintools_permissions(tmp_path)
    assert record.stat().st_mode & 0o777 == 0o600
