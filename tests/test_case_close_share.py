"""`vhir case close X` moves the wintools share only when X has it.

The share follows the same rule as active_case: closing the active case, or
the case the share points at (compared by realpath), moves the share to the
placeholder. wintools is told its case is deactivated only when no active case
remains. Closing any other case leaves the share, its conf and wintools alone,
so the active case's Windows tools keep working. A missing, empty or
unreadable active_case pointer is no active case. Every command is recorded,
none run.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import types

import pytest
import yaml

from vhir_cli import case_copies, main
from vhir_cli.commands import join


@pytest.fixture
def box(tmp_path, monkeypatch):
    """A box joined to wintools with cases A, B and N; smb.conf writes recorded."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    (tmp_path / ".vhir").mkdir()
    cases = tmp_path / "cases"
    for case_id in ("CASE-A", "CASE-B", "CASE-N"):
        (cases / case_id).mkdir(parents=True)
        (cases / case_id / "CASE.yaml").write_text(
            yaml.dump({"case_id": case_id, "status": "open"})
        )
    written, notices = {}, []

    def run(cmd, **kw):
        if cmd[:2] == ["sudo", "tee"]:
            written[cmd[-1]] = kw["input"].decode()
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(
        join, "notify_wintools_case_deactivated", lambda: notices.append("off")
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    monkeypatch.setattr(case_copies, "write_case_copies", lambda c, d: {"copies": []})
    monkeypatch.setattr(case_copies, "summary_lines", lambda c, copied: [])
    monkeypatch.setenv("VHIR_CASES_DIR", str(cases))
    return types.SimpleNamespace(
        home=tmp_path,
        cases=cases,
        pointer=tmp_path / ".vhir" / "active_case",
        placeholder=str(tmp_path / ".vhir" / "share-inactive"),
        written=written,
        notices=notices,
    )


def _share_at(box, target):
    """samba.yaml and the share's conf both point at `target`."""
    target = str(target)
    doc = {
        "share_name": join.SHARE_NAME,
        "wintools_ip": "192.0.2.7",
        "active_share_target": target,
    }
    (box.home / ".vhir" / "samba.yaml").write_text(yaml.dump(doc))
    box.written[join.SMB_CONF_PATH] = join._share_conf(doc, target)


POINTERS = {
    "absolute": lambda box, case_id: str(box.cases / case_id),
    "bare id": lambda box, case_id: case_id,  # the legacy form
}


def _activate(box, case_id, form="absolute"):
    box.pointer.write_text(POINTERS[form](box, case_id))


def _close(box, case_id):
    main._case_close(
        argparse.Namespace(case_id=case_id, summary=""), {"examiner": "tester"}
    )
    status = yaml.safe_load((box.cases / case_id / "CASE.yaml").read_text())["status"]
    assert status == "closed"


def _target(box):
    return yaml.safe_load((box.home / ".vhir" / "samba.yaml").read_text())[
        "active_share_target"
    ]


def _conf_path(box):
    (path,) = [
        line.split("=", 1)[1].strip()
        for line in box.written[join.SMB_CONF_PATH].splitlines()
        if line.strip().startswith("path =")
    ]
    return path


def _active(box):
    return box.pointer.read_text() if box.pointer.exists() else None


@pytest.mark.parametrize("form", ["absolute", "bare id", "VHIR_CASE_DIR on B"])
def test_closing_another_case_leaves_the_active_cases_share(box, monkeypatch, form):
    """R1: A active and shared; closing B moves nothing and tells wintools
    nothing. VHIR_CASE_DIR (a session's own case) doesn't make B active."""
    if form == "VHIR_CASE_DIR on B":
        monkeypatch.setenv("VHIR_CASE_DIR", str(box.cases / "CASE-B"))
        form = "absolute"
    a = str(box.cases / "CASE-A")
    _share_at(box, a)
    _activate(box, "CASE-A", form)
    pointer = _active(box)
    _close(box, "CASE-B")
    after = (_active(box), _target(box), _conf_path(box), box.notices)
    assert after == (pointer, a, a, [])


@pytest.mark.parametrize("form", sorted(POINTERS))
def test_closing_the_active_case_moves_the_share_to_the_placeholder(box, form):
    """R2 twin: as before the fix."""
    _share_at(box, box.cases / "CASE-A")
    _activate(box, "CASE-A", form)
    _close(box, "CASE-A")
    after = (_active(box), _target(box), _conf_path(box), box.notices)
    assert after == (None, box.placeholder, box.placeholder, ["off"])


def test_closing_the_case_the_share_points_at_with_none_active(box):
    """R3: no active case, but the share is B's; closing B still takes it off B."""
    _share_at(box, box.cases / "CASE-B")
    _close(box, "CASE-B")
    after = (_active(box), _target(box), _conf_path(box), box.notices)
    assert after == (None, box.placeholder, box.placeholder, ["off"])


@pytest.mark.parametrize("resolved", ["share", "cases dir"])
def test_the_share_on_a_case_matches_through_a_symlink(box, monkeypatch, resolved):
    """R5: join writes the resolved spelling, activate the one VHIR_CASES_DIR
    gives; either way round, the share on B is B's."""
    real = box.home / "real-cases"
    box.cases.rename(real)
    box.cases.symlink_to(real)
    if resolved == "share":
        _share_at(box, real / "CASE-B")
    else:
        monkeypatch.setenv("VHIR_CASES_DIR", str(real))
        _share_at(box, box.cases / "CASE-B")
    _close(box, "CASE-B")
    after = (_target(box), _conf_path(box), box.notices)
    assert after == (box.placeholder, box.placeholder, ["off"])


def test_closing_the_shared_case_while_another_is_active_tells_wintools_nothing(box):
    """R6: N active, the share on B; closing B takes the share off B, and
    wintools keeps N (the gateway re-sends N's activation)."""
    _share_at(box, box.cases / "CASE-B")
    _activate(box, "CASE-N")
    _close(box, "CASE-B")
    after = (_active(box), _target(box), _conf_path(box), box.notices)
    assert after == (str(box.cases / "CASE-N"), box.placeholder, box.placeholder, [])


def _undecodable(box):
    box.pointer.write_bytes(b"\xff\xfe/cases/CASE-A")


def _a_directory(box):
    box.pointer.mkdir()


def _mode_000(box):
    _activate(box, "CASE-A")
    box.pointer.chmod(0)


POINTER_SHAPES = {
    "missing": lambda box: None,
    "empty": lambda box: box.pointer.write_text("\n"),
    "undecodable": _undecodable,
    "a directory": _a_directory,
    "mode 000": _mode_000,
}


@pytest.mark.parametrize("shape", sorted(POINTER_SHAPES))
def test_an_unreadable_pointer_is_no_active_case(box, shape):
    """R7: the share on A, a pointer close can't read; closing B leaves A's
    share and wintools alone, and the pointer stays as it was."""
    if shape == "mode 000" and os.geteuid() == 0:
        pytest.skip("root reads a mode-000 file")
    a = str(box.cases / "CASE-A")
    _share_at(box, a)
    POINTER_SHAPES[shape](box)
    try:
        _close(box, "CASE-B")
    finally:
        if shape == "mode 000":
            box.pointer.chmod(0o644)
    assert (_target(box), _conf_path(box), box.notices) == (a, a, [])
    assert box.pointer.exists() == (shape != "missing")
