"""vhir update adds -I to the gateway's own launch lines on existing installs.

setup-sift.sh writes ~/.vhir/start-gateway.sh and the vhir-gateway user unit,
and runs the gateway with `python -m sift_gateway`, which puts the directory it
starts in first on sys.path. The installer now writes `python -I`, but update
never rewrote the files. The fixtures are the files v0.6.1's and the current
installer's heredocs render (the same for v0.5.4 to v0.6.1, unit fields aside).
systemctl is a stub on PATH; nothing touches the real user manager.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from vhir_cli.commands import client_setup as cs

SCRIPT_061 = """#!/usr/bin/env bash
# Start Valhuntir Gateway
export VHIR_EXAMINER="steve"
export VHIR_CASES_DIR="/__HOME__/cases"
exec "/__VENV__/bin/python" -m sift_gateway --config "/__HOME__/.vhir/gateway.yaml"
"""
UNIT_061 = """[Unit]
Description=Valhuntir Gateway
After=network.target

[Service]
ExecStart=/__VENV__/bin/python -m sift_gateway --config /__HOME__/.vhir/gateway.yaml
Environment=VHIR_EXAMINER=steve
Environment=VHIR_CASES_DIR=/__HOME__/cases
PassEnvironment=DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR
MemoryMax=4G
KillMode=process
TimeoutStopSec=10
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
# What the current installer (python -I) renders for the same install.
SCRIPT_NEW = SCRIPT_061.replace('python" -m', 'python" -I -m')
UNIT_NEW = UNIT_061.replace("python -m", "python -I -m")


class Box:
    def __init__(self, tmp_path, monkeypatch, systemctl=True, venv="venv"):
        self.home = tmp_path / "home"
        self.venv = tmp_path / venv
        self.script = self.home / ".vhir" / "start-gateway.sh"
        self.unit = self.home / ".config" / "systemd" / "user" / "vhir-gateway.service"
        self.calls = tmp_path / "systemctl.calls"
        stub = tmp_path / "bin"
        stub.mkdir()
        if systemctl:
            (stub / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> "{self.calls}"\n')
            (stub / "systemctl").chmod(0o755)
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.setenv("PATH", str(stub))  # never the real systemctl

    def render(self, text: str) -> str:
        return text.replace("/__VENV__", str(self.venv)).replace(
            "/__HOME__", str(self.home)
        )

    def write(self, path: Path, text: str, mode: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(text))
        path.chmod(mode)

    def install(self, script=SCRIPT_061, unit=UNIT_061) -> None:
        if script is not None:
            self.write(self.script, script, 0o755)
        if unit is not None:
            self.write(self.unit, unit, 0o644)

    def reloads(self) -> int:
        return (
            self.calls.read_text().count("--user daemon-reload")
            if self.calls.exists()
            else 0
        )


@pytest.fixture
def box(tmp_path, monkeypatch):
    return Box(tmp_path, monkeypatch)


def _snap(path: Path):
    st = path.stat()
    return path.read_bytes(), st.st_ino, st.st_mtime_ns


def test_a_061_install_gets_the_files_the_current_installer_writes(box, capsys):
    box.install()
    assert set(cs._isolate_gateway_launchers()) == {box.script, box.unit}
    assert box.script.read_text() == box.render(SCRIPT_NEW)  # byte-identical
    assert box.unit.read_text() == box.render(UNIT_NEW)
    assert stat.S_IMODE(box.script.stat().st_mode) == 0o755  # still runs
    assert stat.S_IMODE(box.unit.stat().st_mode) == 0o644
    assert box.reloads() == 1  # the restart uses the new unit
    out = capsys.readouterr().out
    assert f"Updated: {box.script} (added -I" in out and f"Updated: {box.unit}" in out


def test_another_unit_field_the_user_changed_is_kept(box):
    box.install(unit=UNIT_061.replace("MemoryMax=4G", "MemoryMax=12G"))
    before = box.unit.read_text().splitlines()
    cs._isolate_gateway_launchers()
    after = box.unit.read_text().splitlines()
    assert [(a, b) for a, b in zip(before, after, strict=True) if a != b] == [
        (before[5], before[5].replace("python -m", "python -I -m"))
    ]
    assert "MemoryMax=12G" in after


@pytest.mark.parametrize(
    "edit",
    [
        ("unit", "--config", "--port 4600 --config"),
        ("script", 'exec "', 'exec nice -n 5 "'),
    ],
    ids=["extra flag in ExecStart", "script wrapped in nice"],
)
def test_a_launch_line_the_user_edited_is_left_with_a_notice(box, capsys, edit):
    which, old, new = edit
    box.install(
        script=SCRIPT_061.replace(old, new) if which == "script" else SCRIPT_061,
        unit=UNIT_061.replace(old, new, 1) if which == "unit" else UNIT_061,
    )
    path = box.unit if which == "unit" else box.script
    before = _snap(path)
    cs._isolate_gateway_launchers()
    assert _snap(path) == before
    assert f"Note: {path} has a gateway launch line Valhuntir didn't write" in (
        capsys.readouterr().out
    )


def test_a_second_run_writes_nothing_and_says_nothing(box, capsys):
    box.install()
    cs._isolate_gateway_launchers()
    capsys.readouterr()
    before = (_snap(box.script), _snap(box.unit), box.reloads())
    assert cs._isolate_gateway_launchers() == []
    assert (_snap(box.script), _snap(box.unit), box.reloads()) == before
    assert capsys.readouterr().out == ""


def test_a_users_own_dash_i_variant_is_not_nagged(box, capsys):
    box.install(unit=UNIT_061.replace("python -m", "python -I -E -m"))
    cs._isolate_gateway_launchers()
    assert str(box.unit) not in capsys.readouterr().out


def test_no_launcher_files_is_a_silent_no_op(box, capsys):
    assert cs._isolate_gateway_launchers() == []
    assert capsys.readouterr().out == "" and box.reloads() == 0


def test_a_script_only_install_needs_no_reload(box):
    box.install(unit=None)
    assert cs._isolate_gateway_launchers() == [box.script]
    assert box.reloads() == 0


def test_no_systemctl_still_rewrites_and_says_to_reload(tmp_path, monkeypatch, capsys):
    box = Box(tmp_path, monkeypatch, systemctl=False)
    box.install()
    assert box.unit in cs._isolate_gateway_launchers()
    assert box.unit.read_text() == box.render(UNIT_NEW)
    assert "systemctl --user daemon-reload" in capsys.readouterr().out


def test_a_linked_unit_stays_a_link(box, tmp_path):
    real = tmp_path / "units" / "vhir-gateway.service"
    box.write(real, UNIT_061, 0o644)
    box.unit.parent.mkdir(parents=True)
    box.unit.symlink_to(real)
    cs._isolate_gateway_launchers()
    assert box.unit.is_symlink() and real.read_text() == box.render(UNIT_NEW)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file")
def test_it_never_raises(box, capsys):
    box.install()
    box.unit.chmod(0)  # unreadable
    try:
        cs._isolate_gateway_launchers()
    finally:
        box.unit.chmod(0o644)
    assert f"could not check {box.unit}" in capsys.readouterr().out
    assert box.script.read_text() == box.render(SCRIPT_NEW)  # the other still done


def test_the_client_deploy_runs_it(box, monkeypatch):
    """An older vhir update reaches the new code only through this call
    (its Step 5), after its pull and before its gateway restart."""
    box.install()
    monkeypatch.setattr(cs, "_find_claude_code_assets", lambda: None)
    cs._deploy_claude_code_assets()
    assert box.script.read_text() == box.render(SCRIPT_NEW)
    assert box.unit.read_text() == box.render(UNIT_NEW)


def test_a_venv_path_with_a_space_fixes_the_script_and_notes_the_unit(
    tmp_path, monkeypatch, capsys
):
    """--venv= allows a space. The script quotes its paths; systemd splits an
    unquoted ExecStart, so that unit never ran and is only noted."""
    box = Box(tmp_path, monkeypatch, venv="opt venv")
    box.install()
    assert cs._isolate_gateway_launchers() == [box.script]
    assert box.script.read_text() == box.render(SCRIPT_NEW)
    assert f"Note: {box.unit}" in capsys.readouterr().out
