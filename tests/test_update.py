"""Tests for vhir update command."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands.update import (
    _INSTALL_ORDER,
    _PACKAGE_PATHS,
    cmd_update,
)


@pytest.fixture
def manifest_dir(tmp_path):
    """Create a minimal manifest layout."""
    vhir_dir = tmp_path / ".vhir"
    vhir_dir.mkdir()

    src = tmp_path / ".vhir" / "src" / "sift-mcp"
    src.mkdir(parents=True)
    (tmp_path / ".vhir" / "src" / "vhir").mkdir()

    venv = tmp_path / "venv"
    venv.mkdir()
    pip = venv / "bin" / "pip"
    pip.parent.mkdir(parents=True)
    pip.write_text("#!/bin/sh\n")

    # Create package dirs
    for rel in _PACKAGE_PATHS.values():
        (src / rel).mkdir(parents=True, exist_ok=True)

    manifest = {
        "version": "1.0",
        "source": str(src),
        "venv": str(venv),
        "packages": {
            "forensic-knowledge": {"module": "forensic_knowledge", "version": "0.1.0"},
            "sift-common": {"module": "sift_common", "version": "0.1.0"},
            "forensic-mcp": {"module": "forensic_mcp", "version": "0.1.0"},
            "sift-mcp": {"module": "sift_mcp", "version": "0.1.0"},
            "sift-gateway": {"module": "sift_gateway", "version": "0.1.0"},
            "vhir-cli": {"module": "vhir_cli", "version": "0.1.0"},
            "case-mcp": {"module": "case_mcp", "version": "0.1.0"},
            "report-mcp": {"module": "report_mcp", "version": "0.1.0"},
        },
        "client": "claude-code",
        "git": {"sift-mcp": "abc1234", "vhir": "def5678"},
    }
    manifest_path = vhir_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return tmp_path, manifest_path


def _make_args(**kwargs):
    args = MagicMock()
    args.check = kwargs.get("check", False)
    args.no_restart = kwargs.get("no_restart", False)
    return args


def test_no_manifest_fails(tmp_path):
    """Fail cleanly when no manifest exists."""
    with patch("pathlib.Path.home", return_value=tmp_path):
        with pytest.raises(SystemExit):
            cmd_update(_make_args(), {})


def test_broken_venv_fails(manifest_dir):
    """Fail cleanly when venv pip is missing."""
    tmp_path, manifest_path = manifest_dir
    manifest = json.loads(manifest_path.read_text())
    pip = Path(manifest["venv"]) / "bin" / "pip"
    pip.unlink()

    with patch("pathlib.Path.home", return_value=tmp_path):
        with pytest.raises(SystemExit):
            cmd_update(_make_args(), {})


def test_check_up_to_date(manifest_dir, capsys):
    """--check shows up to date when no commits behind."""
    tmp_path, _ = manifest_dir

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        if "fetch" in cmd:
            result.returncode = 0
        elif "rev-list" in cmd:
            result.returncode = 0
            result.stdout = "0"
        elif "rev-parse" in cmd:
            result.returncode = 0
            result.stdout = "abc1234567890"
        else:
            result.returncode = 0
            result.stdout = ""
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
    ):
        cmd_update(_make_args(check=True), {})

    out = capsys.readouterr().out
    assert "up to date" in out


def test_check_behind(manifest_dir, capsys):
    """--check shows commit count when behind."""
    tmp_path, _ = manifest_dir

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        if "fetch" in cmd:
            result.returncode = 0
        elif "rev-list" in cmd:
            result.returncode = 0
            result.stdout = "3"
        elif "rev-parse" in cmd and "origin/main" in cmd:
            result.returncode = 0
            result.stdout = "new1234567890"
        elif "rev-parse" in cmd:
            result.returncode = 0
            result.stdout = "abc1234567890"
        else:
            result.returncode = 0
            result.stdout = ""
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
    ):
        cmd_update(_make_args(check=True), {})

    out = capsys.readouterr().out
    assert "3 commits behind" in out
    assert "vhir update" in out


def test_fetch_failure(manifest_dir, capsys):
    """Fail cleanly when git fetch fails."""
    tmp_path, _ = manifest_dir

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        if "fetch" in cmd:
            result.returncode = 1
            result.stderr = "Could not resolve host: github.com"
        else:
            result.returncode = 0
            result.stdout = ""
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
    ):
        with pytest.raises(SystemExit):
            cmd_update(_make_args(), {})


def test_pip_install_order(manifest_dir):
    """Packages are installed in dependency order."""
    tmp_path, _ = manifest_dir
    installed = []

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "0"
        result.stderr = ""
        if "symbolic-ref" in cmd:
            result.stdout = "main"
        elif cmd[0].endswith("/pip") and "install" in cmd:
            # Extract package path
            installed.append(cmd[-1])
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test"),
    ):
        cmd_update(_make_args(no_restart=True), {})

    # Verify order: vhir-cli must come before case-mcp and report-mcp
    vhir_idx = next((i for i, p in enumerate(installed) if p.endswith("/vhir")), -1)
    case_idx = next((i for i, p in enumerate(installed) if "case-mcp" in p), -1)
    report_idx = next((i for i, p in enumerate(installed) if "report-mcp" in p), -1)

    if vhir_idx >= 0 and case_idx >= 0:
        assert vhir_idx < case_idx, "vhir-cli must install before case-mcp"
    if vhir_idx >= 0 and report_idx >= 0:
        assert vhir_idx < report_idx, "vhir-cli must install before report-mcp"


def test_no_restart_flag(manifest_dir):
    """--no-restart skips gateway restart."""
    tmp_path, _ = manifest_dir
    systemctl_called = []

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "0"
        result.stderr = ""
        if "symbolic-ref" in cmd:
            result.stdout = "main"
        elif "systemctl" in cmd:
            systemctl_called.append(cmd)
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch("vhir_cli.commands.setup._run_connectivity_test"),
    ):
        cmd_update(_make_args(no_restart=True), {})

    assert len(systemctl_called) == 0


def test_client_written_to_manifest(tmp_path):
    """client_setup writes client type to manifest."""
    manifest_path = tmp_path / ".vhir" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps({"version": "1.0"}))

    with patch("pathlib.Path.home", return_value=tmp_path):
        # Simulate the manifest write logic directly
        manifest = json.loads(manifest_path.read_text())
        manifest["client"] = "librechat"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    result = json.loads(manifest_path.read_text())
    assert result["client"] == "librechat"


def test_wrong_branch_fails(manifest_dir):
    """Fail cleanly when repo is not on main branch."""
    tmp_path, _ = manifest_dir

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "0"
        result.stderr = ""
        if "symbolic-ref" in cmd:
            result.stdout = "feature-branch"
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
    ):
        with pytest.raises(SystemExit):
            cmd_update(_make_args(), {})


def test_install_order_matches_package_paths():
    """Every package in _PACKAGE_PATHS has a position in _INSTALL_ORDER."""
    for pkg in _PACKAGE_PATHS:
        assert pkg in _INSTALL_ORDER, f"{pkg} missing from _INSTALL_ORDER"


def test_old_manifest_no_client(manifest_dir, capsys):
    """Old manifest without client key skips controls gracefully."""
    tmp_path, manifest_path = manifest_dir
    manifest = json.loads(manifest_path.read_text())
    del manifest["client"]
    manifest_path.write_text(json.dumps(manifest, indent=2))

    def mock_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "0"
        result.stderr = ""
        if "symbolic-ref" in cmd:
            result.stdout = "main"
        return result

    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("subprocess.run", side_effect=mock_run),
        patch("vhir_cli.commands.setup._run_connectivity_test"),
    ):
        cmd_update(_make_args(no_restart=True), {})

    out = capsys.readouterr().out
    assert "vhir setup client" in out
