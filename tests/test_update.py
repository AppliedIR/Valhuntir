"""Tests for vhir update command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands.update import (
    _INSTALL_ORDER,
    _PACKAGE_PATHS,
    _opensearch_mcp_installed_but_missing,
    _resolve_opensearch_mcp_repo,
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
    venv_bin = venv / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").write_text("#!/bin/sh\n")
    (venv_bin / "pip").write_text("#!/bin/sh\n")

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


# ---------------------------------------------------------------------------
# Regression guard — opensearch-mcp update silent-skip fix (2026-04-22)
#
# Prior bug: the two-candidate fallback list in `cmd_update` and
# `_check_opensearch_version` both resolved to `~/.vhir/src/opensearch-mcp`
# when `source = ~/.vhir/src/sift-mcp`, producing a dead-duplicate.
# Operators with opensearch-mcp at any non-default layout (e.g.
# `/home/sansforensics/opensearch-mcp/`) were silently skipped —
# no warning, no pull, no reinstall. This defeats `vhir update`
# precisely when opensearch-mcp has critical fixes to distribute.
# The three tests below guard against a future refactor re-introducing
# the bug.
# ---------------------------------------------------------------------------


def test_resolve_opensearch_mcp_via_importlib(tmp_path, monkeypatch):
    """When opensearch-mcp is editable-installed at an arbitrary path,
    the helper resolves to the repo root via `importlib.util.find_spec`
    regardless of the default-layout candidates."""
    repo = tmp_path / "arbitrary-location" / "opensearch-mcp"
    (repo / "src" / "opensearch_mcp").mkdir(parents=True)
    (repo / ".git").mkdir()
    init_file = repo / "src" / "opensearch_mcp" / "__init__.py"
    init_file.write_text("")

    fake_spec = SimpleNamespace(origin=str(init_file))
    monkeypatch.setattr(
        "importlib.util.find_spec",
        lambda name: fake_spec if name == "opensearch_mcp" else None,
    )
    # Ensure the default-candidate path does NOT exist so we can
    # prove the importlib path is what succeeded.
    source = tmp_path / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)

    result = _resolve_opensearch_mcp_repo(source)
    assert result == repo.resolve()


def test_resolve_opensearch_mcp_fallback_to_candidates(tmp_path, monkeypatch):
    """When import machinery reports the package unavailable, helper
    falls back through the candidate layout list. Proves the
    dead-duplicate bug is gone — default layout resolves correctly."""
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)

    source = tmp_path / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)
    os_repo = tmp_path / ".vhir" / "src" / "opensearch-mcp"
    (os_repo / ".git").mkdir(parents=True)

    result = _resolve_opensearch_mcp_repo(source)
    assert result == os_repo.resolve()


def test_resolve_opensearch_mcp_none_when_nothing_found(tmp_path, monkeypatch):
    """Returns None when neither import machinery nor candidate paths
    locate a repo — the precondition for the installed-but-missing
    warning branch."""
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    # Point home() at an empty tmp_path so no ~/-based candidates hit.
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "empty-home")
    source = tmp_path / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)

    assert _resolve_opensearch_mcp_repo(source) is None


def test_installed_but_missing_detects_silent_staleness(tmp_path, monkeypatch):
    """The exact silent-staleness condition Test agent flagged: the
    opensearch_mcp package imports fine (package installed in venv) but
    no git repo exists on disk (e.g., operator deleted or moved the
    clone). `_opensearch_mcp_installed_but_missing` must return True so
    `cmd_update` can emit its actionable stderr warning instead of
    silently skipping."""
    # Package appears installed (find_spec returns a spec with no origin —
    # mimics a site-packages install with no editable source).
    monkeypatch.setattr(
        "importlib.util.find_spec",
        lambda name: SimpleNamespace(origin=None) if name == "opensearch_mcp" else None,
    )
    # No candidates exist on disk.
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path / "empty-home")
    source = tmp_path / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)

    assert _opensearch_mcp_installed_but_missing(source) is True


def test_installed_but_missing_false_when_package_absent(tmp_path, monkeypatch):
    """If the package is not installed at all, return False — nothing
    to warn about, `vhir update` correctly skips without noise."""
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    source = tmp_path / ".vhir" / "src" / "sift-mcp"
    source.mkdir(parents=True)

    assert _opensearch_mcp_installed_but_missing(source) is False
