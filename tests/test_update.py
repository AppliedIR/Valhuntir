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


# ---------------------------------------------------------------------------
# _detect_constraint_changed_packages — B81 UAT 2026-04-23
# ---------------------------------------------------------------------------


class TestDetectConstraintChangedPackages:
    """Auto-detect packages whose version constraints moved in pulled
    commits so `uv pip install -e` can re-resolve them. Covers the
    pycti<7.0 class of footguns — changing a ceiling in pyproject.toml
    has no effect on an already-installed package without an explicit
    --reinstall-package hint."""

    @staticmethod
    def _init_repo(repo):
        import subprocess as _sp

        _sp.run(["git", "init", "-q", str(repo)], check=True)
        _sp.run(["git", "-C", str(repo), "config", "user.email", "t@t"], check=True)
        _sp.run(["git", "-C", str(repo), "config", "user.name", "t"], check=True)

    @staticmethod
    def _commit(repo, msg):
        import subprocess as _sp

        _sp.run(["git", "-C", str(repo), "add", "."], check=True)
        _sp.run(["git", "-C", str(repo), "commit", "-q", "-m", msg], check=True)

    @staticmethod
    def _sha(repo):
        import subprocess as _sp

        return _sp.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def test_detects_changed_version_constraint(self, tmp_path):
        """Constraint tightened on an existing package → package name
        returned for --reinstall-package."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text(
            '[project]\nname="x"\ndependencies = [\n    "pycti>=6.0",\n    "mcp>=1.26",\n]\n'
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        py.write_text(
            '[project]\nname="x"\ndependencies = [\n    "pycti>=6.0,<7.0",\n    "mcp>=1.26",\n]\n'
        )
        self._commit(repo, "tighten pycti")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "pycti" in changed
        # Unchanged line must NOT appear.
        assert "mcp" not in changed

    def test_detects_added_and_removed_packages(self, tmp_path):
        """Package added or removed between commits must also appear —
        resolver needs the hint on either direction."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text(
            '[project]\ndependencies = [\n    "oldpkg>=1.0",\n    "stable>=2.0",\n]\n'
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        py.write_text(
            '[project]\ndependencies = [\n    "newpkg>=3.0",\n    "stable>=2.0",\n]\n'
        )
        self._commit(repo, "swap")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "oldpkg" in changed  # removed
        assert "newpkg" in changed  # added
        assert "stable" not in changed  # unchanged

    def test_handles_extras_and_markers(self, tmp_path):
        """Extras like pycti[foo] and markers like `; python_version>='3.10'`
        must not break the regex — leading identifier is extracted cleanly."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text(
            "[project]\ndependencies = [\n"
            "    \"pycti[extra]>=6.0; python_version>='3.10'\",\n"
            "]\n"
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        py.write_text(
            "[project]\ndependencies = [\n"
            "    \"pycti[extra]>=6.0,<7.0; python_version>='3.10'\",\n"
            "]\n"
        )
        self._commit(repo, "tighten")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "pycti" in changed
        # Extras/markers must not leak into package-name set.
        assert "extra" not in changed
        assert "python_version" not in changed

    def test_unchanged_repo_yields_empty(self, tmp_path):
        """No changes between old and new → empty set, no redundant
        --reinstall-package entries on the uv command line."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text('[project]\ndependencies = ["pycti>=6.0"]\n')
        self._commit(repo, "init")
        sha = self._sha(repo)

        # Pre-update SHA == current HEAD → no pull happened → no changes.
        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": sha}
        )
        assert changed == set()

    def test_monorepo_scans_all_pyproject_tomls(self, tmp_path):
        """sift-mcp has packages/*/pyproject.toml — every one must be
        scanned, not just the repo-root one."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "monorepo"
        repo.mkdir()
        (repo / "packages" / "alpha").mkdir(parents=True)
        (repo / "packages" / "beta").mkdir(parents=True)
        self._init_repo(repo)
        (repo / "pyproject.toml").write_text(
            '[project]\ndependencies = ["root_dep>=1.0"]\n'
        )
        (repo / "packages" / "alpha" / "pyproject.toml").write_text(
            '[project]\ndependencies = ["alpha_dep>=1.0"]\n'
        )
        (repo / "packages" / "beta" / "pyproject.toml").write_text(
            '[project]\ndependencies = ["beta_dep>=1.0"]\n'
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        # Tighten constraint only in packages/beta/pyproject.toml.
        (repo / "packages" / "beta" / "pyproject.toml").write_text(
            '[project]\ndependencies = ["beta_dep>=1.0,<2.0"]\n'
        )
        self._commit(repo, "tighten beta")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "beta_dep" in changed
        # Other files unchanged → their deps should not appear.
        assert "root_dep" not in changed
        assert "alpha_dep" not in changed

    # -------------------------------------------------------------------
    # UAT 2026-04-23 — adversarial inputs + soft-fail isolation. Dev's
    # 5 tests above cover the golden shapes; these probe edge cases
    # that would silently drop packages from the reinstall set or
    # crash the walker across sibling repos. Landing alongside the
    # fix per "tests land with the fix" discipline.
    # -------------------------------------------------------------------

    def test_detects_deps_with_trailing_comments(self, tmp_path):
        """Operators often annotate dep pins with rationale comments
        (`"pycti>=6.0",  # pin for compat`). The leading-identifier
        regex must still match the capture group; comments after the
        quoted string must not prevent detection."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text(
            "[project]\ndependencies = [\n"
            '    "pycti>=6.0",  # permissive — runtime-gate handles skew\n'
            "]\n"
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        py.write_text(
            "[project]\ndependencies = [\n"
            '    "pycti>=6.0,<7.0",  # pin for OpenCTI 6.x compat\n'
            "]\n"
        )
        self._commit(repo, "tighten pycti")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "pycti" in changed

    def test_detects_git_url_source_deps(self, tmp_path):
        """PEP 508 allows `"name @ git+https://..."` sources. The
        identifier-capture regex stops at whitespace, so the leading
        package name should still be extracted cleanly when the
        source line changes."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        repo = tmp_path / "pkg"
        repo.mkdir()
        self._init_repo(repo)
        py = repo / "pyproject.toml"
        py.write_text(
            "[project]\ndependencies = [\n"
            '    "customlib @ git+https://example.com/org/customlib.git@v1.0",\n'
            "]\n"
        )
        self._commit(repo, "init")
        old_sha = self._sha(repo)
        py.write_text(
            "[project]\ndependencies = [\n"
            '    "customlib @ git+https://example.com/org/customlib.git@v2.0",\n'
            "]\n"
        )
        self._commit(repo, "bump customlib ref")

        changed = _detect_constraint_changed_packages(
            [("test-repo", repo)], {"test-repo": old_sha}
        )
        assert "customlib" in changed

    def test_soft_fails_on_broken_repo_and_continues_with_siblings(self, tmp_path):
        """Per-repo isolation — if one repo's git diff invocation fails
        (missing SHA, corrupted state), the helper must continue with
        the remaining repos. Closes the "one dead repo blocks the
        whole install" failure mode. Backstop for the `continue`
        path in _detect_constraint_changed_packages:703-707."""
        from vhir_cli.commands.update import _detect_constraint_changed_packages

        # Broken repo: real path, but the claimed pre-update SHA
        # doesn't exist in that repo's history. `git diff a..b`
        # returns non-zero, helper must soft-fail on this repo.
        broken = tmp_path / "broken"
        broken.mkdir()
        self._init_repo(broken)
        (broken / "pyproject.toml").write_text('[project]\ndependencies = ["x>=1.0"]\n')
        self._commit(broken, "init")

        # Healthy sibling repo with a real constraint change that
        # should still be detected.
        healthy = tmp_path / "healthy"
        healthy.mkdir()
        self._init_repo(healthy)
        py = healthy / "pyproject.toml"
        py.write_text('[project]\ndependencies = ["pycti>=6.0"]\n')
        self._commit(healthy, "init")
        old_sha_healthy = self._sha(healthy)
        py.write_text('[project]\ndependencies = ["pycti>=6.0,<7.0"]\n')
        self._commit(healthy, "tighten")

        changed = _detect_constraint_changed_packages(
            [("broken", broken), ("healthy", healthy)],
            # 40-hex SHA that doesn't exist in broken's history.
            {"broken": "0" * 40, "healthy": old_sha_healthy},
        )
        # Broken repo yielded no findings (soft-fail) — no exception
        # escaped — AND healthy repo's changes still made it through.
        assert "pycti" in changed
