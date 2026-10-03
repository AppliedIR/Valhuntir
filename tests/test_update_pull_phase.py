"""vhir update's pull phase: a stop after something changed says so.

Every repo's branch is checked before any pull, so a wrong branch changes
nothing. A pull that fails or times out after another repo's HEAD moved prints
the part-way block and the finish command; one before any change keeps the
plain exit. A timed-out --installed read prints the block, not a traceback. A
failed fetch shows git's own reason, without guessing at the network. git is a
stub keeping each repo's branch and HEAD.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands import update
from vhir_cli.commands.update import _PACKAGE_PATHS, cmd_update

PART_WAY = "Update stopped part-way"


@pytest.fixture
def world(tmp_path):
    src = tmp_path / ".vhir" / "src" / "sift-mcp"
    for rel in _PACKAGE_PATHS.values():
        (src / rel).mkdir(parents=True, exist_ok=True)
    (src / "deps").mkdir()
    (src / "deps" / "vhir.lock").write_text("# lock\n")
    (src / "deps" / "vhir-cpu.lock").write_text("# variant cpu\n")
    (src / "deps" / "check-lock.py").write_text("")
    vhir = tmp_path / ".vhir" / "src" / "vhir"
    vhir.mkdir()
    os_repo = tmp_path / "opensearch-mcp"
    os_repo.mkdir()
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")
    (tmp_path / ".vhir" / "manifest.json").write_text(
        json.dumps(
            {"source": str(src), "venv": str(venv), "packages": {}, "client": ""}
        )
    )
    repos = {
        str(p): {"name": n, "branch": "main", "head": f"{n}-old", "pull": "ok"}
        for n, p in (("sift-mcp", src), ("vhir", vhir), ("opensearch-mcp", os_repo))
    }
    return SimpleNamespace(home=tmp_path, os_repo=os_repo, repos=repos)


def _run(world, *, fetch_err="", installed_timeout=False):
    """Run cmd_update; returns (exit code or None, stderr+stdout, the heads)."""

    def run(cmd, **kw):
        cmd = [str(c) for c in cmd]
        r = MagicMock(returncode=0, stdout="", stderr="")
        repo = world.repos.get(cmd[2]) if cmd[:2] == ["git", "-C"] else None
        if cmd[:2] == ["uv", "--version"]:
            r.stdout = "uv 0.12.20"
        elif repo and cmd[3] == "fetch" and fetch_err:
            r.returncode, r.stderr = 128, fetch_err
        elif repo and cmd[3] == "symbolic-ref":
            r.stdout = repo["branch"]
        elif repo and cmd[3:5] == ["rev-parse", "HEAD"]:
            r.stdout = repo["head"]
        elif repo and cmd[3] == "pull":
            if repo["pull"] == "merge-then-timeout":  # a slow post-merge hook
                repo["head"] = repo["name"] + "-new"
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            if repo["pull"] == "timeout":
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            if repo["pull"] == "merge-then-fail":  # a post-merge hook failed
                repo["head"] = repo["name"] + "-new"
                r.returncode, r.stderr = 1, "error: post-merge hook failed"
            elif repo["pull"] == "fail":
                r.returncode, r.stderr = (
                    1,
                    "fatal: Not possible to fast-forward, aborting.",
                )
            elif repo["pull"] == "ok":
                repo["head"] = repo["name"] + "-new"
            # "uptodate": HEAD stays
        elif repo and cmd[3] == "rev-list":
            r.stdout = "1"
        elif (
            len(cmd) > 2
            and cmd[1].endswith("check-lock.py")
            and cmd[2] == "--installed"
        ):
            if installed_timeout:
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        elif len(cmd) > 2 and cmd[1] == "-I" and "torch" in cmd[-1]:
            r.returncode = 1  # no torch
        return r

    code = None
    with (
        patch("pathlib.Path.home", return_value=world.home),
        patch("subprocess.run", side_effect=run),
        patch.object(update, "_resolve_opensearch_mcp_repo", lambda src: world.os_repo),
        patch.object(update, "_ensure_password_dir", lambda: None),
        patch("sys.stdin.isatty", return_value=False),
    ):
        try:
            cmd_update(
                MagicMock(check=False, no_restart=True, cpu=False, gpu=False), {}
            )
        except SystemExit as e:
            code = e.code
    return code, {r["name"]: r["head"] for r in world.repos.values()}


def _repo(world, name):
    return next(r for r in world.repos.values() if r["name"] == name)


def test_a_third_repo_off_main_stops_before_any_pull(world, capsys):
    _repo(world, "opensearch-mcp")["branch"] = "feature"
    code, heads = _run(world)
    assert code == 1 and "expected 'main'" in capsys.readouterr().err
    assert set(heads.values()) == {"sift-mcp-old", "vhir-old", "opensearch-mcp-old"}


def test_a_failed_pull_after_another_moved_is_part_way(world, capsys):
    _repo(world, "vhir")["pull"] = "fail"
    code, heads = _run(world)
    err = capsys.readouterr().err
    assert code == 1 and heads["sift-mcp"] == "sift-mcp-new"
    assert "Not possible to fast-forward" in err and "Resolve conflicts" in err
    assert PART_WAY in err and err.rstrip().endswith("finish with: vhir update")


def test_a_pull_timeout_after_another_moved_is_part_way(world, capsys):
    _repo(world, "vhir")["pull"] = "timeout"
    code, _ = _run(world)  # not a traceback: SystemExit
    err = capsys.readouterr().err
    assert code == 1 and "Pulling vhir timed out after 60 seconds." in err
    assert PART_WAY in err and "Resolve conflicts" not in err


def test_an_installed_read_timeout_is_part_way(world, capsys):
    code, _ = _run(world, installed_timeout=True)
    err = capsys.readouterr().err
    assert code == 1 and "timed out after 120 seconds" in err and PART_WAY in err


def test_a_fetch_failure_shows_gits_reason_without_guessing(world, capsys):
    reason = "error: cannot open .git/FETCH_HEAD: Read-only file system"
    code, _ = _run(world, fetch_err=reason)
    err = capsys.readouterr().err
    assert code == 1 and f"git fetch failed for sift-mcp: {reason}" in err
    assert "Check network" not in err


def test_anchor_a_failed_first_pull_changed_nothing_so_no_block(world, capsys):
    _repo(world, "sift-mcp")["pull"] = "fail"
    code, heads = _run(world)
    err = capsys.readouterr().err
    assert code == 1 and "Failed to pull sift-mcp" in err and PART_WAY not in err
    assert set(heads.values()) == {"sift-mcp-old", "vhir-old", "opensearch-mcp-old"}


def test_anchor_an_up_to_date_first_repo_then_a_failure_is_no_block(world, capsys):
    _repo(world, "sift-mcp")["pull"] = "uptodate"
    _repo(world, "vhir")["pull"] = "fail"
    code, _ = _run(world)
    err = capsys.readouterr().err
    assert code == 1 and "Failed to pull vhir" in err and PART_WAY not in err


def test_anchor_a_clean_update_has_no_block(world, capsys):
    code, heads = _run(world)
    out = capsys.readouterr()
    assert code is None and PART_WAY not in out.err
    assert set(heads.values()) == {"sift-mcp-new", "vhir-new", "opensearch-mcp-new"}


def test_a_first_pull_that_merged_then_timed_out_is_part_way(world, capsys):
    _repo(world, "sift-mcp")["pull"] = "merge-then-timeout"
    code, heads = _run(world)
    err = capsys.readouterr().err
    assert code == 1 and heads["sift-mcp"] == "sift-mcp-new"
    assert "Pulling sift-mcp timed out after 60 seconds." in err and PART_WAY in err


def test_a_first_pull_that_merged_then_failed_is_part_way(world, capsys):
    _repo(world, "sift-mcp")["pull"] = "merge-then-fail"
    code, heads = _run(world)
    err = capsys.readouterr().err
    assert code == 1 and heads["sift-mcp"] == "sift-mcp-new"
    assert "post-merge hook failed" in err and PART_WAY in err
