"""A backup whose snapshot fails for want of setup says how to set it up.

`vhir backup --include-opensearch` runs through the real command line with a
stand-in cluster. When the cluster can't write snapshots to this box's
folder (path.repo empty, the folder not writable), the warning is followed
by the setup script's absolute path, quoted for the shell; other failures (a
PARTIAL snapshot, a refused connection) get the warning only. A cause setup
can't change is named instead of the setup hint: an examiner whose uid isn't
OpenSearch's (1000), and VHIR_SNAPSHOTS_DIR set to a folder OpenSearch doesn't
write; a verification exception gets the hint plus what's left when setup has
run, and is blamed on the uid only when its cause is Permission denied. The
500's text is the one a 3.5.0 cluster gives with an empty path.repo; other
values are synthetic.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("opensearch_mcp")

from vhir_cli.commands import backup as B  # noqa: E402
from vhir_cli.commands.update import (  # noqa: E402
    _resolve_opensearch_mcp_repo as REAL_RESOLVE,
)

EMPTY = (
    "[{repo}] location [/usr/share/opensearch/snapshots/{repo}] doesn't match any of the "
    "locations specified by path.repo because this setting is empty"
)


class FakeCluster:
    def __init__(self, mode):
        self.mode = mode
        self.snapshot = SimpleNamespace(
            create_repository=self._register,
            delete_repository=lambda **k: None,
            create=lambda **k: {"accepted": True},
            status=lambda **k: {"snapshots": [{"state": "PARTIAL"}]},
            get=lambda **k: {
                "snapshots": [
                    {
                        "state": "SUCCESS" if mode == "elsewhere" else "PARTIAL",
                        "indices": [],
                    }
                ]
            },
        )
        self.cat = SimpleNamespace(
            indices=lambda **k: [{"index": "case-x-evtx-0", "docs.count": "3"}]
        )

    def info(self):
        return {"version": {"number": "3.5.0"}}

    def _register(self, repository, body, **k):
        from opensearchpy.exceptions import ConnectionError as Refused
        from opensearchpy.exceptions import TransportError

        if self.mode in ("verification", "no space"):
            reason = (
                f"[{repository}] store location [...] is not accessible on the node"
            )
            if self.mode == "no space":
                reason += ": java.io.IOException: No space left on device"
            cause = {"type": "repository_verification_exception", "reason": reason}
            body = {"error": {"root_cause": [cause], **cause}, "status": 500}
            raise TransportError(500, "repository_verification_exception", body)
        if self.mode == "path.repo empty":
            reason = EMPTY.format(repo=repository)
            cause = {"type": "repository_exception", "reason": reason}
            body = {"error": {"root_cause": [cause], **cause}, "status": 500}
            raise TransportError(500, "repository_exception", body)
        if self.mode == "refused":
            raise Refused(
                "N/A", "Connection refused", OSError(111, "Connection refused")
            )


@pytest.fixture
def box(tmp_path, monkeypatch):
    for name in ("home", "cases", "out", "snapshots"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    case = tmp_path / "cases" / "C-1"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: C-1\nstatus: open\n")
    (case / "findings.json").write_text("[]")
    (case / "timeline.json").write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(case))
    monkeypatch.setattr(B, "_SNAPSHOTS_DIR", tmp_path / "snapshots")
    monkeypatch.setattr(B, "_is_opensearch_available", lambda: True)
    monkeypatch.setattr(
        B,
        "_detect_opensearch",
        lambda case_dir: {"available": True, "local": True, "index_count": 1,
                          "total_docs": 3, "size_human": "1 KB"},
    )  # fmt: skip
    repo = tmp_path / "src" / "opensearch-mcp"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "setup-opensearch.sh").write_text("#!/bin/bash\n")
    from vhir_cli.commands import update

    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: repo)
    return SimpleNamespace(tmp=tmp_path, repo=repo)


def _backup(box, monkeypatch, capsys, mode):
    import opensearch_mcp.client

    from vhir_cli.main import main

    monkeypatch.setattr(
        opensearch_mcp.client, "get_client", lambda *a, **k: FakeCluster(mode)
    )
    monkeypatch.setattr(
        sys, "argv", ["vhir", "backup", str(box.tmp / "out"), "--include-opensearch"]
    )
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    out = capsys.readouterr()
    return code, out.err


HINT = (
    "OpenSearch on this box isn't set up for snapshots. To set it up, run:\n"
    "  bash {script}\n"
    "It recreates the vhir-opensearch container; its indexed data is kept.\n"
    "Then run the backup again."
)


@pytest.mark.parametrize("mode", ["path.repo empty", "folder not writable"])
def test_a_setup_failure_names_the_setup_script(box, monkeypatch, capsys, mode):
    monkeypatch.setattr(
        B.os, "getuid", lambda: 1000
    )  # OpenSearch's own uid: setup can fix it
    if mode == "folder not writable":
        (box.tmp / "snapshots").chmod(0o555)  # a folder the examiner can't stage in
    try:
        code, err = _backup(box, monkeypatch, capsys, mode)
    finally:
        (box.tmp / "snapshots").chmod(0o755)
    assert code == 1  # PARTIAL: the indices were asked for
    assert "WARNING: OpenSearch snapshot failed: " in err
    if mode == "path.repo empty":
        assert "repository_exception" in err and "this setting is empty" in err
    else:
        assert f"Permission denied: '{box.tmp / 'snapshots'}" in err
    assert HINT.format(script=box.repo / "scripts" / "setup-opensearch.sh") in err
    assert "cd opensearch-mcp" not in err


@pytest.mark.parametrize("mode", ["partial", "refused"])
def test_other_snapshot_failures_get_no_setup_hint(box, monkeypatch, capsys, mode):
    code, err = _backup(box, monkeypatch, capsys, mode)
    assert code == 1
    assert "WARNING: OpenSearch snapshot failed: " in err
    assert ("PARTIAL" in err) if mode == "partial" else ("Connection refused" in err)
    assert "setup-opensearch.sh" not in err


def test_without_the_repo_the_hint_names_the_folder_to_look_in(
    box, monkeypatch, capsys
):
    from vhir_cli.commands import update

    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: None)
    _, err = _backup(box, monkeypatch, capsys, "path.repo empty")
    assert (
        HINT.format(script="<your opensearch-mcp folder>/scripts/setup-opensearch.sh")
        in err
    )


def test_an_unreadable_candidate_folder_still_gives_the_hint_and_the_partial(
    box, monkeypatch, capsys
):
    import importlib.util

    from vhir_cli.commands import update

    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", REAL_RESOLVE)
    real_find = importlib.util.find_spec
    monkeypatch.setattr(  # no editable install to find: the lookup tries the folders
        importlib.util,
        "find_spec",
        lambda name, *a: None if name == "opensearch_mcp" else real_find(name, *a),
    )
    code_dir = box.tmp / "home" / "code"  # a candidate's parent the examiner can't read
    code_dir.mkdir()
    code_dir.chmod(0)
    try:
        code, err = _backup(box, monkeypatch, capsys, "path.repo empty")
    finally:
        code_dir.chmod(0o755)
    assert code == 1
    assert (
        HINT.format(script="<your opensearch-mcp folder>/scripts/setup-opensearch.sh")
        in err
    )
    assert "Error: PARTIAL backup:" in err


def test_another_uid_is_told_setup_cant_help(box, monkeypatch, capsys):
    monkeypatch.setattr(B.os, "getuid", lambda: 1001)
    (box.tmp / "snapshots").chmod(
        0o555
    )  # as OpenSearch's 1000:1000 folder is to uid 1001
    try:
        code, err = _backup(box, monkeypatch, capsys, "folder not writable")
    finally:
        (box.tmp / "snapshots").chmod(0o755)
    assert code == 1 and "Permission denied" in err
    assert "This account (uid 1001)" in err and "as uid 1000" in err
    assert "setup-opensearch.sh can't change that" in err
    assert "To set it up, run:" not in err


def test_a_snapshots_folder_set_elsewhere_is_named(box, monkeypatch, capsys):
    monkeypatch.setenv("VHIR_SNAPSHOTS_DIR", str(box.tmp / "snapshots"))
    code, err = _backup(box, monkeypatch, capsys, "elsewhere")
    assert (
        code == 1 and "didn't write the snapshot into" in err
    )  # it went to its own folder
    assert f"VHIR_SNAPSHOTS_DIR is set to {box.tmp / 'snapshots'}" in err
    assert "/var/lib/vhir/snapshots" in err and "Unset it" in err
    assert "To set it up, run:" not in err


def test_a_verification_exception_also_says_what_setup_cant_change(
    box, monkeypatch, capsys
):
    monkeypatch.setattr(B.os, "getuid", lambda: 1000)
    code, err = _backup(box, monkeypatch, capsys, "verification")
    assert code == 1 and "repository_verification_exception" in err
    assert HINT.format(script=box.repo / "scripts" / "setup-opensearch.sh") in err
    assert "the cause is the folder itself" in err


def test_the_hint_survives_a_space_in_the_path(box, monkeypatch, capsys):
    import shlex

    from vhir_cli.commands import update

    repo = box.tmp / "jo smith" / "opensearch-mcp"
    (repo / "scripts").mkdir(parents=True)
    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: repo)
    monkeypatch.setattr(B.os, "getuid", lambda: 1000)
    _, err = _backup(box, monkeypatch, capsys, "path.repo empty")
    (line,) = [ln for ln in err.splitlines() if ln.startswith("  bash ")]
    assert shlex.split(line) == ["bash", str(repo / "scripts" / "setup-opensearch.sh")]


def test_another_uid_with_another_cause_sees_that_cause(box, monkeypatch, capsys):
    monkeypatch.setattr(B.os, "getuid", lambda: 1001)
    code, err = _backup(box, monkeypatch, capsys, "no space")
    assert code == 1 and "No space left on device" in err  # the cause, shown
    assert "This account (uid 1001)" not in err  # not blamed on the uid
    assert "the cause is the folder itself" in err
