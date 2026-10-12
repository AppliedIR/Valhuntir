"""A backup whose snapshot fails for want of setup says how to set it up.

`vhir backup --include-opensearch` runs through the real command line with a
stand-in cluster. When the cluster can't write snapshots to this box's
folder (path.repo empty, the folder not writable), the warning is followed
by the setup script's absolute path; other failures (a PARTIAL snapshot, a
refused connection) get the warning only. The 500's text is the one a
3.5.0 cluster gives with an empty path.repo; other values are synthetic.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("opensearch_mcp")

from vhir_cli.commands import backup as B  # noqa: E402

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
            get=lambda **k: {"snapshots": [{"state": "PARTIAL", "indices": []}]},
        )
        self.cat = SimpleNamespace(
            indices=lambda **k: [{"index": "case-x-evtx-0", "docs.count": "3"}]
        )

    def info(self):
        return {"version": {"number": "3.5.0"}}

    def _register(self, repository, body, **k):
        from opensearchpy.exceptions import ConnectionError as Refused
        from opensearchpy.exceptions import TransportError

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
