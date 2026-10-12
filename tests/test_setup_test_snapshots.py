"""`vhir setup test` says whether OpenSearch is set up for vhir backup's snapshots.

It runs the check `vhir update` runs (the container's read-write bind of
/var/lib/vhir/snapshots, and a node whose path.repo holds it), then what
backup itself needs on this box: VHIR_SNAPSHOTS_DIR, if set, is setup's
folder, and this account can create files in the staging folder. It says
what's missing, OK only when nothing is, and one line when it can't check.
A box without opensearch-mcp hears nothing about snapshots. docker, the
cluster client and the gateway are stand-ins; values are synthetic.
"""

from __future__ import annotations

import subprocess
import urllib.request
from types import SimpleNamespace

import pytest

pytest.importorskip("opensearch_mcp")

import vhir_cli.gateway as gateway  # noqa: E402
from vhir_cli.commands import backup, update  # noqa: E402
from vhir_cli.commands.setup import _run_connectivity_test  # noqa: E402

GOOD = "bind /var/lib/vhir/snapshots true"
REPO = "/usr/share/opensearch/snapshots"


@pytest.fixture
def box(tmp_path, monkeypatch):
    import opensearch_mcp.client

    repo = tmp_path / "opensearch-mcp"
    (repo / "scripts").mkdir(parents=True)
    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: repo)
    staging = tmp_path / "snapshots"  # the box's folder, writable to this account
    staging.mkdir()
    monkeypatch.setattr(backup, "_SNAPSHOTS_DIR", staging)
    monkeypatch.delenv("VHIR_SNAPSHOTS_DIR", raising=False)
    seen = SimpleNamespace(mount=GOOD, repo=[REPO], docker_rc=0, staging=staging)

    def run(cmd, *a, **k):
        assert cmd[:3] == ["docker", "inspect", "--format"], cmd
        if seen.docker_rc:
            return subprocess.CompletedProcess(cmd, 1, "", "permission denied\n")
        return subprocess.CompletedProcess(cmd, 0, seen.mount + "\n", "")

    nodes = {"nodes": {"n0": {"settings": {"path": {"repo": None}}}}}

    def info(**k):
        nodes["nodes"]["n0"]["settings"]["path"]["repo"] = seen.repo
        return nodes

    monkeypatch.setattr(update.subprocess, "run", run)
    client = SimpleNamespace(nodes=SimpleNamespace(info=info))
    monkeypatch.setattr(opensearch_mcp.client, "get_client", lambda *a, **k: client)
    monkeypatch.setattr("shutil.which", lambda name: None)  # no sandbox tools: skipped
    monkeypatch.setattr(gateway, "get_local_gateway_url", lambda: "http://gw:4508")
    monkeypatch.setattr(gateway, "get_local_ssl_context", lambda: None)

    def offline(*a, **k):
        raise RuntimeError("no gateway here")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    seen.script = repo / "scripts" / "setup-opensearch.sh"
    return seen


def _test(capsys) -> str:
    _run_connectivity_test()
    out = capsys.readouterr()
    return out.out + out.err


def test_a_box_not_set_up_for_snapshots_is_told(box, capsys):
    box.mount = ""
    text = _test(capsys)
    assert "OpenSearch isn't set up for snapshots" in text
    assert "the container has no read-write bind of /var/lib/vhir/snapshots" in text
    assert f"    bash {box.script}" in text
    assert "OpenSearch snapshots: OK" not in text
    assert "Gateway: ERROR" in text  # the rest of the test still runs


def test_a_box_set_up_for_snapshots_says_ok(box, capsys):
    text = _test(capsys)
    assert "OpenSearch snapshots: OK (vhir backup can save the indices)" in text
    assert "isn't set up" not in text


def test_a_check_that_cant_run_says_so(box, capsys):
    box.docker_rc = 1
    text = _test(capsys)
    assert "Couldn't check whether OpenSearch is set up for snapshots" in text
    assert "OpenSearch snapshots: OK" not in text


def test_a_box_without_opensearch_hears_nothing_of_snapshots(box, capsys, monkeypatch):
    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: None)
    assert "snapshots" not in _test(capsys)


def test_a_snapshots_folder_set_elsewhere_isnt_ok(box, capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("VHIR_SNAPSHOTS_DIR", str(tmp_path / "elsewhere"))
    text = _test(capsys)
    assert (
        "OpenSearch is set up for snapshots, but vhir backup can't stage them:" in text
    )
    assert f"VHIR_SNAPSHOTS_DIR is set to {tmp_path / 'elsewhere'}" in text
    assert "OpenSearch snapshots: OK" not in text


def test_a_folder_this_account_cant_write_isnt_ok(box, capsys):
    box.staging.chmod(0o555)  # as OpenSearch's 1000-owned 0755 folder is to another uid
    try:
        text = _test(capsys)
    finally:
        box.staging.chmod(0o755)
    assert "can't create files in" in text and "Permission denied" in text
    assert "OpenSearch snapshots: OK" not in text
    assert [p.name for p in box.staging.iterdir()] == []  # the probe file is gone
