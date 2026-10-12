"""`vhir setup test` says whether OpenSearch is set up for vhir backup's snapshots.

It runs the check `vhir update` runs (the container's read-write bind of
/var/lib/vhir/snapshots, and a node whose path.repo holds it), then backup's
own path: its staging (the lock, a folder this account makes, the repository
registered), OpenSearch's verification of the repository, and a snapshot of
no indices that must land in this host's staging folder; everything it made
is removed. It says OK only when all of that works, and otherwise the cause
and backup's own advice. A box without opensearch-mcp hears nothing about
snapshots. docker, the gateway and the cluster are stand-ins: the cluster
writes snapshots into its bind as its own uid, and can't write a folder that
uid can't. Values are synthetic.
"""

from __future__ import annotations

import os
import subprocess
import sys
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
    bind = tmp_path / "snapshots"  # the folder the container binds, as setup leaves it
    bind.mkdir()
    monkeypatch.setattr(backup, "_SNAPSHOTS_DIR", bind)  # backup stages there
    monkeypatch.delenv("VHIR_SNAPSHOTS_DIR", raising=False)
    seen = SimpleNamespace(mount=GOOD, repo=[REPO], docker_rc=0, bind=bind,
                           os_uid=os.getuid(), verify_error="")  # fmt: skip

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
    client = SimpleNamespace(nodes=SimpleNamespace(info=info), snapshot=Cluster(seen))
    monkeypatch.setattr(opensearch_mcp.client, "get_client", lambda *a, **k: client)
    monkeypatch.setattr("shutil.which", lambda name: None)  # no sandbox tools: skipped
    monkeypatch.setattr(gateway, "get_local_gateway_url", lambda: "http://gw:4508")
    monkeypatch.setattr(gateway, "get_local_ssl_context", lambda: None)

    def offline(*a, **k):
        raise RuntimeError("no gateway here")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    seen.script = repo / "scripts" / "setup-opensearch.sh"
    return seen


class Cluster:
    """OpenSearch's side of a snapshot: the repository's location inside the
    container is its bind on this host, and it writes there as its own uid."""

    def __init__(self, seen):
        self.seen = seen
        self.repos: dict[str, str] = {}

    def _host(self, repository):
        return self.seen.bind / self.repos[repository].rsplit("/", 1)[1]

    def _writable(self, folder):
        st = folder.stat()
        return bool(
            (st.st_uid == self.seen.os_uid and st.st_mode & 0o200) or st.st_mode & 0o002
        )

    def _check(self, repository):
        folder = self._host(repository)
        if not folder.exists():
            if not self._writable(folder.parent):
                raise PermissionError(
                    f"[{repository}] {folder.parent}: Permission denied"
                )
            folder.mkdir()
        if not self._writable(folder):
            raise RuntimeError(
                f"TransportError(500, 'repository_verification_exception', '[{repository}] "
                f"store location [{folder}] is not accessible on the node: "
                "java.nio.file.AccessDeniedException: Permission denied')"
            )
        if self.seen.verify_error:
            raise RuntimeError(self.seen.verify_error)

    def create_repository(self, repository, body):
        self.repos[repository] = body["settings"]["location"]
        self._check(repository)  # a PUT verifies by default

    def verify_repository(self, repository):
        self._check(repository)
        return {"nodes": {}}

    def create(self, repository, snapshot, body, wait_for_completion):
        (self._host(repository) / "index-0").write_text("{}")

    def get(self, repository, snapshot):
        return {"snapshots": [{"state": "SUCCESS"}]}

    def delete(self, repository, snapshot):
        (self._host(repository) / "index-0").unlink(missing_ok=True)

    def delete_repository(self, repository):
        self.repos.pop(repository, None)


def _left(box):
    """What the check left: nothing but the lock's guard file."""
    return sorted(p.name for p in box.bind.iterdir() if p.name != ".backup.lock.guard")


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


def test_backups_own_run_makes_the_ok(box, capsys):
    text = _test(capsys)
    assert "OpenSearch snapshots: OK (vhir backup can save the indices)" in text
    assert _left(box) == []


def test_a_staging_folder_opensearch_cant_write_isnt_ok(box, capsys, monkeypatch):
    """This account (uid 1001) can make the folder; OpenSearch (uid 1000) can't
    write into it: the shape a temp file in the parent never sees."""
    monkeypatch.setattr(backup.os, "getuid", lambda: 1001)
    box.os_uid = os.getuid() + 4242  # OpenSearch isn't the folder's owner
    box.bind.chmod(
        0o777
    )  # the parent is writable to all, as a group or ACL would make it
    try:
        text = _test(capsys)
    finally:
        box.bind.chmod(0o755)
    assert "vhir backup's own run fails:" in text and "Permission denied" in text
    assert "This account (uid 1001)" in text and "OpenSearch snapshots: OK" not in text
    assert _left(box) == []


def test_a_snapshots_folder_set_elsewhere_isnt_ok(box, capsys, monkeypatch, tmp_path):
    other = tmp_path / "elsewhere"
    monkeypatch.setenv("VHIR_SNAPSHOTS_DIR", str(other))
    monkeypatch.setattr(backup, "_SNAPSHOTS_DIR", other)  # as backup reads the env
    text = _test(capsys)
    assert "didn't write the snapshot into" in text and str(other) in text
    assert f"VHIR_SNAPSHOTS_DIR is set to {other}" in text
    assert "OpenSearch snapshots: OK" not in text
    assert (
        sorted(p.name for p in other.iterdir() if p.name != ".backup.lock.guard") == []
    )


def test_a_verification_failure_shows_its_cause(box, capsys):
    box.verify_error = (
        "[vhir-backup-vhir-setup-test] java.io.IOException: No space left on device"
    )
    text = _test(capsys)
    assert "No space left on device" in text and "OpenSearch snapshots: OK" not in text
    assert _left(box) == []


def test_an_empty_snapshots_dir_is_unset_not_the_current_folder(tmp_path):
    code = "from vhir_cli.commands import backup; print(backup._SNAPSHOTS_DIR)"
    env = {**os.environ, "VHIR_SNAPSHOTS_DIR": ""}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       env=env, cwd=tmp_path, timeout=60)  # fmt: skip
    assert r.stdout.strip() == "/var/lib/vhir/snapshots", r.stdout + r.stderr
