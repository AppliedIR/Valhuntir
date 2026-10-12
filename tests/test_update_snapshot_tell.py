"""`vhir update` says when OpenSearch isn't set up for snapshots.

With the container on the pinned image, Step 7b checks what setup checks: a
read-write bind of /var/lib/vhir/snapshots at /usr/share/opensearch/snapshots,
and a node whose path.repo holds that folder. It says what's missing and the
setup script to run, never prompting or running it; when it can't check, it
says so in one line. On the upgrade path, a setup that exits 3 is reported as
an upgrade whose snapshots aren't set up, and one that runs past its 5 minutes
is reported with the command to run again. The upgrade prompt says the
indexed data is kept, and every printed command survives a path with a space.
docker, the cluster client, input() and bash are stand-ins; values are
synthetic.
"""

from __future__ import annotations

import builtins
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

pytest.importorskip("opensearch_mcp")

from vhir_cli.commands import update  # noqa: E402

REPO = "/usr/share/opensearch/snapshots"
GOOD = "bind /var/lib/vhir/snapshots true"
MOUNT = (
    "the container has no read-write bind of /var/lib/vhir/snapshots at "
    "/usr/share/opensearch/snapshots (docker inspect: '')"
)
PATH_REPO = (
    "couldn't confirm that OpenSearch's path.repo includes /usr/share/opensearch/snapshots "
    "(_nodes/settings: '{}')"
)
RO = "bind /var/lib/vhir/snapshots false"
CANT = "  Couldn't check whether OpenSearch is set up for snapshots ("


def _nodes(repo):
    return {"nodes": {"n0": {"settings": {"path": {"repo": repo}}}}}


OTHER = _nodes(["/mnt/elsewhere"])  # path.repo set, to another folder


@pytest.fixture
def box(tmp_path, monkeypatch):
    repo = tmp_path / "opensearch-mcp"
    (repo / "docker").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "docker" / "docker-compose.yml").write_text(
        "services:\n  opensearch:\n    image: opensearchproject/opensearch:3.5.0\n"
    )
    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: repo)
    seen = SimpleNamespace(bash=[], prompts=[], image="opensearchproject/opensearch:3.5.0",
                           mount="", docker_rc=0, setup_rc=0, answer="", nodes={}, raises=None)  # fmt: skip

    def run(cmd, *a, **k):
        if cmd[0] == "bash":
            seen.bash.append(cmd)
            if seen.setup_rc == "timeout":
                raise subprocess.TimeoutExpired(cmd, k.get("timeout"))
            return subprocess.CompletedProcess(cmd, seen.setup_rc, "", "")
        assert cmd[:3] == ["docker", "inspect", "--format"], cmd
        if seen.docker_rc:
            return subprocess.CompletedProcess(
                cmd, seen.docker_rc, "", "permission denied\n"
            )
        out = seen.image if cmd[3] == "{{.Config.Image}}" else seen.mount
        return subprocess.CompletedProcess(cmd, 0, out + "\n", "")

    def info(**k):
        assert k == {"metric": "settings", "filter_path": "nodes.*.settings.path.repo"}
        if seen.raises:
            raise seen.raises
        return seen.nodes

    def ask(prompt=""):
        seen.prompts.append(prompt)
        return seen.answer

    import opensearch_mcp.client

    monkeypatch.setattr(update.subprocess, "run", run)
    monkeypatch.setattr(builtins, "input", ask)
    client = SimpleNamespace(nodes=SimpleNamespace(info=info))
    monkeypatch.setattr(opensearch_mcp.client, "get_client", lambda *a, **k: client)
    seen.script = repo / "scripts" / "setup-opensearch.sh"
    return seen


def _check(box, capsys) -> str:
    update._check_opensearch_version(box.script.parent)
    out = capsys.readouterr()
    return out.out + out.err


@pytest.mark.parametrize(
    "mount, nodes, problems",
    [
        ("", {}, [MOUNT, PATH_REPO]),  # as installed
        ("", _nodes([REPO]), [MOUNT]),  # the env without the bind
        (GOOD, {}, [PATH_REPO]),  # the bind without the env
        (RO, _nodes([REPO]), [MOUNT.replace("''", repr(RO))]),  # a read-only bind
        (
            GOOD,
            OTHER,
            [PATH_REPO.replace("{}", json.dumps(OTHER, separators=(",", ":")))],
        ),
    ],
    ids=[
        "as-installed",
        "env-without-bind",
        "bind-without-env",
        "read-only",
        "other-folder",
    ],
)
def test_a_box_not_set_up_is_told_what_is_missing_and_what_to_run(
    box, capsys, mount, nodes, problems
):
    box.mount, box.nodes = mount, nodes
    text = _check(box, capsys)
    assert [ln[6:] for ln in text.splitlines() if ln.startswith("    - ")] == problems
    assert f"    bash {box.script}" in text
    assert (box.prompts, box.bash) == ([], [])  # told, never asked or run


@pytest.mark.parametrize("repo", [[REPO], REPO], ids=["list", "string"])
def test_a_box_set_up_hears_nothing(box, capsys, repo):
    box.mount, box.nodes = GOOD, _nodes(repo)
    assert _check(box, capsys) == ""


@pytest.mark.parametrize(
    "case",
    ["docker denied", "image unknown", "client raises", "no client", "no compose file"],
)
def test_a_check_that_cant_run_says_so_once(box, capsys, monkeypatch, case):
    box.mount, box.nodes = GOOD, _nodes([REPO])
    if case == "docker denied":
        box.docker_rc = 1
    elif case == "image unknown":
        box.image = "registry.local/search:1"
    elif case == "client raises":
        box.raises = ConnectionError("refused")
    elif case == "no client":
        monkeypatch.setitem(sys.modules, "opensearch_mcp.client", None)
    else:
        (box.script.parent.parent / "docker" / "docker-compose.yml").unlink()
    lines = [ln for ln in _check(box, capsys).splitlines() if ln.strip()]
    assert len(lines) == 1 and lines[0].startswith(CANT), lines
    assert box.bash == []


@pytest.mark.parametrize(
    "rc, line",
    [
        (3, "  OpenSearch was upgraded, but its snapshots aren't set up; see above."),
        (1, "  OpenSearch upgrade failed."),
    ],
)
def test_an_upgrade_whose_setup_exits_3_says_snapshots_not_upgrade(
    box, capsys, rc, line
):
    box.image, box.answer, box.setup_rc = "opensearchproject/opensearch:3.4.0", "y", rc
    text = _check(box, capsys)
    assert line in text
    assert (rc == 3) is ("OpenSearch upgrade failed." not in text)
    assert box.bash == [["bash", str(box.script)]]


def test_the_upgrade_prompt_says_the_indexed_data_is_kept(box, capsys):
    box.image, box.answer = "opensearchproject/opensearch:3.4.0", "n"
    text = _check(box, capsys)
    assert "Its indexed data is kept" in text
    assert "cleared" not in text and "reingest" not in text


def test_an_upgrade_that_runs_past_its_time_is_told_and_update_goes_on(box, capsys):
    box.image, box.answer, box.setup_rc = (
        "opensearchproject/opensearch:3.4.0",
        "y",
        "timeout",
    )
    text = _check(box, capsys)  # returns: update's later steps still run
    assert "didn't finish in 5 minutes" in text and "docker ps" in text
    assert f"    bash {box.script}" in text


def _spaced(box, monkeypatch, tmp_path):
    repo = tmp_path / "jo smith" / "opensearch-mcp"
    (repo / "docker").mkdir(parents=True)
    (repo / "scripts").mkdir()
    (repo / "docker" / "docker-compose.yml").write_text(
        "services:\n  opensearch:\n    image: opensearchproject/opensearch:3.5.0\n"
    )
    monkeypatch.setattr(update, "_resolve_opensearch_mcp_repo", lambda source: repo)
    return repo / "scripts" / "setup-opensearch.sh"


@pytest.mark.parametrize("path", ["not set up", "upgrade skipped", "upgrade timed out"])
def test_every_printed_command_survives_a_space_in_its_path(
    box, capsys, monkeypatch, tmp_path, path
):
    import shlex

    script = _spaced(box, monkeypatch, tmp_path)
    if path != "not set up":
        box.image = "opensearchproject/opensearch:3.4.0"
        box.answer = "y" if path == "upgrade timed out" else "n"
        box.setup_rc = "timeout" if path == "upgrade timed out" else 0
    update._check_opensearch_version(script.parent)
    out = capsys.readouterr()
    lines = [ln for ln in (out.out + out.err).splitlines() if "bash " in ln]
    assert lines, out
    for line in lines:
        words = shlex.split(line[line.index("bash ") :])
        assert words == ["bash", str(script)], line
