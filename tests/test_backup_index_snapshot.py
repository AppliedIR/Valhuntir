# ruff: noqa: F401, F811 - `box` is the fixture imported below
"""A backup holds the indices it says it holds, and an index restore says
what came back.

The backup waits on the repository's own listing (its status says SUCCESS
before the repository's root index-N is written), then requires that index-N
in its staging folder: a cluster whose snapshot folder isn't staging wrote
the snapshot elsewhere, and the backup is PARTIAL without its indices.
`--verify` fails a backup that says it holds indices but has no index-N.
An index restore whose result doesn't report every shard restored is a
PARTIAL restore, in place and in a renamed copy, and each restore call waits
as long as the backup's snapshot does.
"""

from __future__ import annotations

import json
import shutil
import time

import pytest

import vhir_cli.commands.backup as B

from .test_backup_case_identity import (
    FakeOpenSearch,
    _backup,
    _identity,
    _restore,
    box,
    pytestmark,  # the same packages are needed
)


@pytest.fixture
def no_wait(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda s: None)


def _manifest(path) -> dict:
    return json.loads((B.Path(path) / "backup-manifest.json").read_text())


def test_a_snapshot_written_elsewhere_makes_a_partial_backup(box):
    """The cluster's snapshot folder isn't staging: nothing lands there."""
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    box.os.snapshot.create = lambda body, **k: box.os.created.append(body)
    box.os.snapshot.status = lambda **k: {"snapshots": [{"state": "SUCCESS"}]}
    result = B.create_backup_data(
        box.case, str(box.tmp / "out"), "tester", include_opensearch=True
    )
    error = result["opensearch_snapshot"]["error"]
    assert "didn't write the snapshot into" in error
    assert str(box.tmp / "snapshots" / "vhir-backup-c-1") in error
    manifest = _manifest(result["backup_path"])
    assert manifest["includes_opensearch"] is False
    assert not (B.Path(result["backup_path"]) / "opensearch-snapshot").exists()


def test_the_backup_waits_for_the_repository_s_root_index(box, no_wait):
    """_status says SUCCESS first; the repository lists the snapshot only
    once its root index-N is written."""
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    asked = []

    def create(body, repository, **k):
        box.os.created.append(body)
        box.os.snapshot_holds = sorted(box.os.existing)

    def get(repository, **k):
        asked.append(repository)
        if len(asked) < 2:
            return {"snapshots": [{"state": "IN_PROGRESS"}]}
        (B._SNAPSHOTS_DIR / repository / "index-0").write_bytes(b"")
        return {"snapshots": [{"state": "SUCCESS", "indices": box.os.snapshot_holds}]}

    box.os.snapshot.create = create
    box.os.snapshot.get = get
    box.os.snapshot.status = lambda **k: {"snapshots": [{"state": "SUCCESS"}]}
    path = _backup(box)
    assert (B.Path(path) / "opensearch-snapshot" / "index-0").exists()
    assert _manifest(path)["includes_opensearch"] is True


@pytest.mark.parametrize(
    "drop",
    ["opensearch-snapshot/index-0", None],
    ids=["no-root-index", "whole"],
)
def test_verify_fails_a_backup_whose_indices_have_no_root_index(box, capsys, drop):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    if drop:  # as a backup made before the check: the snapshot went elsewhere
        (B.Path(path) / drop).unlink()
        manifest = _manifest(path)
        manifest["files"] = [e for e in manifest["files"] if e["path"] != drop]
        (B.Path(path) / "backup-manifest.json").write_text(json.dumps(manifest))
    assert B._verify_backup(B.Path(path)) is (drop is None)
    out = capsys.readouterr().out
    assert ("has no index-N file" in out) is bool(drop)


def test_an_index_n_below_the_snapshot_s_top_doesn_t_count(box, capsys):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    top, below = B.Path(path) / "opensearch-snapshot", "indices/x/index-0"
    (top / "indices" / "x").mkdir(parents=True)
    (top / "index-0").rename(top / below)
    manifest = _manifest(path)
    for e in manifest["files"]:
        if e["path"] == "opensearch-snapshot/index-0":
            e["path"] = f"opensearch-snapshot/{below}"
    (B.Path(path) / "backup-manifest.json").write_text(json.dumps(manifest))
    assert B._verify_backup(B.Path(path)) is False
    assert "has no index-N file" in capsys.readouterr().out


@pytest.mark.parametrize(
    "result",
    [
        {"snapshot": {"shards": {"total": 1, "failed": 1, "successful": 0}}},
        {"snapshot": {"shards": {"total": 2, "failed": 0, "successful": 1}}},
        {"snapshot": {"shards": {"total": 2, "failed": 1, "successful": 2}}},
        {"snapshot": {"shards": {"total": 0, "failed": 0, "successful": 0}}},
        {"accepted": True},
        None,
    ],
    ids=[
        "failed",
        "short",
        "a-failure-counted",
        "none-restored",
        "no-shard-count",
        "no-result",
    ],
)
@pytest.mark.parametrize("in_place", [True, False], ids=["in-place", "copy"])
def test_an_index_restore_short_of_shards_is_partial(box, capsys, result, in_place):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    if in_place:  # the case and its indices are gone
        shutil.rmtree(box.case)
        box.os.existing = set()
    real = box.os.snapshot.restore
    box.os.snapshot.restore = lambda **k: (real(**k), result)[1]
    target = box.case if in_place else box.tmp / "cases" / "C-1-copy"
    with pytest.raises(SystemExit) as exit_:
        _restore(path, target)
    assert exit_.value.code == 1
    err = capsys.readouterr().err
    assert "not every shard was restored" in err and "PARTIAL restore" in err
    assert (target / ".restore-in-progress").exists()


@pytest.mark.parametrize("in_place", [True, False], ids=["in-place", "copy"])
def test_each_index_restore_waits_as_long_as_the_backup(box, in_place):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    if in_place:
        shutil.rmtree(box.case)
        box.os.existing = set()
    waits = []
    real = box.os.snapshot.restore
    box.os.snapshot.restore = lambda **k: (waits.append(k.get("request_timeout")),
                                           real(**k))[1]  # fmt: skip
    _restore(path, box.case if in_place else box.tmp / "cases" / "C-1-copy")
    assert waits == [1800]


def test_a_backup_records_the_case_s_real_path(box, tmp_path):
    """Reached through a link: evidence is registered by real path."""
    _identity(box.case)
    real = tmp_path / "data" / "C-1"
    real.parent.mkdir()
    shutil.move(box.case, real)
    box.case.symlink_to(real)
    result = B.create_backup_data(box.case, str(tmp_path / "out"), "tester")
    manifest = _manifest(result["backup_path"])
    assert manifest["source"] == str(box.case)
    assert manifest["source_realpath"] == str(real)
