"""Backup and restore follow a case's identity.

A backup holds the case lock shared, and snapshots the case's own indices:
`case-<c12>-*` from its identity, plus its pre-0.7 `case-<case id>-*` ones.
A restore in the case's own place keeps its identity and index names. A
restore beside the case it was backed up from (another folder, or the
original's indices still there) gives the copy its own identity, renames its
indices into it (pre-0.7 ones under `v1-`) without carrying any alias, and
re-attaches each index template's own aliases. Before, a restore beside the
original was refused while its indices existed.

OpenSearch is a recording stand-in; sift-common and opensearch-mcp's case
scope are the real ones, and the rows skip without them.
"""

from __future__ import annotations

import fnmatch
import importlib
import json
import re
import subprocess
from argparse import Namespace
from types import SimpleNamespace

import pytest
import yaml

import vhir_cli.commands.backup as B


def _have(module: str, attr: str) -> bool:
    try:
        return hasattr(importlib.import_module(module), attr)
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not (
        _have("sift_common.host_identity", "update_case_meta")
        and _have("opensearch_mcp.case_scope", "legacy_expression")
    ),
    reason="needs sift-common's case identity and opensearch-mcp's case scope",
)


def _matches(name: str, expression: str) -> bool:
    parts = [p for p in expression.split(",") if p]
    keep = any(fnmatch.fnmatchcase(name, p) for p in parts if not p.startswith("-"))
    drop = any(fnmatch.fnmatchcase(name, p[1:]) for p in parts if p.startswith("-"))
    return keep and not drop


class FakeOpenSearch:
    """Indices by name; snapshots record what they hold; restores apply
    rename_pattern as OpenSearch would."""

    def __init__(self, existing=()):
        self.existing = set(existing)
        self.snapshot_holds: list[str] = []
        self.created: list[dict] = []
        self.restored: list[dict] = []
        self.alias_actions: list[dict] = []
        self.snapshot = SimpleNamespace(
            create_repository=lambda **k: None,
            delete_repository=lambda **k: None,
            create=self._create,
            status=lambda **k: {"snapshots": [{"state": "SUCCESS"}]},
            restore=self._restore,
        )
        self.cat = SimpleNamespace(indices=self._cat)
        self.indices = SimpleNamespace(
            get=lambda index, **k: {n: {} for n in self.existing if _matches(n, index)},
            simulate_index_template=self._template,
            update_aliases=lambda body: self.alias_actions.extend(body["actions"]),
        )
        self.cluster = SimpleNamespace(health=lambda: {"status": "green"})

    def info(self):
        return {"version": {"number": "2.19.1"}}

    def _cat(self, index, format="json"):
        return [
            {"index": n, "docs.count": "1"} for n in self.existing if _matches(n, index)
        ]

    def _create(self, body, **k):
        self.created.append(body)
        self.snapshot_holds = sorted(
            n for n in self.existing if _matches(n, body["indices"])
        )

    def _restore(self, body, **k):
        self.restored.append(body)
        for name in self.snapshot_holds:
            if not _matches(name, body["indices"]):
                continue
            if "rename_pattern" in body:
                java = re.sub(r"\$(\d)", r"\\\1", body["rename_replacement"])
                name = re.sub(body["rename_pattern"].replace("\\-", "-"), java, name)
            self.existing.add(name)

    def _template(self, name):
        if "-hayabusa-" in name:
            return {"template": {"aliases": {"vhir-sigma-windows": {}}}}
        return {"template": {}}


@pytest.fixture
def box(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    for name, value in (
        ("_SNAPSHOTS_DIR", tmp_path / "snapshots"),
        ("VERIFICATION_DIR", tmp_path / "verification"),
        ("_PASSWORDS_DIR", tmp_path / "passwords"),
    ):
        monkeypatch.setattr(B, name, value)
    monkeypatch.setattr(B, "_is_opensearch_available", lambda: True)
    monkeypatch.setattr(
        B.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0] if a else [], 0, "", ""),
    )
    monkeypatch.setattr(B.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    fake = FakeOpenSearch()
    import opensearch_mcp.client

    monkeypatch.setattr(opensearch_mcp.client, "get_client", lambda *a, **k: fake)
    case = tmp_path / "cases" / "C-1"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: C-1\nstatus: open\nname: n\n")
    (case / "findings.json").write_text("[]")
    return SimpleNamespace(tmp=tmp_path, case=case, os=fake)


def _identity(case, version=2) -> str:
    from sift_common.host_identity import ensure_case_uuid

    c12, _ = ensure_case_uuid(case, naming_version=version)
    return c12


def _meta(case):
    return yaml.safe_load((case / "CASE.yaml").read_text())


def _backup(box) -> str:
    result = B.create_backup_data(
        box.case, str(box.tmp / "out"), "tester", include_opensearch=True
    )
    assert "error" not in (result.get("opensearch_snapshot") or {}), result
    return result["backup_path"]


def _restore(path, target):
    B.cmd_restore(
        Namespace(
            backup_path=path,
            target=str(target),
            skip_opensearch=False,
            skip_ledger=True,
        ),
        {"examiner": "tester"},
    )


def test_a_backup_snapshots_the_case_s_own_indices(box):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0", "case-c-1-evtx-old", "case-zzz-evtx-0"}
    path = _backup(box)
    assert box.os.created[0]["indices"] == f"case-{c12}-*"
    snap = json.loads((B.Path(path) / "backup-manifest.json").read_text())[
        "opensearch_snapshot"
    ]
    assert snap["index_scope"] == f"case-{c12}-*"
    assert snap["case_uuid"].replace("-", "")[:12] == c12


def test_a_backup_waits_for_a_host_operation(box):
    from sift_common.host_identity import case_lock

    _identity(box.case)
    with case_lock(box.case, shared=False):
        with pytest.raises(OSError, match="host operation is running"):
            B.create_backup_data(box.case, str(box.tmp / "out"), "tester")


def test_a_restore_beside_the_original_gets_its_own_identity(box, capsys):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0", f"case-{c12}-hayabusa-0"}
    path = _backup(box)
    copy = box.tmp / "cases" / "C-1-copy"
    _restore(path, copy)

    meta = _meta(copy)
    new = meta["case_uuid"].replace("-", "")[:12]
    assert new != c12 and meta["legacy_alias"] == "none"
    assert _meta(box.case)["case_uuid"].replace("-", "")[:12] == c12  # untouched
    (body,) = box.os.restored
    assert body["include_aliases"] is False
    assert box.os.existing >= {f"case-{new}-evtx-0", f"case-{new}-hayabusa-0"}
    assert {f"case-{c12}-evtx-0", f"case-{c12}-hayabusa-0"} <= box.os.existing
    assert box.os.alias_actions == [
        {"add": {"index": f"case-{new}-hayabusa-0", "alias": "vhir-sigma-windows"}}
    ]
    headers = [
        json.loads(line)
        for line in (copy / "host-observations.jsonl").read_text().splitlines()
    ]
    assert headers[-1]["c12"] == new
    assert "own identity" in capsys.readouterr().out


def test_an_older_case_restored_beside_its_original_keeps_its_indices_apart(box):
    box.os.existing = {"case-c-1-evtx-wks01", "case-c-1-2-evtx-other"}
    (box.tmp / "cases" / "C-1-2").mkdir()
    (box.tmp / "cases" / "C-1-2" / "CASE.yaml").write_text("case_id: C-1-2\n")
    path = _backup(box)
    assert box.os.snapshot_holds == ["case-c-1-evtx-wks01"]  # not C-1-2's
    copy = box.tmp / "cases" / "C-1-copy"
    _restore(path, copy)
    new = _meta(copy)["case_uuid"].replace("-", "")[:12]
    assert f"case-{new}-evtx-v1-wks01" in box.os.existing
    assert "case-c-1-evtx-wks01" in box.os.existing  # the original's, untouched


def test_a_restore_in_the_case_s_own_place_keeps_its_identity(box):
    import shutil

    c12 = _identity(box.case)
    uuid = _meta(box.case)["case_uuid"]
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    shutil.rmtree(box.case)  # the case and its indices are gone
    box.os.existing = set()
    _restore(path, box.case)
    assert _meta(box.case)["case_uuid"] == uuid
    (body,) = box.os.restored
    assert body["indices"] == f"case-{c12}-*" and "rename_pattern" not in body
    assert box.os.existing == {f"case-{c12}-evtx-0"}


def test_restoring_in_place_over_surviving_indices_is_refused(box, capsys):
    import shutil

    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    shutil.rmtree(box.case)  # the folder is gone, its indices aren't
    with pytest.raises(SystemExit):
        _restore(path, box.case)
    assert "--target" in capsys.readouterr().err
    assert not box.case.exists() and box.os.restored == []


def test_a_cross_major_snapshot_is_refused_before_anything_is_written(box, capsys):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    box.os.info = lambda: {"version": {"number": "3.5.0"}}
    copy = box.tmp / "cases" / "C-1-copy"
    with pytest.raises(SystemExit):
        _restore(path, copy)
    assert "version mismatch" in capsys.readouterr().err
    assert not copy.exists() and box.os.restored == []


def test_a_manifest_naming_another_case_s_indices_is_refused(box, capsys):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0", "case-other-evtx-0"}
    path = _backup(box)
    manifest_path = B.Path(path) / "backup-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["opensearch_snapshot"]["index_scope"] = "case-other-*"
    manifest_path.write_text(json.dumps(manifest))
    copy = box.tmp / "cases" / "C-1-copy"
    with pytest.raises(SystemExit):
        _restore(path, copy)
    assert "outside case C-1" in capsys.readouterr().err
    assert not copy.exists() and box.os.restored == []


def test_a_manifest_with_another_identity_is_refused(box, capsys):
    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)
    manifest_path = B.Path(path) / "backup-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["opensearch_snapshot"]["case_uuid"] = (
        "00000000-0000-4000-8000-000000000000"
    )
    manifest["opensearch_snapshot"]["index_scope"] = "case-000000000000-*"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(SystemExit):
        _restore(path, box.tmp / "cases" / "C-1-copy")
    assert "isn't the backed-up case's" in capsys.readouterr().err


@pytest.mark.parametrize("artifact", ["hayabusa", "evtx"])
def test_restored_older_indices_are_found_by_typed_reads(box, artifact):
    from opensearch_mcp.case_scope import case_read_scope

    box.os.existing = {f"case-c-1-{artifact}-wks01"}
    path = _backup(box)
    _restore(path, box.tmp / "cases" / "C-1-copy")
    expression = case_read_scope("C-1-copy", box.os, artifact_type=artifact)
    found = [n for n in box.os.existing if _matches(n, expression)]
    new = _meta(box.tmp / "cases" / "C-1-copy")["case_uuid"].replace("-", "")[:12]
    assert found == [f"case-{new}-{artifact}-v1-wks01"], (expression, box.os.existing)


def test_a_copy_without_case_yaml_says_why_no_indices_were_restored(box, capsys):
    bare = box.tmp / "bare"
    bare.mkdir()
    assert B._new_identity_for_copy(bare, "C-1", {}) is None
    assert "No OpenSearch indices were restored" in capsys.readouterr().err


def test_a_copy_without_its_own_identity_restores_no_indices(box, monkeypatch, capsys):
    from sift_common import host_identity

    c12 = _identity(box.case)
    box.os.existing = {f"case-{c12}-evtx-0"}
    path = _backup(box)

    def fail(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(host_identity, "update_case_meta", fail)
    _restore(path, box.tmp / "cases" / "C-1-copy")
    assert box.os.restored == []  # never under the original's names
    assert "couldn't be given its own identity" in capsys.readouterr().err


def _crafted(box, older=False, **snapshot) -> str:
    """A backup whose manifest's snapshot entry is then edited."""
    own = "case-c-1-evtx-wks01" if older else f"case-{_identity(box.case)}-evtx-0"
    box.os.existing = {own, "case-other-evtx-0"}
    path = _backup(box)
    manifest_path = B.Path(path) / "backup-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["opensearch_snapshot"].update(snapshot)
    manifest_path.write_text(json.dumps(manifest))
    return path


@pytest.mark.parametrize(
    "snapshot",
    [
        {"index_scope": "*"},
        {"case_uuid": "*", "index_scope": "case-*-*"},
        {"index_scope": "case-c-1-*,case-*"},
        {"index_scope": "case-c-1-evtx-*-wks*"},
    ],
    ids=["everything", "wildcard-identity", "a-second-segment", "inner-wildcard"],
)
def test_a_manifest_reaching_past_the_case_is_refused(box, capsys, snapshot):
    path = _crafted(box, **snapshot)
    copy = box.tmp / "cases" / "C-1-copy"
    with pytest.raises(SystemExit):
        _restore(path, copy)
    assert "Error: the snapshot" in capsys.readouterr().err
    assert not copy.exists() and box.os.restored == []


def test_a_wildcard_identity_on_a_case_from_before_identities_is_refused(box, capsys):
    path = _crafted(box, older=True, case_uuid="*", index_scope="case-*-*")
    copy = box.tmp / "cases" / "C-1-copy"
    with pytest.raises(SystemExit):
        _restore(path, copy)
    assert "isn't a UUID" in capsys.readouterr().err
    assert not copy.exists() and box.os.restored == []


def test_an_upper_cased_identity_is_restored_as_the_case_s_own(box):
    path = _crafted(box)
    uuid = _meta(box.case)["case_uuid"]
    c12 = uuid.replace("-", "")[:12]
    manifest_path = B.Path(path) / "backup-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["opensearch_snapshot"]["case_uuid"] = uuid.upper()
    manifest_path.write_text(json.dumps(manifest))
    copy = box.tmp / "cases" / "C-1-copy"
    _restore(path, copy)
    new = _meta(copy)["case_uuid"].replace("-", "")[:12]
    assert f"case-{new}-evtx-0" in box.os.existing  # renamed from the case's own
    assert f"case-{c12.upper()}-evtx-0" not in box.os.existing


def test_a_refused_snapshot_leaves_an_interrupted_restore_in_place(box, monkeypatch):
    path = _crafted(box, index_scope="*")
    copy = box.tmp / "cases" / "C-1-copy"
    copy.mkdir()
    (copy / ".restore-in-progress").write_text("")
    (copy / "findings.json").write_text("[]")
    monkeypatch.setattr(B.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("builtins.input", lambda *a: "y")
    with pytest.raises(SystemExit):
        _restore(path, copy)
    assert (copy / "findings.json").is_file()  # checked before it was removed
