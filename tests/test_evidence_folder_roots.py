"""A folder registers as one root, with a manifest of its files.

A folder (a KAPE collection) couldn't be registered at all: only single
files could. It now registers as one entry of kind "folder" whose manifest
lists each regular file (case-relative path, SHA-256, stat fields) and what
was skipped (links, FIFOs: never followed or read). An entry written before
this release is left as it was.
"""

from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vhir_cli.commands.evidence import cmd_register_evidence, register_evidence_data


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "case"
    (d / "evidence").mkdir(parents=True)
    old = d / "evidence" / "old.bin"
    old.write_bytes(b"OLD")
    entry = {"path": str(old.resolve()), "sha256": _sha(b"OLD"), "description": "",
             "registered_at": "2026-09-01T00:00:00+00:00", "registered_by": "tester"}  # fmt: skip
    (d / "evidence.json").write_text(json.dumps({"files": [entry]}))
    kape = d / "evidence" / "kape"
    (kape / "C" / "Windows").mkdir(parents=True)
    (kape / "C" / "Windows" / "a.evtx").write_bytes(b"ElfFile\x00a")
    (kape / "C" / "b.evtx").write_bytes(b"ElfFile\x00b")
    os.mkfifo(kape / "C" / "pipe")
    (kape / "C" / "link.evtx").symlink_to(old)
    return d


def _registry(case):
    return json.loads((case / "evidence.json").read_text())["files"]


def test_a_folder_registers_as_one_root_with_its_manifest(case):
    before = _registry(case)[0]
    kape = case / "evidence" / "kape"
    r = register_evidence_data(case, str(kape), "tester")
    old, entry = _registry(case)
    assert old == before  # the earlier entry, byte for byte
    assert entry == r and r["kind"] == "folder" and r["path"] == str(kape.resolve())
    assert r["file_count"] == 2 and "sha256" not in r
    manifest = case / r["manifest_path"]
    assert r["manifest_path"] == "evidence-manifests/1.json"
    assert _sha(manifest.read_bytes()) == r["manifest_sha256"]
    m = json.loads(manifest.read_text())
    rows = {row["path"]: row for row in m["files"]}
    a = kape / "C" / "Windows" / "a.evtx"
    assert set(rows) == {"evidence/kape/C/Windows/a.evtx", "evidence/kape/C/b.evtx"}
    row, st = rows["evidence/kape/C/Windows/a.evtx"], os.stat(a)
    assert row["sha256"] == _sha(b"ElfFile\x00a")
    assert (row["size"], row["mtime_ns"], row["ctime_ns"], row["st_dev"], row["st_ino"]) == (
        st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_dev, st.st_ino,
    )  # fmt: skip
    assert m["skipped"] == ["evidence/kape/C/link.evtx", "evidence/kape/C/pipe"]


def test_the_same_folder_again_is_already_registered_and_a_changed_one_is_refused(case):
    kape = case / "evidence" / "kape"
    first = register_evidence_data(case, str(kape), "tester")
    again = register_evidence_data(case, str(kape), "tester")
    assert again["note"].startswith("already registered") and len(_registry(case)) == 2
    (kape / "C" / "b.evtx").write_bytes(b"edited")
    with pytest.raises(ValueError, match="different manifest"):
        register_evidence_data(case, str(kape), "tester")
    assert _registry(case)[1] == first
    r = register_evidence_data(case, str(kape), "tester", force_reregister=True)
    assert (
        r["manifest_path"] == "evidence-manifests/2.json" and len(_registry(case)) == 2
    )
    assert r["previous_manifests"][0]["manifest_sha256"] == first["manifest_sha256"]


def test_nothing_is_registered_while_a_file_is_still_hashing(case):
    kape = case / "evidence" / "kape"
    before = (case / "evidence.json").read_text()

    def later(case_dir, paths):
        return {paths[0]: "ab" * 32}, "hash-0123456789abcdef"

    r = register_evidence_data(case, str(kape), "tester", folder_hasher=later)
    assert r == {"status": "hashing", "job_id": "hash-0123456789abcdef",
                 "path": str(kape.resolve()), "files_hashing": 1}  # fmt: skip
    assert (case / "evidence.json").read_text() == before
    assert not (case / "evidence-manifests").exists()


def test_a_folder_outside_the_case_is_refused(case, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    with pytest.raises(ValueError, match="within the case directory"):
        register_evidence_data(case, str(outside), "tester")


def test_the_cli_registers_a_folder_and_says_so(case, capsys):
    args = SimpleNamespace(path=str(case / "evidence" / "kape"), description="",
                           force_reregister=False, case=None)  # fmt: skip
    with patch("vhir_cli.commands.evidence.get_case_dir", return_value=case):
        cmd_register_evidence(args, {"os_user": "tester", "examiner": "tester"})
    out = capsys.readouterr().out
    assert "Folder: 2 file(s), manifest evidence-manifests/1.json" in out
    assert f"Manifest SHA256: {_registry(case)[1]['manifest_sha256']}" in out


def _verify(case, **kw):
    from vhir_cli.commands.evidence import verify_evidence_data

    v = verify_evidence_data(case, **kw)
    return v, {x["path"].rsplit("/", 1)[1]: x for x in v["results"]}


def test_a_folder_root_verifies_file_by_file(case):
    kape = case / "evidence" / "kape"
    register_evidence_data(case, str(kape), "tester")
    (kape / "C" / "b.evtx").write_bytes(b"edited")
    v, by = _verify(case)
    assert by["old.bin"]["status"] == "OK"
    assert by["a.evtx"]["status"] == "OK" and by["b.evtx"]["status"] == "MODIFIED"
    assert by["b.evtx"]["actual_hash"] == _sha(b"edited")
    (kape / "C" / "Windows" / "a.evtx").unlink()
    v, by = _verify(case)
    assert by["a.evtx"]["status"] == "MISSING"
    assert (v["verified"], v["modified"], v["missing"], v["errors"]) == (1, 1, 1, 0)


def test_a_folder_whose_manifest_changed_is_an_error(case):
    r = register_evidence_data(case, str(case / "evidence" / "kape"), "tester")
    manifest = case / r["manifest_path"]
    manifest.write_text(manifest.read_text() + "\n")  # any change to its bytes
    v, by = _verify(case)
    assert by["kape"]["status"] == "ERROR"
    assert (
        by["kape"]["error"] == "its manifest is missing or changed since registration"
    )
    assert v["errors"] == 1


def test_a_folder_file_still_hashing_is_pending_with_its_job(case):
    register_evidence_data(case, str(case / "evidence" / "kape"), "tester")

    def later(case_dir, paths):
        return {
            p: _sha(open(p, "rb").read()) for p in paths[:1]
        }, "hash-0123456789abcdef"

    v, by = _verify(case, folder_hasher=later)
    pending = [x for x in v["results"] if x["status"] == "PENDING"]
    assert len(pending) == 1 and pending[0]["job_id"] == "hash-0123456789abcdef"
    assert v["pending"] == 1
