"""A backup treats a registered folder (a KAPE collection) as evidence.

A folder registered as one root has its own path in the registry, not its
files'. The backup counted registered evidence as reached only when a file
at that exact path was scanned, so --include-evidence refused a registered
folder as "can't find", and a folder registered outside evidence/ had its
files backed up as case data. Its files are evidence now, and the folder is
reached when they are.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vhir_cli.commands.backup import create_backup_data, scan_case_dir
from vhir_cli.commands.evidence import register_evidence_data


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "BKUP-CASE"
    (d / "evidence").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: BKUP-CASE\nstatus: open\nname: b\n")
    (d / "findings.json").write_text("[]")
    (d / "evidence.json").write_text('{"files": []}')
    return d


def _kape(case, where):
    k = case / where / "kape"
    (k / "C" / "Windows").mkdir(parents=True)
    (k / "C" / "Windows" / "a.evtx").write_bytes(b"A" * 64)
    (k / "C" / "b.evtx").write_bytes(b"B" * 64)
    register_evidence_data(case, str(k), "tester")
    return k


def _copied(case, dest, **kw):
    backup = Path(create_backup_data(case, str(dest), "tester", **kw)["backup_path"])
    return {str(p.relative_to(backup)) for p in backup.rglob("*") if p.is_file()}


@pytest.mark.parametrize("where", ["evidence", "work"])
def test_include_evidence_backs_up_a_registered_folders_files(case, tmp_path, where):
    _kape(case, where)
    copied = _copied(case, tmp_path / "out", include_evidence=True)
    assert {f"{where}/kape/C/Windows/a.evtx", f"{where}/kape/C/b.evtx"} <= copied
    assert "evidence-manifests/1.json" in copied


def test_a_folder_registered_outside_evidence_is_evidence_not_case_data(case, tmp_path):
    _kape(case, "work")
    (case / "work" / "notes.txt").write_text("unregistered\n")
    scan = scan_case_dir(case)
    rels = {rel for rel, _a, _s in scan["evidence"]}
    assert {"work/kape/C/Windows/a.evtx", "work/kape/C/b.evtx"} <= rels
    copied = _copied(case, tmp_path / "out")  # evidence left out by default
    assert not any(c.startswith("work/kape/") for c in copied)
    assert "work/notes.txt" in copied


def test_a_deleted_member_of_a_registered_folder_is_reported_by_name(case, tmp_path):
    """The folder isn't complete because another of its files was reached."""
    k = _kape(case, "evidence")
    (k / "C" / "b.evtx").unlink()
    with pytest.raises(OSError) as e:
        _copied(case, tmp_path / "out", include_evidence=True)
    assert f"{k / 'C' / 'b.evtx'}: " in str(e.value) and "a.evtx" not in str(e.value)


def test_a_member_the_backup_skips_by_name_is_reported_by_name(case, tmp_path):
    """.DS_Store is left out of every backup, but in a macOS collection it is
    registered evidence."""
    k = case / "evidence" / "kape"
    k.mkdir()
    (k / "a.evtx").write_bytes(b"A" * 64)
    (k / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1")
    register_evidence_data(case, str(k), "tester")
    with pytest.raises(OSError, match=r"\.DS_Store: .*leaves out by name"):
        _copied(case, tmp_path / "out", include_evidence=True)
    backup = Path(
        create_backup_data(
            case, str(tmp_path / "out2"), "tester", include_evidence=True,
            skip_unreadable=True,
        )["backup_path"]
    )  # fmt: skip
    manifest = json.loads((backup / "backup-manifest.json").read_text())
    assert [s["path"] for s in manifest["skipped"]] == ["evidence/kape/.DS_Store"]


def test_a_folder_whose_manifest_was_changed_is_not_counted_as_backed_up(
    case, tmp_path
):
    _kape(case, "evidence")
    m = case / "evidence-manifests" / "1.json"
    m.write_text(m.read_text().replace("b.evtx", "c.evtx"))
    with pytest.raises(OSError, match="kape"):
        _copied(case, tmp_path / "out", include_evidence=True)


def test_a_registered_file_at_a_credential_path_is_reported_not_counted(case, tmp_path):
    """passwords/<name>.json is never copied: registered there, it's named."""
    k = case / "passwords"
    k.mkdir()
    (k / "alice.json").write_text('{"note": "evidence, as it happens"}')
    (k / "notes.txt").write_text("copied as usual")
    register_evidence_data(case, str(k), "tester")
    with pytest.raises(OSError, match=r"passwords/alice\.json: .*never copies"):
        _copied(case, tmp_path / "out", include_evidence=True)


def test_a_registered_file_itself_at_a_credential_path_says_why(case, tmp_path):
    k = case / "passwords"
    k.mkdir()
    (k / "bob.json").write_text("{}")
    register_evidence_data(case, str(k / "bob.json"), "tester")
    with pytest.raises(OSError, match=r"passwords/bob\.json: .*never copies"):
        _copied(case, tmp_path / "out", include_evidence=True)
