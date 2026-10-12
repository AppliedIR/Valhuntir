"""An item imported from another case says so: it's graded IMPORTED, because
its chain lives in the case it came from, and keeps where it came from and
its original who, when and grades under `imported_from`. The other examiner's
notes and edits never read as this case's, and the stored hash matches the
item as stored.

Case A's finding (vol3 on a memory sample extracted from a 7z, FULL in A) is
exported with `vhir export` and merged into case B with `vhir merge`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from vhir_cli.case_io import compute_content_hash, import_bundle
from vhir_cli.commands.sync import cmd_export, cmd_merge

STAGED = "2026-10-01T00:00:00+00:00"


def _case(path: Path, case_id: str) -> Path:
    path.mkdir(parents=True)
    (path / "CASE.yaml").write_text(json.dumps({"case_id": case_id, "name": "n"}))
    (path / "audit").mkdir()
    for name in ("findings.json", "timeline.json", "todos.json"):
        (path / name).write_text("[]")
    return path


def _finding() -> dict:
    f = {
        "id": "F-alice-001",
        "status": "DRAFT",
        "type": "finding",
        "title": "Suspicious process in memory sample 2",
        "observation": "vol3 windows.pslist on samples/mem2.raw from evidence/samples.7z",
        "staged": STAGED,
        "modified_at": STAGED,
        "examiner": "alice",
        "created_by": "alice",
        "provenance": "MCP",
        "provenance_schema": 2,
        "provenance_grade": "FULL",
        "provenance_detail": {"summary": "MCP", "mcp": ["sift-alice-20261001-002"]},
        "artifacts": [
            {
                "source": "extractions/sift-alice-20261001-002/pslist.txt",
                "content": "4242 evil.exe",
                "audit_id": "sift-alice-20261001-002",
                "provenance_grade": "FULL",
                "provenance_reason": "",
            },
            {
                "source": "OpenCTI",
                "content": "evil.example.com",
                "audit_id": "opencti-alice-20261001-003",
                "provenance_grade": "BROKEN",
                "provenance_reason": "reference data from opencti, not evidence",
            },
        ],
        "examiner_notes": "checked on alice's box",
        "examiner_modifications": {"title": "Process in sample 2"},
    }
    f["content_hash"] = compute_content_hash(f)
    return f


def _event() -> dict:
    return {
        "id": "T-alice-001",
        "status": "DRAFT",
        "timestamp": "2026-09-30T12:00:00Z",
        "description": "evil.exe started",
        "staged": STAGED,
        "modified_at": STAGED,
        "examiner": "alice",
        "examiner_notes": "from the pslist",
    }


@pytest.fixture
def imported(tmp_path, monkeypatch):
    """The finding and the event as stored in case B, and the bundle."""
    a = _case(tmp_path / "INC-A", "INC-A")
    (a / "findings.json").write_text(json.dumps([_finding()]))
    (a / "timeline.json").write_text(json.dumps([_event()]))
    bundle_file = tmp_path / "bundle.json"
    monkeypatch.setenv("VHIR_CASE_DIR", str(a))
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    cmd_export(
        argparse.Namespace(case=None, file=str(bundle_file), since=""),
        {"examiner": "alice"},
    )
    b = _case(tmp_path / "INC-B", "INC-B")
    monkeypatch.setenv("VHIR_CASE_DIR", str(b))
    monkeypatch.setenv("VHIR_EXAMINER", "bob")
    cmd_merge(argparse.Namespace(case=None, file=str(bundle_file)), {"examiner": "bob"})
    finding = json.loads((b / "findings.json").read_text())[0]
    event = json.loads((b / "timeline.json").read_text())[0]
    return finding, event, json.loads(bundle_file.read_text())


def _reason(bundle) -> str:
    return (
        f"chain lives in case INC-A (imported from {bundle['examiner']}, "
        f"exported {bundle['exported_at']})"
    )


def test_an_imported_finding_and_its_artifacts_are_graded_imported(imported):
    f, _e, bundle = imported
    grades = [f["provenance_grade"]] + [a["provenance_grade"] for a in f["artifacts"]]
    assert grades == ["IMPORTED", "IMPORTED", "IMPORTED"], grades
    reasons = [f["provenance_reason"]] + [
        a["provenance_reason"] for a in f["artifacts"]
    ]
    assert reasons == [_reason(bundle)] * 3, reasons


def test_an_imported_finding_keeps_where_it_came_from_and_its_original(imported):
    f, _e, bundle = imported
    imp = f["imported_from"]
    assert imp["case_id"] == "INC-A" and imp["examiner"] == bundle["examiner"]
    assert imp["exported_at"] == bundle["exported_at"] and imp["imported_at"]
    o = imp["original"]
    assert (o["examiner"], o["created_by"], o["staged"]) == ("alice", "alice", STAGED)
    assert (o["provenance"], o["provenance_grade"]) == ("MCP", "FULL")
    assert o["artifact_grades"] == ["FULL", "BROKEN"]
    assert o["artifact_reasons"] == ["", "reference data from opencti, not evidence"]
    assert "examiner" not in f and "created_by" not in f  # stripped, as before


def test_the_other_examiners_notes_and_edits_never_read_as_this_cases(imported):
    f, e, _bundle = imported
    for item in (f, e):
        moved = {"examiner_notes", "examiner_modifications", "provenance_detail"}
        assert not moved & set(item), sorted(moved & set(item))
    o = f["imported_from"]["original"]
    assert o["examiner_notes"] == "checked on alice's box"
    assert o["examiner_modifications"] == {"title": "Process in sample 2"}
    assert o["provenance_detail"]["mcp"] == ["sift-alice-20261001-002"]
    assert e["imported_from"]["original"]["examiner_notes"] == "from the pslist"


def test_an_imported_items_stored_hash_matches_it_as_stored(imported):
    f, e, _bundle = imported
    assert f["content_hash"] == compute_content_hash(f)
    assert e["content_hash"] == compute_content_hash(e)


def test_an_imported_event_is_stamped_too(imported):
    _f, e, bundle = imported
    assert e["provenance_grade"] == "IMPORTED" and e["status"] == "DRAFT"
    assert e["provenance_reason"] == _reason(bundle)
    assert e["imported_from"]["original"]["examiner"] == "alice"


def test_a_bare_array_bundle_is_imported_with_no_origin_named(tmp_path):
    b = _case(tmp_path / "INC-B", "INC-B")
    import_bundle(b, [_finding()])
    f = json.loads((b / "findings.json").read_text())[0]
    assert f["provenance_grade"] == "IMPORTED"
    imp = f["imported_from"]
    assert (imp["case_id"], imp["examiner"], imp["exported_at"]) == ("", "", "")
    assert (
        f["provenance_reason"] == "chain lives in case ? (imported from ?, exported ?)"
    )


def test_an_item_decided_here_is_left_as_it_is(tmp_path):
    b = _case(tmp_path / "INC-B", "INC-B")
    mine = {**_finding(), "status": "APPROVED", "modified_at": "2026-01-01T00:00:00Z"}
    (b / "findings.json").write_text(json.dumps([mine]))
    import_bundle(
        b, {"case_id": "INC-A", "examiner": "alice", "findings": [_finding()]}
    )
    assert json.loads((b / "findings.json").read_text()) == [mine]


def test_the_same_bundle_imported_twice_keeps_the_same_hash(tmp_path, monkeypatch):
    """Re-importing the same bundle leaves the stored copy as it was, so a
    staged review's hash stays valid; and when it was imported isn't content."""
    import vhir_cli.case_io as cio

    b = _case(tmp_path / "INC-B", "INC-B")
    bundle = {"case_id": "INC-A", "examiner": "alice",
              "exported_at": "2026-10-01T00:00:00+00:00", "findings": [_finding()]}  # fmt: skip
    import_bundle(b, bundle)
    first = json.loads((b / "findings.json").read_text())[0]

    class Later(cio.datetime):
        @classmethod
        def now(cls, tz=None):
            return cio.datetime(2027, 1, 1, tzinfo=tz)

    monkeypatch.setattr(cio, "datetime", Later)
    result = import_bundle(b, bundle)
    assert (result["findings"]["updated"], result["findings"]["skipped"]) == (0, 1)
    again = json.loads((b / "findings.json").read_text())[0]
    assert again == first
    restamped = {**first, "imported_from": {**first["imported_from"],
                                            "imported_at": "2027-01-01T00:00:00+00:00"}}  # fmt: skip
    assert compute_content_hash(restamped) == first["content_hash"]


# The same item, and the same digest, pinned in sift's forensic-mcp tests: the
# two copies of the content hash stay identical.
PINNED_ITEM = {
    "id": "F-alice-001",
    "title": "Suspicious process",
    "status": "DRAFT",
    "provenance_grade": "IMPORTED",
    "imported_from": {
        "case_id": "INC-A",
        "examiner": "alice",
        "exported_at": "2026-10-01T00:00:00+00:00",
        "imported_at": "2026-10-09T12:00:00+00:00",
        "original": {"examiner": "alice"},
    },
}
PINNED_SHA256 = "6fd72fbe10bcb82e3fd1340274347595ca281656438850714fdd8b5722f45e29"


def test_the_content_hash_of_an_imported_item_is_the_pinned_one():
    assert compute_content_hash(PINNED_ITEM) == PINNED_SHA256
