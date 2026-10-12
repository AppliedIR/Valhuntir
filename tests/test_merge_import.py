"""An imported item is in `export --since`, and a failed merge writes nothing.

A merge strips an item's `modified_at` and `staged`, so `export --since T` used
to judge an imported copy by an empty time and leave it out: a peer merging
that export never got it, and nothing said so. The filter now falls back to
when this case imported it. And `import_bundle` used to save findings.json
before merging the timeline, so a timeline that couldn't be merged left the
findings written: both files are now written only after both merges.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import pytest

from vhir_cli.case_io import export_bundle, import_bundle

ST = "2026-10-01T00:00:00+00:00"
FINDING = {"id": "F-alice-001", "status": "DRAFT", "title": "t", "observation": "o",
           "staged": ST, "modified_at": ST}  # fmt: skip
EVENT = {"id": "T-alice-001", "status": "DRAFT", "timestamp": ST, "description": "e",
         "staged": ST, "modified_at": ST}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "bob"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(json.dumps({"case_id": "INC-BOB", "name": "bob"}))
    for name in ("findings.json", "timeline.json"):
        (d / name).write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", "bob")
    return d


def _files(case):
    return {n: (case / n).read_bytes() for n in ("findings.json", "timeline.json")}


def test_an_imported_finding_and_event_are_in_export_since(case):
    """T is aware UTC and taken before the import; the items are new here
    (added, not skipped), and found by id, not by count."""
    since = datetime.now(timezone.utc).isoformat()
    time.sleep(0.01)
    bundle = {"case_id": "INC-A", "examiner": "alice", "exported_at": ST,
              "findings": [dict(FINDING)], "timeline": [dict(EVENT)]}  # fmt: skip
    result = import_bundle(case, bundle)
    assert (result["findings"]["added"], result["timeline"]["added"]) == (1, 1)
    exported = export_bundle(case, since=since)
    assert [f["id"] for f in exported["findings"]] == ["F-alice-001"]
    assert [t["id"] for t in exported["timeline"]] == ["T-alice-001"]


@pytest.mark.parametrize("timeline", [["oops"], None], ids=["oops", "null"])
def test_a_timeline_that_cant_be_merged_writes_neither_file(case, timeline):
    """The finding is one the case doesn't hold, so a merge would add it: the
    control below shows it does, with a valid timeline."""
    new = {"id": "F-carol-001", "status": "DRAFT", "title": "t", "modified_at": ST}
    before = _files(case)
    with pytest.raises(
        (AttributeError, TypeError)
    ):  # "oops" has no .get; None no items
        import_bundle(
            case, {"case_id": "INC-C", "findings": [new], "timeline": timeline}
        )
    assert _files(case) == before

    result = import_bundle(
        case, {"case_id": "INC-C", "findings": [new], "timeline": []}
    )
    assert result["findings"]["added"] == 1


def test_an_import_that_waits_for_the_case_lock_is_in_export_since(case, monkeypatch):
    """The cutoff T falls while the import waits for the lock: the items are
    stored after T, so they're stamped after T."""
    import contextlib

    from vhir_cli import ledger

    real_lock = ledger.case_lock
    cutoffs = []

    @contextlib.contextmanager
    def waited(case_id):
        time.sleep(0.01)  # another writer holds the lock
        cutoffs.append(datetime.now(timezone.utc).isoformat())
        time.sleep(0.01)
        with real_lock(case_id):
            yield

    monkeypatch.setattr(ledger, "case_lock", waited)
    bundle = {
        "case_id": "INC-A",
        "findings": [dict(FINDING)],
        "timeline": [dict(EVENT)],
    }
    assert import_bundle(case, bundle)["findings"]["added"] == 1
    monkeypatch.setattr(ledger, "case_lock", real_lock)
    exported = export_bundle(case, since=cutoffs[0])
    assert [f["id"] for f in exported["findings"]] == ["F-alice-001"]
    assert [t["id"] for t in exported["timeline"]] == ["T-alice-001"]
