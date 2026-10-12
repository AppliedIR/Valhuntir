"""A merge whose local files or bundle hold an id more than once is refused.

Last-write-wins finds an item by its id: with two copies of one id it can
compare against one copy and write over the other, so an APPROVED finding could
be replaced by a DRAFT. A duplicate stops the merge, naming the id, before
anything is written, for `vhir merge` and case-mcp's import alike (both go
through import_bundle).
"""

from __future__ import annotations

import argparse
import json
import re

import pytest

from vhir_cli.case_io import _duplicate_ids, import_bundle
from vhir_cli.commands.sync import cmd_merge

OLD = "2026-01-01T00:00:00+00:00"
NEW = "2026-06-01T00:00:00+00:00"
CONTROLS = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f]")  # any but the line break


@pytest.fixture
def case_dir(tmp_path, monkeypatch):
    d = tmp_path / "case"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(json.dumps({"case_id": "INC-2026-0001"}))
    (d / "findings.json").write_text("[]")
    (d / "timeline.json").write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def _files(case_dir):
    return {n: (case_dir / n).read_bytes() for n in ("findings.json", "timeline.json")}


def _refused(case_dir, bundle, *names):
    before = _files(case_dir)
    result = import_bundle(case_dir, bundle)
    assert result["status"] == "error"
    assert all(n in result["message"] for n in names), result["message"]
    assert "nothing was merged" in result["message"]
    assert _files(case_dir) == before
    return result["message"]


def test_a_local_duplicate_id_is_refused_and_an_approved_finding_kept(case_dir):
    (case_dir / "findings.json").write_text(json.dumps([
        {"id": "F-a-001", "status": "APPROVED", "title": "approved one", "staged": OLD},
        {"id": "F-a-001", "status": "DRAFT", "title": "hand-edited dup", "staged": OLD},
    ]))  # fmt: skip
    incoming = {"id": "F-a-001", "title": "incoming", "staged": NEW}
    _refused(case_dir, {"findings": [incoming]}, "findings.json", "F-a-001")
    approved = json.loads((case_dir / "findings.json").read_text())[0]
    assert (approved["status"], approved["title"]) == ("APPROVED", "approved one")


@pytest.mark.parametrize("key", ["findings", "timeline"])
def test_an_incoming_duplicate_id_is_refused(case_dir, key):
    """Before, the second copy merged as an update over the first (when its
    timestamp is newer): added 1, updated 1."""
    dup = "T-a-001" if key == "timeline" else "X-a-001"  # an event's id names its kind
    copies = [{"id": dup, "description": "first", "staged": OLD},
              {"id": dup, "description": "second", "staged": NEW}]  # fmt: skip
    _refused(case_dir, {key: copies}, f"bundle's {key}", dup)


def test_a_duplicate_in_one_list_writes_neither_file(case_dir):
    """Refused before any write: valid findings aren't merged when the same
    bundle's timeline holds a duplicate id."""
    bundle = {
        "findings": [{"id": "F-b-001", "title": "valid", "staged": NEW}],
        "timeline": [
            {"id": "T-b-001", "staged": OLD},
            {"id": "T-b-001", "staged": NEW},
        ],
    }
    _refused(case_dir, bundle, "bundle's timeline", "T-b-001")
    assert json.loads((case_dir / "findings.json").read_text()) == []


def test_a_local_duplicate_only_blocks_a_merge_of_that_list(case_dir):
    (case_dir / "timeline.json").write_text(json.dumps([
        {"id": "T-a-001", "description": "e", "staged": OLD},
        {"id": "T-a-001", "description": "e again", "staged": OLD},
    ]))  # fmt: skip
    result = import_bundle(case_dir, {"findings": [{"id": "F-b-001", "staged": NEW}]})
    assert result["status"] == "merged" and result["findings"]["added"] == 1
    _refused(
        case_dir, {"timeline": [{"id": "T-b-001", "staged": NEW}]}, "timeline.json"
    )


def test_items_that_have_no_id_or_cant_be_keyed_are_not_duplicates(case_dir):
    """Ids compare by raw value, as the merge keys them: 1 and "1" differ, and
    items with no id, an empty one or an unhashable one are left to the merge."""
    (case_dir / "findings.json").write_text(json.dumps([
        "not an item", {"title": "no id"}, {"title": "no id"},
        {"id": "", "title": "empty"}, {"id": "", "title": "empty"},
        {"id": 1, "staged": OLD}, {"id": "1", "staged": OLD},
    ]))  # fmt: skip
    bundle = {"findings": [{"title": "no id"}, {"title": "no id"},
                           {"id": "F-b-001", "staged": NEW}]}  # fmt: skip
    result = import_bundle(case_dir, bundle)
    assert result["status"] == "merged"
    assert (result["findings"]["added"], result["findings"]["skipped"]) == (1, 2)
    # an unhashable id is never counted (the merge itself rejects it, as before)
    assert _duplicate_ids([{"id": ["x"]}, {"id": ["x"]}, {"id": {"a": 1}}]) == []
    assert _duplicate_ids("not a list") == []


def test_the_cli_names_the_duplicate_without_its_controls(case_dir, tmp_path, capsys):
    """The id is the bundle's data: it can't drive the terminal or the MCP reply."""
    dup = "F-\x1b[2J\x9b\nX"
    bundle = {"findings": [{"id": dup, "staged": OLD}, {"id": dup, "staged": NEW}]}
    message = _refused(case_dir, bundle, "F-?[2J??X")
    assert not CONTROLS.search(message) and "\n" not in message
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    with pytest.raises(SystemExit):
        cmd_merge(argparse.Namespace(file=str(path), case=None), {"examiner": "alice"})
    err = capsys.readouterr().err
    assert err.startswith("Merge failed: ") and "F-?[2J??X" in err
    assert not CONTROLS.search(err) and err.count("\n") == 1


def test_the_refusal_names_at_most_five_ids_each_capped(case_dir):
    long_ids = [c * 100_000 for c in "ab"]
    many = long_ids + [f"F-c-{n:03d}" for n in range(6)]
    message = _refused(case_dir, {"findings": [{"id": i} for i in many * 2]}, "F-c-002")
    assert "a" * 80 + "…" in message and "a" * 81 not in message
    assert "F-c-003" not in message and "and 3 more" in message
    assert len(message) < 600
