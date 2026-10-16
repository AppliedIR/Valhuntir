"""A bundle the merge can't take is refused by name, and a failed write
changes no file.

- import_bundle refuses, before the case is touched, a findings or timeline
  section that isn't a list of objects, an item whose id is set but isn't
  text, and an item nested deeper than 100 levels. The refusal names the
  section, the item and the fault, and nothing is written.
- Every file's text is made before any file is written, so a failure while
  making one (an item already stored too deep to write, say) writes neither.
- What merges today still merges; a bug inside the merge still raises.
"""

from __future__ import annotations

import argparse
import json

import pytest

import vhir_cli.case_io as cio
from vhir_cli.case_io import import_bundle
from vhir_cli.commands.sync import cmd_merge

ST = "2026-10-01T00:00:00+00:00"
NEW_F = {"id": "F-carol-001", "status": "DRAFT", "title": "t", "observation": "o",
         "modified_at": ST, "staged": ST}  # fmt: skip
NEW_T = {"id": "T-carol-001", "status": "DRAFT", "timestamp": ST, "description": "e",
         "modified_at": ST, "staged": ST}  # fmt: skip
TAIL = "; nothing was merged. Fix the bundle or ask for a new export, then merge again."


def msg(key: str, why: str) -> str:
    return f"The bundle's {key} {why}{TAIL}"


@pytest.fixture
def case(tmp_path, monkeypatch):
    """One stored item in each file, written as the merge writes it, so only a
    real change shows."""
    d = tmp_path / "bob"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(json.dumps({"case_id": "INC-BOB", "name": "bob"}))
    (d / "findings.json").write_text(json.dumps([{"id": "F-bob-001", "status": "DRAFT",
        "title": "mine", "created_by": "bob", "modified_at": ST}], indent=2))  # fmt: skip
    (d / "timeline.json").write_text(json.dumps([{"id": "T-bob-001", "status": "DRAFT",
        "description": "mine", "created_by": "bob", "modified_at": ST}], indent=2))  # fmt: skip
    monkeypatch.setenv("VHIR_EXAMINER", "bob")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def files(case) -> dict:
    return {n: (case / n).read_bytes() for n in ("findings.json", "timeline.json")}


def nested(item: dict, levels: int) -> dict:
    """`item` with a field that makes it exactly `levels` levels deep (the
    item is level 1; each list counts)."""
    inner: list = []
    for _ in range(levels - 2):
        inner = [inner]
    return dict(item, x=inner)


NOT_A_LIST = {"null": None, "empty-text": "", "empty-object": {}, "object": {"a": 1},
              "5": 5, "text": "abc"}  # fmt: skip
ID_NOT_TEXT = {"[1]": [1], "5": 5, "0": 0, "false": False, "[]": [], "{}": {}, "5.5": 5.5,
               "true": True, "{a:1}": {"a": 1}}  # fmt: skip

C1 = []
for key, other, valid in (
    ("timeline", "findings", NEW_T),
    ("findings", "timeline", NEW_F),
):
    for name, block in NOT_A_LIST.items():
        C1.append(
            pytest.param(key, other, block, "isn't a list", id=f"{key}-section-{name}")
        )
    second = dict(valid, id=valid["id"].replace("001", "002"))
    for name, (block, n) in {
        "[oops]": (["oops"], 0),
        "[valid,oops]": ([second, "oops"], 1),
    }.items():
        C1.append(
            pytest.param(
                key, other, block, f"item {n} isn't an object", id=f"{key}-{name}"
            )
        )
    for name, bad in ID_NOT_TEXT.items():
        C1.append(pytest.param(key, other, [dict(valid, id=bad)],
                               "item 0 has an id that isn't text", id=f"{key}-id-{name}"))  # fmt: skip
    C1.append(pytest.param(key, other, [nested(valid, 101)],
                           "item 0 nests deeper than 100 levels", id=f"{key}-101-deep"))  # fmt: skip


@pytest.mark.parametrize("key,other,block,why", C1)
def test_a_section_the_merge_cant_take_is_refused_by_name_and_nothing_written(
    case, key, other, block, why
):
    """The other section carries an item the case doesn't hold, so a merge that
    wrote anything would change its file (the control shows it adds)."""
    before = files(case)
    bundle = {"case_id": "INC-C", "examiner": "carol", key: block,
              other: [dict(NEW_F if other == "findings" else NEW_T)]}  # fmt: skip
    assert import_bundle(case, bundle) == {"status": "error", "message": msg(key, why)}
    assert files(case) == before


@pytest.mark.parametrize(
    "bare,why",
    [(["oops"], "item 0 isn't an object"), ([dict(NEW_F), {"id": 7}], "item 1 has an id that isn't text")],
    ids=["oops", "valid-then-id-7"],
)  # fmt: skip
def test_a_bare_array_is_refused_as_findings(case, bare, why):
    before = files(case)
    assert import_bundle(case, bare) == {
        "status": "error",
        "message": msg("findings", why),
    }
    assert files(case) == before


@pytest.mark.parametrize(
    "extra",
    [{}, {"todos": None}, {"todos": 5}, {"todos": ["oops"]}],
    ids=["valid", "todos-null", "todos-5", "todos-oops"],
)
def test_a_mergeable_bundle_still_merges(case, extra):
    result = import_bundle(
        case,
        {
            "case_id": "INC-C",
            "findings": [dict(NEW_F)],
            "timeline": [dict(NEW_T)],
            **extra,
        },
    )
    assert result["status"] == "merged"
    assert (result["findings"]["added"], result["timeline"]["added"]) == (1, 1)


@pytest.mark.parametrize(
    "item",
    [{"title": "no id"}, {"id": None}, {"id": ""}],
    ids=["no-id", "id-null", "id-empty"],
)
def test_an_item_with_no_id_is_still_skipped(case, item):
    result = import_bundle(case, {"case_id": "INC-C", "findings": [item, dict(NEW_F)]})
    assert (result["status"], result["findings"]["added"], result["findings"]["skipped"]) == (
        "merged", 1, 1
    )  # fmt: skip


@pytest.mark.parametrize(
    "bad", [123, [], {}, True, "junk"], ids=["123", "list", "object", "true", "junk"]
)
def test_a_wrong_typed_time_still_merges(case, bad):
    result = import_bundle(
        case,
        {"case_id": "INC-C", "findings": [dict(NEW_F, modified_at=bad, staged=bad)]},
    )
    assert (result["status"], result["findings"]["added"]) == ("merged", 1)


@pytest.mark.parametrize("key,item", [("timeline", NEW_T), ("findings", NEW_F)])
def test_an_item_nested_exactly_100_levels_still_merges(case, key, item):
    result = import_bundle(case, {"case_id": "INC-C", key: [nested(item, 100)]})
    assert (result["status"], result[key]["added"]) == ("merged", 1)


@pytest.mark.parametrize(
    "exc", [RuntimeError, TypeError, AttributeError], ids=lambda e: e.__name__
)
def test_a_bug_in_the_merge_still_raises_and_writes_nothing(case, monkeypatch, exc):
    def broken(*a, **k):
        raise exc("injected bug")

    monkeypatch.setattr(cio, "_stamp_import", broken)
    before = files(case)
    with pytest.raises(exc, match="injected bug"):
        import_bundle(
            case,
            {"case_id": "INC-C", "findings": [dict(NEW_F)], "timeline": [dict(NEW_T)]},
        )
    assert files(case) == before


def test_a_local_file_that_isnt_a_list_is_never_blamed_on_the_bundle(case):
    (case / "timeline.json").write_text("{}")
    before = files(case)
    try:
        result = import_bundle(
            case,
            {"case_id": "INC-C", "findings": [dict(NEW_F)], "timeline": [dict(NEW_T)]},
        )
    except (TypeError, AttributeError):
        result = None
    assert result is None or not result.get("message", "").startswith("The bundle's")
    assert files(case) == before


class _JsonThatCantWrite:
    """case_io's json, whose dumps raises RecursionError (as for an item stored
    too deep to write) on one file's list: the one holding `marker`."""

    def __init__(self, marker: str):
        self.marker = marker

    def __getattr__(self, name):
        return getattr(json, name)

    def dumps(self, value, *a, **kw):
        if isinstance(value, list) and any(
            isinstance(i, dict) and i.get("id") == self.marker for i in value
        ):
            raise RecursionError("maximum recursion depth exceeded while encoding")
        return json.dumps(value, *a, **kw)


@pytest.mark.parametrize("stored_in", ["timeline.json", "findings.json"])
def test_a_file_that_cant_be_written_leaves_both_files_as_they_were(
    case, monkeypatch, stored_in
):
    """A valid bundle adds to both files; one file's text can't be made. Made
    in order and written as made, the other file would be written first."""
    marker = "T-bob-001" if stored_in == "timeline.json" else "F-bob-001"
    monkeypatch.setattr(cio, "json", _JsonThatCantWrite(marker))
    before = files(case)
    with pytest.raises(RecursionError):
        import_bundle(
            case,
            {"case_id": "INC-C", "findings": [dict(NEW_F)], "timeline": [dict(NEW_T)]},
        )
    assert files(case) == before


def test_vhir_merge_says_merge_failed_and_exits_1(case, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(
        json.dumps({"case_id": "INC-C", "findings": [NEW_F], "timeline": ["oops"]})
    )
    before = files(case)
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cmd_merge(argparse.Namespace(case=None, file=str(path)), {"examiner": "bob"})
    out, err = capsys.readouterr()
    refusal = msg("timeline", "item 0 isn't an object")
    assert (e.value.code, out, err) == (1, "", f"Merge failed: {refusal}\n")
    assert files(case) == before


# --- a bundle too deep to decode ----------------------------------------------

TOO_DEEP = {"status": "error", "message": (
    "The bundle nests deeper than 100 levels; nothing was merged. "
    "Fix the bundle or ask for a new export, then merge again.")}  # fmt: skip


def deep_bundle_text(levels: int) -> str:
    """A bundle whose finding holds `levels` nested lists, written as text:
    deep enough, json can't build it, so it can't be made with json.dumps."""
    finding = json.dumps(NEW_F)[:-1] + ', "x": ' + "[" * levels + "]" * levels + "}"
    return '{"case_id": "INC-C", "examiner": "carol", "findings": [' + finding + "]}"


def test_bundle_too_deep_is_the_named_refusal():
    assert cio.bundle_too_deep() == TOO_DEEP


# beyond every json decoder: 3.10 stops near 1000 levels, 3.12 and 3.13 near 10,000
@pytest.mark.parametrize("levels", [20_000, 100_000])
def test_vhir_merge_refuses_a_bundle_too_deep_to_decode_by_name(
    case, tmp_path, capsys, levels
):
    path = tmp_path / "bundle.json"
    path.write_text(deep_bundle_text(levels))
    before = files(case)
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cmd_merge(argparse.Namespace(case=None, file=str(path)), {"examiner": "bob"})
    out, err = capsys.readouterr()
    assert (e.value.code, out, err) == (1, "", f"Merge failed: {TOO_DEEP['message']}\n")
    assert files(case) == before


def test_vhir_merge_still_merges_a_bundle_100_levels_deep(case, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"case_id": "INC-C", "findings": [nested(NEW_F, 100)]}))
    cmd_merge(argparse.Namespace(case=None, file=str(path)), {"examiner": "bob"})
    assert "F-carol-001" in (case / "findings.json").read_text()


def test_a_bundle_one_json_decodes_and_another_doesnt_is_refused_by_name_either_way(
    case, tmp_path, capsys
):
    """2000 levels: 3.10's json can't decode it (the bundle refusal), 3.12's
    can (the item refusal). Both are named; neither writes."""
    path = tmp_path / "bundle.json"
    path.write_text(deep_bundle_text(2000))
    before = files(case)
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cmd_merge(argparse.Namespace(case=None, file=str(path)), {"examiner": "bob"})
    out, err = capsys.readouterr()
    item = msg("findings", "item 0 nests deeper than 100 levels")
    assert e.value.code == 1 and out == ""
    assert err in (f"Merge failed: {TOO_DEEP['message']}\n", f"Merge failed: {item}\n")
    assert files(case) == before
