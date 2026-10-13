"""An imported bundle never brings another case's host identity: findings and
timeline items come in without `host_id` and the `vhir.*` host fields, and the
case's host files are never touched. The merge is real. Values are synthetic.
"""

from __future__ import annotations

import json

import pytest
import yaml

from vhir_cli.case_io import import_bundle

HOST_FILES = ("host-observations.jsonl", "host-decisions.jsonl", "host-ops.json")


@pytest.fixture
def case(tmp_path):
    case = tmp_path / "INC-2026-2431"
    case.mkdir()
    (case / "CASE.yaml").write_text(yaml.dump({"case_id": case.name, "status": "open"}))
    (case / "findings.json").write_text("[]")
    (case / "timeline.json").write_text("[]")
    for name, text in zip(
        HOST_FILES, ('{"kind": "unit"}\n', "", '{"ops": {}}'), strict=True
    ):
        (case / name).write_text(text)
    return case


def _item(iid, **extra):
    return {"id": iid, "title": "From the other case", "host": "WKS01",
            "modified_at": "2026-01-01T00:00:00+00:00", **extra}  # fmt: skip


def _stored(case, name):
    return {i["id"]: i for i in json.loads((case / name).read_text())}


def test_a_finding_and_an_event_come_in_without_the_other_cases_host_identity(case):
    import_bundle(case, {
        "findings": [_item("F-x-001", host_id="WKS01-OTHER", **{
            "vhir.host_key": "0123456789abcdef", "vhir.unit": "u1"})],
        "timeline": [_item("T-x-001", vhir={"host_key": "0123456789abcdef",
                                            "prev_ids": ["a"], "source": "kept"})],
    })  # fmt: skip
    finding = _stored(case, "findings.json")["F-x-001"]
    assert not {"host_id", "vhir.host_key", "vhir.unit"} & set(finding), finding
    assert finding["host"] == "WKS01" and finding["title"] == "From the other case"
    event = _stored(case, "timeline.json")["T-x-001"]
    assert event["vhir"] == {"source": "kept"}, event


def test_a_bare_array_bundle_is_stripped_too(case):
    import_bundle(case, [_item("F-x-002", host_id="WKS01-OTHER")])
    assert "host_id" not in _stored(case, "findings.json")["F-x-002"]


def test_the_cases_host_files_are_never_touched(case):
    before = {n: (case / n).read_bytes() for n in HOST_FILES}
    import_bundle(case, {
        "findings": [_item("F-x-003")],
        **{n: [{"kind": "bind", "unit": "u9", "raw": "EVIL", "key": "k"}] for n in HOST_FILES},
        "host_files": {n: "replaced" for n in HOST_FILES},
    })  # fmt: skip
    assert {n: (case / n).read_bytes() for n in HOST_FILES} == before


def test_anchor_an_item_without_host_fields_comes_in_whole(case):
    item = _item("F-x-004", observation="obs", vhir={"source": "kept"})
    import_bundle(case, {"findings": [item]})
    stored = _stored(case, "findings.json")["F-x-004"]
    content = (
        "title",
        "host",
        "observation",
        "vhir",
    )  # (the merge sets its own stamps)
    assert {k: stored[k] for k in content} == {k: item[k] for k in content}
