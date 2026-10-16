"""A bundle item whose id names another kind than its section is refused.

Approval, review and the portal read an item's kind from its id's prefix
(case_io.id_kind: IOC- is an IOC, T- a timeline event, any other a finding);
verify reads it from the file. So a merge refuses, whole and by name, a
findings item whose id reads as an event's or an IOC's, and a timeline item
whose id doesn't read as an event's. Ids of every form a writer has made
still merge. decide.item_type is that same rule.
"""

from __future__ import annotations

import argparse
import json

import pytest

import vhir_cli.case_io as cio
from vhir_cli import decide
from vhir_cli.case_io import import_bundle
from vhir_cli.commands.sync import cmd_merge

END = "; nothing was merged. Fix the bundle or ask for a new export, then merge again."
T_IN_F = "has a timeline event's id (it starts with T-)"
IOC_IN_F = "has an IOC's id (it starts with IOC-)"
NOT_T = "has an id that doesn't start with T-"
LOCAL_F, LOCAL_T = ["F-alice-001"], ["T-alice-001"]


def f(i):
    return {"id": i, "title": f"t {i}", "observation": "o", "status": "DRAFT",
            "modified_at": "2026-10-12T09:00:00+00:00"}  # fmt: skip


def t(i):
    return {"id": i, "timestamp": "2026-10-01T12:00:00Z", "description": f"d {i}",
            "status": "DRAFT", "modified_at": "2026-10-12T09:00:00+00:00"}  # fmt: skip


@pytest.fixture
def case(tmp_path, monkeypatch):
    """The DRAFT finding F-alice-001 and the DRAFT event T-alice-001."""
    d = tmp_path / "alice"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: INC-A\nstatus: open\n")
    (d / "findings.json").write_text(json.dumps([f("F-alice-001")], indent=2))
    (d / "timeline.json").write_text(json.dumps([t("T-alice-001")], indent=2))
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    return d


def files(case) -> dict:
    return {n: (case / n).read_bytes() for n in ("findings.json", "timeline.json")}


def ids(case, name) -> list:
    return [x.get("id") for x in json.loads((case / name).read_text())]


@pytest.mark.parametrize(
    "bundle,section,n,fault",
    [
        ({"findings": [f("T-bob-001")]}, "findings", 0, T_IN_F),
        ({"findings": [f("IOC-bob-001")]}, "findings", 0, IOC_IN_F),
        ({"timeline": [t("F-bob-001")]}, "timeline", 0, NOT_T),
        ({"timeline": [t("alice/T-001")]}, "timeline", 0, NOT_T),
        ({"timeline": [t("t-bob-001")]}, "timeline", 0, NOT_T),
        ([f("T-x-1")], "findings", 0, T_IN_F),
        ({"findings": [f("F-bob-001"), f("T-bob-002")]}, "findings", 1, T_IN_F),
        ({"timeline": [t("IOC-bob-009")]}, "timeline", 0, NOT_T),
        ({"findings": [f("F-bob-001")], "timeline": [t("F-bob-002")]}, "timeline", 0, NOT_T),
    ],
    ids=["finding-T", "finding-IOC", "event-F", "event-scoped", "event-lower-t",
         "bare-array-T", "second-finding", "event-IOC", "good-findings-bad-event"],
)  # fmt: skip
def test_an_item_whose_id_names_another_kind_is_refused_and_nothing_written(
    case, bundle, section, n, fault
):
    before = files(case)
    assert import_bundle(case, bundle) == {
        "status": "error",
        "message": f"The bundle's {section} item {n} {fault}{END}",
    }
    assert files(case) == before


@pytest.mark.parametrize(
    "bundle,findings,timeline",
    [
        ({"findings": [f("F-bob-001")], "timeline": [t("T-bob-001")]},
         LOCAL_F + ["F-bob-001"], LOCAL_T + ["T-bob-001"]),
        ({"findings": [f("legacy-7")], "timeline": [t("T-001")]},
         LOCAL_F + ["legacy-7"], LOCAL_T + ["T-001"]),
        ({"findings": [f("F-001")]}, LOCAL_F + ["F-001"], LOCAL_T),
        ({"findings": [{"title": "no id"}]}, LOCAL_F, LOCAL_T),
        ({"timeline": [{**t("T-alice-001"), "modified_at": "2026-10-12T10:00:00+00:00"}]},
         LOCAL_F, LOCAL_T),
    ],
    ids=["right-prefixes", "unknown-and-legacy-forms", "legacy-F-001", "no-id",
         "same-kind-update"],
)  # fmt: skip
def test_ids_of_every_form_a_writer_made_still_merge(case, bundle, findings, timeline):
    assert import_bundle(case, bundle)["status"] == "merged"
    assert (ids(case, "findings.json"), ids(case, "timeline.json")) == (
        findings,
        timeline,
    )


def test_approval_reads_an_items_kind_by_the_rule_the_merge_enforces(monkeypatch):
    monkeypatch.setattr(cio, "id_kind", lambda item_id: "sentinel")
    assert decide.item_type("F-x-001") == "sentinel"


def test_vhir_merge_says_merge_failed_and_exits_1(case, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"case_id": "INC-B", "findings": [f("T-alice-001")]}))
    before = files(case)
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        cmd_merge(argparse.Namespace(case=None, file=str(path)), {"examiner": "alice"})
    out, err = capsys.readouterr()
    refusal = f"The bundle's findings item 0 {T_IN_F}{END}"
    assert (e.value.code, out, err) == (1, "", f"Merge failed: {refusal}\n")
    assert files(case) == before
