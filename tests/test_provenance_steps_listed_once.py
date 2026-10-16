"""Each step of a finding's provenance chain is listed once, in `vhir review
--detail` and in the reports. A query that reads many files out of one mounted
image stores the root and mount links once per file; the view lists each step
once within a group's chain and within the tail of links no record follows. Two
links are the same step when their JSON objects are equal with keys sorted;
the first is kept, in stored order. A step two groups share is listed in both,
so neither group's chain has a gap. The stored chain and the grade are
unchanged."""

from __future__ import annotations

import copy
import gzip
import json
import re
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from vhir_cli.case_io import compute_content_hash
from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review
from vhir_cli.provenance_view import finding_lines, link_line, provenance_block

from .signing import sign_approved

FIXTURE = Path(__file__).parent / "fixtures" / "fan_in_chain.json.gz"
STEP = re.compile(r"^\s+\d+\. ")


def _fan_in() -> dict:
    """One stored finding whose one artifact read 360 logs out of one mounted
    image: 1082 links, 364 of them distinct, two repeated 360 times."""
    (f,) = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    return f


def _key(link):
    return json.dumps(link, sort_keys=True)


def _steps(lines) -> list[str]:
    """The numbered step lines, without their numbers."""
    return [STEP.sub("", ln) for ln in lines if STEP.match(ln)]


def _link(method, aid, src, dst, **extra):
    return {"method": method, "audit_id": aid, "entry_sha256": "e" * 64,
            "from": {"path": src, "sha256": "a" * 64},
            "to": {"path": dst, "sha256": "b" * 64}, **extra}  # fmt: skip


def _record(rid):
    return {"method": "recorded-id", "audit_id": f"opensearch-x-{rid}",
            "entry_sha256": "e" * 64, "from": {"path": "", "sha256": ""},
            "to": {"path": "", "sha256": ""},
            "document": {"_index": "case-x-vol", "_id": rid, "content_hash": "9" * 64}}  # fmt: skip


def _finding(chain) -> dict:
    return {"id": "F-x-001", "title": "t", "status": "DRAFT", "provenance_schema": 2,
            "provenance_grade": "FULL",
            "artifacts": [{"provenance_grade": "FULL", "provenance_chain": chain,
                           "provenance_root": {"path": "/e/disk.E01", "sha256": "a" * 64}}]}  # fmt: skip


ROOT = _link("registered-path", "sift-x-001", "/e/disk.E01", "/e/disk.E01")
MOUNT = _link("recorded-id", "sift-x-002", "/e/disk.E01", "/mnt/x")
A = _link("recorded-mount", "sift-x-003", "/mnt/x/a.evtx", "/mnt/x")
B = _link("recorded-mount", "sift-x-004", "/mnt/x/b.evtx", "/mnt/x")


# --- the stored fan-in shape ---------------------------------------------------


def test_fan_in_chain_lists_each_step_once():
    f = _fan_in()
    chain = f["artifacts"][0]["provenance_chain"]
    distinct = list({_key(x): x for x in reversed(chain)}.values())[::-1]
    assert (len(chain), len(distinct)) == (1082, 364)
    steps = _steps(finding_lines(f))
    assert len(steps) == 364
    for line in {link_line(x) for x in chain}:
        assert steps.count(line) == 1, line
    # the root and mount links, stored 360 times each, are the first two steps
    assert steps[:2] == [link_line(chain[0]), link_line(chain[1])]
    assert "(no hash)" in steps[1] and "sha256=?" not in "\n".join(steps)


def test_fan_in_keeps_the_stored_chain_and_the_grade():
    f = _fan_in()
    before = copy.deepcopy(f)
    lines = finding_lines(f)
    assert f == before
    assert lines[0] == "  Provenance: FULL"
    assert lines[1] == "    [1] FULL"


def test_fan_in_in_the_report_block_lists_each_step_once():
    f = _fan_in()
    chain = f["artifacts"][0]["provenance_chain"]
    lines = provenance_block({"findings": [f]})
    assert len(_steps(lines)) == 364
    assert _steps(lines).count(link_line(chain[0])) == 1


# --- groups and the tail ---------------------------------------------------------


def test_a_repeated_step_in_one_group_s_chain_shows_once():
    steps = _steps(
        finding_lines(_finding([ROOT, MOUNT, A, ROOT, MOUNT, B, _record("r1")]))
    )
    assert steps == [link_line(x) for x in (ROOT, MOUNT, A, B, _record("r1"))]


def test_a_step_two_groups_share_shows_in_both():
    chain = [ROOT, MOUNT, A, _record("r1"), ROOT, MOUNT, B, _record("r2")]
    steps = _steps(finding_lines(_finding(chain)))
    assert steps == [link_line(x) for x in chain]
    assert steps.count(link_line(ROOT)) == 2 and steps.count(link_line(MOUNT)) == 2


def test_two_ingests_that_start_with_the_same_step_each_list_it():
    chain = [ROOT, A, _record("r1"), ROOT, B, _record("r2")]
    steps = _steps(finding_lines(_finding(chain)))
    assert steps == [link_line(x) for x in chain]


def test_records_from_two_ingests_interleaved_each_sit_under_their_own():
    chain = [ROOT, A, _record("r1"), ROOT, B, _record("r2"), ROOT, A, _record("r3")]
    steps = _steps(finding_lines(_finding(chain)))
    want = (ROOT, A, _record("r1"), _record("r3"), ROOT, B, _record("r2"))
    assert steps == [link_line(x) for x in want]


def test_records_of_one_ingest_stored_together_stay_under_it():
    chain = [ROOT, A, _record("r1"), _record("r3"), ROOT, B, _record("r2")]
    steps = _steps(finding_lines(_finding(chain)))
    assert steps == [link_line(x) for x in chain]


def test_the_tail_no_record_follows_lists_each_step_once():
    steps = _steps(finding_lines(_finding([ROOT, MOUNT, A, ROOT, MOUNT, B, A])))
    assert steps == [link_line(x) for x in (ROOT, MOUNT, A, B)]


def test_a_group_and_the_tail_each_keep_a_step_they_share():
    chain = [ROOT, A, _record("r1"), ROOT, B, ROOT]
    steps = _steps(finding_lines(_finding(chain)))
    assert steps == [link_line(x) for x in (ROOT, A, _record("r1"), ROOT, B)]


def test_the_same_step_with_its_keys_in_another_order_shows_once():
    again = json.loads(json.dumps(MOUNT))
    again = {k: again[k] for k in reversed(list(again))}
    again["from"] = {k: again["from"][k] for k in reversed(list(again["from"]))}
    assert list(again) != list(MOUNT)
    steps = _steps(finding_lines(_finding([ROOT, MOUNT, A, again, B])))
    assert steps == [link_line(x) for x in (ROOT, MOUNT, A, B)]


@pytest.mark.parametrize(
    "field, value",
    [("entry_sha256", "f" * 64), ("audit_id", "sift-x-099"), ("method", "hash+place")],
)
def test_steps_that_differ_in_one_field_both_show(field, value):
    other = {**A, field: value}
    steps = _steps(finding_lines(_finding([ROOT, A, other])))
    assert len(steps) == 3


def test_steps_whose_ends_differ_only_in_a_hash_both_show():
    other = copy.deepcopy(A)
    other["from"]["sha256"] = "c" * 64
    steps = _steps(finding_lines(_finding([ROOT, A, other])))
    assert len(steps) == 3 and steps[1] != steps[2]


def test_an_identical_record_link_still_shows_once_per_group():
    steps = _steps(finding_lines(_finding([ROOT, _record("r1"), ROOT, _record("r1")])))
    assert steps == [link_line(ROOT), link_line(_record("r1"))]


# --- the views ---------------------------------------------------------------------


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-9"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-9", "status": "open"}))
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    for name in ("timeline.json", "iocs.json", "todos.json"):
        (d / name).write_text("[]")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "examiner")
    return d


def _save(d, f):
    f = json.loads(json.dumps(f))
    f["content_hash"] = compute_content_hash(f)
    (d / "findings.json").write_text(json.dumps([f], indent=1))


def _fan_in_steps(out: str) -> list[str]:
    return _steps(out.split("\n"))


def test_review_detail_lists_each_fan_in_step_once(case, capsys):
    f = _fan_in()
    f["status"] = "DRAFT"
    _save(case, f)
    args = dict(case=None, findings=True, detail=True, verify=False, iocs=False,
                timeline=False, audit=False, evidence=False, limit=50, todos=False,
                open=False)  # fmt: skip
    cmd_review(Namespace(**args), {})
    steps = _fan_in_steps(capsys.readouterr().out)
    chain = f["artifacts"][0]["provenance_chain"]
    assert len(steps) == 364
    assert steps.count(link_line(chain[0])) == 1
    assert steps.count(link_line(chain[1])) == 1


def test_the_report_lists_each_fan_in_step_once(case, capsys):
    _save(case, _fan_in())
    sign_approved(case, "examiner")
    args = {"case": None, "full": False, "executive_summary": False,
            "report_timeline": False, "from_date": None, "to_date": None, "ioc": False,
            "report_findings": "F-examiner-010", "status_brief": False, "save": None}  # fmt: skip
    cmd_report(Namespace(**args), {"examiner": "examiner"})
    out = capsys.readouterr().out
    tail = out[out.index("PROVENANCE") :]
    steps = _fan_in_steps(tail)
    chain = _fan_in()["artifacts"][0]["provenance_chain"]
    assert len(steps) == 364
    assert steps.count(link_line(chain[0])) == 1
