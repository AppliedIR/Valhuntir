"""`vhir review` indexes only the audit entries it resolves.

The audit trail grows for the life of a case; the findings detail and the
withdrawn-candidates view each resolve a handful of cited ids. Each builds the
index from only those ids, and prints the same chain as before.
"""

from __future__ import annotations

import json

import pytest

import vhir_cli.commands.review as review
from vhir_cli.case_io import load_audit_index, save_findings

CITED = ["sift-tester-20261007-002", "sift-tester-20261007-003"]


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    (tmp_path / "audit").mkdir()
    calls = [{"ts": "2026-10-07T07:59:00Z", "tool": "run_command",
              "audit_id": f"sift-tester-20261007-{n:03d}",
              "params": {"command": f"PECmd -d /prefetch/{n}"}} for n in range(50)]  # fmt: skip
    (tmp_path / "audit" / "sift-mcp.jsonl").write_text(
        "".join(json.dumps(c) + "\n" for c in calls)
    )
    return tmp_path


@pytest.fixture
def indexed(monkeypatch):
    """The ids of every index review builds, in order."""
    built = []

    def recording(case_dir, *args, **kwargs):
        index = load_audit_index(case_dir, *args, **kwargs)
        built.append(set(index))
        return index

    monkeypatch.setattr(review, "load_audit_index", recording)
    return built


def _withdrawn(case, skeptic_ids):
    entry = {"ts": "2026-10-07T08:00:00Z", "tool": "record_finding",
             "audit_id": "forensic-tester-20261007-001", "examiner": "tester",
             "result_summary": {"status": "WITHDRAWN", "title": "t", "observation": "o",
                                "contradiction": "c", "skeptic_audit_ids": skeptic_ids}}  # fmt: skip
    (case / "audit" / "forensic-mcp.jsonl").write_text(json.dumps(entry) + "\n")


def test_withdrawn_candidates_index_only_the_skeptics_calls(case, indexed, capsys):
    _withdrawn(case, CITED)
    review._show_withdrawn(case)
    assert indexed == [set(CITED)]
    out = capsys.readouterr().out
    assert "PECmd -d /prefetch/2" in out and "PECmd -d /prefetch/3" in out
    assert "PECmd -d /prefetch/4" not in out


def test_the_findings_detail_indexes_only_the_cited_calls(case, indexed, capsys):
    save_findings(case, [{"id": "F-tester-001", "status": "DRAFT", "title": "t",
                          "audit_ids": CITED}])  # fmt: skip
    review._show_findings_detail(case)
    assert indexed == [set(CITED)]
    assert "PECmd -d /prefetch/3" in capsys.readouterr().out


NONE = "    [NONE]  {} — no audit record"
SHAPES = [  # a cited-ids value as stored, and the ids shown for it
    (None, []), (5, ["5"]), ({"a": "x"}, ["{'a': 'x'}"]), ("abc", ["abc"]),
    ([1, 2], ["1", "2"]), ([{"x": 1}], ["{'x': 1}"]), ([None], ["None"]),
]  # fmt: skip


@pytest.mark.parametrize("value,shown", SHAPES)
def test_any_cited_ids_value_is_shown_never_a_crash(value, shown, capsys):
    review._print_evidence_chain(review._cited(value), {"x": {}})
    assert capsys.readouterr().out.splitlines() == [NONE.format(i) for i in shown]


@pytest.mark.parametrize("value,shown", [([{"x": 1}], "{'x': 1}"), ("abc", "abc")])
def test_each_view_shows_a_value_that_isnt_a_list_of_text(case, capsys, value, shown):
    _withdrawn(case, [CITED[0], *value] if isinstance(value, list) else value)
    review._show_withdrawn(case)
    save_findings(case, [{"id": "F-tester-001", "title": "t", "audit_ids": CITED},
                         {"id": "F-tester-002", "title": "u", "audit_ids": value}])  # fmt: skip
    review._show_findings_detail(case)
    (case / "timeline.json").write_text(
        json.dumps(
            [
                {
                    "id": "T-tester-001",
                    "timestamp": "2026-10-07T07:00:00Z",
                    "audit_ids": value,
                }
            ]
        )
    )
    review._show_timeline(case, detail=True)
    out = capsys.readouterr().out.splitlines()
    assert out.count(NONE.format(shown)) == 2  # withdrawn and findings chains
    assert f"  Evidence:     {shown}" in out and f"  Evidence:    {shown}" in out
    assert "  [F-tester-001] t" in out  # the valid finding prints first


def test_an_int_cited_value_doesnt_stop_the_findings_index(case, indexed, capsys):
    save_findings(case, [{"id": "F-tester-001", "title": "t", "audit_ids": CITED},
                         {"id": "F-tester-002", "title": "u", "audit_ids": 5}])  # fmt: skip
    review._show_findings_detail(case)
    assert indexed == [set(CITED)]
    assert NONE.format("5") in capsys.readouterr().out.splitlines()
