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


@pytest.mark.parametrize(
    "skeptic_ids", [None, "sift-tester-20261007-002", {"a": 1}, []]
)
def test_skeptic_ids_that_arent_a_list_print_no_chain_as_before(
    case, indexed, capsys, skeptic_ids
):
    _withdrawn(case, skeptic_ids)
    review._show_withdrawn(case)
    assert indexed == [set()]
    assert "Skeptic's tool calls" not in capsys.readouterr().out


def test_an_unhashable_skeptic_id_fails_where_it_did_before(case, indexed, capsys):
    """The chain printer still meets it, after the ids before it."""
    _withdrawn(case, [CITED[0], {"a": 1}])
    with pytest.raises(TypeError):
        review._show_withdrawn(case)
    assert indexed == [{CITED[0]}]
    assert "PECmd -d /prefetch/2" in capsys.readouterr().out
