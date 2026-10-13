"""export_bundle's `since` compares instants, not text.

`since="…+05:30"` exported none of the items after that instant, and
same-second fractional items fell before a `…Z` since, because the
timestamps were compared as strings. When either side doesn't parse, the
comparison stays textual, as it was.
"""

from __future__ import annotations

import json

import pytest

from vhir_cli.case_io import export_bundle


@pytest.fixture
def export(tmp_path):
    def run(findings, since):
        case = tmp_path / "case-utc"
        case.mkdir(exist_ok=True)
        (case / "CASE.yaml").write_text("case_id: case-utc\nstatus: open\n")
        (case / "findings.json").write_text(json.dumps(findings))
        (case / "timeline.json").write_text(json.dumps(findings))
        bundle = export_bundle(case, since=since)
        got = sorted(f["id"] for f in bundle["findings"])
        assert sorted(t["id"] for t in bundle["timeline"]) == got
        return got

    return run


def test_an_offset_since_exports_what_came_after_it(export):
    items = [
        {"id": f"F-{i:02d}", "modified_at": f"2026-10-02T08:{30 + i}:00.123456+00:00"}
        for i in range(1, 11)
    ]
    assert len(export(items, "2026-10-02T14:00:00+05:30")) == 10  # = 08:30Z


def test_a_z_since_keeps_same_second_fractional_items(export):
    items = [
        {"id": "eq", "modified_at": "2026-10-02T08:38:43+00:00"},
        {"id": "frac", "modified_at": "2026-10-02T08:38:43.215000+00:00"},
        {"id": "later", "modified_at": "2026-10-02T08:38:44.000001+00:00"},
        {"id": "before", "modified_at": "2026-10-02T08:38:42.999999+00:00"},
    ]
    assert export(items, "2026-10-02T08:38:43Z") == ["eq", "frac", "later"]


STORED = [
    {"id": "x", "modified_at": "2026-10-02T08:38:43.215000+00:00"},
    {"id": "y", "modified_at": "2026-10-02T09:00:00.000001+00:00"},
    {"id": "nots", "title": "merged, no modified_at"},
]


@pytest.mark.parametrize(
    "since,want",
    [
        ("2026-10-02T08:38:43.215000+00:00", ["x", "y"]),  # the stored format
        ("2026-10-02", ["x", "y"]),
        ("2026-10-03", []),
        ("2026-13-01", []),  # date-shaped but not a date: compared as text
        ("2026-00-01", ["x", "y"]),  # date-shaped, month 0: compared as text
    ],
)
def test_stored_format_and_unparseable_values_are_unchanged(export, since, want):
    # The item with no timestamp compares "" as text, as before: never exported.
    assert export(STORED, since) == want
