"""A finding's MITRE technique ids as each CLI view shows them: the ids joined
with ", ", never the list's Python form. `review --findings --detail`, the
findings report on screen and the saved report each print the same text
`vhir approve --review` already prints; a finding with no ids prints no MITRE
line."""

from __future__ import annotations

import pytest

from vhir_cli import display
from vhir_cli.case_io import save_findings, save_timeline

from .signing import sign_approved
from .test_finding_iocs_and_tabs_shown import _cli, _finding, _view, case  # noqa: F401

# The views that print a finding's MITRE line; "report-saved" is the file
# `report --findings <id> --save` writes
MITRE_VIEWS = ["review-detail", "report", "report-saved", "approve-review"]

# (stored fields, the MITRE text every view shows); None: no MITRE line
MITRE_SHAPES = {
    "list": ({"mitre_ids": ["T1021.002", "T1135"]}, "T1021.002, T1135"),
    "list-as-captured": ({"mitre_ids": ["T1053.005", "T1036.005"]}, "T1053.005, T1036.005"),
    "one-id": ({"mitre_ids": ["T1135"]}, "T1135"),
    "string": ({"mitre_ids": "T1021.002"}, "T1021.002"),
    "number-in-list": ({"mitre_ids": ["T1135", 1135]}, "T1135, 1135"),
    "dict-in-list": ({"mitre_ids": [{"id": "T1135"}]}, "{'id': 'T1135'}"),
    "an-ioc-s-field": ({"mitre_techniques": ["T1135", "T1021"]}, "T1135, T1021"),
    "empty-list": ({"mitre_ids": []}, None),
    "none": ({"mitre_ids": None}, None),
    "missing": ({}, None),
}  # fmt: skip


def _mitre_lines(text):
    return [ln for ln in text.split("\n") if ln.lstrip().startswith("MITRE:")]


def _shown(name, case, monkeypatch, capsys, fields):  # noqa: F811
    if name != "report-saved":
        return _view(name, case, monkeypatch, capsys, **fields)
    save_timeline(case, [])
    save_findings(case, [_finding(status="APPROVED", **fields)])
    sign_approved(case)
    argv = ["report", "--findings", "F-tester-001", "--save", "f.txt"]
    _cli(monkeypatch, capsys, argv)
    return (case / "reports" / "f.txt").read_text()


# `vhir approve --review` shows a finding's mitre_ids field only
CASES = [
    (name, shape)
    for name in MITRE_VIEWS
    for shape in MITRE_SHAPES
    if (name, shape) != ("approve-review", "an-ioc-s-field")
]


@pytest.mark.parametrize("name, shape", CASES)
def test_mitre_ids_print_as_text_in_every_view(name, shape, case, monkeypatch, capsys):  # noqa: F811
    fields, text = MITRE_SHAPES[shape]
    lines = _mitre_lines(_shown(name, case, monkeypatch, capsys, fields))
    if text is None:
        assert lines == []
        return
    (line,) = lines
    assert line.split("MITRE:", 1)[1].strip() == text, line


@pytest.mark.parametrize("name", ["review-detail", "report"])
def test_a_control_in_an_id_stays_inert_on_screen(name, case, monkeypatch, capsys):  # noqa: F811
    fields = {"mitre_ids": ["T1135\x1b[2J", "T10\t21"]}
    (line,) = _mitre_lines(_shown(name, case, monkeypatch, capsys, fields))
    assert line.split("MITRE:", 1)[1].strip() == "T1135?[2J, T10  21", line


def test_the_saved_report_keeps_the_stored_ids(case, monkeypatch, capsys):  # noqa: F811
    """The saved file holds the stored text, as every other saved field does."""
    fields = {"mitre_ids": ["T1135\x1b[2J", "T1021"]}
    (line,) = _mitre_lines(_shown("report-saved", case, monkeypatch, capsys, fields))
    assert line.split("MITRE:", 1)[1].strip() == "T1135\x1b[2J, T1021", repr(line)


@pytest.mark.parametrize(
    "value, text",
    [
        (["T1021.002", "T1135"], "T1021.002, T1135"),
        (("T1021.002", "T1135"), "T1021.002, T1135"),
        ([], ""),
        ("T1135", "T1135"),
        ([{"id": "T1135"}], "{'id': 'T1135'}"),
        ([None, "T1135"], "None, T1135"),
        (1135, "1135"),
        (None, "None"),
        (["T1135\x1b[2J"], "T1135\x1b[2J"),
    ],
)
def test_list_text_shapes(value, text):
    assert display.list_text(value) == text
