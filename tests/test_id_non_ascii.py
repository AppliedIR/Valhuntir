# ruff: noqa: F401, F811 - `case` is the fixture imported below
"""A bundle id with a space, a control character or a character outside ASCII
is refused: it can sit beside a real id that it looks like (a leading space,
a zero-width space, a Cyrillic letter). Every id a writer makes still merges."""

from __future__ import annotations

import argparse
import json

import pytest

from vhir_cli.case_io import import_bundle
from vhir_cli.commands.sync import cmd_merge

from .test_id_kind_prefix import END, case, f, files, ids, t

FAULT = "has an id with a space, a control character or a character outside ASCII"


@pytest.mark.parametrize(
    "bad", [" T-alice-001", "F-alice-001\x07", "Т-alice-001", "​T-alice-001"],
    ids=["leading-space", "control", "cyrillic-te", "zero-width-space"],
)  # fmt: skip
@pytest.mark.parametrize("section", ["findings", "timeline"])
def test_an_id_outside_printable_ascii_is_refused(case, bad, section):
    item = f(bad) if section == "findings" else t("T-" + bad)
    before = files(case)
    assert import_bundle(case, {section: [item]}) == {
        "status": "error", "message": f"The bundle's {section} item 0 {FAULT}{END}"}  # fmt: skip
    assert files(case) == before


@pytest.mark.parametrize("good", ["F-bob-001", "F-bob_x.1:2"])
def test_printable_ascii_ids_merge(case, good):
    assert import_bundle(case, {"findings": [f(good)]})["status"] != "error"
    assert ids(case, "findings.json") == ["F-alice-001", good]


def test_vhir_merge_names_the_fault(case, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"findings": [f("Т-alice-001")]}))
    before = files(case)
    with pytest.raises(SystemExit) as exited:
        cmd_merge(argparse.Namespace(file=str(path), case=None), {"examiner": "alice"})
    out, err = capsys.readouterr()
    assert exited.value.code == 1 and out == ""
    assert err == f"Merge failed: The bundle's findings item 0 {FAULT}{END}\n"
    assert files(case) == before
