# ruff: noqa: F811 - `case` is the fixture imported below
"""A 0-byte or blank findings file reads as an empty list when signing and
verifying.

The commit goes ahead on it; verify names an approved finding the file no
longer holds, through the chain, and passes a case that lost nothing.
"""

from __future__ import annotations

import pytest

from vhir_cli.commands import approve as A
from vhir_cli.ledger_verify import verify_case

from .test_signed_decisions import IDENT, _run, _signed, case  # noqa: F401


@pytest.fixture(autouse=True)
def _own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.mark.parametrize("blank", ["", "  \n"], ids=["empty", "blank"])
def test_a_blank_findings_file_signs_and_verify_names_the_lost_approval(case, blank):
    A._approve_specific(case, ["F-steve-002"], IDENT, case / "cfg")
    (case / "findings.json").chmod(0o644)
    (case / "findings.json").write_text(blank)
    assert (
        _run(lambda: A._approve_specific(case, ["T-steve-001"], IDENT, case / "cfg"))
        == 0
    )
    assert _signed() == [("F-steve-002", "approve"), ("T-steve-001", "approve")]
    result = verify_case(case)
    assert {v.item_id: v.status for v in result.items} == {"T-steve-001": "VALID"}
    assert [(code, "names F-steve-002" in text) for code, text in result.failures] == [
        ("ITEM_MISSING", True)
    ]
    assert result.exit_code != 0


@pytest.mark.parametrize("blank", ["", "  \n"], ids=["empty", "blank"])
def test_a_blank_findings_file_that_lost_no_approval_verifies(case, blank):
    (case / "findings.json").write_text(blank)
    assert (
        _run(lambda: A._approve_specific(case, ["T-steve-001"], IDENT, case / "cfg"))
        == 0
    )
    result = verify_case(case)
    assert result.failures == [] and result.exit_code == 0
