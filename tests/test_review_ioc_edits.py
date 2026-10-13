"""`vhir approve --review` edits an IOC's tags and description only.

An IOC's value and type are what the examiner decides; the portal refuses
any other edit, and so does the CLI's review: such an entry is skipped,
unsigned, with the fields named.
"""

from __future__ import annotations

import json
from pathlib import Path

import vhir_cli.commands.approve as approve_mod
from vhir_cli import ledger
from vhir_cli.case_io import compute_content_hash, load_iocs

from .test_finding_challenge_cli import IDENT, case  # noqa: F401

IOC = {"id": "IOC-tester-001", "value": "203.0.113.7", "type": "ipv4-addr",
       "status": "DRAFT", "tags": [], "description": ""}  # fmt: skip


def _review(case, mods, monkeypatch):  # noqa: F811
    (case / "findings.json").write_text("[]")
    (case / "timeline.json").write_text("[]")
    (case / "iocs.json").write_text(json.dumps([IOC]))
    entry = {"id": IOC["id"], "type": "ioc", "action": "approve", "modifications": mods,
             "content_hash_at_review": compute_content_hash(IOC)}  # fmt: skip
    (case / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-1", "items": [entry]})
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    approve_mod._review_mode(case, IDENT, Path("cfg"))


def test_an_ioc_s_value_edit_is_skipped_unsigned(case, monkeypatch, capsys):  # noqa: F811
    _review(case, {"value": {"original": "203.0.113.7", "modified": "198.51.100.1"}},
            monkeypatch)  # fmt: skip
    assert "an IOC's value can't be edited" in capsys.readouterr().out
    (ioc,) = load_iocs(case)
    assert ioc["value"] == "203.0.113.7" and ioc["status"] == "DRAFT"
    assert not ledger.chain_path("C-1").exists()


def test_an_ioc_s_tags_are_edited_and_signed(case, monkeypatch, capsys):  # noqa: F811
    _review(case, {"tags": {"original": [], "modified": ["c2"]}}, monkeypatch)
    (ioc,) = load_iocs(case)
    assert ioc["tags"] == ["c2"] and ioc["status"] == "APPROVED"
    (line,) = [json.loads(x) for x in ledger.chain_path("C-1").read_text().splitlines()]
    assert json.loads(line["content_snapshot"])["tags"] == ["c2"]
