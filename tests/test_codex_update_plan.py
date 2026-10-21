# ruff: noqa: F401, F811 - `box` is the fixture imported below
"""Valhuntir's Codex profile turns on Codex's checklist tool.

Codex 0.163 offers its update_plan tool only with
`tools.update_plan.enabled = true`; `tools.update_plan = true` stops it
starting. vhir writes the key as a root key in the head, before
developer_instructions, so it is part of what vhir owns and not one of the
tables a client adds after the instructions. A profile vhir wrote before the
key gets it on the next update. Everything here is under tmp_path; no gateway
is reached.
"""

from __future__ import annotations

import json

import pytest

from vhir_cli.commands import client_setup as cs

from .test_codex_profile_keeps import (
    CODEX_TUI,
    _recorded,
    _setup,
    _sha,
    _toml,
    box,
)

KEY = "tools.update_plan.enabled = true\n"


def _old_head(text: str) -> str:
    """The profile as vhir wrote it before the key."""
    assert text.count(KEY) == 1
    return text.replace(KEY, "")


def _record(box, text: str) -> None:
    m = json.loads(box.manifest.read_text())
    m["codex_profile_sha256"] = _sha(text.encode())
    box.manifest.write_text(json.dumps(m))


def test_the_key_is_a_root_key_before_the_instructions(box):
    _setup()
    text = box.profile.read_text()
    lines = text.splitlines(keepends=True)
    assert lines.count(KEY) == 1
    first = next(i for i, ln in enumerate(lines) if ln.startswith("developer_"))
    assert lines.index(KEY) < first
    assert not [ln for ln in lines[: lines.index(KEY)] if ln.startswith("[")]
    assert "tools.update_plan = true" not in text


def test_the_profile_parses_to_update_plan_enabled(box):
    pytest.importorskip("tomllib")
    _setup()
    p = _toml(box.profile.read_text())
    assert p["tools"] == {"update_plan": {"enabled": True}}
    assert p["sandbox_mode"] == "workspace-write"
    assert "tools" not in p["mcp_servers"]


def test_the_key_is_in_the_owned_part_and_the_split_is_as_before(box):
    _setup()
    written = box.profile.read_text()
    text = written + CODEX_TUI
    head, _ = cs._after_instructions(text)
    assert KEY in head
    owned, kept = cs._client_tables(text)
    assert owned == written and KEY in owned
    assert kept == [CODEX_TUI.lstrip("\n")]
    assert cs._profile_sections(text) == cs._profile_sections(_old_head(text))
    assert cs._client_tables(_old_head(text)) == (_old_head(written), kept)
    assert _recorded(box) == _sha(written.encode())


@pytest.mark.parametrize("tui", ["", CODEX_TUI], ids=["alone", "codex-tui"])
def test_an_unedited_old_head_profile_gets_the_key_on_update(box, capsys, tui):
    _setup()
    new = box.profile.read_text()
    old = _old_head(new)
    box.profile.write_text(old + tui)
    _record(box, old)
    capsys.readouterr()
    assert cs.deploy_codex_assets() == "updated"
    assert "vhir would change" not in capsys.readouterr().out
    text = box.profile.read_text()
    assert text == new + tui
    assert _recorded(box) == _sha(new.encode())
    assert cs.deploy_codex_assets() == "unchanged"  # and stays settled
    p = _toml(text)
    if p is not None:
        assert p["tools"]["update_plan"]["enabled"] is True


def test_an_edited_old_head_profile_is_asked_about_not_changed(box, monkeypatch):
    _setup()
    old = _old_head(box.profile.read_text())
    _record(box, old)
    edited = old.replace('"on-request"', '"never"')
    box.profile.write_text(edited)
    asked = []

    def answer(prompt=""):
        asked.append(prompt)
        return "n"

    monkeypatch.setattr("builtins.input", answer)
    cs.deploy_codex_assets()
    assert asked
    assert box.profile.read_text() == edited
