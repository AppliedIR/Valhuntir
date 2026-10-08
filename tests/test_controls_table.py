"""One table says what each client's controls protect and what they don't:
the docs table is its rendering, every client's block names run_command as
the one path outside the sandbox, MCP-only clients get only the server-side
rows, and the block reports the deployed state (a sandbox the user turned
off, Codex's requirements moved away)."""

from __future__ import annotations

import json
from pathlib import Path

from vhir_cli import controls
from vhir_cli.commands import client_setup as cs

DOCS = Path(__file__).resolve().parents[1] / "docs" / "security.md"


def test_the_docs_table_is_the_code_table():
    text = DOCS.read_text()
    start = text.index("<!-- controls-table:begin")
    start = text.index("\n", start) + 1
    assert (
        text[start : text.index("<!-- controls-table:end -->")] == controls.markdown()
    )


def test_every_client_hears_that_run_command_is_outside_the_sandbox():
    for client in ("claude-code", "codex", "librechat"):
        text = "\n".join(controls.block_lines(client))
        assert (
            "run_command: nothing: it's the one tool that runs outside every client sandbox"
            in text
        )
        assert "the gateway's audit of the call is the only trace" in text


def test_mcp_only_clients_get_the_server_side_rows_only():
    text = "\n".join(controls.block_lines("open-webui"))
    assert "Sandbox:" not in text and "Audit:" not in text
    assert "can't be checked" in text


def test_a_sandbox_the_user_kept_off_reads_sandbox_off(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text(json.dumps({"sandbox": {"enabled": False}}))
    assert cs._sandbox_off(s)
    s.write_text(json.dumps({"sandbox": {"enabled": True, "failIfUnavailable": True}}))
    assert not cs._sandbox_off(s)
    text = "\n".join(controls.block_lines("claude-code", sandbox_off=True))
    assert "Sandbox: SANDBOX OFF" in text


def test_codex_requirements_moved_away_read_codex_controls_off():
    text = "\n".join(controls.block_lines("codex", codex_state="off"))
    assert "Managed requirements: CODEX CONTROLS OFF" in text
    on = "\n".join(controls.block_lines("codex"))
    assert "~/.codex and ~/.agents are read-only to it" in on


def test_the_codex_guard_row_claims_no_relative_path_rule_and_names_apply_patch():
    (guard,) = [r for r in controls.ROWS if r[0] == "Case-data guard"]
    assert "relative path is refused" not in guard[2] + guard[3]
    assert "apply_patch edits aren't checked" in guard[3]
    assert "another folder isn't checked correctly" in guard[3]


def test_the_audit_row_lists_a_deny_rules_refusal_as_not_recorded():
    (audit,) = [r for r in controls.ROWS if r[0] == "Audit"]
    assert "a deny rule's refusal" in audit[3] and "refused ones" not in audit[2]
