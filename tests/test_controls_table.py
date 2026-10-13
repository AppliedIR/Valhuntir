"""One table says what each client's controls protect and what they don't:
the docs table is its rendering, every client's block names run_command as
the one path outside the sandbox, MCP-only clients get only the server-side
rows, and the block reports the deployed state (a sandbox the user turned
off, Codex's requirements moved away)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


CLIENT_ROWS = ("Deny rules", "Sandbox", "Managed requirements", "Audit",
               "Case-data guard", "Start-up check")  # fmt: skip


def test_a_sandbox_kept_off_by_choice_reads_sandbox_off():
    text = "\n".join(controls.block_lines("claude-code", sandbox_off=True))
    assert "Sandbox: SANDBOX OFF" in text


@pytest.mark.parametrize("client", ["claude-code", "codex"])
def test_controls_not_applied_claim_no_row_of_the_client(client):
    text = "\n".join(controls.block_lines(client, not_applied="declined"))
    assert not [r for r in CLIENT_ROWS if f"    {r}:" in text], text
    assert "run_command:" in text and "Signed approvals:" in text  # the gateway's
    assert text.endswith("    NOT in effect: declined.")
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


@pytest.mark.parametrize("client", ["librechat", "other"])
def test_setup_prints_the_mcp_only_block(client, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cs._generate_config(client, {}, "steve")
    out = capsys.readouterr().out
    assert "Controls (as deployed now):" in out and "run_command:" in out
    assert "MCP-only: the server-side controls only" in out


def test_setup_shows_a_declined_change_as_the_file_holds_it(
    tmp_path, monkeypatch, capsys
):
    mine = tmp_path / "settings.json"
    mine.write_text(
        json.dumps({"permissions": {"deny": []}})
    )  # the user kept their own
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cs, "_is_sift", lambda: False)
    monkeypatch.setattr(
        cs, "_deploy_claude_code_assets", lambda *a, **k: (mine, "kept")
    )
    cs._generate_config("claude-code", {}, "steve")
    out = capsys.readouterr().out
    assert f"Forensic controls NOT applied to {mine}" in out
    assert "NOT in effect: this machine has no case" in out  # off the SIFT box
    assert not [r for r in CLIENT_ROWS if f"    {r}:" in out]
