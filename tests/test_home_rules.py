"""vhir's client settings deny the Edit tool on the deployed skills and
agents and on the Codex folders, anchor every settings and vhir rule at the
home folder too ("**/" matches inside the session's folder only), and keep
the AI's tools off host identity's records and the case paths map."""

from __future__ import annotations

from vhir_cli.commands import client_setup as cs

HOME = {
    "Edit(~/.claude/skills/**)",
    "Edit(~/.claude/agents/**)",
    "Edit(~/.agents/**)",
    "Edit(~/.codex/**)",
}
HOST = {
    "Edit(**/host-observations.jsonl)",
    "Edit(**/host-decisions.jsonl)",
    "Edit(**/host-ops.json)",
    "Edit(**/host-dictionary.yaml)",
    "Edit(**/.vhir/case-paths.json)",
    "Edit(~/.vhir/case-paths.json)",
}


def test_the_home_folders_and_host_records_are_denied():
    assert HOME | HOST <= cs._FORENSIC_DENY_RULES


def test_every_settings_and_vhir_rule_has_its_home_twin():
    folder = [
        r
        for r in cs._FORENSIC_DENY_RULES
        if r.startswith(("Edit(**/.claude/", "Edit(**/.vhir/"))
    ]
    assert folder and all(
        r.replace("Edit(**/.", "Edit(~/.") in cs._FORENSIC_DENY_RULES for r in folder
    )
