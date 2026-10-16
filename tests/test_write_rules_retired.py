"""Claude Code's Edit rules already cover the tools that write files, so the
Write( deny rules only added lines to its start-up output: none is shipped,
a re-deploy takes the ones vhir wrote off, and the user's own rules stay."""

from __future__ import annotations

import json
from pathlib import Path

from vhir_cli.commands import client_setup as cs

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_BEFORE = {
    "Write(**/findings.json)", "Write(**/timeline.json)", "Write(**/approvals.jsonl)",
    "Write(**/todos.json)", "Write(**/CASE.yaml)", "Write(**/actions.jsonl)",
    "Write(**/audit/*.jsonl)", "Write(**/evidence.json)", "Write(**/iocs.json)",
    "Write(/var/lib/vhir/**)", "Write(**/.claude/settings.json)",
    "Write(**/.claude/CLAUDE.md)", "Write(**/.claude/rules/**)",
    "Write(**/.vhir/hooks/**)", "Write(**/.vhir/active_case)",
    "Write(**/.vhir/gateway.yaml)", "Write(**/.vhir/config.yaml)",
    "Write(**/.vhir/.password_lockout)", "Write(**/pending-reviews.json)",
}  # fmt: skip


def test_no_write_rule_is_shipped_and_every_old_one_is_retired():
    assert not [r for r in cs._FORENSIC_DENY_RULES if r.startswith("Write(")]
    assert SHIPPED_BEFORE <= cs._OLD_FORENSIC_DENY_RULES


def test_a_redeploy_takes_off_the_write_rules_and_keeps_the_users(tmp_path):
    mine = ["Write(**/my-notes.md)", "Edit(**/secret.txt)"]
    target, source = tmp_path / "settings.json", tmp_path / "template.json"
    target.write_text(
        json.dumps({"permissions": {"deny": sorted(SHIPPED_BEFORE) + mine}})
    )
    source.write_text(
        json.dumps({"permissions": {"deny": sorted(cs._FORENSIC_DENY_RULES)}})
    )
    deny = cs._merged_settings(target, source, None)["permissions"]["deny"]
    assert not set(deny) & SHIPPED_BEFORE
    assert set(mine) <= set(deny) and set(deny) >= cs._FORENSIC_DENY_RULES


def test_the_remote_scripts_ship_no_write_rule():
    for name in (
        "setup-client-linux.sh",
        "setup-client-macos.sh",
        "setup-client-windows.ps1",
    ):
        assert '"Write(' not in (ROOT / name).read_text(encoding="utf-8"), name
