"""Every MCP server name vhir writes into a client config has an allow rule in
each remote-client installer's Claude Code settings, and in the set
uninstall strips, so a fresh client never lacks one of its own backends and
uninstall leaves none behind."""

import re
from pathlib import Path

import pytest

from vhir_cli.commands import client_setup

ROOT = Path(__file__).parent.parent

# The allow block of the settings each installer writes: a JSON array in the
# shell installers, a PowerShell @( ) array in the Windows one
_BLOCKS = {
    "setup-client-linux.sh": re.compile(r'"allow": \[(.*?)\]', re.S),
    "setup-client-macos.sh": re.compile(r'"allow": \[(.*?)\]', re.S),
    "setup-client-windows.ps1": re.compile(r"allow = @\((.*?)\)", re.S),
}


def _missing(rules):
    return sorted(
        n for n in client_setup._VHIR_BACKEND_NAMES if f"mcp__{n}__*" not in rules
    )


@pytest.mark.parametrize("installer", sorted(_BLOCKS))
def test_each_installer_allows_every_backend(installer):
    block = _BLOCKS[installer].search((ROOT / installer).read_text())
    assert block, f"{installer}: no allow block found"
    rules = set(re.findall(r'"(mcp__[^"]+)"', block.group(1)))
    assert len(rules) >= 13, rules
    assert not _missing(rules), f"{installer}: no allow rule for {_missing(rules)}"


def test_uninstall_strips_every_backend_rule():
    assert not _missing(client_setup._FORENSIC_ALLOW_RULES)
