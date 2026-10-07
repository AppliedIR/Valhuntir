"""The threat-intel backend has two names: threatintel-mcp, and opencti-mcp in
configurations from before. Client setup allows both, and uninstall and the
duplicate check recognize both, so neither name is left behind or doubled.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vhir_cli.commands.client_setup import (
    _duplicate_backends,
    _remove_forensic_settings,
    _remove_vhir_mcp_entries,
)

REPO = Path(__file__).parent.parent
NAMES = ("opencti-mcp", "threatintel-mcp")
PATTERNS = [f"mcp__{name}__*" for name in NAMES]


@pytest.mark.parametrize(
    "script",
    ["setup-client-linux.sh", "setup-client-macos.sh", "setup-client-windows.ps1"],
)
def test_each_client_script_allows_both_names(script):
    allowed = re.findall(r'"(mcp__[\w-]+__\*)"', (REPO / script).read_text())
    assert all(p in allowed for p in PATTERNS), allowed


def test_uninstall_removes_both_entries_and_keeps_the_users_own(tmp_path):
    path = tmp_path / ".claude.json"
    servers = {name: {"type": "http", "url": f"http://gw/mcp/{name}"} for name in NAMES}
    path.write_text(json.dumps({"mcpServers": {**servers, "mine": {"command": "x"}}}))
    _remove_vhir_mcp_entries(path)
    assert json.loads(path.read_text())["mcpServers"] == {"mine": {"command": "x"}}


def test_uninstall_removes_both_permission_patterns_and_keeps_the_users_own(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"permissions": {"allow": [*PATTERNS, "mcp__zz-mine__*"]}})
    )
    _remove_forensic_settings(path)
    assert json.loads(path.read_text())["permissions"]["allow"] == ["mcp__zz-mine__*"]


def test_either_name_routed_through_the_gateway_is_a_duplicate(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    **{
                        name: {"type": "http", "url": f"http://gw:4508/mcp/{name}"}
                        for name in NAMES
                    },
                    "elsewhere": {"type": "http", "url": "http://other/mcp/x"},
                }
            }
        )
    )
    gateway = {"vhir": {"url": "http://gw:4508/mcp"}}
    assert sorted(_duplicate_backends(gateway)) == sorted(NAMES)
