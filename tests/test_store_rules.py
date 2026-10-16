"""The store's deny rules are written as absolute paths ("//"), the old
single-slash rules (which matched nothing) are taken off on a re-deploy, and
every list in the user's sandbox settings is merged as a union, so their own
entries stay. Paths are synthetic."""

from __future__ import annotations

import json
from pathlib import Path

from vhir_cli.commands import client_setup as cs

ROOT = Path(__file__).resolve().parents[1]
STORE_RULES = ("Read(//var/lib/vhir/**)", "Edit(//var/lib/vhir/**)")
SINGLE_SLASH = ("Read(/var/lib/vhir/**)", "Edit(/var/lib/vhir/**)")


def _merge(tmp_path, existing: dict, incoming: dict) -> dict:
    target, source = tmp_path / "settings.json", tmp_path / "template.json"
    target.write_text(json.dumps(existing))
    source.write_text(json.dumps(incoming))
    return cs._merged_settings(target, source, None)


def test_the_store_rules_are_absolute_paths():
    assert set(STORE_RULES) <= cs._FORENSIC_DENY_RULES
    assert not set(SINGLE_SLASH) & cs._FORENSIC_DENY_RULES
    assert set(SINGLE_SLASH) <= cs._OLD_FORENSIC_DENY_RULES


def test_a_redeploy_takes_off_the_single_slash_rules_and_keeps_the_users(tmp_path):
    mine = "Read(//home/x/secret/**)"
    merged = _merge(
        tmp_path,
        {"permissions": {"deny": [*SINGLE_SLASH, mine]}},
        {"permissions": {"deny": list(STORE_RULES)}},
    )
    deny = merged["permissions"]["deny"]
    assert mine in deny and set(STORE_RULES) <= set(deny)
    assert not set(SINGLE_SLASH) & set(deny)


def test_every_sandbox_list_is_a_union_with_the_users(tmp_path):
    merged = _merge(
        tmp_path,
        {"sandbox": {"enabled": True, "excludedCommands": ["mine"],
                     "filesystem": {"denyRead": ["/home/x/secret"],
                                    "denyWrite": ["/home/x/keep"]}}},
        {"sandbox": {"enabled": True, "excludedCommands": ["docker"],
                     "filesystem": {"denyRead": ["/var/lib/vhir"],
                                    "denyWrite": ["~/.vhir/gateway.yaml"]}}},
    )  # fmt: skip
    fs = merged["sandbox"]["filesystem"]
    assert fs["denyRead"] == ["/home/x/secret", "/var/lib/vhir"]
    assert fs["denyWrite"] == ["/home/x/keep", "~/.vhir/gateway.yaml"]
    assert merged["sandbox"]["excludedCommands"] == ["mine", "docker"]


def test_the_remote_scripts_write_the_store_rules_as_absolute_paths():
    for name in (
        "setup-client-linux.sh",
        "setup-client-macos.sh",
        "setup-client-windows.ps1",
    ):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert all(f'"{r}"' in text for r in STORE_RULES), name
        assert not any(f'"{r}"' in text for r in SINGLE_SLASH), name
