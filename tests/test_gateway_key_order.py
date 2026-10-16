"""Rebinding the gateway for remote access keeps gateway.yaml's key order.

setup-sift writes the owner's key first under api_keys, and local readers
take the first key as the local examiner's token. yaml.dump sorts keys by
default, so a rewrite could put a joined machine's key first and local tools
would act as that examiner.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import yaml

from vhir_cli.commands import join

OWNER = "vhir_gw_" + "f" * 24  # sorts after the joined key
JOINED = "vhir_gw_" + "0" * 24


def test_rebinding_keeps_the_owners_key_first(tmp_path):
    gw = tmp_path / ".vhir" / "gateway.yaml"
    gw.parent.mkdir()
    config = {
        "gateway": {"host": "127.0.0.1", "port": 4508},
        "api_keys": {
            OWNER: {"examiner": "steve", "role": "lead"},
            JOINED: {"examiner": "laptop"},
        },
        "backends": {"forensic-mcp": {"type": "stdio"}},
    }
    gw.write_text(yaml.dump(config, default_flow_style=False, sort_keys=False))
    restart = MagicMock(returncode=1, stderr="stubbed")  # stop right after the write
    with (
        patch("pathlib.Path.home", return_value=tmp_path),
        patch("builtins.input", return_value="y"),
        patch("subprocess.run", return_value=restart),
    ):
        join._ensure_remote_binding()
    written = yaml.safe_load(gw.read_text())
    assert written["gateway"]["host"] == "0.0.0.0"
    assert list(written["api_keys"]) == [OWNER, JOINED]
    assert list(written) == ["gateway", "api_keys", "backends"]
