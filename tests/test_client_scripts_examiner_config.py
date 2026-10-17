"""The client scripts write the examiner name to ~/.vhir/config.yaml as a string.

The name was written unquoted, so a YAML word, a number or a date (`no`,
`true`, `0x10`, `2026-10-16`) loaded as a bool, an int or a date, and a name
of `-` made the whole file unparseable, gateway_token included. These run each
script's own config.yaml block in a scratch HOME and load the file back.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).parent.parent
SCRIPTS = ["setup-client-linux.sh", "setup-client-macos.sh"]
TOKEN = "vhir_gw_000000000000000000000000"
STUBS = 'header(){ :; }\nok(){ :; }\ninfo(){ :; }\nprompt(){ echo "$2"; }\n'


def _config_block(script: str) -> str:
    text = (REPO / script).read_text()
    i = text.index("# Store token")
    return text[i : text.index("# Write VHIR_EXAMINER to shell profile", i)]


def _write(home: Path, script: str, name: str) -> Path:
    r = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + STUBS + _config_block(script)],
        env={
            "HOME": str(home),
            "PATH": "/usr/bin:/bin",
            "EXAMINER_NAME": name,
            "GATEWAY_URL": "https://10.0.0.5:4508",
            "GATEWAY_TOKEN": TOKEN,
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    return home / ".vhir" / "config.yaml"


@pytest.mark.parametrize("script", SCRIPTS)
@pytest.mark.parametrize("name", ["no", "true", "-", "0x10", "2026-10-16", "alice"])
def test_the_name_loads_back_as_the_same_string(tmp_path, script, name):
    doc = yaml.safe_load(_write(tmp_path, script, name).read_text())
    assert doc["examiner"] == name and type(doc["examiner"]) is str
    assert doc["gateway_token"] == TOKEN
    assert doc["gateway_url"] == "https://10.0.0.5:4508"
