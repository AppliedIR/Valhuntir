"""Valhuntir's own `python -m` / `-c` launches run isolated (-I).

Without -I, Python puts the current directory first on sys.path, so a
`json.py` or `re.py` in the directory a launch starts from (a case directory
holding extracted evidence, say) runs as the user. The opensearch-mcp stdio
entry that setup client writes, and update's PyTorch probe, both start
from the user's directory.
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from vhir_cli.commands import client_setup as cs
from vhir_cli.commands import update

REAL_FIND_SPEC = importlib.util.find_spec


def test_the_opensearch_entry_runs_isolated(tmp_path, monkeypatch):
    # setup client records the client in ~/.vhir/manifest.json: keep it here
    monkeypatch.setenv("HOME", str(tmp_path))
    assert Path.home() == tmp_path
    manifest = tmp_path / ".vhir" / "manifest.json"
    manifest.parent.mkdir()
    manifest.write_text('{"client": "codex"}')
    seen = {}
    monkeypatch.setattr(cs, "_discover_services", lambda url, token: [])
    monkeypatch.setattr(cs, "_read_local_token", lambda: None)
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: (
            object() if name == "opensearch_mcp" else REAL_FIND_SPEC(name, *a, **k)
        ),
    )
    monkeypatch.setattr(
        cs, "_generate_config", lambda client, servers, ex: seen.update(servers)
    )
    args = argparse.Namespace(
        client="claude-code",
        sift=None,
        windows=None,
        windows_token=None,
        remnux=None,
        remnux_token=None,
        examiner="steve",
        no_mslearn=True,
        no_zeltser=True,
        yes=True,
        uninstall=False,
    )
    cs._setup_client(args, {"examiner": "steve"})
    entry = seen["opensearch-mcp"]
    assert entry["command"] == sys.executable
    assert entry["args"] == ["-I", "-m", "opensearch_mcp"]
    assert json.loads(manifest.read_text())["client"] == "claude-code"  # here only


def test_the_pytorch_probe_never_imports_from_the_cwd(tmp_path, monkeypatch):
    canary = tmp_path / "CANARY"
    here = tmp_path / "case"
    here.mkdir()
    for name in ("re", "enum", "warnings", "types"):  # what the probe imports
        (here / f"{name}.py").write_text(
            f"open({str(canary)!r}, 'a').write({name!r})\n"
        )
    clean = update._torch_installed(sys.executable)
    monkeypatch.chdir(here)
    assert update._torch_installed(sys.executable) == clean
    assert not canary.exists(), canary.read_text()
