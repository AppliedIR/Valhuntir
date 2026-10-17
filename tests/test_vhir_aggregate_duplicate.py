"""One shape of Valhuntir entries per gateway: when setup writes the
per-backend entries, an earlier aggregate `vhir` entry for the same gateway
is removed (backed up and announced, as other duplicate entries are), so
Claude Code doesn't load every tool twice. One for another gateway, or the
user's own entries, are kept."""

from __future__ import annotations

import json
import types

import pytest

from vhir_cli.commands import client_setup as cs

GW = "http://127.0.0.1:4508"
SIX = [
    "forensic-mcp",
    "case-mcp",
    "sift-mcp",
    "report-mcp",
    "forensic-rag-mcp",
    "windows-triage-mcp",
]
VHIR = {"vhir": {"type": "http", "url": f"{GW}/mcp"}}
MINE = {"my-own": {"type": "http", "url": "http://elsewhere:9/mcp"}}


def _per_backend(type_="streamable-http"):
    return {n: {"type": type_, "url": f"{GW}/mcp/{n}"} for n in SIX}


@pytest.fixture
def box(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    monkeypatch.setattr(cs, "_deploy_claude_code_assets", lambda *a, **k: None)
    calls = []

    def fake_add(name, entry):  # what `claude mcp add -s user` stores
        calls.append(name)
        path = home / ".claude.json"
        data = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(data.get("mcpServers"), dict):  # as the real CLI does
            data["mcpServers"] = {}
        data["mcpServers"][name] = {
            k: entry[k] for k in ("type", "url", "headers") if k in entry
        }
        path.write_text(json.dumps(data))

    monkeypatch.setattr(cs, "_claude_mcp_add", fake_add)

    def setup(branch, servers):
        monkeypatch.setattr(cs, "_is_sift", lambda: branch != "project-mcp-json")
        monkeypatch.setattr(
            cs, "_claude_mcp_add_available", lambda: branch == "claude-cli"
        )
        cs._generate_config("claude-code", json.loads(json.dumps(servers)), "steve")

    def path(branch):
        return (
            project / ".mcp.json"
            if branch == "project-mcp-json"
            else home / ".claude.json"
        )

    return types.SimpleNamespace(setup=setup, path=path, calls=calls)


BRANCHES = ["claude-cli", "fallback", "project-mcp-json"]


def _backups(path):
    return sorted(path.parent.glob(path.name + ".vhir-backup-*"))


@pytest.mark.parametrize("branch", BRANCHES)
@pytest.mark.parametrize(
    "start",
    [
        {**VHIR, **MINE},  # the aggregate an install or update leaves
        {**VHIR, **_per_backend("http"), **MINE},  # and a later run's 6 beside it
    ],
    ids=["aggregate", "aggregate-and-per-backend"],
)
def test_the_aggregate_for_this_gateway_is_removed_backed_up_and_announced(
    box, capsys, branch, start
):
    path = box.path(branch)
    path.write_text(json.dumps({"mcpServers": start}))
    box.setup(branch, _per_backend())
    servers = json.loads(path.read_text())["mcpServers"]
    assert "vhir" not in servers
    assert set(SIX) | {"my-own"} <= set(servers)
    (backup,) = _backups(path)
    assert "vhir" in json.loads(backup.read_text())["mcpServers"]
    assert "removed (duplicates): vhir" in capsys.readouterr().out


@pytest.mark.parametrize("branch", BRANCHES)
def test_the_aggregate_still_removes_the_per_backend_entries(box, branch):
    path = box.path(branch)
    path.write_text(json.dumps({"mcpServers": {**_per_backend("http"), **MINE}}))
    box.setup(branch, VHIR)
    assert sorted(json.loads(path.read_text())["mcpServers"]) == ["my-own", "vhir"]


@pytest.mark.parametrize(
    "url,servers",
    [
        (
            "http://127.0.0.1:45080/mcp",
            _per_backend(),
        ),  # another port starting the same
        ("http://10.0.0.9:4508/mcp", _per_backend()),  # another host
        ("https://127.0.0.1:4508/mcp", _per_backend()),  # another scheme
        ("http://localhost:4508/mcp", _per_backend()),  # another spelling: kept
        (  # a new set routed through no gateway
            f"{GW}/mcp",
            {
                "wintools-mcp": {
                    "type": "streamable-http",
                    "url": "http://127.0.0.1:4624/mcp",
                }
            },
        ),
    ],
)
@pytest.mark.parametrize("branch", BRANCHES)
def test_an_aggregate_for_another_gateway_is_kept(box, branch, url, servers):
    path = box.path(branch)
    path.write_text(
        json.dumps({"mcpServers": {"vhir": {"type": "http", "url": url}, **MINE}})
    )
    box.setup(branch, servers)
    assert json.loads(path.read_text())["mcpServers"]["vhir"]["url"] == url


@pytest.mark.parametrize("branch", BRANCHES)
def test_a_rerun_with_the_per_backend_entries_written_changes_nothing(
    box, capsys, branch
):
    path = box.path(branch)
    path.write_text(json.dumps({"mcpServers": MINE}))
    box.setup(branch, _per_backend())
    for backup in _backups(path):
        backup.unlink()
    capsys.readouterr()
    box.calls.clear()
    before = json.loads(path.read_text())
    box.setup(branch, _per_backend())
    out = capsys.readouterr().out
    assert "removed (duplicates)" not in out and "entries added" not in out
    assert _backups(path) == [] and box.calls == []
    assert json.loads(path.read_text()) == before
