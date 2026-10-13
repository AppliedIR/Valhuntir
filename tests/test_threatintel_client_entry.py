"""One threat-intel client entry on every install: when setup writes
`threatintel-mcp`, an existing Valhuntir `opencti-mcp` entry for the same
gateway is removed (backed up and announced, as other duplicate entries
are). One for another gateway, or the user's own entries, are kept."""

from __future__ import annotations

import json

import pytest

from vhir_cli.commands import client_setup as cs

GW = "http://sift.local:4508"


def _servers():
    return {
        "threatintel-mcp": {
            "type": "streamable-http",
            "url": f"{GW}/mcp/threatintel-mcp",
        },
        "forensic-mcp": {"type": "streamable-http", "url": f"{GW}/mcp/forensic-mcp"},
    }


@pytest.fixture
def box(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(project)
    monkeypatch.setattr(cs, "_deploy_claude_code_assets", lambda *a, **k: None)
    monkeypatch.setattr(cs, "_claude_mcp_add_available", lambda: False)
    return home, project


def _existing(path, **extra):
    entries = {"opencti-mcp": {"type": "http", "url": f"{GW}/mcp/opencti-mcp"},
               "my-own": {"type": "http", "url": "http://elsewhere/mcp"}, **extra}  # fmt: skip
    path.write_text(json.dumps({"mcpServers": entries}))


@pytest.mark.parametrize("where", ["sift", "remote"])
def test_the_earlier_entry_is_replaced_by_the_one_name_backed_up_and_announced(
    box, monkeypatch, capsys, where
):
    home, project = box
    monkeypatch.setattr(cs, "_is_sift", lambda: where == "sift")
    path = home / ".claude.json" if where == "sift" else project / ".mcp.json"
    _existing(path)
    cs._generate_config("claude-code", _servers(), "steve")
    servers = json.loads(path.read_text())["mcpServers"]
    assert sorted(servers) == ["forensic-mcp", "my-own", "threatintel-mcp"]
    (backup,) = path.parent.glob(f"{path.name}.vhir-backup-*")
    assert "opencti-mcp" in json.loads(backup.read_text())["mcpServers"]
    assert "removed (duplicates): opencti-mcp" in capsys.readouterr().out


def test_an_earlier_entry_for_another_gateway_is_kept(box, monkeypatch):
    home, _ = box
    monkeypatch.setattr(cs, "_is_sift", lambda: True)
    path = home / ".claude.json"
    _existing(path)
    data = json.loads(path.read_text())
    data["mcpServers"]["opencti-mcp"]["url"] = "http://other-sift:4508/mcp/opencti-mcp"
    path.write_text(json.dumps(data))
    cs._generate_config("claude-code", _servers(), "steve")
    assert "opencti-mcp" in json.loads(path.read_text())["mcpServers"]


def test_the_entries_being_written_are_never_counted_as_duplicates(box):
    home, _ = box
    path = home / ".claude.json"
    _existing(
        path, **{"forensic-mcp": {"type": "http", "url": f"{GW}/mcp/forensic-mcp"}}
    )
    assert cs._duplicate_backends(_servers(), path) == ["opencti-mcp"]


@pytest.mark.parametrize(
    "url",
    [
        "http://sift.local:45080/mcp/opencti-mcp",  # another port starting the same
        "https://sift.local:4508/mcp/opencti-mcp",  # another scheme
        "http://sift.local.example:4508/mcp/opencti-mcp",  # another host
        "http://sift.local:4508/other/opencti-mcp",  # not a gateway route
    ],
)
@pytest.mark.parametrize("vhir", [True, False])  # the gateway read from either entry
def test_only_an_entry_for_this_very_gateway_is_ever_removed(box, url, vhir):
    home, _ = box
    path = home / ".claude.json"
    _existing(path)
    data = json.loads(path.read_text())
    data["mcpServers"]["opencti-mcp"]["url"] = url
    data["mcpServers"]["case-mcp"] = {
        "type": "http",
        "url": url.replace("opencti", "case"),
    }
    path.write_text(json.dumps(data))
    servers = {**({"vhir": {"type": "http", "url": f"{GW}/mcp"}} if vhir else {}),
               **_servers()}  # fmt: skip
    assert cs._duplicate_backends(servers, path) == []
    # the same entries for this gateway are removed (the control)
    for name in ("opencti-mcp", "case-mcp"):
        data["mcpServers"][name]["url"] = f"{GW}/mcp/{name}"
    path.write_text(json.dumps(data))
    removed = ["opencti-mcp", "case-mcp"] if vhir else ["opencti-mcp"]
    assert cs._duplicate_backends(servers, path) == removed
