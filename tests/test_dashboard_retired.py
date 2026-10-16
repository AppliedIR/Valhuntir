"""`vhir dashboard` says the legacy dashboard is retired and opens the Portal."""

from __future__ import annotations

from argparse import Namespace

import yaml

from vhir_cli.commands import dashboard


def _gateway(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".vhir").mkdir(parents=True)
    (home / ".vhir" / "gateway.yaml").write_text(
        yaml.safe_dump({"gateway": {"host": "127.0.0.1", "port": 4508}})
    )
    monkeypatch.setenv("HOME", str(home))
    opened: list[str] = []
    monkeypatch.setattr(dashboard.webbrowser, "open", opened.append)
    return opened


def test_dashboard_says_it_is_retired_and_opens_the_portal(
    tmp_path, monkeypatch, capsys
):
    opened = _gateway(tmp_path, monkeypatch)
    dashboard.cmd_dashboard(Namespace(), {"examiner": "alice"})
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "The legacy dashboard is retired; use `vhir portal`."
    assert opened == ["http://127.0.0.1:4508/portal/"]


def test_portal_is_unchanged(tmp_path, monkeypatch, capsys):
    opened = _gateway(tmp_path, monkeypatch)
    dashboard.cmd_portal(Namespace(), {"examiner": "alice"})
    assert capsys.readouterr().out == "Examiner Portal: http://127.0.0.1:4508/portal/\n"
    assert opened == ["http://127.0.0.1:4508/portal/"]


def test_the_help_says_dashboard_is_retired():
    from vhir_cli.main import build_parser

    assert "Retired: opens the Examiner Portal" in build_parser().format_help()
