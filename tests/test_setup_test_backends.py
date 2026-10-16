"""`vhir setup test` says what it checked about each backend.

It printed "OK" for a backend whose process answered (it doesn't check the
service behind it), "FAIL (unknown error)" for one the gateway hasn't
started yet, and "N of M backends operational".
"""

from __future__ import annotations

import io
import json
import urllib.request

import vhir_cli.gateway as gateway
from vhir_cli.commands.setup import _run_connectivity_test

HEALTH = {
    "status": "degraded",
    "tools_count": 8,
    "backends": {
        "threatintel-mcp": {"status": "ok", "tools": 8},
        "opensearch-mcp": {"status": "stopped"},
        "windows-triage-mcp": {"status": "error", "error": "database missing"},
    },
}


class _Reply(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_each_backend_line_says_what_was_checked(monkeypatch, capsys):
    monkeypatch.setattr(gateway, "get_local_gateway_url", lambda: "http://gw:4508")
    monkeypatch.setattr(gateway, "get_local_ssl_context", lambda: None)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: _Reply(json.dumps(HEALTH).encode())
    )
    _run_connectivity_test()
    out = capsys.readouterr().out
    assert "threatintel-mcp           running (8 tools)" in out
    assert (
        "opensearch-mcp            not started (the gateway retries every 30 s)" in out
    )
    assert "windows-triage-mcp        FAIL (database missing)" in out
    assert "1 of 3 backends running. 1 not started. 1 failed." in out
    assert "not the services behind it" in out
    assert "backends operational" not in out and "mcp           OK" not in out
