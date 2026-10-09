"""`vhir setup client --client=open-webui`.

Open WebUI runs Python Tools on its server and drops the instructions MCP
servers send at initialize. So setup writes the lock-profile env file, and a
system prompt holding the forensic prefix and each backend's instructions as
the gateway sends them; it prints the steps to add each backend in the Admin
Panel, never the token. Everything here is under tmp_path.
"""

from __future__ import annotations

import argparse
import http.server
import json
import threading
import types

import pytest

from vhir_cli.commands import client_setup as cs

TOKEN = "vhir_gw_" + "ab" * 12
INSTRUCTIONS = {
    "forensic-mcp": "Record findings with evidence.\nNever guess.",
    "sift-mcp": "Run forensic tools with run_command.",
}


def _servers():
    servers = {
        n: {"type": "streamable-http", "url": f"http://127.0.0.1:4508/mcp/{n}",
            "headers": {"Authorization": f"Bearer {TOKEN}"}}
        for n in INSTRUCTIONS
    }  # fmt: skip
    servers["zeltser-ir-writing"] = {"type": "streamable-http", "url": "https://z/mcp"}
    return servers


@pytest.fixture
def owui(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cs.Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(isatty=lambda: False))
    asked = []

    def initialize(url, token):
        asked.append((url, token))
        return INSTRUCTIONS.get(url.rsplit("/", 1)[1])

    monkeypatch.setattr(cs, "_initialize_instructions", initialize)
    return types.SimpleNamespace(dir=tmp_path, asked=asked)


def test_the_env_file_is_the_lock_profile(owui):
    cs._write_openwebui(_servers())
    env = (owui.dir / "openwebui-vhir.env").read_text()
    settings = dict(
        ln.split("=", 1) for ln in env.splitlines() if ln and not ln.startswith("#")
    )
    assert settings == {
        "ENABLE_PLUGINS": "False",
        "USER_PERMISSIONS_WORKSPACE_TOOLS_ACCESS": "False",
        "ENABLE_DIRECT_INTEGRATIONS": "False",
        "ENABLE_DIRECT_CONNECTIONS": "False",
        "USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS": "False",
        "ENABLE_CODE_INTERPRETER": "False",
        "CODE_INTERPRETER_ENGINE": "pyodide",
        "CODE_EXECUTION_ENGINE": "pyodide",
    }


def test_the_system_prompt_carries_each_backend_s_instructions_as_sent(owui):
    cs._write_openwebui(_servers())
    prompt = (owui.dir / "openwebui-system-prompt.md").read_text()
    assert prompt.startswith(cs._PROMPT_PREFIX.rstrip("\n"))
    for name, text in INSTRUCTIONS.items():
        assert f"## {name}\n\n{text}\n" in prompt
    # asked with each backend's own token; the internet MCPs aren't asked
    assert {u.rsplit("/", 1)[1] for u, _ in owui.asked} == set(INSTRUCTIONS)
    assert {t for _, t in owui.asked} == {TOKEN}


def test_the_steps_name_each_backend_and_never_print_the_token(owui, capsys):
    cs._write_openwebui(_servers())
    out = capsys.readouterr().out
    assert "--env-file openwebui-vhir.env" in out and "Admin Panel" in out
    for name in INSTRUCTIONS:
        assert f"http://127.0.0.1:4508/mcp/{name}" in out
    assert "Function Name Filter List" in out and TOKEN not in out


def test_a_backend_that_doesn_t_answer_is_named(owui, capsys):
    servers = _servers()
    servers["case-mcp"] = {
        "type": "streamable-http",
        "url": "http://127.0.0.1:4508/mcp/case-mcp",
    }
    cs._write_openwebui(servers)
    out = capsys.readouterr().out
    assert "their instructions aren't in the system prompt: case-mcp" in out
    assert "## case-mcp" not in (owui.dir / "openwebui-system-prompt.md").read_text()


def test_the_cli_offers_open_webui(owui, monkeypatch, capsys):
    from vhir_cli.main import build_parser

    assert build_parser().parse_args(["setup", "client", "--client", "open-webui"])
    args = argparse.Namespace(
        client="open-webui", sift="http://127.0.0.1:9", windows=None,
        windows_token=None, remnux=None, remnux_token=None, examiner="t",
        no_mslearn=False, yes=True, uninstall=False,
    )  # fmt: skip
    cs.cmd_setup_client(args, {"examiner": "t"})
    assert (owui.dir / "openwebui-vhir.env").is_file()
    assert (owui.dir / "openwebui-system-prompt.md").is_file()


# --- reading the instructions from a real MCP endpoint ----------------------------


@pytest.mark.parametrize("stream", [True, False], ids=["event-stream", "json"])
def test_initialize_reads_the_instructions_the_endpoint_returns(stream):
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen["auth"] = self.headers.get("Authorization")
            seen["method"] = body["method"]
            reply = {"jsonrpc": "2.0", "id": body["id"],
                     "result": {"instructions": "Line one.\nLine two."}}  # fmt: skip
            data = (
                f"event: message\ndata: {json.dumps(reply)}\n\n"
                if stream
                else json.dumps(reply)
            ).encode()
            self.send_response(200)
            ctype = "text/event-stream" if stream else "application/json"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_port}/mcp/forensic-mcp"
        assert cs._initialize_instructions(url, TOKEN) == "Line one.\nLine two."
    finally:
        srv.shutdown()
    assert seen == {"auth": f"Bearer {TOKEN}", "method": "initialize"}


def test_initialize_against_nothing_is_none():
    assert cs._initialize_instructions("http://127.0.0.1:9/mcp/x", None) is None


def test_setup_says_an_existing_instance_takes_only_enable_plugins_and_where_the_rest_are(
    owui, capsys
):
    """Open WebUI keeps seven of the eight lock-profile keys in its database from
    its first start: setup says so and names where each is set."""
    cs._write_openwebui(_servers())
    out = capsys.readouterr().out
    assert "On an instance that has started before, that sets only" in out
    assert "ENABLE_PLUGINS: its database keeps the other seven" in out
    keys = [
        ln.split("=")[0]
        for ln in cs.OPENWEBUI_ENV.splitlines()
        if "=" in ln and not ln.startswith("#")
    ]
    listed = [k.split("=")[0] for k, _ in cs.OPENWEBUI_ADMIN_PANEL]
    assert sorted(listed) == sorted(k for k in keys if k != "ENABLE_PLUGINS")
    for key, where in cs.OPENWEBUI_ADMIN_PANEL:
        assert f"{key}: {where}" in out


def test_each_admin_panel_location_is_the_switch_for_its_key():
    """Open WebUI 0.11.4: the Integrations page's Direct Integrations switch
    sets ENABLE_DIRECT_INTEGRATIONS, the Connections page's Direct Connections
    switch ENABLE_DIRECT_CONNECTIONS, and the group permissions' Direct Tool
    Servers switch USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS."""
    where = dict(cs.OPENWEBUI_ADMIN_PANEL)
    assert where["ENABLE_DIRECT_INTEGRATIONS=False"] == (
        "Settings > Integrations > User Connections: Direct Integrations off"
    )
    assert where["ENABLE_DIRECT_CONNECTIONS=False"] == (
        "Settings > Connections > User Connections: Direct Connections off"
    )
    assert where["USER_PERMISSIONS_FEATURES_DIRECT_TOOL_SERVERS=False"] == (
        "Users > Groups > Default permissions > Edit, Features Permissions: "
        "Direct Tool Servers off"
    )
