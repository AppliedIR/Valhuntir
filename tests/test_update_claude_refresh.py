"""`vhir update` refreshes Claude Code's server list from the gateway's backends.

When Step 8 finds the gateway up and Claude Code is set up on this machine
("claude-code" in the manifest's clients, and ~/.claude.json exists), Step 9
reads the backend list from /health on the same budget. An entry in
mcpServers is Valhuntir's when its URL is the local gateway's (scheme, host,
port) with the path /mcp/<name> or /mcp. Each listed backend without an entry
is added, Valhuntir's entries for backends no longer listed are removed, and
every other entry and key keeps its value. The write asks first (the
`_write_user_file` consent, with its backup) and, after the Yes, applies the
shown changes to the file as it is then. A backend that isn't up when the
time is spent, or a gateway that lists none, leaves the file alone and the
update pending, fix "vhir update".

/health is the stand-in from tests/health_stand_in.py. The texts are literals,
so a tree without the refresh fails on the asserts. Values are synthetic.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
import yaml

from tests import test_update_gateway_state
from tests.health_stand_in import T0, body
from tests.test_update_gateway_state import Answer

box = test_update_gateway_state.box  # the fixture: a scratch home with an install

TOKEN = "vhir_gw_" + "1" * 24
LOCAL = "http://127.0.0.1:4508"
OTHER = "http://192.0.2.30:4508"  # another gateway
NO_ENTRIES = (
    "Claude Code has no server entries for this gateway ({url}). To refresh its"
    " server list, run `vhir setup client` in a terminal."
)
KEPT = "To refresh the AI client's server list, run `vhir setup client` in a terminal."
NOT_REFRESHED = "the AI client's server list was not refreshed: "
APPLY = "Apply these changes to "


def _entry(name, base=LOCAL):
    return {
        "type": "http",
        "url": f"{base}/mcp/{name}",
        "headers": {"Authorization": f"Bearer {TOKEN}"},
    }


def _ok(*names, **status):
    """/health's backends: each name "ok", plus name=status pairs."""
    got = {n: {"status": "ok"} for n in names}
    got.update({n.replace("_", "-"): {"status": s} for n, s in status.items()})
    return (200, body("ok", got))


FOREIGN_SERVERS = {
    "wintools-mcp": {
        "type": "http",
        "url": "https://192.0.2.10:4624/mcp",
        "headers": {"Authorization": "Bearer vhir_wt_" + "2" * 24},
    },
    "remnux-mcp": {"type": "http", "url": "http://192.0.2.20:3000/mcp"},
    "zeltser-ir-writing": {"type": "http", "url": "https://ir-writing.example.com/mcp"},
    "mslearn": {"type": "http", "url": "https://learn.example.com/api/mcp"},
    "jdoe-tool": {"command": "jdoe-tool", "args": ["--serve"]},
}


def _refresh(
    box,
    capsys,
    *,
    servers,
    health,
    tty=True,
    answers=("y",),
    clients=("claude-code",),
    tls=False,
    **kw,
):
    """One `vhir update` with Claude Code set up; `servers` is mcpServers in
    ~/.claude.json (None: no file), `health` what /health gives."""
    gw = {"host": "127.0.0.1", "port": 4508}
    if tls:
        gw["tls"] = {"certfile": str(box.home / ".vhir" / "tls" / "gateway-cert.pem")}
    (box.home / ".vhir" / "gateway.yaml").write_text(
        yaml.dump(
            {"gateway": gw, "api_keys": {TOKEN: {"examiner": "jdoe"}}},
            sort_keys=False,
        )
    )
    path = box.home / ".claude.json"
    if servers is not None:
        doc = {"numStartups": 7, "userID": "jdöe EXAMPLE ✓", "mcpServers": servers}
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    before = path.read_bytes() if path.exists() else None
    from vhir_cli.commands import update

    with (
        patch("vhir_cli.commands.client_setup._deploy_claude_code_assets"),
        patch.object(
            update, "_write_update_state", wraps=update._write_update_state
        ) as writes,
    ):
        run = test_update_gateway_state._run(
            box,
            capsys,
            tty=tty,
            answers=answers,
            manifest=lambda m: {**m, "clients": list(clients)},
            gateway=Answer(health),
            **kw,
        )
    run.path, run.before = path, before
    run.after = path.read_bytes() if path.exists() else None
    run.doc = json.loads(run.after) if run.after else None
    run.prompts = [c[1] for c in run.calls if c[0] == "input"]
    run.asked = [p for p in run.prompts if APPLY in p]
    run.backups = sorted(box.home.glob(".claude.json.vhir-backup-*"))
    # Step 9's writes; the record before the pull has version ""
    run.writes = [c for c in writes.call_args_list if c.args and c.args[0]]
    return run


def _servers(run):
    return run.doc["mcpServers"]


# --- a refresh ---------------------------------------------------------------


def test_a_new_backend_is_added_and_the_others_keep_their_values(box, capsys):
    mine = {**_entry("forensic-mcp"), "timeout": 30}
    servers = {"forensic-mcp": mine, "case-mcp": _entry("case-mcp")}
    run = _refresh(
        box,
        capsys,
        servers=servers,
        health=_ok("forensic-mcp", "case-mcp", "report-mcp"),
    )
    assert _servers(run).get("report-mcp") == _entry("report-mcp"), _servers(run)
    assert _servers(run)["forensic-mcp"] == mine
    assert _servers(run)["case-mcp"] == _entry("case-mcp")
    assert len(run.asked) == 1 and str(run.path) in run.asked[0]
    assert len(run.backups) == 1 and run.backups[0].read_bytes() == run.before
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    assert TOKEN not in run.out + run.err  # the printed diff redacts the bearer


def test_the_aggregate_entry_is_replaced_by_per_backend_entries(box, capsys):
    servers = {"vhir": {**_entry("x"), "url": f"{LOCAL}/mcp"}, **FOREIGN_SERVERS}
    run = _refresh(box, capsys, servers=servers, health=_ok("forensic-mcp", "case-mcp"))
    assert "vhir" not in _servers(run), _servers(run)
    assert _servers(run).get("forensic-mcp") == _entry("forensic-mcp")
    assert _servers(run).get("case-mcp") == _entry("case-mcp")
    for name, value in FOREIGN_SERVERS.items():
        assert _servers(run)[name] == value


def test_other_entries_and_keys_keep_their_values(box, capsys):
    servers = {"forensic-mcp": _entry("forensic-mcp"), **FOREIGN_SERVERS}
    run = _refresh(box, capsys, servers=servers, health=_ok("forensic-mcp", "case-mcp"))
    for name, value in FOREIGN_SERVERS.items():
        assert _servers(run)[name] == value, name
    assert run.doc["numStartups"] == 7
    assert run.doc["userID"] == "jdöe EXAMPLE ✓"
    assert "jdöe EXAMPLE ✓".encode() in run.after  # written without \\u escapes
    assert _servers(run)["forensic-mcp"] == _entry("forensic-mcp")


def test_a_direct_wintools_entry_wins_over_the_joined_backend(box, capsys):
    servers = {
        "wintools-mcp": FOREIGN_SERVERS["wintools-mcp"],
        "forensic-mcp": _entry("forensic-mcp"),
    }
    run = _refresh(
        box,
        capsys,
        servers=servers,
        health=_ok("forensic-mcp", "case-mcp", "wintools-mcp"),
    )
    assert _servers(run)["wintools-mcp"] == FOREIGN_SERVERS["wintools-mcp"]
    assert _servers(run).get("case-mcp") == _entry("case-mcp"), _servers(run)
    assert f"{LOCAL}/mcp/wintools-mcp" not in run.after.decode()


def test_a_valhuntir_name_on_another_gateway_is_left_alone(box, capsys):
    servers = {
        "forensic-mcp": _entry("forensic-mcp", OTHER),
        "case-mcp": _entry("case-mcp"),
    }
    run = _refresh(box, capsys, servers=servers, health=_ok("forensic-mcp", "case-mcp"))
    assert _servers(run)["forensic-mcp"] == _entry("forensic-mcp", OTHER)
    assert _servers(run)["case-mcp"] == _entry("case-mcp")


def test_any_name_on_the_local_gateway_is_valhuntir_s(box, capsys):
    servers = {
        "jdoe-alias": _entry("old-mcp"),  # the local gateway, a backend it dropped
        "forensic-mcp": _entry("forensic-mcp"),
    }
    run = _refresh(box, capsys, servers=servers, health=_ok("forensic-mcp", "case-mcp"))
    assert "jdoe-alias" not in _servers(run), _servers(run)
    assert _servers(run).get("case-mcp") == _entry("case-mcp")


# --- nothing to refresh --------------------------------------------------------


@pytest.mark.parametrize("how", ["not-in-manifest", "no-claude-json"])
def test_claude_code_not_set_up_here_is_left_alone(box, capsys, how):
    run = _refresh(
        box,
        capsys,
        servers=None if how == "no-claude-json" else {"case-mcp": _entry("case-mcp")},
        clients=("claude-code",) if how == "no-claude-json" else (),
        health=_ok("case-mcp", "report-mcp"),
    )
    assert run.after == run.before
    assert run.asked == [] and run.backups == []
    assert ".claude.json" not in run.out + run.err


@pytest.mark.parametrize("how", ["another-host", "http-with-tls"])
def test_no_entries_for_this_gateway_is_one_block_line(box, capsys, how):
    tls = how == "http-with-tls"
    base = OTHER if how == "another-host" else LOCAL
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp", base)},
        health=_ok("forensic-mcp", "case-mcp"),
        tls=tls,
    )
    url = "https://127.0.0.1:4508" if tls else LOCAL
    assert any(NO_ENTRIES.format(url=url) in line for line in run.block), run.block
    assert run.after == run.before
    assert run.asked == []
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0


# --- the consent ---------------------------------------------------------------


def test_no_terminal_keeps_the_file_and_says_how(box, capsys):
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp", "case-mcp"),
        tty=False,
        answers=(),
    )
    assert any(f"Not changed: {run.path}" in line for line in run.block), run.block
    assert any(KEPT in line for line in run.block), run.block
    assert run.after == run.before and run.backups == []
    assert run.state.get("status") == "complete", run.state


def test_answering_no_keeps_the_file(box, capsys):
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp", "case-mcp"),
        answers=("n",),
    )
    assert len(run.asked) == 1, run.prompts
    assert any(KEPT in line for line in run.block), run.block
    assert run.after == run.before and run.backups == []
    assert run.state.get("status") == "complete", run.state


def test_a_key_written_during_the_prompt_is_kept(box, capsys):
    path = box.home / ".claude.json"

    def claude_code_writes_then_yes(prompt):
        doc = json.loads(path.read_text())
        doc["jdoeAdded"] = {"at": "EXAMPLE"}
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
        return "y"

    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp", "case-mcp"),
        answers=(claude_code_writes_then_yes,),
    )
    assert len(run.asked) == 1, run.prompts
    assert run.doc.get("jdoeAdded") == {"at": "EXAMPLE"}, run.doc
    assert _servers(run) == {
        "forensic-mcp": _entry("forensic-mcp"),
        "case-mcp": _entry("case-mcp"),
    }
    assert run.doc["numStartups"] == 7
    assert len(run.backups) == 1  # of the file as it was at the Yes
    assert b"jdoeAdded" in run.backups[0].read_bytes()


def test_a_file_that_stops_being_json_before_the_yes_is_not_written(box, capsys):
    path = box.home / ".claude.json"

    def broken_then_yes(prompt):
        path.write_text('{"mcpServers": EXAMPLE')
        return "y"

    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp", "case-mcp"),
        answers=(broken_then_yes,),
    )
    assert len(run.asked) == 1, run.prompts
    assert run.after == b'{"mcpServers": EXAMPLE'
    assert any("vhir setup client" in line for line in run.block), run.block


# --- backends not up -------------------------------------------------------------


def test_a_joined_backend_that_failed_to_load_leaves_it_pending(box, capsys):
    servers = {"forensic-mcp": _entry("forensic-mcp"), "jdoe-wt": _entry("jdoe-wt")}
    run = _refresh(
        box, capsys, servers=servers, health=_ok("forensic-mcp", jdoe_wt="error")
    )
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("reason") == f"{NOT_REFRESHED}jdoe-wt not up", run.state
    assert run.state.get("fix") == "vhir update", run.state
    assert run.after == run.before and run.asked == []
    assert any("jdoe-wt" in line for line in run.block), run.block
    assert run.rc == 1


def test_a_stopped_backend_waits_on_the_one_budget_then_is_pending(box, capsys):
    servers = {"forensic-mcp": _entry("forensic-mcp")}
    run = _refresh(
        box, capsys, servers=servers, health=_ok("forensic-mcp", jdoe_os="stopped")
    )
    assert run.state.get("reason") == f"{NOT_REFRESHED}jdoe-os not up", run.state
    assert run.state.get("fix") == "vhir update", run.state
    assert run.rc == 1
    assert run.after == run.before and run.asked == []
    # wait_for_health's own loop on one 240 s budget: its waiting lines only
    waits = [ln for ln in run.out.splitlines() if "waiting for the gateway" in ln]
    assert waits and all(w.endswith(" of 240 s)") for w in waits), waits
    assert len(run.health.calls) > 2
    assert all(at < T0 + 240 for _, _, at in run.health.calls)
    assert 230 <= run.health.waited() <= 240
    assert sum(run.health.slept) == run.health.waited()
    assert "\n".join(run.block).count("jdoe-os") == 1, run.block


@pytest.mark.parametrize("backends", ["empty", "missing"])
def test_no_backends_listed_leaves_it_pending(box, capsys, backends):
    answer = (
        (200, body("ok", {}))
        if backends == "empty"
        else (200, json.dumps({"status": "ok"}).encode())
    )
    run = _refresh(
        box, capsys, servers={"forensic-mcp": _entry("forensic-mcp")}, health=answer
    )
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("reason") == (
        f"{NOT_REFRESHED}the gateway listed no backends"
    ), run.state
    assert run.state.get("fix") == "vhir update", run.state
    assert run.after == run.before and run.asked == []
    assert run.rc == 1


def test_step_8_pending_skips_the_refresh(box, capsys):
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=ConnectionRefusedError(),
    )
    assert len(run.health.calls) <= 1  # Step 8's one call, no more
    assert run.after == run.before and run.asked == []
    assert NOT_REFRESHED not in run.out + run.err


# --- one state write ---------------------------------------------------------------


def test_a_refresh_skip_is_the_one_pending_write(box, capsys):
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp", jdoe_os="stopped"),
    )
    assert [c.kwargs.get("status") for c in run.writes] == ["pending"], run.writes
    assert run.rc == 1


def test_a_refresh_with_nothing_to_change_is_the_one_complete_write(box, capsys):
    run = _refresh(
        box,
        capsys,
        servers={"forensic-mcp": _entry("forensic-mcp")},
        health=_ok("forensic-mcp"),
    )
    assert [c.kwargs.get("status") for c in run.writes] == ["complete"], run.writes
    assert run.after == run.before and run.asked == []
    assert run.rc == 0
