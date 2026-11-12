"""`vhir update` records complete only when the gateway answers /health.

Step 8 waits for the local gateway's /health (vhir_cli.gateway.wait_for_health)
after a restart that worked, for at most 240 s; Step 9 writes the update state
from that answer and is the one place that sets the exit status. A failed
restart is pending without a wait. With --no-restart, an update that pulled a
tree the gateway serves (or rewrote its launch line) is the asked pending,
"restart the gateway", and exits 0; with nothing to restart, Step 8 waits for
/health on the same 240 s budget (a gateway the user just restarted may still be
starting). Every other pending exits 1.

/health is the stand-in from tests/health_stand_in.py, on its own clock: no row
dials a port or sleeps for real. The texts are literals, so a tree without the
wait fails on the asserts rather than on an import.
"""

from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from types import SimpleNamespace

import pytest
import yaml

from tests import health_stand_in, test_update_lock
from tests.health_stand_in import T0, body
from tests.test_update import steps_block
from tests.test_update_lock import _update

box = test_update_lock.box  # the fixture: a scratch home with an install

RESTART_FIX = "systemctl --user restart vhir-gateway"
RESTART = "restart the gateway"
RESTART_FAILED_FIX = (
    "If the gateway runs as a service: systemctl --user status vhir-gateway,"
    " fix what it shows, then run vhir update. If you start it by hand: stop it,"
    " run ~/.vhir/start-gateway.sh, then run vhir update --no-restart."
)
UNPROVEN = "can't tell that the gateway was restarted after the last update"


@dataclass(frozen=True)
class Answer:
    """What /health gives on every call, the repos the run pulls, and the
    reason and fix Step 9 records for it."""

    health: object
    reason: str = ""
    fix: str = ""
    pulls: tuple = ()


PASS = Answer(health_stand_in.PASS)
FOREIGN = Answer(
    (200, b"<html>EXAMPLE</html>"),
    "something on port 4508 answered /health, but not as the Valhuntir gateway",
    f"find what holds port 4508 (ss -ltnp), stop it, then: {RESTART_FIX}",
)
UNKNOWN = Answer(
    (500, b""),
    "the gateway answered /health with HTTP 500",
    "systemctl --user status vhir-gateway",
)
REFUSED = Answer(
    ConnectionRefusedError(),
    "nothing answered on port 4508 (refused)",
    f"start the gateway: {RESTART_FIX}",
)
STALE_HEADS = Answer(health_stand_in.PASS, RESTART, RESTART_FIX, pulls=("sift-mcp",))


def _state(box):
    path = box.home / ".vhir" / "update-state.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _run(box, capsys, **kw):
    kw.setdefault("gateway", PASS)
    calls, exited = _update(box, **kw)
    out, err = capsys.readouterr()
    health = health_stand_in.current()
    return SimpleNamespace(
        calls=calls,
        rc=0 if exited is None else (exited.code or 0),
        out=out,
        err=err,
        block=steps_block(err),
        state=_state(box),
        health=health,
    )


def _pending(run, reason, fix):
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("reason") == reason, run.state
    assert run.state.get("fix") == fix, run.state
    assert any(f"Update pending: {reason}" in line for line in run.block), run.block
    assert any(f"Run: {fix}" in line for line in run.block), run.block


def _passes_after(seconds):
    def answer(h):
        return (
            health_stand_in.PASS if h.waited() >= seconds else ConnectionRefusedError()
        )

    return answer


# --- a normal run: Step 7 restarts the gateway, Step 8 waits for /health ----


def test_a_gateway_that_never_answers_leaves_it_pending_after_240_s(box, capsys):
    run = _run(box, capsys, no_restart=False, gateway=REFUSED)
    _pending(run, REFUSED.reason, REFUSED.fix)
    assert run.rc == 1
    assert len(run.health.calls) > 1
    assert all(at < T0 + 240 for _, _, at in run.health.calls)
    assert run.health.waited() <= 240


def test_a_gateway_that_answers_after_30_s_is_complete(box, capsys):
    run = _run(box, capsys, no_restart=False, gateway=Answer(_passes_after(30)))
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    waits = [line for line in run.out.splitlines() if "waiting for the gateway" in line]
    assert waits == [
        "  waiting for the gateway (10 of 240 s)",
        "  waiting for the gateway (20 of 240 s)",
    ]
    assert 30 <= run.health.waited() < 40  # the stand-in's clock: no real sleep


@pytest.mark.parametrize(
    "restart",
    [1, FileNotFoundError("systemctl")],
    ids=["rc-1", "no-systemctl"],
)
def test_a_failed_restart_is_pending_with_one_fix_and_no_wait(box, capsys, restart):
    escaped = None
    try:
        run = _run(box, capsys, no_restart=False, restart_rc=restart)
    except Exception as e:  # what the restart raised must not end the update
        escaped = e
    assert escaped is None, f"no exception escaped: {escaped!r}"
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("fix") == RESTART_FAILED_FIX, run.state
    assert run.state.get("reason", "").startswith("the gateway restart failed ("), (
        run.state
    )
    assert any(RESTART_FAILED_FIX in line for line in run.block), run.block
    assert run.rc == 1
    assert run.health.calls == []
    # one owner: the failed-restart text prints once, in the block
    assert (run.out + run.err).count("start-gateway.sh") == 1, run.out + run.err
    assert "Traceback" not in run.out + run.err


def test_a_failed_restart_with_no_stderr_names_its_exit_status(box, capsys):
    run = _run(box, capsys, no_restart=False, restart_rc=3, restart_err="")
    assert run.state.get("reason") == "the gateway restart failed (exit status 3)", (
        run.state
    )
    assert "failed (exit status 3)" in run.out, run.out


@pytest.mark.parametrize(
    ("kw", "fix"),
    [
        ({"restart_rc": 1}, RESTART_FAILED_FIX),
        ({"gateway": REFUSED}, REFUSED.fix),
        ({"gateway": STALE_HEADS, "no_restart": True}, RESTART_FIX),
    ],
    ids=["restart-failed", "no-answer", "asked"],
)
def test_the_pending_lines_are_the_reason_and_the_fix_only(box, capsys, kw, fix):
    run = _run(box, capsys, **{"no_restart": False, **kw})
    at = next(i for i, line in enumerate(run.block) if "Update pending:" in line)
    assert run.block[at + 1] == f"Run: {fix}", run.block
    assert not any("Then run" in line for line in run.block), run.block


def test_a_restart_that_worked_says_to_reconnect_only_when_health_passes(box, capsys):
    from vhir_cli.gateway import RECONNECT_HINT

    run = _run(box, capsys, no_restart=False)
    assert any(RECONNECT_HINT in line for line in run.block)
    run = _run(box, capsys, no_restart=False, gateway=UNKNOWN)
    assert not any(RECONNECT_HINT in line for line in run.block)


# --- --no-restart ----------------------------------------------------------


def _launch_line_rewritten(monkeypatch, box):
    from vhir_cli.commands import client_setup

    def rewrite(*a, **kw):
        path = box.home / ".vhir" / "start-gateway.sh"
        client_setup._LAUNCHERS_UPDATED.append(path)
        return [path]

    monkeypatch.setattr(client_setup, "_isolate_gateway_launchers", rewrite)


@pytest.mark.parametrize(
    "why",
    ["sift-mcp-moved", "opensearch-before", "opensearch-after", "launch-line"],
)
def test_no_restart_with_a_restart_needed_is_the_asked_pending(
    box, capsys, monkeypatch, why
):
    kw = {"no_restart": True}
    if why == "sift-mcp-moved":
        kw["gateway"] = STALE_HEADS
    elif why.startswith("opensearch"):
        kw.update(opensearch=True, unreadable=("opensearch-mcp", why.split("-")[1]))
    else:
        _launch_line_rewritten(monkeypatch, box)
    run = _run(box, capsys, **kw)
    _pending(run, RESTART, RESTART_FIX)
    assert run.rc == 0
    assert run.health.calls == []


def test_no_restart_with_nothing_to_restart_asks_health_once(box, capsys):
    run = _run(box, capsys, no_restart=True)
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    assert len(run.health.calls) == 1


def test_no_restart_waits_for_a_gateway_that_starts_listening_late(box, capsys):
    """The user restarted the gateway just before `vhir update --no-restart`, and
    it listens after 8 s: Step 8 waits on its budget, then judges."""
    path = box.home / ".vhir" / "update-state.json"
    path.write_text(
        json.dumps({"status": "pending", "reason": RESTART, "fix": RESTART_FIX})
    )
    run = _run(box, capsys, no_restart=True, gateway=Answer(_passes_after(8)))
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    assert len(run.health.calls) > 1
    assert 8 <= run.health.waited() < 10  # the stand-in's clock: no real sleep
    assert any(UNPROVEN in line for line in run.block), run.block


def test_no_restart_with_a_gateway_that_never_answers_is_pending_after_the_budget(
    box, capsys, monkeypatch
):
    from vhir_cli import gateway

    monkeypatch.setattr(gateway, "DEADLINE", 20.0)  # a short budget, the same loop
    run = _run(box, capsys, no_restart=True, gateway=REFUSED)
    _pending(run, REFUSED.reason, REFUSED.fix)
    assert run.rc == 1
    assert len(run.health.calls) > 1
    assert all(at < T0 + 20 for _, _, at in run.health.calls)
    assert run.health.waited() <= 20


@pytest.mark.parametrize(
    ("before", "says"),
    [
        ({"status": "pending", "reason": RESTART, "fix": RESTART_FIX}, True),
        ({"status": "complete", "reason": "", "fix": ""}, False),
        ({"status": "pending", "reason": "EXAMPLE reason", "fix": "EXAMPLE"}, False),
    ],
    ids=["owed-restart", "complete", "other-pending"],
)
def test_a_restart_owed_by_the_last_run_is_named_once_health_passes(
    box, capsys, before, says
):
    (box.home / ".vhir" / "update-state.json").write_text(json.dumps(before))
    run = _run(box, capsys, no_restart=True)
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    lines = [line for line in run.block if UNPROVEN in line]
    assert bool(lines) == says, run.block
    assert not says or RESTART_FIX in lines[0]


def test_a_restart_owed_is_still_named_when_the_update_hands_over(box, capsys):
    """The new code's process reads the handoff, not the record the first
    process wrote before the pull."""
    path = box.home / ".vhir" / "update-state.json"
    path.write_text(
        json.dumps({"status": "pending", "reason": RESTART, "fix": RESTART_FIX})
    )
    first = _run(box, capsys, no_restart=True, vhir_moves=True)
    execv = next(c for c in first.calls if c[0] == "execv")
    handoff = execv[execv.index("--after-pull") + 1]
    assert json.loads(path.read_text()).get("reason") != RESTART  # the pre-pull record
    run = _run(box, capsys, no_restart=True, after_pull=handoff)
    assert run.state.get("status") == "complete", run.state
    lines = [line for line in run.block if UNPROVEN in line]
    assert lines and RESTART_FIX in lines[0], run.block


# --- what counts as an answer, and the reasons -----------------------------


def test_a_200_that_isn_t_the_gateway_keeps_polling_and_ends_pending(box, capsys):
    run = _run(box, capsys, no_restart=False, gateway=FOREIGN)
    _pending(run, FOREIGN.reason, FOREIGN.fix)
    assert run.rc == 1
    assert len(run.health.calls) > 1


def test_degraded_passes(box, capsys):
    run = _run(box, capsys, no_restart=False, gateway=Answer((200, body("degraded"))))
    assert run.state.get("status") == "complete", run.state
    assert len(run.health.calls) == 1


def test_every_call_is_capped_at_15_s_and_the_time_left(box, capsys):
    def slow(h):  # every call takes its whole timeout
        h.now += h.calls[-1][1]
        return TimeoutError()

    run = _run(box, capsys, no_restart=False, gateway=Answer(slow))
    assert run.rc == 1
    timeouts = [(t, at) for _, t, at in run.health.calls]
    assert timeouts and all(t == min(15.0, T0 + 240 - at) for t, at in timeouts)
    assert run.health.waited() <= 240


def test_a_health_that_answers_in_12_s_passes(box, capsys):
    def in_12_s(h):
        h.now += 12
        return health_stand_in.PASS

    run = _run(box, capsys, no_restart=False, gateway=Answer(in_12_s))
    assert run.state.get("status") == "complete", run.state
    assert [t for _, t, _ in run.health.calls] == [15.0]


@pytest.mark.parametrize(
    ("answer", "host", "names"),
    [
        (ssl.SSLError("EXAMPLE"), None, "TLS"),
        ((500, b""), None, "HTTP 500"),
        (ConnectionRefusedError(), "192.0.2.10", "gateway.host"),
    ],
    ids=["tls", "http-500", "specific-host"],
)
def test_the_fail_reasons(box, capsys, answer, host, names):
    if host:
        gw = {"gateway": {"host": host, "port": 4508}}
        (box.home / ".vhir" / "gateway.yaml").write_text(yaml.dump(gw))
    run = _run(box, capsys, no_restart=False, gateway=Answer(answer))
    assert run.state.get("status") == "pending", run.state
    assert names in run.state.get("reason", "") + run.state.get("fix", ""), run.state


@pytest.mark.parametrize("host", ["localhost"], ids=["localhost"])
def test_a_loopback_or_all_interfaces_host_names_the_stopped_gateway(box, capsys, host):
    gw = {"gateway": {"host": host, "port": 4508}}
    (box.home / ".vhir" / "gateway.yaml").write_text(yaml.dump(gw))
    run = _run(box, capsys, no_restart=False, gateway=Answer(ConnectionRefusedError()))
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("reason") == "nothing answered on port 4508 (refused)", (
        run.state
    )
    assert run.state.get("fix") == f"start the gateway: {RESTART_FIX}", run.state


@pytest.mark.parametrize("host", ["::1", "::"], ids=["ipv6-loopback", "ipv6-all"])
def test_an_ipv6_host_gets_the_bind_hint(box, capsys, host):
    """An IPv6 bind listens on IPv6 only, so the 127.0.0.1 probe is refused
    while the gateway runs: the fix is the bind, not a restart."""
    gw = {"gateway": {"host": host, "port": 4508}}
    (box.home / ".vhir" / "gateway.yaml").write_text(yaml.dump(gw))
    run = _run(box, capsys, no_restart=False, gateway=Answer(ConnectionRefusedError()))
    assert run.state.get("status") == "pending", run.state
    want = (
        f"set gateway.host in ~/.vhir/gateway.yaml to 127.0.0.1 or 0.0.0.0,"
        f" then: {RESTART_FIX}"
    )
    assert run.state.get("fix") == want, run.state
    assert run.state.get("reason") == (
        f"the gateway is set to listen only on {host}, and local clients dial 127.0.0.1"
    ), run.state


def test_the_deadline_is_240_s():
    from vhir_cli import gateway

    assert getattr(gateway, "DEADLINE", None) == 240.0


def test_a_backend_not_ok_is_named_and_the_state_stays_complete(box, capsys):
    backends = {
        "forensic-mcp": {"status": "ok"},
        "sift-mcp": {"status": "error"},
        "case-mcp": "EXAMPLE",
    }
    run = _run(
        box, capsys, no_restart=False, gateway=Answer((200, body(backends=backends)))
    )
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0
    assert any(
        "These backends aren't ok: case-mcp, sift-mcp." in line for line in run.block
    ), run.block
