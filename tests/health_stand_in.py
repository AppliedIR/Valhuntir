"""A stand-in for the local gateway's /health, set up for every test.

`vhir update` waits for the gateway to answer /health (vhir_cli.gateway's
wait_for_health). No test may dial a real port or sleep for real, so
conftest replaces the gateway module's transport with `HealthStandIn.send`
and its `time` with the stand-in's clock, which moves only when the code
sleeps or an answer function moves it (a call that takes time). By default
every call passes; a row sets `answer` to what the gateway gives:

- a (status, body) pair, or an exception the dial raises;
- or a function of the stand-in returning one of those, for answers that
  change with the clock.

`calls` records each call as (url, timeout, the clock at the call)."""

from __future__ import annotations

import json
import time

T0 = 1000.0  # the clock when a row starts


def body(status="ok", backends=None) -> bytes:
    return json.dumps({"status": status, "backends": backends or {}}).encode()


PASS = (200, body())


class HealthStandIn:
    def __init__(self) -> None:
        self.now = T0
        self.answer = PASS
        self.calls: list[tuple[str, float, float]] = []
        self.slept: list[float] = []

    # the gateway module's `time`
    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def __getattr__(self, name):
        return getattr(time, name)

    # the gateway module's `_transport`
    def send(self, url, timeout, context):
        self.calls.append((url, timeout, self.now))
        got = self.answer(self) if callable(self.answer) else self.answer
        if isinstance(got, BaseException):
            raise got
        return got

    def waited(self) -> float:
        return self.now - T0


CURRENT: list[HealthStandIn] = []  # the running row's stand-in (conftest sets it)


def current() -> HealthStandIn:
    return CURRENT[-1]
