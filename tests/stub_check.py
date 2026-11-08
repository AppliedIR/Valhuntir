"""Stubs of product names that a row's run checks after the row's own asserts.

`stub()` replaces a name on a product module, as monkeypatch.setattr(...,
raising=False) does, and records two facts: whether the name was there before
the stub, and how many times the stub was called. The autouse `stub_check`
fixture asserts both in teardown, so a misspelled stub (a name the product never
had, or one it never reads) fails the row instead of passing it unread. The
check runs after the row's own asserts and never changes how the row's call
phase ends: before the fix, the row still fails on its own assert or on the
missing name it calls.

Every row file that calls `stub()`, directly or through a helper, imports
`stub_check` so the fixture runs for its rows."""

from __future__ import annotations

import contextlib

import pytest

_MISSING = object()
_ACTIVE: list[list[dict]] = []


def _record(obj, name, value, exists, calls):
    if not _ACTIVE:
        raise RuntimeError(
            f"stub({name}) outside a row that uses the stub_check fixture"
        )
    if calls not in ("some", "none", "any"):
        raise ValueError(f"calls={calls!r}")
    before = getattr(obj, name, _MISSING)
    rec = {
        "where": f"{getattr(obj, '__name__', obj)}.{name}",
        "was_there": before is not _MISSING,
        "exists": exists,
        "calls": calls,
        "count": 0,
    }
    _ACTIVE[-1].append(rec)
    if callable(value):

        def counted(*a, **kw):
            rec["count"] += 1
            return value(*a, **kw)

        return before, counted
    return before, value


def stub(monkeypatch, obj, name, value, *, exists=True, calls="some"):
    """Set obj.name to value for the row. exists: the name must be on obj before
    the stub. calls: "some" (the product calls it at least once), "none" (never),
    or "any" (not checked)."""
    _, wrapped = _record(obj, name, value, exists, calls)
    monkeypatch.setattr(obj, name, wrapped, raising=False)


@contextlib.contextmanager
def stubbed(obj, name, value, *, exists=True, calls="some"):
    """stub() as a context manager, for helpers built on an ExitStack."""
    before, wrapped = _record(obj, name, value, exists, calls)
    setattr(obj, name, wrapped)
    try:
        yield wrapped
    finally:
        if before is _MISSING:
            delattr(obj, name)
        else:
            setattr(obj, name, before)


def problems(records):
    """The teardown findings for one row's stubs, one line each."""
    out = []
    for r in records:
        if r["exists"] and not r["was_there"]:
            out.append(f"stub {r['where']}: the product has no such name")
        if r["calls"] == "some" and r["count"] == 0:
            out.append(f"stub {r['where']}: never called")
        if r["calls"] == "none" and r["count"]:
            out.append(f"stub {r['where']}: called {r['count']} times, must be 0")
    return out


@pytest.fixture(autouse=True)
def stub_check():
    records: list[dict] = []
    _ACTIVE.append(records)
    try:
        yield records
    finally:
        _ACTIVE.pop()
    found = problems(records)
    assert not found, "; ".join(found)
