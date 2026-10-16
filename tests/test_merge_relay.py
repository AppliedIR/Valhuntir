"""A merge compares an imported copy by its author's revision time, and
`export --since` counts what it can't judge.

A merge strips a copy's own modified_at and staged, so a stored copy used to
compare as "no time": a revision relayed through a third case was skipped,
and an older bundle arriving late replaced a newer copy. Each side is now
judged by its content's last change: the author's time at the root of the
imported_from.original chain, or a later edit made on the way at approve
(examiner_modifications). A copy's own decision time isn't a revision and
never travels. Items with no time at all, which `export --since` can't judge,
are counted and said.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from vhir_cli.case_io import (
    export_bundle,
    import_bundle,
    load_findings,
    save_findings,
    save_timeline,
)
from vhir_cli.commands.approve import _approve_specific
from vhir_cli.commands.sync import cmd_export

from .signing import enrol
from .test_merge_decision_fields import _case, _finding


@pytest.fixture
def identity():
    return {"os_user": "testuser", "examiner": "analyst1", "examiner_source": "flag",
            "analyst": "analyst1", "analyst_source": "flag"}  # fmt: skip


@pytest.fixture(autouse=True)
def isolate_password_state(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    d.mkdir(mode=0o700)
    monkeypatch.setattr("vhir_cli.approval_auth._PASSWORDS_DIR", d)
    monkeypatch.setattr("vhir_cli.approval_auth._LOCKOUT_FILE", tmp_path / ".lockout")


@pytest.fixture
def pw_config(tmp_path):
    enrol("analyst1")  # passphrase testpass1
    return tmp_path / ".vhir" / "config.yaml"


def rt(bundle):
    """As a bundle file carries it."""
    return json.loads(json.dumps(bundle, default=str))


def now():
    return datetime.now(timezone.utc).isoformat()


def _event():
    return {"id": "T-alice-001", "status": "DRAFT", "timestamp": "2026-02-19T10:00:00Z",
            "description": "own event", "staged": "2026-02-19T12:00:00Z",
            "modified_at": "2026-02-19T12:00:00Z", "created_by": "alice",
            "examiner": "alice"}  # fmt: skip


def _alice(tmp_path, mp, **finding):
    a = _case(tmp_path, "A", "alice", mp)
    save_findings(
        a, [_finding("F-alice-001", created_by="alice", examiner="alice", **finding)]
    )
    save_timeline(a, [_event()])
    return a


def _approve(case, mp, identity, pw_config, who, ids=("F-alice-001",), **kw):
    """A real approve (or reject) in `case` as `who`; an `interpretation=`
    makes it an approve-time edit."""
    mp.setenv("VHIR_EXAMINER", who)
    mp.setenv("VHIR_CASE_DIR", str(case))
    with patch("vhir_cli.approval_auth.getpass_prompt", return_value="testpass1"):
        _approve_specific(case, list(ids), identity, pw_config, **kw)


def _revise(alice, mp, identity, pw_config):
    """Alice revises her finding (and approves her event): her new bundle."""
    _approve(alice, mp, identity, pw_config, "alice", ids=("F-alice-001", "T-alice-001"),
             interpretation="REVISED")  # fmt: skip
    (f,) = load_findings(alice)
    assert (f["status"], f["interpretation"]) == ("APPROVED", "REVISED")
    return rt(export_bundle(alice))


def interp(case):
    return [f.get("interpretation") for f in load_findings(case)]


# --- SPEC-003: the relay, a second hop, an older copy ------------------------


@pytest.mark.parametrize("export", ["full", "since"])
def test_a_revision_relayed_through_a_third_case_lands(
    tmp_path, monkeypatch, identity, pw_config, export
):
    """(a) Carol holds alice's first copy; bob relays alice's revision."""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    carol = _case(tmp_path, "C", "carol", monkeypatch)
    assert import_bundle(bob, first)["findings"]["added"] == 1
    assert import_bundle(carol, first)["findings"]["added"] == 1
    revised = _revise(alice, monkeypatch, identity, pw_config)
    since = now()
    time.sleep(0.02)
    assert import_bundle(bob, revised)["findings"]["updated"] == 1
    relay = rt(export_bundle(bob, since=since if export == "since" else ""))
    result = import_bundle(carol, relay)
    assert (result["findings"]["updated"], result["timeline"]["updated"]) == (1, 1)
    assert interp(carol) == ["REVISED"]


def test_an_older_bundle_never_replaces_a_relayed_revision(
    tmp_path, monkeypatch, identity, pw_config
):
    """(a2) Carol's copy is a copy of a copy (bob's relay); alice's first
    bundle arrives after it."""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    import_bundle(bob, first)
    import_bundle(bob, _revise(alice, monkeypatch, identity, pw_config))
    carol = _case(tmp_path, "C", "carol", monkeypatch)
    assert import_bundle(carol, rt(export_bundle(bob)))["findings"]["added"] == 1
    result = import_bundle(carol, first)
    assert result["findings"]["updated"] == 0 and interp(carol) == ["REVISED"]


def test_an_older_bundle_arriving_late_never_replaces_a_newer_copy(
    tmp_path, monkeypatch, identity, pw_config
):
    """(c)"""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    revised = _revise(alice, monkeypatch, identity, pw_config)
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    assert import_bundle(bob, revised)["findings"]["added"] == 1
    result = import_bundle(bob, first)
    assert result["findings"]["updated"] == 0 and interp(bob) == ["REVISED"]


# --- SPEC-003 guards: what must keep working ---------------------------------


def test_a_revision_older_than_the_import_of_the_first_copy_still_applies(
    tmp_path, monkeypatch, identity, pw_config
):
    """(d) Bob imports alice's first bundle after her revision time, then the
    revision: the import's own time isn't a revision."""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    revised = _revise(alice, monkeypatch, identity, pw_config)
    time.sleep(0.02)
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    import_bundle(bob, first)
    result = import_bundle(bob, revised)
    assert result["findings"]["updated"] == 1 and interp(bob) == ["REVISED"]


@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_a_decision_on_a_stale_copy_never_masks_the_authors_revision(
    tmp_path, monkeypatch, identity, pw_config, decision
):
    """(e) After alice revises, bob decides on his old copy with no edit;
    carol takes bob's export, then alice's revision."""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    carol = _case(tmp_path, "C", "carol", monkeypatch)
    import_bundle(bob, first)
    import_bundle(carol, first)
    revised = _revise(alice, monkeypatch, identity, pw_config)
    time.sleep(0.02)
    _approve(bob, monkeypatch, identity, pw_config, "bob", decision=decision,
             reason="r" if decision == "reject" else "")  # fmt: skip
    import_bundle(carol, rt(export_bundle(bob)))
    result = import_bundle(carol, revised)
    assert result["findings"]["updated"] == 1 and interp(carol) == ["REVISED"]


def test_an_edit_made_at_approve_on_the_way_is_a_revision(
    tmp_path, monkeypatch, identity, pw_config
):
    """(f) Bob approves alice's copy with a new interpretation; carol, who
    holds alice's copy, takes bob's export."""
    alice = _alice(tmp_path, monkeypatch)
    first = rt(export_bundle(alice))
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    carol = _case(tmp_path, "C", "carol", monkeypatch)
    import_bundle(bob, first)
    import_bundle(carol, first)
    _approve(bob, monkeypatch, identity, pw_config, "bob", interpretation="BOBX")
    result = import_bundle(carol, rt(export_bundle(bob)))
    assert result["findings"]["updated"] == 1 and interp(carol) == ["BOBX"]


# --- the sign-off's amendment: a time compares, whatever its shape --------------


def test_a_naive_author_time_compares_with_an_aware_one(
    tmp_path, monkeypatch, identity, pw_config
):
    """A naive time is read as UTC, never a TypeError: bob's copy carries
    alice's naive time, her revision an aware one."""
    naive = "2026-02-19T12:00:00"
    alice = _alice(tmp_path, monkeypatch, staged=naive, modified_at=naive)
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    assert import_bundle(bob, rt(export_bundle(alice)))["findings"]["added"] == 1
    result = import_bundle(bob, _revise(alice, monkeypatch, identity, pw_config))
    assert result["findings"]["updated"] == 1 and interp(bob) == ["REVISED"]


@pytest.mark.parametrize("bad", [5, ["2026"], {"t": 1}, True])
def test_a_time_that_isnt_a_string_is_no_time(tmp_path, monkeypatch, bad):
    """A crafted bundle stored a copy whose author time isn't a string: it is
    no time, never an AttributeError, so a timed copy is newer."""
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    crafted = _finding("F-x-001", title="crafted")
    crafted.update(modified_at=bad, staged=bad)
    assert (
        import_bundle(bob, {"case_id": "X", "findings": [crafted]})["findings"]["added"]
        == 1
    )
    newer = _finding("F-x-001", title="newer", modified_at=now())
    result = import_bundle(bob, {"case_id": "X", "findings": [newer]})
    assert result["findings"]["updated"] == 1
    assert [f["title"] for f in load_findings(bob)] == ["newer"]


# --- SPEC-004: export --since counts what it can't judge ----------------------

UNTIMED = {"id": "F-old-001", "status": "DRAFT", "title": "t", "observation": "o"}


def test_export_since_counts_the_items_it_cant_judge(tmp_path, monkeypatch, capsys):
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    timed = _finding("F-bob-001", created_by="bob", modified_at=now(), staged=now())
    save_findings(bob, [dict(UNTIMED), timed])
    save_timeline(bob, [])
    since = "2026-01-01T00:00:00+00:00"
    bundle = export_bundle(bob, since=since)
    assert [f["id"] for f in bundle["findings"]] == ["F-bob-001"]
    assert bundle["untimed"] == {"findings": 1, "timeline": 0}
    capsys.readouterr()
    cmd_export(argparse.Namespace(file=str(tmp_path / "out.json"), case=None, since=since),
               {"examiner": "bob"})  # fmt: skip
    assert (
        "  Left out (no time recorded): 1 findings, 0 timeline events; "
        "export without --since to include them\n"
    ) in capsys.readouterr().out


def test_no_count_without_since_or_when_every_item_has_a_time(tmp_path, monkeypatch):
    bob = _case(tmp_path, "B", "bob", monkeypatch)
    save_findings(bob, [dict(UNTIMED)])
    save_timeline(bob, [])
    assert "untimed" not in export_bundle(bob)
    save_findings(bob, [_finding("F-bob-001", created_by="bob")])
    assert "untimed" not in export_bundle(bob, since="2026-01-01T00:00:00+00:00")
