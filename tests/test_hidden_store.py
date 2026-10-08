"""A store the shell can't see stops close, backup and export, loudly.

Claude Code's sandbox read-denies /var/lib/vhir, so a shell inside it sees
the store folder empty; copying the case's signed history from there would
leave it out without a word. A box with no store at all, and a 0.6 box with
only some of the folders, go on as before. Paths are the test's own store
folder (conftest).
"""

from __future__ import annotations

import json
from argparse import Namespace

import pytest

from vhir_cli import case_copies, ledger, verification
from vhir_cli.case_io import export_bundle
from vhir_cli.commands.backup import create_backup_data

IDENT = {"examiner": "steve", "os_user": "steve", "analyst": "steve"}
SAYS = "looks empty from here: its signing and approval folders can't be seen"


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    d = root / "C-7"
    d.mkdir(parents=True)
    (d / "CASE.yaml").write_text("case_id: C-7\nstatus: open\n")
    (d / "findings.json").write_text(json.dumps([]))
    (d / "timeline.json").write_text("[]")
    monkeypatch.setenv("VHIR_CASES_DIR", str(root))
    monkeypatch.setenv("HOME", str(tmp_path))
    return d


def _store():
    return ledger.LEDGER_DIR.parent


def _hide():
    """What a read-denied store looks like from inside the sandbox: the folder
    is there, and empty."""
    for sub in ("ledger", "keys"):
        (_store() / sub).rmdir()
    assert _store().is_dir() and not any(_store().iterdir())


def _close(case_id, monkeypatch):
    from vhir_cli.main import _case_close

    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    try:
        _case_close(Namespace(case_id=case_id, summary=""), IDENT)
    except SystemExit as e:
        return e.code
    return 0


def _status(d):
    import yaml

    return yaml.safe_load((d / "CASE.yaml").read_text())["status"]


def test_close_stops_when_the_store_looks_empty(case, monkeypatch, capsys):
    _hide()
    assert _close("C-7", monkeypatch) == 1
    err = capsys.readouterr().err
    assert SAYS in err and "The case was not closed" in err
    assert _status(case) == "open" and not (case / "ledger").exists()


def test_backup_stops_when_the_store_looks_empty(case, tmp_path):
    _hide()
    dest = tmp_path / "backups"
    dest.mkdir()
    with pytest.raises(case_copies.CopyFailed, match=SAYS):
        create_backup_data(case, str(dest), "steve")
    assert list(dest.iterdir()) == []


def test_export_stops_when_the_store_looks_empty(case):
    _hide()
    with pytest.raises(case_copies.CopyFailed, match=SAYS):
        export_bundle(case)


def test_a_box_with_no_store_closes_as_before(case, monkeypatch):
    _hide()
    _store().rmdir()
    assert _close("C-7", monkeypatch) == 0 and _status(case) == "closed"


def test_a_0_6_box_with_some_of_the_folders_closes_as_before(case, monkeypatch):
    _hide()
    verification.VERIFICATION_DIR.mkdir()
    assert _close("C-7", monkeypatch) == 0 and _status(case) == "closed"
