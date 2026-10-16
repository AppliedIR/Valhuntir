"""A case has one identity (`case_uuid`), held by one folder.

A case's indices will be named after its identity, not its folder, so a
renamed folder keeps its data and a copy can't write into its original's
indices. `case init` and `case activate` mint the identity through
sift-common (on a SIFT workstation), a second folder holding the same
identity (a `cp -r` copy) is refused at activation, and `vhir case
new-identity` gives the copy its own. Rows that need sift-common's case
identity skip without it.
"""

from __future__ import annotations

import argparse
import importlib
import json
import shutil

import pytest
import yaml

from vhir_cli import main


def _sift_identity() -> bool:
    try:
        module = importlib.import_module("sift_common.host_identity")
    except ImportError:
        return False
    return hasattr(module, "update_case_meta")


needs_sift = pytest.mark.skipif(
    not _sift_identity(), reason="sift-common with case identities is not installed"
)


def _without_sift(monkeypatch):
    """As on a machine without sift-common's case identities."""
    try:
        from vhir_cli import case_identity
    except ImportError:  # a vhir from before case identities
        return
    monkeypatch.setattr(case_identity, "host_identity", lambda: None)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".vhir").mkdir()
    return tmp_path


def _init(home, case_id="C-1"):
    data = main._case_init_data(
        name="n", examiner="tester", cases_dir=str(home / "cases"), case_id=case_id
    )
    return home / "cases" / case_id, data


def _meta(case_dir):
    return yaml.safe_load((case_dir / "CASE.yaml").read_text())


def _headers(case_dir):
    lines = (case_dir / "host-observations.jsonl").read_text().splitlines()
    return [r for r in map(json.loads, lines) if r.get("kind") == "case"]


@needs_sift
def test_a_new_case_gets_its_identity_and_host_logs(home):
    case_dir, _ = _init(home)
    meta = _meta(case_dir)
    assert len(meta["case_uuid"].replace("-", "")) == 32
    assert meta["naming_version"] == 2
    for name in ("host-observations.jsonl", "host-decisions.jsonl", "host-ops.json"):
        assert (case_dir / name).is_file(), name
    assert _headers(case_dir)[-1]["c12"] == meta["case_uuid"].replace("-", "")[:12]


@needs_sift
def test_an_older_case_gets_its_identity_at_activation(home):
    case_dir, _ = _init(home)
    meta = _meta(case_dir)
    for key in ("case_uuid", "naming_version"):
        del meta[key]
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
    for name in ("host-observations.jsonl", "host-decisions.jsonl", "host-ops.json"):
        (case_dir / name).unlink()
    main._case_activate_data("C-1", cases_dir=str(home / "cases"))
    meta = _meta(case_dir)
    assert len(meta["case_uuid"].replace("-", "")) == 32
    assert meta["naming_version"] == 1
    assert meta["name"] == "n"  # every other key kept


@needs_sift
def test_a_lost_identity_is_refused_with_the_one_to_restore(home):
    case_dir, _ = _init(home)
    meta = _meta(case_dir)
    lost = meta.pop("case_uuid")
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
    with pytest.raises(ValueError, match=lost):
        main._case_activate_data("C-1", cases_dir=str(home / "cases"))
    assert "case_uuid" not in _meta(case_dir)  # not re-minted over the records


@needs_sift
def test_a_copy_is_refused_at_activation(home):
    case_dir, _ = _init(home)
    shutil.copytree(case_dir, home / "cases" / "C-1-copy")
    with pytest.raises(ValueError) as refused:
        main._case_activate_data("C-1-copy", cases_dir=str(home / "cases"))
    message = str(refused.value)
    assert str(case_dir.resolve()) in message and "C-1-copy" in message
    assert "vhir case new-identity C-1-copy" in message
    main._case_activate_data("C-1", cases_dir=str(home / "cases"))  # the original


@needs_sift
def test_a_copy_in_another_cases_folder_is_refused_too(home):
    case_dir, _ = _init(home)
    shutil.copytree(case_dir, home / "elsewhere" / "C-1")
    with pytest.raises(ValueError, match="copy of the case"):
        main._case_activate_data("C-1", cases_dir=str(home / "elsewhere"))


@needs_sift
def test_a_renamed_case_folder_still_activates(home):
    case_dir, _ = _init(home)
    case_dir.rename(home / "cases" / "C-1-renamed")
    main._case_activate_data("C-1-renamed", cases_dir=str(home / "cases"))
    paths = json.loads((home / ".vhir" / "case-paths.json").read_text())
    assert paths[_meta(home / "cases" / "C-1-renamed")["case_uuid"]].endswith(
        "C-1-renamed"
    )


@needs_sift
def test_new_identity_lets_the_copy_be_used(home, capsys):
    case_dir, _ = _init(home)
    original = _meta(case_dir)["case_uuid"]
    copy = home / "cases" / "C-1-copy"
    shutil.copytree(case_dir, copy)
    main._case_new_identity(
        argparse.Namespace(case_id="C-1-copy", cases_dir=str(home / "cases"))
    )
    meta = _meta(copy)
    assert meta["case_uuid"] != original and meta["legacy_alias"] == "none"
    assert meta["name"] == "n"
    assert _headers(copy)[-1]["c12"] == meta["case_uuid"].replace("-", "")[:12]
    assert _meta(case_dir)["case_uuid"] == original  # the original is unchanged
    main._case_activate_data("C-1-copy", cases_dir=str(home / "cases"))
    main._case_activate_data("C-1", cases_dir=str(home / "cases"))
    assert meta["case_uuid"] in capsys.readouterr().out


@needs_sift
def test_new_identity_is_refused_for_a_case_that_isnt_a_copy(home, capsys):
    case_dir, _ = _init(home)
    original = _meta(case_dir)["case_uuid"]
    with pytest.raises(SystemExit):
        main._case_new_identity(
            argparse.Namespace(case_id="C-1", cases_dir=str(home / "cases"))
        )
    assert "isn't a copy" in capsys.readouterr().err
    assert _meta(case_dir)["case_uuid"] == original


def test_new_identity_needs_sift_common(home, monkeypatch, capsys):
    _without_sift(monkeypatch)
    case_dir, _ = _init(home)
    with pytest.raises(SystemExit):
        main._case_new_identity(
            argparse.Namespace(case_id="C-1", cases_dir=str(home / "cases"))
        )
    assert "needs the SIFT workstation's sift-common" in capsys.readouterr().err


def test_anchor_without_sift_common_a_case_is_made_as_before(home, monkeypatch):
    _without_sift(monkeypatch)
    case_dir, data = _init(home)
    assert "case_uuid" not in _meta(case_dir)
    assert data["activation"]["active"] == "C-1"
    main._case_activate_data("C-1", cases_dir=str(home / "cases"))


def test_the_new_identity_command_is_on_the_cli():
    args = main.build_parser().parse_args(["case", "new-identity", "C-1-copy"])
    assert (args.case_action, args.case_id) == ("new-identity", "C-1-copy")


@needs_sift
def test_an_older_case_s_copy_is_refused_after_its_first_activation(home):
    case_dir, _ = _init(home)
    meta = _meta(case_dir)
    for key in ("case_uuid", "naming_version"):
        del meta[key]
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
    (home / ".vhir" / "case-paths.json").unlink()
    for name in ("host-observations.jsonl", "host-decisions.jsonl", "host-ops.json"):
        (case_dir / name).unlink()
    main._case_activate_data("C-1", cases_dir=str(home / "cases"))  # mints
    shutil.copytree(case_dir, home / "cases" / "C-1-copy")
    with pytest.raises(ValueError, match="copy of the case"):
        main._case_activate_data("C-1-copy", cases_dir=str(home / "cases"))


@needs_sift
def test_reopening_a_copied_closed_case_is_refused(home, monkeypatch, capsys):
    monkeypatch.setenv("VHIR_CASES_DIR", str(home / "cases"))
    case_dir, _ = _init(home)
    meta = _meta(case_dir)
    meta["status"] = "closed"
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(meta))
    shutil.copytree(case_dir, home / "cases" / "C-1-copy")
    pointer = (home / ".vhir" / "active_case").read_text()
    with pytest.raises(SystemExit):
        main._case_reopen(argparse.Namespace(case_id="C-1-copy"), {})
    assert "copy of the case" in capsys.readouterr().err
    assert _meta(home / "cases" / "C-1-copy")["status"] == "closed"
    assert (home / ".vhir" / "active_case").read_text() == pointer


def _copied(home):
    """An original and its `cp -r` copy; the copy's files as they are now."""
    case_dir, _ = _init(home)
    copy = home / "cases" / "C-1-copy"
    shutil.copytree(case_dir, copy)
    return case_dir, copy, _files(home, copy)


def _files(home, copy):
    """What a failed new identity must leave as it was."""
    case_yaml = copy / "CASE.yaml"
    return {
        "case": case_yaml.read_bytes(),
        "mode": case_yaml.stat().st_mode,
        "headers": _headers(copy),
        "paths": (home / ".vhir" / "case-paths.json").read_bytes(),
    }


def _new_identity_fails(home, capsys) -> str:
    with pytest.raises(SystemExit) as stopped:
        main._case_new_identity(
            argparse.Namespace(case_id="C-1-copy", cases_dir=str(home / "cases"))
        )
    assert stopped.value.code == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1 and "Errno" not in err
    return err


@needs_sift
@pytest.mark.parametrize("locked", ["folder", "lock file"])
def test_a_new_identity_that_cant_be_recorded_changes_nothing(home, capsys, locked):
    from vhir_cli.case_identity import copy_of

    case_dir, copy, before = _copied(home)
    vhir = home / ".vhir"
    if locked == "lock file":
        (vhir / "case-paths.lock").chmod(0o400)
    vhir.chmod(0o555)
    try:
        err = _new_identity_fails(home, capsys)
    finally:
        vhir.chmod(0o755)
        (vhir / "case-paths.lock").chmod(0o600)
    assert _files(home, copy) == before
    assert f"keeps case identity {_meta(case_dir)['case_uuid']}" in err
    assert "Permission denied" in err
    assert copy_of(copy)  # still a copy: `case list` shows the one identity


@needs_sift
@pytest.mark.parametrize("step", ["update_case_meta", "write_case_header"])
def test_a_new_identity_cut_short_puts_the_old_one_back(
    home, monkeypatch, capsys, step
):
    from sift_common import host_identity

    from vhir_cli.case_identity import copy_of

    case_dir, copy, before = _copied(home)

    def fail(*a, **k):
        raise OSError(28, "No space left on device", str(copy / "x"))

    monkeypatch.setattr(host_identity, step, fail)
    err = _new_identity_fails(home, capsys)
    assert "No space left on device" in err
    assert _files(home, copy) == before
    assert copy_of(copy)
    assert _meta(case_dir)["case_uuid"] == _meta(copy)["case_uuid"]


@needs_sift
def test_a_header_written_before_its_failure_is_undone(home, monkeypatch, capsys):
    from sift_common import host_identity

    case_dir, copy, before = _copied(home)
    real = host_identity.write_case_header
    calls = []

    def lands_then_fails(*a, **k):
        calls.append(a[1])
        real(*a, **k)
        if len(calls) == 1:
            raise OSError(5, "Input/output error")

    monkeypatch.setattr(host_identity, "write_case_header", lands_then_fails)
    _new_identity_fails(home, capsys)
    old_c12 = before["headers"][-1]["c12"]
    assert calls[1] == old_c12 and calls[0] != old_c12
    assert _headers(copy)[-1]["c12"] == old_c12
    assert _headers(copy)[-1]["reason"] == "new identity undone"
    assert (copy / "CASE.yaml").read_bytes() == before["case"]
    assert host_identity.recorded_c12(copy) == old_c12


@needs_sift
def test_a_case_yaml_that_cant_be_put_back_says_what_to_set(home, monkeypatch, capsys):
    from sift_common import host_identity

    from vhir_cli import case_identity

    case_dir, copy, _ = _copied(home)

    def fail(*a, **k):
        raise OSError(28, "No space left on device")

    def no_undo(path, data, mode):
        raise OSError(30, "Read-only file system", str(path))

    monkeypatch.setattr(host_identity, "write_case_header", fail)
    monkeypatch.setattr(case_identity, "_put_back", no_undo)
    err = _new_identity_fails(home, capsys)
    old = _meta(case_dir)["case_uuid"]
    assert f"set case_uuid: {old} in its CASE.yaml" in err
    assert "Read-only file system" in err and "No space left" in err


@needs_sift
def test_a_record_step_that_fails_changes_nothing(home, monkeypatch, capsys):
    from vhir_cli import case_identity

    _, copy, before = _copied(home)

    def fail(path, content):
        raise OSError(13, "Permission denied", str(path))

    monkeypatch.setattr(case_identity, "_atomic_write", fail)
    err = _new_identity_fails(home, capsys)
    assert _files(home, copy) == before
    assert "case-paths.json: Permission denied" in err


def test_a_put_back_that_fails_leaves_the_file_and_no_temp_file(tmp_path, monkeypatch):
    from vhir_cli import case_identity

    target = tmp_path / "CASE.yaml"
    target.write_bytes(b"case_uuid: new\n")

    def fail(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(case_identity.os, "replace", fail)
    with pytest.raises(OSError, match="No space left"):
        case_identity._put_back(target, b"case_uuid: old\n", 0o644)
    assert target.read_bytes() == b"case_uuid: new\n"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize(
    ("error", "line"),
    [
        (
            OSError(13, "Permission denied", "/c/CASE.yaml"),
            "/c/CASE.yaml: Permission denied",
        ),
        (OSError(5, "Input/output error"), "Input/output error"),
        (OSError("lock held"), "lock held"),
        (ValueError("bad header"), "bad header"),
        (ValueError(), "ValueError"),
    ],
)
def test_a_failed_step_is_named_in_one_line(error, line):
    from vhir_cli.case_identity import _reason

    assert _reason(error) == line


@needs_sift
@pytest.mark.parametrize("outcome", ["given", "refused"])
def test_a_copy_lists_as_a_second_row_before_and_after_a_new_identity(
    home, capsys, outcome
):
    """A `cp -r` copy is a second folder with the same case_id: `case list`
    shows two rows either way. new-identity changes the identity, not the
    case_id."""

    def ids():
        rows = main._case_list_data(home / "cases")["cases"]
        return sorted(r["id"] for r in rows)

    _, copy, before = _copied(home)
    assert ids() == ["C-1", "C-1"]
    if outcome == "given":
        main._case_new_identity(
            argparse.Namespace(case_id="C-1-copy", cases_dir=str(home / "cases"))
        )
    else:
        vhir = home / ".vhir"
        vhir.chmod(0o555)
        try:
            _new_identity_fails(home, capsys)
        finally:
            vhir.chmod(0o755)
        assert _files(home, copy) == before
    assert ids() == ["C-1", "C-1"]


@needs_sift
def test_a_new_identity_records_both_folders(home, capsys):
    case_dir, copy, _ = _copied(home)
    main._case_new_identity(
        argparse.Namespace(case_id="C-1-copy", cases_dir=str(home / "cases"))
    )
    paths = json.loads((home / ".vhir" / "case-paths.json").read_text())
    assert paths == {
        _meta(case_dir)["case_uuid"]: str(case_dir.resolve()),
        _meta(copy)["case_uuid"]: str(copy.resolve()),
    }
    assert not list(copy.glob(".CASE.yaml.*"))


@needs_sift
def test_new_identity_waits_for_the_case_to_be_idle(home, capsys):
    from sift_common import host_identity

    case_dir, _ = _init(home)
    copy = home / "cases" / "C-1-copy"
    shutil.copytree(case_dir, copy)
    before = _meta(copy)["case_uuid"]
    with host_identity.case_lock(copy, shared=True):  # an ingest, say
        with pytest.raises(SystemExit):
            main._case_new_identity(
                argparse.Namespace(case_id="C-1-copy", cases_dir=str(home / "cases"))
            )
    assert "in use" in capsys.readouterr().err
    assert _meta(copy)["case_uuid"] == before
    paths = json.loads((home / ".vhir" / "case-paths.json").read_text())
    assert list(paths) == [before]  # the new identity's record is taken back


@needs_sift
def test_a_corrupt_case_paths_file_is_refused_not_overwritten(home):
    _init(home)
    paths = home / ".vhir" / "case-paths.json"
    paths.write_text("{not json")
    with pytest.raises(ValueError, match="can't be read"):
        main._case_activate_data("C-1", cases_dir=str(home / "cases"))
    assert paths.read_text() == "{not json"
