"""Tests for the $EDITOR-backed item edit path of the approve command."""

import os
import subprocess

import pytest
import yaml

from vhir_cli.commands.approve import _apply_edit


@pytest.fixture
def identity():
    return {"examiner": "tester"}


def _fake_editor(recorder, rewrite=None, raises=None):
    """Build a subprocess.run replacement that records and optionally rewrites."""

    def runner(argv, **kwargs):
        recorder.append(argv[1])
        if rewrite is not None:
            with open(argv[1], "w") as f:
                f.write(rewrite)
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(argv, 0)

    return runner


def test_apply_edit_records_modification(monkeypatch, identity):
    """A field changed in the editor is applied and tracked."""
    item = {"title": "Old title", "observation": "obs"}
    seen = []
    edited = yaml.dump({"title": "New title", "observation": "obs"})
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(subprocess, "run", _fake_editor(seen, rewrite=edited))

    _apply_edit(item, identity)

    assert item["title"] == "New title"
    assert item["examiner_modifications"]["title"]["original"] == "Old title"
    assert item["examiner_modifications"]["title"]["modified_by"] == "tester"
    assert not os.path.exists(seen[0])


def test_apply_edit_editor_failure_leaves_item_untouched(monkeypatch, identity, capsys):
    """A non-zero editor exit aborts the edit and removes the temp file."""
    item = {"title": "Old title"}
    seen = []
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_editor(seen, raises=subprocess.CalledProcessError(1, "fake-editor")),
    )

    _apply_edit(item, identity)

    assert item == {"title": "Old title"}
    assert "Editor exited with error" in capsys.readouterr().err
    assert not os.path.exists(seen[0])


def test_apply_edit_invalid_yaml_leaves_item_untouched(monkeypatch, identity, capsys):
    """Unparseable YAML aborts the edit and removes the temp file."""
    item = {"title": "Old title"}
    seen = []
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(
        subprocess, "run", _fake_editor(seen, rewrite="title: [unclosed")
    )

    _apply_edit(item, identity)

    assert item == {"title": "Old title"}
    assert "invalid YAML" in capsys.readouterr().err
    assert not os.path.exists(seen[0])


def test_apply_edit_editor_timeout_leaves_item_untouched(monkeypatch, identity, capsys):
    """An editor timeout aborts the edit and removes the temp file."""
    item = {"title": "Old title"}
    seen = []
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake_editor(seen, raises=subprocess.TimeoutExpired("fake-editor", 3600)),
    )

    _apply_edit(item, identity)

    assert item == {"title": "Old title"}
    assert "Editor timed out" in capsys.readouterr().err
    assert not os.path.exists(seen[0])


def test_apply_edit_interrupt_removes_temp_file(monkeypatch, identity):
    """An interrupt during the editor still removes the temp file."""
    item = {"title": "Old title"}
    seen = []
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(
        subprocess, "run", _fake_editor(seen, raises=KeyboardInterrupt())
    )

    with pytest.raises(KeyboardInterrupt):
        _apply_edit(item, identity)

    assert not os.path.exists(seen[0])


def test_apply_edit_missing_editor_leaves_item_untouched(monkeypatch, identity, capsys):
    """A missing editor binary aborts the edit and removes the temp file."""
    item = {"title": "Old title"}
    seen = []
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(
        subprocess, "run", _fake_editor(seen, raises=FileNotFoundError("fake-editor"))
    )

    _apply_edit(item, identity)

    assert item == {"title": "Old title"}
    assert "Failed to launch editor" in capsys.readouterr().err
    assert not os.path.exists(seen[0])


def test_apply_edit_dump_failure_removes_temp_file(monkeypatch, identity, tmp_path):
    """The temp file is removed even when writing the item to it fails."""
    import tempfile

    def dump(*args, **kwargs):
        raise yaml.representer.RepresenterError("cannot represent an object")

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.setattr("vhir_cli.commands.approve.yaml.dump", dump)

    with pytest.raises(yaml.representer.RepresenterError):
        _apply_edit({"title": "Old title"}, identity)

    assert list(tmp_path.iterdir()) == []


def _edit(monkeypatch, item, identity, text):
    monkeypatch.setenv("EDITOR", "fake-editor")
    monkeypatch.setattr(subprocess, "run", _fake_editor([], rewrite=text))
    _apply_edit(item, identity)


def _finding():
    return {"id": "F-tester-001", "title": "Old title", "observation": "obs",
            "status": "DRAFT", "audit_ids": ["sift-tester-001"], "created_by": "tester"}  # fmt: skip


def test_keys_the_editor_didnt_offer_are_named_and_left(monkeypatch, identity, capsys):
    """An id, a status or the evidence never reaches the signed item."""
    item = _finding()
    text = yaml.dump({"title": "New title", "id": "F-tester-999", "status": "REJECTED",
                      "audit_ids": ["sift-forged-001"], "created_by": "mallory"})  # fmt: skip
    _edit(monkeypatch, item, identity, text)
    assert {**_finding(), "title": "New title"} == {
        k: v for k, v in item.items() if k != "examiner_modifications"}  # fmt: skip
    assert set(item["examiner_modifications"]) == {"title"}
    assert capsys.readouterr().err == (
        "  Not editable here, left unchanged: audit_ids, created_by, id, status\n"
    )


@pytest.mark.parametrize("text", ["- just\n- a list\n", "just text\n"])
def test_a_file_that_isnt_a_set_of_fields_leaves_the_item(
    monkeypatch, identity, capsys, text
):
    item = _finding()
    _edit(monkeypatch, item, identity, text)
    assert item == _finding()
    assert capsys.readouterr().err == (
        "  The edited file isn't a set of fields; the item is unchanged.\n"
    )


def test_an_unquoted_time_is_kept_as_typed(monkeypatch, identity):
    """YAML would read it as a datetime and store another form of it."""
    item = {
        "id": "T-tester-001",
        "timestamp": "2026-01-02T03:04:05Z",
        "description": "d",
    }
    _edit(
        monkeypatch, item, identity, "timestamp: 2026-01-02T03:04:06Z\ndescription: d\n"
    )
    assert item["timestamp"] == "2026-01-02T03:04:06Z"
    assert (
        item["examiner_modifications"]["timestamp"]["modified"]
        == "2026-01-02T03:04:06Z"
    )
