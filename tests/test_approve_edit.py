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
