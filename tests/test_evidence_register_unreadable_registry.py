"""Registering evidence against an evidence.json that can't be read or parsed
is refused and leaves the file as it was; starting a new registry over it would
throw away every earlier registration. An absent, empty or whitespace-only file
still means an empty registry."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vhir_cli.commands.evidence import cmd_register_evidence, register_evidence_data

TWO = json.dumps(
    {
        "files": [
            {"path": "/cases/X/evidence/one.img", "sha256": "1" * 64},
            {"path": "/cases/X/evidence/two.img", "sha256": "2" * 64},
        ]
    },
    indent=2,
).encode()

IDENTITY = {"examiner": "analyst1", "os_user": "testuser"}


@pytest.fixture(autouse=True)
def _examiner_confirms(monkeypatch):
    """CLI registration asks at the terminal; here the examiner says yes."""
    monkeypatch.setattr(
        "vhir_cli.commands.evidence.require_tty_confirmation", lambda prompt: True
    )


class Args:
    def __init__(self, path: str):
        self.case = None
        self.path = path
        self.description = ""
        self.force_reregister = False


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_CASE_DIR", str(tmp_path))
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "new.img").write_bytes(b"new image\n")
    return tmp_path


def _new(case: Path) -> str:
    return str(case / "evidence" / "new.img")


def _entries(case: Path) -> int:
    return len(json.loads((case / "evidence.json").read_text())["files"])


def _cli_refuses(case: Path, capsys) -> str:
    with pytest.raises(SystemExit) as exc:
        cmd_register_evidence(Args(_new(case)), IDENTITY)
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "evidence.json" in err
    assert "nothing was registered" in err
    return err


@pytest.mark.parametrize(
    "content",
    [
        TWO + b"\n{garbage-not-json",
        b"\xef\xbb\xbf" + TWO,  # saved with a byte-order mark
        TWO[: len(TWO) // 2],  # cut off part way
    ],
    ids=["trailing garbage", "byte-order mark", "truncated"],
)
def test_a_registry_that_cant_be_parsed_is_refused_and_left_as_it_was(
    case, capsys, content
):
    (case / "evidence.json").write_bytes(content)
    _cli_refuses(case, capsys)
    assert (case / "evidence.json").read_bytes() == content


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="permission bits don't bind root",
)
def test_a_registry_that_cant_be_read_is_refused_and_left_as_it_was(case, capsys):
    reg = case / "evidence.json"
    reg.write_bytes(TWO)
    reg.chmod(0o000)
    _cli_refuses(case, capsys)
    reg.chmod(0o644)
    assert reg.read_bytes() == TWO


def test_the_function_case_mcp_calls_raises_and_writes_nothing(case):
    content = TWO + b"\n{garbage-not-json"
    (case / "evidence.json").write_bytes(content)
    with pytest.raises(ValueError, match="nothing was registered"):
        register_evidence_data(case_dir=case, path=_new(case), examiner="analyst1")
    assert (case / "evidence.json").read_bytes() == content


# --- anchors (pass before and after) ----------------------------------------


@pytest.mark.parametrize(
    "content", [None, b"", b"  \n"], ids=["absent", "empty", "whitespace"]
)
def test_an_absent_or_empty_registry_registers_as_empty(case, content):
    if content is not None:
        (case / "evidence.json").write_bytes(content)
    register_evidence_data(case, _new(case), "analyst1")
    assert _entries(case) == 1


def test_a_valid_registry_keeps_its_entries(case):
    (case / "evidence.json").write_bytes(TWO)
    register_evidence_data(case, _new(case), "analyst1")
    assert _entries(case) == 3
