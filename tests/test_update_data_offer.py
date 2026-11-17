"""`vhir update` offers the newest data release an installed package's downloader names.

Every call runs `<venv python> -I`. Each downloader's `--check` prints JSON:
installed, newest, absent, download_bytes. Each is considered only when its
package is in the manifest's packages, and offered when the data is absent or
another release. On a terminal a Yes (or an empty answer) runs the downloader
with --tag <newest> and no --dest, before the gateway restart; with
--no-restart a download makes the update the asked pending. A failed download
is one block line, and the update goes on. Not asked without a terminal; a No
is recorded for that release and not asked again.

subprocess is the stand-in of tests/test_update_lock.py; `_data` answers the
--check calls and the downloads. The texts are literals, so a tree without the
offer fails on the asserts rather than on an import.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from tests import test_update_gateway_state
from tests.test_update_gateway_state import RESTART, RESTART_FIX, _run

box = test_update_gateway_state.box  # the fixture: a scratch home with an install

INDEX = "rag_mcp.scripts.download_index"
TRIAGE = "windows_triage.scripts.download_databases"
INDEX_OFFER = "knowledge index download"
TRIAGE_OFFER = "triage database download"


@pytest.fixture(autouse=True)
def data_installed():
    """Overrides tests/conftest.py's: these rows run the update's own checks."""


NEW = "rag-index-v2026.11.12"


def _state(kind):
    """current: the newest installed; absent: nothing installed; None: --check fails."""
    if kind is None:
        return MagicMock(returncode=1, stdout="", stderr="x: offline")
    state = {"installed": NEW if kind == "current" else "unknown", "newest": NEW}
    state.update(absent=kind == "absent", download_bytes=12_000_001)
    return MagicMock(returncode=0, stdout=json.dumps(state), stderr="")


def _data(index="current", triage="current", fails=()):
    """What each --check answers (_state); the downloaders named in `fails` exit 1."""

    def answer(cmd):
        if cmd[1:3] == ["-I", "-m"] and cmd[3:] == [INDEX, "--check"]:
            return _state(index)
        if cmd[1:3] == ["-I", "-m"] and cmd[3:] == [TRIAGE, "--check"]:
            return _state(triage)
        if cmd[1:3] == ["-I", "-m"] and cmd[3] in (INDEX, TRIAGE):
            return MagicMock(
                returncode=1 if cmd[3] in fails else 0, stdout="", stderr=""
            )
        return None

    return answer


def _with_triage(m):
    m["packages"]["windows-triage-mcp"] = {}
    return m


def _without_rag(m):
    del m["packages"]["rag-mcp"]
    return m


def _python(box):
    return str(box.home / "venv" / "bin" / "python")


def _downloads(run):
    return [
        c
        for c in run.calls
        if c[1:3] == ["-I", "-m"] and c[3] in (INDEX, TRIAGE) and c[4:] != ["--check"]
    ]


def _asked(run):
    """The download questions asked (other offers ask their own)."""
    return [c[1] for c in run.calls if c[0] == "input" and "Download" in c[1]]


@pytest.mark.parametrize("answer", ["y", ""], ids=["yes", "empty"])
def test_an_absent_index_is_downloaded_on_a_yes_before_the_restart(box, capsys, answer):
    run = _run(
        box, capsys, no_restart=False, tty=True, answers=[answer],
        data=_data("absent"),
    )  # fmt: skip
    assert _downloads(run) == [[_python(box), "-I", "-m", INDEX, "--tag", NEW]]
    at = run.calls.index([_python(box), "-I", "-m", INDEX, "--tag", NEW])
    restart = run.calls.index(["systemctl", "--user", "restart", "vhir-gateway"])
    assert at < restart
    assert run.state.get("status") == "complete", run.state


def test_the_newest_index_installed_is_not_offered(box, capsys):
    run = _run(box, capsys, no_restart=False, tty=True, data=_data())
    assert [_python(box), "-I", "-m", INDEX, "--check"] in run.calls
    assert _downloads(run) == []
    assert _asked(run) == []


def _rag_out_triage_in(m):
    return _with_triage(_without_rag(m))


@pytest.mark.parametrize(
    "manifest, gone, checked",
    [
        (None, "windows_triage", "rag_mcp"),
        (_rag_out_triage_in, "rag_mcp", "windows_triage"),
    ],
    ids=["no-triage-package", "no-rag-package"],
)
def test_data_of_a_package_not_installed_is_neither_checked_nor_offered(
    box, capsys, manifest, gone, checked
):
    run = _run(box, capsys, tty=True, manifest=manifest, data=_data("absent", "absent"))
    assert any(checked in " ".join(c) for c in run.calls), (
        run.calls
    )  # the installed one
    assert not any(gone in " ".join(c) for c in run.calls), run.calls


def test_absent_triage_dbs_download_the_newest_tag_with_no_dest(box, capsys):
    run = _run(
        box, capsys, tty=True, answers=["y", "y"], manifest=_with_triage,
        data=_data("absent", "absent"),
    )  # fmt: skip
    assert sorted(_downloads(run)) == [
        [_python(box), "-I", "-m", INDEX, "--tag", NEW],
        [_python(box), "-I", "-m", TRIAGE, "--tag", NEW],
    ]


def test_a_failed_download_is_one_block_line_and_the_update_goes_on(box, capsys):
    run = _run(
        box, capsys, tty=True, answers=["y"], data=_data("absent", fails=(INDEX,))
    )
    lines = [line for line in run.block if "GITHUB_TOKEN" in line]
    assert lines == [
        "Download failed. Set GITHUB_TOKEN (GitHub can refuse unauthenticated"
        f" downloads) and run: {_python(box)} -I -m {INDEX} --tag {NEW}, then restart the gateway."
    ]
    assert run.state.get("status") == "complete", run.state
    assert run.rc == 0


def test_a_download_with_no_restart_is_the_asked_pending(box, capsys):
    run = _run(
        box, capsys, no_restart=True, tty=True, answers=["y"], data=_data("absent")
    )
    assert _downloads(run) == [[_python(box), "-I", "-m", INDEX, "--tag", NEW]]
    assert run.state.get("status") == "pending", run.state
    assert run.state.get("reason") == RESTART, run.state
    assert run.state.get("fix") == RESTART_FIX, run.state
    assert run.rc == 0


def test_no_terminal_is_not_asked(box, capsys):
    run = _run(box, capsys, tty=False, data=_data("absent"))
    assert _downloads(run) == []
    assert _asked(run) == []
    assert (
        f"Not asked (no terminal): {INDEX_OFFER}."
        " Re-run `vhir update` in a terminal to be asked."
    ) in run.block


def test_each_no_is_recorded_and_not_asked_again(box, capsys):
    data = _data("absent", "absent")
    first = _run(
        box, capsys, tty=True, answers=["n", "n"], manifest=_with_triage, data=data
    )
    assert len(_asked(first)) == 2, _asked(first)
    assert _downloads(first) == []
    again = _run(box, capsys, tty=True, answers=["y", "y"], data=data)
    assert _asked(again) == []
    assert _downloads(again) == []
    for offer in (INDEX_OFFER, TRIAGE_OFFER):
        assert any(f"Declined earlier: {offer}" in line for line in again.block), (
            again.block
        )
