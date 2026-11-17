"""The data offer's rows: what `vhir update` does with each --check answer.

Each downloader's --check prints JSON (installed, newest, absent,
download_bytes). Update offers the newest release when the data is absent or
another release: one line with the tag and the size, "[Y/n] " on a terminal;
a No is recorded for that release. With VHIR_ASSUME_DEFAULTS=true it downloads
without asking, unless the installed release is unknown: then a Not-asked line
with the command. A --check that fails is one line with its reason, and the
update goes on.

subprocess is the stand-in of tests/test_update_lock.py. `_answers` answers the
--check calls, the downloads, and the presence checks of a tree that has no
--check (there the data is present unless the row says absent). The texts are
literals, so a tree without the offer fails on the asserts.
"""

from __future__ import annotations

import inspect
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tests import test_update_gateway_state
from tests.test_update_gateway_state import RESTART, _run
from vhir_cli.commands import update

box = test_update_gateway_state.box  # the fixture: a scratch home with an install

INDEX = "rag_mcp.scripts.download_index"
TRIAGE = "windows_triage.scripts.download_databases"
INDEX_OFFER = "knowledge index download"
TRIAGE_OFFER = "triage database download"
NEW, OLD, NEWER = (
    "rag-index-v2026.11.12",
    "rag-index-v2026.03.01",
    "rag-index-v2026.12.01",
)
TNEW, TOLD = "triage-db-v2026.11.12", "triage-db-v2026.02.25"
SIZE = 12_000_001  # 13 MB, rounded up
INDEX_KEPT = "the shipped index; your documents in knowledge/ are kept"
TRIAGE_KEPT = "known_good.db and context.db"


@pytest.fixture(autouse=True)
def data_installed(monkeypatch):
    """Overrides tests/conftest.py's: these rows run the update's own checks;
    the flag is unset unless a row sets it."""
    monkeypatch.delenv("VHIR_ASSUME_DEFAULTS", raising=False)


def st(installed, newest, absent=False):
    return {
        "installed": installed,
        "newest": newest,
        "absent": absent,
        "download_bytes": SIZE,
    }


CURRENT, TCURRENT = st(NEW, NEW), st(TNEW, TNEW)
OLDER, TOLDER = st(OLD, NEW), st(TOLD, TNEW)
ABSENT, TABSENT = st("unknown", NEW, True), st("unknown", TNEW, True)


def _reply(x):
    if isinstance(x, BaseException):
        raise x
    if isinstance(x, dict):
        return MagicMock(returncode=0, stdout=json.dumps(x), stderr="")
    return x


def _answers(index=CURRENT, triage=TCURRENT, fails=()):
    """index and triage: a --check state (st), a reply, or an exception to raise."""

    def absent(x):
        return isinstance(x, dict) and x.get("absent")

    def answer(cmd):
        if cmd[1:3] == ["-I", "-m"] and cmd[3:] == [INDEX, "--check"]:
            return _reply(index)
        if cmd[1:3] == ["-I", "-m"] and cmd[3:] == [TRIAGE, "--check"]:
            return _reply(triage)
        if cmd[1:3] == ["-I", "-m"] and cmd[3] in (INDEX, TRIAGE):
            return MagicMock(
                returncode=1 if cmd[3] in fails else 0, stdout="", stderr=""
            )
        # A tree without --check asks the packages whether the data is there.
        if cmd[1:] == ["-I", "-m", "rag_mcp.status", "--json", "--no-check"]:
            count = 0 if absent(index) else 5
            return MagicMock(returncode=0, stdout=json.dumps({"document_count": count}))
        if cmd[1:3] == ["-I", "-c"] and "windows_triage" in cmd[3]:
            return MagicMock(
                returncode=1 if absent(triage) else 0, stdout="", stderr=""
            )
        return None

    return answer


def _with_triage(m):
    m["packages"]["windows-triage-mcp"] = {}
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
    return [c[1] for c in run.calls if c[0] == "input" and "Download" in c[1]]


def _block(run):
    return [line.strip() for line in run.block]


def _declined(box):
    return json.loads(box.manifest.read_text()).get("declined_offers", {})


def _line(what, newest, installed, kept=""):
    tail = (
        "not installed."
        if installed is None
        else f"yours is {installed}. It replaces {kept}."
    )
    return f"{what}: {newest}, a 13 MB download, {tail}"


def _never(prompt):
    raise AssertionError(f"input() called: {prompt!r}")


# --- D-2: current data is neither asked nor named -----------------------------


@pytest.mark.parametrize("flag", [None, "true"], ids=["terminal", "flag"])
def test_d2_current_data_is_not_asked_named_or_downloaded(
    box, capsys, monkeypatch, flag
):
    if flag:
        monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", flag)
    run = _run(
        box, capsys, tty=True, answers=[_never], manifest=_with_triage, data=_answers()
    )
    assert _downloads(run) == []
    assert _asked(run) == []
    named = [ln for ln in (run.out + run.err).splitlines() if NEW in ln or TNEW in ln]
    assert named == [], named


# --- D-3: a --check that fails is one line per kind, and the update goes on ---


OFFLINE = "<urlopen error [Errno -3] Temporary failure in name resolution>"
LIMITED = "HTTP Error 403: rate limit exceeded"


def _failed(what, reason):
    return MagicMock(
        returncode=1, stdout="", stderr=f"Could not check for {what}: {reason}\n"
    )


@pytest.mark.parametrize(
    "index, triage, reason",
    [
        (
            _failed("a newer RAG index", OFFLINE),
            _failed("newer triage databases", OFFLINE),
            OFFLINE,
        ),
        (
            _failed("a newer RAG index", LIMITED),
            _failed("newer triage databases", LIMITED),
            LIMITED,
        ),
        (
            subprocess.TimeoutExpired(["python"], 120),
            subprocess.TimeoutExpired(["python"], 120),
            "no reply in 120 s",
        ),
    ],
    ids=["offline", "rate-limited", "timeout"],
)
def test_d3_a_failed_check_is_one_line_per_kind_and_the_update_goes_on(
    box, capsys, index, triage, reason
):
    up = _run(box, capsys, tty=True, manifest=_with_triage, data=_answers())
    run = _run(box, capsys, tty=True, answers=[_never], data=_answers(index, triage))
    lines = [ln for ln in run.out.splitlines() if "Couldn't check for newer" in ln]
    assert lines == [
        f"  Couldn't check for newer knowledge index ({reason}); nothing was changed.",
        f"  Couldn't check for newer triage databases ({reason}); nothing was changed.",
    ]
    assert _downloads(run) == [] and _asked(run) == []
    assert (run.rc, run.state.get("status")) == (up.rc, up.state.get("status"))


# --- D-4: a No is recorded with the release; a newer release is asked ---------


def test_d4_a_no_is_kept_for_that_release_and_a_newer_one_is_asked(box, capsys):
    first = _run(box, capsys, tty=True, answers=["n"], data=_answers(OLDER))
    want = _line("Knowledge index", NEW, OLD, INDEX_KEPT)
    assert _asked(first) == [f"\n  {want} Download it now? [Y/n] "]
    assert _downloads(first) == []
    assert _declined(box).get(INDEX_OFFER) == [NEW]
    again = _run(box, capsys, tty=True, answers=["y"], data=_answers(OLDER))
    assert _asked(again) == [] and _downloads(again) == []
    assert (
        f"Declined earlier: {INDEX_OFFER} ({NEW}). It is asked again when that changes."
        in _block(again)
    )
    newer = _run(box, capsys, tty=True, answers=["n"], data=_answers(st(OLD, NEWER)))
    assert [NEWER in q for q in _asked(newer)] == [True]


# --- D-5 (and Y1's off legs): no terminal, the flag not "true" ----------------


@pytest.mark.parametrize(
    "flag", [None, "false", "1", ""], ids=["unset", "false", "1", "empty"]
)
@pytest.mark.parametrize("index", [OLDER, ABSENT], ids=["older", "absent"])
def test_d5_no_terminal_is_not_asked_and_says_so(box, capsys, monkeypatch, flag, index):
    if flag is not None:
        monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", flag)
    run = _run(box, capsys, tty=False, answers=[_never], data=_answers(index))
    assert _downloads(run) == [] and _asked(run) == []
    assert (
        f"Not asked (no terminal): {INDEX_OFFER}."
        " Re-run `vhir update` in a terminal to be asked."
    ) in _block(run)


# --- D-10: one path for data: update.py fetches nothing itself (GUARD) -------


def test_d10_update_fetches_no_data_itself():
    src = inspect.getsource(update)
    assert [w for w in ("api.github.com", "urlopen", "requests") if w in src] == []


# --- D-12: --check once per kind, one clock, its reason in the line ----------


def test_d12_check_has_one_120_s_clock_and_its_reason_in_the_line(capsys):
    check = getattr(update, "_data_check", None)
    assert check is not None, "no --check reader"
    seen = []

    def run(cmd, **kw):
        seen.append(([str(c) for c in cmd], kw))
        return _failed("a newer RAG index", LIMITED)

    with patch("subprocess.run", side_effect=run):
        assert check("/venv/bin/python", INDEX, "knowledge index") is None
    assert seen == [
        (
            ["/venv/bin/python", "-I", "-m", INDEX, "--check"],
            {"capture_output": True, "text": True, "timeout": 120},
        )
    ]
    assert capsys.readouterr().out == (
        f"  Couldn't check for newer knowledge index ({LIMITED}); nothing was changed.\n"
    )


def test_d12_check_runs_once_per_kind(box, capsys):
    whole = _run(box, capsys, tty=True, manifest=_with_triage, data=_answers())
    checks = [c for c in whole.calls if c[4:] == ["--check"]]
    assert checks == [
        [_python(box), "-I", "-m", INDEX, "--check"],
        [_python(box), "-I", "-m", TRIAGE, "--check"],
    ]


# --- Y1: the flag downloads older or absent data without a question ----------


@pytest.mark.parametrize(
    "index, triage, lines",
    [
        (
            OLDER,
            TOLDER,
            [
                _line("Knowledge index", NEW, OLD, INDEX_KEPT),
                _line("Triage databases", TNEW, TOLD, TRIAGE_KEPT),
            ],
        ),
        (
            ABSENT,
            TABSENT,
            [
                _line("Knowledge index", NEW, None),
                _line("Triage databases", TNEW, None),
            ],
        ),
    ],
    ids=["older", "absent"],
)
def test_y1_the_flag_downloads_the_offered_tag_and_owes_the_restart(
    box, capsys, monkeypatch, index, triage, lines
):
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    run = _run(
        box, capsys, tty=False, no_restart=True, answers=[_never], manifest=_with_triage,
        data=_answers(index, triage),
    )  # fmt: skip
    assert _asked(run) == []
    assert _downloads(run) == [
        [_python(box), "-I", "-m", INDEX, "--tag", NEW],
        [_python(box), "-I", "-m", TRIAGE, "--tag", TNEW],
    ]
    said = [ln for ln in run.out.splitlines() if "Downloading it" in ln]
    assert said == [
        f"  {ln} Downloading it (VHIR_ASSUME_DEFAULTS is set)." for ln in lines
    ]
    assert (run.state.get("status"), run.state.get("reason")) == ("pending", RESTART)


def test_y1_control_the_flag_with_nothing_to_download_owes_no_restart(
    box, capsys, monkeypatch
):
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    run = _run(
        box, capsys, tty=False, no_restart=True, manifest=_with_triage, data=_answers()
    )
    assert _downloads(run) == []
    assert run.state.get("status") == "complete", run.state


def test_y1b_a_recorded_no_beats_the_flag(box, capsys, monkeypatch):
    m = json.loads(box.manifest.read_text())
    m["declined_offers"] = {INDEX_OFFER: [NEW]}
    box.manifest.write_text(json.dumps(m))
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    run = _run(box, capsys, tty=False, answers=[_never], data=_answers(OLDER))
    assert _downloads(run) == []
    assert (
        f"Declined earlier: {INDEX_OFFER} ({NEW}). It is asked again when that changes."
        in _block(run)
    )


# --- Y4: an empty answer is Yes; any other non-yes is No, recorded -----------


def test_y4_an_empty_answer_downloads_absent_data(box, capsys):
    run = _run(box, capsys, tty=True, answers=[""], data=_answers(ABSENT))
    assert _asked(run) == [
        f"\n  {_line('Knowledge index', NEW, None)} Download it now? [Y/n] "
    ]
    assert _downloads(run) == [[_python(box), "-I", "-m", INDEX, "--tag", NEW]]
    assert INDEX_OFFER not in _declined(box)


@pytest.mark.parametrize("reply", ["n", "x", EOFError], ids=["n", "x", "eof"])
def test_y4_a_non_yes_downloads_nothing_and_is_recorded(box, capsys, reply):
    run = _run(box, capsys, tty=True, answers=[reply], data=_answers(ABSENT))
    assert len(_asked(run)) == 1 and NEW in _asked(run)[0]
    assert _downloads(run) == []
    assert _declined(box).get(INDEX_OFFER) == [NEW]


# --- Y5: a triage install no reader can name (a database changed) ------------

UNKNOWN = st("unknown", TNEW)
UNKNOWN_LINE = _line("Triage databases", TNEW, "unknown", TRIAGE_KEPT)


def test_y5_unknown_triage_is_offered_on_a_terminal(box, capsys):
    run = _run(
        box, capsys, tty=True, answers=["y"], manifest=_with_triage,
        data=_answers(CURRENT, UNKNOWN),
    )  # fmt: skip
    assert _asked(run) == [f"\n  {UNKNOWN_LINE} Download it now? [Y/n] "]
    assert _downloads(run) == [[_python(box), "-I", "-m", TRIAGE, "--tag", TNEW]]


def test_y5_the_flag_leaves_unknown_triage_and_names_the_command(
    box, capsys, monkeypatch
):
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    run = _run(
        box, capsys, tty=False, answers=[_never], manifest=_with_triage,
        data=_answers(OLDER, UNKNOWN),
    )  # fmt: skip
    cmd = f"{_python(box)} -I -m {TRIAGE} --tag {TNEW}"
    assert (
        f"Not asked (VHIR_ASSUME_DEFAULTS is set): {UNKNOWN_LINE} To download it: {cmd}"
        in _block(run)
    )
    assert _downloads(run) == [[_python(box), "-I", "-m", INDEX, "--tag", NEW]]


# --- Y7: the other offers keep "[y/N] ", "" as No, and the flag's No (GUARD) --


@pytest.mark.parametrize(
    "offer", ["CUDA package removal", "OpenSearch upgrade", "SIFT tools update"]
)
def test_y7_the_flag_still_takes_no_at_the_other_offers(
    box, capsys, monkeypatch, offer
):
    monkeypatch.setattr("pathlib.Path.home", lambda: box.home)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setenv("VHIR_ASSUME_DEFAULTS", "true")
    assert update._may_ask(offer, ["s"], "s") is False
    assert capsys.readouterr().out == (
        f"Not asked (VHIR_ASSUME_DEFAULTS is set): {offer}."
        " Re-run `vhir update` without it to be asked.\n"
    )


@pytest.mark.parametrize(
    "offer", ["CUDA package removal", "OpenSearch upgrade", "SIFT tools update"]
)
def test_y7_an_empty_answer_at_the_other_offers_is_no_and_recorded(
    box, monkeypatch, offer
):
    monkeypatch.setattr("pathlib.Path.home", lambda: box.home)
    monkeypatch.setattr("builtins.input", lambda q="": "")
    assert update._confirm(offer, ["s"], "  Remove them now? [y/N] ") is False
    assert _declined(box) == {offer: ["s"]}


def test_y7_only_the_data_offer_and_the_key_upgrade_ask_y_n():
    other = inspect.getsource(update).replace(inspect.getsource(update._offer_data), "")
    assert other.count("[Y/n]") == 1  # the key upgrade's own prompt (update.py:257)
