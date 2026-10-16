"""Artifact content longer than forensic-mcp stores is kept to its first 5000
chars, followed by a line saying so: "[cut: 5000 of N chars stored]". Every
view that shows the content shows that line, on its own line, so the examiner
knows the text is not all there: `vhir approve` and `vhir reject` with no
IDs or with --review (the whole content, behind the gutter), and `vhir review
--detail` (a short preview, then the line). `vhir approve <IDs>` and `vhir
reject <IDs>` show no artifact content, and so no line. Control characters
before the line stay escaped. Content with no such line reads as before."""

from __future__ import annotations

import pytest

from vhir_cli.commands.approve import _safe
from vhir_cli.display import one_line

from .test_finding_iocs_and_tabs_shown import _Prompt, _view, case  # noqa: F401

MARKER = "[cut: 5000 of 10198 chars stored]"
BODY = "LogonType 3 from 172.16.6.12 " * 200  # longer than any preview


def _cut(body):
    return f"{body[:5000]}\n{MARKER}"


FULL_VIEWS = ["approve", "approve-review", "reject-review"]
PREVIEW_VIEWS = ["review-detail"]
NO_CONTENT_VIEWS = ["approve-ids", "reject-ids"]
GUTTER = "      │ "
SHOWN = {**{v: GUTTER for v in FULL_VIEWS}, **{v: " " * 8 for v in PREVIEW_VIEWS}}


def _out(name, case, monkeypatch, capsys, content):  # noqa: F811
    def no_reason(prompt=""):
        raise _Prompt

    monkeypatch.setattr("vhir_cli.approval_auth.read_tty_line", no_reason)
    return _view(name, case, monkeypatch, capsys, content=content)


def _marker_lines(out):
    return [ln for ln in out.split("\n") if "[cut:" in ln]


@pytest.mark.parametrize("name", FULL_VIEWS + PREVIEW_VIEWS)
def test_a_cut_content_shows_the_cut_line_once(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, _cut(BODY))
    marks = _marker_lines(out)
    assert marks == [SHOWN[name] + MARKER], marks


@pytest.mark.parametrize("name", PREVIEW_VIEWS)
def test_the_preview_ends_then_the_cut_line_follows(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, _cut(BODY))
    lines = out.split("\n")
    at = next(i for i, ln in enumerate(lines) if "[cut:" in ln)
    assert lines[at - 1].endswith("..."), lines[at - 1]
    assert lines[at] == " " * 8 + MARKER
    assert BODY[:200] in out and BODY[:201] not in out


@pytest.mark.parametrize("name", FULL_VIEWS)
def test_the_whole_stored_text_then_the_cut_line(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, _cut(BODY))
    lines = out.split("\n")
    at = next(i for i, ln in enumerate(lines) if "[cut:" in ln)
    assert lines[at - 1] == GUTTER + BODY[:5000].split("\n")[-1]
    assert lines[at] == GUTTER + MARKER


@pytest.mark.parametrize("end", ["\t", "\r", "\x1b[2J"])
@pytest.mark.parametrize("name", FULL_VIEWS + PREVIEW_VIEWS)
def test_a_control_character_before_the_cut_line_stays_escaped(
    name,
    end,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    for body in (BODY[:4990] + end, "short evidence" + end):
        out = _out(name, case, monkeypatch, capsys, f"{body}\n{MARKER}")
        assert "\t" not in out and "\r" not in out and "\x1b[2J" not in out
        assert _marker_lines(out) == [SHOWN[name] + MARKER]
        lines = out.split("\n")
        before = lines[lines.index(SHOWN[name] + MARKER) - 1]
        if name in PREVIEW_VIEWS and len(body) > 200:
            assert before == " " * 8 + body[:200] + "..."
        else:
            escape = one_line if name in PREVIEW_VIEWS else _safe
            assert before == SHOWN[name] + escape(body)
            assert escape(body) != body


@pytest.mark.parametrize("name", FULL_VIEWS + PREVIEW_VIEWS)
def test_content_with_no_cut_line_reads_as_before(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, BODY)
    assert "[cut:" not in out


@pytest.mark.parametrize("name", PREVIEW_VIEWS)
def test_a_cut_line_not_at_the_end_is_text_like_any_other(
    name,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    out = _out(name, case, monkeypatch, capsys, f"{BODY}\n{MARKER}\nmore")
    assert "[cut:" not in out


@pytest.mark.parametrize("name", PREVIEW_VIEWS)
def test_a_short_preview_shows_the_cut_line_once(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, f"short evidence\n{MARKER}")
    assert _marker_lines(out) == [" " * 8 + MARKER]
    assert "short evidence\n" + " " * 8 + MARKER in out


@pytest.mark.parametrize("name", NO_CONTENT_VIEWS)
def test_approving_by_id_shows_no_content_and_no_cut_line(
    name,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    out = _out(name, case, monkeypatch, capsys, _cut(BODY))
    assert "F-tester-001" in out
    assert "[cut:" not in out and BODY[:40] not in out
