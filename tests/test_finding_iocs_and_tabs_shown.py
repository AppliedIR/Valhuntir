"""A finding's iocs, and tab-separated quoted evidence, as each CLI view shows
them: iocs read as their values (a typed one with its type), never as the
list's Python or JSON form, and a TAB keeps its column instead of showing as
"?" or "\\x09". Every other control character stays inert, as before."""

from __future__ import annotations

import json
import re
import sys
import unicodedata
from argparse import Namespace

import pytest
import yaml

from vhir_cli import display
from vhir_cli.case_io import save_findings, save_timeline
from vhir_cli.commands import approve
from vhir_cli.commands.approve import cmd_approve
from vhir_cli.commands.reject import cmd_reject

from .signing import enrol, sign_approved

UNC = "\\\\172.16.6.12\\c$\\Users"  # as stored: two leading backslashes
SID = "S-1-5-21-2838623409-1327563992-2591358621-1136"
IOCS = ["172.16.6.12", UNC, {"value": "tdungan", "type": "user-account"}, SID]
NETSCAN = (
    "0xb50c4d057ae0\tTCPv4\t172.16.6.11\t3389\t172.16.30.23\t55264\tESTABLISHED\t-\n"
    "*** 6784\t6664\tcmd.exe\t0xb50c4e3eb0c0\t1\t-\t2\tFalse\t2023-01-25 14:52:04.000000 UTC\tN/A"
)
COLUMNS = re.compile(r"0xb50c4d057ae0 +TCPv4 +172\.16\.6\.11 +3389 ")
HOSTILE = (
    "runs:a\t\t\t\tb\n"
    "tabesc:x\t\x1b[2Jy\n"
    "tabcr:p\t\rq\n"
    "tabnul:n\t\x00m\n"
    "osc:\t\x1b]0;owned\x07z\n"
    "c1:\t\x9b2Jw"
)
OBS = "netscan shows RDP from 172.16.30.23"
IDENT = {"examiner": "analyst1", "os_user": "u", "examiner_source": "flag"}

IOC_VIEWS = [
    "review-detail",
    "approve",
    "approve-ids",
    "approve-review",
    "reject-ids",
    "reject-review",
    "report",
]
# The views that print a finding's quoted evidence (`approve <IDs>` and
# `reject <IDs>` show the finding's text, not its artifacts)
EVIDENCE_VIEWS = ["review-detail", "approve", "approve-review", "reject-review"]
# Views that show a control as an escape (the ones before the password); every
# other print shows it as "?". `vhir approve` and `vhir reject --review` list
# the DRAFT items the same way; quoted evidence is escaped in approve --review
# too.
IOC_ESCAPED = {"approve", "reject-review"}
EVIDENCE_ESCAPED = {"approve", "approve-review", "reject-review"}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-1"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-1", "status": "open"}))
    (d / "evidence.json").write_text('{"files": []}')
    (d / "todos.json").write_text("[]")
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    enrol("analyst1")
    return d


_UNSET = object()


def _finding(
    status="DRAFT",
    iocs=_UNSET,
    content=NETSCAN,
    title="Lateral movement to rd01",
    interpretation="Remote logon",
    **extra,
):
    f = {
        "id": "F-tester-001",
        "status": status,
        "title": title,
        "confidence": "MEDIUM",
        "observation": OBS,
        "interpretation": interpretation,
        "type": "finding",
        "audit_ids": ["sift-tester-20261016-001"],
        "staged": "2026-10-16T08:00:00Z",
        "modified_at": "2026-10-16T08:00:00Z",
        "created_by": "tester",
        "artifacts": [
            {
                "source": "/cases/C-1/evidence/rd01.mem",
                "extraction": "vol -f rd01.mem windows.netscan",
                "audit_id": "sift-tester-20261016-001",
                "content": content,
            }
        ],
    }
    if iocs is not _UNSET:
        f["iocs"] = iocs
    f.update(extra)
    return f


class _Prompt(BaseException):
    pass


def _approve(monkeypatch, capsys, args, cmd=cmd_approve, answer="a"):
    def prompt(*a, **k):
        raise _Prompt

    monkeypatch.setattr("vhir_cli.approval_auth.getpass_prompt", prompt)
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    try:
        cmd(args, IDENT)
    except (_Prompt, SystemExit):
        pass
    return capsys.readouterr().out


def _cli(monkeypatch, capsys, argv):
    from vhir_cli import main as m

    monkeypatch.setattr(sys, "argv", ["vhir", *argv])
    try:
        m.main()
    except SystemExit:
        pass
    return capsys.readouterr().out


def _view(name, case, monkeypatch, capsys, modified=OBS + ".", **finding):
    """One CLI view's output for a finding built from `finding`."""
    save_timeline(case, [])
    if name == "report":
        save_findings(case, [_finding(status="APPROVED", **finding)])
        sign_approved(case)
        return _cli(monkeypatch, capsys, ["report", "--findings", "F-tester-001"])
    save_findings(case, [_finding(**finding)])
    if name == "review-detail":
        return _cli(monkeypatch, capsys, ["review", "--findings", "--detail"])
    if name == "approve":
        return _approve(monkeypatch, capsys, Namespace(case=None, ids=[], review=False))
    if name == "approve-ids":
        return _approve(
            monkeypatch,
            capsys,
            Namespace(case=None, ids=["F-tester-001"], review=False),
        )
    if name == "reject-ids":
        return _approve(
            monkeypatch,
            capsys,
            Namespace(case=None, ids=["F-tester-001"], review=False, reason=""),
            cmd=cmd_reject,
            answer="r",
        )
    if name in ("approve-review", "reject-review"):
        (case / "pending-reviews.json").write_text(json.dumps({"case_id": "C-1", "items": [
            {"id": "F-tester-001", "type": "finding", "action": "approve",
             "staged_by": "analyst1",
             "modifications": {"observation": {"original": OBS, "modified": modified}}}]}))  # fmt: skip
        if name == "reject-review":
            return _approve(
                monkeypatch,
                capsys,
                Namespace(case=None, ids=[], review=True),
                cmd=cmd_reject,
                answer="r",
            )
        return _approve(monkeypatch, capsys, Namespace(case=None, ids=[], review=True))
    raise AssertionError(name)


def _iocs_lines(out):
    return [ln for ln in out.split("\n") if ln.lstrip().startswith("IOCs:")]


def _iocs_text(out):
    (line,) = _iocs_lines(out)
    return line.split("IOCs:", 1)[1].lstrip(" ")


def _no_control(line):
    return not [c for c in line if unicodedata.category(c) == "Cc"]


# ---------------------------------------------------------------- iocs, each view


@pytest.mark.parametrize("name", IOC_VIEWS)
def test_iocs_print_as_values_in_every_view(name, case, monkeypatch, capsys):
    out = _view(name, case, monkeypatch, capsys, iocs=IOCS)
    assert _iocs_text(out) == (f"172.16.6.12, {UNC}, tdungan (user-account), {SID}"), (
        _iocs_lines(out)
    )


# Each data shape a finding's iocs can hold, with the text every view shows:
# (stored iocs, text where a control shows as "?", text where it is escaped).
# None as the text: the view shows no IOCs line.
LONG = "A" * (70 * 1024)
IOC_SHAPES = {
    "typed": ([{"value": "tdungan", "type": "user-account"}], "tdungan (user-account)", None),
    "typed-empty-type": ([{"value": "rd01", "type": ""}], "rd01", None),
    "untyped-dict": ([{"value": "rd01"}], "rd01", None),
    "type-map": ({"ipv4": ["10.0.0.1", "10.0.0.2"], "user": "tdungan"},
                 "ipv4: 10.0.0.1, 10.0.0.2; user: tdungan", None),
    "list": (["172.16.6.12", UNC], f"172.16.6.12, {UNC}", None),
    "list-with-gaps": ([None, "", "rd01", []], "rd01", None),
    "string": ("172.16.6.12", "172.16.6.12", None),
    "number": (3389, "3389", None),
    "numbers-in-list": ([3389, 1.5, True], "3389, 1.5, True", None),
    "none": (None, None, None),
    "missing": (_UNSET, None, None),
    "empty-string": ("", None, None),
    "empty-list": ([], None, None),
    "controls": (["a\tb", "x\x1b[2Jy", "p\rq", "n\x00m", "c\x9bw"],
                 "a       b, x?[2Jy, p?q, n?m, c?w",
                 "a       b, x\\x1b[2Jy, p\\x0dq, n\\x00m, c\\x9bw"),
    "control-in-type": ([{"value": "v", "type": "t\x1b]0;owned\x07"}],
                        "v (t?]0;owned?)", "v (t\\x1b]0;owned\\x07)"),
    "very-long": ([LONG], LONG, None),
    "non-ascii": (["пользователь", {"value": "ユーザー", "type": "user-account"}, "\u202eexe.txt"],
                  "пользователь, ユーザー (user-account), ?exe.txt",
                  "пользователь, ユーザー (user-account), \\u202eexe.txt"),
    "html-js": (["<script>alert(1)</script>", "a&b\"c'd"],
                "<script>alert(1)</script>, a&b\"c'd", None),
    "multiple-hosts": ([{"value": "rd01", "type": "hostname"}, {"value": "dc01", "type": "hostname"},
                        {"value": "base-wkstn-05", "type": "hostname"}],
                       "rd01 (hostname), dc01 (hostname), base-wkstn-05 (hostname)", None),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(IOC_SHAPES))
@pytest.mark.parametrize("name", IOC_VIEWS)
def test_ioc_shapes_in_every_view(name, shape, case, monkeypatch, capsys):
    iocs, text, escaped = IOC_SHAPES[shape]
    kw = {} if iocs is _UNSET else {"iocs": iocs}
    out = _view(name, case, monkeypatch, capsys, **kw)
    if text is None:
        assert _iocs_lines(out) == []
        return
    want = escaped if (name in IOC_ESCAPED and escaped is not None) else text
    assert _iocs_text(out) == want, _iocs_lines(out)[:1]
    assert _no_control(_iocs_lines(out)[0])


def test_saved_report_file_holds_the_values_defanged(case, monkeypatch, capsys):
    """`report --save` writes the stored values, then defangs every IOC in the
    file: the line reads as the screen does, not as JSON."""
    save_timeline(case, [])
    save_findings(case, [_finding(status="APPROVED", iocs=IOCS)])
    sign_approved(case)
    _cli(
        monkeypatch, capsys, ["report", "--findings", "F-tester-001", "--save", "f.txt"]
    )
    (line,) = [
        ln
        for ln in (case / "reports" / "f.txt").read_text().split("\n")
        if ln.lstrip().startswith("IOCs:")
    ]
    assert "{" not in line and '"' not in line and "'" not in line, line
    assert line.endswith(f", tdungan (user-account), {SID}"), line
    assert "172.16.6.12" not in line  # each IP defanged
    assert line.count("172[.]16[.]6[.]12") == 2, line


# ------------------------------------------------- quoted evidence, each view


@pytest.mark.parametrize("name", EVIDENCE_VIEWS)
def test_tab_separated_evidence_keeps_its_columns(name, case, monkeypatch, capsys):
    out = _view(name, case, monkeypatch, capsys)
    assert COLUMNS.search(out), [ln for ln in out.split("\n") if "TCPv4" in ln]
    assert "\\x09" not in out and "TCPv4?" not in out


def _hostile_lines(name, case, monkeypatch, capsys):
    out = _view(name, case, monkeypatch, capsys, content=HOSTILE)
    tags = [t.split(":")[0] + ":" for t in HOSTILE.split("\n")]
    hits = [ln for ln in out.split("\n") if any(t in ln for t in tags)]
    assert len(hits) == len(tags), hits
    return hits


@pytest.mark.parametrize("name", EVIDENCE_VIEWS)
def test_no_control_from_evidence_reaches_the_terminal(name, case, monkeypatch, capsys):
    """Tabs next to every other control: no control character is printed on
    any evidence line (the view's own colour codes are on other lines)."""
    hits = _hostile_lines(name, case, monkeypatch, capsys)
    assert all(_no_control(ln) for ln in hits), hits
    assert any("owned" in ln for ln in hits)  # shown, inert


@pytest.mark.parametrize("name", EVIDENCE_VIEWS)
def test_controls_next_to_tabs_show_as_before(name, case, monkeypatch, capsys):
    """A TAB keeps its column; every other control shows as the view showed it."""
    shown = [
        ln.split("│ ", 1)[-1].strip()
        for ln in _hostile_lines(name, case, monkeypatch, capsys)
    ]
    tags = tuple(t.split(":")[0] + ":" for t in HOSTILE.split("\n"))
    if name in EVIDENCE_ESCAPED:
        assert shown == [
            "runs:a" + " " * 26 + "b",
            "tabesc:x        \\x1b[2Jy",
            "tabcr:p \\x0dq",
            "tabnul:n        \\x00m",
            "osc:    \\x1b]0;owned\\x07z",
            "c1:     \\x9b2Jw",
        ], shown
    else:
        assert [s for s in shown if s.startswith(tags)] == [
            "runs:a" + " " * 26 + "b",
            "tabesc:x        ?[2Jy",
            "tabcr:p ?q",
            "tabnul:n        ?m",
            "osc:    ?]0;owned?z",
            "c1:     ?2Jw",
        ], shown


def _content_shown(name, out):
    """The quoted evidence lines a view printed, as text."""
    lines = out.split("\n")
    if name == "review-detail":
        i = next(n for n, ln in enumerate(lines) if ln.strip().startswith("$ vol"))
        block = []
        for ln in lines[i + 1 :]:
            if not ln.startswith("        "):
                break
            block.append(ln[8:])
        return block
    return [
        ln.split("│", 1)[1][1:]
        for ln in lines
        if "│" in ln and ln.startswith("      │")
    ]


# (stored content, what review --detail shows, what approve shows): each a
# list of lines. review --detail cuts the stored content at 200 characters
# (200 tabs show as 1600 spaces) and shows no empty content; approve shows
# content in full. A TAB stop counts characters: a wide (CJK) character is one.
CONTENT_SHAPES = {
    "string": ("cmd.exe /c whoami", ["cmd.exe /c whoami"], ["cmd.exe /c whoami"]),
    "tab-columns": ("a\tbb\tccc", ["a       bb      ccc"], ["a       bb      ccc"]),
    "number": (3389, ["3389"], ["3389"]),
    "none": (None, [], ["None"]),
    "empty-string": ("", [], [""]),
    "list": (["a\tb"], ["['a\\tb']"], ["['a\\tb']"]),
    "dict": ({"k": "v"}, ["{'k': 'v'}"], ["{'k': 'v'}"]),
    "very-long-tabs": ("\t" * (9 * 1024) + "end",
                       [" " * (8 * 200) + "..."], [" " * (8 * 9 * 1024) + "end"]),
    "non-ascii": ("пользователь\tユーザー\t\u202eexe", ["пользователь    ユーザー    ?exe"],
                  ["пользователь    ユーザー    \\u202eexe"]),
    "html-js": ("<b>\t</b>&\"'", ["<b>     </b>&\"'"], ["<b>     </b>&\"'"]),
    "multiple-hosts": ("rd01\t172.16.6.11\ndc01\t172.16.4.4",
                       ["rd01    172.16.6.11", "dc01    172.16.4.4"],
                       ["rd01    172.16.6.11", "dc01    172.16.4.4"]),
}  # fmt: skip


@pytest.mark.parametrize("shape", list(CONTENT_SHAPES))
@pytest.mark.parametrize("name", EVIDENCE_VIEWS)
def test_evidence_shapes_in_every_view(name, shape, case, monkeypatch, capsys):
    content, review_shows, approve_shows = CONTENT_SHAPES[shape]
    out = _view(name, case, monkeypatch, capsys, content=content)
    want = review_shows if name == "review-detail" else approve_shows
    assert _content_shown(name, out) == want
    assert all(_no_control(ln) for ln in _content_shown(name, out))


# ---------------------------------------------- `approve --review`: an edited field


@pytest.mark.parametrize("name", IOC_VIEWS)
def test_tab_in_title_and_interpretation_keeps_its_column(
    name, case, monkeypatch, capsys
):
    """Every view, `approve <IDs>` and `reject <IDs>` included, prints the
    finding's own text with a TAB as spaces to its column."""
    out = _view(
        name,
        case,
        monkeypatch,
        capsys,
        title="Lateral\tmovement to rd01",
        interpretation="Remote\tlogon",
    )
    assert "\t" not in out and "\\x09" not in out
    assert "Lateral?" not in out and "Remote?" not in out
    assert re.search(r"Lateral +movement to rd01", out), out
    assert re.search(r"Remote +logon", out), out


def test_review_diff_keeps_a_tab_column(case, monkeypatch, capsys):
    """An edited field's - before / + after lines: a TAB in the edit keeps its
    column; a control next to it stays "?"."""
    out = _view(
        "approve-review",
        case,
        monkeypatch,
        capsys,
        modified="netscan shows RDP\tfrom 172.16.30.23\t\x1b[2J",
    )
    obs = [ln for ln in out.split("\n") if re.search(r"[-+] netscan shows RDP", ln)]
    assert len(obs) == 2, obs
    assert f"- {OBS}" in obs[0]
    assert "+ netscan shows RDP       from 172.16.30.23       ?[2J" in obs[1], obs[1]
    assert "\t" not in obs[1] and "RDP?from" not in obs[1]


def _rendered(capsys, field, item, modifications):
    approve._render_field("Label", item, modifications, field)
    return capsys.readouterr().out


def test_render_field_iocs_as_values(capsys):
    item = {"iocs": IOCS}
    assert _rendered(capsys, "iocs", item, {}) == (
        f"  Label:         172.16.6.12, {UNC}, tdungan (user-account), {SID}\n"
    )


def test_render_field_iocs_edit_as_values(capsys):
    """IOCs aren't editable from the Portal today; an edit, if one were staged,
    reads as values on both lines too."""
    mod = {"iocs": {"original": [{"value": "a", "type": "t"}], "modified": ["b\tc"]}}
    out = _rendered(capsys, "iocs", {"iocs": []}, mod)
    assert "- a (t)" in out and "+ b       c" in out, out
    assert "{" not in out and "\t" not in out


def test_render_field_other_lists_still_joined(capsys):
    """A list in any other field reads as its items, as before."""
    mod = {"tags": {"original": ["x", "y"], "modified": ["x\ty", 3]}}
    assert _rendered(capsys, "tags", {"tags": ["x"]}, {}) == "  Label:         x\n"
    out = _rendered(capsys, "tags", {}, mod)
    assert "- x, y" in out and "+ x       y, 3" in out, out


# ------------------------------------------------------------- the text helpers


def test_ioc_text_shapes():
    assert (
        display.ioc_text(IOCS) == f"172.16.6.12, {UNC}, tdungan (user-account), {SID}"
    )
    assert display.ioc_text({"value": "v", "type": None}) == "v"
    assert display.ioc_text({"value": None, "type": "t"}) == "(t)"
    assert display.ioc_text({"value": ["a", "b"], "type": "ipv4"}) == "a, b (ipv4)"
    assert display.ioc_text({}) == ""
    assert display.ioc_text({"toString": None}) == "toString: "
    assert (
        display.ioc_text(None) == ""
        and display.ioc_text("") == ""
        and display.ioc_text(0) == "0"
    )


def test_ioc_text_deep_nesting_is_cut():
    deep: list = ["x"]
    for _ in range(50):
        deep = [deep]
    assert display.ioc_text(deep) == "..."
    loop: list = []
    loop.append(loop)
    assert display.ioc_text(loop) == "..."
    nested = {"value": "x"}
    for _ in range(50):
        nested = {"value": nested}
    assert display.ioc_text(nested) == "..."


def test_tab_keeps_its_column_mid_line():
    assert display.one_line("ab\tc") == "ab      c"
    assert approve._safe("ab\tc") == "ab      c"
    assert display.one_line("\t\x1b") == "        ?"
    assert approve._safe("\t\x1b") == "        \\x1b"
