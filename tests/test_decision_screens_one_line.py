"""The decision screens print every case value on one line, its control
characters shown as "?" (approve-screen-oneline, audit 8 H1/H2, M4, L1-L5).

The analysis VM writes the case root, so a field NAME, an id, a file name or a
CASE.yaml value can hold terminal sequences. `vhir approve --review` printed
extra signed-body keys raw: a planted key painted a fake "Sign 1 decision(s)"
screen while three were signed. Each family row plants all 16 classes audit 8
used in every field the family prints, captures stdout and stderr, and asserts
that no planted sequence gets through (the product's own SGR stays). The
marker `@<field>@` proves the row reached each field.
"""

from __future__ import annotations

import json
import re
import unicodedata
from argparse import Namespace
from pathlib import Path

import pytest
import yaml

from vhir_cli import decide, ledger
from vhir_cli.approval_checks import AuditUnreadable
from vhir_cli.case_io import load_findings, save_findings, save_timeline
from vhir_cli.commands.approve import _approve_specific, cmd_approve

from .signing import PASSPHRASE, enrol

CLASSES = [  # audit 8's classes
    ("csi_up_erase", "\x1b[1A\x1b[2K"),
    ("csi_clear", "\x1b[H\x1b[2J"),
    ("cr_overwrite", "AAAA\rStatus: APPROVED"),
    ("osc52", "\x1b]52;c;ZWNobyBwd25lZA==\x07"),
    ("osc8", "\x1b]8;;http://evil.example/\x1b\\click\x1b]8;;\x1b\\"),
    ("osc0_title", "\x1b]0;pwned-title\x07"),
    ("sgr_hide", "\x1b[8mHID\x1b[0m"),
    ("sgr_black", "\x1b[30;40mBLK"),
    ("c1_csi", "\u009b2J"),
    ("c1_osc", "\u009d0;t\u0007"),
    ("bel", "\x07"),
    ("bs", "X\x08"),
    ("bidi_rlo", "‮"),
    ("bidi_iso", "⁦⁩"),
    ("zw", "​‍﻿"),
    ("nl_fake", "\nStatus: APPROVED"),
]


def pay(tag: str, classes=CLASSES) -> str:
    return f"@{tag}@" + "".join(f"<{i}>{b}" for i, (_, b) in enumerate(classes)) + "<E>"


def name_pay(tag: str) -> str:
    """For a file name: every class without a "/"."""
    return pay(tag, [(n, b.replace("/", "")) for n, b in CLASSES])


# what passes ledger.validate_case_id (no C0, no DEL): C1, bidi, zero-width
CASE_ID = "C-1" + pay("case_id", [("c1_csi", "\u009b2J"), ("c1_osc", "\u009d0;t\u009c"),
                                  ("bidi_rlo", "‮"), ("bidi_iso", "⁦⁩"),
                                  ("zw", "​‍﻿")])  # fmt: skip

_PRODUCT_SGR = re.compile(r"\x1b\[(?:0|1|2|3[0-7])m")  # approve's own colours
_UNSAFE = {"Cc", "Cf", "Cs", "Zl", "Zp"}


def assert_clean(text: str, *tags: str) -> None:
    """Every `tags` field was printed, and nothing planted reached the terminal."""
    for tag in tags:
        assert f"@{tag}@" in text, f"{tag} not printed:\n{text}"
    bare = _PRODUCT_SGR.sub("", text)
    raw = sorted(
        {repr(ch) for ch in bare if ch != "\n" and unicodedata.category(ch) in _UNSAFE}
    )
    assert raw == [], f"raw control characters {raw} in:\n{text}"
    assert "\nStatus: APPROVED" not in text


IDENT = {"examiner": "alice", "os_user": "u", "examiner_source": "flag"}


def _finding(fid, title="Prefetch: svc-upd.exe", **extra):
    item = {"id": fid, "status": "DRAFT", "title": title, "observation": "obs",
            "interpretation": "interp", "confidence": "MEDIUM", "type": "finding",
            "created_by": "alice", "staged": "2026-10-12T00:00:00Z"}  # fmt: skip
    item.update(extra)
    return item


@pytest.fixture
def case(tmp_path, monkeypatch):
    def make(case_id="C-1"):
        d = tmp_path / "C-1"
        (d / "audit").mkdir(parents=True)
        (d / "CASE.yaml").write_text(yaml.dump({"case_id": case_id, "status": "open"}))
        (d / "evidence.json").write_text('{"files": []}')
        (d / "todos.json").write_text("[]")
        monkeypatch.setenv("VHIR_EXAMINER", "alice")
        monkeypatch.setenv("VHIR_CASE_DIR", str(d))
        enrol("alice")
        return d

    return make


def _passphrase(monkeypatch, answer="n"):
    monkeypatch.setattr(
        "vhir_cli.approval_auth.getpass_prompt", lambda *a, **k: PASSPHRASE
    )
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)


def _signed(case_id) -> list[str]:
    return [
        json.loads(t)["item_id"]
        for _, t, _ in ledger.read_lines(ledger.chain_path(case_id))
        if "item_id" in json.loads(t)
    ]


# --- F1: approve and sign ------------------------------------------------------


def test_f1_review_shows_planted_keys_escaped_and_the_true_summary(
    case, monkeypatch, capsys
):
    """C1/C2: audit 8's chain. One entry is the examiner's, two are planted
    with staged_by = the examiner (audit 3 H4, out of scope); the third
    finding's extra keys paint a fake one-decision screen. The screen now
    shows the 3 decisions that are signed."""
    d = case()
    E = "\x1b"
    paint = {f"{E}[{row:02d};119f" * 2: "  Sign 1 decision(s) from pending reviews"
             for row in range(36, 40)}  # fmt: skip
    paint[f"{E}]10;#000000\x07{E}]11;#000000\x07{E}[1;2r"] = "To be signed: F-alice-001"
    planted = {pay("key"): pay("value"), **paint}
    findings = [_finding("F-alice-001"), _finding("F-alice-002"),
                _finding("F-alice-003", **planted)]  # fmt: skip
    save_findings(d, findings)
    save_timeline(d, [])
    entries = [{"id": f["id"], "type": "finding", "action": "approve",
                "staged_by": "alice"} for f in findings]  # fmt: skip
    (d / "pending-reviews.json").write_text(
        json.dumps({"case_id": "C-1", "items": entries})
    )
    _passphrase(monkeypatch)
    cmd_approve(Namespace(case=None, ids=[], review=True), IDENT)
    cap = capsys.readouterr()
    assert_clean(cap.out + cap.err, "key", "value")
    assert "Sign 3 decision(s) from pending reviews" in cap.out
    assert "To be signed: F-alice-001, F-alice-002, F-alice-003" in cap.out
    assert sorted(_signed("C-1")) == ["F-alice-001", "F-alice-002", "F-alice-003"]


def test_f1_a_copy_refusal_names_its_values_escaped(case, monkeypatch, capsys):
    """approve.py's preflight: the refusal names the case's id and folders."""
    d = case()
    save_findings(d, [_finding("F-alice-001")])
    save_timeline(d, [])
    monkeypatch.setattr(
        decide, "copy_problem", lambda _d: ledger.copy_text(pay("copy"))
    )
    with pytest.raises(SystemExit) as e:
        cmd_approve(Namespace(case=None, ids=[], review=False), IDENT)
    cap = capsys.readouterr()
    assert e.value.code == 1
    assert_clean(cap.out + cap.err, "copy")


def test_f1_an_unreadable_audit_log_is_named_escaped(case, monkeypatch, capsys):
    """AuditUnreadable, printed by main as `Error: {e}` (main.py:769, kept):
    an audit/ entry that isn't a regular file, named by the VM. The approval
    checks read audit/ for a finding with schema-2 provenance."""
    d = case()
    (d / "audit" / f"{name_pay('audit')}.jsonl").mkdir()
    link = {"audit_id": "sift-alice-1", "entry_sha256": "0" * 64}
    art = {"source": "x", "content": "c", "provenance_chain": [link]}
    save_findings(d, [_finding("F-alice-001", provenance_schema=2, artifacts=[art])])
    save_timeline(d, [])
    _passphrase(monkeypatch)
    with pytest.raises(AuditUnreadable) as e:
        _approve_specific(d, ["F-alice-001"], IDENT, d.parent / "config.yaml")
    assert_clean(f"Error: {e.value}", "audit")
    assert load_findings(d)[0]["status"] == "DRAFT"


# --- F2: after signing (decide.py) ----------------------------------------------


def test_f2_the_head_line_and_a_chain_note_are_escaped(case, monkeypatch, capsys):
    """:721 (the head line's case id) and :553 (a chain copy that isn't
    referenced), through a normal signing."""
    d = case(CASE_ID)
    chains = d / "ledger" / "chains"
    chains.mkdir(parents=True)
    (chains / f"{name_pay('chain')}.jsonl").write_text('{"seq": 2}\n')
    save_findings(d, [_finding("F-alice-001")])
    save_timeline(d, [])
    _passphrase(monkeypatch)
    _approve_specific(d, ["F-alice-001"], IDENT, d.parent / "config.yaml")
    cap = capsys.readouterr()
    assert_clean(cap.out + cap.err, "case_id", "chain")
    assert "doesn't start a chain; not referenced" in cap.err
    assert _signed(CASE_ID) == ["F-alice-001"]


def _interrupted(monkeypatch, d):
    monkeypatch.setattr(decide, "_save_twice", _raise(KeyboardInterrupt()))


def _raise(exc):
    def f(*a, **k):
        raise exc

    return f


def _torn(monkeypatch, d):
    torn = ledger.LedgerTorn(
        f"a write to {pay('torn')} failed and couldn't be cut back"
    )
    monkeypatch.setattr(ledger, "commit", _raise(torn))


def _unsaved(monkeypatch, d):
    monkeypatch.setattr(decide, "_save_twice", lambda *a, **k: OSError(pay("save")))


def _no_log(monkeypatch, d):
    (d / "approvals.jsonl").mkdir()


@pytest.mark.parametrize(
    "fault, tags, code",
    [
        (_interrupted, ("id",), 130),  # :495
        (_torn, ("torn",), 1),  # :519
        (_unsaved, ("save", "id"), 1),  # :567-568
        (_no_log, ("id",), None),  # :702-703
    ],
    ids=[
        "interrupted after signing",
        "torn ledger write",
        "save failed",
        "no activity log",
    ],
)
def test_f2_each_failure_after_signing_names_its_values_escaped(
    case, monkeypatch, capsys, fault, tags, code
):
    """Four injected faults, so each branch is reached; the id is planted."""
    d = case()
    fid = "F-alice-001" + pay("id")
    save_findings(d, [_finding(fid)])
    save_timeline(d, [])
    _passphrase(monkeypatch)
    fault(monkeypatch, d)
    if code is None:
        _approve_specific(d, [fid], IDENT, d.parent / "config.yaml")
    else:
        with pytest.raises(SystemExit) as e:
            _approve_specific(d, [fid], IDENT, d.parent / "config.yaml")
        assert e.value.code == code
    cap = capsys.readouterr()
    assert_clean(cap.out + cap.err, *tags)


# --- F3: review --audit and --verify ---------------------------------------------


def test_f3_review_audit_names_audit_files_escaped(case, capsys):
    """review.py :565 (a corrupt line) and :569 (a log it can't read)."""
    from vhir_cli.commands.review import cmd_review

    d = case()
    (d / "audit" / f"{name_pay('corrupt')}.jsonl").write_text("not json\n")
    (d / "audit" / f"{name_pay('unread')}.jsonl").mkdir()
    cmd_review(Namespace(case=None, audit=True, limit=50), IDENT)
    cap = capsys.readouterr()
    assert_clean(cap.out + cap.err, "corrupt", "unread")


def test_f3_review_verify_shows_a_chains_sources_escaped(capsys):
    """ledger_verify.render :1476: a chain's sources name the case's copies."""
    from vhir_cli.ledger_verify import Chain, Line, Result, render

    body = {"seq": 1, "case_id": "C-1"}
    line = Line(chain="c1", seq=1, obj=body, sig_ok=True, fp="fp")
    result = Result("C-1", "CASE.yaml", chains=[Chain("c1", [line], [pay("source")])])
    assert_clean(render(result), "source")


# --- F4: case status and case list ------------------------------------------------


def _hostile_case(cases: Path, name="C-1") -> Path:
    d = cases / name
    d.mkdir(parents=True)
    meta = {"case_id": pay("case_id"), "name": pay("name"), "status": pay("status"),
            "examiner": pay("examiner")}  # fmt: skip
    (d / "CASE.yaml").write_text(yaml.dump(meta))
    return d


def test_f4_case_status_and_list_show_case_yaml_escaped(tmp_path, monkeypatch, capsys):
    from vhir_cli.main import _case_list, _case_status

    d = _hostile_case(tmp_path / "cases")
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    _case_status(Namespace(case=None), IDENT)
    status = capsys.readouterr()
    assert_clean(status.out + status.err, "case_id", "name", "status", "examiner")
    _case_list(Namespace(), IDENT)
    listing = capsys.readouterr()
    assert_clean(listing.out + listing.err, "name", "status")


# --- F5: the merge, export, close and backup summary --------------------------------


def test_f5_the_anchor_summary_shows_every_value_escaped():
    from vhir_cli.case_copies import summary_lines

    summary = {
        "keys": [{"examiner": pay("examiner"), "fingerprint": pay("fingerprint"),
                  "chain_id": pay("key_chain"), "first_seq": pay("first"),
                  "last_seq": pay("last"), "label": pay("label")}],
        "heads": [{"chain_id": pay("head_chain"), "seq": pay("seq"), "hash": pay("hash")}],
        "own_diverged": pay("own"),
        "diverged": [pay("diverged")],
    }  # fmt: skip
    text = "\n".join(summary_lines(pay("case_id"), summary))
    assert_clean(text, "examiner", "fingerprint", "key_chain", "first", "last", "label",
                 "head_chain", "seq", "hash", "own", "diverged", "case_id")  # fmt: skip


# --- C3: normal values print as before ----------------------------------------------


def test_c3_normal_values_print_as_before(case, tmp_path, monkeypatch, capsys):
    from vhir_cli.case_copies import summary_lines
    from vhir_cli.main import _case_list

    d = case()
    save_findings(d, [_finding("F-alice-001", custom_field="kept as it is")])
    save_timeline(d, [])
    (d / "pending-reviews.json").write_text(json.dumps({"case_id": "C-1", "items": [
        {"id": "F-alice-001", "type": "finding", "action": "approve", "staged_by": "alice"}]}))  # fmt: skip
    _passphrase(monkeypatch)
    cmd_approve(Namespace(case=None, ids=[], review=True), IDENT)
    assert "  Custom field:   kept as it is\n" in capsys.readouterr().out

    monkeypatch.setenv("VHIR_CASES_DIR", str(d.parent))
    (d / "CASE.yaml").write_text(
        yaml.dump({"case_id": "C-1", "name": "Ransomware", "status": "open"})
    )
    _case_list(Namespace(), IDENT)
    assert f"{'C-1':<25} {'open':<10} Ransomware" in capsys.readouterr().out

    lines = summary_lines("C-1", {"keys": [{"examiner": "alice", "fingerprint": "ab12",
                          "chain_id": "c0ffee", "first_seq": 1, "last_seq": 4, "label": "this box"}],
                          "heads": [{"chain_id": "c0ffee", "seq": 4, "hash": "dead"}]})  # fmt: skip
    assert lines == ["Signing keys:", "  alice ab12 (chain c0ffee seq 1-4; this box)",
                     "Ledger head C-1 chain c0ffee: seq 4 sha256:dead"]  # fmt: skip
