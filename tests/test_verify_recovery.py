# ruff: noqa: F401, F811 - `case` and `steve` are the fixtures imported below
"""Each failure verify prints carries its recovery, and following it reaches
exit 0.

For the chain failures the recovery is to restore what was there from a copy
taken before the change (or cut the chain back to a recorded head), moving
the altered file aside. Each row breaks a signed case, checks the code and the
printed recovery, follows the recovery and checks the case verifies again,
anchored by the examiners' pins and the head.
"""

from __future__ import annotations

import base64
import json

from vhir_cli import ledger
from vhir_cli.ledger_verify import RECOVERY, REPLACE_NOTE, render, verify_case

from .test_verify_case import (
    AT2,
    Examiner,
    _approve,
    _chain_lines,
    _edit_again,
    _finding,
    _head_arg,
    _save,
    _status,
    _write_chain,
    case,
    steve,
)


def _codes(result) -> set[str]:
    return {c for c, _ in result.failures} | {v.status for v in result.items}


def _says_its_recovery(result, code):
    text = render(result)
    assert f"Recovery: {RECOVERY[code]}" in text, text
    assert REPLACE_NOTE in text  # a chain file is replaced only this way
    assert text.splitlines()[-1] == "Exit 2"


def _anchored(case, pins, head):
    result = verify_case(case, expect_keys=pins, expect_heads=[_head_arg(head)])
    assert result.exit_code == 0 and result.anchored, render(result)


def _bad_sig(line: str) -> str:
    obj = json.loads(line)
    sig = bytearray(base64.b64decode(obj["sig"]))
    sig[0] ^= 1
    obj["sig"] = base64.b64encode(bytes(sig)).decode()
    return json.dumps(obj)


def _set_aside(tmp_path):
    """The altered chain file, moved aside as the recovery says (never deleted)."""
    path = ledger.chain_path("C1")
    aside = tmp_path / "C1.jsonl.replaced-20261008T120000Z"
    aside.write_bytes(path.read_bytes())
    return aside


def _two(case, steve):
    fs = [_finding(1), _finding(2)]
    _save(case, findings=fs)
    _approve(case, steve, fs[0])
    return _approve(case, steve, fs[1])


def test_a_replaced_signature_on_an_earlier_line_is_restored_from_a_copy(
    case, steve, tmp_path
):
    """(a) The line is history: deciding its item again doesn't clear it."""
    _two(case, steve)
    copy = _chain_lines()  # a copy taken before the change
    _write_chain([_bad_sig(copy[0])] + copy[1:])
    _edit_again(case, steve, "F-steve-001")
    result = verify_case(case)
    assert "TAMPERED_LINE" in _codes(result) and result.exit_code == 2
    _says_its_recovery(result, "TAMPERED_LINE")
    _set_aside(tmp_path)
    now = _chain_lines()
    _write_chain([copy[0]] + now[1:])  # the original line, from the copy
    _anchored(case, [steve.pin()], ledger.current_head("C1"))


def test_a_replaced_signature_on_the_latest_line_is_restored_from_a_copy(
    case, steve, tmp_path
):
    """(b) TAMPERED on the latest line; deciding again makes it TAMPERED_LINE;
    restoring the line gives exit 0."""
    head = _two(case, steve)
    copy = _chain_lines()
    _write_chain(copy[:1] + [_bad_sig(copy[1])])
    result = verify_case(case)
    assert _status(result, "F-steve-002") == "TAMPERED" and result.exit_code == 2
    _says_its_recovery(result, "TAMPERED")
    _set_aside(tmp_path)
    _write_chain(copy)
    _anchored(case, [steve.pin()], head)


def test_a_body_edited_mid_chain_is_restored_from_a_copy(case, steve, tmp_path):
    """(f) An edited body breaks its signature and the next line's link: both
    rows say to restore from a copy."""
    fs = [_finding(n) for n in (1, 2, 3)]
    _save(case, findings=fs)
    for f in fs:
        head = _approve(case, steve, f)
    copy = _chain_lines()
    mid = json.loads(copy[1])
    mid["content_snapshot"] = mid["content_snapshot"].replace("seen", "SEEN")
    _write_chain([copy[0], json.dumps(mid), copy[2]])
    result = verify_case(case)
    assert {"TAMPERED", "CHAIN_BROKEN"} <= _codes(result) and result.exit_code == 2
    _says_its_recovery(result, "CHAIN_BROKEN")
    _set_aside(tmp_path)
    _write_chain(copy)
    _anchored(case, [steve.pin()], head)


def test_an_unpinned_key_s_line_is_pinned_or_cut_back(case, steve, tmp_path):
    """(c) A line signed with a key no pin lists, its item then decided again
    with the pinned key: case-level KEY_NOT_PINNED. Pinning that key (it is
    an examiner's) gives exit 0; otherwise, with the line after the recorded
    head, the copy that ends at that head gives exit 0 with it."""
    _save(case, findings=[_finding(1), _finding(2)])
    recorded = _approve(case, steve, _finding(1))  # the head an earlier report printed
    other = Examiner("steve")
    _approve(case, other, _finding(2))
    _edit_again(case, steve, "F-steve-002")
    result = verify_case(case, expect_keys=[steve.pin()])
    assert any(c == "KEY_NOT_PINNED" for c, _ in result.failures)
    assert result.exit_code == 2
    _says_its_recovery(result, "KEY_NOT_PINNED")
    # it is the examiner's own other key: add its pin, with its range
    _anchored(
        case, [steve.pin(), other.pin(first=2, last=2)], ledger.current_head("C1")
    )
    # it isn't: restore the copy that ends at the recorded head, and decide
    # again what was decided after it
    _set_aside(tmp_path)
    _write_chain(_chain_lines()[: recorded[0]])
    findings = json.loads((case / "findings.json").read_text())
    findings[1] = _finding(2)  # back to its state at the head
    _save(case, findings=findings)
    _anchored(case, [steve.pin()], recorded)


def test_cut_back_to_the_latest_head_every_examiner_gave(case, steve, tmp_path):
    """(g) A's head at seq 2, B's at seq 3, a line by a key of B's that no pin
    lists at seq 4: cutting back to seq 3 gives exit 0 with both heads."""
    bob = Examiner("bob")
    _save(case, findings=[_finding(n) for n in (1, 2, 3, 4)])
    _approve(case, steve, _finding(1))
    a_head = _approve(case, steve, _finding(2))
    b_head = _approve(case, bob, _finding(3))
    _approve(case, Examiner("bob"), _finding(4))  # a key of bob's no record has
    pins = [steve.pin(), bob.pin()]
    assert verify_case(case, expect_keys=pins).exit_code == 2
    _set_aside(tmp_path)
    _write_chain(_chain_lines()[: b_head[0]])
    findings = json.loads((case / "findings.json").read_text())
    findings[3] = _finding(4)
    _save(case, findings=findings)
    result = verify_case(
        case, expect_keys=pins, expect_heads=[_head_arg(a_head), _head_arg(b_head)]
    )
    assert result.exit_code == 0 and result.anchored, render(result)
