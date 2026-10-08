"""The shipped docs state what a verified result shows, and nothing false.

The security model described a password-keyed HMAC ledger: report
reconciliation, backups carrying password hashes for verification, a
password reset that re-signs the ledger, and a password "the AI cannot
supply". None of that is how approvals work now. These rows pin the stated
limits in the public security model, the absence of the old claims across
the shipped docs and package, the limits line verify prints, and the deny
rules every client script ships.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SECURITY = (ROOT / "docs" / "security.md").read_text()
SHIPPED = (
    [ROOT / "README.md", ROOT / "SECURITY.md"]
    + sorted((ROOT / "docs").glob("*.md"))
    + [ROOT / f"setup-client-{n}" for n in ("linux.sh", "macos.sh", "windows.ps1")]
)

LIMITS = [
    "What a pass shows.", "Offline guessing.", "Code and memory on this machine.",
    "Key changes.", "Truncation and restore.", "What a VALID line covers.", "Anchors.",
    "Verification code.", "Approvals made under 0.6", "Clocks.",
    "Status counters and labels.", "Collaboration.", "Uninstall", "Shared OS account.",
    "What file writes can do to the result.",
]  # fmt: skip

VERBATIM = [
    # what an unanchored pass prints
    "Not anchored: to prove this independently of this machine, compare the key "
    "fingerprint with a copy kept off it (any earlier report, export or backup).",
    # an unanchored pass
    "Exit 0 without anchors shows that the case files and the ledger on this machine "
    "agree with each other. It doesn't show that the keys that signed them are the "
    "examiners' own: files on this machine can contain a key no examiner made.",
    # the passphrase rule
    "The minimum is 8 characters, as in 0.6; 15 or more is recommended, and the "
    "examiner chooses.",
    # what the deny rules do
    "Valhuntir's Claude Code settings deny `vhir approve` and `vhir reject` to the "
    "assistant's shell tool. This guards against an accidental or instructed run. It "
    "doesn't stop a process with administrative rights, or a program that drives vhir "
    "through a pseudo-terminal.",
    # anchors
    "An anchor is a fingerprint (or head) held somewhere this machine can't change",
    # approvals made under 0.6
    "They carry no signature that 0.7 can check. They record that an approval was "
    "made, not who made it.",
    # a folder copied by hand
    "A folder copied by hand shares its case's identity; before signing in a copy, "
    "give it its own with `vhir case new-identity`.",
    # collaboration: a bundle's chains are data
    "An import never replaces a local APPROVED or REJECTED item, and adds no chain file",
    # the accepted residuals, verbatim
    "A copied key or an observed password can sign later lines, and those lines verify "
    "VALID. Rotating the key doesn't invalidate lines signed before the rotation. This "
    "build doesn't protect against that, or detect it, while the AI keeps sudo.",
    "verify can't prove the case's first line and key are the originals using only "
    "this machine; comparing the key fingerprint with any earlier copy that left the "
    "machine (a backup, report or export) proves it; and a verdict is independent of "
    "this machine only when it's run off it.",
]


def test_the_security_model_states_every_limit_in_order():
    found = [re.search(rf"^{n}\. \*\*{re.escape(t)}", SECURITY, re.M) for n, t in
             enumerate(LIMITS, 1)]  # fmt: skip
    assert all(found), [LIMITS[i] for i, f in enumerate(found) if not f]
    assert [f.start() for f in found] == sorted(f.start() for f in found)


@pytest.mark.parametrize("text", VERBATIM)
def test_the_security_model_says_it_as_written(text):
    assert text in " ".join(SECURITY.split())


def test_the_public_model_carries_no_internal_labels():
    labels = re.findall(
        r"\b(?:SPEC-\d+|RF-\d+|DQ-\d+|R16(?:\.\d)?|[XYZVW]\d+(?:\.\d+)?|N[1-5]|C\d{2})\b",
        SECURITY,
    )
    assert labels == []


FALSE = [
    r"HMAC-signed", r"HMAC verification ledger", r"HMAC signature",
    r"re-signs? (?:all|the) (?:ledger|previously approved)",
    r"Password hash files are always included", r"password hash(?:es)? (?:restore|files)",
    r"prompts for the examiner password to verify", r"password the AI cannot supply",
    r"password entry that the AI cannot supply", r"cannot forge",
    r"rm /var/lib/vhir/passwords", r"report reconciliation",
    r"SSH access to SIFT is required for finding approval",
]  # fmt: skip


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_no_shipped_doc_makes_an_old_claim(path):
    text = path.read_text()
    hits = [p for p in FALSE if re.search(p, text, re.I)]
    assert hits == [], hits


def test_the_package_s_docstrings_make_no_old_claim():
    src = ROOT / "src" / "vhir_cli"
    for path in src.rglob("*.py"):
        text = path.read_text()
        assert "the hash is also the ledger's signing key" not in text, path
        assert "re-signs all ledger entries" not in text, path
    auth = (src / "approval_auth.py").read_text()
    assert (
        "It doesn't stop a program that runs vhir under a\npseudo-terminal, or a process "
        "with administrative rights (limit 3)." in auth
    )


def test_a_failed_verify_ends_with_the_failure_footer(tmp_path):
    from vhir_cli import ledger_verify

    (tmp_path / "CASE.yaml").write_text("case_id: C-L\n")
    (tmp_path / "findings.json").write_text(
        '[{"id": "F-x-001", "status": "APPROVED", "title": "t"}]'
    )
    (tmp_path / "timeline.json").write_text("[]")
    result = ledger_verify.verify_case(tmp_path)
    assert result.exit_code == 2
    lines = ledger_verify.render(result).splitlines()
    assert lines[-2] == ledger_verify.FAILED_FOOTER and lines[-1] == "Exit 2"
    assert (
        ledger_verify.LIMITS not in lines
    )  # "the files agree" isn't said of a failure


def test_verify_ends_with_the_limits(tmp_path, monkeypatch):
    from vhir_cli import ledger_verify

    (tmp_path / "CASE.yaml").write_text("case_id: C-L\n")
    for name in ("findings.json", "timeline.json"):
        (tmp_path / name).write_text("[]")
    lines = ledger_verify.render(ledger_verify.verify_case(tmp_path)).splitlines()
    assert lines[-2] == ledger_verify.LIMITS and lines[-1] == "Exit 0"
    assert "security/#stated-limits" in ledger_verify.LIMITS


RULES = {
    "Bash(vhir approve*)", "Bash(*vhir approve*)", "Bash(vhir reject*)",
    "Bash(*vhir reject*)",
}  # fmt: skip


@pytest.mark.parametrize("script", ["linux.sh", "macos.sh", "windows.ps1"])
def test_every_client_script_denies_approve_and_reject_as_vhir_does(script):
    from vhir_cli.commands.client_setup import _FORENSIC_DENY_RULES

    text = (ROOT / f"setup-client-{script}").read_text()
    shipped = set(re.findall(r'"(Bash\([^"]*vhir (?:approve|reject)[^"]*\))"', text))
    ours = {r for r in _FORENSIC_DENY_RULES if "approve" in r or "reject" in r}
    assert shipped == ours == RULES


def test_every_code_the_model_names_is_one_vhir_prints():
    """A status or error code named in the public model is one the code has."""
    src = "\n".join(p.read_text() for p in (ROOT / "src" / "vhir_cli").rglob("*.py"))
    codes = set(re.findall(r"`([A-Z][A-Z0-9]*_[A-Z0-9_]+)`", SECURITY))
    assert codes and sorted(c for c in codes if c not in src) == []


def test_ledger_is_described_as_the_cli_does():
    from vhir_cli.main import build_parser

    review = build_parser()._subparsers._group_actions[0].choices["review"]
    (action,) = [a for a in review._actions if "--ledger" in a.option_strings]
    assert "instead of" in action.help
    assert "reads only the given chain copies, instead of" in " ".join(SECURITY.split())
