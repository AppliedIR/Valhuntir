"""The passphrase rule: 8 to 256 code points; 15 or more recommended.

Under 8 or over 256 is refused. Anything in range is accepted, with a warning
when it's short, common, a run, or mostly the examiner's name or product
words: the examiner decides.
"""

from __future__ import annotations

import pytest

from vhir_cli.passphrase import RECOMMENDATION, check


@pytest.mark.parametrize(
    "pw", ["seven77", "seveén", "x" * 257], ids=["7", "7 with é", "257"]
)
def test_outside_8_to_256_code_points_is_refused(pw):
    error, _ = check(pw, "steve")
    assert error and "characters" in error


@pytest.mark.parametrize(
    "pw", ["eight888", "Tr0ub4dor&3", "eighét88"], ids=["8", "11", "8 with é"]
)
def test_8_to_14_is_accepted_with_the_recommendation(pw):
    error, warnings = check(pw, "steve")
    assert error is None
    assert (
        warnings[0]
        == f"Your passphrase is {len(pw)} characters; 15 or more is recommended."
    )


@pytest.mark.parametrize(
    "pw, reason",
    [
        ("passwordpassword", "commonly used"),
        ("aaaaaaaaaaaaaaaa", "repeated, or a run"),
        ("abcdefghijklmnop", "repeated, or a run"),
        ("steve-sift-vhir-2026", "your name or product words"),
    ],
)
def test_weak_choices_are_accepted_with_a_reason(pw, reason):
    error, warnings = check(pw, "steve")
    assert error is None and len(warnings) == 1 and reason in warnings[0]


def test_anchor_a_long_unrelated_phrase_gets_no_warning():
    assert check("albatross sifting quietly onward", "al") == (
        None,
        [],
    )  # "al" is under 3
    assert check("four unrelated words here", "steve") == (None, [])


def test_the_recommendation_text():
    assert RECOMMENDATION.startswith("At least 8 characters; 15 or more recommended")


def test_the_name_rule_alone():
    """Long enough, not common, not a run: only the name and product words."""
    error, warnings = check("STEVE-VHIR-valhuntir-sift", "steve")
    assert error is None and warnings == [
        "Most of it is your name or product words (vhir, valhuntir, sift)."
    ]
    assert check("steve sift and a long unrelated phrase", "steve") == (None, [])


def test_a_passphrase_that_is_only_the_name_gets_the_name_warning():
    error, warnings = check("steve-steve-steve-2026", "steve")
    assert error is None and warnings == [
        "Most of it is your name or product words (vhir, valhuntir, sift)."
    ]


def test_every_prompt_and_message_says_passphrase():
    """The examiner's secret is a passphrase in every prompt, message and help
    text. Exempt: the flag names (--setup-password, ...), the SMB and sudo
    passwords, and the rule's own list of weak passphrases."""
    import ast
    import re
    from pathlib import Path

    import vhir_cli

    root = Path(vhir_cli.__file__).parent
    said = []
    for path in sorted(root.rglob("*.py")):
        if path.name == "passphrase.py":
            continue
        tree = ast.parse(path.read_text())
        docs = {
            id(n.body[0].value)
            for n in ast.walk(tree)
            if isinstance(
                n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and n.body
            and isinstance(n.body[0], ast.Expr)
        }
        for n in ast.walk(tree):
            if not (isinstance(n, ast.Constant) and isinstance(n.value, str)):
                continue
            text = re.sub(r"--[\w-]+", "", n.value)  # flag names
            text = re.sub(r"(?i)(smb|sudo) password", "", text)
            if (
                id(n) not in docs
                and re.search(r"(?i)\bpassword\b", text)
                and not re.fullmatch(
                    r"[\w*()~-]*[/_.][\w./*()~-]*", n.value
                )  # paths, names
            ):
                said.append(f"{path.relative_to(root)}:{n.lineno}: {n.value!r}")
    assert said == []
