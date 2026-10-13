"""The passphrase rule, applied wherever a passphrase is set.

At least 8 code points (as in 0.6) and at most 256, with no composition rules.
15 or more is recommended and printed at every point that sets one; the
examiner decides. A passphrase that is a common one, is built mostly from the
examiner's name or product words, or is one repeated character or a keyboard
run, is accepted with a warning that names the reason. Code points are
counted after UTF-8 decoding; nothing is normalised.
"""

from __future__ import annotations

import re

MIN_LENGTH = 8
MAX_LENGTH = 256
RECOMMENDED = 15

RECOMMENDATION = (
    "At least 8 characters; 15 or more recommended, for example four or more "
    "unrelated words. The longer it is, the harder it is to guess from the files "
    "on this machine."
)

_PRODUCT_WORDS = frozenset({"vhir", "valhuntir", "sift"})

# Common passphrases of 15 or more characters (shorter ones get the length
# warning). Matched ignoring case. A short list: the warning names the reason,
# and the examiner decides.
_COMMON = frozenset(
    {
        "passwordpassword",
        "password1234567",
        "password12345678",
        "password123456789",
        "123456789012345",
        "1234567890123456",
        "qwertyuiopasdfgh",
        "qwertyuiopasdfghjkl",
        "1q2w3e4r5t6y7u8i",
        "correcthorsebatterystaple",
        "correct horse battery staple",
        "iloveyouiloveyou",
        "letmeinletmein1",
        "welcome12345678",
        "changemechangeme",
        "administrator123",
    }
)


def _run(text: str) -> bool:
    """One character repeated, or an ascending or descending run, end to end."""
    if len(set(text)) == 1:
        return True
    steps = {ord(b) - ord(a) for a, b in zip(text, text[1:], strict=False)}
    return steps in ({1}, {-1})


def check(passphrase: str, examiner: str = "") -> tuple[str | None, list[str]]:
    """`(error, warnings)`: an error when the length is outside 8-256 code
    points (the passphrase is refused); otherwise the reasons to choose a
    stronger one, each a sentence (the passphrase is accepted)."""
    n = len(passphrase)
    if n < MIN_LENGTH:
        return (
            f"Passphrase must be at least {MIN_LENGTH} characters (yours is {n}).",
            [],
        )
    if n > MAX_LENGTH:
        return f"Passphrase must be at most {MAX_LENGTH} characters (yours is {n}).", []
    warnings = []
    if n < RECOMMENDED:
        warnings.append(
            f"Your passphrase is {n} characters; {RECOMMENDED} or more is recommended."
        )
    if passphrase.lower() in _COMMON:
        warnings.append("It's a commonly used passphrase.")
    elif _run(passphrase):
        warnings.append("It's one character repeated, or a run of characters.")
    else:
        context = set(_PRODUCT_WORDS)
        if len(examiner) >= 3:
            context.add(examiner.lower())
        tokens = [t for t in re.split(r"\W+", passphrase) if t]
        rest = [t for t in tokens if t.lower() not in context]
        if len(rest) < len(tokens) and len("".join(rest)) < RECOMMENDED:
            warnings.append(
                "Most of it is your name or product words (vhir, valhuntir, sift)."
            )
    return None, warnings
