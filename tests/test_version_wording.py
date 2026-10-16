"""Text a person or the AI reads names the release that changed things as
it shipped: 0.6.4. The approval-integrity and host-identity work was planned
as "0.7" and shipped in 0.6.4, so no "0.7" version wording is left."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# a version 0.7, never a size ("0.7 GB"), part of another number, or the
# prefix still read for units 0.6.4 pre-release builds wrote
VERSION = re.compile(r"(?<![0-9.])0\.7(?!\.?[0-9]|\s*GB)")
READ_ONLY = re.compile(r"\"pre-0\.7 index \"|\x27pre-0\.7\x27|\"pre-0\.7\" is what")


def test_no_0_7_version_wording_is_left():
    left = [
        f"{p.relative_to(ROOT)}:{n}"
        for p in [*sorted(ROOT.glob("src/**/*.py")), *sorted(ROOT.glob("docs/**/*.md"))]
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1)
        if VERSION.search(READ_ONLY.sub("", line))
    ]
    assert left == []
