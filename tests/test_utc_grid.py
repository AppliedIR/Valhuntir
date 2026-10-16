"""Every stored timestamp shape against every since shape: export_bundle's
comparator agrees with the true instant on this Python, 3.10 included
(its fromisoformat takes only 3/6-digit fractions and ±HH:MM). Extreme
dates that overflow on conversion compare as text instead of crashing.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

import pytest

from vhir_cli.case_io import _at_or_after, export_bundle

# Stored values every writer produces, and the shapes the timestamp validator
# admits (Z, ±HH:MM, ±HHMM, 1/3/6-digit fractions, naive, no seconds, date only).
STORED = [
    "2026-10-02T08:38:43.215123+00:00",
    "2026-10-02T08:38:43Z",
    "2026-10-02T08:38:43.5Z",
    "2026-10-02T08:38:43.1Z",
    "2026-10-02T08:38:43.215Z",
    "2026-10-02T14:08:43+05:30",
    "2026-10-02T14:08:43+0530",
    "2026-10-02T03:38:43-0500",
    "2026-10-02T03:38:43.25-05:00",
    "2026-10-02T08:38:43",
    "2026-10-02T08:38",
    "2026-10-02",
]
BOUNDS = [
    "2026-10-02T08:38:43Z",
    "2026-10-02T08:38:43.5Z",
    "2026-10-02T14:08:43+0530",
    "2026-10-02T14:08:43.300+05:30",
    "2026-10-02T03:38:43-0500",
    "2026-10-02T08:38:43",
    "2026-10-02",
    "2026-10-01T23:00:00-0100",
]
_SHAPE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?"
    r"(Z|[+-]\d{2}:?\d{2})?$"
)


def _instant(ts):
    """The true instant, parsed by hand (naive and date-only read as UTC)."""
    y, mo, d, h, mi, s, frac, off = _SHAPE.match(ts).groups()
    micro = int((frac or "").ljust(6, "0")[:6] or 0)
    t = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0), micro)
    if off and off != "Z":
        sign = -1 if off[0] == "-" else 1
        hh, mm = off[1:].replace(":", "")[:2], off[1:].replace(":", "")[2:]
        t -= sign * timedelta(hours=int(hh), minutes=int(mm))
    return t


GRID = [(v, b) for v in STORED for b in BOUNDS]


@pytest.mark.parametrize("value,bound", GRID)
def test_every_shape_compares_by_instant(value, bound):
    assert _at_or_after(value, bound) == (_instant(value) >= _instant(bound))


def test_extreme_dates_dont_crash_the_export(tmp_path):
    case = tmp_path / "case-utc"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: case-utc\nstatus: open\n")
    items = [
        {"id": "first", "modified_at": "0001-01-01T00:00:00+01:00"},
        {"id": "last", "modified_at": "9999-12-31T23:59:59-01:00"},
        {"id": "now", "modified_at": "2026-10-02T08:38:43.215123+00:00"},
    ]
    (case / "findings.json").write_text(json.dumps(items))
    (case / "timeline.json").write_text("[]")
    got = export_bundle(case, since="2026-01-01T00:00:00Z")["findings"]
    assert sorted(f["id"] for f in got) == ["last", "now"]
