"""defang_iocs runs an IOC's pattern only where the IOC's fold occurs in the
text's fold, as one anchored match at that place, never a search, sub or
scan over the whole text. Counted, not timed."""

from __future__ import annotations

import re
import types

import pytest

# isort: split
import vhir_cli.defang
from vhir_cli.defang import defang_iocs


@pytest.fixture
def pattern_calls(monkeypatch):
    """Each call defang_iocs makes on a pattern it compiles, as its method
    name. The module's own re is swapped for one whose compile hands back
    the real pattern wrapped, so nothing else sees the change."""
    calls = []

    class Counted:
        def __init__(self, pattern):
            self.pattern = pattern

        def __getattr__(self, method):
            def call(*args, **kwargs):
                calls.append(method)
                return getattr(self.pattern, method)(*args, **kwargs)

            return call

    spy = types.ModuleType("re")
    spy.__dict__.update(re.__dict__)
    spy.compile = lambda *args, **kwargs: Counted(re.compile(*args, **kwargs))
    monkeypatch.setattr(vhir_cli.defang, "re", spy)
    return calls


def test_an_iocs_pattern_runs_only_where_its_fold_occurs(pattern_calls):
    iocs = ["evil.com", "10.1.2.3", "bad.example.org"]  # the last only inside a name
    text = "\n".join(["Beacon to EVIL.com from 10.1.2.3; notbad.example.org"] * 2000)
    line = "Beacon to EVIL[.]com from 10[.]1[.]2[.]3; notbad.example.org"
    want = "\n".join([line] * 2000)
    assert defang_iocs(text, iocs) == want
    # one anchored match where each fold occurs, a miss included; a search,
    # sub or scan over the text would run the pattern across all of it
    assert set(pattern_calls) == {"match"}
    assert len(pattern_calls) == 3 * 2000
