"""The conftest guard refuses every way of reaching its directory.

It's pointed at a stand-in here, never at /var/lib/vhir. Backup and the
installer reach the real one through chown, utime, links and subprocesses
such as cp and chown, which the guard didn't see.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

guard = next(
    m for n, m in sys.modules.items() if n.endswith("conftest") and hasattr(m, "_HITS")
)

OPERATIONS = {
    "chown": lambda p, q: os.chown(p, os.getuid(), os.getgid()),
    "utime": lambda p, q: os.utime(p),
    "truncate": lambda p, q: os.truncate(p, 0),
    "link": lambda p, q: os.link(p, q),
    "symlink": lambda p, q: os.symlink(p, q),
    "cp": lambda p, q: subprocess.run(["cp", str(p), str(q)], check=True),
    "chown command": lambda p, q: subprocess.run(
        ["chown", str(os.getuid()), str(p)], check=True
    ),
    "open": lambda p, q: open(p).close(),
}


@pytest.fixture
def stand_in(tmp_path, monkeypatch):
    root = tmp_path / "var-lib-vhir"
    (root / "verification").mkdir(parents=True)
    (root / "verification" / "CASE.jsonl").write_text("{}\n")
    monkeypatch.setattr(guard, "_ROOT", str(root))
    return root


@pytest.mark.parametrize("operation", sorted(OPERATIONS))
def test_each_way_in_is_refused(stand_in, operation):
    target = stand_in / "verification" / "CASE.jsonl"
    n = len(guard._HITS)
    try:
        with pytest.raises(PermissionError):
            OPERATIONS[operation](target, stand_in / "verification" / "copy")
        hits = guard._HITS[n:]
    finally:
        del guard._HITS[n:]  # this test's own hits, recorded on purpose
    assert hits and all(str(stand_in) in h for h in hits), hits
    # Checked with stat, which the guard doesn't see: nothing happened.
    assert target.stat().st_size == 3
    assert not (stand_in / "verification" / "copy").exists()


def test_the_same_operations_elsewhere_go_through(stand_in, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    target = other / "f"
    target.write_text("x")
    n = len(guard._HITS)
    for name, operation in sorted(OPERATIONS.items()):
        if name in ("link", "symlink", "cp"):
            operation(target, other / f"copy-{name.replace(' ', '-')}")
        else:
            operation(target, None)
    assert guard._HITS[n:] == []
    assert shutil.which("cp") and shutil.which("chown")
