"""Registration records what the approval check needs, and refuses what isn't
an original.

- A file entry records its stat fields (size, mtime, ctime, device, inode), so
  approval can see a registered file changed since.
- The CLI registers only with a terminal confirmation, so a shell the AI runs
  can't register as the examiner.
- A file under the case's extractions/, or one this case's own tools recorded
  as an output (matched by its SIFT path and hash), is refused, naming the
  operations, unless every one of them was an acquisition: then it registers
  as an acquired root.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from vhir_cli.commands.evidence import register_evidence_data


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "case"
    for sub in ("evidence", "extractions", "audit"):
        (d / sub).mkdir(parents=True)
    (d / "evidence.json").write_text('{"files": []}')
    return d


def test_a_file_entry_records_its_stat_fields(case):
    p = case / "evidence" / "samples.7z"
    p.write_bytes(b"S10")
    r = register_evidence_data(case, str(p), "tester")
    st = os.stat(p)
    assert (r["size"], r["mtime_ns"], r["ctime_ns"], r["st_dev"], r["st_ino"]) == (
        st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_dev, st.st_ino,
    )  # fmt: skip
    p.write_bytes(b"S10 changed")
    r = register_evidence_data(case, str(p), "tester", force_reregister=True)
    assert r["size"] == len(b"S10 changed") and r["mtime_ns"] == os.stat(p).st_mtime_ns
    assert (
        json.loads((case / "evidence.json").read_text())["files"][0]["size"]
        == r["size"]
    )
