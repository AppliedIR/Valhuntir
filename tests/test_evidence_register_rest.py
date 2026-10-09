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


def _cli(case, *args):
    """`vhir evidence register …` in a new session: no controlling terminal."""
    import subprocess
    import sys

    code = "import sys; from vhir_cli.main import main; sys.argv = ['vhir', *sys.argv[1:]]; main()"
    env = {**os.environ, "VHIR_CASE_DIR": str(case), "VHIR_EXAMINER": "tester"}
    return subprocess.run([sys.executable, "-c", code, "evidence", "register", *args],
                          env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          start_new_session=True, timeout=60)  # fmt: skip


def _files(case):
    return json.loads((case / "evidence.json").read_text())["files"]


def test_cli_registration_without_a_terminal_registers_nothing(case):
    (case / "CASE.yaml").write_text("case_id: case\n")
    p = case / "evidence" / "samples.7z"
    p.write_bytes(b"IMG1")
    r = _cli(case, str(p))
    assert r.returncode != 0 and _files(case) == [], r.stderr
    register_evidence_data(case, str(p), "tester")  # registered with a terminal
    p.write_bytes(b"IMG2")
    r = _cli(case, "--force-reregister", str(p))
    assert r.returncode != 0 and "previous_hashes" not in _files(case)[0], r.stderr
    assert _files(case)[0]["sha256"] == _sha(b"IMG1")  # the baseline stays


@pytest.mark.parametrize("answer", [True, False], ids=["confirmed", "declined"])
def test_cli_registration_asks_the_examiner_first(case, monkeypatch, capsys, answer):
    from types import SimpleNamespace

    from vhir_cli.commands import evidence as ev

    asked = []
    monkeypatch.setattr(
        ev, "require_tty_confirmation", lambda q: asked.append(q) or answer
    )
    monkeypatch.setattr(ev, "get_case_dir", lambda c: case)
    p = case / "evidence" / "samples.7z"
    p.write_bytes(b"IMG1")
    args = SimpleNamespace(
        path=str(p), description="", force_reregister=False, case=None
    )
    if answer:
        ev.cmd_register_evidence(args, {"os_user": "t", "examiner": "tester"})
        assert len(_files(case)) == 1
    else:
        with pytest.raises(SystemExit) as e:
            ev.cmd_register_evidence(args, {"os_user": "t", "examiner": "tester"})
        assert e.value.code != 0 and _files(case) == []
    assert len(asked) == 1 and str(p) in asked[0]


def test_a_file_under_the_cases_extractions_is_refused(case):
    s2 = case / "extractions" / "op-7z-001" / "sample2.raw"
    s2.parent.mkdir()
    s2.write_bytes(b"MEMORY-SAMPLE-2")
    with pytest.raises(ValueError, match="under this case's extractions/"):
        register_evidence_data(case, str(s2), "tester", registered_via="mcp")
    with pytest.raises(ValueError, match="under this case's extractions/"):
        register_evidence_data(case, str(s2.parent), "tester")  # a folder of them
    assert _files(case) == []


def test_a_bash_made_file_elsewhere_with_no_record_registers_as_the_ais(case):
    """No record to refuse it by: it registers, labelled as the AI's."""
    made = case / "work" / "sample2.raw"
    made.parent.mkdir()
    made.write_bytes(b"MEMORY-SAMPLE-2-from-bash")
    r = register_evidence_data(case, str(made), "tester", registered_via="mcp")
    assert r["registered_via"] == "mcp" and _files(case)[0]["path"] == str(
        made.resolve()
    )


def _record(case, log, **entry):
    with open(case / "audit" / f"{log}.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def test_this_cases_recorded_output_is_refused_naming_its_operation(case, tmp_path):
    out = case / "work" / "vol-pslist-sample2.txt"
    out.parent.mkdir()
    out.write_text("PID PPID ImageFileName\n4 0 System\n")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-007", tool="run_command",
            result_summary={"output_file": str(out), "output_sha256": _sha(out.read_bytes())})  # fmt: skip
    with pytest.raises(ValueError, match="sift-tester-20261009-007"):
        register_evidence_data(case, str(out), "tester")
    # the same record in another case's trail is never consulted
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "audit").mkdir(parents=True)
    other = case / "work" / "same.txt"
    other.write_text("PID PPID ImageFileName\n4 0 System\n")
    _record(elsewhere, "sift-mcp", audit_id="sift-x-1", tool="run_command",
            result_summary={"output_file": str(other), "output_sha256": _sha(other.read_bytes())})  # fmt: skip
    register_evidence_data(case, str(other), "tester")


@pytest.mark.parametrize("relative", [True, False], ids=["case-relative", "absolute"])
def test_a_wintools_output_is_refused_by_its_sift_path(case, relative):
    csv = case / "work" / "evtx" / "20261009_EvtxECmd_Output.csv"
    csv.parent.mkdir(parents=True)
    csv.write_text("TimeCreated,EventId\n2026-10-01,4624\n")
    sift_path = "work/evtx/20261009_EvtxECmd_Output.csv" if relative else str(csv)
    _record(case, "wintools-mcp", audit_id="wt-tester-20261009-003", tool="EvtxECmd",
            outputs=[{"path": "work\\evtx\\20261009_EvtxECmd_Output.csv",
                      "sift_path": sift_path, "sha256": _sha(csv.read_bytes())}])  # fmt: skip
    with pytest.raises(ValueError, match="wt-tester-20261009-003"):
        register_evidence_data(case, str(csv), "tester")


def test_a_pending_output_matches_by_path_and_an_empty_file_never_matches(case):
    out = case / "work" / "big.raw"
    out.parent.mkdir()
    out.write_bytes(b"big")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-008", tool="run_command",
            outputs=[{"path": str(out), "sha256": "pending:hash-0123456789abcdef"}])  # fmt: skip
    with pytest.raises(ValueError, match="sift-tester-20261009-008"):
        register_evidence_data(case, str(out), "tester")
    empty = case / "work" / "empty.txt"
    empty.write_bytes(b"")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-009", tool="run_command",
            result_summary={"output_file": str(empty), "output_sha256": _sha(b"")})  # fmt: skip
    register_evidence_data(case, str(empty), "tester")


def test_a_folder_holding_a_recorded_output_is_refused(case):
    kape = case / "evidence" / "kape"
    kape.mkdir()
    (kape / "a.evtx").write_bytes(b"A")
    made = kape / "parsed.csv"
    made.write_bytes(b"parsed")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-010", tool="run_command",
            result_summary={"output_files": [str(made)], "output_sha256s": [_sha(b"parsed")]})  # fmt: skip
    with pytest.raises(ValueError, match="sift-tester-20261009-010"):
        register_evidence_data(case, str(kape), "tester")
