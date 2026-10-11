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
import re
from types import SimpleNamespace

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


def _winpmem(case, **entry):
    mem = case / "extractions" / "wt-acq-001" / "HOST1.raw"
    mem.parent.mkdir(parents=True)
    mem.write_bytes(b"\x00" * 4096 + b"MEM")
    _record(case, "wintools-mcp", audit_id="wt-tester-20261009-004", tool="winpmem",
            outputs=[{"path": "extractions\\wt-acq-001\\HOST1.raw",
                      "sift_path": "extractions/wt-acq-001/HOST1.raw",
                      "sha256": _sha(mem.read_bytes())}], **entry)  # fmt: skip
    return mem


def test_an_acquisitions_output_registers_as_an_acquired_root(case):
    mem = _winpmem(case, acquisition=True)
    r = register_evidence_data(case, str(mem), "tester", registered_via="mcp")
    assert (
        r["acquired_by"] == "wt-tester-20261009-004"
        and r["acquisition_tool"] == "winpmem"
    )
    assert _files(case)[0]["acquired_by"] == "wt-tester-20261009-004"


def test_a_forced_reregister_of_other_bytes_drops_the_acquisition_label(case):
    """The label is re-derived: the new bytes aren't the acquisition's output.
    (An acquisition written outside extractions/, where other bytes register.)"""
    mem = case / "evidence" / "HOST1.raw"
    mem.write_bytes(b"\x00" * 4096 + b"MEM")
    _record(case, "wintools-mcp", audit_id="wt-tester-20261009-004", tool="winpmem",
            acquisition=True, outputs=[{"sift_path": "evidence/HOST1.raw",
                                        "sha256": _sha(mem.read_bytes())}])  # fmt: skip
    assert register_evidence_data(case, str(mem), "tester")["acquired_by"]
    mem.write_bytes(b"not what winpmem wrote")
    r = register_evidence_data(case, str(mem), "tester", force_reregister=True)
    assert not {"acquired_by", "acquisition_tool"} & set(r), r
    assert not {"acquired_by", "acquisition_tool"} & set(_files(case)[0])


def test_an_output_of_an_acquisition_and_another_operation_is_refused(case):
    mem = _winpmem(case, acquisition=True, acquisition_tool="winpmem_mini_x64.exe")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-011", tool="run_command",
            result_summary={"output_file": str(mem), "output_sha256": _sha(mem.read_bytes())})  # fmt: skip
    with pytest.raises(ValueError, match="sift-tester-20261009-011"):
        register_evidence_data(case, str(mem), "tester")


def _pending_acquisition(case, job_hashed: bytes):
    """An acquisition whose output hash is still pending, and whose hash job
    closed with the hash of `job_hashed`."""
    mem = case / "evidence" / "HOST1.raw"
    mem.write_bytes(b"\x00" * 4096 + b"MEM")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-020", tool="run_command",
            acquisition=True, acquisition_tool="winpmem",
            outputs=[{"path": str(mem), "sift_path": "evidence/HOST1.raw",
                      "sha256": "pending:job-20261009-020"}])  # fmt: skip
    _record(case, "file-identity", audit_id="file-identity-20261009-021", tool="hash_complete",
            job_id="job-20261009-020", path=str(mem), sha256=_sha(job_hashed))  # fmt: skip
    return mem


def test_a_pending_acquisition_whose_job_hashed_other_bytes_grants_no_identity(case):
    mem = _pending_acquisition(case, b"\x00" * 4096 + b"MEM")
    mem.write_bytes(b"not what winpmem wrote")
    r = register_evidence_data(case, str(mem), "tester")
    assert not {"acquired_by", "acquisition_tool"} & set(r), r
    assert not {"acquired_by", "acquisition_tool"} & set(_files(case)[0])


def test_a_pending_acquisition_whose_job_hashed_these_bytes_keeps_its_identity(case):
    mem = _pending_acquisition(case, b"\x00" * 4096 + b"MEM")
    r = register_evidence_data(case, str(mem), "tester")
    assert r["acquired_by"] == "sift-tester-20261009-020"
    assert r["acquisition_tool"] == "winpmem"


def _open_acquisition(case, job="job-20261009-020"):
    """An acquisition whose output's hash is recorded as pending on `job`, with
    bytes now at its path that the acquisition never wrote."""
    mem = case / "evidence" / "HOST1.raw"
    mem.write_bytes(b"not what winpmem wrote")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-020", tool="run_command",
            acquisition=True, acquisition_tool="winpmem",
            outputs=[{"path": str(mem), "sift_path": "evidence/HOST1.raw",
                      "sha256": f"pending:{job}"}])  # fmt: skip
    return mem


def _refused_naming_op_and_job(case, path):
    with pytest.raises(ValueError, match="sift-tester-20261009-020.*job-20261009-020"):
        register_evidence_data(case, str(path), "tester")
    assert _files(case) == []


def test_an_acquisition_output_whose_hash_job_is_still_open_is_refused(case):
    mem = _open_acquisition(case)
    _refused_naming_op_and_job(case, mem)


def test_an_acquisition_output_whose_hash_job_failed_is_refused(case):
    mem = _open_acquisition(case)
    _record(case, "file-identity", audit_id="file-identity-20261009-021", tool="hash_failed",
            job_id="job-20261009-020", path=str(mem), error="read error")  # fmt: skip
    _refused_naming_op_and_job(case, mem)


def test_an_acquisition_output_closed_only_by_another_jobs_entry_is_refused(case):
    mem = _open_acquisition(case)
    _record(case, "file-identity", audit_id="file-identity-20261009-021", tool="hash_complete",
            job_id="job-20261009-099", path=str(mem), sha256=_sha(mem.read_bytes()))  # fmt: skip
    _refused_naming_op_and_job(case, mem)


def test_an_acquisition_output_its_job_closed_with_two_hashes_is_refused(case):
    mem = _open_acquisition(case)
    for n, data in enumerate((mem.read_bytes(), b"other bytes")):
        _record(case, "file-identity", audit_id=f"file-identity-20261009-02{n + 1}",
                tool="hash_complete", job_id="job-20261009-020", path=str(mem),
                sha256=_sha(data))  # fmt: skip
    _refused_naming_op_and_job(case, mem)


def test_a_folder_holding_an_acquisition_output_still_hashing_is_refused(case):
    mem = _open_acquisition(case)
    _refused_naming_op_and_job(case, mem.parent)
    assert not list(case.glob("evidence-manifests/*.json"))  # no manifest row written


def _closing(case, n, tool, rows, job="job-20261009-020"):
    """A hash job's closing entry, its rows in files[] as a list job writes them."""
    _record(case, "file-identity", audit_id=f"file-identity-20261009-03{n}", tool=tool,
            job_id=job, files=rows)  # fmt: skip


def test_a_closing_row_with_a_list_for_its_hash_crashes_no_registration(case):
    mem = _open_acquisition(case)
    _closing(case, 1, "hash_complete", [{"path": str(mem), "sha256": ["a", "b"]}])
    _refused_naming_op_and_job(case, mem)
    other = case / "evidence" / "other.txt"
    other.write_bytes(b"an original")
    assert register_evidence_data(case, str(other), "tester")["sha256"] == _sha(
        b"an original"
    )


def test_a_closing_row_with_a_number_for_its_hash_is_refused_not_crashed(case):
    mem = _open_acquisition(case)
    _closing(case, 1, "hash_complete", [{"path": str(mem), "sha256": 12345}])
    _refused_naming_op_and_job(case, mem)


def test_a_job_that_failed_and_then_completed_for_one_file_is_refused(case):
    mem = _open_acquisition(case)
    _closing(case, 1, "hash_failed", [{"path": str(mem), "error": "OSError: read"}])
    _closing(
        case, 2, "hash_complete", [{"path": str(mem), "sha256": _sha(mem.read_bytes())}]
    )
    _refused_naming_op_and_job(case, mem)


def test_a_list_job_that_failed_another_file_keeps_this_files_identity(case):
    mem = _open_acquisition(case)
    q = case / "evidence" / "HOST1.pagefile"
    _closing(case, 1, "hash_complete", [{"path": str(mem), "sha256": _sha(mem.read_bytes())},
                                        {"path": str(q), "error": "OSError: read"}])  # fmt: skip
    r = register_evidence_data(case, str(mem), "tester")
    assert r["acquired_by"] == "sift-tester-20261009-020"
    assert r["acquisition_tool"] == "winpmem"


def test_a_list_job_that_hashed_these_bytes_keeps_the_acquisitions_identity(case):
    mem = _open_acquisition(case)
    _closing(
        case, 1, "hash_complete", [{"path": str(mem), "sha256": _sha(mem.read_bytes())}]
    )
    r = register_evidence_data(case, str(mem), "tester")
    assert r["acquired_by"] == "sift-tester-20261009-020"
    assert r["acquisition_tool"] == "winpmem"


def _malformed_closings(mem, shape: str) -> list[dict]:
    """The job's closing entries for each malformed shape (a hand-edited or
    corrupted audit line); `mem` is the acquisition's pending output."""
    job, ok = "job-20261009-020", {"path": str(mem), "sha256": _sha(mem.read_bytes())}
    complete = {"tool": "hash_complete", "job_id": job}
    return {
        "files_number": [{**complete, "files": 1}],
        "files_bool": [{**complete, "files": True}],
        "nul_in_files_path": [{**complete, "files": [{"path": "/x\x00y", "sha256": "a" * 64}, ok]}],
        "nul_in_top_path": [{**complete, "path": "/x\x00y", "sha256": "a" * 64}, {**complete, "files": [ok]}],
        "lone_surrogate_path": [{**complete, "files": [{"path": "/x\ud800", "sha256": "a" * 64}, ok]}],
        # a failure for the file hidden behind a row that can't be read: it must
        # not be dropped, leaving the clean entry to grant the labels
        "hidden_failure": [{**complete, "files": [ok]},
                           {"tool": "hash_failed", "job_id": job,
                            "files": [{"path": "/x\x00y"}, {"path": str(mem), "error": "read"}]}],
    }[shape]  # fmt: skip


@pytest.mark.parametrize(
    "shape",
    ["files_number", "files_bool", "nul_in_files_path", "nul_in_top_path",
     "lone_surrogate_path", "hidden_failure"],
)  # fmt: skip
def test_a_closing_entry_that_cant_be_read_leaves_its_job_open(case, shape):
    """Nothing in a malformed closing entry stops the case's registrations; its
    job's pending files stay refused, others register."""
    mem = _open_acquisition(case)
    for n, entry in enumerate(_malformed_closings(mem, shape)):
        _record(
            case, "file-identity", audit_id=f"file-identity-20261009-04{n}", **entry
        )
    other = case / "evidence" / "other.txt"
    other.write_bytes(b"an original")
    assert register_evidence_data(case, str(other), "tester")["sha256"] == _sha(
        b"an original"
    )
    with pytest.raises(
        ValueError, match="sift-tester-20261009-020.*hasn't recorded one hash"
    ):
        register_evidence_data(case, str(mem), "tester")
    assert [os.path.basename(f["path"]) for f in _files(case)] == ["other.txt"]


@pytest.mark.parametrize(
    "rows",
    [
        {"files": {"path": "P", "error": "read"}},  # files as an object
        {"files": "P"},  # files as a string
        {"files": []},  # no rows, and no top-level path
        {"files": ["P"]},  # a row that isn't an object
        {"files": [{"error": "read"}]},  # a row without a path
        {"files": [{"path": 5, "error": "read"}]},  # a path that isn't a string
        {"files": [{"path": "", "error": "read"}]},  # an empty path
        {"files": [{"path": "evidence/HOST1.raw", "error": "read"}]},  # a relative path
        {"files": [{"path": "P", "sha256": "a" * 64, "error": "read"}]},  # guard: both
        {"files": [{"path": "P"}]},  # guard: neither a hash nor an error
    ],
    ids=["files_object", "files_string", "files_empty", "row_not_object", "row_no_path",
         "path_not_string", "path_empty", "path_relative", "guard_both", "guard_neither"],
)  # fmt: skip
def test_a_failure_entry_that_cant_be_read_is_never_skipped(case, rows):
    """A job that hashed the file, then closed it again with an entry whose rows
    can't all be read: the second entry isn't skipped, so the file stays open."""
    mem = _open_acquisition(case)
    _closing(
        case, 1, "hash_complete", [{"path": str(mem), "sha256": _sha(mem.read_bytes())}]
    )
    real = json.loads(json.dumps(rows).replace('"P"', json.dumps(str(mem))))
    _record(case, "file-identity", audit_id="file-identity-20261009-032", tool="hash_failed",
            job_id="job-20261009-020", **real)  # fmt: skip
    other = case / "evidence" / "other.txt"
    other.write_bytes(b"an original")
    assert register_evidence_data(case, str(other), "tester")["sha256"] == _sha(
        b"an original"
    )
    with pytest.raises(
        ValueError, match="sift-tester-20261009-020.*hasn't recorded one hash"
    ):
        register_evidence_data(case, str(mem), "tester")


def _writer_job(case, monkeypatch, paths):
    """The hash job file_identity runs, closing `paths` as the writer does."""
    fi = pytest.importorskip("sift_common.file_identity")
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    fi._job(("k",), "job-20261009-020", paths, str(case), "test")


def _pending(case, mem):
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-020", tool="run_command",
            acquisition=True, acquisition_tool="winpmem",
            outputs=[{"path": str(mem), "sha256": "pending:job-20261009-020"}])  # fmt: skip


def _labelled(case, mem):
    r = register_evidence_data(case, str(mem), "tester")
    assert (r.get("acquired_by"), r.get("acquisition_tool")) == (
        "sift-tester-20261009-020", "winpmem")  # fmt: skip


def test_a_writer_made_one_file_closing_keeps_the_acquisitions_identity(
    case, monkeypatch
):
    mem = case / "evidence" / "HOST1.raw"
    mem.write_bytes(b"MEM")
    _pending(case, mem)
    _writer_job(case, monkeypatch, str(mem))
    _labelled(case, mem)


def test_a_writer_made_list_closing_keeps_the_acquisitions_identity(case, monkeypatch):
    mem, page = case / "evidence" / "HOST1.raw", case / "evidence" / "HOST1.pagefile"
    mem.write_bytes(b"MEM")
    page.write_bytes(b"PAGE")
    _pending(case, mem)
    _writer_job(case, monkeypatch, [str(mem), str(page)])
    _labelled(case, mem)


def test_a_writer_made_partial_list_keeps_the_hashed_files_identity(case, monkeypatch):
    mem = case / "evidence" / "HOST1.raw"
    mem.write_bytes(b"MEM")
    _pending(case, mem)
    _writer_job(case, monkeypatch, [str(mem), str(case / "evidence" / "gone.pagefile")])
    _labelled(case, mem)


def test_a_writer_made_closing_of_a_non_utf8_name_keeps_its_identity(case, monkeypatch):
    raw = os.path.join(os.fsencode(case / "evidence"), b"HOST\xff.raw")
    with open(raw, "wb") as f:
        f.write(b"MEM")
    mem = case / "evidence" / os.fsdecode(b"HOST\xff.raw")  # a surrogate-escaped name
    _pending(case, mem)
    _writer_job(case, monkeypatch, str(mem))
    _labelled(case, mem)


def test_a_writer_made_failure_is_refused(case, monkeypatch):
    mem = case / "evidence" / "HOST1.raw"
    _pending(case, mem)
    _writer_job(case, monkeypatch, str(mem))  # nothing there yet: the job fails
    mem.write_bytes(b"MEM")
    with pytest.raises(
        ValueError, match="sift-tester-20261009-020.*hasn't recorded one hash"
    ):
        register_evidence_data(case, str(mem), "tester")


def test_the_refusal_for_a_job_still_open_says_to_register_after_it_completes(case):
    mem = _open_acquisition(case)
    with pytest.raises(ValueError) as refused:
        register_evidence_data(case, str(mem), "tester")
    why = str(refused.value)
    assert "job-20261009-020" in why and "register it after that job completes" in why
    assert "failed" not in why


def test_the_refusal_for_a_failed_job_quotes_its_error_and_says_to_acquire_anew(case):
    """A failed job will never record a hash: waiting for it is the wrong advice."""
    mem = _open_acquisition(case)
    _closing(case, 1, "hash_failed",
             [{"path": str(mem), "error": "PermissionError: [Errno 13] Permission denied"}])  # fmt: skip
    with pytest.raises(ValueError) as refused:
        register_evidence_data(case, str(mem), "tester")
    why = str(refused.value)
    assert "job-20261009-020 failed" in why
    assert "PermissionError: [Errno 13] Permission denied" in why
    assert "acquire it again to a new path and register that file" in why
    assert "after that job completes" not in why


def test_a_failed_jobs_error_is_quoted_on_one_line_with_its_controls_shown(case):
    """The recorded error can carry a file name: what reaches the terminal can't
    colour it, move the cursor or break the line, and it's capped."""
    mem = _open_acquisition(case)
    error = "PermissionError: '\x1b[31mevil\nname'" + "x" * 500
    _closing(case, 1, "hash_failed", [{"path": str(mem), "error": error}])
    with pytest.raises(ValueError) as refused:
        register_evidence_data(case, str(mem), "tester")
    why = str(refused.value)
    assert "\x1b" not in why and "\n" not in why
    assert "'?[31mevil?name'" in why
    assert "x" * 300 not in why


def test_after_a_failed_job_an_acquisition_to_a_new_path_registers(case):
    """The advice works: P stays refused for good, the new acquisition's file
    registers with its identity."""
    mem = _open_acquisition(case)
    _closing(
        case,
        1,
        "hash_failed",
        [{"path": str(mem), "error": "PermissionError: [Errno 13]"}],
    )
    again = case / "evidence" / "HOST1-again.raw"
    again.write_bytes(b"MEM again")
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-021", tool="run_command",
            acquisition=True, acquisition_tool="winpmem",
            outputs=[{"path": str(again), "sha256": "pending:job-20261009-021"}])  # fmt: skip
    _closing(case, 2, "hash_complete", [{"path": str(again), "sha256": _sha(b"MEM again")}],
             job="job-20261009-021")  # fmt: skip
    r = register_evidence_data(case, str(again), "tester")
    assert (r["acquired_by"], r["acquisition_tool"]) == (
        "sift-tester-20261009-021",
        "winpmem",
    )
    with pytest.raises(
        ValueError, match="job-20261009-020 failed.*acquire it again to a new path"
    ):
        register_evidence_data(case, str(mem), "tester")


# --- the CLI prints a refusal so nothing in it drives the terminal -------------

_CONTROLS = "\x1b[2J\x9b\nX"  # ESC, CSI (C1) and a line break
_SHOWN_RAW = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f]")  # any but the line break


def _cli_refused(case, path, capsys, monkeypatch):
    """`vhir evidence register <path>`, confirmed, refused: what reaches stderr."""
    with pytest.raises(SystemExit):
        _cli_register(case, path, capsys, monkeypatch)
    return capsys.readouterr().err


def _drives_nothing(err):
    assert not _SHOWN_RAW.search(err)
    first, *rest = err.rstrip("\n").split("\n")
    assert rest and all(line.startswith("  ") for line in rest)
    return first


def test_the_cli_prints_a_refusal_with_controls_in_its_path_job_and_error_safely(
    case, capsys, monkeypatch
):
    """A file name, job id and error are case data: on the terminal their
    controls show as "?" and a line break in them starts an indented line."""
    mem = case / "evidence" / f"HOST1{_CONTROLS}.raw"
    mem.write_bytes(b"not what winpmem wrote")
    job = f"job-20261009-020{_CONTROLS}"
    _record(case, "sift-mcp", audit_id="sift-tester-20261009-020", tool="run_command",
            acquisition=True, acquisition_tool="winpmem",
            outputs=[{"path": str(mem), "sha256": f"pending:{job}"}])  # fmt: skip
    _closing(case, 1, "hash_failed", [{"path": str(mem), "error": f"OSError{_CONTROLS}"}],
             job=job)  # fmt: skip
    err = _cli_refused(case, mem, capsys, monkeypatch)
    _drives_nothing(err)
    # the path and the job break the line; the error, quoted on one line, can't
    assert err.count("?[2J?\n  X") == 2 and "(OSError?[2J??X)" in err
    assert "acquire it again to a new path and register that file" in err
    assert _files(case) == []


@pytest.mark.parametrize("raised", [FileNotFoundError, ValueError, OSError])
def test_every_error_the_cli_prints_for_a_registration_is_printed_safely(
    case, capsys, monkeypatch, raised
):
    def refuse(**kw):
        raise raised(f"no{_CONTROLS}")

    monkeypatch.setattr("vhir_cli.commands.evidence.register_evidence_data", refuse)
    err = _cli_refused(case, case / "evidence" / "any.raw", capsys, monkeypatch)
    assert _drives_nothing(err).endswith("no?[2J?") and err.endswith("\n  X\n")


def test_the_cli_still_prints_a_multi_line_refusal_as_its_own_lines(
    case, tmp_path, capsys, monkeypatch
):
    outside = tmp_path / "outside.raw"
    outside.write_bytes(b"S10")
    err = _cli_refused(case, outside, capsys, monkeypatch)
    first = _drives_nothing(err)
    assert first == "Error: Evidence path must be within the case directory."
    for line in ("    Resolved: ", "    Case dir: ", "  Or create a symlink:"):
        assert any(got.startswith(line) for got in err.split("\n"))

    p = case / "evidence" / "samples.7z"
    p.write_bytes(b"S10")
    register_evidence_data(case, str(p), "tester")
    p.write_bytes(b"S10 changed")
    err = _cli_refused(case, p, capsys, monkeypatch)
    _drives_nothing(err)
    for line in (
        "    Registered: ",
        "    Current:    ",
        "  Run 'vhir evidence verify'",
    ):
        assert any(got.startswith(line) for got in err.split("\n"))


# --- stat fields come from the hashed bytes' own fd ----------------------------


def _changing_hasher(monkeypatch, path, times):
    """sha256() whose first update appends to `path`, for `times` hashes."""
    from vhir_cli.commands import evidence

    real, left = hashlib.sha256, [times]

    class Changing:
        def __init__(self, data=b""):
            self._h, self._first = real(data), True

        def update(self, chunk):
            if self._first and left[0] > 0:
                left[0] -= 1
                with open(path, "ab") as f:
                    f.write(b"+")
            self._first = False
            self._h.update(chunk)

        def hexdigest(self):
            return self._h.hexdigest()

    monkeypatch.setattr(evidence.hashlib, "sha256", Changing)


def test_a_file_changed_after_it_was_hashed_keeps_the_hashed_bytes_stat(
    case, monkeypatch
):
    """The stat fields vouch for the bytes hashed, so a later change is seen."""
    from vhir_cli.commands import evidence

    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    check = evidence._not_an_original

    def change_then_check(*a, **k):  # runs between the hash and the old stat
        with open(p, "ab") as f:
            f.write(b"later")
        return check(*a, **k)

    monkeypatch.setattr(evidence, "_not_an_original", change_then_check)
    r = register_evidence_data(case, str(p), "tester")
    assert r["sha256"] == _sha(b"M" * 100) and r["size"] == 100, r


def test_a_file_changed_while_hashed_is_hashed_again(case, monkeypatch):
    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    _changing_hasher(monkeypatch, p, times=1)
    r = register_evidence_data(case, str(p), "tester")
    assert r["sha256"] == _sha(b"M" * 100 + b"+") and r["size"] == 101, r
    assert "hash_note" not in r


def test_a_file_that_keeps_changing_is_registered_as_such_with_no_stat(
    case, monkeypatch
):
    """Never as stable: no stat fields vouch for it, so it's always re-hashed."""
    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    _changing_hasher(monkeypatch, p, times=99)
    r = register_evidence_data(case, str(p), "tester")
    assert r["hash_note"] == "changed while hashing", r
    assert not {"size", "mtime_ns", "ctime_ns", "st_dev", "st_ino"} & set(r)


def test_a_forced_reregister_that_keeps_changing_drops_the_old_stat(case, monkeypatch):
    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    assert register_evidence_data(case, str(p), "tester")["size"] == 100
    p.write_bytes(b"N" * 100)
    _changing_hasher(monkeypatch, p, times=99)
    r = register_evidence_data(case, str(p), "tester", force_reregister=True)
    assert r["hash_note"] == "changed while hashing" and "size" not in r, r


# --- an audit log that can't be read leaves the derivation unchecked, said so ----


@pytest.fixture
def unreadable_log(case):
    log = case / "audit" / "sift-mcp.jsonl"
    log.write_text("{}\n")
    log.chmod(0)
    yield log
    log.chmod(0o644)


def test_a_file_registered_while_a_log_cant_be_read_says_derivation_unchecked(
    case, unreadable_log
):
    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    r = register_evidence_data(case, str(p), "tester")
    note = r.get("derivation_note", "")
    assert note.startswith("derivation unchecked: ") and "sift-mcp.jsonl" in note, r


def test_a_folder_registered_while_a_log_cant_be_read_says_derivation_unchecked(
    case, unreadable_log
):
    k = case / "evidence" / "kape"
    k.mkdir()
    (k / "a.evtx").write_bytes(b"A" * 64)
    r = register_evidence_data(case, str(k), "tester")
    assert r.get("derivation_note", "").startswith("derivation unchecked: "), r


def test_registering_a_legacy_entry_again_adds_its_stat_fields(case):
    """An entry from before stat fields: the same file again fills them in, so
    the approval check's fast path can vouch for it."""
    p = case / "evidence" / "old.bin"
    p.write_bytes(b"OLD")
    legacy = {"path": str(p.resolve()), "sha256": _sha(b"OLD"), "description": "",
              "registered_at": "2026-09-01T00:00:00+00:00", "registered_by": "tester"}  # fmt: skip
    (case / "evidence.json").write_text(json.dumps({"files": [legacy]}))
    register_evidence_data(case, str(p), "tester")
    (entry,) = _files(case)
    assert entry["size"] == 3 and entry["st_ino"] == os.stat(p).st_ino, entry
    assert entry["registered_at"] == legacy["registered_at"]  # the same registration


# --- the CLI says what a registration's notes say ------------------------------


def _cli_register(case, path, capsys, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import patch

    from vhir_cli.commands.evidence import cmd_register_evidence

    monkeypatch.setattr(
        "vhir_cli.commands.evidence.require_tty_confirmation", lambda prompt: True
    )
    args = SimpleNamespace(path=str(path), description="", force_reregister=False,
                           case=None)  # fmt: skip
    with patch("vhir_cli.commands.evidence.get_case_dir", return_value=case):
        cmd_register_evidence(args, {"os_user": "tester", "examiner": "tester"})
    return capsys.readouterr().out


def test_the_cli_prints_a_derivation_note_at_register_and_verify(
    case, unreadable_log, capsys, monkeypatch
):
    from unittest.mock import patch

    from vhir_cli.commands.evidence import cmd_verify_evidence

    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    out = _cli_register(case, p, capsys, monkeypatch)
    assert "WARNING: derivation unchecked: audit/sift-mcp.jsonl can't be read" in out, (
        out
    )
    with patch("vhir_cli.commands.evidence.get_case_dir", return_value=case):
        cmd_verify_evidence(SimpleNamespace(case=None), {})
    assert "WARNING: derivation unchecked" in capsys.readouterr().out


def test_the_cli_never_says_hash_recorded_for_a_file_that_kept_changing(
    case, capsys, monkeypatch
):
    p = case / "evidence" / "mem.raw"
    p.write_bytes(b"M" * 100)
    _changing_hasher(monkeypatch, p, times=99)
    out = _cli_register(case, p, capsys, monkeypatch)
    assert "Integrity" not in out, out  # no integrity line at all
    assert "WARNING: the file changed while hashing" in out


def test_an_acquisition_registered_while_a_log_cant_be_read_says_so(
    case, unreadable_log
):
    mem = _winpmem(case, acquisition=True)
    r = register_evidence_data(case, str(mem), "tester")
    assert r["acquired_by"] == "wt-tester-20261009-004", r
    assert r.get("derivation_note", "").startswith("derivation unchecked: "), r


def test_a_warning_never_carries_a_log_names_control_characters(
    case, capsys, monkeypatch
):
    """A log name is the case's, which the AI's shell can write: printed, its
    escape sequences can't clear the screen or hide the warning."""
    log = case / "audit" / "x\x1b[2J\x1b[H.jsonl"
    log.write_text("{}\n")
    log.chmod(0)
    try:
        p = case / "evidence" / "mem.raw"
        p.write_bytes(b"M" * 100)
        out = _cli_register(case, p, capsys, monkeypatch)
    finally:
        log.chmod(0o644)
    assert "\x1b" not in out and "x?[2J?[H.jsonl" in out, repr(out)


def test_a_file_registered_alone_and_in_a_folder_keeps_both_notes(
    case, unreadable_log, monkeypatch
):
    """Verify gives a folder member its folder's notes and its own entry's, not
    one over the other."""
    from vhir_cli.commands.evidence import verify_evidence_data

    k = case / "evidence" / "kape"
    k.mkdir()
    (k / "a.evtx").write_bytes(b"A" * 64)
    register_evidence_data(case, str(k), "tester")  # the folder: derivation unchecked
    unreadable_log.chmod(0o644)  # readable now: the file's own entry has no such note
    _changing_hasher(monkeypatch, k / "a.evtx", times=99)
    register_evidence_data(case, str(k / "a.evtx"), "tester")  # its own: hash note
    monkeypatch.undo()
    notes = [
        r.get("notes", [])
        for r in verify_evidence_data(case)["results"]
        if r["path"].endswith("kape/a.evtx")
    ]
    assert any(
        any("derivation unchecked" in n for n in ns)
        and any("changed while hashing" in n for n in ns)
        for ns in notes
    ), notes


def test_a_members_own_note_stays_on_that_member(case, unreadable_log, monkeypatch):
    """Each folder member's notes are its own list: one member registered alone
    with a note never lends it to its siblings."""
    from vhir_cli.commands.evidence import verify_evidence_data

    k = case / "evidence" / "kape"
    k.mkdir()
    (k / "a.evtx").write_bytes(b"A" * 64)
    (k / "b.evtx").write_bytes(b"B" * 64)
    register_evidence_data(case, str(k), "tester")  # both: derivation unchecked
    unreadable_log.chmod(0o644)
    _changing_hasher(monkeypatch, k / "a.evtx", times=99)
    register_evidence_data(case, str(k / "a.evtx"), "tester")  # a alone: hash note
    monkeypatch.undo()
    b_notes = [
        r.get("notes", [])
        for r in verify_evidence_data(case)["results"]
        if r["path"].endswith("kape/b.evtx")
    ]
    assert b_notes and not any(
        "changed while hashing" in n for ns in b_notes for n in ns
    ), b_notes
