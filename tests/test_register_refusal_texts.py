"""A refusal to register says what its own code checked, and nothing more.
Each row asserts the whole text.

- A file under extractions/ that no record names: never an original, no
  record names it, and the two ways out in order (re-make it with
  run_command; for a finding only, declare it first).
- The same while part of the audit can't be read: "in the audit it could
  read", with what couldn't be read.
- An empty file under extractions/: nothing can link it, and no way out.
- A file a record names: the record ids, and no claim that it links.
- A record whose path is relative names nothing, whatever the cwd.
- A wintools record's case-relative sift_path names its file whether the
  case folder is given absolute or relative, under extractions/ or not.
- A path outside the case: `ln -s` first, then `cp`, both from the
  resolved source; the printed `ln -s` registers.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from vhir_cli.commands.evidence import register_evidence_data

WAYS_OUT = (
    "Ways out, in this order: (1) re-make it with run_command from registered "
    "evidence or a recorded output, the only route an ingest accepts; (2) for a "
    "finding only, declare how it was made with log_external_action, naming the "
    "inputs (registered evidence or recorded outputs) in input_files and this "
    "file in output_files. Declare first: reads made before the declaration don't "
    "link, so re-run them after it or cite the declaration's audit_id. For a "
    "folder, name each file."
)


def _no_record(real) -> str:
    return (
        f"{real} is under this case's extractions/, where files are never "
        "registered as originals, and no record in this case names it as an "
        f"output with these bytes. {WAYS_OUT}"
    )


def _unread(real, why) -> str:
    return (
        f"{real} is under this case's extractions/, where files are never "
        "registered as originals, and no record in the audit it could read names "
        f"it as an output with these bytes (derivation unchecked: {why}). {WAYS_OUT}"
    )


def _empty(real) -> str:
    return (
        f"{real} is under this case's extractions/ and is empty: no record or "
        "declaration can link an empty file, so it can't be registered or ingested."
    )


def _recorded(real, ids) -> str:
    return (
        f"{real} is an output this case recorded ({ids}): register the original "
        "evidence it was made from."
    )


def _outside(given, resolved, case) -> str:
    return (
        "Evidence path must be within the case directory.\n"
        f"  Path:     {given}\n"
        f"  Resolved: {resolved}\n"
        f"  Case dir: {case.resolve()}\n"
        "Link it into the case evidence directory (recommended):\n"
        f"  ln -s {resolved} {case / 'evidence' / given.name}\n"
        "Or copy it there (this duplicates the bytes):\n"
        f"  cp {resolved} {case / 'evidence'}/"
    )


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("VHIR_EXAMINER", "tester")
    d = tmp_path / "case"
    for sub in ("evidence", "extractions/manual", "audit"):
        (d / sub).mkdir(parents=True)
    (d / "evidence.json").write_text('{"files": []}')
    (d / "evidence" / "orig.bin").write_bytes(b"original bytes\n")
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    return d


def _record(case, log, **entry):
    with open(case / "audit" / f"{log}.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def _refusal(case, path, **kw) -> str:
    with pytest.raises(ValueError) as e:
        register_evidence_data(case, str(path), "tester", registered_via="mcp", **kw)
    assert json.loads((case / "evidence.json").read_text())["files"] == []
    return str(e.value)


def _bash_made(case, name="rec.bin", data=b"made by bash\n"):
    p = case / "extractions" / "manual" / name
    p.write_bytes(data)
    return p


def test_a_file_no_record_names_gets_both_ways_out(case):
    rec = _bash_made(case)
    assert _refusal(case, rec) == _no_record(rec.resolve())


def test_with_part_of_the_audit_unread_it_says_what_it_could_read(case):
    rec = _bash_made(case)
    (case / "audit" / "x.jsonl").mkdir()
    assert _refusal(case, rec) == _unread(
        rec.resolve(), "audit/x.jsonl can't be read (a folder)"
    )


def test_each_file_of_a_folder_gets_the_text_on_the_call_after_its_hashing(case):
    from vhir_cli.commands.evidence import _hash_each

    folder = case / "extractions" / "manual-msgtrk"
    folder.mkdir()
    (folder / "a.log").write_text("message tracking\n")
    calls = []

    def hasher(case_dir, paths):
        calls.append(paths)
        return ({}, "job-1") if len(calls) == 1 else _hash_each(case_dir, paths)

    first = register_evidence_data(
        case, str(folder), "tester", registered_via="mcp", folder_hasher=hasher
    )
    assert first["status"] == "hashing"
    assert _refusal(case, folder, folder_hasher=hasher) == (
        f"{folder.resolve()} holds a file that isn't an original: "
        + _no_record((folder / "a.log").resolve())
    )


@pytest.mark.parametrize("cwd", ["case", "neutral"])
def test_a_record_with_a_relative_path_names_nothing(case, monkeypatch, cwd):
    rec = _bash_made(case)
    _record(case, "case-mcp", audit_id="case-tester-1", tool="log_external_action",
            outputs=[{"path": "extractions/manual/rec.bin", "sha256": _sha(rec.read_bytes())}],
            result_summary={"output_files": ["extractions/manual/rec.bin"]})  # fmt: skip
    if cwd == "case":
        monkeypatch.chdir(case)
    assert _refusal(case, rec) == _no_record(rec.resolve())


def test_an_empty_file_under_extractions_has_no_way_out(case):
    empty = _bash_made(case, "empty.bin", b"")
    assert _refusal(case, empty) == _empty(empty.resolve())
    # a declaration naming it changes nothing: the empty file's hash never matches
    _record(case, "case-mcp", audit_id="case-tester-2", tool="log_external_action",
            inputs=[{"path": str(case / "evidence" / "orig.bin")}],
            outputs=[{"path": str(empty), "sha256": _sha(b"")}])  # fmt: skip
    assert _refusal(case, empty) == _empty(empty.resolve())


@pytest.mark.parametrize("inputs", ["registered", "unregistered"])
def test_a_recorded_output_names_its_records_and_claims_no_link(case, inputs):
    out = _bash_made(case, "parsed.csv", b"a,b\n")
    orig = case / "evidence" / "orig.bin"
    if inputs == "registered":
        register_evidence_data(case, str(orig), "tester")
    _record(case, "sift-mcp", audit_id="sift-tester-3", tool="run_command",
            input_files=[str(orig)], input_sha256s=[_sha(orig.read_bytes())],
            result_summary={"output_files": [str(out)], "output_sha256s": [_sha(b"a,b\n")]})  # fmt: skip
    files = json.loads((case / "evidence.json").read_text())["files"]
    with pytest.raises(ValueError) as e:
        register_evidence_data(case, str(out), "tester", registered_via="mcp")
    assert str(e.value) == _recorded(out.resolve(), "sift-tester-3")
    assert json.loads((case / "evidence.json").read_text())["files"] == files


@pytest.mark.parametrize("windows_path", [True, False])
@pytest.mark.parametrize("where", ["extractions/wt", "work/evtx"])
@pytest.mark.parametrize("form", ["absolute", "relative", "dot"])
def test_a_wintools_sift_path_names_its_file_however_the_case_is_given(
    case, monkeypatch, form, where, windows_path
):
    (case / where).mkdir(parents=True)
    out = case / where / "out.csv"
    out.write_bytes(b"x,y\n")
    rec = {"sift_path": f"{where}/out.csv", "sha256": _sha(b"x,y\n")}
    if windows_path:
        rec["path"] = where.replace("/", "\\") + "\\out.csv"
    _record(case, "wintools-mcp", audit_id="wt-2", tool="EvtxECmd", outputs=[rec])
    monkeypatch.chdir(case if form == "dot" else case.parent)
    given = {"absolute": case, "relative": Path("case"), "dot": Path(".")}[form]
    with pytest.raises(ValueError) as e:
        register_evidence_data(given, str(out), "tester", registered_via="mcp")
    assert str(e.value) == _recorded(out.resolve(), "wt-2")
    assert json.loads((case / "evidence.json").read_text())["files"] == []


def test_a_path_outside_the_case_offers_a_link_first(case, tmp_path):
    big = tmp_path / "outside" / "big.img"
    big.parent.mkdir()
    big.write_bytes(b"disk image\n")
    via = tmp_path / "via"
    via.symlink_to(big.parent)
    given = via / "big.img"
    assert _refusal(case, given) == _outside(given, big.resolve(), case)


def test_the_printed_link_registers_the_resolved_source(case, tmp_path):
    big = tmp_path / "outside" / "big.img"
    big.parent.mkdir()
    big.write_bytes(b"disk image\n")
    text = _refusal(case, big)
    (line,) = [s.strip() for s in text.split("\n") if s.strip().startswith("ln -s ")]
    subprocess.run(shlex.split(line), check=True)
    r = register_evidence_data(case, "evidence/big.img", "tester")
    assert r["path"] == str(big.resolve()) and r["sha256"] == _sha(b"disk image\n")


# --- the CLI, confirmed at a terminal: the same texts --------------------------


def _cli_pty(case, path) -> str:
    """`vhir evidence register <path>` in a pty (`script`), answered "y": what
    it printed after "Error: "."""
    code = "import sys; from vhir_cli.main import main; sys.argv = ['vhir', *sys.argv[1:]]; main()"
    cmd = shlex.join([sys.executable, "-c", code, "evidence", "register", str(path)])
    env = {**os.environ, "VHIR_CASE_DIR": str(case), "VHIR_EXAMINER": "tester"}
    r = subprocess.run(["script", "-qec", cmd, "/dev/null"], input="y\n", env=env,
                       capture_output=True, text=True, timeout=60)  # fmt: skip
    out = r.stdout.replace("\r\n", "\n")
    assert r.returncode != 0 and "Error: " in out, out
    return out.split("Error: ", 1)[1].rstrip("\n")


def _as_printed(text: str) -> str:
    return text.replace("\n", "\n  ")


@pytest.mark.skipif(shutil.which("script") is None, reason="needs script(1) for a pty")
@pytest.mark.parametrize("state", ["no-record", "unread", "folder", "empty", "recorded", "outside"])  # fmt: skip
def test_the_cli_prints_the_same_text(case, tmp_path, state):
    rec = _bash_made(case)
    path, want = rec, _no_record(rec.resolve())
    if state == "unread":
        (case / "audit" / "x.jsonl").mkdir()
        want = _unread(rec.resolve(), "audit/x.jsonl can't be read (a folder)")
    elif state == "folder":
        path = rec.parent
        want = f"{path.resolve()} holds a file that isn't an original: {want}"
    elif state == "empty":
        path = _bash_made(case, "empty.bin", b"")
        want = _empty(path.resolve())
    elif state == "recorded":
        _record(case, "sift-mcp", audit_id="sift-tester-4", tool="run_command",
                result_summary={"output_file": str(rec), "output_sha256": _sha(rec.read_bytes())})  # fmt: skip
        want = _recorded(rec.resolve(), "sift-tester-4")
    elif state == "outside":
        path = tmp_path / "outside.img"
        path.write_bytes(b"disk image\n")
        want = _outside(path, path.resolve(), case)
    assert _cli_pty(case, path) == _as_printed(want)
    assert json.loads((case / "evidence.json").read_text())["files"] == []
