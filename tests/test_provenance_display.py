"""How a finding's provenance reads in `vhir review` and in the reports: the
grade as stored, with its reason; each artifact's root and who registered
it; each link's method and both ends with their hashes, root first. A
finding recorded before 0.6.4, and a query logged before it, read "recorded
before 0.6.4"; an import names the case its chain lives in.

The fixture holds each route as the chain resolver stores it."""

from __future__ import annotations

import json
import re
from argparse import Namespace

import pytest
import yaml

from vhir_cli.case_io import compute_content_hash
from vhir_cli.commands.report import cmd_report
from vhir_cli.commands.review import cmd_review
from vhir_cli.ledger_verify import approved_view
from vhir_cli.provenance_view import finding_lines, grade_label, provenance_block

from .signing import sign_approved

H7Z, HM2, HOUT, HDOC, HIMG, HCSV = (
    "a" * 64,
    "b" * 64,
    "f" * 64,
    "9" * 64,
    "c" * 64,
    "d" * 64,
)
EV, X = "/cases/c1/evidence", "/cases/c1/extractions"
ROOT = {"path": f"{EV}/samples.7z", "sha256": H7Z, "label": "AI-registered"}
IMG = {"path": f"{EV}/disk.E01", "sha256": HIMG, "label": "examiner-registered"}
PRE = "recorded before 0.6.4"
UNLOGGED = "no recorded origin: made outside recorded tools"


def link(method, aid, fp, fh, tp, th, **extra):
    return {"method": method, "audit_id": aid, "entry_sha256": "e" * 64,
            "from": {"path": fp, "sha256": fh}, "to": {"path": tp, "sha256": th}, **extra}  # fmt: skip


def art(grade, reason="", chain=(), root=ROOT, brk=None, **extra):
    """An artifact as the resolver stores it: `source_evidence` is the root's
    path when a root was reached."""
    a = {"source": "s", "extraction": "e", "content": "PID 4242", "audit_id": "x-1",
         "provenance_grade": grade, "provenance_reason": reason,
         "provenance_chain": list(chain), "provenance_root": root,
         "provenance_break": brk, **extra}  # fmt: skip
    if root:
        a["source_evidence"] = root["path"]
    return a


def finding(fid, title, grade, *arts, **extra):
    return {"id": fid, "title": title, "status": "DRAFT", "confidence": "MEDIUM",
            "examiner": "steve", "observation": "o", "interpretation": "i",
            "audit_ids": ["x-1"], "provenance": "MCP", "provenance_schema": 2,
            "provenance_grade": grade, "artifacts": list(arts), **extra}  # fmt: skip


RUN = [link("registered-path", "sift-steve-001", ROOT["path"], H7Z, f"{X}/1/mem2.raw", HM2),
       link("hash+place", "sift-steve-002", f"{X}/1/mem2.raw", HM2, f"{X}/2/stdout.bin", HOUT)]  # fmt: skip
QUERY_064 = f"{PRE}: opensearch-steve-009 records no results to follow"
FINDINGS = [
    {"id": "F-steve-000", "title": "Legacy", "status": "DRAFT", "confidence": "LOW",
     "examiner": "steve", "observation": "o", "interpretation": "i", "audit_ids": ["x-1"],
     "provenance": "MCP", "provenance_grade": "FULL", "source_evidence": ROOT["path"]},
    finding("F-steve-001", "run_command route", "FULL", art("FULL", chain=RUN)),
    finding("F-steve-002", "Bash route, logged", "DECLARED", art(
        "DECLARED", "declared: Bash outputs logged by log_external_action", [
            RUN[0], link("declared", "claude-code-steve-002", f"{X}/1/mem2.raw", HM2,
                         "stdout", HOUT)])),
    finding("F-steve-003", "ingest route", "FULL", art("FULL", chain=[
        link("registered-path", "opensearch-steve-001", ROOT["path"], H7Z, "archive", H7Z),
        link("manifest", "opensearch-steve-002", ROOT["path"], H7Z, "mem2.raw", HM2),
        link("recorded-id", "opensearch-steve-003", "mem2.raw", HM2, "doc:vol/abc", HDOC,
             document={"_index": "vol", "_id": "abc", "content_hash": HDOC})])),
    finding("F-steve-004", "Bash route, not logged", "BROKEN",
            art("BROKEN", UNLOGGED, root=None, brk={"kind": "no-recorded-origin"})),
    {"id": "F-steve-005", "title": "Imported", "status": "DRAFT", "confidence": "MEDIUM",
     "examiner": "steve", "observation": "o", "interpretation": "i", "audit_ids": ["x-1"],
     "provenance_grade": "IMPORTED",
     "imported_from": {"case_id": "case-A", "examiner": "alice",
                       "exported_at": "2026-10-08T09:00:00Z"},
     "artifacts": [{"source": "s", "extraction": "e", "content": "c", "audit_id": "x-1",
                    "provenance_grade": "IMPORTED", "provenance_chain": RUN}]},
    finding("F-steve-006", "image route: mount then EvtxECmd", "FULL", art("FULL", root=IMG, chain=[
        link("registered-path", "sift-steve-010", IMG["path"], HIMG, "/mnt/case/disk", ""),
        link("recorded-mount", "sift-steve-011", "/mnt/case/disk/Security.evtx", "8" * 64,
             f"{X}/11/Security.csv", HCSV)])),
    finding("F-steve-007", "quoted enrichment", "FULL", art(
        "FULL", "reference: lookup_ioc, opencti 6.4, op opencti-steve-001", [
            *RUN, {"method": "reference", "audit_id": "opencti-steve-001",
                   "entry_sha256": "e" * 64,
                   "reference": {"source": "lookup_ioc", "source_version": "opencti 6.4"},
                   "to": {"path": f"{X}/r/response.json", "sha256": "7" * 64}}])),
    finding("F-steve-008", "query logged before 0.6.4", "BROKEN", art(
        "BROKEN", QUERY_064, root=None, brk={"kind": "recorded-before-0.6.4"})),
    finding("F-steve-009", "pre-0.6.4 query and a run", "BROKEN",
            art("BROKEN", QUERY_064, root=None, brk={"kind": "recorded-before-0.6.4"}),
            art("FULL", chain=RUN)),
    finding("F-steve-010", "enrichment step not recorded", "BROKEN", art(
        "BROKEN", "opensearch-steve-004: the quote is enrichment data from x, which "
        "isn't recorded", root=None, brk={"kind": "reference-not-recorded"})),
]  # fmt: skip
BY_ID = {f["id"]: f for f in FINDINGS}


@pytest.fixture
def case(tmp_path, monkeypatch):
    d = tmp_path / "C-8"
    (d / "audit").mkdir(parents=True)
    (d / "CASE.yaml").write_text(yaml.dump({"case_id": "C-8", "status": "open"}))
    (d / "evidence.json").write_text(json.dumps({"files": []}))
    for name in ("timeline.json", "iocs.json", "todos.json"):
        (d / name).write_text("[]")
    _save(d, FINDINGS)
    monkeypatch.setenv("VHIR_CASE_DIR", str(d))
    monkeypatch.setenv("VHIR_EXAMINER", "steve")
    return d


def _save(d, findings):
    out = []
    for f in findings:
        f = json.loads(json.dumps(f))
        f["content_hash"] = compute_content_hash(f)
        out.append(f)
    p = d / "findings.json"
    if p.exists():
        p.chmod(0o644)
    p.write_text(json.dumps(out, indent=1))


def _review(case, capsys, **kw) -> str:
    args = dict(case=None, findings=True, detail=False, verify=False, iocs=False,
                timeline=False, audit=False, evidence=False, limit=50, todos=False,
                open=False)  # fmt: skip
    args.update(kw)
    cmd_review(Namespace(**args), {})
    return capsys.readouterr().out


def section(out: str, fid: str) -> str:
    start = out.index(f"[{fid}]")
    nxt = re.search(r"\n\s*\[F-steve-\d{3}\]", out[start + 1 :])
    return out[start : start + 1 + nxt.start()] if nxt else out[start:]


# --- vhir review --findings --detail ------------------------------------------


def test_the_run_command_route_reads_full_with_its_root_and_each_step_root_first(
    case, capsys
):
    s = section(_review(case, capsys, detail=True), "F-steve-001")
    assert "Provenance: FULL" in s and "MCP" not in s.split("Evidence")[0]
    assert f"root: {ROOT['path']} sha256={H7Z[:16]} (AI-registered)" in s
    i, j = (
        s.index("[registered-path] sift-steve-001"),
        s.index("[hash+place] sift-steve-002"),
    )
    assert i < j
    assert f"{ROOT['path']} sha256={H7Z[:16]} -> {X}/1/mem2.raw sha256={HM2[:16]}" in s
    assert f"sha256={HOUT[:16]}" in s


def test_the_logged_bash_route_reads_declared_with_its_reason(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-002")
    assert (
        "Provenance: DECLARED: declared: Bash outputs logged by log_external_action"
        in s
    )
    assert "[declared] claude-code-steve-002" in s


def test_the_unlogged_bash_route_reads_broken_with_its_reason(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-004")
    assert f"Provenance: BROKEN: {UNLOGGED}" in s and "root:" not in s


def test_a_finding_recorded_before_0_6_4_says_so(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-000")
    assert f"Provenance: {PRE}" in s and "FULL" not in s


def test_an_import_names_the_case_its_chain_lives_in(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-005")
    assert (
        "Provenance: IMPORTED: chain lives in case case-A (imported from alice, "
        "exported 2026-10-08T09:00:00Z)"
    ) in s
    assert (
        PRE not in s and "[registered-path]" not in s
    )  # the chain is the other case's


def test_a_query_logged_before_0_6_4_reads_so_never_broken(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-008")
    assert f"Provenance: {PRE}: opensearch-steve-009 records no results to follow" in s
    assert "BROKEN" not in s


def test_a_mixed_finding_reads_before_0_6_4_and_each_artifact_its_own_grade(
    case, capsys
):
    s = section(_review(case, capsys, detail=True), "F-steve-009")
    assert f"Provenance: {PRE}:" in s and "BROKEN" not in s
    assert f"[1] {PRE}: opensearch-steve-009 records no results to follow" in s
    assert "[2] FULL" in s and "[registered-path] sift-steve-001" in s


def test_another_broken_kind_still_reads_broken(case, capsys):
    s = section(_review(case, capsys, detail=True), "F-steve-010")
    assert "Provenance: BROKEN: opensearch-steve-004" in s


def test_a_reference_link_names_its_source_and_version_and_full_keeps_its_reason(
    case, capsys
):
    s = section(_review(case, capsys, detail=True), "F-steve-007")
    assert (
        "Provenance: FULL: reference: lookup_ioc, opencti 6.4, op opencti-steve-001"
        in s
    )
    assert "[reference] opencti-steve-001 reference: lookup_ioc, opencti 6.4: ->" in s


def test_the_mount_route_shows_the_recorded_mount_and_an_examiner_registered_root(
    case, capsys
):
    s = section(_review(case, capsys, detail=True), "F-steve-006")
    assert f"root: {IMG['path']} sha256={HIMG[:16]} (examiner-registered)" in s
    assert "[recorded-mount] sift-steve-011" in s


# --- vhir review --findings ------------------------------------------------------


def test_the_table_shows_the_grade_not_the_tier(case, capsys):
    out = _review(case, capsys)
    rows = {line[:40].strip(): line for line in out.splitlines()}
    assert "DECLARED" in rows["Bash route, logged"]
    assert PRE in rows["Legacy"] and PRE in rows["query logged before 0.6.4"]
    assert "IMPORTED" in rows["Imported"]
    assert " MCP " not in out


# --- The formatter -------------------------------------------------------------


def test_the_block_shows_every_grade_reason_method_and_hash():
    text = "\n".join(provenance_block({"findings": FINDINGS}))
    assert text.startswith("PROVENANCE\n")
    for method in ("registered-path", "hash+place", "declared", "manifest",
                   "recorded-id", "recorded-mount", "reference"):  # fmt: skip
        assert f"[{method}]" in text, method
    for h in (H7Z, HM2, HOUT, HDOC, HIMG, HCSV):
        assert h[:16] in text
    for label in ("FULL", "DECLARED", f"BROKEN: {UNLOGGED}", "IMPORTED: chain lives in case case-A",
                  f"{PRE}: opensearch-steve-009"):  # fmt: skip
        assert label in text, label


def test_with_no_approved_findings_the_block_says_so():
    assert provenance_block({"findings": []})[-1] == "No approved, verified findings."


def test_a_root_s_label_comes_from_how_it_was_registered():
    from vhir_cli.provenance_view import root_label

    assert root_label({"path": "/e", "registered_via": "mcp"}) == "AI-registered"
    assert root_label({"path": "/e"}) == "examiner-registered"
    assert (
        root_label({"path": "/e", "kind": "folder", "file_count": 3})
        == "folder (3 files)"
    )
    assert (
        root_label({"path": "/e", "label": "acquired by sift-1"})
        == "acquired by sift-1"
    )


def test_untrusted_text_can_t_move_the_cursor():
    f = json.loads(json.dumps(BY_ID["F-steve-001"]))
    f["artifacts"][0]["provenance_root"]["path"] = "/e/\x1b[2Jevil"
    f["artifacts"][0]["provenance_reason"] = "x\x1b]0;title\x07"
    text = "\n".join(finding_lines(f))
    assert "\x1b" not in text and "\x07" not in text


def test_the_grade_label_without_its_reason():
    assert grade_label(BY_ID["F-steve-002"], reason=False) == "DECLARED"
    assert grade_label(BY_ID["F-steve-009"], reason=False) == PRE


# --- vhir report -----------------------------------------------------------------


def _report_args(**kw):
    args = {"case": None, "full": False, "executive_summary": False,
            "report_timeline": False, "from_date": None, "to_date": None, "ioc": False,
            "report_findings": None, "status_brief": False, "save": None}  # fmt: skip
    args.update(kw)
    return Namespace(**args)


def test_the_report_ends_with_provenance_after_verification(case, capsys):
    fs = json.loads((case / "findings.json").read_text())
    for f in fs:
        if f["id"] in ("F-steve-001", "F-steve-009"):
            f["status"] = "APPROVED"
    _save(case, fs)
    sign_approved(case, "steve")
    cmd_report(
        _report_args(report_findings="F-steve-001,F-steve-009"), {"examiner": "steve"}
    )
    out = capsys.readouterr().out
    v, p = out.index("VERIFICATION"), out.index("PROVENANCE")
    assert v < p
    tail = out[p:]
    assert "[F-steve-001] run_command route" in tail and "Provenance: FULL" in tail
    assert "[F-steve-009]" in tail and f"Provenance: {PRE}:" in tail
    assert "F-steve-002" not in tail  # only approved, verified findings
    assert [f["id"] for f in approved_view(case)["findings"]] == [
        "F-steve-001", "F-steve-009",
    ]  # fmt: skip


def test_every_root_of_an_artifact_is_listed():
    f = json.loads(json.dumps(BY_ID["F-steve-001"]))
    f["artifacts"][0]["provenance_roots"] = [ROOT, IMG]
    text = "\n".join(finding_lines(f))
    assert f"root: {ROOT['path']} sha256={H7Z[:16]} (AI-registered)" in text
    assert f"root: {IMG['path']} sha256={HIMG[:16]} (examiner-registered)" in text


JOB = "hash-0123456789abcdef"


def test_a_hash_still_being_computed_names_its_job_never_reads_as_a_hash():
    f = finding("F-steve-020", "output hashed in the background", "FULL", art(
        "FULL", chain=[*RUN, link("recorded-id", "sift-steve-030", f"{X}/3/big.bin",
                                  f"pending:{JOB}", f"{X}/3/big.bin", HOUT)]))  # fmt: skip
    text = "\n".join(provenance_block({"findings": [f]}))
    assert (
        f"{X}/3/big.bin pending (job {JOB}) -> {X}/3/big.bin sha256={HOUT[:16]}" in text
    )
    assert "sha256=pending" not in text


def test_each_candidate_of_an_ambiguous_artifact_is_listed_by_the_fields_it_has():
    cands = [
        {"audit_id": "sift-steve-040", "entry_sha256": "e" * 64, "path": f"{X}/4/a.csv",
         "sha256": HCSV},
        {"audit_id": "sift-steve-041", "entry_sha256": "e" * 64, "path": f"{X}/4/a.csv",
         "sha256": ""},
        {"audit_id": "sift-steve-042", "entry_sha256": "e" * 64, "tool": "run_command"},
        {"audit_id": "sift-steve-043", "entry_sha256": "e" * 64, "path": "/mnt/case/disk",
         "image": IMG["path"]},
    ]  # fmt: skip
    f = finding("F-steve-021", "two producers", "AMBIGUOUS", art(
        "AMBIGUOUS", "two operations wrote a.csv", root=None,
        provenance_candidates=cands))  # fmt: skip
    text = "\n".join(finding_lines(f))
    assert f"candidate: sift-steve-040 path={X}/4/a.csv sha256={HCSV[:16]}" in text
    assert f"candidate: sift-steve-041 path={X}/4/a.csv no hash" in text
    assert "candidate: sift-steve-042 tool=run_command\n" in text + "\n"
    assert (
        f"candidate: sift-steve-043 path=/mnt/case/disk image={IMG['path']}\n"
        in text + "\n"
    )
