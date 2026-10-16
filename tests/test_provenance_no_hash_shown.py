"""A provenance root or step end recorded with no hash (a mounted image's
mount point, an output file not hashed) reads "(no hash)" in every view that
shows it: `vhir review --detail`, the report, and the Root line `vhir approve`
prints before the password in each of its modes. It never reads
"sha256=?". A real hash, and one still being computed, read as before. The
stored records are unchanged."""

from __future__ import annotations

import copy

import pytest

from vhir_cli.provenance_view import (
    candidate_line,
    finding_lines,
    link_line,
    root_line,
)

from .test_finding_iocs_and_tabs_shown import _Prompt, _view, case  # noqa: F401

REAL = "ab" * 32
IMAGE = "/cases/C-1/evidence/rd01-triage.vhdx"
MOUNT = "/cases/C-1/tmp/ingest-1/nbd0p1"

# (stored sha256, how it reads); "missing" leaves the key out
SHAS = {
    "empty": ("", "(no hash)"),
    "none": (None, "(no hash)"),
    "missing": (..., "(no hash)"),
    "zero": (0, "(no hash)"),
    "empty-dict": ({}, "(no hash)"),
    "real": (REAL, f"sha256={REAL[:16]}"),
    "pending": ("pending:job-7", "pending (job job-7)"),
    "number": (12345, "sha256=12345"),
    "list": (["x"], "sha256=['x']"),
}


def _end(path, sha):
    return {"path": path} if sha is ... else {"path": path, "sha256": sha}


@pytest.mark.parametrize("shape", list(SHAS))
def test_root_line_reads_each_hash_shape(shape):
    sha, text = SHAS[shape]
    root = {**_end(IMAGE, sha), "label": "AI-registered"}
    assert root_line(root) == f"{IMAGE} {text} (AI-registered)"


@pytest.mark.parametrize("shape", list(SHAS))
def test_a_step_s_ends_read_each_hash_shape(shape):
    sha, text = SHAS[shape]
    link = {"method": "recorded-id", "audit_id": "os-1",
            "from": _end(IMAGE, REAL), "to": _end(MOUNT, sha)}  # fmt: skip
    assert link_line(link) == (
        f"[recorded-id] os-1: {IMAGE} sha256={REAL[:16]} -> {MOUNT} {text}"
    )


@pytest.mark.parametrize("shape", list(SHAS))
def test_a_returned_record_reads_each_content_hash_shape(shape):
    sha, text = SHAS[shape]
    doc = {"_index": "case-1-evtx", "_id": "d1"}
    if sha is not ...:
        doc["content_hash"] = sha
    link = {"method": "recorded-id", "audit_id": "os-2", "document": doc}
    assert link_line(link) == f"[recorded-id] os-2: record d1 in case-1-evtx {text}"


@pytest.mark.parametrize("shape", list(SHAS))
def test_a_candidate_reads_each_hash_shape(shape):
    sha, text = SHAS[shape]
    c = {"audit_id": "sift-1", "path": "/x/a.csv"}
    if sha is not ...:
        c["sha256"] = sha
        assert candidate_line(c) == f"sift-1 path=/x/a.csv {text}"
    else:  # no hash recorded at all: none shown
        assert candidate_line(c) == "sift-1 path=/x/a.csv"


def test_a_path_with_no_hash_and_no_path_still_reads_no_file():
    link = {"method": "recorded-id", "audit_id": "os-3",
            "from": {"path": "", "sha256": ""}, "to": {"path": MOUNT, "sha256": ""}}  # fmt: skip
    assert link_line(link) == f"[recorded-id] os-3: (no file) -> {MOUNT} (no hash)"


def _provenance(root_sha, mount_sha):
    root = {"path": IMAGE, "sha256": root_sha, "label": "AI-registered"}
    chain = [
        {"method": "registered-path", "audit_id": "", "entry_sha256": "",
         "from": root, "to": root},
        {"method": "recorded-id", "audit_id": "opensearchingest1-tester-001",
         "entry_sha256": "e" * 64, "from": {"path": IMAGE, "sha256": root_sha},
         "to": {"path": MOUNT, "sha256": mount_sha}},
    ]  # fmt: skip
    art = {"source": IMAGE, "extraction": "idx_search", "content": "4624",
           "audit_id": "sift-tester-20261016-001", "provenance_grade": "FULL",
           "provenance_reason": "", "provenance_chain": chain,
           "provenance_root": root, "provenance_roots": [root]}  # fmt: skip
    return {"provenance_schema": 2, "provenance_grade": "FULL", "artifacts": [art]}


def test_finding_lines_leave_the_stored_finding_as_it_was():
    f = {"id": "F-1", **_provenance("", "")}
    before = copy.deepcopy(f)
    text = "\n".join(finding_lines(f))
    assert f == before
    assert f"root: {IMAGE} (no hash) (AI-registered)" in text


CHAIN_VIEWS = ["review-detail", "report"]
ROOT_VIEWS = ["approve", "approve-ids", "approve-review"]
# `vhir reject` shows no provenance: the Root line is part of an approval's
# checks, which a rejection doesn't run
NO_PROVENANCE_VIEWS = ["reject-ids", "reject-review"]


def _out(name, case, monkeypatch, capsys, root_sha, mount_sha):  # noqa: F811
    def no_reason(prompt=""):
        raise _Prompt

    monkeypatch.setattr("vhir_cli.approval_auth.read_tty_line", no_reason)
    return _view(name, case, monkeypatch, capsys, **_provenance(root_sha, mount_sha))


@pytest.mark.parametrize("name", CHAIN_VIEWS)
def test_an_empty_hash_reads_no_hash_in_the_chain(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, "", "")
    assert "sha256=?" not in out
    assert f"root: {IMAGE} (no hash) (AI-registered)" in out
    assert f"-> {MOUNT} (no hash)" in out


@pytest.mark.parametrize("name", CHAIN_VIEWS)
def test_a_real_hash_reads_as_before_in_the_chain(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, REAL, REAL)
    assert "(no hash)" not in out
    assert f"root: {IMAGE} sha256={REAL[:16]} (AI-registered)" in out
    assert f"-> {MOUNT} sha256={REAL[:16]}" in out


@pytest.mark.parametrize("name", ROOT_VIEWS)
def test_an_empty_root_hash_reads_no_hash_before_the_password(
    name,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    out = _out(name, case, monkeypatch, capsys, "", "")
    assert "sha256=?" not in out
    roots = [ln for ln in out.split("\n") if ln.startswith("  Root: ")]
    assert roots == [f"  Root: {IMAGE} (no hash) (AI-registered)"], roots


@pytest.mark.parametrize("name", ROOT_VIEWS)
def test_a_real_root_hash_reads_as_before_before_the_password(
    name,
    case,  # noqa: F811
    monkeypatch,
    capsys,
):
    out = _out(name, case, monkeypatch, capsys, REAL, "")
    roots = [ln for ln in out.split("\n") if ln.startswith("  Root: ")]
    assert roots == [f"  Root: {IMAGE} sha256={REAL[:16]} (AI-registered)"], roots


@pytest.mark.parametrize("name", NO_PROVENANCE_VIEWS)
def test_reject_shows_no_root_and_no_sha256_question(name, case, monkeypatch, capsys):  # noqa: F811
    out = _out(name, case, monkeypatch, capsys, "", "")
    assert "F-tester-001" in out
    assert "sha256=?" not in out and "  Root: " not in out
