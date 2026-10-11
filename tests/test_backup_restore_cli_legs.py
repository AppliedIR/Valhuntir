"""Backup and restore through the real `vhir` command line: a backup made
before the case had an identity restores as the right case, and nothing is
left out or left behind silently.

- A backup with no identity is a copy only beside a folder whose CASE.yaml
  still reads as the case; restored in its place, it keeps reading its old
  indices, and an identity this box recorded for the folder is named.
- A case-root backup-manifest.json or .backup-in-progress, and a file that
  isn't regular (a named pipe), stop the backup before copying, unless
  --skip-unreadable lists them as skipped.
- A backup stopped before copying leaves nothing in its destination.
- Without sift-common, a copy beside an original whose identity it would
  share is refused before anything is written.

Each leg runs `vhir` (main) with real arguments in this process, so the
suite's /var/lib/vhir isolation holds. Legs that need sift-common or
opensearch-mcp are skipped, and named, where those aren't installed.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture
def box(tmp_path, monkeypatch):
    for name in ("home", "cases", "out"):
        (tmp_path / name).mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("VHIR_CASES_DIR", str(tmp_path / "cases"))
    monkeypatch.setenv("VHIR_EXAMINER", "alice")
    monkeypatch.delenv("VHIR_CASE_DIR", raising=False)
    return tmp_path


def vhir(capsys, *args) -> tuple[int, str]:
    """`vhir <args>`: its exit code and everything it printed."""
    from vhir_cli.main import main

    old, sys.argv = sys.argv, ["vhir", *map(str, args)]
    try:
        main()
        code = 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    finally:
        sys.argv = old
    out = capsys.readouterr()
    return code, out.out + out.err


def make_case(box, cid="C-1") -> Path:
    d = box / "cases" / cid
    d.mkdir()
    (d / "CASE.yaml").write_text(f"case_id: {cid}\nstatus: open\n")
    (d / "findings.json").write_text("[]")
    (d / "timeline.json").write_text("[]")
    return d


def meta(d: Path):
    p = d / "CASE.yaml"
    return yaml.safe_load(p.read_text()) if p.exists() else None


def only_backup(box) -> Path:
    (b,) = [p for p in (box / "out").iterdir() if p.is_dir()]
    return b


def backed_up(box, capsys) -> Path:
    code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
    assert code == 0, out
    return only_backup(box)


def legacy_read(case_dir: Path) -> str:
    """The pre-0.6.4 index expression the case reads (opensearch-mcp's own)."""
    from opensearch_mcp.case_scope import CaseScope, legacy_expression
    from opensearch_mcp.write_context import case_identity

    c12, ver = case_identity(case_dir)
    scope = CaseScope(case_id=case_dir.name, case_dir=case_dir, c12=c12,
                      naming_version=ver, legacy_id="C-1")  # fmt: skip
    return legacy_expression(scope)


def needs_sift_and_opensearch():
    pytest.importorskip("sift_common", reason="needs sift-common (SIFT workstation)")
    pytest.importorskip("opensearch_mcp", reason="needs opensearch-mcp")


# --- a backup made before the case had an identity -------------------------


@pytest.mark.parametrize(
    "damage", ["CASE.yaml removed", "folder emptied", "empty", "unparseable", "a list"]
)
def test_a_pre_identity_backup_beside_a_damaged_original_restores_as_the_case(
    box, capsys, damage
):
    needs_sift_and_opensearch()
    src = make_case(box)
    bk = backed_up(box, capsys)
    assert "case_uuid" not in meta(bk)
    if damage == "CASE.yaml removed":
        (src / "CASE.yaml").unlink()
    elif damage == "folder emptied":
        shutil.rmtree(src)
        src.mkdir()
    else:
        text = {"empty": "", "unparseable": "case_id: [unclosed\n", "a list": "- a\n"}
        (src / "CASE.yaml").write_text(text[damage])
    target = box / "cases" / "C-1-restored"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 0, out
    assert "legacy_alias" not in meta(target)
    assert vhir(capsys, "case", "activate", "C-1-restored")[0] == 0
    assert "case-c-1-*" in legacy_read(target).split(",")


def test_a_pre_identity_backup_in_place_names_the_identity_it_cant_carry(box, capsys):
    needs_sift_and_opensearch()
    src = make_case(box)
    bk = backed_up(box, capsys)
    assert vhir(capsys, "case", "activate", "C-1")[0] == 0
    was = meta(src)["case_uuid"]
    shutil.rmtree(src)  # the original is lost; restored in its place
    code, out = vhir(capsys, "restore", bk, "--target", src, "--skip-opensearch")
    assert code == 0, out
    c12 = was.replace("-", "")[:12]
    assert f"held case identity {was} on this box" in out
    assert f"indices named case-{c12}-* won't be read by the restored case" in out


@pytest.mark.parametrize("original", ["no identity", "an identity since"])
def test_beside_a_live_original_a_pre_identity_backup_restores_as_before(
    box, capsys, original
):
    """Controls: a live original with no identity gives a copy with its own,
    reading no old indices; one activated since gives a copy that keeps
    reading the case's old indices, as before."""
    needs_sift_and_opensearch()
    make_case(box)
    bk = backed_up(box, capsys)
    if original == "an identity since":
        assert vhir(capsys, "case", "activate", "C-1")[0] == 0
    target = box / "cases" / "C-1-restored"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 0, out
    assert vhir(capsys, "case", "activate", "C-1-restored")[0] == 0
    if original == "no identity":
        assert meta(target)["legacy_alias"] == "none" and legacy_read(target) == ""
    else:
        assert "case-c-1-*" in legacy_read(target).split(",")


# --- names the backup writes, and files that aren't regular ----------------


def _manifest(bk):
    return json.loads((bk / "backup-manifest.json").read_text())


@pytest.mark.parametrize("name", ["backup-manifest.json", ".backup-in-progress"])
def test_a_case_root_file_under_a_name_the_backup_writes_stops_it(box, capsys, name):
    src = make_case(box)
    (src / name).write_text("the examiner's own file\n")
    code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
    assert code == 1
    assert "Backup stopped before copying" in out and f"{src / name}: the backup" in out
    assert list((box / "out").iterdir()) == []
    code, out = vhir(
        capsys, "backup", "--case", "C-1", box / "out", "--skip-unreadable"
    )
    assert code == 0, out
    bk = only_backup(box)
    assert [s["path"] for s in _manifest(bk)["skipped"]] == [name]
    assert vhir(capsys, "backup", "--verify", bk)[0] == 0


def test_another_tools_manifest_in_a_subfolder_is_case_data(box, capsys):
    src = make_case(box)
    (src / "work").mkdir()
    (src / "work" / "backup-manifest.json").write_text('{"tool": "x"}')
    bk = backed_up(box, capsys)
    assert "work/backup-manifest.json" in {f["path"] for f in _manifest(bk)["files"]}
    target = box / "cases" / "R"
    assert vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")[0] == 0
    assert (target / "work" / "backup-manifest.json").read_text() == '{"tool": "x"}'


@pytest.mark.parametrize("where", ["notes.pipe", "work/spool.fifo"])
def test_a_named_pipe_stops_the_backup_and_skip_unreadable_lists_it(box, capsys, where):
    src = make_case(box)
    (src / where).parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(src / where)
    code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
    assert code == 1 and "Backup stopped before copying" in out
    assert f"{src / where}: not a regular file (a named pipe" in out
    assert list((box / "out").iterdir()) == []
    code, out = vhir(
        capsys, "backup", "--case", "C-1", box / "out", "--skip-unreadable"
    )
    assert code == 0, out
    assert [s["path"] for s in _manifest(only_backup(box))["skipped"]] == [where]


def test_a_named_pipe_in_evidence_left_out_is_ignored(box, capsys):
    src = make_case(box)
    (src / "evidence").mkdir()
    os.mkfifo(src / "evidence" / "run.fifo")
    backed_up(box, capsys)


# --- a backup stopped before copying ----------------------------------------


def test_a_backup_stopped_before_copying_leaves_its_destination_empty(box, capsys):
    src = make_case(box)
    (src / "work").mkdir()
    os.symlink("/etc/hostname", src / "work" / "h")  # leads out of the case
    for _ in range(2):
        code, out = vhir(capsys, "backup", "--case", "C-1", box / "out")
        assert code == 1 and "Backup stopped before copying" in out
    assert list((box / "out").iterdir()) == []


# --- without sift-common ----------------------------------------------------


def _without_sift_common(monkeypatch):
    for name in [
        m for m in sys.modules if m == "sift_common" or m.startswith("sift_common.")
    ]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, "sift_common", None)  # not installed


def test_without_sift_common_a_copy_sharing_the_originals_identity_is_refused(
    box, capsys, monkeypatch
):
    pytest.importorskip(
        "sift_common", reason="activating the original needs sift-common"
    )
    make_case(box)
    assert vhir(capsys, "case", "activate", "C-1")[0] == 0
    bk = backed_up(box, capsys)
    assert meta(bk).get("case_uuid")
    _without_sift_common(monkeypatch)
    target = box / "cases" / "C-1-copy"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 1
    assert "needs its own case identity" in out and "Nothing was written" in out
    assert "--skip-opensearch" not in out
    assert not target.exists()


def test_without_sift_common_a_pre_identity_copy_restores_as_before(
    box, capsys, monkeypatch
):
    make_case(box)
    bk = backed_up(box, capsys)
    _without_sift_common(monkeypatch)
    target = box / "cases" / "C-1-restored"
    code, out = vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch")
    assert code == 0, out
    assert vhir(capsys, "case", "activate", "C-1-restored")[0] == 0


def test_without_sift_common_a_restore_in_place_is_allowed(box, capsys, monkeypatch):
    pytest.importorskip(
        "sift_common", reason="activating the original needs sift-common"
    )
    src = make_case(box)
    assert vhir(capsys, "case", "activate", "C-1")[0] == 0
    bk = backed_up(box, capsys)
    shutil.rmtree(src)
    _without_sift_common(monkeypatch)
    code, out = vhir(capsys, "restore", bk, "--target", src, "--skip-opensearch")
    assert code == 0, out


def _within(seconds, pipe, call):
    """call() in a thread; a run still blocked after `seconds` is released by
    opening `pipe`, and fails."""
    import threading

    result = {}
    t = threading.Thread(target=lambda: result.update(r=call()), daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        with open(pipe, "w"):
            pass
        t.join(seconds)
        pytest.fail(f"hung on the pipe {pipe}")
    return result["r"]


@pytest.mark.parametrize("extra", [[], ["--skip-unreadable"]], ids=["plain", "skip"])
def test_a_named_pipe_at_case_yaml_is_refused_by_name_instead_of_hanging(
    box, capsys, extra
):
    src = make_case(box)
    (src / "CASE.yaml").unlink()
    os.mkfifo(src / "CASE.yaml")
    code, out = _within(
        20,
        src / "CASE.yaml",
        lambda: vhir(capsys, "backup", "--case", "C-1", box / "out", *extra),
    )
    assert code == 1
    assert f"{src / 'CASE.yaml'} isn't a regular file" in out
    assert list((box / "out").iterdir()) == []


def _reachable_cluster(box, monkeypatch):
    """opensearch-mcp as installed, with a cluster that answers: the backup's
    OpenSearch check then reads the case's CASE.yaml first."""
    import importlib.machinery
    import types

    (box / "home" / ".vhir").mkdir(exist_ok=True)
    (box / "home" / ".vhir" / "opensearch.yaml").write_text(
        "host: http://127.0.0.1:9200\n"
    )
    client = types.SimpleNamespace(
        cluster=types.SimpleNamespace(health=lambda: {"status": "green"}),
        cat=types.SimpleNamespace(indices=lambda **k: []),
    )
    osm = types.ModuleType("opensearch_mcp")
    osm.__spec__ = importlib.machinery.ModuleSpec("opensearch_mcp", None)
    osm.client = types.SimpleNamespace(get_client=lambda *a, **k: client)
    osm.paths = types.SimpleNamespace(vhir_dir=lambda: box / "home" / ".vhir")
    for name, mod in (("opensearch_mcp", osm), ("opensearch_mcp.client", osm.client),
                      ("opensearch_mcp.paths", osm.paths)):  # fmt: skip
        monkeypatch.setitem(sys.modules, name, mod)


def test_a_named_pipe_at_case_yaml_with_a_cluster_up_is_refused_by_name(
    box, capsys, monkeypatch
):
    src = make_case(box)
    (src / "CASE.yaml").unlink()
    os.mkfifo(src / "CASE.yaml")
    _reachable_cluster(box, monkeypatch)
    code, out = _within(
        20,
        src / "CASE.yaml",
        lambda: vhir(capsys, "backup", "--case", "C-1", box / "out"),
    )
    assert code == 1
    assert f"{src / 'CASE.yaml'} isn't a regular file" in out
    assert list((box / "out").iterdir()) == []


def test_a_restore_beside_an_original_whose_case_yaml_is_a_pipe_is_refused_by_name(
    box, capsys
):
    src = make_case(box)
    bk = backed_up(box, capsys)
    (src / "CASE.yaml").unlink()
    os.mkfifo(src / "CASE.yaml")
    target = box / "cases" / "C-1-restored"
    code, out = _within(
        20,
        src / "CASE.yaml",
        lambda: vhir(capsys, "restore", bk, "--target", target, "--skip-opensearch"),
    )
    assert code == 1
    assert f"{src / 'CASE.yaml'} isn't a regular file" in out
    assert not target.exists()


@pytest.mark.parametrize(
    "parts", [[], ["--include-evidence"]], ids=["case", "evidence"]
)
def test_a_named_pipe_at_evidence_json_stops_the_backup_instead_of_hanging(
    box, capsys, parts
):
    """The registry is read before the scan: a pipe there used to block the
    read, with or without --skip-unreadable. Each run gets 20 seconds; a hung
    one is released by opening the pipe, and fails."""
    src = make_case(box)
    os.mkfifo(src / "evidence.json")

    def run(*extra):
        args = ("backup", "--case", "C-1", box / "out", *parts, *extra)
        return _within(20, src / "evidence.json", lambda: vhir(capsys, *args))

    code, out = run()
    assert code == 1 and "Backup stopped before copying" in out
    assert f"{src / 'evidence.json'}: not a regular file (a named pipe" in out
    assert list((box / "out").iterdir()) == []
    code, out = run("--skip-unreadable")
    assert code == 0, out
    assert [s["path"] for s in _manifest(only_backup(box))["skipped"]] == [
        "evidence.json"
    ]
