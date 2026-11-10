"""`vhir update` never asks which PyTorch build to install. It records the
build it detects from the installed torch when nothing is recorded, keeps an
existing record, and records --cpu or --gpu on every route but macOS. When the
recorded build and the GPU probe disagree, the update says how to switch.

Each row runs with a terminal, so a question would be asked if update still
asked one, and reads the manifest's torch_variant after the manifest step.
The routes: one process; a pull that changed vhir, so the new code finishes
from the handoff; an older vhir's update handed over (Step 4 again with no
questions); a handoff that is missing or unreadable."""

from __future__ import annotations

import re

import pytest

from tests.test_update_lock import _asked, _lock_of, _manifest, _update, box
from vhir_cli.main import build_parser

__all__ = ["box"]

OLDER = '{"older_update": true}'
CUDA_LINE = (
    "vhir update --cpu switches to the CPU build, then, on a terminal, lists the"
    " CUDA packages it no longer needs, with their sizes, and offers to remove them."
)
OTHER_LINE = "vhir update --cpu switches to the CPU build."
GPU_LINE = "vhir update --gpu for faster index builds"
SIZE = re.compile(r"\d\s*GB")


def _start(record=None, rag=True):
    def edit(m):
        if not rag:
            del m["packages"]["rag-mcp"]
        if record:
            m["torch_variant"] = record
        return m

    return edit


def _route(box, route, **kw):
    """Run one update on `route`; returns every command run, in order."""
    if route == "direct":
        calls, exited = _update(box, tty=True, **kw)
        assert exited is None
        return calls
    if route == "older":
        calls, exited = _update(box, tty=True, after_pull=OLDER, **kw)
        assert exited is None
        return calls
    # "reexec": the pull changes vhir, so Steps 4.5-9 run in the new process,
    # started with only what the first one put on its command line
    first, exited = _update(box, tty=True, vhir_moves=True, **kw)
    assert exited is None
    args = _new_process_args(first)
    for key in ("manifest", "cpu", "gpu"):
        kw.pop(key, None)
    second, exited = _new_process(box, args, **kw)
    assert exited is None
    return first + second


def _new_process_args(calls, handoff=None):
    """The new process's options, parsed from the os.execv argv; `handoff`
    replaces the --after-pull text."""
    (execv,) = [c for c in calls if c[0] == "execv"]
    argv = execv[execv.index("update") :]
    if handoff is not None:
        argv[argv.index("--after-pull") + 1] = handoff
    return build_parser().parse_args(argv)


def _new_process(box, args, **kw):
    return _update(
        box,
        tty=True,
        after_pull=args.after_pull,
        cpu=bool(args.cpu),
        gpu=bool(args.gpu),
        no_restart=bool(args.no_restart),
        **kw,
    )


def _record(box):
    return _manifest(box).get("torch_variant")


ROUTES = ["direct", "reexec", "older"]


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "torch,lock,record",
    [
        ("2.14.1", "vhir.lock", "gpu"),  # untagged on Linux: the CUDA build
        ("2.1.0+cu121", "vhir.lock", "gpu"),
        ("2.14.1+cpu", "vhir-cpu.lock", "cpu"),
    ],
)
def test_the_installed_build_is_recorded_without_a_question(
    box, route, torch, lock, record
):
    assert "torch_variant" not in _manifest(box)  # never asked before
    calls = _route(box, route, torch=torch)
    assert not _asked(calls)
    assert _lock_of(calls).endswith(lock)
    assert _record(box) == record


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("before", [None, "cpu", "gpu"])
@pytest.mark.parametrize("gpu_found", [False, True])
def test_rag_without_torch_picks_cpu_unless_a_gpu_is_found(
    box, route, before, gpu_found
):
    calls = _route(box, route, manifest=_start(before), torch="", gpu_found=gpu_found)
    assert not _asked(calls)
    found = "gpu" if gpu_found else "cpu"
    assert _lock_of(calls).endswith("vhir.lock" if gpu_found else "vhir-cpu.lock")
    assert _record(box) == (before or found)  # a record is kept, never the build


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("before", [None, "cpu", "gpu"])
def test_no_torch_and_no_rag_creates_no_record_and_keeps_one(
    box, capsys, route, before
):
    calls = _route(box, route, manifest=_start(before, rag=False), torch="")
    assert not _asked(calls)
    assert "PyTorch build: cpu" in capsys.readouterr().out
    assert _lock_of(calls).endswith("vhir-cpu.lock")
    if before is None:
        assert "torch_variant" not in _manifest(box)
    else:
        assert _record(box) == before


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("flag", ["cpu", "gpu"])
def test_a_flag_is_recorded_with_no_torch_and_no_rag(box, route, flag):
    calls = _route(
        box,
        route,
        manifest=_start(rag=False),
        torch="",
        cpu=flag == "cpu",
        gpu=flag == "gpu",
    )
    assert not _asked(calls)
    assert _lock_of(calls).endswith("vhir-cpu.lock" if flag == "cpu" else "vhir.lock")
    assert _record(box) == flag


@pytest.mark.parametrize("handoff", ["{not json", "", "{}"])
@pytest.mark.parametrize("flag", ["cpu", "gpu"])
def test_a_flag_survives_a_missing_or_unreadable_handoff(box, flag, handoff):
    first, _ = _update(
        box,
        tty=True,
        vhir_moves=True,
        torch="2.14.1",
        cpu=flag == "cpu",
        gpu=flag == "gpu",
    )
    second, exited = _new_process(box, _new_process_args(first, handoff))
    assert exited is None and not _asked(first + second)
    assert _record(box) == flag


@pytest.mark.parametrize("flag", ["cpu", "gpu"])
def test_on_macos_a_flag_is_not_applicable_and_not_recorded(box, capsys, flag):
    calls, exited = _update(
        box, tty=True, platform="darwin", cpu=flag == "cpu", gpu=flag == "gpu"
    )
    assert exited is None and not _asked(calls)
    out = capsys.readouterr().out
    assert f"--{flag} is not applicable on macOS (PyPI's PyTorch has no CUDA)." in out
    assert "torch_variant" not in _manifest(box)


def _switch_lines(text):
    return [ln for ln in text.splitlines() if "vhir update --" in ln]


@pytest.mark.parametrize(
    "torch,gpu_found,record,line,not_line",
    [
        ("2.14.1", False, "gpu", CUDA_LINE, None),  # R5's shape
        ("2.5.1+rocm6.2", False, "gpu", OTHER_LINE, "lists the CUDA packages"),
        ("2.5.1+xpu", False, "gpu", OTHER_LINE, "lists the CUDA packages"),
        ("2.14.1+cpu", True, "cpu", GPU_LINE, None),
        ("2.14.1+cpu", False, "cpu", None, None),
    ],
)
def test_a_build_the_gpu_probe_disagrees_with_names_its_switch(
    box, capsys, torch, gpu_found, record, line, not_line
):
    calls, exited = _update(box, tty=True, torch=torch, gpu_found=gpu_found)
    assert exited is None and not _asked(calls)
    assert _record(box) == record
    seen = capsys.readouterr()
    text = seen.out + seen.err
    if line:
        assert line in text
    else:
        assert "switches to the CPU build" not in text and GPU_LINE not in text
    if not_line:
        assert not_line not in text
    assert not [ln for ln in _switch_lines(text) if SIZE.search(ln)]  # no size
