"""`vhir update` installs from the dependency lock in the pulled sift-mcp.

Every package but OpenCTI's goes through one locked install (`-c`/`-b` with
`deps/vhir.lock`), opensearch-mcp included whenever it's installed, even
though the installer never put it in the manifest, and so are the installed
packages the lock names (`check-lock.py --installed`), so that it moves them. The venv is checked
against the lock (`deps/check-lock.py --strict`), OpenCTI's client is then
installed unlocked, and the venv is checked again (`--final`). uv older than
0.6.0 ignores the lock's hashes, so update refuses it before pulling.
subprocess is a stand-in that records each command.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from vhir_cli.commands.update import _PACKAGE_PATHS, cmd_update

REAL_FIND_SPEC = importlib.util.find_spec


@pytest.fixture
def box(tmp_path):
    src = tmp_path / ".vhir" / "src" / "sift-mcp"
    for rel in _PACKAGE_PATHS.values():
        (src / rel).mkdir(parents=True)
    (src / "deps").mkdir()
    (src / "deps" / "vhir.lock").write_text("# lock\n")
    (src / "deps" / "vhir-cpu.lock").write_text("# variant cpu\n")
    (src / "deps" / "check-lock.py").write_text("")
    (tmp_path / ".vhir" / "src" / "vhir").mkdir()
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").write_text("#!/bin/sh\n")
    names = [
        "forensic-knowledge",
        "sift-common",
        "forensic-mcp",
        "sift-mcp",
        "sift-gateway",
        "vhir-cli",
        "case-mcp",
        "report-mcp",
        "rag-mcp",
        "opencti-mcp",
    ]
    manifest = {
        "source": str(src),
        "venv": str(venv),
        "packages": {n: {} for n in names},
        "client": "",
    }
    (tmp_path / ".vhir" / "manifest.json").write_text(json.dumps(manifest))
    return SimpleNamespace(
        home=tmp_path,
        src=src,
        lock=src / "deps" / "vhir.lock",
        cpu_lock=src / "deps" / "vhir-cpu.lock",
        manifest=tmp_path / ".vhir" / "manifest.json",
    )


def _update(
    box,
    *,
    uv="uv 0.12.20",
    check_rc=None,
    opensearch=False,
    opencti=False,
    manifest=None,
    cpu=False,
    gpu=False,
    torch="2.14.0",
    tty=False,
    answers=(),
    platform="linux",
    leftovers="",
    install_rc=0,
    opencti_rc=0,
    after_check_rc=0,
    uninstall="ok",
    smi_hangs=False,
):
    """Run cmd_update; returns (commands, SystemExit or None). By default the
    venv has GPU PyTorch (torch 2.14.0) and stdin isn't a terminal; `answers`
    are what input() returns, in order; `leftovers` is check-lock's
    --cuda-leftovers output."""
    check_rc = check_rc or {}
    calls = []
    if manifest:
        path = box.home / ".vhir" / "manifest.json"
        path.write_text(json.dumps(manifest(json.loads(path.read_text()))))
    os_repo = box.home / "opensearch-mcp"
    (os_repo / ".git").mkdir(parents=True, exist_ok=True)
    (os_repo / "src" / "opensearch_mcp").mkdir(parents=True, exist_ok=True)

    def find_spec(name, *a, **kw):
        if name == "opensearch_mcp":
            if not opensearch:
                return None
            init = os_repo / "src" / "opensearch_mcp" / "__init__.py"
            return SimpleNamespace(origin=str(init))
        if name == "opencti_mcp":
            return SimpleNamespace(origin="x") if opencti else None
        return REAL_FIND_SPEC(name, *a, **kw)

    replies = list(answers)

    def run(cmd, **kw):
        calls.append([str(c) for c in cmd])
        result = MagicMock(returncode=0, stdout="0", stderr="")
        if cmd[0] == "nvidia-smi" and smi_hangs:
            raise subprocess.TimeoutExpired(cmd, 30)
        if cmd[:3] == ["uv", "pip", "uninstall"] and uninstall != "ok":
            if uninstall == "timeout":
                raise subprocess.TimeoutExpired(cmd, 600)
            if kw.get("check"):  # as subprocess.run does with check=True
                raise subprocess.CalledProcessError(2, cmd)
            result.returncode = 2
        if len(cmd) > 2 and cmd[1] == "-c" and "torch" in cmd[2]:
            result.returncode, result.stdout = (0, torch) if torch else (1, "")
        elif cmd[:3] == ["uv", "pip", "install"] and "-c" in cmd:
            result.returncode = install_rc
        elif cmd[:3] == ["uv", "pip", "install"]:  # opencti-mcp, unlocked
            result.returncode = opencti_rc
        elif cmd[:3] == ["uv", "pip", "check"]:
            result.returncode = after_check_rc
        elif cmd[:2] == ["uv", "--version"]:
            result.stdout = uv
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif len(cmd) > 2 and str(cmd[1]).endswith("check-lock.py"):
            result.returncode = check_rc.get(cmd[2], 0)
            result.stdout = {"--installed": "setuptools starlette"}.get(cmd[2], "")
            if cmd[2] == "--cuda-leftovers":
                result.stdout = leftovers
        return result

    def ask(prompt=""):
        calls.append(["input", prompt])
        reply = replies.pop(0) if replies else ""
        if reply is EOFError:  # end of input at this prompt
            raise EOFError
        return reply

    exited = None
    with (
        patch("pathlib.Path.home", return_value=box.home),
        patch("subprocess.run", side_effect=run),
        patch("importlib.util.find_spec", side_effect=find_spec),
        patch("builtins.input", side_effect=ask),
        patch("sys.stdin.isatty", return_value=tty),
        patch("sys.platform", platform),
        patch(
            "shutil.which", return_value="/usr/bin/nvidia-smi" if smi_hangs else None
        ),
    ):
        try:
            # A MagicMock's unset attributes are truthy: the flags are set.
            args = MagicMock(check=False, no_restart=True, cpu=cpu, gpu=gpu)
            cmd_update(args, {})
        except SystemExit as e:
            exited = e
    return calls, exited


def _steps(calls):
    out = []
    for c in calls:
        if c[:3] == ["uv", "pip", "install"]:
            out.append(("install", c))
        elif len(c) > 2 and c[1].endswith("check-lock.py"):
            out.append(("check", c[2]))
    return out


def test_one_locked_install_then_opencti_unlocked_with_checks_between(box):
    calls, exited = _update(box)
    assert exited is None
    steps = _steps(calls)
    # The contract: --strict passes immediately before the unlocked OpenCTI
    # step, and --final runs right after it.
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "--installed",
        "install",
        "--strict",
        "install",
        "--final",
    ]
    locked, opencti = steps[1][1], steps[3][1]
    # What the venv already has that the lock names goes into the locked
    # install, as plain requirements; the unlocked step doesn't get them.
    assert locked[locked.index("-b") + 2 : locked.index("-b") + 4] == [
        "setuptools",
        "starlette",
    ]
    assert "starlette" not in opencti
    lock = str(box.lock)
    assert (
        locked[locked.index("-c") + 1] == lock
        and locked[locked.index("-b") + 1] == lock
    )
    assert not any("packages/opencti" in a for a in locked)
    assert any(a.endswith("packages/forensic-rag") for a in locked)
    assert "-c" not in opencti and "-b" not in opencti
    assert opencti[-2:] == ["-e", str(box.src / "packages" / "opencti")]
    # The checks run the pulled sift-mcp's checker against its lock.
    for c in calls:
        if len(c) > 2 and c[1].endswith("check-lock.py"):
            assert c[1] == str(box.src / "deps" / "check-lock.py")
            assert c[c.index("--lock") + 1] == lock
    # pycti's otel pins are held in the lock now; nothing reinstalls the exporter.
    assert "opentelemetry-exporter-otlp-proto-grpc" not in locked


def test_installed_opensearch_mcp_is_reinstalled_though_not_in_the_manifest(box):
    calls, exited = _update(box, opensearch=True)
    assert exited is None
    locked = next(c for kind, c in _steps(calls) if kind == "install")
    assert str(box.home / "opensearch-mcp") in locked
    assert locked.index(str(box.home / "opensearch-mcp")) > locked.index("-c")


def test_opensearch_mcp_not_installed_is_left_alone(box):
    calls, _ = _update(box, opensearch=False)
    locked = next(c for kind, c in _steps(calls) if kind == "install")
    assert not any("opensearch-mcp" in a for a in locked)


def test_without_opencti_both_checks_still_run(box):
    def drop(m):
        del m["packages"]["opencti-mcp"]
        return m

    calls, exited = _update(box, manifest=drop)
    assert exited is None
    steps = _steps(calls)
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "--installed",
        "install",
        "--strict",
        "--final",
    ]


@pytest.mark.parametrize("mode", ["--installed", "--strict", "--final"])
def test_a_failed_check_stops_the_update(box, capsys, mode):
    calls, exited = _update(box, check_rc={mode: 1})
    assert exited is not None and exited.code == 1
    assert "dependency lock" in capsys.readouterr().err
    steps = _steps(calls)
    assert steps[-1] == ("check", mode)  # nothing after it, not even an install
    assert not any(c[:2] == ["systemctl", "--user"] for c in calls)


@pytest.mark.parametrize(
    "uv,refused",
    [
        ("uv 0.5.31", True),
        ("uv 0.4.0 (abc 2024-08-01)", True),
        ("not uv", True),
        ("uv 0.6.0", True),
        ("uv 0.6.8", True),
        ("uv 0.6.9", False),
        ("uv 0.12.20 (x86_64-unknown-linux-gnu)", False),
    ],
)
def test_uv_older_than_0_6_9_is_refused_before_anything_is_pulled(
    box, capsys, uv, refused
):
    calls, exited = _update(box, uv=uv)
    pulled = any("pull" in c for c in calls)
    if refused:
        assert exited is not None and exited.code == 1
        err = capsys.readouterr().err
        assert "older than 0.6.9" in err and "--torch-backend" in err
        assert not pulled and not _steps(calls)
    else:
        assert exited is None and pulled


def test_a_pulled_sift_mcp_without_the_lock_stops_before_installing(box, capsys):
    box.lock.unlink()
    calls, exited = _update(box)
    assert exited is not None and exited.code == 1
    assert "Dependency lock not found" in capsys.readouterr().err
    assert not _steps(calls)


def test_opencti_installed_but_not_in_the_manifest_still_gets_its_step(box):
    def drop(m):
        del m["packages"]["opencti-mcp"]
        return m

    calls, exited = _update(box, manifest=drop, opencti=True)
    assert exited is None
    steps = _steps(calls)
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "--installed",
        "install",
        "--strict",
        "install",
        "--final",
    ]
    assert "-c" not in steps[3][1] and steps[3][1][-1].endswith("packages/opencti")


# --- The PyTorch build ----------------------------------------------------------


def _locked(calls):
    (locked,) = [c for c in calls if c[:3] == ["uv", "pip", "install"] and "-c" in c]
    return locked


def _lock_of(calls):
    locked = _locked(calls)
    return locked[locked.index("-c") + 1]


def _manifest(box):
    return json.loads(box.manifest.read_text())


def _asked(calls):
    return [c[1] for c in calls if c[0] == "input"]


@pytest.mark.parametrize("cpu,gpu", [(True, False), (False, True)])
def test_a_flag_sets_the_build_and_the_record(box, cpu, gpu):
    installed = "2.14.0" if cpu else "2.14.0+cpu"  # the other build
    calls, exited = _update(box, cpu=cpu, gpu=gpu, torch=installed, tty=True)
    assert exited is None and not _asked(calls)
    locked = _locked(calls)
    assert _lock_of(calls) == str(box.cpu_lock if cpu else box.lock)
    assert ("--torch-backend" in locked) is cpu
    pairs = list(zip(locked, locked[1:], strict=False))
    assert (("--reinstall-package", "torch") in pairs) is gpu  # +cpu satisfies ==2.14.0
    assert _manifest(box)["torch_variant"] == ("cpu" if cpu else "gpu")


@pytest.mark.parametrize(
    "installed,variant", [("2.10.0", "gpu"), ("2.14.0+cpu", "cpu"), ("", "cpu")]
)
def test_without_a_terminal_the_installed_build_is_kept(
    box, capsys, installed, variant
):
    calls, exited = _update(box, torch=installed)
    assert exited is None and not _asked(calls)
    assert _lock_of(calls) == str(box.cpu_lock if variant == "cpu" else box.lock)
    out = capsys.readouterr().out
    assert f"PyTorch build: {variant} (switch with: vhir update --cpu or --gpu)" in out
    assert "torch_variant" not in _manifest(box)


@pytest.mark.parametrize(
    "answer,variant", [("", "cpu"), ("gpu", "gpu"), ("CPU", "cpu")]
)
def test_an_old_install_on_a_terminal_is_asked_default_cpu(
    box, capsys, answer, variant
):
    calls, exited = _update(box, torch="2.10.0", tty=True, answers=[answer])
    assert exited is None and len(_asked(calls)) == 1
    out = capsys.readouterr().out
    assert "Installed now: the GPU build (torch 2.10.0)" in out
    assert "0.2 GB download" in out and "3 GB download" in out
    assert _lock_of(calls) == str(box.cpu_lock if variant == "cpu" else box.lock)
    assert _manifest(box)["torch_variant"] == variant


def test_a_wrong_answer_is_asked_again(box):
    calls, _ = _update(box, torch="2.10.0", tty=True, answers=["gpus", "gpu"])
    assert len(_asked(calls)) == 2 and _manifest(box)["torch_variant"] == "gpu"


def test_an_install_already_asked_is_not_asked_again(box):
    """Its twin above asks: the record is what stops it."""
    calls, exited = _update(
        box, manifest=lambda m: {**m, "torch_variant": "gpu"}, torch="2.14.0", tty=True
    )
    assert exited is None and not _asked(calls)


def test_the_installed_build_beats_a_stale_record(box):
    """torch was swapped by a run that stopped before the manifest."""
    calls, _ = _update(
        box,
        manifest=lambda m: {**m, "torch_variant": "gpu"},
        torch="2.14.0+cpu",
        tty=True,
    )
    assert _lock_of(calls) == str(box.cpu_lock) and not _asked(calls)


@pytest.mark.parametrize("rag,asks", [(True, True), (False, False)])
def test_without_torch_it_asks_only_when_installing_rag(box, rag, asks):
    def recorded(m):
        if not rag:
            del m["packages"]["rag-mcp"]
        return {**m, "torch_variant": "cpu"}

    calls, _ = _update(box, manifest=recorded, torch="", tty=True)
    assert bool(_asked(calls)) is asks


@pytest.mark.parametrize("cpu", [False, True])
def test_macos_uses_the_pypi_lock_and_records_nothing(box, capsys, cpu):
    calls, exited = _update(box, cpu=cpu, torch="2.14.0", tty=True, platform="darwin")
    assert exited is None and not _asked(calls)
    assert _lock_of(calls) == str(box.lock) and "--torch-backend" not in _locked(calls)
    assert "torch_variant" not in _manifest(box)
    if cpu:
        assert "--cpu is not applicable on macOS" in capsys.readouterr().out


@pytest.mark.parametrize("cpu,hint", [(True, True), (False, False)])
def test_a_failed_install_on_the_cpu_lock_names_the_pytorch_index(
    box, capsys, cpu, hint
):
    _, exited = _update(box, cpu=cpu, gpu=not cpu, install_rc=1)
    assert exited is not None and exited.code == 1
    assert ("download.pytorch.org" in capsys.readouterr().err) is hint


def test_a_missing_cpu_lock_is_named(box, capsys):
    box.cpu_lock.unlink()
    calls, exited = _update(box, cpu=True)
    assert exited is not None and "Dependency lock not found" in capsys.readouterr().err
    assert not _steps(calls)


# --- Removing the CUDA packages the CPU build left: only on an explicit yes ----

LEFTOVERS = (
    "nvidia-cudnn-cu12 1054000000\nnvidia-cublas-cu12 870000000\ntriton 668000000\n"
)
NAMES = ["nvidia-cudnn-cu12", "nvidia-cublas-cu12", "triton"]


def _cleanup(box, **kw):
    kw.setdefault("cpu", True)
    kw.setdefault("tty", True)
    return _update(box, leftovers=LEFTOVERS, **kw)


def _index(calls, head):
    return next(i for i, c in enumerate(calls) if c[: len(head)] == head)


def test_yes_removes_them_after_the_final_check_and_cleans_the_cache(box, capsys):
    calls, exited = _cleanup(box, answers=["yes"])
    assert exited is None
    out = capsys.readouterr().out
    assert (
        "2.59 GB" in out and "--link-mode symlink" in out
    )  # the total; who else it affects
    final = next(i for i, c in enumerate(calls) if c[2:3] == ["--final"])
    uninstall = _index(calls, ["uv", "pip", "uninstall"])
    clean = _index(calls, ["uv", "cache", "clean"])
    assert final < uninstall < clean
    assert calls[uninstall][-3:] == NAMES  # requirers first, as check-lock orders them
    # Only what was uninstalled: cleaning torch's cache would break a venv
    # that links its CPU torch there (uv --link-mode symlink).
    assert calls[clean][3:] == NAMES and "--force" not in calls[clean]
    assert "check none are yours" in out
    assert any(c[:3] == ["uv", "pip", "check"] for c in calls[clean:])


@pytest.mark.parametrize("answer", ["", "n", "no"])
def test_the_default_keeps_them(box, answer):
    calls, _ = _cleanup(box, answers=[answer])
    assert any("Remove them now? [y/N]" in p for p in _asked(calls))
    heads = (["uv", "pip", "uninstall"], ["uv", "cache", "clean"])
    assert not any(c[:3] in heads for c in calls)


@pytest.mark.parametrize("kw", [{"tty": False}, {"cpu": False, "gpu": True}])
def test_no_terminal_or_the_gpu_build_never_offers(box, kw):
    calls, _ = _cleanup(box, answers=["y"], **kw)
    assert not _asked(calls)
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


def test_a_removal_that_did_not_finish_prints_how_to_finish(box, capsys):
    _, exited = _cleanup(box, answers=["y"], after_check_rc=1)
    assert exited is None
    err = capsys.readouterr().err
    assert "Finish it: uv pip uninstall" in err and "nvidia-cudnn-cu12" in err


# --- Nothing in the new steps stops an update it shouldn't --------------------


def test_a_hanging_gpu_probe_means_no_gpu_and_the_update_goes_on(box, capsys):
    calls, exited = _update(box, torch="2.10.0", tty=True, answers=[""], smi_hangs=True)
    assert exited is None and "no NVIDIA GPU was found" in capsys.readouterr().out
    assert _lock_of(calls) == str(box.cpu_lock)


def test_no_answer_at_the_variant_question_installs_nothing(box, capsys):
    """End of input mustn't become a silent swap to the CPU default."""
    calls, exited = _update(box, torch="2.10.0", tty=True, answers=[EOFError])
    assert exited is not None and exited.code == 1
    assert "nothing installed" in capsys.readouterr().err
    assert not _steps(calls)


def _finished(box, calls, exited):
    """The update went on past the clean-up: manifest written, no restart asked."""
    assert exited is None
    assert "updated_at" in _manifest(box)


def test_no_answer_at_the_clean_up_keeps_them_and_the_update_goes_on(box, capsys):
    calls, exited = _cleanup(box, answers=[EOFError])
    _finished(box, calls, exited)
    assert (
        "Clean-up not finished; the commands above complete it"
        in capsys.readouterr().out
    )
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


@pytest.mark.parametrize("uninstall", ["failed", "timeout"])
def test_an_uninstall_that_fails_skips_the_cache_clean(box, capsys, uninstall):
    """The cache copies stay while the venv still links them."""
    calls, exited = _cleanup(box, answers=["y"], uninstall=uninstall)
    _finished(box, calls, exited)
    assert "Clean-up not finished" in capsys.readouterr().out
    assert not any(c[:3] == ["uv", "cache", "clean"] for c in calls)


# --- An update that stops after the pull says so and how to finish ------------

PART_WAY = "Update stopped part-way: the code was pulled and packages may have changed"


@pytest.mark.parametrize(
    "stop",
    ["lock missing", "--installed", "install", "--strict", "opencti", "--final"],
)
@pytest.mark.parametrize("flag", ["", "cpu", "gpu"])
def test_every_post_pull_stop_prints_the_part_way_block_and_the_finish_command(
    box, capsys, stop, flag
):
    if stop == "lock missing":
        (box.cpu_lock if flag == "cpu" else box.lock).unlink()
    _, exited = _update(
        box,
        cpu=flag == "cpu",
        gpu=flag == "gpu",
        opencti=True,
        install_rc=1 if stop == "install" else 0,
        opencti_rc=1 if stop == "opencti" else 0,
        check_rc={stop: 1} if stop.startswith("--") else None,
    )
    assert exited is not None and exited.code == 1
    err = capsys.readouterr().err
    assert PART_WAY in err and "the gateway wasn't restarted" in err
    finish = err.rstrip().splitlines()[-1]
    assert finish.endswith("finish with: vhir update" + (f" --{flag}" if flag else ""))


def test_anchor_a_clean_update_prints_no_part_way_block(box, capsys):
    _, exited = _update(box, opencti=True)
    assert exited is None and PART_WAY not in capsys.readouterr().err
