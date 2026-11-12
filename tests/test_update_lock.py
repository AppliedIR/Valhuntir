"""`vhir update` installs from the dependency lock in the pulled sift-mcp.

Every package goes through one locked install (`-c`/`-b` with
`deps/vhir.lock`), opensearch-mcp and opencti-mcp included whenever they're
installed, even if the manifest doesn't record them, and so are the installed
packages the lock names (`check-lock.py --installed`), so that it moves them.
The venv is then checked against the lock (`deps/check-lock.py --strict`) and
for conflicts (`--final`). uv older than 0.6.0 ignores the lock's hashes, so
update refuses it before pulling.
subprocess is a stand-in that records each command.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from tests import health_stand_in
from tests.test_update import STEPS_CLOSE, STEPS_OPEN, steps_block
from vhir_cli.commands.update import _PACKAGE_PATHS, cmd_update

REAL_FIND_SPEC = importlib.util.find_spec
# `systemctl --user show vhir-gateway` for a gateway run by its systemd unit
UNIT_SHOW = (
    "LoadState=loaded\nUnitFileState=enabled\nActiveState=active\n"
    "SubState=running\nMainPID=4242\n"
)


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
    opencti_leftovers="",
    install_rc=0,
    hangs=(),
    after_check_rc=0,
    uninstall="ok",
    smi_hangs=False,
    gpu_found=False,
    check=False,
    no_restart=True,
    after_pull=None,
    vhir_moves=False,
    pulls=(),
    restart_rc=0,
    restart_err=None,
    unit_show=UNIT_SHOW,
    gateway=None,
    unreadable=None,
):
    """Run cmd_update; returns (commands, SystemExit or None). By default the
    venv has GPU PyTorch (torch 2.14.0) and stdin isn't a terminal; `answers`
    are what input() returns, in order; `leftovers` is check-lock's
    --cuda-leftovers output. `after_pull` is the --after-pull handoff text;
    with `vhir_moves` the vhir pull moves its HEAD, so the run hands over to
    the new code: os.execv is recorded as ["execv", *argv] and ends the run.
    Each repo named in `pulls` moves its HEAD at the pull, without a hand-over.
    `restart_rc` is the gateway restart's exit status (`restart_err` its
    stderr, when set) and `unit_show` what
    `systemctl --user show` prints. `gateway` (tests.test_update_gateway_state)
    is what /health answers on every call, and the repos it pulls. A
    `restart_rc` exception is what the restart raises. `unreadable` is (repo,
    "before" or "after"): its HEAD can't be read before its pull, or after it."""
    check_rc = check_rc or {}
    calls = []
    if gateway is not None:
        health_stand_in.current().answer = gateway.health
        pulls = (*pulls, *gateway.pulls)
    moving = {f"/{name}" for name in pulls} | ({"/vhir"} if vhir_moves else set())
    heads = {"/vhir": "v1"}
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
        if cmd[0] == "nvidia-smi" and gpu_found:
            result.returncode, result.stdout = 0, "GPU 0: NVIDIA (UUID: GPU-x)\n"
        if cmd[:3] == ["uv", "pip", "uninstall"] and uninstall != "ok":
            if uninstall == "timeout":
                raise subprocess.TimeoutExpired(cmd, 600)
            if kw.get("check"):  # as subprocess.run does with check=True
                raise subprocess.CalledProcessError(2, cmd)
            result.returncode = 2
        if "-c" in cmd[1:3] and "torch" in cmd[-1]:  # the probe: python [-I] -c …
            result.returncode, result.stdout = (0, torch) if torch else (1, "")
        elif cmd[:3] == ["uv", "pip", "install"] and "-c" in cmd:
            result.returncode = install_rc
        elif cmd[:3] == ["uv", "pip", "install"]:  # nothing installs unlocked
            raise AssertionError(f"an install without the lock: {cmd}")
        elif cmd[:3] == ["uv", "pip", "check"]:
            result.returncode = after_check_rc
        elif cmd[:2] == ["uv", "--version"]:
            result.stdout = uv
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif (
            unreadable
            and cmd[:2] == ["git", "-C"]
            and cmd[2].endswith(f"/{unreadable[0]}")
            and cmd[3:] == ["rev-parse", "HEAD"]
        ):
            repo = cmd[2]
            pulled = any(c[2:4] == [repo, "pull"] for c in calls if c[:2] == cmd[:2])
            if pulled == (unreadable[1] == "after"):
                result.returncode, result.stdout = 128, ""
        elif cmd[:2] == ["git", "-C"] and any(cmd[2].endswith(m) for m in moving):
            repo = next(m for m in moving if cmd[2].endswith(m))
            if cmd[3:] == ["rev-parse", "HEAD"]:
                result.stdout = heads.setdefault(repo, "v1")
            elif cmd[3:5] == ["pull", "--ff-only"]:
                heads[repo] = "v2"
        elif cmd[:3] == ["systemctl", "--user", "restart"]:
            if isinstance(restart_rc, BaseException):
                raise restart_rc
            result.returncode = restart_rc
            result.stderr = (
                "" if restart_rc == 0 else "Job for vhir-gateway.service failed."
            )
            if restart_err is not None:
                result.stderr = restart_err
        elif cmd[:3] == ["systemctl", "--user", "show"]:
            result.stdout = unit_show
        elif len(cmd) > 2 and str(cmd[1]).endswith("check-lock.py"):
            if cmd[2] in hangs:
                raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
            result.returncode = check_rc.get(cmd[2], 0)
            result.stdout = {"--installed": "setuptools starlette"}.get(cmd[2], "")
            if cmd[2] == "--cuda-leftovers":
                result.stdout = leftovers
            if cmd[2] == "--opencti-leftovers":
                result.stdout = opencti_leftovers
        return result

    def ask(prompt=""):
        calls.append(["input", prompt])
        reply = replies.pop(0) if replies else ""
        if reply is EOFError:  # end of input at this prompt
            raise EOFError
        if callable(reply):  # a row's own answer, which may act before it replies
            reply = reply(prompt)
        return reply

    def execv(exe, argv):
        calls.append(["execv", *argv])
        raise Execd

    if vhir_moves:
        (box.home / "venv" / "bin" / "vhir").write_text("#!/bin/sh\n")
    exited = None
    stands = [
        patch("pathlib.Path.home", return_value=box.home),
        patch("subprocess.run", side_effect=run),
        patch("importlib.util.find_spec", side_effect=find_spec),
        patch("builtins.input", side_effect=ask),
        patch("sys.stdin.isatty", return_value=tty),
        patch("sys.platform", platform),
        patch(
            "shutil.which",
            return_value="/usr/bin/nvidia-smi" if (smi_hangs or gpu_found) else None,
        ),
        patch("os.execv", side_effect=execv),
    ]
    with contextlib.ExitStack() as stack:
        for stand in stands:
            stack.enter_context(stand)
        try:
            # A MagicMock's unset attributes are truthy: the flags are set.
            args = MagicMock(check=check, no_restart=no_restart, cpu=cpu, gpu=gpu)
            args.after_pull = after_pull
            cmd_update(args, {})
        except SystemExit as e:
            exited = e
        except Execd:
            pass
    return calls, exited


class Execd(Exception):
    """os.execv was called (a real one never returns)."""


def _steps(calls):
    out = []
    for c in calls:
        if c[:3] == ["uv", "pip", "install"]:
            out.append(("install", c))
        elif len(c) > 2 and c[1].endswith("check-lock.py"):
            out.append(("check", c[2]))
    return out


def test_one_locked_install_opencti_too_then_both_checks(box):
    calls, exited = _update(box)
    assert exited is None
    steps = _steps(calls)
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "--installed",
        "install",
        "--strict",
        "--final",
        "--opencti-leftovers",  # asked or not, the query runs
    ]
    locked = steps[1][1]
    # What the venv already has that the lock names goes into the locked
    # install, as plain requirements.
    assert locked[locked.index("-b") + 2 : locked.index("-b") + 4] == [
        "setuptools",
        "starlette",
    ]
    lock = str(box.lock)
    assert (
        locked[locked.index("-c") + 1] == lock
        and locked[locked.index("-b") + 1] == lock
    )
    assert str(box.src / "packages" / "opencti") in locked
    assert any(a.endswith("packages/forensic-rag") for a in locked)
    # The checks run the pulled sift-mcp's checker against its lock.
    for c in calls:
        if len(c) > 2 and c[1].endswith("check-lock.py"):
            assert c[1] == str(box.src / "deps" / "check-lock.py")
            assert c[c.index("--lock") + 1] == lock
    assert "opentelemetry-exporter-otlp-proto-grpc" not in locked


def test_a_dropped_pycti_requirement_is_never_reinstalled(box):
    with patch(
        "vhir_cli.commands.update._detect_constraint_changed_packages",
        return_value={"pycti", "httpx"},
    ):
        calls, exited = _update(box)
    assert exited is None
    locked = next(c for kind, c in _steps(calls) if kind == "install")
    assert "httpx" in locked and "pycti" not in locked
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


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
        "--opencti-leftovers",  # asked or not, the query runs
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


def test_opencti_installed_but_not_in_the_manifest_joins_the_locked_install(box):
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
        "--final",
        "--opencti-leftovers",  # asked or not, the query runs
    ]
    assert str(box.src / "packages" / "opencti") in steps[1][1]


def test_opencti_not_installed_is_left_alone(box):
    def drop(m):
        del m["packages"]["opencti-mcp"]
        return m

    calls, _ = _update(box, manifest=drop, opencti=False)
    locked = next(c for kind, c in _steps(calls) if kind == "install")
    assert not any("packages/opencti" in a for a in locked)


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
@pytest.mark.parametrize("tty", [False, True])
def test_with_or_without_a_terminal_the_installed_build_is_kept_and_recorded(
    box, capsys, installed, variant, tty
):
    calls, exited = _update(box, torch=installed, tty=tty)
    assert exited is None and not _asked(calls)
    assert _lock_of(calls) == str(box.cpu_lock if variant == "cpu" else box.lock)
    out = capsys.readouterr().out
    assert f"PyTorch build: {variant} (switch with: vhir update --cpu or --gpu)" in out
    assert _manifest(box)["torch_variant"] == variant


def test_a_recorded_install_is_not_asked(box):
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


def test_after_yes_no_dependency_check_says_the_removal_did_not_finish(box, capsys):
    """A failing `uv pip check` reports packages that were incompatible before
    the removal; it says nothing about the removal, so none runs after it."""
    calls, exited = _cleanup(box, answers=["y"], after_check_rc=1)
    assert exited is None
    uninstall = _index(calls, ["uv", "pip", "uninstall"])
    assert not any(c[:3] == ["uv", "pip", "check"] for c in calls[uninstall:])
    out, err = capsys.readouterr()
    assert "didn't finish" not in out + err and "Finish it" not in out + err


# --- Nothing in the new steps stops an update it shouldn't --------------------


def test_a_hanging_gpu_probe_means_no_gpu_and_the_update_goes_on(box, capsys):
    calls, exited = _update(box, torch="2.10.0", tty=True, smi_hangs=True)
    assert exited is None and "no NVIDIA GPU was found" in capsys.readouterr().err
    assert _lock_of(calls) == str(box.lock)  # the installed build is kept


def _finished(box, calls, exited):
    """The update went on past the clean-up: manifest written, no restart asked."""
    assert exited is None
    assert "updated_at" in _manifest(box)


def test_no_answer_at_the_clean_up_keeps_them_and_the_update_goes_on(box, capsys):
    """No answer is No, and the No is recorded, as at every offer."""
    calls, exited = _cleanup(box, answers=[EOFError])
    _finished(box, calls, exited)
    assert "Kept. The commands above remove them later." in capsys.readouterr().out
    assert "CUDA package removal" in _manifest(box).get("declined_offers", {})
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


@pytest.mark.parametrize("uninstall", ["failed", "timeout"])
def test_an_uninstall_that_fails_skips_the_cache_clean(box, capsys, uninstall):
    """The cache copies stay while the venv still links them."""
    calls, exited = _cleanup(box, answers=["y"], uninstall=uninstall)
    _finished(box, calls, exited)
    assert "Clean-up not finished" in capsys.readouterr().out
    assert not any(c[:3] == ["uv", "cache", "clean"] for c in calls)


# --- OpenCTI's leftovers: offered for removal, default No -------------------

OPENCTI = ["pycti", "fastapi", "stix2"]


def _opencti(box, **kw):
    kw.setdefault("tty", True)
    kw.setdefault("gpu", True)  # the build is chosen: no PyTorch question
    return _update(box, opencti_leftovers="\n".join(OPENCTI) + "\n", **kw)


def test_yes_removes_the_opencti_leftovers_and_the_check_is_clean(box, capsys):
    calls, exited = _opencti(box, answers=["y"])
    _finished(box, calls, exited)
    out = capsys.readouterr().out
    final = next(i for i, c in enumerate(calls) if c[2:3] == ["--final"])
    uninstall = _index(calls, ["uv", "pip", "uninstall"])
    assert final < uninstall and calls[uninstall][-3:] == OPENCTI
    assert not any(c[:3] == ["uv", "cache", "clean"] for c in calls)
    assert any(c[:3] == ["uv", "pip", "check"] for c in calls[uninstall:])
    assert "only Valhuntir's environment" in out and "opencti_query.py" in out
    assert "Removed; the dependency check is clean." in out


@pytest.mark.parametrize("answer", ["", "n", EOFError])
def test_no_or_no_answer_keeps_the_opencti_leftovers(box, capsys, answer):
    calls, exited = _opencti(box, answers=[answer])
    _finished(box, calls, exited)
    assert any("Remove them now? [y/N]" in p for p in _asked(calls))
    assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


def test_no_terminal_or_no_leftovers_never_offers(box):
    for kw in ({"tty": False}, {"opencti_leftovers": ""}):
        calls, _ = _update(box, **{"tty": True, "gpu": True, "answers": ["y"], **kw})
        assert not _asked(calls)
        assert not any(c[:3] == ["uv", "pip", "uninstall"] for c in calls)


def test_a_failed_opencti_removal_never_stops_the_update(box, capsys):
    calls, exited = _opencti(box, answers=["y"], uninstall="failed")
    _finished(box, calls, exited)
    assert "Clean-up not finished" in capsys.readouterr().out


# --- An update that stops after the pull says so and how to finish ------------

PART_WAY = "Update stopped part-way: the code was pulled and packages may have changed"


@pytest.mark.parametrize(
    "stop",
    ["lock missing", "--installed", "install", "--strict", "--final"],
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
        check_rc={stop: 1} if stop.startswith("--") else None,
    )
    assert exited is not None and exited.code == 1
    err = capsys.readouterr().err
    assert PART_WAY in err and "the gateway wasn't restarted" in err
    # the finish command is the end block's last step
    assert err.rstrip().splitlines()[-1] == STEPS_CLOSE and STEPS_OPEN in err
    block = steps_block(err)
    finish = block[-1] if block else ""
    assert finish.endswith("finish with: vhir update" + (f" --{flag}" if flag else ""))


def test_anchor_a_clean_update_prints_no_part_way_block(box, capsys):
    _, exited = _update(box, opencti=True)
    assert exited is None and PART_WAY not in capsys.readouterr().err


@pytest.mark.parametrize("hang", ["--strict", "--final"])
def test_a_timeout_after_the_pull_prints_the_part_way_block(box, capsys, hang):
    _, exited = _update(box, opencti=True, hangs=(hang,))
    assert exited is not None and exited.code == 1  # not a traceback
    err = capsys.readouterr().err
    assert "timed out" in err and PART_WAY in err
    # the finish command is the end block's last step
    assert err.rstrip().splitlines()[-1] == STEPS_CLOSE and STEPS_OPEN in err
    block = steps_block(err)
    assert block and block[-1].endswith("finish with: vhir update")


# --- The gateway's own launch lines get -I before the restart -----------------


def _launchers(box):
    script = box.home / ".vhir" / "start-gateway.sh"
    unit = box.home / ".config" / "systemd" / "user" / "vhir-gateway.service"
    unit.parent.mkdir(parents=True)
    script.write_text(
        '#!/usr/bin/env bash\nexec "/v/bin/python" -m sift_gateway --config "/c.yaml"\n'
    )
    script.chmod(0o755)
    unit.write_text(
        "[Service]\nExecStart=/v/bin/python -m sift_gateway --config /c.yaml\n"
    )
    return script, unit


def test_update_isolates_the_launch_lines_before_the_restart(box):
    script, unit = _launchers(box)
    calls, exited = _update(box, no_restart=False)
    assert exited is None
    assert '"/v/bin/python" -I -m sift_gateway' in script.read_text()
    assert "python -I -m sift_gateway" in unit.read_text()
    order = [c[1:3] for c in calls if c[:1] == ["systemctl"]]
    assert order.index(["--user", "daemon-reload"]) < order.index(["--user", "restart"])


def test_no_restart_still_rewrites_and_says_when_it_applies(box, capsys):
    script, unit = _launchers(box)
    calls, exited = _update(box, no_restart=True)
    assert exited is None and "python -I -m" in unit.read_text()
    assert ["systemctl", "--user", "restart", "vhir-gateway"] not in calls
    got = capsys.readouterr()
    # the --no-restart line moved from stdout into the end block
    block = steps_block(got.err)
    assert any("takes effect at the next gateway restart" in line for line in block)
    assert "takes effect at the next gateway restart" not in got.out


def test_check_writes_nothing(box):
    script, unit = _launchers(box)
    before = (script.read_bytes(), unit.read_bytes())
    _update(box, check=True)
    assert (script.read_bytes(), unit.read_bytes()) == before


def test_no_restart_says_when_it_applies_after_the_client_deploy_rewrote(
    box, capsys, monkeypatch
):
    """claude-code: Step 5's deploy rewrites the lines, so Step 6.5 finds
    nothing; the note still has to be printed."""
    from vhir_cli.commands import client_setup

    script, unit = _launchers(box)
    monkeypatch.setattr(client_setup, "_find_claude_code_assets", lambda: None)
    _update(box, no_restart=True, manifest=lambda m: {**m, "client": "claude-code"})
    got = capsys.readouterr()
    out, block = got.out, steps_block(got.err)
    assert "python -I -m" in unit.read_text() and f"Updated: {unit}" in out
    # the --no-restart line moved from stdout into the end block
    assert any("takes effect at the next gateway restart" in line for line in block)
    assert "takes effect at the next gateway restart" not in out


def test_no_note_when_nothing_was_rewritten(box, capsys):
    script, unit = _launchers(box)
    _update(box, no_restart=True)  # rewrites
    capsys.readouterr()
    _update(box, no_restart=True)  # nothing left to do
    got = capsys.readouterr()
    # neither on stdout nor in the end block
    assert "takes effect at the next gateway restart" not in got.out
    block = steps_block(got.err)
    assert not any("takes effect at the next gateway restart" in line for line in block)


def test_a_user_edited_launcher_is_noted_once_per_update(box, capsys, monkeypatch):
    """claude-code: Step 5's deploy and Step 6.5 both reach the launchers."""
    from vhir_cli.commands import client_setup

    script, unit = _launchers(box)
    script.write_text(script.read_text().replace('exec "', 'exec nice -n 5 "'))
    unit.write_text(unit.read_text().replace("--config", "--port 4600 --config"))
    monkeypatch.setattr(client_setup, "_find_claude_code_assets", lambda: None)
    _update(box, manifest=lambda m: {**m, "client": "claude-code"})
    out = capsys.readouterr().out
    for path in (script, unit):
        assert out.count(f"Note: {path} has a gateway launch line") == 1, path
    _update(box, manifest=lambda m: {**m, "client": "claude-code"})  # a later update
    out = capsys.readouterr().out
    assert out.count(f"Note: {unit} has a gateway launch line") == 1  # noted again


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0 file")
def test_an_unreadable_launcher_is_noted_once_per_update(box, capsys, monkeypatch):
    from vhir_cli.commands import client_setup

    script, unit = _launchers(box)
    monkeypatch.setattr(client_setup, "_find_claude_code_assets", lambda: None)
    unit.chmod(0)
    try:
        _update(box, manifest=lambda m: {**m, "client": "claude-code"})
    finally:
        unit.chmod(0o644)
    assert capsys.readouterr().out.count(f"Note: could not check {unit}") == 1
