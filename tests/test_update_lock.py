"""`vhir update` installs from the dependency lock in the pulled sift-mcp.

Every package but OpenCTI's goes through one locked install (`-c`/`-b` with
`deps/vhir.lock`), opensearch-mcp included whenever it's installed, even
though the installer never put it in the manifest. The venv is checked
against the lock (`deps/check-lock.py --strict`), OpenCTI's client is then
installed unlocked, and the venv is checked again (`--final`). uv older than
0.6.0 ignores the lock's hashes, so update refuses it before pulling.
subprocess is a stand-in that records each command.
"""

from __future__ import annotations

import importlib.util
import json
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
    return SimpleNamespace(home=tmp_path, src=src, lock=src / "deps" / "vhir.lock")


def _update(
    box,
    *,
    uv="uv 0.12.20",
    check_rc=None,
    opensearch=False,
    opencti=False,
    manifest=None,
):
    """Run cmd_update; returns (commands, SystemExit or None)."""
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

    def run(cmd, **kw):
        calls.append([str(c) for c in cmd])
        result = MagicMock(returncode=0, stdout="0", stderr="")
        if cmd[:2] == ["uv", "--version"]:
            result.stdout = uv
        elif "symbolic-ref" in cmd:
            result.stdout = "main"
        elif len(cmd) > 2 and str(cmd[1]).endswith("check-lock.py"):
            result.returncode = check_rc.get(cmd[2], 0)
        return result

    exited = None
    with (
        patch("pathlib.Path.home", return_value=box.home),
        patch("subprocess.run", side_effect=run),
        patch("importlib.util.find_spec", side_effect=find_spec),
    ):
        try:
            cmd_update(MagicMock(check=False, no_restart=True), {})
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
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "install",
        "--strict",
        "install",
        "--final",
    ]
    locked, opencti = steps[0][1], steps[2][1]
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
    locked = _steps(calls)[0][1]
    assert str(box.home / "opensearch-mcp") in locked
    assert locked.index(str(box.home / "opensearch-mcp")) > locked.index("-c")


def test_opensearch_mcp_not_installed_is_left_alone(box):
    calls, _ = _update(box, opensearch=False)
    assert not any("opensearch-mcp" in a for a in _steps(calls)[0][1])


def test_without_opencti_both_checks_still_run(box):
    def drop(m):
        del m["packages"]["opencti-mcp"]
        return m

    calls, exited = _update(box, manifest=drop)
    assert exited is None
    steps = _steps(calls)
    assert [s[0] if s[0] == "install" else s[1] for s in steps] == [
        "install",
        "--strict",
        "--final",
    ]


@pytest.mark.parametrize("mode", ["--strict", "--final"])
def test_a_failed_check_stops_the_update(box, capsys, mode):
    calls, exited = _update(box, check_rc={mode: 1})
    assert exited is not None and exited.code == 1
    assert "dependency lock" in capsys.readouterr().err
    steps = _steps(calls)
    assert steps[-1] == ("check", mode)  # nothing after it
    assert not any(c[:2] == ["systemctl", "--user"] for c in calls)


@pytest.mark.parametrize(
    "uv,refused",
    [
        ("uv 0.5.31", True),
        ("uv 0.4.0 (abc 2024-08-01)", True),
        ("not uv", True),
        ("uv 0.6.0", False),
        ("uv 0.12.20 (x86_64-unknown-linux-gnu)", False),
    ],
)
def test_uv_older_than_0_6_is_refused_before_anything_is_pulled(
    box, capsys, uv, refused
):
    calls, exited = _update(box, uv=uv)
    pulled = any("pull" in c for c in calls)
    if refused:
        assert exited is not None and exited.code == 1
        assert "older than 0.6.0" in capsys.readouterr().err
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
        "install",
        "--strict",
        "install",
        "--final",
    ]
    assert "-c" not in steps[2][1] and steps[2][1][-1].endswith("packages/opencti")
