"""Update Valhuntir installation on a SIFT workstation.

Pulls latest code, reinstalls packages, redeploys forensic controls,
and restarts the gateway. Runs on SIFT workstations only.

Remote clients that joined via 'vhir join' are not updated by this
command — they would need to re-run their client setup script.
"""

from __future__ import annotations

import datetime
import importlib.metadata
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

# Install order matches setup-sift.sh dependency chain.
# vhir-cli must come before case-mcp/report-mcp.
_INSTALL_ORDER = [
    "forensic-knowledge",
    "sift-common",
    "forensic-mcp",
    "sift-mcp",
    "sift-gateway",
    "vhir-cli",
    "case-mcp",
    "case-dashboard",
    "report-mcp",
    "windows-triage-mcp",
    "rag-mcp",
    "opencti-mcp",
    "opensearch-mcp",
]

# Paths relative to manifest["source"] (sift-mcp repo root).
# vhir-cli is special — relative to parent directory.
# opensearch-mcp is external — resolved at install time from sibling dir.
_PACKAGE_PATHS = {
    "forensic-knowledge": "packages/forensic-knowledge",
    "sift-common": "packages/sift-common",
    "forensic-mcp": "packages/forensic-mcp",
    "sift-mcp": "packages/sift-mcp",
    "case-mcp": "packages/case-mcp",
    "case-dashboard": "packages/case-dashboard",
    "report-mcp": "packages/report-mcp",
    "sift-gateway": "packages/sift-gateway",
    "windows-triage-mcp": "packages/windows-triage",
    "rag-mcp": "packages/forensic-rag",
    "opencti-mcp": "packages/opencti",
}


_BWRAP_PROFILE_PATH = Path("/etc/apparmor.d/bwrap")

_BWRAP_PROFILE_CONTENT = """\
# AppArmor profile for bubblewrap — grants user namespace access.
# Installed by Valhuntir for Claude Code kernel sandbox.
# Safe to remove: sudo rm /etc/apparmor.d/bwrap && sudo systemctl reload apparmor
abi <abi/4.0>,
include <tunables/global>

profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
"""


def _ensure_bwrap_profile() -> None:
    """Check if bwrap works; if not and AppArmor restricts userns, offer to fix."""
    import shutil

    if not shutil.which("bwrap"):
        return  # No bwrap installed, sandbox not applicable

    # Quick test: can bwrap create namespaces?
    try:
        result = subprocess.run(
            ["bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return  # Sandbox works
    except (subprocess.TimeoutExpired, OSError):
        pass  # Broken — continue to fix

    # Check if this is the Ubuntu 23.10+ AppArmor restriction
    try:
        sysctl = subprocess.run(
            ["sysctl", "-n", "kernel.apparmor_restrict_unprivileged_userns"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if sysctl.stdout.strip() != "1":
            return  # Different issue, can't auto-fix
    except (subprocess.TimeoutExpired, OSError):
        return

    if _BWRAP_PROFILE_PATH.is_file():
        # Profile exists but not loaded or stale — reload it
        print("  Sandbox: bwrap profile exists but sandbox failing. Reloading...")
    else:
        # Profile missing — create it
        print("  Sandbox: bwrap blocked by AppArmor (Ubuntu 23.10+).")
        print("  Installing AppArmor profile for bwrap (requires sudo)...")
        try:
            result = subprocess.run(
                ["sudo", "tee", str(_BWRAP_PROFILE_PATH)],
                input=_BWRAP_PROFILE_CONTENT,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                print(f"  WARNING: Could not write profile: {result.stderr.strip()}")
                return
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"  WARNING: Could not install bwrap profile: {e}")
            return

    # Load/reload the profile
    try:
        r = subprocess.run(
            ["sudo", "apparmor_parser", "-rT", str(_BWRAP_PROFILE_PATH)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0:
            # Verify it actually works now
            v = subprocess.run(
                ["bwrap", "--ro-bind", "/", "/", "--unshare-net", "--", "/bin/true"],
                capture_output=True,
                timeout=5,
            )
            if v.returncode == 0:
                print("  Sandbox: bwrap AppArmor profile loaded — sandbox working")
            else:
                print("  Sandbox: profile loaded but bwrap still fails.")
                print(f"  stderr: {v.stderr.decode(errors='replace').strip()}")
                print("  A reboot may be required.")
        else:
            print(f"  WARNING: apparmor_parser failed: {r.stderr.strip()}")
            print("  Try manually: sudo apparmor_parser -rT /etc/apparmor.d/bwrap")
    except subprocess.TimeoutExpired:
        print("  WARNING: apparmor_parser timed out")
    except OSError as e:
        print(f"  WARNING: Could not run apparmor_parser: {e}")


def _ensure_password_dir() -> None:
    """Ensure /var/lib/vhir/passwords/ exists, migrating from pins/ if needed,
    and the signing folders keys/ and ledger/ (the case lock lives there)."""
    passwords_dir = Path("/var/lib/vhir/passwords")
    pins_dir = Path("/var/lib/vhir/pins")
    _ensure_signing_dirs()

    if passwords_dir.is_dir():
        return

    # Migrate pins/ → passwords/ (requires sudo because parent is root-owned)
    if pins_dir.is_dir():
        print(
            "  Migrating passphrase storage (pins/ → passwords/)... ",
            end="",
            flush=True,
        )
        result = subprocess.run(
            ["sudo", "mv", str(pins_dir), str(passwords_dir)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print("done")
            return
        print(f"failed ({result.stderr.strip()})")

    # Create fresh directory.
    # Safety: passwords_dir is a hardcoded constant, not user input.
    import getpass

    user = getpass.getuser()
    print("  Creating passphrase storage directory... ", end="", flush=True)
    result = subprocess.run(
        [
            "sudo",
            "sh",
            "-c",
            f"mkdir -p {passwords_dir} && chown {user}:{user} {passwords_dir} && chmod 700 {passwords_dir}",
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode == 0:
        print("done")
    else:
        print("failed")
        print(
            f"  Run manually: sudo mkdir -p {passwords_dir} && "
            f"sudo chown $USER:$USER {passwords_dir} && "
            f"sudo chmod 700 {passwords_dir}",
            file=sys.stderr,
        )


def _ensure_signing_dirs() -> None:
    """/var/lib/vhir/keys/ and /var/lib/vhir/ledger/ (the case lock lives
    there), owned by this user, 0700. The name also marks this update as one
    that makes them (client_setup._under_an_older_update)."""
    from vhir_cli.commands.client_setup import ensure_signing_dirs

    ensure_signing_dirs()


def _offer_signing_key(identity: dict) -> None:
    """After an update: the examiner's signing credential, as the installer
    reports it. A 0.6 password is offered the upgrade; none is told how to
    set one up; a signing key's fingerprint is printed."""
    from vhir_cli import credentials, keys

    examiner = identity.get("examiner", "")
    config_path = Path.home() / ".vhir" / "config.yaml"
    try:
        current = credentials.state(examiner, config_path)
    except (credentials.CredentialError, keys.KeysFileInvalid) as e:
        print(
            f"  Signing key: can't be read ({e}); run `vhir config --forgot-password`."
        )
        return
    if current == "schema3":
        fp = keys.key_fingerprint(keys.active(keys.load(examiner)))
        print(f"  Signing key for {examiner}: {fp}")
        return
    if current == "none":
        print(
            f"  No signing passphrase for {examiner}: set one with `vhir config --setup-password`."
        )
        return
    print(f"  {examiner} has a 0.6 passphrase: approvals now need a signing key.")
    answer = ""
    if sys.stdin.isatty():
        try:
            answer = (
                input("  Upgrade it now (vhir config --upgrade-key)? [Y/n] ")
                .strip()
                .lower()
            )
        except EOFError:
            answer = "n"
    if not sys.stdin.isatty() or answer in ("n", "no"):
        print("  Run `vhir config --upgrade-key` when you're ready.")
        return
    try:
        credentials.upgrade(examiner, config_path)
    except credentials.CredentialError as e:
        print(f"  {e} Run `vhir config --upgrade-key` to try again.", file=sys.stderr)


def _resolve_opensearch_mcp_repo(source: Path) -> Path | None:
    """Locate the opensearch-mcp repo on disk.

    opensearch-mcp lives in its own git repo (AppliedIR/opensearch-mcp),
    separate from the sift-mcp monorepo. Operators install it in a
    variety of non-standard layouts (sibling of home dir, under
    ~/.vhir/src/, custom paths). Prior code hard-coded two candidate
    paths that both resolved to ~/.vhir/src/opensearch-mcp when
    source=~/.vhir/src/sift-mcp (dead duplicate), silently skipping
    `vhir update` for operators using any other layout.

    Resolution order:
    1. Python import machinery (`importlib.util.find_spec`) —
       self-discovers wherever `uv pip install -e` placed the repo,
       regardless of install-tool (pip or uv) or filesystem layout.
    2. Well-known candidate paths, expanded.
    """
    # Step 1: installed-package lookup (editable-install metadata).
    try:
        import importlib.util

        spec = importlib.util.find_spec("opensearch_mcp")
        if spec and spec.origin:
            # spec.origin = .../opensearch-mcp/src/opensearch_mcp/__init__.py
            # three levels up from __init__.py = repo root
            pkg_root = Path(spec.origin).resolve().parent.parent.parent
            if (pkg_root / ".git").is_dir():
                return pkg_root
    except Exception:  # noqa: BLE001 — any import-machinery failure falls through
        pass

    # Step 2: known candidates. source.parent is typically ~/.vhir/src,
    # so source.parent/"opensearch-mcp" covers the default layout.
    # Home-level and ~/code/ are common alternates.
    candidates = [
        source.parent / "opensearch-mcp",
        Path.home() / "opensearch-mcp",
        Path.home() / "code" / "opensearch-mcp",
        Path.home() / ".vhir" / "src" / "opensearch-mcp",
    ]
    # Dedupe while preserving order.
    seen: set[Path] = set()
    for c in candidates:
        try:
            resolved = c.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir() and (resolved / ".git").is_dir():
            return resolved
    return None


def _module_installed(module: str) -> bool:
    """True when the package is in this venv (vhir runs from it). The
    manifest can't say: the installer never recorded opensearch-mcp, and
    OpenCTI's client may have been added after it was written."""
    try:
        import importlib.util

        return importlib.util.find_spec(module) is not None
    except Exception:  # noqa: BLE001
        return False


# 0.6.9 is the first with --torch-backend, which the CPU PyTorch lock needs;
# hash checks of the lock need 0.6.0.
_UV_FLOOR = (0, 6, 9)

_TORCH_INDEX_HINT = (
    "  CPU PyTorch comes from download.pytorch.org; if you use a package mirror,"
    " re-run with --gpu."
)


def _uv_version() -> tuple[int, int, int] | None:
    """uv's version, or None when it can't be read."""
    import re

    try:
        out = subprocess.run(
            ["uv", "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.match(r"uv (\d+)\.(\d+)\.(\d+)", out.stdout or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def _check_uv_floor() -> None:
    # Older uv installs from the lock without checking its hashes, and says
    # nothing. (cmd_update ignores a failed `uv self update`.)
    uv_version = _uv_version()
    if uv_version is None or uv_version < _UV_FLOOR:
        shown = ".".join(map(str, uv_version)) if uv_version else "unknown"
        print(
            f"uv {shown} is older than 0.6.9, which vhir update needs for"
            " --torch-backend and hash checks.\n"
            "Update it: uv self update   (or reinstall: "
            "curl -LsSf https://astral.sh/uv/install.sh | sh)",
            file=sys.stderr,
        )
        sys.exit(1)


def _stop_part_way(args) -> NoReturn:
    """Exit after the pull: say what state that leaves and how to finish."""
    flag = " --cpu" if args.cpu else " --gpu" if args.gpu else ""
    print(
        "\n  Update stopped part-way: the code was pulled and packages may have"
        " changed, but the forensic controls weren't redeployed and the gateway"
        " wasn't restarted.\n  Fix the problem above, then finish with:"
        f" vhir update{flag}",
        file=sys.stderr,
    )
    sys.exit(1)


def _check_lock(args, venv_python: str, checker: Path, lock: Path, mode: str) -> None:
    """Run the venv against the lock (deps/check-lock.py, from the pulled
    sift-mcp); it prints what it finds. Stops the update when the check fails."""
    try:
        result = subprocess.run(
            [venv_python, str(checker), mode, "--lock", str(lock)], timeout=120
        )
    except subprocess.TimeoutExpired:
        print("  The dependency check timed out after 120 seconds.", file=sys.stderr)
        _stop_part_way(args)
    if result.returncode != 0:
        print(
            "  The installed packages don't match the dependency lock (above).",
            file=sys.stderr,
        )
        _stop_part_way(args)


def _torch_installed(venv_python: str) -> str:
    """The venv's torch version ("2.14.0+cpu" for the CPU build), or ""."""
    try:
        out = subprocess.run(
            [
                venv_python,
                "-I",
                "-c",
                'import importlib.metadata as m; print(m.version("torch"))',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def _torch_variant(
    args, manifest: dict, installed: str, ask: bool = True
) -> tuple[str, str]:
    """(the build to install, the record to keep). The flag, else the build
    already in the venv, else CPU. Asked only on a terminal, with no flag,
    when the venv has torch but was never asked (no record), or forensic-rag
    is to be installed without it. macOS has one build (PyPI's) and no record."""
    flag = "cpu" if args.cpu else "gpu" if args.gpu else ""
    record = manifest.get("torch_variant", "")
    if sys.platform == "darwin":
        if flag:
            print(
                f"  --{flag} is not applicable on macOS (PyPI's PyTorch has no CUDA)."
            )
        return "pypi", record
    if flag:
        return flag, flag
    variant = "cpu" if installed.endswith("+cpu") or not installed else "gpu"
    rag = "rag-mcp" in manifest.get("packages", {})
    asked = (installed and not record) or (rag and not installed)
    if ask and sys.stdin.isatty() and asked:
        import shutil

        found = "no NVIDIA GPU was found"
        default = "cpu"  # no GPU: Enter keeps CPU even if a GPU build is installed
        if shutil.which("nvidia-smi"):
            try:
                smi = subprocess.run(
                    ["nvidia-smi", "-L"], capture_output=True, text=True, timeout=30
                )
                if smi.returncode == 0 and smi.stdout.startswith("GPU"):
                    found = "an NVIDIA GPU was found"
                    default = variant  # a GPU is here: Enter keeps the build installed
            except (OSError, subprocess.SubprocessError):
                pass  # a probe that fails or hangs: no GPU detected
        print(f"\n  PyTorch for knowledge search ({found}):")
        if installed:
            print(
                f"    Installed now: the {variant.upper()} build (torch {installed})."
            )
            print(
                "    Choosing the other build replaces it; CUDA packages it leaves"
                " are listed after the install."
            )
        print("    cpu  about 0.2 GB download, 0.7 GB on disk; slower index builds")
        print(
            "    gpu  about 3 GB download, 5.4 GB on disk; much faster index"
            " builds; needs an NVIDIA GPU"
        )
        while True:
            try:
                answer = input(f"    PyTorch build (cpu/gpu) [{default}]: ")
            except EOFError:  # no answer mustn't become a silent swap to CPU
                print(
                    "\nNo answer to the PyTorch question; nothing installed."
                    " Re-run with: vhir update --cpu or --gpu",
                    file=sys.stderr,
                )
                _stop_part_way(args)
            answer = answer.strip().lower() or default
            if answer in ("cpu", "gpu"):
                return answer, answer
            print("    Please enter cpu or gpu.")
    print(f"  PyTorch build: {variant} (switch with: vhir update --cpu or --gpu)")
    return variant, record


def _offer_cuda_cleanup(venv_python: str, checker: Path, lock: Path) -> None:
    """After the CPU build is in and --final passed: offer to remove the CUDA
    packages it doesn't use. Asks first, loudly; the default is No. Nothing
    here stops the update: no answer, a timeout or a failed step leaves the
    commands it printed to finish by hand."""
    try:
        _cleanup(venv_python, checker, lock)
    except (EOFError, OSError, subprocess.SubprocessError):
        print("\n  Clean-up not finished; the commands above complete it.")


def _cleanup(venv_python: str, checker: Path, lock: Path) -> None:
    out = subprocess.run(
        [venv_python, str(checker), "--cuda-leftovers", "--lock", str(lock)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    rows = [line.split() for line in out.stdout.splitlines() if line.strip()]
    if out.returncode != 0 or not rows:
        return
    names = [r[0] for r in rows]
    total = sum(int(r[1]) for r in rows)
    print("\n  " + "=" * 66)
    print(
        "  CUDA-family packages the chosen lock doesn't install (check none are yours):"
    )
    for name, size in rows:
        print(f"    {name:<34} {int(size) / 1e9:6.2f} GB")
    print(f"    {'total in the venv':<34} {total / 1e9:6.2f} GB")
    print("  Removing them runs:")
    print(f"    uv pip uninstall --python {venv_python} {' '.join(names)}")
    print(f"    uv cache clean {' '.join(names)}")
    print(
        "  This changes only Valhuntir's environment and uv's download cache,\n"
        "  and any other uv environment installed with --link-mode symlink that\n"
        "  uses these packages: such an environment would need a reinstall.\n"
        "  The disk comes back only with the cache clean (the venv's files are\n"
        "  links into it). A later GPU install downloads them again (~3 GB)."
    )
    print("  " + "=" * 66)
    if input("  Remove them now? [y/N] ").strip().lower() not in ("y", "yes"):
        print("  Kept. The commands above remove them later.")
        return
    py = ["--python", venv_python]
    # check=True: a failed uninstall must not reach the cache clean, which
    # would break a venv that links those files from the cache.
    subprocess.run(["uv", "pip", "uninstall", *py, *names], timeout=600, check=True)
    subprocess.run(["uv", "cache", "clean", *names], timeout=600)


def _offer_opencti_cleanup(venv_python: str, checker: Path, lock: Path) -> None:
    """After --final passed: offer to remove pycti, OpenCTI's old client, and
    what only it brought in (check-lock's list). Asks first; the default is No.
    Nothing here stops the update."""
    try:
        out = subprocess.run(
            [venv_python, str(checker), "--opencti-leftovers", "--lock", str(lock)],
            capture_output=True, text=True, timeout=120,
        )  # fmt: skip
        names = out.stdout.split() if out.returncode == 0 else []
        if not names:
            return
        remove = f"uv pip uninstall --python {venv_python} {' '.join(names)}"
        print("\n  " + "=" * 66)
        print("  Left by an earlier OpenCTI install; Valhuntir no longer uses them:")
        print(f"    {' '.join(names)}\n  Removing them runs:\n    {remove}")
        print(
            "  This changes only Valhuntir's environment. The optional standalone\n"
            "  opencti_query.py script (sift-mcp packages/opencti) needs pycti; to\n"
            f"  use it again: uv pip install --python {venv_python} pycti"
        )
        print("  " + "=" * 66)
        if input("  Remove them now? [y/N] ").strip().lower() not in ("y", "yes"):
            print("  Kept. The command above removes them later.")
            return
        py = ["--python", venv_python]
        subprocess.run(["uv", "pip", "uninstall", *py, *names], timeout=600, check=True)
        check = subprocess.run(
            ["uv", "pip", "check", *py], capture_output=True, text=True, timeout=120
        )
        if check.returncode == 0:
            print("  Removed; the dependency check is clean.")
        else:
            print(
                f"  Removed; the check reports: {(check.stdout + check.stderr).strip()}"
            )
    except (EOFError, OSError, subprocess.SubprocessError):
        print("\n  Clean-up not finished; the command above completes it.")


def _opensearch_mcp_installed_but_missing(source: Path) -> bool:
    """True when the opensearch-mcp package is installed in the venv
    but no git repo was found on disk — a silent-staleness condition
    that `vhir update` cannot recover from and should warn about."""
    try:
        import importlib.util

        if importlib.util.find_spec("opensearch_mcp") is None:
            return False  # not installed at all → legitimate skip
    except Exception:  # noqa: BLE001
        return False
    return _resolve_opensearch_mcp_repo(source) is None


def _check_opensearch_version(source: Path) -> None:
    """Warn if running OpenSearch container doesn't match pinned version."""
    import re

    repo = _resolve_opensearch_mcp_repo(source)
    if repo is None:
        return  # No opensearch-mcp repo found — opensearch not installed

    os_path = repo / "docker" / "docker-compose.yml"
    setup_script = os_path.parent.parent / "scripts" / "setup-opensearch.sh"
    if not os_path.is_file():
        return _cant_check_snapshots(f"{os_path} is missing")
    text = os_path.read_text()
    m = re.search(r"opensearchproject/opensearch:(\S+)", text)
    if not m:
        return _cant_check_snapshots(f"{os_path} names no opensearch image")
    pinned = m.group(1)

    # Check running container version
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", "vhir-opensearch"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return _cant_check_snapshots(f"docker: {e}")
    if result.returncode != 0:
        return _cant_check_snapshots(
            "docker inspect vhir-opensearch: "
            + (result.stderr.strip().splitlines() or ["failed"])[0]
        )
    running_image = result.stdout.strip()
    running_m = re.search(r"opensearchproject/opensearch:(\S+)", running_image)
    if not running_m:
        return _cant_check_snapshots(f"the container runs {running_image!r}")
    running = running_m.group(1)
    if running == pinned:
        _tell_snapshot_setup(setup_script)

    if running != pinned:
        print(
            f"\n  OpenSearch version mismatch: running {running}, code requires {pinned}."
        )
        print("  Upgrading recreates the container. Its indexed data is kept: it")
        print("  lives in a Docker volume the new container uses. Case records")
        print("  (findings, timeline, evidence) are NOT affected.")
        try:
            answer = input("\n  Upgrade OpenSearch now? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer in ("y", "yes"):
            print(f"  Running {setup_script}...")
            try:
                result = subprocess.run(["bash", str(setup_script)], timeout=300)
            except subprocess.TimeoutExpired:  # the rest of update still runs
                print(
                    "  OpenSearch upgrade: setup-opensearch.sh didn't finish in 5 minutes"
                    " and was stopped;\n  the container may still be starting (docker ps)."
                    f" Run it again:\n    bash {shlex.quote(str(setup_script))}",
                    file=sys.stderr,
                )
                print()
                return
            # setup-opensearch.sh exits 3: OpenSearch runs, but snapshots aren't set up
            if result.returncode == 3:
                print(
                    "  OpenSearch was upgraded, but its snapshots aren't set up; see above.",
                    file=sys.stderr,
                )
            elif result.returncode != 0:
                print("  OpenSearch upgrade failed.", file=sys.stderr)
        else:
            print(f"  Skipped. To upgrade later: bash {shlex.quote(str(setup_script))}")
        print()


_SNAPSHOT_REPO = "/usr/share/opensearch/snapshots"
_SNAPSHOT_MOUNT_FORMAT = (
    '{{range .Mounts}}{{if eq .Destination "/usr/share/opensearch/snapshots"}}'
    "{{.Type}} {{.Source}} {{.RW}}{{end}}{{end}}"
)


def _cant_check_snapshots(reason: str) -> None:
    print(f"\n  Couldn't check whether OpenSearch is set up for snapshots ({reason}).")


def _tell_snapshot_setup(setup_script: Path) -> bool | None:
    """Say so when the running container can't take vhir backup's snapshots: the
    same two things setup-opensearch.sh checks (the bind, the node's path.repo).
    True when it can, False when it can't, None when that couldn't be checked."""
    try:
        r = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                _SNAPSHOT_MOUNT_FORMAT,
                "vhir-opensearch",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            raise OSError(
                (r.stderr.strip().splitlines() or ["docker inspect failed"])[0]
            )
        from opensearch_mcp.client import get_client

        reply = get_client().nodes.info(
            metric="settings", filter_path="nodes.*.settings.path.repo"
        )
    except Exception as e:  # noqa: BLE001 — any failure is "couldn't check", said once
        return _cant_check_snapshots(f"{type(e).__name__}: {e}")
    problems = []
    if r.stdout.strip() != "bind /var/lib/vhir/snapshots true":
        problems.append(
            "the container has no read-write bind of /var/lib/vhir/snapshots at "
            f"{_SNAPSHOT_REPO} (docker inspect: {r.stdout.strip()!r})"
        )
    try:
        nodes = reply["nodes"]
        repos = [n["settings"]["path"]["repo"] for n in nodes.values()]
        ok = bool(nodes) and all(
            _SNAPSHOT_REPO in ([x] if isinstance(x, str) else x) for x in repos
        )
    except (KeyError, TypeError, AttributeError):
        ok = False
    if not ok:
        problems.append(
            f"couldn't confirm that OpenSearch's path.repo includes {_SNAPSHOT_REPO} "
            f"(_nodes/settings: '{json.dumps(reply, separators=(',', ':'))[:160]}')"
        )
    if not problems:
        return True
    print(
        "\n  OpenSearch isn't set up for snapshots, so `vhir backup --include-opensearch`"
    )
    print("  can't save its indices:")
    for line in problems:
        print(f"    - {line}")
    print(
        "  To set it up (it recreates the vhir-opensearch container; its indexed data"
    )
    print(f"  is kept), run:\n    bash {shlex.quote(str(setup_script))}\n")
    return False


def _redeploy_clients(manifest: dict) -> list[str]:
    """Step 5: redeploy each client's local controls; returns the clients."""
    from vhir_cli.commands.codex_controls import manifest_clients

    clients = manifest_clients(manifest)
    if "claude-desktop" in clients:
        from vhir_cli.commands.client_setup import DESKTOP_DROPPED

        print(f"  {DESKTOP_DROPPED}")
    from vhir_cli.controls import MCP, print_block

    if "claude-code" in clients:
        from vhir_cli.commands.client_setup import _deploy_claude_code_assets

        print("  Redeploying forensic controls...")
        settings = _deploy_claude_code_assets()
        path = settings[0] if isinstance(settings, tuple) else None
        if isinstance(settings, tuple) and settings[1] == "kept":
            print(f"  Forensic controls NOT applied to {path}; see above.")
        print_block("claude-code", path)  # what the file holds now
    if "codex" in clients:
        from vhir_cli.commands.client_setup import deploy_codex_assets
        from vhir_cli.commands.codex_controls import (
            codex_controls_state,
            deploy_codex_controls,
            state_lines,
        )

        print("  Redeploying Codex's profile, skills and managed requirements...")
        deploy_codex_assets()
        if codex_controls_state(clients) == "off":  # the opt-out: said, not undone
            for line in state_lines(clients):
                print(line)
        else:
            deploy_codex_controls()
        print_block("codex")
    for other in [
        c for c in clients if c not in ("claude-code", "codex", "claude-desktop")
    ]:
        print(f"  Client: {other} (no local controls to redeploy)")
        print_block(MCP)
    if not clients:
        print("  No client type in manifest. Run 'vhir setup client' to configure.")
    return clients


def cmd_update(args, identity: dict) -> None:
    """Pull latest code and redeploy Valhuntir installation."""
    check_only = getattr(args, "check", False)
    after_pull = getattr(args, "after_pull", None)
    if not isinstance(after_pull, str):
        after_pull = None

    # Step 1: Preflight
    manifest_path = Path.home() / ".vhir" / "manifest.json"
    if not manifest_path.is_file():
        print(
            "No manifest found at ~/.vhir/manifest.json.\n"
            "This command requires a SIFT installation (setup-sift.sh).",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Cannot read manifest: {e}", file=sys.stderr)
        sys.exit(1)

    source = Path(manifest.get("source", ""))
    vhir_dir = source.parent / "vhir"
    venv = manifest.get("venv", "")

    if not source.is_dir():
        print(f"Source directory not found: {source}", file=sys.stderr)
        sys.exit(1)

    venv_python = str(Path(venv) / "bin" / "python")
    if not Path(venv_python).exists():
        print(
            "Virtual environment corrupted — python not found.\n"
            "Re-run setup-sift.sh to rebuild.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Verify uv is available (installed by setup-sift.sh)
    try:
        uv_ok = subprocess.run(["uv", "--version"], capture_output=True).returncode == 0
    except FileNotFoundError:
        uv_ok = False
    if not uv_ok:
        print(
            "uv not found. Run setup-sift.sh to install it.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Keep uv current (handles stale installs and pre-existing user installs)
    if after_pull is None:
        subprocess.run(
            ["uv", "self", "update", "--quiet"], capture_output=True, timeout=60
        )

    repos = [("sift-mcp", source), ("vhir", vhir_dir)]

    # Add opensearch-mcp if installed (external repo, not in sift-mcp monorepo)
    os_repo = _resolve_opensearch_mcp_repo(source)
    if os_repo is not None:
        repos.append(("opensearch-mcp", os_repo))
    elif after_pull is None and _opensearch_mcp_installed_but_missing(source):
        # Package is installed in the venv but no git repo found anywhere.
        # Silent skip was the v0.6.1 bug — make it visibly actionable.
        print(
            "\n  WARNING: opensearch-mcp package is installed but its git repo\n"
            "  was not found in any known location. `vhir update` cannot\n"
            "  pull or reinstall it automatically. Update manually:\n"
            "    cd <path-to-opensearch-mcp> && git pull && uv pip install -e .\n",
            file=sys.stderr,
        )

    if after_pull is not None:  # Steps 1-4 ran in the process that started this one
        pre_update_git, torch_record, older = _read_handoff(after_pull, repos, manifest)
        # An older vhir's update pulled this code: Step 4 again, from the lock
        if older:
            _write_update_state("", pre_update_git.get("vhir", ""))
            _check_uv_floor()  # 0.6.0 and 0.6.1 have none
            record = _install_packages(
                args,
                manifest,
                source,
                vhir_dir,
                venv_python,
                repos,
                pre_update_git,
                ask=False,
            )
            # The older update's answer (it asked in its Step 4), else ours
            torch_record = torch_record or record
        _finish_update(
            args,
            identity,
            manifest,
            manifest_path,
            venv,
            source,
            repos,
            pre_update_git,
            torch_record,
        )
        return

    # Step 2: Fetch + compare
    for name, path in repos:
        if not path.is_dir():
            print(f"  {name}: not found at {path}", file=sys.stderr)
            continue
        result = subprocess.run(
            ["git", "-C", str(path), "fetch", "origin"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            print(
                f"git fetch failed for {name}: {result.stderr.strip()}",
                file=sys.stderr,
            )
            sys.exit(1)

    for name, path in repos:
        if not path.is_dir():
            continue
        result = subprocess.run(
            ["git", "-C", str(path), "rev-list", "HEAD..origin/main", "--count"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        count = int(result.stdout.strip()) if result.returncode == 0 else 0
        current = _git_head(path)
        if count == 0:
            print(f"  {name}: up to date ({current[:7]})")
        else:
            remote = _git_remote_head(path)
            print(
                f"  {name}: {count} commit{'s' if count != 1 else ''} behind ({current[:7]} → {remote[:7]})"
            )

    if check_only:
        print("\n  Run 'vhir update' to apply.")
        return

    _check_uv_floor()

    # Step 3: Record pre-update state + pull
    pre_update_git = {}
    for name, path in repos:
        if path.is_dir():
            pre_update_git[name] = _git_head(path)

    # Every repo's branch before any pull, so a wrong one changes nothing.
    for name, path in repos:
        branch = _git_branch(path) if path.is_dir() else ""
        if branch and branch != "main":
            print(
                f"{name} is on branch '{branch}', expected 'main'.\n"
                f"Switch to main: git -C {path} checkout main",
                file=sys.stderr,
            )
            sys.exit(1)

    # The fetch (Step 2) has succeeded and the pull is next: record the update
    # as started (version ""), so any stop before Step 9 keeps every command
    # warning until a later run finishes. A stop at Step 2 (e.g. offline) never
    # reaches here, so the record stays the last complete update's.
    _write_update_state("", pre_update_git.get("vhir", ""))
    pulled = False  # a repo's HEAD moved in this run
    for name, path in repos:
        if not path.is_dir():
            continue
        try:
            result = subprocess.run(
                ["git", "-C", str(path), "pull", "--ff-only"],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            print(f"Pulling {name} timed out after 60 seconds.", file=sys.stderr)
            # this repo too: a pull can merge, then fail or hang in a hook
            if pulled or _git_head(path) not in (
                "unknown",
                pre_update_git.get(name, ""),
            ):
                _stop_part_way(args)
            sys.exit(1)
        if result.returncode != 0:
            quoted_path = shlex.quote(str(path))
            print(
                f"Failed to pull {name}: {result.stderr.strip()}\n"
                "  If the message above says your local changes would be overwritten\n"
                f"  (git -C {quoted_path} status --short lists them):\n"
                f"    git -C {quoted_path} stash push -u\n"
                "    vhir update\n"
                f"    git -C {quoted_path} stash pop",
                file=sys.stderr,
            )
            if pulled or _git_head(path) not in (
                "unknown",
                pre_update_git.get(name, ""),
            ):
                _stop_part_way(args)
            sys.exit(1)
        # Count new commits
        old = pre_update_git.get(name, "")
        new = _git_head(path)
        if old and old != new:
            pulled = True
            count_result = subprocess.run(
                ["git", "-C", str(path), "rev-list", f"{old}..{new}", "--count"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            n = count_result.stdout.strip() if count_result.returncode == 0 else "?"
            print(f"  Pulling {name}... {n} new commit{'s' if n != '1' else ''}")
        else:
            print(f"  Pulling {name}... already up to date")

    # Step 4: Reinstall packages (batched for unified dependency resolution).
    torch_record = _install_packages(
        args, manifest, source, vhir_dir, venv_python, repos, pre_update_git
    )

    # This process loaded vhir-cli before the pull: when the pull changed it,
    # Steps 4.5-9 run in a new process, from the new code.
    if "vhir" in pre_update_git and pre_update_git["vhir"] != _git_head(vhir_dir):
        _reexec_after_pull(args, venv, venv_python, pre_update_git, torch_record)
    _finish_update(
        args,
        identity,
        manifest,
        manifest_path,
        venv,
        source,
        repos,
        pre_update_git,
        torch_record,
    )


def _install_packages(
    args,
    manifest: dict,
    source: Path,
    vhir_dir: Path,
    venv_python: str,
    repos: list[tuple[str, Path]],
    pre_update_git: dict,
    ask: bool = True,
) -> str:
    """Step 4: every package, each third-party one from the lock in the freshly
    pulled sift-mcp. Returns the torch record to keep. ask=False asks nothing
    (an older vhir's update already asked its questions)."""
    torch_installed = _torch_installed(venv_python)
    variant, torch_record = _torch_variant(args, manifest, torch_installed, ask)
    lock = source / "deps" / ("vhir-cpu.lock" if variant == "cpu" else "vhir.lock")
    checker = source / "deps" / "check-lock.py"
    if not lock.is_file() or not checker.is_file():
        print(
            f"Dependency lock not found in {source / 'deps'}.\n"
            "The sift-mcp checkout is older than this vhir-cli; pull it to main.",
            file=sys.stderr,
        )
        _stop_part_way(args)
    installed = manifest.get("packages", {})
    pkg_paths = []
    for pkg_name in _INSTALL_ORDER:
        # Installed but not in the manifest still counts (an earlier install).
        unrecorded = {"opensearch-mcp": "opensearch_mcp", "opencti-mcp": "opencti_mcp"}
        if pkg_name not in installed and not (
            pkg_name in unrecorded and _module_installed(unrecorded[pkg_name])
        ):
            continue
        if pkg_name == "vhir-cli":
            pkg_path = str(vhir_dir)
        elif pkg_name == "opensearch-mcp":
            # External repo — self-discover wherever the operator cloned
            # it (editable-install metadata, then well-known candidates).
            os_repo = _resolve_opensearch_mcp_repo(source)
            if os_repo is None:
                continue  # warning already emitted earlier in cmd_update
            pkg_path = str(os_repo)
        else:
            rel = _PACKAGE_PATHS.get(pkg_name)
            if not rel:
                continue
            pkg_path = str(source / rel)
        if not Path(pkg_path).is_dir():
            print(
                f"  Warning: {pkg_name} source not found at {pkg_path}", file=sys.stderr
            )
            continue
        pkg_paths.append(pkg_path)

    cmd = ["uv", "pip", "install", "--python", venv_python, "--quiet"]
    cmd += ["-c", str(lock), "-b", str(lock)]
    # The CPU lock's torch is on the PyTorch index, which only --torch-backend
    # reaches; 2.14.0+cpu satisfies the GPU lock's ==2.14.0, so a switch to GPU
    # has to reinstall it.
    if variant == "cpu":
        cmd += ["--torch-backend", "cpu"]
    elif variant == "gpu" and torch_installed.endswith("+cpu"):
        cmd += ["--reinstall-package", "torch"]
    # Auto-detect dependencies whose version constraints changed in
    # the pulled commits and mark them for --reinstall-package so the
    # resolver honors tightened pins (e.g. `uv pip` otherwise leaves
    # a package already installed at a version the new constraint
    # forbids). UAT 2026-04-23 B81.
    reinstall = _detect_constraint_changed_packages(repos, pre_update_git)
    # OpenCTI's old client is no longer a dependency: a leftover is left
    # alone, and the dependency check says how to remove it.
    reinstall.discard("pycti")
    for pkg in sorted(reinstall):
        cmd.extend(["--reinstall-package", pkg])
    # Packages already in the venv that the lock names (pip's seeds, what an
    # earlier OpenCTI install pulled in) join the install, so -c moves them too.
    try:
        held = subprocess.run(
            [venv_python, str(checker), "--installed", "--lock", str(lock)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(
            "  Reading the venv's packages timed out after 120 seconds.",
            file=sys.stderr,
        )
        _stop_part_way(args)
    if held.returncode != 0:
        print(
            f"  Cannot read the venv's packages against the dependency lock: "
            f"{held.stderr.strip()}",
            file=sys.stderr,
        )
        _stop_part_way(args)
    cmd.extend(held.stdout.split())
    for p in pkg_paths:
        cmd.extend(["-e", p])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"  Package install failed: {result.stderr.strip()}",
            file=sys.stderr,
        )
        if variant == "cpu":
            print(_TORCH_INDEX_HINT, file=sys.stderr)
        _stop_part_way(args)
    print(f"  Reinstalling packages... {len(pkg_paths)} packages")
    _check_lock(args, venv_python, checker, lock, "--strict")

    _check_lock(args, venv_python, checker, lock, "--final")
    if variant == "cpu" and ask and sys.stdin.isatty():
        _offer_cuda_cleanup(venv_python, checker, lock)
    if ask and sys.stdin.isatty():  # with no terminal, --final's note names them
        _offer_opencti_cleanup(venv_python, checker, lock)
    return torch_record


def _reexec_after_pull(
    args, venv: str, venv_python: str, pre_update_git: dict, torch_record: str
) -> NoReturn:
    """Replace this process with `vhir update --after-pull` from the new code."""
    script = Path(venv) / "bin" / "vhir"
    handoff = json.dumps(
        {"pre_update_git": pre_update_git, "torch_record": torch_record}
    )
    argv = [venv_python, str(script), "update", "--after-pull", handoff]
    if getattr(args, "no_restart", False):
        argv.append("--no-restart")
    if not script.is_file():
        _update_incomplete(f"{script} was not found")
    print("  Continuing the update with the new code...", flush=True)
    sys.stderr.flush()
    try:
        os.execv(venv_python, argv)
    except OSError as e:
        _update_incomplete(f"Cannot start the new code: {e}")
    sys.exit(1)  # execv returns only by raising


def _update_incomplete(reason: str) -> NoReturn:
    bar = "=" * 72
    print(
        f"\n{bar}\n"
        "  UPDATE INCOMPLETE: run `vhir update` again\n"
        f"  {reason}.\n"
        "  The new code is installed, but the forensic controls, the manifest and\n"
        "  the gateway restart were not done with it.\n"
        f"{bar}",
        file=sys.stderr,
    )
    sys.exit(1)


def _read_handoff(
    text: str, repos: list[tuple[str, Path]], manifest: dict
) -> tuple[dict, str, bool]:
    """The pre-pull heads and torch choice the first process passed on, and
    whether it was an older vhir's update (update_handover), which passes no
    heads: then they come from the manifest."""
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict) and data.get("older_update") is True:
        record = data.get("torch_record")
        record = record if record in ("cpu", "gpu") else ""
        return _heads_before_older_update(manifest, repos), record, True
    if isinstance(data, dict) and isinstance(data.get("pre_update_git"), dict):
        record = data.get("torch_record")
        return data["pre_update_git"], record if isinstance(record, str) else "", False
    return _current_heads(repos), "", False


def _current_heads(repos: list[tuple[str, Path]]) -> dict:
    return {name: _git_head(path) for name, path in repos if path.is_dir()}


def _heads_before_older_update(manifest: dict, repos: list[tuple[str, Path]]) -> dict:
    """The heads before an older vhir's update pulled this code. Its Step 6
    writes the manifest's git (the heads after the pull) and pre_update_git.
    Until then, or when that write failed, git still holds the heads from
    before the pull, and pre_update_git is the update before's."""
    current = _current_heads(repos)

    def heads(value) -> dict:
        if not isinstance(value, dict):
            return {}
        return {
            k: v for k, v in value.items() if isinstance(k, str) and isinstance(v, str)
        }

    git, before = heads(manifest.get("git")), heads(manifest.get("pre_update_git"))
    if git and git.get("vhir") == current.get("vhir"):
        return before or current
    return git or current


def _write_update_state(version: str, vhir_commit: str) -> None:
    """Record an update's progress; every vhir command compares it with the
    installed code (main._warn_if_update_incomplete). version "" is written
    just before the pull, so any stop before Step 9 keeps warning; the full
    record (the version installed on disk, read fresh) is written after
    Step 9."""
    state = {
        "version": version,
        "vhir_commit": vhir_commit,
        "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    path = Path.home() / ".vhir" / "update-state.json"
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(state, indent=2) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        print(f"  Warning: could not record the update: {e}", file=sys.stderr)


def _finish_update(
    args,
    identity: dict,
    manifest: dict,
    manifest_path: Path,
    venv: str,
    source: Path,
    repos: list[tuple[str, Path]],
    pre_update_git: dict,
    torch_record: str,
) -> None:
    """Steps 4.5-9, after the pull and the install."""
    no_restart = getattr(args, "no_restart", False)

    # Step 4.5: Ensure password storage directory exists
    _ensure_password_dir()

    # Step 4.6: Ensure valhuntir → vhir symlink exists
    vhir_bin = Path(venv) / "bin" / "vhir"
    valhuntir_bin = Path(venv) / "bin" / "valhuntir"
    if vhir_bin.exists() and not valhuntir_bin.exists():
        try:
            valhuntir_bin.symlink_to(vhir_bin)
        except OSError:
            pass  # non-fatal

    # Step 5: Redeploy forensic controls
    from vhir_cli.commands import client_setup

    client_setup._LAUNCHERS_UPDATED.clear()  # what this update rewrites
    client_setup._LAUNCHERS_NOTED.clear()
    clients = _redeploy_clients(manifest)

    # Step 5.5: Fix sandbox if bwrap profile missing (Ubuntu 23.10+)
    if "claude-code" in clients or "codex" in clients:
        _ensure_bwrap_profile()

    # Step 6: Update manifest, as Step 5 left it: its deploys record their own
    # keys there (the Codex profile's hash), which the copy read at the start
    # doesn't hold
    try:
        reread = json.loads(manifest_path.read_text())
        if isinstance(reread, dict):
            manifest = reread
    except (OSError, ValueError):
        pass  # the copy read at the start
    manifest["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest["pre_update_git"] = pre_update_git
    git_hashes = {}
    for name, path in repos:
        if path.is_dir():
            git_hashes[name] = _git_head(path)
    manifest["git"] = git_hashes
    if torch_record:  # the user chose (asked, or --cpu/--gpu)
        manifest["torch_variant"] = torch_record
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print("  Updating manifest... done")
    except OSError as e:
        print(f"  Warning: could not update manifest: {e}", file=sys.stderr)

    # Step 6.5: the gateway's own launch lines run python -I (other clients;
    # claude-code installs had it at Step 5, so this finds nothing to do)
    client_setup._isolate_gateway_launchers()
    if client_setup._LAUNCHERS_UPDATED and no_restart:
        print("  The updated launch line takes effect at the next gateway restart.")

    # Step 7: Restart gateway
    if no_restart:
        print(
            "  Gateway restart skipped (--no-restart): portal approvals and portal saves "
            "must wait for the gateway restart. Until then, a commit through the old "
            "gateway applies every staged entry as the committer's decision, and a save "
            "through it can be refused or can remove other examiners' staged entries."
        )
    else:
        print("  Restarting gateway... ", end="", flush=True)
        try:
            result = subprocess.run(
                ["systemctl", "--user", "restart", "vhir-gateway"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            restart_ok = result.returncode == 0
            failure = result.stderr.strip()
        except subprocess.TimeoutExpired:
            # systemd carries on with the restart: report the state it reached
            try:
                state = (
                    subprocess.run(
                        ["systemctl", "--user", "is-active", "vhir-gateway"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    ).stdout.strip()
                    or "unknown"
                )
            except (subprocess.TimeoutExpired, OSError):
                state = "unknown"
            restart_ok = state == "active"
            failure = f"no answer in 60 s; the gateway is {state}"
        if restart_ok:
            print("done")
        else:
            print(f"failed ({failure})")
            print("  Check with: systemctl --user status vhir-gateway")
            print(
                "  Or, if you start it by hand: stop it, then run"
                " ~/.vhir/start-gateway.sh"
            )
            restart_ok = False

    # Step 7b: Check OpenSearch version mismatch
    _check_opensearch_version(source)

    # Step 8: Smoke test (wait for gateway to bind port after restart)
    run_test = not no_restart
    if not no_restart and not restart_ok:
        print("  Skipping connectivity test (restart failed)")
        run_test = False
    if run_test:
        import time as _time

        _time.sleep(3)
        print("  Running connectivity test...")
        from vhir_cli.commands.setup import _run_connectivity_test

        _run_connectivity_test(sift_tools=False)

    # Step 9: Summary
    hashes = manifest.get("git", {})
    parts = [f"{name}@{h[:7]}" for name, h in sorted(hashes.items())]
    print(f"\n  Updated to {', '.join(parts)}")
    # The version installed now, read fresh: vhir_cli.__version__ was read
    # when this process started, which can be before the pull
    installed = importlib.metadata.version("vhir-cli")
    _write_update_state(installed, manifest.get("git", {}).get("vhir", ""))
    if "claude-code" in clients or "codex" in clients:
        print("  Restart your LLM client to pick up new rules.")
    _offer_signing_key(identity)
    _print_share_rejoin_notice()
    if not no_restart and restart_ok:
        from vhir_cli.gateway import RECONNECT_HINT

        print(f"  {RECONNECT_HINT}")

    # Last, so it isn't scrolled away: SIFT tools too old for Valhuntir
    from vhir_cli.commands.setup import _print_sift_tools_warning

    _print_sift_tools_warning()


def _print_share_rejoin_notice() -> None:
    """A box joined before vhir had its own share name: say how wintools
    moves to it. Update adds no Samba changes; join makes them."""
    from vhir_cli.commands.join import SHARE_NAME, share_needs_rejoin

    if share_needs_rejoin():
        print(
            f"\n  wintools: vhir now shares the case as //SIFT/{SHARE_NAME}. This box still"
            " shares it as [cases], which also covers SIFT's own [cases] share.\n"
            "  Join wintools again to move to the new share: on SIFT run"
            " 'vhir setup join-code', then on Windows run setup-windows.ps1 with the new"
            " join code. The active case stays shared through the move.\n"
            "  Re-join before updating wintools on Windows: an updated wintools writes"
            " nothing to the case until SIFT re-joins (or until the case is activated"
            " again here, 'vhir case activate <case>')."
        )


def _git_head(path: Path) -> str:
    """Return current HEAD commit hash."""
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _detect_constraint_changed_packages(
    repos: list[tuple[str, Path]], pre_update_git: dict[str, str]
) -> set[str]:
    """Return package names whose version constraints changed in any
    pyproject.toml pulled during this update.

    Closes B81 (UAT 2026-04-23): `uv pip install -e ...` does not
    force-downgrade a package already installed at a version the
    updated pyproject.toml now forbids. Adding `--reinstall-package
    <name>` for every dep whose line changed makes the resolver
    re-evaluate that package and honor the new constraint.

    Approach: for each repo that advanced during `git pull`, diff
    pyproject.toml files old..new and collect package names from
    added/removed lines. PEP 508 dep strings at the start of a quoted
    line are matched; extras (`pycti[foo]`) and markers are tolerated
    (regex captures the leading identifier only). Over-reinstalling
    is safe — uv treats --reinstall-package as a no-op when the pin
    already matches; under-reinstalling is the bug we're closing.
    """
    import re

    # Identifier inside a quoted PEP 508 dep string — anywhere on the
    # line, since pyproject.toml sometimes uses single-line
    # `dependencies = ["pycti>=6.0"]` and sometimes one-per-line. The
    # lookahead requires a PEP 508 separator (`[`, `=`, `<`, `>`,
    # `!`, `~`, `;`, whitespace, closing quote) after the identifier
    # to avoid matching prose in table names or comments. PEP 503
    # normalisation (lower, `-`/`_`/`.` equivalence) is the
    # resolver's job — we pass the spelling as it appears.
    DEP_LINE = re.compile(r'["\']([A-Za-z][A-Za-z0-9_.\-]*)(?=[\[=<>!~; \t"\'])')
    changed: set[str] = set()

    for name, path in repos:
        if not path.is_dir():
            continue
        old = pre_update_git.get(name, "")
        new = _git_head(path)
        if not old or old == new or new == "unknown":
            continue
        # Whole-repo diff (monorepos like sift-mcp have many
        # pyproject.toml — packages/*/pyproject.toml + root). Git's
        # `**` pathspec glob behavior is fragile across configs, so
        # we skip pathspec entirely and filter on file headers in
        # the diff output below. --unified=0 drops hunk context so
        # the dep-line regex only sees +/- lines of changed content.
        result = subprocess.run(
            ["git", "-C", str(path), "diff", "--unified=0", f"{old}..{new}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            # Soft-fail: a broken diff invocation must not block the
            # install. Worst case: no auto-reinstall, operator drifts
            # on one package. Fall back to the hand-maintained list.
            continue
        # State machine: only process +/- lines when the current hunk
        # belongs to a pyproject.toml file. `diff --git a/... b/...`
        # lines switch the current file.
        in_pyproject = False
        for line in result.stdout.splitlines():
            if line.startswith("diff --git "):
                # `diff --git a/path/to/file b/path/to/file` — take
                # the b-path (post-change filename) and check suffix.
                parts = line.split()
                b_path = (
                    parts[-1][2:]
                    if len(parts) >= 4 and parts[-1].startswith("b/")
                    else ""
                )
                in_pyproject = b_path.endswith("pyproject.toml")
                continue
            if not in_pyproject:
                continue
            # Only process actual change lines (+/-) — headers (+++/---)
            # and context lines (which don't exist under --unified=0,
            # but belt-and-suspenders) are skipped.
            if not line or line[0] not in "+-":
                continue
            if line.startswith("+++") or line.startswith("---"):
                continue
            # findall: single-line deps like `dependencies =
            # ["pycti>=6.0"]` have the quoted identifier mid-line;
            # multi-line deps have it near the start. Both work.
            for match in DEP_LINE.findall(line):
                changed.add(match)

    return changed


def _git_branch(path: Path) -> str:
    """Return current branch name, or empty string if detached."""
    result = subprocess.run(
        ["git", "-C", str(path), "symbolic-ref", "--short", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_remote_head(path: Path) -> str:
    """Return origin/main HEAD commit hash."""
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "origin/main"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"
