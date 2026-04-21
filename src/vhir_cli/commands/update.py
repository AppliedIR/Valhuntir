"""Update Valhuntir installation on a SIFT workstation.

Pulls latest code, reinstalls packages, redeploys forensic controls,
and restarts the gateway. Runs on SIFT workstations only.

Remote clients that joined via 'vhir join' are not updated by this
command — they would need to re-run their client setup script.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

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
    """Ensure /var/lib/vhir/passwords/ exists, migrating from pins/ if needed."""
    passwords_dir = Path("/var/lib/vhir/passwords")
    pins_dir = Path("/var/lib/vhir/pins")

    if passwords_dir.is_dir():
        return

    # Migrate pins/ → passwords/ (requires sudo because parent is root-owned)
    if pins_dir.is_dir():
        print(
            "  Migrating password storage (pins/ → passwords/)... ", end="", flush=True
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
    print("  Creating password storage directory... ", end="", flush=True)
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
    if not os_path.is_file():
        return
    text = os_path.read_text()
    m = re.search(r"opensearchproject/opensearch:(\S+)", text)
    if not m:
        return
    pinned = m.group(1)

    # Check running container version
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.Config.Image}}", "vhir-opensearch"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return  # Container not running
    running_image = result.stdout.strip()
    running_m = re.search(r"opensearchproject/opensearch:(\S+)", running_image)
    if not running_m:
        return
    running = running_m.group(1)

    if running != pinned:
        print(
            f"\n  OpenSearch version mismatch: running {running}, code requires {pinned}."
        )
        print("  Upgrading requires recreating the container. Indexed search data")
        print("  will be cleared and must be reingested. Case records (findings,")
        print("  timeline, evidence) are NOT affected.")
        setup_script = os_path.parent.parent / "scripts" / "setup-opensearch.sh"
        try:
            answer = input("\n  Upgrade OpenSearch now? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer in ("y", "yes"):
            print(f"  Running {setup_script}...")
            result = subprocess.run(
                ["bash", str(setup_script)],
                timeout=300,
            )
            if result.returncode != 0:
                print("  OpenSearch upgrade failed.", file=sys.stderr)
        else:
            print(f"  Skipped. To upgrade later: bash {setup_script}")
        print()


def cmd_update(args, identity: dict) -> None:
    """Pull latest code and redeploy Valhuntir installation."""
    check_only = getattr(args, "check", False)
    no_restart = getattr(args, "no_restart", False)

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
    subprocess.run(["uv", "self", "update", "--quiet"], capture_output=True, timeout=60)

    repos = [("sift-mcp", source), ("vhir", vhir_dir)]

    # Add opensearch-mcp if installed (external repo, not in sift-mcp monorepo)
    os_repo = _resolve_opensearch_mcp_repo(source)
    if os_repo is not None:
        repos.append(("opensearch-mcp", os_repo))
    elif _opensearch_mcp_installed_but_missing(source):
        # Package is installed in the venv but no git repo found anywhere.
        # Silent skip was the v0.6.1 bug — make it visibly actionable.
        print(
            "\n  WARNING: opensearch-mcp package is installed but its git repo\n"
            "  was not found in any known location. `vhir update` cannot\n"
            "  pull or reinstall it automatically. Update manually:\n"
            "    cd <path-to-opensearch-mcp> && git pull && uv pip install -e .\n",
            file=sys.stderr,
        )

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
                f"Cannot reach remote for {name}: {result.stderr.strip()}\n"
                "Check network and try again.",
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

    # Step 3: Record pre-update state + pull
    pre_update_git = {}
    for name, path in repos:
        if path.is_dir():
            pre_update_git[name] = _git_head(path)

    for name, path in repos:
        if not path.is_dir():
            continue
        # Verify on main branch before pulling
        branch = _git_branch(path)
        if branch and branch != "main":
            print(
                f"{name} is on branch '{branch}', expected 'main'.\n"
                f"Switch to main: git -C {path} checkout main",
                file=sys.stderr,
            )
            sys.exit(1)
        result = subprocess.run(
            ["git", "-C", str(path), "pull", "--ff-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            print(
                f"Failed to pull {name}: {result.stderr.strip()}\n"
                f"Resolve conflicts in {path} or re-run setup-sift.sh.",
                file=sys.stderr,
            )
            sys.exit(1)
        # Count new commits
        old = pre_update_git.get(name, "")
        new = _git_head(path)
        if old and old != new:
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

    # Step 4: Reinstall packages (batched for unified dependency resolution)
    installed = manifest.get("packages", {})
    pkg_paths = []
    for pkg_name in _INSTALL_ORDER:
        if pkg_name not in installed:
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
    # Force re-resolution of opentelemetry exporter when both RAG and opencti
    # are installed (prevents sdk/exporter version mismatch on update)
    if "rag-mcp" in installed and "opencti-mcp" in installed:
        cmd.extend(["--reinstall-package", "opentelemetry-exporter-otlp-proto-grpc"])
    for p in pkg_paths:
        cmd.extend(["-e", p])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        print(
            f"  Package install failed: {result.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"  Reinstalling packages... {len(pkg_paths)} packages")

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
    client = manifest.get("client")
    if client == "claude-code":
        from vhir_cli.commands.client_setup import _deploy_claude_code_assets

        print("  Redeploying forensic controls...")
        _deploy_claude_code_assets()
    elif client:
        print(f"  Client: {client} (no local controls to redeploy)")
    else:
        print("  No client type in manifest. Run 'vhir setup client' to configure.")

    # Step 5.5: Fix sandbox if bwrap profile missing (Ubuntu 23.10+)
    if client == "claude-code":
        _ensure_bwrap_profile()

    # Step 6: Update manifest
    manifest["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    manifest["pre_update_git"] = pre_update_git
    git_hashes = {}
    for name, path in repos:
        if path.is_dir():
            git_hashes[name] = _git_head(path)
    manifest["git"] = git_hashes
    try:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print("  Updating manifest... done")
    except OSError as e:
        print(f"  Warning: could not update manifest: {e}", file=sys.stderr)

    # Step 7: Restart gateway
    if no_restart:
        print("  Gateway restart skipped (--no-restart)")
    else:
        print("  Restarting gateway... ", end="", flush=True)
        result = subprocess.run(
            ["systemctl", "--user", "restart", "vhir-gateway"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        restart_ok = result.returncode == 0
        if restart_ok:
            print("done")
        else:
            print(f"failed ({result.stderr.strip()})")
            print("  Check with: systemctl --user status vhir-gateway")
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

        _run_connectivity_test()

    # Step 9: Summary
    hashes = manifest.get("git", {})
    parts = [f"{name}@{h[:7]}" for name, h in sorted(hashes.items())]
    print(f"\n  Updated to {', '.join(parts)}")
    if client == "claude-code":
        print("  Restart your LLM client to pick up new rules.")


def _git_head(path: Path) -> str:
    """Return current HEAD commit hash."""
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


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
