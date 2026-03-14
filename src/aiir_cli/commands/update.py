"""Update AIIR installation on a SIFT workstation.

Pulls latest code, reinstalls packages, redeploys forensic controls,
and restarts the gateway. Runs on SIFT workstations only.

Remote clients that joined via 'aiir join' are not updated by this
command — they would need to re-run their client setup script.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

# Install order matches setup-sift.sh dependency chain.
# aiir-cli must come before case-mcp/report-mcp.
_INSTALL_ORDER = [
    "forensic-knowledge",
    "sift-common",
    "forensic-mcp",
    "sift-mcp",
    "sift-gateway",
    "aiir-cli",
    "case-mcp",
    "case-dashboard",
    "report-mcp",
    "windows-triage-mcp",
    "rag-mcp",
    "opencti-mcp",
]

# Paths relative to manifest["source"] (sift-mcp repo root).
# aiir-cli is special — relative to parent directory.
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


def _ensure_password_dir() -> None:
    """Ensure /var/lib/aiir/passwords/ exists, migrating from pins/ if needed."""
    passwords_dir = Path("/var/lib/aiir/passwords")
    pins_dir = Path("/var/lib/aiir/pins")

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


def cmd_update(args, identity: dict) -> None:
    """Pull latest code and redeploy AIIR installation."""
    check_only = getattr(args, "check", False)
    no_restart = getattr(args, "no_restart", False)

    # Step 1: Preflight
    manifest_path = Path.home() / ".aiir" / "manifest.json"
    if not manifest_path.is_file():
        print(
            "No manifest found at ~/.aiir/manifest.json.\n"
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
    aiir_dir = source.parent / "aiir"
    venv = manifest.get("venv", "")

    if not source.is_dir():
        print(f"Source directory not found: {source}", file=sys.stderr)
        sys.exit(1)

    pip_path = Path(venv) / "bin" / "pip"
    if not pip_path.exists():
        print(
            "Virtual environment corrupted — pip not found.\n"
            "Re-run setup-sift.sh to rebuild.",
            file=sys.stderr,
        )
        sys.exit(1)

    repos = [("sift-mcp", source), ("aiir", aiir_dir)]

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
        print("\n  Run 'aiir update' to apply.")
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

    # Step 4: Reinstall packages
    installed = manifest.get("packages", {})
    pip = str(Path(venv) / "bin" / "pip")
    count = 0
    for pkg_name in _INSTALL_ORDER:
        if pkg_name not in installed:
            continue
        if pkg_name == "aiir-cli":
            pkg_path = str(aiir_dir)
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
        result = subprocess.run(
            [pip, "install", "-e", pkg_path, "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            print(
                f"  Failed to install {pkg_name}: {result.stderr.strip()}",
                file=sys.stderr,
            )
            sys.exit(1)
        count += 1
    print(f"  Reinstalling packages... {count} packages")

    # Fix opentelemetry version conflict (pycti ~=1.35 vs chromadb)
    if "rag-mcp" in installed and "opencti-mcp" in installed:
        subprocess.run(
            [
                pip,
                "install",
                "--quiet",
                "opentelemetry-sdk>=1.40",
                "opentelemetry-api>=1.40",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    # Step 4.5: Ensure password storage directory exists
    _ensure_password_dir()

    # Step 5: Redeploy forensic controls
    client = manifest.get("client")
    if client == "claude-code":
        from aiir_cli.commands.client_setup import _deploy_claude_code_assets

        print("  Redeploying forensic controls...")
        _deploy_claude_code_assets()
    elif client:
        print(f"  Client: {client} (no local controls to redeploy)")
    else:
        print("  No client type in manifest. Run 'aiir setup client' to configure.")

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
            ["systemctl", "--user", "restart", "aiir-gateway"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print("done")
        else:
            print(f"failed ({result.stderr.strip()})")
            print("  Check with: systemctl --user status aiir-gateway")

    # Step 8: Smoke test
    print("  Running connectivity test...")
    from aiir_cli.commands.setup import _run_connectivity_test

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
