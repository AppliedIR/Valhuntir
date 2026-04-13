"""Back up and restore case data for archival, legal preservation, and disaster recovery.

Creates timestamped backup with SHA-256 manifest for integrity verification.
Restore enforces original case path for audit trail integrity.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.case_io import get_case_dir, load_case_meta
from vhir_cli.verification import VERIFICATION_DIR

_SKIP_NAMES = {"__pycache__", ".DS_Store", "examiners.bak"}
_PASSWORDS_DIR = Path("/var/lib/vhir/passwords")
_SNAPSHOTS_DIR = Path(os.environ.get("VHIR_SNAPSHOTS_DIR", "/var/lib/vhir/snapshots"))


def cmd_backup(args, identity: dict) -> None:
    """Entry point for 'vhir backup'."""
    verify_path = getattr(args, "verify", None)
    if verify_path:
        ok = _verify_backup(Path(verify_path))
        if not ok:
            sys.exit(1)
    else:
        _create_backup(args, identity)


def _create_backup(args, identity: dict) -> None:
    """Create a case backup (CLI wrapper with TTY prompts)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    destination = getattr(args, "destination", None)
    if not destination:
        print("Error: destination is required (unless using --verify)", file=sys.stderr)
        sys.exit(1)

    examiner = identity.get("examiner", "unknown")

    # Determine what to include
    include_all = getattr(args, "all", False)
    include_evidence = getattr(args, "include_evidence", False) or include_all
    include_extractions = getattr(args, "include_extractions", False) or include_all
    include_opensearch_flag = getattr(args, "include_opensearch", False)
    include_opensearch = include_opensearch_flag

    # Detect OpenSearch availability
    os_info = _detect_opensearch(case_dir)

    # Interactive prompts (only when TTY and no flags)
    if not include_all and sys.stdin.isatty():
        scan = scan_case_dir(case_dir)
        case_data_size = sum(s for _, _, s in scan["case_data"])
        evidence_size = sum(s for _, _, s in scan["evidence"])
        extractions_size = sum(s for _, _, s in scan["extractions"])

        print(f"Case data:    {human_size(case_data_size)}")
        if scan["evidence"] and not include_evidence:
            print(
                f"Evidence:     {human_size(evidence_size)} ({len(scan['evidence'])} files)"
            )
            resp = input("Include evidence files? [y/N] ").strip().lower()
            include_evidence = resp in ("y", "yes")
        if scan["extractions"] and not include_extractions:
            print(
                f"Extractions:  {human_size(extractions_size)} ({len(scan['extractions'])} files)"
            )
            resp = input("Include extraction files? [y/N] ").strip().lower()
            include_extractions = resp in ("y", "yes")
        if os_info.get("available") and os_info.get("local") and not include_opensearch:
            print(
                f"OpenSearch:   {os_info.get('size_human', '?')} "
                f"({os_info.get('index_count', 0)} indices, "
                f"{os_info.get('total_docs', 0):,} docs)"
            )
            resp = input("Include OpenSearch indices? [y/N] ").strip().lower()
            include_opensearch = resp in ("y", "yes")
        elif os_info.get("available") and not os_info.get("local"):
            print(
                f"OpenSearch:   remote ({os_info.get('host', '?')}) -- not included in backup"
            )
    elif include_all:
        # --all includes OpenSearch for local Docker, skips for remote
        if os_info.get("available") and os_info.get("local"):
            include_opensearch = True
        scan = scan_case_dir(case_dir)
        total = sum(
            s
            for cat in ("case_data", "evidence", "extractions")
            for _, _, s in scan[cat]
        )
        print(f"Total backup size: {human_size(total)} (excluding OpenSearch)")

    # Explicit --include-opensearch must succeed
    if include_opensearch_flag and not os_info.get("available"):
        print("Error: OpenSearch is not available.", file=sys.stderr)
        sys.exit(1)
    if include_opensearch_flag and not os_info.get("local"):
        print(
            "Error: Remote OpenSearch snapshot not supported.\n"
            "Use your OpenSearch host's native backup tools.",
            file=sys.stderr,
        )
        sys.exit(1)

    def progress(label: str, i: int, total: int) -> None:
        if i % 50 == 0 or i == total:
            print(f"{label}... {i}/{total}", end="\r")

    try:
        result = create_backup_data(
            case_dir=case_dir,
            destination=destination,
            examiner=examiner,
            include_evidence=include_evidence,
            include_extractions=include_extractions,
            include_opensearch=include_opensearch,
            progress_fn=progress,
        )
    except OSError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Print symlink warnings
    for link_path, target, size in result.get("symlinks", []):
        print(f"Following symlink: {link_path} -> {target} ({human_size(size)})")

    # Verification ledger note
    if result.get("includes_verification_ledger"):
        pass  # included silently
    elif result.get("ledger_note"):
        print(result["ledger_note"])

    # OpenSearch snapshot error
    snap_info = result.get("opensearch_snapshot", {})
    if snap_info.get("error"):
        print(
            f"\nWARNING: OpenSearch snapshot failed: {snap_info['error']}\n"
            "Backup completed without OpenSearch indices.\n"
            "Re-run setup-opensearch.sh to enable snapshot support:\n"
            "  cd opensearch-mcp && ./scripts/setup-opensearch.sh",
            file=sys.stderr,
        )

    # Trailing newline after progress output
    print()

    print(f"Backup complete: {result['backup_path']}")
    print(f"  Files: {result['file_count']}")
    print(f"  Size:  {human_size(result['total_bytes'])}")
    if result.get("includes_opensearch"):
        snap = result.get("opensearch_snapshot", {})
        print(
            f"  OpenSearch: {snap.get('index_count', 0)} indices, "
            f"{snap.get('total_docs', 0):,} docs"
        )
    if result.get("password_examiners"):
        print(f"  Password hashes: {', '.join(result['password_examiners'])}")

    # Password warning
    print()
    print("=" * 64)
    print("IMPORTANT: This backup contains HMAC-signed findings.")
    print()
    print("To verify or restore these findings in the future, you MUST")
    print("know the examiner password used when findings were approved.")
    print()
    print("The backup does NOT contain the plaintext password.")
    print("It is YOUR responsibility to remember or securely store it.")
    print("=" * 64)


# ---------------------------------------------------------------------------
# Core logic (no TTY, no sys.exit — callable from CLI and MCP)
# ---------------------------------------------------------------------------


def create_backup_data(
    case_dir: Path,
    destination: str,
    examiner: str,
    *,
    include_evidence: bool = False,
    include_extractions: bool = False,
    include_opensearch: bool = False,
    purpose: str = "",
    progress_fn=None,
) -> dict:
    """Create a case backup and return result dict.

    This is the shared implementation used by both the CLI and the MCP tool.
    No TTY interaction — callers handle prompts and output.

    Args:
        case_dir: Resolved case directory path.
        destination: Directory to create the backup in.
        examiner: Examiner identity for the manifest.
        include_evidence: Include evidence/ files.
        include_extractions: Include extractions/ files.
        include_opensearch: Include OpenSearch index snapshot (local Docker only).
        purpose: Why the backup is being made (stored in manifest).
        progress_fn: Optional callback(label, i, total) for progress.

    Returns:
        Dict with backup_path, file_count, total_bytes, manifest,
        symlinks, includes_verification_ledger, ledger_note,
        includes_opensearch, opensearch_snapshot, password_examiners.

    Raises:
        OSError: If backup directory cannot be created or files cannot be copied.
    """
    meta = load_case_meta(case_dir)
    case_id = meta.get("case_id", case_dir.name)
    dest = Path(destination)

    # Create backup dir with collision avoidance (atomic mkdir to avoid TOCTOU)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    backup_name = f"{case_id}-{date_str}"
    backup_dir = dest / backup_name
    suffix = 0
    while True:
        try:
            backup_dir.mkdir(parents=True, exist_ok=False)
            break
        except FileExistsError:
            suffix += 1
            backup_dir = dest / f"{backup_name}-{suffix}"

    # Write in-progress marker
    marker = backup_dir / ".backup-in-progress"
    marker.touch()

    # Scan case directory
    scan = scan_case_dir(case_dir)

    # Build file list
    files_to_copy = list(scan["case_data"])
    if include_evidence:
        files_to_copy.extend(scan["evidence"])
    if include_extractions:
        files_to_copy.extend(scan["extractions"])

    # Copy verification ledger if it exists
    ledger_path = VERIFICATION_DIR / f"{case_id}.jsonl"
    ledger_included = False
    ledger_note = ""
    if ledger_path.is_file():
        try:
            vdir = backup_dir / "verification"
            vdir.mkdir(exist_ok=True)
            shutil.copy2(str(ledger_path), str(vdir / f"{case_id}.jsonl"))
            ledger_included = True
        except OSError:
            ledger_note = "Warning: could not copy verification ledger"
    else:
        ledger_note = "Note: no verification ledger found for this case"

    # Copy password hash files for all examiners with findings
    password_examiners: list[str] = []
    try:
        findings_file = case_dir / "findings.json"
        if findings_file.exists():
            findings = json.loads(findings_file.read_text())
            if isinstance(findings, list):
                examiners_in_case = {
                    f.get("created_by", "") for f in findings if f.get("created_by")
                }
                pw_dir = backup_dir / "passwords"
                for ex in sorted(examiners_in_case):
                    pw_file = _PASSWORDS_DIR / f"{ex}.json"
                    if pw_file.is_file():
                        pw_dir.mkdir(exist_ok=True)
                        shutil.copy2(str(pw_file), str(pw_dir / f"{ex}.json"))
                        password_examiners.append(ex)
    except (json.JSONDecodeError, OSError):
        pass  # best-effort

    # Copy files
    total_files = len(files_to_copy)
    for i, (rel_path, abs_path, _size) in enumerate(files_to_copy, 1):
        dst = backup_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(abs_path), str(dst))
        if progress_fn:
            progress_fn("Copying", i, total_files)

    # OpenSearch snapshot (local Docker only)
    opensearch_snapshot_info: dict = {}
    if include_opensearch:
        try:
            opensearch_snapshot_info = _create_opensearch_snapshot(
                case_id, backup_dir, progress_fn
            )
        except Exception as e:
            opensearch_snapshot_info = {"error": str(e)}

    # Generate manifest — walk the backup dir (not source)
    all_backup_files = []
    for root, _dirs, filenames in os.walk(backup_dir, followlinks=True):
        for fname in filenames:
            if fname == ".backup-in-progress":
                continue
            fpath = Path(root) / fname
            rel = fpath.relative_to(backup_dir)
            all_backup_files.append((str(rel), fpath))

    manifest_files = []
    total_bytes = 0
    total_manifest = len(all_backup_files)
    for i, (rel, fpath) in enumerate(sorted(all_backup_files), 1):
        fsize = fpath.stat().st_size
        fhash = sha256_file(fpath)
        manifest_files.append({"path": rel, "sha256": fhash, "bytes": fsize})
        total_bytes += fsize
        if progress_fn:
            progress_fn("Generating manifest", i, total_manifest)

    manifest = {
        "version": 1,
        "case_id": case_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": str(case_dir),
        "examiner": examiner,
        "includes_evidence": include_evidence,
        "includes_extractions": include_extractions,
        "includes_verification_ledger": ledger_included,
        "includes_password_hashes": bool(password_examiners),
        "password_examiners": password_examiners,
        "includes_opensearch": bool(
            opensearch_snapshot_info and not opensearch_snapshot_info.get("error")
        ),
        "notes": ["approvals.jsonl is an archival copy, not used for verification"],
        "files": manifest_files,
        "total_bytes": total_bytes,
        "file_count": len(manifest_files),
    }
    if opensearch_snapshot_info and not opensearch_snapshot_info.get("error"):
        manifest["opensearch_snapshot"] = opensearch_snapshot_info
    if purpose:
        manifest["purpose"] = purpose

    manifest_path = backup_dir / "backup-manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

    # Remove in-progress marker
    try:
        marker.unlink()
    except OSError:
        pass

    return {
        "backup_path": str(backup_dir),
        "file_count": len(manifest_files),
        "total_bytes": total_bytes,
        "total_size": human_size(total_bytes),
        "manifest": "backup-manifest.json",
        "includes_verification_ledger": ledger_included,
        "includes_opensearch": bool(
            opensearch_snapshot_info and not opensearch_snapshot_info.get("error")
        ),
        "opensearch_snapshot": opensearch_snapshot_info,
        "password_examiners": password_examiners,
        "ledger_note": ledger_note,
        "symlinks": scan["symlinks"],
    }


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


def _verify_backup(backup_path: Path) -> bool:
    """Verify a backup's integrity. Returns True if all checks pass."""
    if not backup_path.is_dir():
        print(f"Error: not a directory: {backup_path}", file=sys.stderr)
        return False

    # Check for incomplete backup
    if (backup_path / ".backup-in-progress").exists():
        print("FAILED: Incomplete backup — copy was interrupted")
        return False

    manifest_file = backup_path / "backup-manifest.json"
    if not manifest_file.exists():
        print("FAILED: backup-manifest.json not found", file=sys.stderr)
        return False

    try:
        manifest = json.loads(manifest_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"FAILED: cannot read manifest: {e}", file=sys.stderr)
        return False

    files = manifest.get("files", [])
    ok_count = 0
    mismatch_count = 0
    missing_count = 0
    total = len(files)

    for i, entry in enumerate(files, 1):
        rel_path = entry["path"]
        expected_hash = entry["sha256"]
        fpath = backup_path / rel_path

        if not fpath.exists():
            print(f"  MISSING: {rel_path}")
            missing_count += 1
        else:
            actual_hash = sha256_file(fpath)
            if actual_hash != expected_hash:
                print(f"  MISMATCH: {rel_path}")
                mismatch_count += 1
            else:
                ok_count += 1

        if i % 50 == 0 or i == total:
            print(f"Checking... {i}/{total}", end="\r")
    if total:
        print()

    print(f"\nVerification: {ok_count} OK", end="")
    if mismatch_count:
        print(f", {mismatch_count} MISMATCH", end="")
    if missing_count:
        print(f", {missing_count} MISSING", end="")
    print()

    if mismatch_count or missing_count:
        print("FAILED: backup integrity check failed")
        return False

    print("PASSED: all files verified")
    return True


# ---------------------------------------------------------------------------
# Helpers (public — used by MCP tool via import)
# ---------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file in 64KB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def human_size(nbytes: int) -> str:
    """Format byte count for display."""
    if nbytes >= 1_000_000_000:
        return f"{nbytes / 1_000_000_000:.1f} GB"
    if nbytes >= 1_000_000:
        return f"{nbytes / 1_000_000:.1f} MB"
    if nbytes >= 1_000:
        return f"{nbytes / 1_000:.0f} KB"
    return f"{nbytes} B"


def scan_case_dir(case_dir: Path) -> dict:
    """Scan case directory and categorize files.

    Returns dict with keys: case_data, evidence, extractions, symlinks.
    Each list contains (relative_path, absolute_path, size) tuples.
    """
    case_data = []
    evidence = []
    extractions = []
    symlinks = []

    for root, dirs, files in os.walk(case_dir, followlinks=True):
        # Filter out skip names
        dirs[:] = [d for d in dirs if d not in _SKIP_NAMES]

        root_path = Path(root)
        for fname in files:
            if fname in _SKIP_NAMES:
                continue
            abs_path = root_path / fname
            rel_path = abs_path.relative_to(case_dir)

            try:
                size = abs_path.stat().st_size
            except OSError:
                continue

            # Track symlinks
            if abs_path.is_symlink():
                try:
                    target = str(abs_path.resolve())
                except OSError:
                    target = "(unresolvable)"
                symlinks.append((str(rel_path), target, size))

            entry = (str(rel_path), str(abs_path), size)
            parts = rel_path.parts

            if parts and parts[0] == "evidence":
                evidence.append(entry)
            elif parts and parts[0] == "extractions":
                extractions.append(entry)
            else:
                case_data.append(entry)

    return {
        "case_data": case_data,
        "evidence": evidence,
        "extractions": extractions,
        "symlinks": symlinks,
    }


# ---------------------------------------------------------------------------
# OpenSearch Snapshot Helpers
# ---------------------------------------------------------------------------


def _is_opensearch_available() -> bool:
    """Check if OpenSearch is reachable (no case_dir needed)."""
    try:
        import importlib.util

        if importlib.util.find_spec("opensearch_mcp") is None:
            return False
        from opensearch_mcp.client import get_client

        client = get_client()
        client.cluster.health()
        return True
    except Exception:
        return False


def _detect_opensearch(case_dir: Path) -> dict:
    """Detect OpenSearch availability and case index info."""
    try:
        import importlib.util

        if importlib.util.find_spec("opensearch_mcp") is None:
            return {"available": False}

        from opensearch_mcp.client import get_client
        from opensearch_mcp.paths import vhir_dir

        config_path = vhir_dir() / "opensearch.yaml"
        if not config_path.exists():
            return {"available": False}

        import yaml

        config = yaml.safe_load(config_path.read_text()) or {}
        host = config.get("host", "")
        local = "localhost" in host or "127.0.0.1" in host

        client = get_client()
        client.cluster.health()

        # Get case index stats
        meta = load_case_meta(case_dir)
        case_id = meta.get("case_id", case_dir.name)
        from opensearch_mcp.paths import sanitize_index_component

        pattern = f"case-{sanitize_index_component(case_id)}-*"
        try:
            indices = client.cat.indices(index=pattern, format="json")
        except Exception:
            indices = []

        total_docs = sum(int(idx.get("docs.count", 0)) for idx in indices)
        total_bytes = sum(_parse_size(idx.get("store.size", "0")) for idx in indices)

        return {
            "available": True,
            "local": local,
            "host": host,
            "index_count": len(indices),
            "total_docs": total_docs,
            "size_bytes": total_bytes,
            "size_human": human_size(total_bytes),
        }
    except Exception:
        return {"available": False}


def _parse_size(size_str: str) -> int:
    """Parse OpenSearch size string (e.g., '2.1gb', '500kb') to bytes."""
    s = size_str.lower().strip()
    try:
        if s.endswith("gb"):
            return int(float(s[:-2]) * 1_000_000_000)
        if s.endswith("mb"):
            return int(float(s[:-2]) * 1_000_000)
        if s.endswith("kb"):
            return int(float(s[:-2]) * 1_000)
        if s.endswith("b"):
            return int(float(s[:-1]))
        return int(s)
    except (ValueError, IndexError):
        return 0


def _create_opensearch_snapshot(
    case_id: str, backup_dir: Path, progress_fn=None
) -> dict:
    """Create OpenSearch snapshot for a case's indices. Local Docker only."""
    import time

    from opensearch_mcp.client import get_client
    from opensearch_mcp.paths import sanitize_index_component

    client = get_client()
    safe_id = sanitize_index_component(case_id)
    repo_name = f"vhir-backup-{safe_id}"
    pattern = f"case-{safe_id}-*"
    snapshot_name = "snap"
    staging = _SNAPSHOTS_DIR / repo_name

    # Lock file
    lock_path = _SNAPSHOTS_DIR / ".backup.lock"
    _SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    _acquire_lock(lock_path)

    try:
        # Clean stale staging data
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)

        # Register repo — path inside container
        container_path = f"/usr/share/opensearch/snapshots/{repo_name}"
        client.snapshot.create_repository(
            repository=repo_name,
            body={"type": "fs", "settings": {"location": container_path}},
        )

        # Get index stats before snapshot
        indices = client.cat.indices(index=pattern, format="json")
        total_docs = sum(int(idx.get("docs.count", 0)) for idx in indices)

        # Get OpenSearch version
        info = client.info()
        os_version = info.get("version", {}).get("number", "unknown")

        # Create snapshot
        client.snapshot.create(
            repository=repo_name,
            snapshot=snapshot_name,
            body={"indices": pattern, "include_global_state": False},
            wait_for_completion=False,
        )

        # Poll for completion (30 minute timeout)
        max_wait = 1800
        start = time.monotonic()
        while True:
            if time.monotonic() - start > max_wait:
                raise RuntimeError(
                    "Snapshot timed out after 30 minutes. "
                    "Check OpenSearch health and retry."
                )
            status = client.snapshot.status(
                repository=repo_name, snapshot=snapshot_name
            )
            snapshots = status.get("snapshots", [])
            if snapshots:
                state = snapshots[0].get("state", "")
                if state == "SUCCESS":
                    break
                if state in ("FAILED", "PARTIAL", "INCOMPATIBLE"):
                    raise RuntimeError(f"Snapshot failed: {state}")
            time.sleep(2)

        # Move snapshot data to backup dir
        backup_snapshot_dir = backup_dir / "opensearch-snapshot"
        # Remove target if it exists (prior run or collision)
        if backup_snapshot_dir.exists():
            shutil.rmtree(backup_snapshot_dir)
        try:
            os.rename(str(staging), str(backup_snapshot_dir))
        except OSError:
            # Cross-filesystem — estimate size and warn
            staging_size = sum(
                f.stat().st_size for f in staging.rglob("*") if f.is_file()
            )
            if progress_fn:
                progress_fn(
                    f"Copying OpenSearch snapshot ({human_size(staging_size)})",
                    0,
                    1,
                )
            shutil.copytree(str(staging), str(backup_snapshot_dir))
            shutil.rmtree(staging, ignore_errors=True)

        # Deregister repo
        try:
            client.snapshot.delete_repository(repository=repo_name)
        except Exception:
            pass

        return {
            "opensearch_version": os_version,
            "index_count": len(indices),
            "total_docs": total_docs,
        }
    except Exception:
        # Cleanup on failure
        try:
            client.snapshot.delete_repository(repository=repo_name)
        except Exception:
            pass
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        _release_lock(lock_path)


def _acquire_lock(lock_path: Path) -> None:
    """Acquire a PID-based lock file. Stale lock detection."""
    if lock_path.exists():
        try:
            old_pid = int(lock_path.read_text().strip())
            # Check if PID is still running
            os.kill(old_pid, 0)
            raise RuntimeError(
                f"Another backup/restore is in progress (PID {old_pid}). "
                f"If this is stale, remove {lock_path}"
            )
        except (ValueError, ProcessLookupError, PermissionError):
            # Stale lock — remove it
            lock_path.unlink(missing_ok=True)
    lock_path.write_text(str(os.getpid()))


def _release_lock(lock_path: Path) -> None:
    """Release the lock file."""
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


def cmd_restore(args, identity: dict) -> None:
    """Entry point for 'vhir restore'."""
    backup_path = Path(args.backup_path)
    skip_opensearch = getattr(args, "skip_opensearch", False)
    skip_ledger = getattr(args, "skip_ledger", False)

    if not backup_path.is_dir():
        print(f"Error: not a directory: {backup_path}", file=sys.stderr)
        sys.exit(1)

    # Check markers
    if (backup_path / ".backup-in-progress").exists():
        print("Error: Incomplete backup — copy was interrupted.", file=sys.stderr)
        sys.exit(1)

    # Read manifest
    manifest_file = backup_path / "backup-manifest.json"
    if not manifest_file.exists():
        print("Error: backup-manifest.json not found.", file=sys.stderr)
        sys.exit(1)

    try:
        manifest = json.loads(manifest_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error: cannot read manifest: {e}", file=sys.stderr)
        sys.exit(1)

    # Version check
    if manifest.get("version", 0) != 1:
        print(
            f"Error: Backup manifest version {manifest.get('version')} "
            "is not supported. This version of vhir supports manifest version 1.",
            file=sys.stderr,
        )
        sys.exit(1)

    case_id = manifest.get("case_id", "")
    source_path = manifest.get("source", "")
    if not case_id or not source_path:
        print("Error: manifest missing case_id or source.", file=sys.stderr)
        sys.exit(1)

    target_dir = Path(source_path)
    cases_parent = target_dir.parent

    # Show backup summary
    print(f"\nBackup: {case_id} ({manifest.get('timestamp', '?')})")
    print(f"  Source:       {source_path}")
    print(f"  Files:        {manifest.get('file_count', '?')}")
    print(f"  Size:         {human_size(manifest.get('total_bytes', 0))}")
    if manifest.get("includes_opensearch"):
        snap = manifest.get("opensearch_snapshot", {})
        print(
            f"  OpenSearch:   {snap.get('index_count', 0)} indices, "
            f"{snap.get('total_docs', 0):,} docs"
        )
    else:
        print("  OpenSearch:   not included")
    if manifest.get("includes_verification_ledger"):
        print("  Ledger:       yes")
    else:
        print("  Ledger:       not included")
    if manifest.get("password_examiners"):
        print(f"  Passwords:    {', '.join(manifest['password_examiners'])}")
    print()

    # Interactive prompts
    restore_opensearch = (
        not skip_opensearch
        and manifest.get("includes_opensearch")
        and (backup_path / "opensearch-snapshot").is_dir()
    )
    restore_ledger = not skip_ledger and manifest.get("includes_verification_ledger")

    if sys.stdin.isatty():
        if restore_opensearch:
            resp = input("Restore OpenSearch indices? [Y/n] ").strip().lower()
            if resp in ("n", "no"):
                restore_opensearch = False
        if restore_ledger:
            resp = input("Restore verification ledger? [Y/n] ").strip().lower()
            if resp in ("n", "no"):
                restore_ledger = False

    # Conflict checks
    if target_dir.exists():
        # Check for .restore-in-progress marker
        if (target_dir / ".restore-in-progress").exists():
            if sys.stdin.isatty():
                resp = (
                    input(
                        "Previous restore was interrupted. Clean up and retry? [Y/n] "
                    )
                    .strip()
                    .lower()
                )
                if resp not in ("n", "no"):
                    shutil.rmtree(target_dir)
                else:
                    sys.exit(1)
            else:
                # Non-TTY: auto-clean interrupted restore (it's partial data, not real)
                shutil.rmtree(target_dir)
        else:
            print(
                f"Error: Case directory already exists: {target_dir}\n"
                f"Remove it first, then re-run restore.",
                file=sys.stderr,
            )
            sys.exit(1)

    if restore_ledger:
        ledger_target = VERIFICATION_DIR / f"{case_id}.jsonl"
        if ledger_target.exists():
            print(
                f"Error: Verification ledger already exists: {ledger_target}\n"
                f"Remove it first or use --skip-ledger.",
                file=sys.stderr,
            )
            sys.exit(1)

    if restore_opensearch and _is_opensearch_available():
        # Check for existing indices
        try:
            from opensearch_mcp.client import get_client
            from opensearch_mcp.paths import sanitize_index_component

            client = get_client()
            safe = sanitize_index_component(case_id)
            existing = client.cat.indices(index=f"case-{safe}-*", format="json")
            if existing:
                print(
                    f"Error: OpenSearch indices for case-{safe}-* already exist.\n"
                    "Delete them first or use --skip-opensearch.",
                    file=sys.stderr,
                )
                sys.exit(1)
        except Exception:
            pass  # OpenSearch query failed — will handle during restore

        # Version check
        snap_info = manifest.get("opensearch_snapshot", {})
        backup_version = snap_info.get("opensearch_version", "")
        if backup_version:
            try:
                client = get_client()
                info = client.info()
                current_version = info.get("version", {}).get("number", "")
                if (
                    current_version
                    and backup_version.split(".")[0] != current_version.split(".")[0]
                ):
                    print(
                        f"Error: OpenSearch version mismatch.\n"
                        f"  Backup: {backup_version}\n"
                        f"  Current: {current_version}\n"
                        "Snapshots are not compatible across major versions.\n"
                        "Use --skip-opensearch to restore without indices.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            except Exception:
                pass

    # Create target directory
    try:
        cases_parent.mkdir(parents=True, exist_ok=True)
        target_dir.mkdir(parents=False, exist_ok=False)
    except PermissionError:
        print(
            f"Error: Cannot create {target_dir}: Permission denied\n\n"
            f"Fix with:\n"
            f"  sudo mkdir -p {cases_parent}\n"
            f"  sudo chown $(whoami):$(whoami) {cases_parent}\n\n"
            f"Then re-run: vhir restore {backup_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    # Write restore marker
    restore_marker = target_dir / ".restore-in-progress"
    restore_marker.touch()

    def progress(label: str, i: int, total: int) -> None:
        if i % 50 == 0 or i == total:
            print(f"  {label}... {i}/{total}", end="\r")

    # Copy case files
    print("Restoring...")
    files = manifest.get("files", [])
    total = len(files)
    for i, entry in enumerate(files, 1):
        rel = entry["path"]
        src = backup_path / rel
        dst = target_dir / rel
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
        progress("Copying files", i, total)
    if total:
        print()

    # Restore verification ledger
    if restore_ledger:
        ledger_src = backup_path / "verification" / f"{case_id}.jsonl"
        if ledger_src.exists():
            try:
                result = subprocess.run(
                    [
                        "sudo",
                        "cp",
                        str(ledger_src),
                        str(VERIFICATION_DIR / f"{case_id}.jsonl"),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    print("  Verification ledger... restored (sudo)")
                else:
                    print(
                        f"  Verification ledger... FAILED (sudo)\n"
                        f"  Manual: sudo cp {ledger_src} "
                        f"{VERIFICATION_DIR / f'{case_id}.jsonl'}",
                        file=sys.stderr,
                    )
                    restore_ledger = False
            except Exception as e:
                print(f"  Verification ledger... FAILED: {e}", file=sys.stderr)
                restore_ledger = False

    # Restore password hashes
    pw_restored: list[str] = []
    if not skip_ledger:
        pw_dir = backup_path / "passwords"
        if pw_dir.is_dir():
            for pw_file in pw_dir.glob("*.json"):
                examiner_name = pw_file.stem
                try:
                    result = subprocess.run(
                        [
                            "sudo",
                            "cp",
                            str(pw_file),
                            str(_PASSWORDS_DIR / pw_file.name),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        pw_restored.append(examiner_name)
                    else:
                        print(
                            f"  Password hash ({examiner_name})... FAILED (sudo)\n"
                            f"  Manual: sudo cp {pw_file} "
                            f"{_PASSWORDS_DIR / pw_file.name}",
                            file=sys.stderr,
                        )
                except Exception as e:
                    print(
                        f"  Password hash ({examiner_name})... FAILED: {e}",
                        file=sys.stderr,
                    )
            if pw_restored:
                print(f"  Password hashes... restored ({', '.join(pw_restored)})")

    # Password verification (TTY only)
    current_examiner = identity.get("examiner", "")
    if pw_restored and current_examiner in pw_restored and sys.stdin.isatty():
        _verify_restored_password(current_examiner)

    # Restore OpenSearch indices
    os_restored = False
    if restore_opensearch:
        snapshot_dir = backup_path / "opensearch-snapshot"
        if snapshot_dir.is_dir():
            try:
                _restore_opensearch_snapshot(case_id, snapshot_dir, progress)
                os_restored = True
            except Exception as e:
                print(f"  OpenSearch restore... FAILED: {e}", file=sys.stderr)
                print("  Re-ingest from evidence if needed.")

    # Verify restored files
    ok_count = 0
    mismatch_count = 0
    missing_count = 0
    for i, entry in enumerate(files, 1):
        rel = entry["path"]
        expected = entry["sha256"]
        fpath = target_dir / rel
        if not fpath.exists():
            missing_count += 1
        elif sha256_file(fpath) != expected:
            mismatch_count += 1
        else:
            ok_count += 1
        progress("Verifying", i, total)
    if total:
        print()

    # Remove restore marker
    try:
        restore_marker.unlink()
    except OSError:
        pass

    # Summary
    print(f"\nRestored case {case_id} to {target_dir}")
    print(f"  Files: {ok_count} verified", end="")
    if mismatch_count:
        print(f", {mismatch_count} MISMATCH", end="")
    if missing_count:
        print(f", {missing_count} MISSING", end="")
    print()
    if os_restored:
        snap = manifest.get("opensearch_snapshot", {})
        print(
            f"  OpenSearch: {snap.get('index_count', 0)} indices, "
            f"{snap.get('total_docs', 0):,} docs"
        )
    elif manifest.get("includes_opensearch"):
        print("  OpenSearch: not restored (skipped or failed)")
    else:
        print("  OpenSearch: not included in backup")
    if restore_ledger:
        print("  Ledger: restored")
    elif skip_ledger:
        print("  Ledger: skipped")
    else:
        print("  Ledger: not included in backup")

    print()
    print("=" * 64)
    print("CASE IS NOT ACTIVE. You must activate it before use:")
    print()
    print(f"  vhir case activate {case_id}")
    print()
    print("If using Claude Code, launch from the case directory:")
    print()
    print(f"  cd {target_dir} && claude")
    print("=" * 64)


def _verify_restored_password(examiner: str) -> None:
    """Prompt for password and verify against restored hash."""
    import getpass

    try:
        from vhir_cli.approval_auth import verify_password

        print(f"\nVerification ledger restored for examiner '{examiner}'.")
        while True:
            pw = getpass.getpass(
                "Enter the examiner password used when findings were approved: "
            )
            if verify_password(examiner, pw):
                print("Password correct. HMAC verification will work.")
                return
            print(
                "\nPassword does not match. HMAC verification will fail "
                f"for {examiner}'s findings."
            )
            print("  r -- Re-enter password (try again)")
            print("  s -- Skip -- proceed without working HMAC verification")
            choice = input("Choice [r/s]: ").strip().lower()
            if choice != "r":
                print(
                    f"\nWARNING: Findings by '{examiner}' will not pass "
                    "HMAC verification. Run 'vhir config --setup-password' "
                    "to set a new password if the original is lost."
                )
                return
    except (ImportError, Exception):
        pass  # approval_auth not available — skip verification


def _restore_opensearch_snapshot(
    case_id: str, snapshot_dir: Path, progress_fn=None
) -> None:
    """Restore OpenSearch indices from a snapshot directory."""

    from opensearch_mcp.client import get_client
    from opensearch_mcp.paths import sanitize_index_component

    client = get_client()
    safe_id = sanitize_index_component(case_id)
    repo_name = f"vhir-backup-{safe_id}"
    staging = _SNAPSHOTS_DIR / repo_name

    lock_path = _SNAPSHOTS_DIR / ".backup.lock"
    _SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)
    _acquire_lock(lock_path)

    try:
        # Copy snapshot to staging
        if staging.exists():
            shutil.rmtree(staging)
        if progress_fn:
            progress_fn("Copying snapshot to staging", 0, 1)
        shutil.copytree(str(snapshot_dir), str(staging))

        # Register repo
        container_path = f"/usr/share/opensearch/snapshots/{repo_name}"
        client.snapshot.create_repository(
            repository=repo_name,
            body={"type": "fs", "settings": {"location": container_path}},
        )

        # Restore — wait_for_completion=True ensures all shards are fully
        # recovered before we deregister the repo and clean staging.
        # number_of_replicas=0 prevents RED status on single-node clusters.
        if progress_fn:
            progress_fn("Restoring OpenSearch indices", 0, 1)
        client.snapshot.restore(
            repository=repo_name,
            snapshot="snap",
            body={
                "indices": f"case-{safe_id}-*",
                "include_global_state": False,
                "index_settings": {"index.number_of_replicas": 0},
            },
            wait_for_completion=True,
        )

        print("  OpenSearch indices... restored")
    finally:
        # Cleanup
        try:
            client.snapshot.delete_repository(repository=repo_name)
        except Exception:
            pass
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        _release_lock(lock_path)
