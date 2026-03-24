"""Back up case data for archival, legal preservation, and disaster recovery.

Creates timestamped backup with SHA-256 manifest for integrity verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.case_io import get_case_dir, load_case_meta
from vhir_cli.verification import VERIFICATION_DIR

_SKIP_NAMES = {"__pycache__", ".DS_Store", "examiners.bak"}


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

    # Interactive prompts (only when TTY and no flags)
    if not include_all and sys.stdin.isatty():
        scan = scan_case_dir(case_dir)
        case_data_size = sum(s for _, _, s in scan["case_data"])
        evidence_size = sum(s for _, _, s in scan["evidence"])
        extractions_size = sum(s for _, _, s in scan["extractions"])

        print(f"Case data: {human_size(case_data_size)}")
        if scan["evidence"] and not include_evidence:
            print(
                f"Evidence: {human_size(evidence_size)} ({len(scan['evidence'])} files)"
            )
            resp = input("Include evidence files? [y/N] ").strip().lower()
            include_evidence = resp in ("y", "yes")
        if scan["extractions"] and not include_extractions:
            print(
                f"Extractions: {human_size(extractions_size)} ({len(scan['extractions'])} files)"
            )
            resp = input("Include extraction files? [y/N] ").strip().lower()
            include_extractions = resp in ("y", "yes")
    elif include_all:
        scan = scan_case_dir(case_dir)
        total = sum(
            s
            for cat in ("case_data", "evidence", "extractions")
            for _, _, s in scan[cat]
        )
        print(f"Total backup size: {human_size(total)}")

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

    # Trailing newline after progress output
    print()

    print(f"Backup complete: {result['backup_path']}")
    print(f"  Files: {result['file_count']}")
    print(f"  Size:  {human_size(result['total_bytes'])}")


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
        purpose: Why the backup is being made (stored in manifest).
        progress_fn: Optional callback(label, i, total) for progress.

    Returns:
        Dict with backup_path, file_count, total_bytes, manifest,
        symlinks, includes_verification_ledger, ledger_note.

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

    # Copy files
    total_files = len(files_to_copy)
    for i, (rel_path, abs_path, _size) in enumerate(files_to_copy, 1):
        dst = backup_dir / rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(str(abs_path), str(dst))
        if progress_fn:
            progress_fn("Copying", i, total_files)

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
        "notes": ["approvals.jsonl is an archival copy, not used for verification"],
        "files": manifest_files,
        "total_bytes": total_bytes,
        "file_count": len(manifest_files),
    }
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
