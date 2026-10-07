"""Back up and restore case data for archival, legal preservation, and disaster recovery.

Creates timestamped backup with SHA-256 manifest for integrity verification.
Restore asks where to restore, offering the folder the case was backed up
from; without a terminal, --target names it.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.case_io import (
    _EXAMINER_RE,
    CaseError,
    _validate_case_id,
    get_case_dir,
    load_case_meta,
)
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
            skip_unreadable=getattr(args, "skip_unreadable", False),
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
    _print_skipped(result["skipped"])

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
    case_dir: Path, destination: str, examiner: str, **kwargs
) -> dict:
    """Create a case backup (see _create_backup_data), holding the case lock
    shared: ingest and enrichment may run alongside, a host operation may not."""
    with _shared_case_lock(case_dir):
        return _create_backup_data(case_dir, destination, examiner, **kwargs)


def _create_backup_data(
    case_dir: Path,
    destination: str,
    examiner: str,
    *,
    include_evidence: bool = False,
    include_extractions: bool = False,
    include_opensearch: bool = False,
    purpose: str = "",
    progress_fn=None,
    skip_unreadable: bool = False,
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
        skip_unreadable: Leave out what can't be read or followed, and list
            it in the manifest, instead of stopping.

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

    # Build under an ".incomplete" name; only a finished backup takes the
    # case-date name, so a failed or interrupted one can't pass for a backup.
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    backup_name = f"{case_id}-{date_str}"
    backup_dir = _reserve_dir(dest, f"{backup_name}.incomplete")

    # Write in-progress marker
    marker = backup_dir / ".backup-in-progress"
    marker.touch()

    # Scan case directory
    scan = scan_case_dir(case_dir)
    # What the scan couldn't read or follow stops the backup before anything
    # is copied, unless it is in a part of the case this backup leaves out;
    # skip_unreadable leaves it out and lists it in the manifest instead.
    problems = []
    for err in scan["unreadable"]:
        top = Path(err.filename).relative_to(case_dir).parts[:1]
        evidence = (
            top == ("evidence",) or os.path.realpath(err.filename) in scan["registered"]
        )
        if evidence and not include_evidence:
            continue
        if not evidence and top == ("extractions",) and not include_extractions:
            continue
        problems.append(err)
    # A registered file that is there but the scan didn't reach (behind a
    # link or folder it wouldn't follow) is a problem too, wherever that is.
    if include_evidence:
        reached = {os.path.realpath(a) for _r, a, _s in scan["evidence"]}
        reached |= {os.path.realpath(e.filename) for e in problems}
        problems += [
            FileNotFoundError(
                errno.ENOENT,
                "registered evidence the backup can't reach (behind a link it "
                "won't follow; link the storage at the top of the case or of "
                "evidence/)",
                r,
            )
            for r in scan["registered"] - reached
            if os.path.isfile(r)
        ]
    problems.sort(key=lambda e: e.filename)
    if problems and not skip_unreadable:
        raise OSError(
            f"Backup stopped before copying: {len(problems)} path(s) can't be "
            "backed up as they are. Fix them and run the backup again, or run "
            "it again with --skip-unreadable (MCP backup_case: "
            "skip_unreadable=true) to leave them out; the backup's manifest "
            "then lists each one as skipped.\n"
            + "\n".join(f"  {e.filename}: {_reason(e)}" for e in problems)
        )
    skipped = [
        {"path": os.path.relpath(e.filename, case_dir), "reason": _reason(e)}
        for e in problems
    ]

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
                # Only well-formed examiner names: "./steve" or "../x" would
                # alias a control path or read outside the password store.
                examiners_in_case = {
                    f.get("created_by")
                    for f in findings
                    if isinstance(f.get("created_by"), str)
                    and _EXAMINER_RE.match(f["created_by"])
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
    # A case file at a control path this backup just wrote (e.g. a copy left
    # in the case dir by an older restore) must not replace the live copy.
    written = {f"passwords/{ex}.json" for ex in password_examiners}
    if ledger_included:
        written.add(f"verification/{case_id}.jsonl")
    for i, (rel_path, abs_path, _size) in enumerate(files_to_copy, 1):
        if rel_path in written:
            continue
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
                case_id, backup_dir, progress_fn, case_dir=case_dir
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
    if skipped:
        manifest["skipped"] = skipped

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
    final = _reserve_dir(dest, backup_name)
    os.rename(backup_dir, final)  # replaces the empty directory just reserved
    backup_dir = final

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
        "skipped": skipped,
    }


def _reason(err: OSError) -> str:
    """Why a path can't be backed up, in words."""
    if err.errno == errno.ENOENT and os.path.islink(err.filename):
        return "broken symlink (its target is missing)"
    if err.errno == errno.ELOOP:
        return "symlink loop"
    return err.strerror


def _print_skipped(skipped) -> None:
    """List the paths left out when the backup was made (in its manifest)."""
    if skipped:
        print(f"  Skipped when backed up: {len(skipped)} path(s), not in the backup:")
        for s in skipped:
            print(f"    SKIPPED: {s.get('path')} ({s.get('reason')})")


def _reserve_dir(dest: Path, name: str) -> Path:
    """Create dest/name, or name-1, name-2, ... (atomic mkdir avoids TOCTOU)."""
    path, suffix = dest / name, 0
    while True:
        try:
            path.mkdir(parents=True, exist_ok=False)
            return path
        except FileExistsError:
            suffix += 1
            path = dest / f"{name}-{suffix}"


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

    _print_skipped(manifest.get("skipped"))
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


def _registered_paths(case_dir: Path) -> set[str]:
    """Resolved paths of the case's registered evidence (evidence.json);
    a relative entry is relative to the case directory."""
    registry = case_dir / "evidence.json"
    if not registry.exists():
        return set()
    try:
        files = json.loads(registry.read_text()).get("files", [])
    except (OSError, ValueError, AttributeError) as e:
        print(
            f"Warning: can't read {registry} ({e}); registered evidence outside "
            "evidence/ can't be excluded, so this backup may include it.",
            file=sys.stderr,
        )
        return set()
    paths = set()
    for f in files if isinstance(files, list) else []:
        p = f.get("path") if isinstance(f, dict) else None
        if isinstance(p, str) and p:
            try:
                paths.add(str((case_dir / p).resolve()))  # an absolute p stands
            except (OSError, RuntimeError, ValueError):  # ValueError: a NUL in p
                continue
    return paths


def scan_case_dir(case_dir: Path) -> dict:
    """Scan case directory and categorize files.

    Returns dict with keys: case_data, evidence, extractions, symlinks,
    unreadable (the OSError for each entry the walk could not list, stat,
    read or follow), registered.
    Each list contains (relative_path, absolute_path, size) tuples.
    """
    case_data = []
    evidence = []
    extractions = []
    symlinks = []
    unreadable: list[OSError] = []
    # Registered evidence is evidence wherever it sits (the case root, work/).
    registered = _registered_paths(case_dir)
    # A symlink may lead out of the case only where the examiner links storage
    # in: at the top of the case or of evidence/, or as registered evidence.
    # Any other link must stay inside the case or the storage linked in on its
    # own path; one in extracted evidence (etc/hostname -> /etc/hostname) would
    # otherwise copy this machine's file as evidence.
    roots = {os.path.realpath(case_dir), *registered}

    # (st_dev, st_ino) of every directory from case_dir down to the current
    # root, keyed by the path os.walk yields. A directory symlink pointing back
    # at one of them (evidence/ is normally itself a symlink to a collection
    # mount) is re-entered until the kernel's symlink limit bites, so the same
    # subtree gets listed — and copied and hashed — up to 41 times.
    try:
        case_st = case_dir.stat()
        chains = {str(case_dir): ((case_st.st_dev, case_st.st_ino),)}
    except OSError:
        chains = {}

    def _leaves_case(path: Path) -> bool:
        if not os.path.islink(path):  # False, not EACCES, in a dir we can't search
            return False
        real = os.path.realpath(path)
        parts = path.relative_to(case_dir).parts
        depth = 2 if parts[0] == "evidence" else 1
        entries = {case_dir.joinpath(*parts[:i]) for i in range(1, depth + 1)}
        allowed = roots | {os.path.realpath(p) for p in entries}
        if any(os.path.commonpath([real, r]) == r for r in allowed):
            return False
        unreadable.append(
            OSError(errno.EXDEV, f"symlink to {real}, outside the case", str(path))
        )
        return True

    def _loops(path: Path) -> bool:  # a link to its own folder or one above it
        real = os.path.realpath(path)
        if os.path.commonpath([real, os.path.realpath(path.parent)]) != real:
            return False
        unreadable.append(OSError(errno.ELOOP, "symlink loop", str(path)))
        return True

    for root, dirs, files in os.walk(
        case_dir, followlinks=True, onerror=unreadable.append
    ):
        root_path = Path(root)
        # Filter out skip names, links that lead out of the case, and loops
        dirs[:] = [
            d
            for d in dirs
            if d not in _SKIP_NAMES
            and not _leaves_case(root_path / d)
            and not _loops(root_path / d)
        ]

        # Drop subdirectories that loop back onto the path we came in by
        chain = chains.pop(str(root), ())
        kept = []
        for d in dirs:
            sub = os.path.join(str(root), d)
            try:
                sub_st = os.stat(sub)
            except OSError:
                kept.append(d)  # unreadable: os.walk's onerror lists it
                continue
            key = (sub_st.st_dev, sub_st.st_ino)
            if key in chain:
                unreadable.append(OSError(errno.ELOOP, "symlink loop", sub))
                continue
            chains[sub] = chain + (key,)
            kept.append(d)
        dirs[:] = kept

        for fname in files:
            if fname in _SKIP_NAMES:
                continue
            abs_path = root_path / fname
            rel_path = abs_path.relative_to(case_dir)
            if _leaves_case(abs_path):
                continue

            try:
                size = abs_path.stat().st_size
            except OSError as e:  # e.g. a dangling symlink
                unreadable.append(e)
                continue
            if not os.access(abs_path, os.R_OK):
                unreadable.append(
                    PermissionError(errno.EACCES, "Permission denied", str(abs_path))
                )
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

            if (parts and parts[0] == "evidence") or (
                registered and str(abs_path.resolve()) in registered
            ):
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
        "unreadable": unreadable,
        "registered": registered,
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
        pattern = _index_scope(case_dir, case_id)
        try:
            indices = (
                client.cat.indices(index=pattern, format="json") if pattern else []
            )
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


# --- The case's identity and index scope --------------------------------
#
# A case's indices are named from its identity (case_uuid in CASE.yaml),
# `case-<c12>-…`; a case from before 0.7 also has `case-<case id>-…` ones.
# sift-common (the identity, the case lock) and opensearch-mcp (the scope)
# are used when installed, as on a SIFT workstation.


def _host_identity():
    """sift-common's host_identity, or None without it (or an older one)."""
    import importlib.util

    if importlib.util.find_spec("sift_common") is None:
        return None
    try:
        from sift_common import host_identity
    except ImportError:
        return None
    return host_identity if hasattr(host_identity, "update_case_meta") else None


@contextlib.contextmanager
def _shared_case_lock(case_dir: Path):
    module = _host_identity()
    with contextlib.ExitStack() as stack:
        # Only a case that has the lock file: taking the lock would otherwise
        # create the case's host files, and a backup changes nothing in it
        if module is not None and (case_dir / module.CASE_LOCK).is_file():
            try:
                stack.enter_context(module.case_lock(case_dir, shared=True))
            except module.CaseLockBusy as e:
                raise OSError(
                    f"Backup not started: a host operation is running on this case "
                    f"({e}). Try again when it has finished."
                ) from None
        yield


def _case_uuid(case_dir: Path) -> str:
    raw = str(load_case_meta(case_dir).get("case_uuid") or "").strip().lower()
    return raw if len(raw.replace("-", "")) == 32 else ""


def _index_scope(case_dir: Path, case_id: str) -> str:
    """The index expression of the case's indices: `case-<c12>-*`, plus its
    pre-0.7 ones; `case-<case id>-*` with an opensearch-mcp from before case
    identities. "" when it has none."""
    from opensearch_mcp.paths import sanitize_index_component

    try:
        from opensearch_mcp.case_scope import CaseScope, legacy_expression
        from opensearch_mcp.write_context import case_identity
    except ImportError:
        return f"case-{sanitize_index_component(case_id)}-*"
    c12, version = case_identity(case_dir)
    scope = CaseScope(
        case_id=case_dir.name,
        case_dir=case_dir,
        c12=c12,
        naming_version=version,
        legacy_id=case_id,
    )
    parts = [f"{scope.prefix}*"] if c12 else []
    old = legacy_expression(scope)
    if old:
        parts.append(old)
    return ",".join(parts)


def _create_opensearch_snapshot(
    case_id: str, backup_dir: Path, progress_fn=None, case_dir: Path | None = None
) -> dict:
    """Create OpenSearch snapshot for a case's indices. Local Docker only."""
    import time

    from opensearch_mcp.client import get_client
    from opensearch_mcp.paths import sanitize_index_component

    client = get_client()
    safe_id = sanitize_index_component(case_id)
    repo_name = f"vhir-backup-{safe_id}"
    pattern = _index_scope(case_dir, case_id) if case_dir else f"case-{safe_id}-*"
    if not pattern:
        raise RuntimeError("the case has no indices to snapshot")
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
            # What restore needs to bring the indices back under this case,
            # or rename them for a copy restored beside it
            "index_scope": pattern,
            "case_uuid": _case_uuid(case_dir) if case_dir else "",
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


def _stays_inside(rel) -> bool:
    """True for a relative path that names something inside its folder:
    no absolute path, no `..` component (a `..` inside a name is fine)."""
    if not isinstance(rel, str) or not rel:
        return False
    parts = Path(rel).parts
    return (
        not Path(rel).is_absolute()
        and ".." not in parts
        and os.path.normpath(rel) not in (".", "")
    )


def _repoint_evidence(target_dir: Path, source: str) -> tuple[int, list[str]] | None:
    """Point evidence.json entries under the backed-up case at the restored copy.

    Registration stores absolute paths, so after a restore elsewhere they still
    name the original's files. An entry under the recorded source, or under
    its real path, gets the same relative path under the restored folder;
    entries elsewhere (evidence linked in from outside) are kept and listed.
    Returns (entries re-pointed, entries left outside the case), or None when
    the registry can't be read, in which case it's left untouched.
    """
    reg = target_dir / "evidence.json"
    if not reg.exists():
        return 0, []
    try:
        data = json.loads(reg.read_text())
        files = data["files"]
        if not isinstance(files, list):
            raise TypeError("files is not a list")
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"  Note: evidence.json can't be read ({e}); it was left as it is.")
        return None
    new_root = target_dir.resolve()
    roots = [Path(os.path.abspath(source)), Path(os.path.realpath(source))]
    moved, outside = 0, []
    for entry in files:
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str):
            continue
        for root in roots:
            try:
                rel = Path(path).relative_to(root)  # by component, not by prefix
            except ValueError:
                continue
            entry["path"] = str(new_root / rel)
            moved += entry["path"] != path
            break
        else:
            try:
                Path(path).relative_to(new_root)
            except ValueError:
                outside.append(path)
    if moved:
        from vhir_cli.case_io import _atomic_write

        mode = reg.stat().st_mode & 0o777
        _atomic_write(reg, json.dumps(data, indent=2, default=str))
        os.chmod(reg, mode)
    return moved, outside


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

    # The manifest is data from the backup folder: check what it names before
    # anything is created, prompted for or removed.
    try:
        _validate_case_id(case_id)
    except CaseError as e:
        print(f"Error: the backup's case_id can't be used: {e}", file=sys.stderr)
        sys.exit(1)
    for entry in manifest.get("files", []):
        rel = entry.get("path") if isinstance(entry, dict) else None
        if not _stays_inside(rel):
            print(
                f"Error: the backup lists a file outside the case folder: {rel!r}. "
                "Nothing was restored.",
                file=sys.stderr,
            )
            sys.exit(1)

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

    # Where to restore: the examiner says so, defaulting to where it came from
    target = getattr(args, "target", None)
    if target:
        target_dir = Path(target).expanduser()
    elif sys.stdin.isatty():
        answer = input(f"Restore case {case_id} to [{source_path}]: ").strip()
        target_dir = Path(answer).expanduser() if answer else Path(source_path)
    else:
        print(
            f"Error: no terminal to confirm where to restore case {case_id}.\n"
            f"  It was backed up from {source_path}.\n"
            f"  Re-run with --target <folder>, e.g. --target {source_path}",
            file=sys.stderr,
        )
        sys.exit(1)
    cases_parent = target_dir.parent

    # Interactive prompts
    restore_opensearch = (
        not skip_opensearch
        and manifest.get("includes_opensearch")
        and (backup_path / "opensearch-snapshot").is_dir()
    )
    restore_ledger = not skip_ledger and manifest.get("includes_verification_ledger")
    ledger_declined = False

    if sys.stdin.isatty():
        if restore_opensearch:
            resp = input("Restore OpenSearch indices? [Y/n] ").strip().lower()
            if resp in ("n", "no"):
                restore_opensearch = False
        if restore_ledger:
            resp = input("Restore verification ledger? [Y/n] ").strip().lower()
            if resp in ("n", "no"):
                restore_ledger = False
                ledger_declined = True

    # Restored to another folder (--target), the copy gets its own identity
    # and its indices are renamed into it; restored in its own place, it
    # keeps both, and its indices must not still exist. Checked before
    # anything is written or removed.
    snap_info = manifest.get("opensearch_snapshot") or {}
    alongside = target_dir.resolve() != Path(source_path).resolve()
    if restore_opensearch:
        problem = _snapshot_identity_problem(snap_info, backup_path)
        if problem:
            print(
                f"Error: {problem}. The snapshot's indices weren't restored and "
                "nothing was written.\nUse --skip-opensearch to restore the case "
                "files alone.",
                file=sys.stderr,
            )
            sys.exit(1)
    snap_info = {**snap_info, "case_uuid": _snapshot_uuid(snap_info) or ""}
    if restore_opensearch and _is_opensearch_available():
        from opensearch_mcp.client import get_client

        # In its own place, none of the case's indices may still exist; a
        # listing that fails refuses too
        if not alongside:
            try:
                prefixes = _own_prefixes(snap_info["case_uuid"], case_id)
                listed = get_client().cat.indices(index=prefixes, format="json")
                new, old = _own_indices(
                    [row["index"] for row in listed or []],
                    snap_info["case_uuid"],
                    case_id,
                    target_dir,
                )
            except Exception as e:
                print(
                    f"Error: couldn't check whether case {case_id}'s OpenSearch indices "
                    f"still exist ({e}); nothing was written.\n"
                    "Use --skip-opensearch to restore the case files alone.",
                    file=sys.stderr,
                )
                sys.exit(1)
            if new or old:
                print(
                    f"Error: OpenSearch indices of case {case_id} still exist "
                    f"({', '.join((new + old)[:5])}"
                    f"{', …' if len(new + old) > 5 else ''}).\n"
                    "Restore it as a copy beside them with --target <another folder>, "
                    "delete them first, or use --skip-opensearch.",
                    file=sys.stderr,
                )
                sys.exit(1)

        # Version check
        backup_version = snap_info.get("opensearch_version", "")
        if backup_version:
            try:
                info = get_client().info()
                current_version = info.get("version", {}).get("number", "")
            except Exception:
                current_version = ""
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
    if alongside and restore_opensearch and _host_identity() is None:
        print(
            "Error: this restore is beside the case it was backed up from, so its "
            "indices must be renamed into a new case identity, which needs the "
            "SIFT workstation's sift-common.\n"
            "Restore in the case's own place, or use --skip-opensearch.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Conflict checks
    if target_dir.exists():
        # Check for .restore-in-progress marker
        if (target_dir / ".restore-in-progress").exists():
            # Never removed without the examiner's yes, which defaults to no
            count = sum(len(files) for _r, _d, files in os.walk(target_dir))
            if sys.stdin.isatty():
                resp = (
                    input(
                        f"A previous restore was interrupted: {target_dir} holds "
                        f"{count} file(s). Delete it and restore again? [y/N] "
                    )
                    .strip()
                    .lower()
                )
                if resp in ("y", "yes"):
                    shutil.rmtree(target_dir)
                else:
                    print("Restore cancelled; nothing was changed.", file=sys.stderr)
                    sys.exit(1)
            else:
                print(
                    f"Error: A previous restore was interrupted: {target_dir} "
                    f"({count} file(s), marked .restore-in-progress).\n"
                    f"Remove it first, then re-run restore.",
                    file=sys.stderr,
                )
                sys.exit(1)
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
            f"Then re-run: vhir restore {backup_path} --target {target_dir}",
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
    # The declared ledger, hashes and snapshot stay out of the case directory
    # (hash material is kept from the LLM); they're installed or used from
    # the backup.
    pw_names = manifest.get("password_examiners") or []
    control = {f"passwords/{ex}.json" for ex in pw_names}
    if manifest.get("includes_verification_ledger"):
        control.add(f"verification/{case_id}.jsonl")

    def _is_control(rel: str) -> bool:
        return rel in control or (
            bool(manifest.get("includes_opensearch"))
            and rel.startswith("opensearch-snapshot/")
        )

    for i, entry in enumerate(files, 1):
        rel = entry["path"]
        src = backup_path / rel
        dst = target_dir / rel
        if src.exists() and not _is_control(rel):
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
                    # Fix ownership — sudo cp creates root-owned files
                    import getpass

                    user = getpass.getuser()
                    ledger_dest = VERIFICATION_DIR / f"{case_id}.jsonl"
                    subprocess.run(
                        ["sudo", "chown", f"{user}:{user}", str(ledger_dest)],
                        capture_output=True,
                        timeout=10,
                    )
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
                if examiner_name not in pw_names:
                    continue  # only the hashes the backup declared
                # Never replace a different (or unreadable) hash on this box:
                # the examiner may have changed their password since the backup.
                current = _PASSWORDS_DIR / pw_file.name
                why = ""
                try:
                    if (
                        current.exists()
                        and current.read_bytes() != pw_file.read_bytes()
                    ):
                        why = "kept the existing, different hash"
                except OSError as e:
                    why = f"couldn't check for an existing hash ({e})"
                if why:
                    print(
                        f"  Password hash ({examiner_name})... {why}; "
                        f"the backup's copy was not installed ({pw_file})",
                        file=sys.stderr,
                    )
                    continue
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
                        # Fix ownership — sudo cp creates root-owned files
                        import getpass

                        user = getpass.getuser()
                        subprocess.run(
                            [
                                "sudo",
                                "chown",
                                f"{user}:{user}",
                                str(_PASSWORDS_DIR / pw_file.name),
                            ],
                            capture_output=True,
                            timeout=10,
                        )
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

    # Verify restored files
    ok_count = 0
    mismatch_count = 0
    missing_count = 0
    for i, entry in enumerate(files, 1):
        rel = entry["path"]
        expected = entry["sha256"]
        fpath = (backup_path if _is_control(rel) else target_dir) / rel
        if not fpath.exists():
            print(f"  MISSING: {rel}")
            missing_count += 1
        elif sha256_file(fpath) != expected:
            print(f"  MISMATCH: {rel}")
            mismatch_count += 1
        else:
            ok_count += 1
        progress("Verifying", i, total)
    if total:
        print()

    integrity_ok = not (mismatch_count or missing_count)

    # A copy beside the original gets its own identity before its indices
    # are restored under it
    # (after the copied files are verified: it changes CASE.yaml and the
    # host log, as the evidence re-pointing below changes evidence.json)
    rename = None
    if alongside and integrity_ok:
        rename = _new_identity_for_copy(target_dir, case_id, snap_info)

    # Restore OpenSearch indices
    os_restored = False
    # A copy beside the original restores its indices only under its own
    # identity, never under the original's names
    if restore_opensearch and (not alongside or rename is not None):
        snapshot_dir = backup_path / "opensearch-snapshot"
        if snapshot_dir.is_dir():
            try:
                _restore_opensearch_snapshot(
                    case_id,
                    snapshot_dir,
                    progress,
                    case_uuid=snap_info["case_uuid"],
                    target=target_dir,
                    rename=rename,
                )
                os_restored = True
            except Exception as e:
                print(f"  OpenSearch restore... FAILED: {e}", file=sys.stderr)
                print("  Re-ingest from evidence if needed.")

    # Evidence registered in the backed-up case is re-pointed at the restored
    # copy, so verify checks these files. Before the marker goes: a failed
    # write leaves the restore flagged.
    if integrity_ok and target_dir.resolve() != Path(os.path.realpath(source_path)):
        try:
            repointed = _repoint_evidence(target_dir, source_path)
        except OSError as e:
            print(
                f"Error: evidence.json could not be updated for {target_dir}: {e}\n"
                f"  {target_dir} is marked .restore-in-progress — do not use it.",
                file=sys.stderr,
            )
            sys.exit(1)
        if repointed:
            moved, outside = repointed
            if moved:
                print(f"  Evidence: {moved} registry path(s) now point to {target_dir}")
            if outside:
                print("  Evidence still registered outside the restored case:")
                for path in outside:
                    print(f"    {path}")

    # Remove restore marker — only once every file verified, so a bad restore
    # stays flagged, and a re-run asks before removing it.
    if integrity_ok:
        try:
            restore_marker.unlink()
        except OSError:
            pass

    # Summary
    if integrity_ok:
        print(f"\nRestored case {case_id} to {target_dir}")
    else:
        print(f"\nRestore of case {case_id} to {target_dir} FAILED verification")
    print(f"  Files: {ok_count} verified", end="")
    if mismatch_count:
        print(f", {mismatch_count} MISMATCH", end="")
    if missing_count:
        print(f", {missing_count} MISSING", end="")
    print()
    _print_skipped(manifest.get("skipped"))

    if not integrity_ok:
        print(
            f"\nError: Restored case does not match the backup manifest.\n"
            f"  {target_dir} is marked .restore-in-progress — do not use it.\n"
            f"  Verify the backup first: vhir backup --verify {backup_path}",
            file=sys.stderr,
        )
        sys.exit(1)

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
    elif skip_ledger or ledger_declined:
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

        config_path = Path.home() / ".vhir" / "config.yaml"
        print(f"\nVerification ledger restored for examiner '{examiner}'.")
        while True:
            pw = getpass.getpass(
                "Enter the examiner password used when findings were approved: "
            )
            if verify_password(config_path, examiner, pw):
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
    except ImportError:
        pass  # approval_auth not available — skip verification
    except Exception as e:
        print(f"  Password verification... FAILED: {e}", file=sys.stderr)


def _snapshot_uuid(snap_info: dict) -> str | None:
    """The snapshot's case identity in its canonical form: "" when it has
    none (a backup from before case identities), None when it isn't one."""
    import uuid

    hexed = str(snap_info.get("case_uuid") or "").strip().lower().replace("-", "")
    if not hexed:
        return ""
    if not re.fullmatch(r"[0-9a-f]{32}", hexed):
        return None
    return str(uuid.UUID(hex=hexed))


def _snapshot_identity_problem(snap_info: dict, backup_path: Path) -> str:
    """Why the snapshot's case identity can't be used, or "": it must be a
    UUID, and the backed-up case's. (Its `index_scope` isn't used: the
    restore names the case's own indices itself.)"""
    uuid = _snapshot_uuid(snap_info)
    if uuid is None:
        return f"the snapshot's case identity ({snap_info.get('case_uuid')!r}) isn't a UUID"
    backed_up = _case_uuid(backup_path) if (backup_path / "CASE.yaml").is_file() else ""
    if uuid and backed_up and uuid != _snapshot_uuid({"case_uuid": backed_up}):
        return (
            f"the snapshot's case identity ({uuid}) isn't the backed-up case's "
            f"({backed_up})"
        )
    return ""


def _index_component(value: str) -> str:
    """A case id as it appears in index names (opensearch-mcp's rule)."""
    return re.sub(r"[^a-z0-9._-]", "-", value.lower())


def _own_prefixes(case_uuid: str, case_id: str) -> str:
    """The patterns to list the case's indices by (a listing only: what's
    restored is then picked by name)."""
    parts = [f"case-{case_uuid.replace('-', '')[:12]}-*"] if case_uuid else []
    return ",".join(parts + [f"case-{_index_component(case_id)}-*"])


def _own_indices(
    names, case_uuid: str, case_id: str, target: Path
) -> tuple[list[str], list[str]]:
    """The case's own indices among `names`, by name: its 0.7 ones
    (`case-<c12>-…`, from its identity) and its pre-0.7 ones (`case-<case
    id>-…`, less those of another local case whose id is longer,
    `case-<id>-2-…`). The restore's own folder (`target`) is never one of
    those others, whatever it's called."""
    legacy = f"case-{_index_component(case_id)}-"

    def resolved(path: Path) -> Path | None:
        try:
            return path.resolve()
        except (OSError, RuntimeError):  # a symlink loop (RuntimeError before 3.13)
            return None

    def other_case(d: Path) -> bool:
        try:
            where = resolved(d)
            return where is not None and where != here and (d / "CASE.yaml").is_file()
        except OSError:
            return False

    here = resolved(target) or target.absolute()
    try:
        local = [d for d in target.parent.iterdir() if other_case(d)]
    except OSError:
        local = []
    ids = {d.name for d in local} | {
        str(load_case_meta(d).get("case_id") or d.name) for d in local
    }
    longer = tuple(
        p
        for p in (f"case-{_index_component(i)}-" for i in ids)
        if p != legacy and p.startswith(legacy)
    )
    v2 = f"case-{case_uuid.replace('-', '')[:12]}-" if case_uuid else ""
    new = sorted(n for n in names if v2 and n.startswith(v2))
    old = sorted(
        n
        for n in names
        if n.startswith(legacy)
        and n not in new
        and not (longer and n.startswith(longer))
    )
    return new, old


def _new_identity_for_copy(target_dir: Path, case_id: str, snap_info: dict):
    """Give a case restored beside its original its own identity, with no
    legacy alias (its older indices are renamed into the new identity).
    Returns what the snapshot restore renames from and to, or None without
    sift-common (the copy then keeps the original's identity, and says so)."""
    import uuid

    module = _host_identity()
    old = snap_info.get("case_uuid") or _case_uuid(target_dir)
    if module is None:
        print(
            "  Restored beside the original: this copy still has the original's "
            "identity. Give it its own with `vhir case new-identity` before "
            "using it.",
            file=sys.stderr,
        )
        return None
    if not (target_dir / "CASE.yaml").is_file():
        print(
            "  No OpenSearch indices were restored: the restored folder has no "
            "CASE.yaml, so there's no case identity to restore them under.",
            file=sys.stderr,
        )
        return None
    new = str(uuid.uuid4())
    c12 = new.replace("-", "")[:12]
    try:
        module.update_case_meta(target_dir, {"case_uuid": new, "legacy_alias": "none"})
        module.write_case_header(
            target_dir,
            c12,
            f"restored beside the case it was backed up from ({old or case_id})",
            case_uuid=new,
        )
    except (OSError, module.HostLogError) as e:
        print(
            f"  Restored beside the original, but this copy couldn't be given its "
            f"own identity ({e}). Run `vhir case new-identity` before using it.",
            file=sys.stderr,
        )
        return None
    print(f"  Restored beside the original: this copy has its own identity, {new}.")
    try:
        from opensearch_mcp.paths import sanitize_index_component
    except ImportError:  # no OpenSearch here: nothing to rename
        return None
    return {
        "old_c12": old.replace("-", "")[:12] if old else "",
        "legacy_prefix": f"case-{sanitize_index_component(case_id)}-",
        "new_c12": c12,
    }


def _template_aliases(client, prefix: str) -> list[dict]:
    """The alias actions each restored index's own index template gives it
    (restored with include_aliases false, so a legacy or other case's alias
    can't come with them)."""
    actions = []
    for index in sorted(client.indices.get(index=f"{prefix}*") or {}):
        template = client.indices.simulate_index_template(name=index) or {}
        aliases = (template.get("template") or {}).get("aliases") or {}
        for alias, options in sorted(aliases.items()):
            actions.append({"add": {"index": index, "alias": alias, **(options or {})}})
    return actions


def _restore_opensearch_snapshot(
    case_id: str,
    snapshot_dir: Path,
    progress_fn=None,
    case_uuid: str = "",
    target: Path | None = None,
    rename: dict | None = None,
) -> None:
    """Restore the case's own indices from a snapshot directory, each named
    (never by pattern): under their own names in the case's place, or renamed
    into the copy's identity (`rename`)."""

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
        # Copy snapshot to staging (use sudo — staging dir is owned by UID 1000)
        if staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(staging)],
                capture_output=True,
                timeout=60,
            )
        if progress_fn:
            progress_fn("Copying snapshot to staging", 0, 1)
        subprocess.run(
            ["sudo", "cp", "-r", str(snapshot_dir), str(staging)],
            capture_output=True,
            timeout=600,
            check=True,
        )
        subprocess.run(
            ["sudo", "chown", "-R", "1000:1000", str(staging)],
            capture_output=True,
            timeout=30,
        )

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
        common = {
            "include_global_state": False,
            "index_settings": {"index.number_of_replicas": 0},
        }
        held = client.snapshot.get(repository=repo_name, snapshot="snap")
        names = [
            n for snap in held.get("snapshots") or [] for n in snap.get("indices") or []
        ]
        current, legacy = _own_indices(
            names, case_uuid, case_id, target or _SNAPSHOTS_DIR / case_id
        )
        if not current and not legacy:
            print(f"  OpenSearch indices... none of case {case_id}'s in the snapshot")
            return
        if rename is None:
            client.snapshot.restore(
                repository=repo_name,
                snapshot="snap",
                body={"indices": ",".join(current + legacy), **common},
                wait_for_completion=True,
            )
        else:
            new = f"case-{rename['new_c12']}-"
            renames = []
            if current and rename["old_c12"]:  # 0.7 indices: the new identity
                old = f"case-{rename['old_c12']}-"
                renames.append((",".join(current), f"{re.escape(old)}(.+)", f"{new}$1"))
            # pre-0.7 indices, kept apart under v1-
            if legacy:
                # case-<id>-<type>-<host> -> case-<new>-<type>-v1-<host>:
                # typed reads (case-<c12>-<type>-*) find them, and they stay
                # apart from the 0.7 indices (case-<c12>-<type>-0)
                renames.append(
                    (
                        ",".join(legacy),
                        f"{re.escape(rename['legacy_prefix'])}(.+)-([^-]+)",
                        f"{new}$1-v1-$2",
                    )
                )
            for indices, pattern, replacement in renames:
                client.snapshot.restore(
                    repository=repo_name,
                    snapshot="snap",
                    body={
                        "indices": indices,
                        "rename_pattern": pattern,
                        "rename_replacement": replacement,
                        "include_aliases": False,
                        "ignore_unavailable": True,
                        **common,
                    },
                    wait_for_completion=True,
                )
            actions = _template_aliases(client, new)
            if actions:
                client.indices.update_aliases(body={"actions": actions})

        print("  OpenSearch indices... restored")
    finally:
        # Cleanup
        try:
            client.snapshot.delete_repository(repository=repo_name)
        except Exception:
            pass
        if staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(staging)],
                capture_output=True,
                timeout=60,
            )
        _release_lock(lock_path)
