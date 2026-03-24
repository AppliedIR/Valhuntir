"""Evidence management commands: lock, unlock, register, list, verify, log.

Subcommand group:
  vhir evidence register <path> [--description]
  vhir evidence list
  vhir evidence verify
  vhir evidence log [--path <filter>]
  vhir evidence lock
  vhir evidence unlock

Legacy aliases (backward compat):
  vhir register-evidence <path>
  vhir lock-evidence
  vhir unlock-evidence
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_tty_confirmation
from vhir_cli.case_io import get_case_dir


def cmd_evidence(args, identity: dict) -> None:
    """Handle evidence subcommands."""
    action = getattr(args, "evidence_action", None)
    if action == "register":
        cmd_register_evidence(args, identity)
    elif action == "list":
        cmd_list_evidence(args, identity)
    elif action == "verify":
        cmd_verify_evidence(args, identity)
    elif action == "log":
        cmd_evidence_log(args, identity)
    elif action == "lock":
        cmd_lock_evidence(args, identity)
    elif action == "unlock":
        cmd_unlock_evidence(args, identity)
    else:
        print(
            "Usage: vhir evidence {register|list|verify|log|lock|unlock}",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_lock_evidence(args, identity: dict) -> None:
    """Lock evidence directory by making all files read-only (chmod 444)."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_dir = case_dir / "evidence"

    if not evidence_dir.exists():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    count = 0
    errors = 0
    for path in evidence_dir.rglob("*"):
        if path.is_file():
            try:
                path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)  # 444
                count += 1
            except OSError as e:
                print(f"  Warning: could not chmod {path}: {e}", file=sys.stderr)
                errors += 1

    # Also make the directory itself read-only
    try:
        evidence_dir.chmod(
            stat.S_IRUSR
            | stat.S_IXUSR
            | stat.S_IRGRP
            | stat.S_IXGRP
            | stat.S_IROTH
            | stat.S_IXOTH
        )  # 555
    except OSError as e:
        print(f"  Warning: could not chmod evidence directory: {e}", file=sys.stderr)
        errors += 1

    _log_evidence_action(case_dir, "lock", f"Locked {count} files", identity)
    print(f"Locked evidence directory: {count} file(s) set to read-only (444)")
    if errors:
        print(f"  {errors} file(s) could not be locked (see warnings above)")
    print("Directory set to 555 (no writes)")


def cmd_unlock_evidence(args, identity: dict) -> None:
    """Unlock evidence directory for new files."""
    case_dir = get_case_dir(getattr(args, "case", None))
    evidence_dir = case_dir / "evidence"

    if not evidence_dir.exists():
        print(f"Evidence directory not found: {evidence_dir}", file=sys.stderr)
        sys.exit(1)

    # Confirm via /dev/tty (blocks AI-via-Bash from piping "y")
    print("WARNING: Unlocking evidence directory allows writes.")
    print(f"  Path: {evidence_dir}")
    if not require_tty_confirmation("Unlock evidence directory? [y/N]: "):
        print("Cancelled.")
        return

    # Restore write permissions on directory
    try:
        evidence_dir.chmod(
            stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
        )  # 755
    except OSError as e:
        print(f"Failed to unlock evidence directory: {e}", file=sys.stderr)
        sys.exit(1)

    _log_evidence_action(case_dir, "unlock", "Unlocked evidence directory", identity)
    print("Evidence directory unlocked (755). Files remain read-only.")
    print("Use 'vhir evidence register <path>' after adding new files.")


def register_evidence_data(
    case_dir, path: str, examiner: str, description: str = ""
) -> dict:
    """Register an evidence file and return structured data.

    Validates path, computes SHA-256, writes registry.

    Args:
        case_dir: Path to the active case directory.
        path: Path to the evidence file.
        examiner: Examiner identity slug.
        description: Optional description.

    Returns:
        Dict with path, sha256, description, registered_at, registered_by.

    Raises:
        FileNotFoundError: If evidence file doesn't exist.
        ValueError: If path is outside the case directory.
        OSError: If registry write fails.
    """
    from vhir_cli.case_io import _atomic_write

    case_dir = Path(case_dir)
    evidence_path = Path(path)

    if not evidence_path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    # Validate path is within case directory
    resolved = evidence_path.resolve()
    case_resolved = case_dir.resolve()
    in_case = (
        str(resolved).startswith(str(case_resolved) + os.sep)
        or resolved == case_resolved
    )
    if not in_case:
        # Resolved path is outside — check unresolved (symlink in case dir)
        evidence_path_abs = (
            evidence_path if evidence_path.is_absolute() else case_dir / evidence_path
        )
        normalized = Path(os.path.normpath(evidence_path_abs))
        case_norm = Path(os.path.normpath(case_resolved))
        if not (
            str(normalized).startswith(str(case_norm) + os.sep)
            or normalized == case_norm
        ):
            raise ValueError(
                f"Evidence path must be within the case directory.\n"
                f"  Evidence file:     {evidence_path}\n"
                f"  Resolved to:       {resolved}\n"
                f"  Case evidence dir: {case_dir / 'evidence'}"
            )

    # Compute SHA256
    sha = hashlib.sha256()
    with open(evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    file_hash = sha.hexdigest()

    # Record in evidence registry
    reg_file = case_dir / "evidence.json"
    try:
        if reg_file.exists():
            registry = json.loads(reg_file.read_text())
        else:
            registry = {"files": []}
    except (json.JSONDecodeError, OSError):
        registry = {"files": []}

    # Dedup check — match by resolved path
    for existing in registry.get("files", []):
        if existing.get("path") == str(resolved):
            if existing.get("sha256") == file_hash:
                return {
                    **existing,
                    "note": "already registered (same path and hash)",
                }
            else:
                # Same path, different hash — file changed. Update entry.
                existing["sha256"] = file_hash
                existing["registered_at"] = datetime.now(timezone.utc).isoformat()
                existing["registered_by"] = examiner
                if description:
                    existing["description"] = description
                _atomic_write(
                    reg_file,
                    json.dumps(registry, indent=2, default=str),
                )
                return {
                    **existing,
                    "note": "updated (same path, hash changed)",
                }

    entry = {
        "path": str(resolved),
        "sha256": file_hash,
        "description": description,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "registered_by": examiner,
    }
    registry["files"].append(entry)

    _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))

    return entry


def cmd_register_evidence(args, identity: dict) -> None:
    """CLI wrapper — registers evidence and prints summary."""
    case_dir = get_case_dir(getattr(args, "case", None))

    try:
        data = register_evidence_data(
            case_dir=case_dir,
            path=args.path,
            examiner=identity.get("examiner", identity.get("analyst", "")),
            description=args.description,
        )
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Failed to write evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    # Log access
    _log_evidence_action(
        case_dir, "register", data["path"], identity, sha256=data["sha256"]
    )

    print(f"Registered: {data['path']}")
    print(f"  SHA256: {data['sha256']}")
    print("  Integrity: SHA-256 hash recorded")


def _log_evidence_action(
    case_dir: Path, action: str, detail: str, identity: dict, **extra
) -> None:
    """Write evidence action to access log."""
    try:
        log_file = case_dir / "evidence_access.jsonl"
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "detail": detail,
            "examiner": identity.get("examiner", identity.get("analyst", "")),
            "os_user": identity["os_user"],
        }
        entry.update(extra)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        print(f"WARNING: failed to write evidence access log: {e}", file=sys.stderr)


def list_evidence_data(case_dir) -> dict:
    """Return registered evidence as structured data.

    Args:
        case_dir: Path to the active case directory.

    Returns:
        Dict with "evidence" list and "registry_exists" bool.

    Raises:
        OSError: If registry can't be read.
    """
    case_dir = Path(case_dir)
    reg_file = case_dir / "evidence.json"

    if not reg_file.exists():
        return {"evidence": [], "registry_exists": False}

    registry = json.loads(reg_file.read_text())
    return {"evidence": registry.get("files", []), "registry_exists": True}


def cmd_list_evidence(args, identity: dict) -> None:
    """CLI wrapper — prints formatted evidence list."""
    case_dir = get_case_dir(getattr(args, "case", None))

    try:
        data = list_evidence_data(case_dir)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    if not data["registry_exists"]:
        print("No evidence registry found.")
        return

    files = data["evidence"]
    if not files:
        print("No evidence files registered.")
        return

    print(f"{'#':<4} {'SHA256':<20} {'Registered By':<15} Path")
    print("-" * 80)
    for i, entry in enumerate(files, 1):
        sha = entry.get("sha256", "?")[:16] + "..."
        by = entry.get("registered_by", "?")
        path = entry.get("path", "?")
        print(f"{i:<4} {sha:<20} {by:<15} {path}")
        if entry.get("description"):
            print(f"     Description: {entry['description']}")

    print(f"\n{len(files)} evidence file(s) registered")


def verify_evidence_data(case_dir) -> dict:
    """Verify evidence integrity and return structured results.

    Args:
        case_dir: Path to the active case directory.

    Returns:
        Dict with "results" list and summary counts (verified, modified,
        missing, errors).

    Raises:
        OSError: If registry can't be read.
    """
    case_dir = Path(case_dir)
    reg_file = case_dir / "evidence.json"

    if not reg_file.exists():
        return {"results": [], "verified": 0, "modified": 0, "missing": 0, "errors": 0}

    registry = json.loads(reg_file.read_text())
    files = registry.get("files", [])
    if not files:
        return {"results": [], "verified": 0, "modified": 0, "missing": 0, "errors": 0}

    results = []
    verified = modified = missing = errors = 0

    for entry in files:
        path = Path(entry.get("path", ""))
        expected_hash = entry.get("sha256", "")

        if not path.exists():
            results.append(
                {
                    "path": str(path),
                    "status": "MISSING",
                    "expected_hash": expected_hash,
                    "actual_hash": None,
                }
            )
            missing += 1
            continue

        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
            actual_hash = sha.hexdigest()
        except OSError as e:
            results.append(
                {
                    "path": str(path),
                    "status": "ERROR",
                    "expected_hash": expected_hash,
                    "actual_hash": None,
                    "error": str(e),
                }
            )
            errors += 1
            continue

        if actual_hash == expected_hash:
            results.append(
                {
                    "path": str(path),
                    "status": "OK",
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                }
            )
            verified += 1
        else:
            results.append(
                {
                    "path": str(path),
                    "status": "MODIFIED",
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                }
            )
            modified += 1

    return {
        "results": results,
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "errors": errors,
    }


def cmd_verify_evidence(args, identity: dict) -> None:
    """CLI wrapper — prints formatted verification results."""
    case_dir = get_case_dir(getattr(args, "case", None))

    try:
        data = verify_evidence_data(case_dir)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Failed to read evidence registry: {e}", file=sys.stderr)
        sys.exit(1)

    results = data["results"]
    if not results:
        print("No evidence files registered.")
        return

    print(f"{'Status':<12} {'Path'}")
    print("-" * 70)

    for r in results:
        print(f"{r['status']:<12} {r['path']}")
        if r["status"] == "MODIFIED":
            print(f"             Expected: {r['expected_hash']}")
            print(f"             Actual:   {r['actual_hash']}")
        elif r["status"] == "ERROR" and r.get("error"):
            print(f"             Error: {r['error']}")

    print(
        f"\n{data['verified']} verified, {data['modified']} MODIFIED, {data['missing']} missing, {data['errors']} errors"
    )
    if data["modified"]:
        print("ALERT: Evidence files have been modified since registration.")
        sys.exit(2)


def cmd_evidence_log(args, identity: dict) -> None:
    """Show evidence access log entries."""
    case_dir = get_case_dir(getattr(args, "case", None))
    log_file = case_dir / "evidence_access.jsonl"

    if not log_file.exists():
        print("No evidence access log found.")
        return

    path_filter = getattr(args, "path_filter", None)

    try:
        log_text = log_file.read_text()
    except OSError as e:
        print(f"Failed to read evidence access log: {e}", file=sys.stderr)
        sys.exit(1)

    entries = []
    for line in log_text.strip().split("\n"):
        if not line:
            continue
        try:
            entry = json.loads(line)
            entries.append(entry)
        except json.JSONDecodeError:
            continue

    if path_filter:
        entries = [e for e in entries if path_filter in e.get("detail", "")]

    if not entries:
        print("No evidence access log entries found.")
        return

    print(f"{'Timestamp':<22} {'Action':<10} {'Examiner':<12} Detail")
    print("-" * 80)
    for e in entries:
        ts = e.get("ts", "?")[:19]
        action = e.get("action", "?")
        examiner = e.get("examiner", "?")
        detail = e.get("detail", "")
        if len(detail) > 80:
            detail = detail[:77] + "..."
        print(f"{ts:<22} {action:<10} {examiner:<12} {detail}")

    print(f"\n{len(entries)} entries")
