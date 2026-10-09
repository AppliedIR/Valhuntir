"""Evidence management commands: lock, unlock, register, list, verify, log.

Subcommand group:
  vhir evidence register <path> [--description] [--force-reregister]
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
import importlib.util
import json
import os
import stat
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.approval_auth import require_tty_confirmation
from vhir_cli.case_io import get_case_dir
from vhir_cli.display import display_safe
from vhir_cli.display import lines as indent_lines


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
    case_dir,
    path: str,
    examiner: str,
    description: str = "",
    force_reregister: bool = False,
    registered_via: str | None = None,
    folder_hasher=None,
) -> dict:
    """Register an evidence file, or a folder as one root with a manifest of
    its files, and return structured data.

    Validates path, computes SHA-256, writes registry.

    Args:
        case_dir: Path to the active case directory.
        path: Path to the evidence file.
        examiner: Examiner identity slug.
        description: Optional description.
        force_reregister: Allow re-registering a file whose hash changed.
        registered_via: "mcp" when the AI registered it (case-mcp passes it);
            host names from such a file are the AI's, never artifact evidence.
        folder_hasher: for a folder, (case_dir, paths) -> (hashes, job_id).
            Defaults to hashing every file now; case-mcp passes one that hashes
            large files in the background, and a job id means nothing is
            registered yet (`{"status": "hashing", "job_id": …}`).

    Returns:
        Dict with path, sha256, description, registered_at, registered_by.

    Raises:
        FileNotFoundError: If evidence file doesn't exist.
        ValueError: If path is outside the case directory, or the file is
            already registered with a different hash and force_reregister
            is not set.
        OSError: If registry write fails.
    """
    from vhir_cli.case_io import _atomic_write

    case_dir = Path(case_dir)
    evidence_path = Path(path)

    # Resolve relative paths against case directory
    if not evidence_path.is_absolute():
        evidence_path = case_dir / evidence_path

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
                f"  Path:     {evidence_path}\n"
                f"  Resolved: {resolved}\n"
                f"  Case dir: {case_resolved}\n"
                f"Copy evidence into the case evidence directory first:\n"
                f"  cp {evidence_path} {case_dir / 'evidence' / evidence_path.name}\n"
                f"Or create a symlink:\n"
                f"  ln -s {resolved} {case_dir / 'evidence' / evidence_path.name}"
            )

    if evidence_path.is_dir():
        return _register_folder(
            case_dir, resolved, examiner, description, force_reregister,
            registered_via, folder_hasher or _hash_each,
        )  # fmt: skip

    # Compute SHA256
    sha = hashlib.sha256()
    with open(evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    file_hash = sha.hexdigest()
    why, acquired = _not_an_original(case_dir, str(resolved), file_hash)
    if why:
        raise ValueError(why)
    st = os.stat(evidence_path)  # the approval check compares these
    entry_fields = {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
                   "ctime_ns": st.st_ctime_ns, "st_dev": st.st_dev, "st_ino": st.st_ino}  # fmt: skip
    entry_fields.update(acquired or {})  # an acquisition's output says so

    # Record in evidence registry
    # Absent, 0-byte or whitespace-only means an empty registry. Anything else
    # that can't be read or parsed is refused before writing: starting a new
    # registry over it would throw away every earlier registration.
    reg_file = case_dir / "evidence.json"
    registry = _read_registry(reg_file)

    # Dedup check — match by resolved path
    for existing in registry.get("files", []):
        if existing.get("path") == str(resolved):
            if existing.get("sha256") == file_hash:
                return {
                    **existing,
                    "note": "already registered (same path and hash)",
                }
            else:
                # Same path, different hash — the file changed after it was
                # registered. Overwriting sha256 would move the integrity
                # baseline that 'vhir evidence verify' compares against, so
                # refuse unless the examiner explicitly asks for it.
                if not force_reregister:
                    raise ValueError(
                        f"Evidence already registered with a different hash — "
                        f"the file changed since registration.\n"
                        f"  Path:       {resolved}\n"
                        f"  Registered: {existing.get('sha256')}\n"
                        f"  Current:    {file_hash}\n"
                        f"Run 'vhir evidence verify' to review the case, then "
                        f"re-register with --force-reregister if the new "
                        f"content is the intended evidence."
                    )
                # Keep the superseded hash so the original baseline stays
                # recoverable from evidence.json.
                existing.setdefault("previous_hashes", []).append(
                    {
                        "sha256": existing.get("sha256"),
                        "registered_at": existing.get("registered_at"),
                        "registered_by": existing.get("registered_by"),
                        "superseded_at": datetime.now(timezone.utc).isoformat(),
                        "superseded_by": examiner,
                    }
                )
                existing["sha256"] = file_hash
                existing.update(entry_fields)
                existing["registered_at"] = datetime.now(timezone.utc).isoformat()
                existing["registered_by"] = examiner
                if registered_via:
                    existing["registered_via"] = registered_via
                else:  # the examiner's registration now
                    existing.pop("registered_via", None)
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
        **entry_fields,
    }
    if registered_via:
        entry["registered_via"] = registered_via
    registry["files"].append(entry)

    _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))

    return entry


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _outputs_of(case_dir: Path, entry: dict) -> list[tuple[str, str]]:
    """(real path, SHA-256) of each output an audit entry records: its output
    records (a wintools one by its SIFT path, relative to the case), and its
    output files and saved stdout."""
    out = [(str(case_dir / o["sift_path"]) if o.get("sift_path") else o.get("path"),
            o.get("sha256")) for o in entry.get("outputs") or [] if isinstance(o, dict)]  # fmt: skip
    rs = (
        entry.get("result_summary")
        if isinstance(entry.get("result_summary"), dict)
        else {}
    )
    out += zip(
        rs.get("output_files") or [], rs.get("output_sha256s") or [], strict=False
    )
    out.append((rs.get("output_file"), rs.get("output_sha256")))
    return [(os.path.realpath(p), h) for p, h in out if isinstance(p, str) and p
            and isinstance(h, str)]  # fmt: skip


def _recorded_outputs(case_dir: Path) -> dict[str, list[tuple[str, dict]]]:
    """Every output this case's audit records: real path -> (hash, entry). No
    other case's trail is read."""
    index: dict[str, list[tuple[str, dict]]] = {}
    for log in sorted((case_dir / "audit").glob("*.jsonl")):
        try:
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict):
                for p, h in _outputs_of(case_dir, entry):
                    index.setdefault(p, []).append((h, entry))
    return index


def _made_here(index: dict, real: str, sha256: str) -> list[dict]:
    """The entries that recorded the file as an output, at this path with this
    hash (a hash still pending matches on the path alone). The empty file's
    hash never matches."""
    if sha256 == _EMPTY_SHA256:
        return []
    return [
        e for h, e in index.get(real, []) if h == sha256 or h.startswith("pending:")
    ]


def _not_an_original(case_dir: Path, real: str, sha256: str, index=None) -> tuple:
    """(Why a file can't be registered as an original, or None; and, for an
    acquisition's output, its `acquired_by` and `acquisition_tool`). A file
    this case's tools made is linked to what it was made from, never
    registered: one this case recorded as an operation's output, or one under
    its extractions/. A file every recording operation acquired (a live memory
    or disk collection) is evidence itself: it registers, labelled."""
    ops = _made_here(
        _recorded_outputs(case_dir) if index is None else index, real, sha256
    )
    if ops and all(e.get("acquisition") is True for e in ops):
        first = ops[0]
        return None, {"acquired_by": first.get("audit_id", ""),
                      "acquisition_tool": first.get("acquisition_tool") or first.get("tool", "")}  # fmt: skip
    if ops:
        ids = ", ".join(str(e.get("audit_id", "?")) for e in ops)
        return (
            f"{real} is an output this case recorded ({ids}): register the original "
            "evidence it was made from; this file is linked to it."
        ), None
    extractions = os.path.realpath(case_dir / "extractions") + os.sep
    if real.startswith(extractions):
        return (
            f"{real} is under this case's extractions/, made by its tools: register "
            "the original evidence it was made from; this file is linked to it."
        ), None
    return None, None


def _read_registry(reg_file: Path) -> dict:
    registry = {"files": []}
    try:
        text = reg_file.read_text() if reg_file.exists() else ""
        if text.strip():
            registry = json.loads(text)
    except (OSError, ValueError) as e:
        raise ValueError(
            f"{reg_file} can't be read as JSON ({e}); nothing was registered. "
            "Fix or restore it, then register again."
        ) from e
    return registry


def _file_identity():
    """sift-common's file identity module, or None without the sift stack."""
    if importlib.util.find_spec("sift_common") is None:
        return None
    try:
        from sift_common import file_identity
    except ImportError:
        return None
    return file_identity


def _sha256_of(path: str) -> str:
    """The SHA-256 of a regular file. Opened non-blocking and checked before
    any read, so a FIFO is refused (ValueError) instead of blocking."""
    fi = _file_identity()
    if fi is not None:
        return fi.hash_file(path).sha256
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"{path} is not a regular file")
    sha = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _hash_each(
    case_dir, paths: list[str]
) -> tuple[dict[str, str], str, dict[str, str]]:
    """Hash every file now (the CLI has no time limit); no job. A file that
    can't be hashed is an error of its own, never the whole folder's."""
    hashes, errors = {}, {}
    for p in paths:
        try:
            hashes[p] = _sha256_of(p)
        except (OSError, ValueError) as e:
            errors[p] = str(e)
    return hashes, "", errors


def _walk_folder(folder: Path) -> tuple[list[str], list[str], dict[str, str]]:
    """(regular files, everything else, what couldn't be read: path -> why)
    under folder, in a stable order. Links aren't followed: a link, FIFO or
    device is listed, never read; a folder that can't be listed is named,
    never silently left out."""
    regular, skipped, unreadable = [], [], {}
    walk = os.walk(folder, onerror=lambda e: unreadable.__setitem__(e.filename, str(e)))
    for root, dirs, files in walk:
        dirs.sort()
        links = sorted(d for d in dirs if os.path.islink(os.path.join(root, d)))
        for name in sorted(files) + links:
            p = os.path.join(root, name)
            try:
                is_reg = stat.S_ISREG(os.lstat(p).st_mode)
            except OSError as e:
                unreadable[p] = str(e)
                continue
            (regular if is_reg else skipped).append(p)
    return regular, skipped, unreadable


def _register_folder(
    case_dir: Path, folder: Path, examiner: str, description: str,
    force_reregister: bool, registered_via: str | None, hasher,
) -> dict:  # fmt: skip
    """A folder is one root: its manifest lists each regular file (case path,
    SHA-256, stat fields) and what was skipped. Nothing is written while any
    file is still hashing."""
    from vhir_cli.case_io import _atomic_write

    regular, skipped, unreadable = _walk_folder(folder)
    hashes, job_id, *more = hasher(case_dir, regular)
    unreadable.update(more[0] if more else {})
    if job_id:
        return {"status": "hashing", "job_id": job_id, "path": str(folder),
                "files_hashing": sum(p not in hashes for p in regular)}  # fmt: skip
    base = case_dir.resolve()
    rows = []
    recorded = _recorded_outputs(case_dir)  # read once for the whole folder
    for p in regular:
        if p not in hashes:  # not readable as a regular file when hashed
            unreadable.setdefault(p, "not readable as a regular file")
            continue
        why, acquired = _not_an_original(
            case_dir, os.path.realpath(p), hashes[p], recorded
        )
        if why:
            raise ValueError(f"{folder} holds a file that isn't an original: {why}")
        st = os.lstat(p)
        rows.append({"path": os.path.relpath(p, base), "sha256": hashes[p],
                     "size": st.st_size, "mtime_ns": st.st_mtime_ns,
                     "ctime_ns": st.st_ctime_ns, "st_dev": st.st_dev,
                     "st_ino": st.st_ino})  # fmt: skip
        rows[-1].update(acquired or {})
    doc = {"folder": str(folder), "files": rows,
           "skipped": sorted(os.path.relpath(p, base) for p in skipped)}  # fmt: skip
    if unreadable:  # only then, so a manifest written before the key is unchanged
        doc["unreadable"] = [{"path": os.path.relpath(p, base), "error": why}
                             for p, why in sorted(unreadable.items())]  # fmt: skip
    manifest = json.dumps(doc, indent=2, sort_keys=True).encode()
    manifest_sha = hashlib.sha256(manifest).hexdigest()

    reg_file = case_dir / "evidence.json"
    registry = _read_registry(reg_file)
    existing = next((e for e in registry.get("files", [])
                     if e.get("path") == str(folder)), None)  # fmt: skip
    if existing and existing.get("manifest_sha256") == manifest_sha:
        return {**existing, "note": "already registered (same path and manifest)"}
    if existing and not force_reregister:
        raise ValueError(
            f"Folder already registered with a different manifest: its files "
            f"changed since registration.\n  Path: {folder}\nRun 'vhir evidence "
            f"verify' to review the case, then re-register with --force-reregister "
            f"if the new content is the intended evidence."
        )
    manifests = case_dir / "evidence-manifests"
    manifests.mkdir(exist_ok=True)
    taken = [int(m.stem) for m in manifests.glob("*.json") if m.stem.isdigit()]
    manifest_file = manifests / f"{max(taken, default=0) + 1}.json"
    _atomic_write(manifest_file, manifest.decode())
    entry = {
        "kind": "folder",
        "path": str(folder),
        "manifest_path": str(manifest_file.relative_to(case_dir)),
        "manifest_sha256": manifest_sha,
        "file_count": len(rows),
        "description": description,
        "registered_at": datetime.now(timezone.utc).isoformat(),
        "registered_by": examiner,
    }
    if registered_via:
        entry["registered_via"] = registered_via
    if existing:  # --force-reregister: the earlier manifest stays recoverable
        previous = {k: existing.get(k) for k in
                    ("manifest_path", "manifest_sha256", "registered_at", "registered_by")}  # fmt: skip
        entry["previous_manifests"] = existing.get("previous_manifests", []) + [
            previous
        ]
        registry["files"][registry["files"].index(existing)] = entry
    else:
        registry.setdefault("files", []).append(entry)
    _atomic_write(reg_file, json.dumps(registry, indent=2, default=str))
    return entry


def registered_entry_for(case_dir, path) -> dict | None:
    """The registry entry `path` is (by real path), or the manifest row of the
    folder root holding it; None when it isn't registered or isn't in its
    folder's manifest (added later, or skipped). The file itself is never
    read, and a manifest changed since registration isn't trusted."""
    case_dir = Path(case_dir)
    try:
        registry = json.loads((case_dir / "evidence.json").read_text())
    except (OSError, ValueError):
        return None
    real = os.path.realpath(path)
    entries = registry.get("files", []) if isinstance(registry, dict) else []
    entries = [e for e in entries if isinstance(e, dict)]
    for entry in entries:  # the file itself first, whatever the order
        if entry.get("kind") != "folder" and entry.get("path") == real:
            return entry
    rel = os.path.relpath(real, case_dir.resolve())
    for entry in entries:  # then every folder holding it, until one lists it
        root = entry.get("path", "")
        if entry.get("kind") == "folder" and real.startswith(root + os.sep):
            row = next((r for r in _manifest_rows(case_dir, entry) or []
                        if r.get("path") == rel), None)  # fmt: skip
            if row:
                return row
    return None


def _manifest_rows(case_dir: Path, entry: dict) -> list[dict] | None:
    """A folder root's manifest rows, or None when the manifest is missing or
    no longer has the hash recorded at registration."""
    try:
        data = (case_dir / entry["manifest_path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.get("manifest_sha256"):
            return None
        return json.loads(data)["files"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def cmd_register_evidence(args, identity: dict) -> None:
    """CLI wrapper — registers evidence and prints summary. Only with the
    examiner's confirmation at the terminal: a shell the AI runs has none, so
    it can't register as the examiner."""
    case_dir = get_case_dir(getattr(args, "case", None))
    force = getattr(args, "force_reregister", False)
    verb = "Re-register (replacing its baseline hash)" if force else "Register"
    if not require_tty_confirmation(f"{verb} {args.path} as evidence? [y/N]: "):
        print("Not registered.", file=sys.stderr)
        sys.exit(1)

    try:
        data = register_evidence_data(
            case_dir=case_dir,
            path=args.path,
            examiner=identity.get("examiner", identity.get("analyst", "")),
            description=args.description,
            force_reregister=force,
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
    sha256 = data.get("sha256") or data.get("manifest_sha256", "")
    _log_evidence_action(case_dir, "register", data["path"], identity, sha256=sha256)

    print(f"Registered: {data['path']}")
    if data.get("kind") == "folder":
        print(
            f"  Folder: {data['file_count']} file(s), manifest {data['manifest_path']}"
        )
        print(f"  Manifest SHA256: {sha256}")
        return
    if data.get("note") == "updated (same path, hash changed)":
        prior = data["previous_hashes"][-1]["sha256"]
        print(f"  WARNING: hash changed since registration (was {prior})")
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
    for i, raw in enumerate(files, 1):
        entry = display_safe(raw)  # for printing inline
        sha = entry.get("sha256", "?")[:16] + "..."
        by = entry.get("registered_by", "?")
        path = entry.get("path", "?")
        print(f"{i:<4} {sha:<20} {by:<15} {path}")
        if entry.get("description"):
            print(f"     Description: {indent_lines(raw['description'], ' ' * 18)}")

    print(f"\n{len(files)} evidence file(s) registered")


def verify_evidence_data(case_dir, folder_hasher=None) -> dict:
    """Verify evidence integrity and return structured results.

    Args:
        case_dir: Path to the active case directory.
        folder_hasher: as for register_evidence_data. A folder root is verified
            file by file against its manifest; a file still hashing is PENDING,
            with its job id.

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

    pending = 0
    for entry in files:
        if entry.get("kind") == "folder":
            folder = _verify_folder(case_dir, entry, folder_hasher or _hash_each)
            results.extend(folder)
            n = Counter(r["status"] for r in folder)
            verified, modified = verified + n["OK"], modified + n["MODIFIED"]
            missing, errors = missing + n["MISSING"], errors + n["ERROR"]
            pending += n["PENDING"]
            continue
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

    summary = {
        "results": results,
        "verified": verified,
        "modified": modified,
        "missing": missing,
        "errors": errors,
    }
    if pending:
        summary["pending"] = pending
    return summary


def _verify_folder(case_dir: Path, entry: dict, hasher) -> list[dict]:
    """Each manifest file's status: OK, MODIFIED, MISSING, or PENDING while it
    hashes. A manifest that's missing or changed makes the root an ERROR."""
    rows = _manifest_rows(case_dir, entry)
    if rows is None:
        return [{"path": entry.get("path", ""), "status": "ERROR", "expected_hash": "",
                 "actual_hash": None,
                 "error": "its manifest is missing or changed since registration"}]  # fmt: skip
    base = case_dir.resolve()
    paths = {r["path"]: str(base / r["path"]) for r in rows}
    hashes, job_id, *more = hasher(
        case_dir, [p for p in paths.values() if os.path.exists(p)]
    )
    errors = more[0] if more else {}
    results = []
    for r in rows:
        p = paths[r["path"]]
        actual = hashes.get(p)
        status = ("MISSING" if not os.path.exists(p) else
                  "ERROR" if p in errors else
                  "PENDING" if actual is None and job_id else
                  "ERROR" if actual is None else
                  "OK" if actual == r["sha256"] else "MODIFIED")  # fmt: skip
        result = {"path": p, "status": status, "expected_hash": r["sha256"],
                  "actual_hash": actual}  # fmt: skip
        if status == "PENDING":
            result["job_id"] = job_id
        elif status == "ERROR":
            result["error"] = errors.get(p, "not readable as a regular file")
        results.append(result)
    return results


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

    for raw in results:
        r = display_safe(raw)  # for printing inline
        print(f"{r['status']:<12} {r['path']}")
        if raw["status"] == "MODIFIED":
            print(f"             Expected: {r['expected_hash']}")
            print(f"             Actual:   {r['actual_hash']}")
        elif raw["status"] == "ERROR" and raw.get("error"):
            print(f"             Error: {r['error']}")

    print(
        f"\n{data['verified']} verified, {data['modified']} MODIFIED, {data['missing']} missing, {data['errors']} errors"
    )
    if data["modified"]:
        print("ALERT: Evidence files have been modified since registration.")
        sys.exit(2)
    if data["missing"] or data["errors"]:
        print(
            f"ALERT: {data['missing']} evidence file(s) missing and "
            f"{data['errors']} that couldn't be read: not verified."
        )
        sys.exit(1)


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
        e = display_safe(e)  # for printing inline
        ts = e.get("ts", "?")[:19]
        action = e.get("action", "?")
        examiner = e.get("examiner", "?")
        detail = e.get("detail", "")
        if len(detail) > 80:
            detail = detail[:77] + "..."
        print(f"{ts:<22} {action:<10} {examiner:<12} {detail}")

    print(f"\n{len(entries)} entries")
