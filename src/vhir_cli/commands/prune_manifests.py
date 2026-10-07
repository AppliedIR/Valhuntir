"""Prune ingest manifests from case evidence registry.

Cleans up cases polluted by the pre-fix `_register_evidence()` that wrote
per-artifact ingest manifests into `case/evidence/` and registered each via
`evidence_register`. Ingest manifests are internal provenance and belong in
`case/audit/ingest-manifests/`, not the forensic-evidence registry.

This command is idempotent: run-twice is a no-op once the case is clean.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

from vhir_cli.case_io import _atomic_write, get_case_dir
from vhir_cli.commands.evidence import _log_evidence_action


def cmd_prune_ingest_manifests(args, identity: dict) -> None:
    """Move ingest manifests out of evidence registry into audit dir."""
    case_id = getattr(args, "case_id", None)
    try:
        case_dir = get_case_dir(case_id)
    except Exception as e:
        print(f"Error resolving case: {e}", file=sys.stderr)
        sys.exit(1)

    evidence_file = case_dir / "evidence.json"
    evidence_dir = case_dir / "evidence"
    audit_manifests_dir = case_dir / "audit" / "ingest-manifests"

    if not evidence_file.exists():
        print(f"No evidence.json in {case_dir}. Nothing to prune.")
        return

    try:
        data = json.loads(evidence_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {evidence_file}: {e}", file=sys.stderr)
        sys.exit(1)

    files = data.get("files", []) if isinstance(data, dict) else []
    if not isinstance(files, list):
        print(f"Unexpected evidence.json shape in {evidence_file}", file=sys.stderr)
        sys.exit(1)

    # evidence_register stores str(evidence_path.resolve()) — if
    # `case/evidence/` is a symlink to `/mnt/evidence/` (the documented
    # pattern per evidence_register's error message), stored paths are
    # resolved-target paths. We must match against BOTH the unresolved
    # prefix (plain case) AND the resolved prefix (symlinked mount) to
    # avoid silent false negatives on symlinked-evidence cases.
    prefixes = {str(evidence_dir) + os.sep}
    try:
        prefixes.add(str(evidence_dir.resolve()) + os.sep)
    except OSError:
        pass  # symlink target missing — stick with the literal prefix

    manifests_removed = []
    for entry in files:
        path = entry.get("path", "") if isinstance(entry, dict) else ""
        if path.endswith(".manifest.json") and any(
            path.startswith(p) for p in prefixes
        ):
            manifests_removed.append(path)

    if not manifests_removed:
        print(f"No ingest manifests found in {evidence_file}. Nothing to prune.")
        return

    audit_manifests_dir.mkdir(parents=True, exist_ok=True)

    moved_count = 0
    missing_count = 0
    overflow_count = 0
    unregistered = []
    for src_path in manifests_removed:
        src = Path(src_path)
        if not src.exists():
            missing_count += 1
            unregistered.append(src_path)
            continue
        # Collision-safe: pre-fix `_write_ingest_manifest` used a 50-char
        # stem truncation that collided on Windows EVTX channel names
        # (e.g. TerminalServices-LocalSessionManager Admin vs Operational),
        # so multiple source paths can share a manifest filename. Disambiguate
        # the move target rather than silently overwriting.
        dest = audit_manifests_dir / src.name
        if dest.exists():
            stem = src.name.removesuffix(".manifest.json")
            for counter in range(1, 1000):
                candidate = audit_manifests_dir / f"{stem}-{counter}.manifest.json"
                if not candidate.exists():
                    dest = candidate
                    break
            else:
                print(
                    f"  WARNING: >999 collisions for {src.name}; skipping",
                    file=sys.stderr,
                )
                overflow_count += 1
                continue
        try:
            shutil.move(str(src), str(dest))
            moved_count += 1
            unregistered.append(src_path)
        except OSError as e:
            print(f"  WARNING: could not move {src} → {dest}: {e}", file=sys.stderr)

    # Only unregister manifests that actually left `case/evidence/`. A file
    # skipped by the overflow guard or stranded by a failed move (e.g. the
    # 0555 directory `vhir evidence lock` leaves behind) is still sitting in
    # the evidence directory: dropping its registry entry would make it an
    # unregistered artifact that `evidence verify` and `evidence list` can
    # never see again. Missing-on-disk entries leave no such orphan, so they
    # are unregistered as before.
    unregistered_paths = set(unregistered)
    retained = [
        entry
        for entry in files
        if not (isinstance(entry, dict) and entry.get("path") in unregistered_paths)
    ]

    if isinstance(data, dict):
        data["files"] = retained
    _atomic_write(evidence_file, json.dumps(data, indent=2, default=str))

    # Registry removals are chain-of-custody events, same as the "register"
    # records cmd_register_evidence writes for every addition.
    for path in unregistered:
        _log_evidence_action(case_dir, "unregister", path, identity)

    still_registered = len(manifests_removed) - len(unregistered)

    print(f"Pruned case: {case_dir}")
    print(f"  Manifests unregistered: {len(unregistered)}")
    print(f"  Manifest files moved: {moved_count}")
    if missing_count:
        print(f"  Manifest files missing on disk: {missing_count}")
    if overflow_count:
        print(f"  Manifest files skipped (>999 collisions): {overflow_count}")
    if still_registered:
        print(f"  Manifests left registered (file not relocated): {still_registered}")
    print(f"  Real evidence entries retained: {len(retained) - still_registered}")
