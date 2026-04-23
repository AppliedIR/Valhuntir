"""Prune ingest manifests from case evidence registry.

Cleans up cases polluted by the pre-fix `_register_evidence()` that wrote
per-artifact ingest manifests into `case/evidence/` and registered each via
`evidence_register`. Ingest manifests are internal provenance and belong in
`case/audit/ingest-manifests/`, not the forensic-evidence registry.

This command is idempotent: run-twice is a no-op once the case is clean.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from vhir_cli.case_io import _atomic_write, get_case_dir


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

    evidence_prefix = str(evidence_dir) + "/"
    manifests_removed = []
    retained = []
    for entry in files:
        path = entry.get("path", "") if isinstance(entry, dict) else ""
        if path.endswith(".manifest.json") and path.startswith(evidence_prefix):
            manifests_removed.append(path)
        else:
            retained.append(entry)

    if not manifests_removed:
        print(f"No ingest manifests found in {evidence_file}. Nothing to prune.")
        return

    audit_manifests_dir.mkdir(parents=True, exist_ok=True)

    moved_count = 0
    missing_count = 0
    for src_path in manifests_removed:
        src = Path(src_path)
        if not src.exists():
            missing_count += 1
            continue
        dest = audit_manifests_dir / src.name
        try:
            shutil.move(str(src), str(dest))
            moved_count += 1
        except OSError as e:
            print(f"  WARNING: could not move {src} → {dest}: {e}", file=sys.stderr)

    if isinstance(data, dict):
        data["files"] = retained
    _atomic_write(evidence_file, json.dumps(data, indent=2, default=str))

    print(f"Pruned case: {case_dir}")
    print(f"  Manifests unregistered: {len(manifests_removed)}")
    print(f"  Manifest files moved: {moved_count}")
    if missing_count:
        print(f"  Manifest files missing on disk: {missing_count}")
    print(f"  Real evidence entries retained: {len(retained)}")
