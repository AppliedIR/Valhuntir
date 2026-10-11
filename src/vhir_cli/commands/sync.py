"""Export and merge commands for examiner collaboration.

Export findings/timeline as JSON, merge incoming data with last-write-wins.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from vhir_cli.case_io import (
    export_bundle,
    get_case_dir,
    import_bundle,
)


def cmd_export(args, identity: dict) -> None:
    """Export findings + timeline as JSON bundle."""
    case_dir = get_case_dir(getattr(args, "case", None))
    output_file = Path(getattr(args, "file", ""))
    since = getattr(args, "since", "") or ""

    if not output_file.name:
        print("--file is required for export", file=sys.stderr)
        sys.exit(1)

    try:
        bundle = export_bundle(case_dir, since=since)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Failed to read case data for export: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(output_file, "w") as f:
            json.dump(bundle, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
    except (OSError, TypeError) as e:
        print(f"Failed to write export bundle to {output_file}: {e}", file=sys.stderr)
        sys.exit(1)

    from vhir_cli.case_copies import summary_lines

    print(f"Exported to {output_file}")
    print(f"  Examiner: {bundle.get('examiner', '?')}")
    print(f"  Findings: {len(bundle.get('findings', []))}")
    print(f"  Timeline: {len(bundle.get('timeline', []))}")
    if untimed := bundle.get("untimed"):
        print(
            f"  Left out (no time recorded): {untimed['findings']} findings, "
            f"{untimed['timeline']} timeline events; export without --since to include them"
        )
    for line in summary_lines(
        str(bundle.get("case_id", "")), bundle.get("ledger") or {}
    ):
        print(line)


def cmd_merge(args, identity: dict) -> None:
    """Merge incoming bundle into local findings + timeline."""
    case_dir = get_case_dir(getattr(args, "case", None))
    input_file = Path(getattr(args, "file", ""))

    if not input_file.name:
        print("--file is required for merge", file=sys.stderr)
        sys.exit(1)

    if not input_file.exists():
        print(f"File not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(input_file) as f:
            bundle = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Bundle file contains invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"Failed to read bundle file {input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        result = import_bundle(case_dir, bundle)
    except OSError as e:
        print(f"Failed to write merged data: {e}", file=sys.stderr)
        sys.exit(1)

    if result.get("status") == "error":
        print(f"Merge failed: {result.get('message')}", file=sys.stderr)
        sys.exit(1)

    fr = result.get("findings", {})
    tr = result.get("timeline", {})

    def kept(r: dict) -> str:  # items this case recorded, never replaced by a merge
        n = r.get("own", 0)
        return (
            f", {n} kept: recorded in this case (incoming copy not applied)"
            if n
            else ""
        )

    print("Merge complete:")
    print(
        f"  Findings: {fr.get('added', 0)} added, {fr.get('updated', 0)} updated, {fr.get('skipped', 0)} skipped{kept(fr)}"
    )
    print(
        f"  Timeline: {tr.get('added', 0)} added, {tr.get('updated', 0)} updated, {tr.get('skipped', 0)} skipped{kept(tr)}"
    )
    anchors = result.get("ledger") or {}
    if anchors.get("keys") or anchors.get("heads"):
        from vhir_cli.case_copies import summary_lines

        print(
            "  The bundle's signed history wasn't added (decisions don't travel by "
            "merge). Its keys and heads, to compare with the other box:"
        )
        for line in summary_lines(str(bundle.get("case_id", "")), anchors):
            print(f"  {line}")
