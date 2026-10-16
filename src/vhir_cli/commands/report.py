"""Report generation commands.

Reads case data from the case directory and produces formatted reports:
  vhir report --full                      Full case report (JSON)
  vhir report --executive-summary         High-level summary
  vhir report --timeline [--from/--to]    Timeline events
  vhir report --ioc                       Extracted IOCs
  vhir report --findings <id,...>         Specific findings detail
  vhir report --status-brief              Quick status counts
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from vhir_cli.case_io import (
    _at_or_after,
    _at_or_before,
    display_instant,
    get_case_dir,
    load_case_meta,
    load_findings,
    load_iocs,
    load_timeline,
    load_todos,
    text_of,
)
from vhir_cli.defang import (
    _NETWORK_TYPES,
    defang_iocs,
    network_ioc,
    structured_iocs,
)
from vhir_cli.display import cited_text, ioc_text, list_text, one_line
from vhir_cli.display import lines as indent_lines
from vhir_cli.ioc_groups import TEXT_ONLY, ioc_groups
from vhir_cli.ledger_verify import (
    approved_view,
    shown_label,
    verification_block,
    verification_json,
)
from vhir_cli.provenance_view import provenance_block


def cmd_report(args, identity: dict) -> None:
    """Generate case reports."""
    case_dir = get_case_dir(getattr(args, "case", None))

    # Detect multiple report flags — only one allowed at a time
    flags = []
    for flag in (
        "full",
        "executive_summary",
        "report_timeline",
        "ioc",
        "report_findings",
        "status_brief",
    ):
        val = getattr(args, flag, None)
        if val:
            flags.append(flag)
    if len(flags) > 1:
        print("Error: specify only one report type at a time.", file=sys.stderr)
        sys.exit(1)

    if getattr(args, "full", False):
        _report_full(case_dir, args)
    elif getattr(args, "executive_summary", False):
        _shown_and_saved(case_dir, args, _report_executive_summary)
    elif getattr(args, "report_timeline", False):
        _shown_and_saved(case_dir, args, _report_timeline)
    elif getattr(args, "ioc", False):
        _shown_and_saved(case_dir, args, _report_ioc)
    elif getattr(args, "report_findings", None):
        _shown_and_saved(case_dir, args, _report_findings)
    elif getattr(args, "status_brief", False):
        _shown_and_saved(case_dir, args, _report_status_brief)
    else:
        print(
            "Usage: vhir report --full | --executive-summary | --timeline | --ioc | --findings <ids> | --status-brief",
            file=sys.stderr,
        )
        sys.exit(1)


def _d(value, safe: bool):
    """One value for a report line: as the terminal shows it (`safe`), else as
    stored. Only formatting goes through here; every count, match and
    extraction reads the stored records."""
    return one_line(value) if safe else value


def _ml(value, safe: bool, indent: str):
    """A multi-line field: its lines under the value (`safe`), else as stored."""
    return indent_lines(value, indent) if safe else value


def _shown_and_saved(case_dir: Path, args, report) -> None:
    """Print a text report built from display-safe records; with --save, write
    the same report built from the records as stored, so the file is exact."""
    output = report(case_dir, args, safe=True)
    if output is None:
        return
    view = approved_view(case_dir)
    block = verification_block(view) + [""] + provenance_block(view)
    print(output + "\n\n" + "\n".join(_d(x, True) for x in block))
    save = getattr(args, "save", None)
    if save:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            stored = report(case_dir, args, safe=False)
        stored = stored if stored is not None else output
        _save_output(case_dir, save, stored + "\n\n" + "\n".join(block), view)


def _report_iocs(case_dir: Path, view: dict) -> list[str]:
    """The IOCs of the case that are domains, URLs or IPv4 addresses, live,
    longest first (a URL before the host it holds): the values in the approved
    findings' `iocs` fields, and the case's IOC records approved or cited by
    an approved finding, as report-mcp gathers them. A name a finding's text
    merely mentions isn't one. Hashes, paths and the rest aren't."""
    findings = view.get("findings") or []
    approved = {f.get("id") for f in findings}
    kept: set[str] = set()

    def take(value, typed: bool) -> None:
        if (v := network_ioc(value, typed)) is not None:
            kept.add(v)

    for value, typed in structured_iocs(findings):
        take(value, typed)
    case_iocs = [  # the case's IOCs that one of the approved findings cites
        i for i in load_iocs(case_dir)
        if isinstance(i, dict) and isinstance(i.get("source_findings"), list)
        and approved.intersection(map(str, i["source_findings"]))
    ]  # fmt: skip
    for ioc in [*(view.get("iocs") or []), *case_iocs]:  # approved, or so cited
        if isinstance(ioc, dict) and any(
            t in str(ioc.get("type", "")).lower() for t in _NETWORK_TYPES
        ):
            take(ioc.get("value", ""), True)
    return sorted(kept, key=lambda v: (-len(v), v))


def _save_output(
    case_dir: Path, save_path: str | None, content: str, view: dict | None
) -> None:
    """Write report content to file if --save is specified. A text report
    (`view` given) has every IOC of the case defanged, its block too: nothing
    reads its text back. JSON (`view` None) keeps them live: it is input for
    tools."""
    if not save_path:
        return
    if view is not None:
        content = defang_iocs(content, _report_iocs(case_dir, view))
    out = Path(save_path)
    if not out.is_absolute():
        reports_dir = case_dir / "reports"
        out = reports_dir / save_path
    # Validate resolved path stays within case_dir
    try:
        resolved = out.resolve()
        case_resolved = case_dir.resolve()
        if (
            not str(resolved).startswith(str(case_resolved) + os.sep)
            and resolved != case_resolved
        ):
            print(
                f"Error: save path must be within the case directory: {case_dir}",
                file=sys.stderr,
            )
            sys.exit(1)
    except OSError as e:
        print(f"Failed to resolve save path: {e}", file=sys.stderr)
        sys.exit(1)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        print(f"\nSaved to: {out}")
    except OSError as e:
        print(f"Failed to save report: {e}", file=sys.stderr)


def _status_counts(items: list[dict]) -> dict[str, int]:
    """Count items by status."""
    counts: dict[str, int] = {}
    for item in items:
        status = item.get("status", "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _extract_all_iocs(
    findings: list[dict], records: list, all_records: list | None = None
) -> dict[str, list[str]]:
    """The IOC records by label, then the values the findings name that no
    record of the case holds (`ioc_groups`). `records` are the records
    listed; `all_records` every IOC record of the case, whatever its status
    (`records` when not given)."""
    return ioc_groups(findings, records, all_records)


def _report_full(case_dir: Path, args) -> None:
    """Full case report: metadata + approved findings + timeline as JSON."""
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    view = approved_view(case_dir)  # only verified approvals count as approved
    approved_findings = view["findings"]
    approved_timeline = view["timeline"]

    report = {
        "report_type": "full",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": {
            "case_id": meta.get("case_id", ""),
            "name": meta.get("name", ""),
            "status": meta.get("status", ""),
            "examiner": meta.get("examiner", ""),
            "created": meta.get("created", ""),
        },
        "summary": {
            "total_findings": len(findings),
            "approved_findings": len(approved_findings),
            "total_timeline_events": len(timeline),
            "approved_timeline_events": len(approved_timeline),
            "finding_status": _status_counts(findings),
            "timeline_status": _status_counts(timeline),
            "open_todos": sum(1 for t in todos if t.get("status") == "open"),
        },
        "approved_findings": approved_findings,
        "approved_timeline": approved_timeline,
        "approved_iocs": view["iocs"],
        "iocs": _extract_all_iocs(approved_findings, view["iocs"], load_iocs(case_dir)),
        "verification": verification_json(view),
    }

    output = json.dumps(report, indent=2, default=str)
    print(output)
    _save_output(case_dir, getattr(args, "save", None), output, None)  # JSON: live


def _report_executive_summary(case_dir: Path, args, safe: bool = True) -> str | None:
    """Executive summary: counts and key statistics."""
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    f_counts = _status_counts(findings)
    t_counts = _status_counts(timeline)
    view = approved_view(case_dir)
    iocs = _extract_all_iocs(view["findings"], view["iocs"], load_iocs(case_dir))
    total_iocs = sum(len(v) for v in iocs.values())

    lines = []
    lines.append("EXECUTIVE SUMMARY")
    lines.append("=" * 50)
    lines.append(
        f"Case:       {_d(meta.get('case_id', '?'), safe)} - {_d(meta.get('name', ''), safe)}"
    )
    lines.append(f"Status:     {_d(meta.get('status', '?'), safe)}")
    lines.append(f"Examiner:   {_d(meta.get('examiner', '?'), safe)}")
    lines.append(f"Created:    {_d(meta.get('created', '?'), safe)}")
    lines.append("")
    lines.append("Findings:")
    lines.append(f"  Total: {len(findings)}")
    for status, count in sorted(f_counts.items()):
        lines.append(f"  {_d(status, safe)}: {count}")
    lines.append("")
    lines.append("Timeline Events:")
    lines.append(f"  Total: {len(timeline)}")
    for status, count in sorted(t_counts.items()):
        lines.append(f"  {_d(status, safe)}: {count}")
    lines.append("")
    lines.append(
        f"Approved (verified): {len(view['findings'])} findings, "
        f"{len(view['timeline'])} timeline events; not verified: {len(view['not_verified'])}"
    )
    lines.append("")
    lines.append(f"IOCs (from approved findings): {total_iocs}")
    for ioc_type, values in iocs.items():
        lines.append(f"  {_d(ioc_type, safe)}: {len(values)}")
    lines.append("")
    open_todos = sum(1 for t in todos if t.get("status") == "open")
    lines.append(f"Open TODOs: {open_todos}")

    output = "\n".join(lines)
    return output


def _report_timeline(case_dir: Path, args, safe: bool = True) -> str | None:
    """Timeline report with optional date filtering."""
    timeline = load_timeline(case_dir)
    timeline.sort(
        key=lambda t: (display_instant(t.get("timestamp")), text_of(t.get("timestamp")))
    )

    from_date = getattr(args, "from_date", None)
    to_date = getattr(args, "to_date", None)

    if from_date:
        timeline = [
            t for t in timeline if _at_or_after(t.get("timestamp", ""), from_date)
        ]
    if to_date:
        timeline = [
            t for t in timeline if _at_or_before(t.get("timestamp", ""), to_date)
        ]

    if not timeline:
        print("No timeline events found.")
        return None

    lines = []
    lines.append(f"{'ID':<22} {'Status':<10} {'Timestamp':<22} Description")
    lines.append("-" * 90)
    for t in timeline:
        tid = t.get("id", "?")
        status = t.get("status", "?")
        ts = display_instant(t.get("timestamp"))
        desc = text_of(t.get("description"))
        if len(desc) > 35:
            desc = desc[:32] + "..."
        lines.append(
            f"{_d(tid, safe):<22} {_d(status, safe):<10} {_d(ts, safe):<22} {_d(desc, safe)}"
        )

    lines.append("")
    lines.append(f"Total: {len(timeline)} events")

    output = "\n".join(lines)
    return output


def _report_ioc(case_dir: Path, args, safe: bool = True) -> str | None:
    """IOC report: the case's approved IOC records by type, then the values the
    approved findings name that no IOC record of the case holds."""
    view = approved_view(case_dir)
    groups = _extract_all_iocs(view["findings"], view["iocs"], load_iocs(case_dir))
    records = {k: v for k, v in groups.items() if k != TEXT_ONLY}

    lines = []
    lines.append("IOC REPORT (Approved IOCs Only)")
    lines.append("=" * 50)
    if not records:
        lines.append("\n  Approved IOC records: none")
    for ioc_type, values in groups.items():
        lines.append(f"\n  {_d(ioc_type, safe)} ({len(values)}):")
        for v in values:
            lines.append(f"    {_d(v, safe)}")

    total = sum(len(v) for v in records.values())
    lines.append(f"\nTotal: {total} IOC records across {len(records)} types")
    return "\n".join(lines)


def _report_findings(case_dir: Path, args, safe: bool = True) -> str | None:
    """Report on specific findings by ID."""
    ids_str = getattr(args, "report_findings", "")
    if not ids_str:
        print("No finding IDs specified.", file=sys.stderr)
        sys.exit(1)

    requested_ids = [fid.strip() for fid in ids_str.split(",") if fid.strip()]
    findings = load_findings(case_dir)

    by_id = {f["id"]: f for f in findings if "id" in f}
    view = approved_view(case_dir)
    unverified = {n["id"]: n["status"] for n in view["not_verified"]}
    found = []
    missing = []
    for fid in requested_ids:
        if fid in by_id:
            found.append(by_id[fid])
        else:
            missing.append(fid)

    if missing:
        print(f"Not found: {', '.join(missing)}", file=sys.stderr)

    if not found:
        print("No matching findings.", file=sys.stderr)
        sys.exit(1)

    lines = []
    for f in found:
        lines.append(f"{'=' * 60}")
        lines.append(f"  [{_d(f['id'], safe)}] {_d(f.get('title', 'Untitled'), safe)}")
        lines.append(f"{'=' * 60}")
        lines.append(f"  Status:       {_d(f.get('status', '?'), safe)}")
        if f["id"] in unverified:
            lines.append(f"  Verification: NOT VERIFIED ({unverified[f['id']]})")
        elif f["id"] in view["labels"]:
            shown = shown_label(view["labels"][f["id"]])
            lines.append(f"  Verification: {_d(shown, safe)}")
        lines.append(f"  Evidence:     {_d(cited_text(f.get('audit_ids')), safe)}")
        lines.append(f"  Observation:  {_ml(f.get('observation', ''), safe, ' ' * 16)}")
        lines.append(
            f"  Interpretation: {_ml(f.get('interpretation', ''), safe, ' ' * 18)}"
        )
        if f.get("iocs"):
            lines.append(f"  IOCs:         {_d(ioc_text(f['iocs']), safe)}")
        # a finding's ids are mitre_ids (mitre_techniques is an IOC's field)
        if mitre := f.get("mitre_ids") or f.get("mitre_techniques"):
            lines.append(f"  MITRE:        {_d(list_text(mitre), safe)}")
        if f.get("approved_at"):
            lines.append(f"  Approved:     {_d(f['approved_at'], safe)}")
        if f.get("rejected_at"):
            lines.append(f"  Rejected:     {_d(f['rejected_at'], safe)}")
            lines.append(f"  Reason:       {_d(f.get('rejection_reason', '?'), safe)}")
        lines.append("")

    output = "\n".join(lines)
    return output


def _report_status_brief(case_dir: Path, args, safe: bool = True) -> str | None:
    """Quick status counts."""
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)
    todos = load_todos(case_dir)

    f_counts = _status_counts(findings)
    t_counts = _status_counts(timeline)
    open_todos = sum(1 for t in todos if t.get("status") == "open")

    lines = []
    lines.append(
        f"Case {_d(meta.get('case_id', '?'), safe)}: {_d(meta.get('status', '?'), safe)}"
    )
    f_parts = ", ".join(f"{_d(s, safe)} {c}" for s, c in sorted(f_counts.items()))
    t_parts = ", ".join(f"{_d(s, safe)} {c}" for s, c in sorted(t_counts.items()))
    lines.append(f"Findings: {len(findings)} ({f_parts})")
    lines.append(f"Timeline: {len(timeline)} ({t_parts})")
    lines.append(f"Open TODOs: {open_todos}")

    output = "\n".join(lines)
    return output
