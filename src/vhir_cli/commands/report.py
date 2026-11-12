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

from vhir_cli import case_io, defang
from vhir_cli.case_io import (
    _at_or_after,
    _at_or_before,
    display_instant,
    get_case_dir,
    load_case_meta,
    text_of,
)
from vhir_cli.display import cited_text, ioc_text, list_text, one_line
from vhir_cli.display import lines as indent_lines
from vhir_cli.ioc_groups import TEXT_ONLY, ioc_groups
from vhir_cli.ioc_scope import SCOPE_NOTES, scope_iocs
from vhir_cli.ledger_verify import (
    approved_view,
    shown_label,
    verification_block,
    verification_json,
)
from vhir_cli.provenance_view import UNREADABLE, WITHHELD, provenance_block, withheld


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
        _shown_and_saved(case_dir, args, _report_executive_summary, todos=True)
    elif getattr(args, "report_timeline", False):
        _shown_and_saved(case_dir, args, _report_timeline)
    elif getattr(args, "ioc", False):
        _shown_and_saved(case_dir, args, _report_ioc)
    elif getattr(args, "report_findings", None):
        _shown_and_saved(case_dir, args, _report_findings)
    elif getattr(args, "status_brief", False):
        _shown_and_saved(case_dir, args, _report_status_brief, todos=True)
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


# the files verify reads, which every mode reads; the key each one's records go under
VERIFIED = ("findings.json", "timeline.json", "iocs.json")
_KEY = {"findings.json": "findings", "timeline.json": "timeline", "iocs.json": "iocs",
        "todos.json": "todos"}  # fmt: skip


def _snapshot(case_dir: Path, todos: bool = True) -> dict:
    """One read of the case, for every part of one report: the records verify
    read (findings, timeline and IOCs as verified) with its approved view, and
    CASE.yaml and, for a report that prints them (`todos`), todos.json, which
    verify doesn't read. An approval that lands while a report runs can't put
    one part out of step with another.

    Each record file the report reads is also read by the one reader
    (`case_io.read_record_files`): `read` holds what it found, `unreadable`
    the (path, why) of each file it couldn't read, and `bad` their names. An
    unreadable file contributes no records, and no renderer gets an entry
    that isn't a record."""
    view = approved_view(case_dir)
    read = case_io.read_record_files(
        case_dir, (*VERIFIED, "todos.json") if todos else VERIFIED
    )
    bad = {name for name, f in read.items() if f.why}
    snap: dict = {"view": view, "findings": [], "timeline": [], "iocs": []}
    for key, item in view["result"].records:
        if f"{key}.json" not in bad and isinstance(item, dict):
            snap[key].append(item)
    snap.update(meta=load_case_meta(case_dir), todos=[], read=read, bad=bad,
                unreadable=case_io.unreadable_of(read))  # fmt: skip
    if todos:
        snap["todos"] = read["todos.json"].records
    return snap


def _shown_and_saved(case_dir: Path, args, report, todos: bool = False) -> None:
    """Print a text report built from display-safe records; with --save, write
    the same report built from the records as stored, so the file is exact.
    Both, the block and the IOCs the file defangs come from one snapshot.
    When a file the report reads is unreadable, its header and remediation
    lines print first, the report and block follow, nothing is saved and it
    exits 1."""
    snap = _snapshot(case_dir, todos)
    unreadable, view = snap["unreadable"], snap["view"]
    if unreadable:
        print("\n".join(case_io.unreadable_lines(unreadable, view["result"])) + "\n")
    output = report(case_dir, args, safe=True, snap=snap)
    if output is None:
        return
    block = verification_block(view) + [""]
    block += provenance_block(view, findings_unreadable="findings.json" in snap["bad"])
    print(output + "\n\n" + "\n".join(_d(x, True) for x in block))
    save = getattr(args, "save", None)
    if unreadable:
        if save:
            print(case_io.not_saved_line(p for p, _ in unreadable), file=sys.stderr)
        sys.exit(1)
    if save:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            stored = report(case_dir, args, safe=False, snap=snap)
        stored = stored if stored is not None else output
        _save_output(
            case_dir, save, stored + "\n\n" + "\n".join(block), view, snap["read"]
        )


def _report_iocs(
    case_dir: Path, view: dict, read: dict | None = None, again: dict | None = None
) -> list[str]:
    """The IOCs a saved text report defangs: every domain, URL and IPv4
    address recorded in the case, whatever its status, since a status can
    change while a report is saved. They are the values in each finding's
    `iocs` field and each IOC record of such a type, in three reads: the
    records verify read for `view`, the records the reader read for the
    report (`read`), and findings.json and iocs.json read again just before
    the write (`again`, read here when not given), so a value recorded since
    is defanged too. An unreadable file adds none. Live, longest first (a URL
    before the host it holds), as report-mcp gathers them. A name a finding's
    text merely mentions isn't one. Hashes, paths and the rest aren't."""
    result = view.get("result")
    records = [*(result.records if result is not None else [])]
    if again is None:
        again = case_io.read_record_files(case_dir, ("findings.json", "iocs.json"))
    for files in (read or {}, again):
        for name in ("findings.json", "iocs.json"):
            if name in files:
                records += [(_KEY[name], i) for i in files[name].records]
    findings = [
        *(view.get("findings") or []),
        *(i for k, i in records if k == "findings"),
    ]
    iocs = [*(view.get("iocs") or []), *(i for k, i in records if k == "iocs")]
    kept: set[str] = set()

    walked = [
        *(
            w
            for f in findings
            if isinstance(f, dict)
            for w in defang.walk_iocs(f.get("iocs"))
        ),
        *defang.walk_records(iocs),
    ]
    for value, network, nearest in walked:
        if (
            v := defang.select_network_ioc(value, nearest, network=network)
        ) is not None:
            kept.add(v)
    return sorted(kept, key=lambda v: (-len(v), v))


def _save_output(
    case_dir: Path,
    save_path: str | None,
    content: str,
    view: dict | None,
    read: dict | None = None,
) -> None:
    """Write report content to file if --save is specified. A text report
    (`view` given) has every IOC of the case defanged, its block too: nothing
    reads its text back. JSON (`view` None) keeps them live: it is input for
    tools. A text report whose IOC files can't be read again just before the
    write isn't written."""
    if not save_path:
        return
    if view is not None:
        again = case_io.read_record_files(case_dir, ("findings.json", "iocs.json"))
        if unreadable := case_io.unreadable_of(again):
            print(case_io.not_saved_line(p for p, _ in unreadable), file=sys.stderr)
            sys.exit(1)
        content = defang.defang_iocs(content, _report_iocs(case_dir, view, read, again))
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
        print(f"\nSaved to: {out}", file=sys.stderr)
    except OSError as e:
        print(f"Failed to save report: {e}", file=sys.stderr)


def _shown(bad: set, files: set, label: str, lines: list[str], view=None) -> list[str]:
    """A report line or block drawn from `files`: `label: unreadable (see above)`
    when one of them can't be read, `label: withheld: ...` when `view` is
    given and blanked, else `lines`."""
    if bad & files:
        return [f"{label}: {UNREADABLE}"]
    if view is not None and withheld(view):
        return [f"{label}: {WITHHELD}"]
    return lines


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
    snap = _snapshot(case_dir)
    meta, findings, timeline, todos = (
        snap[k] for k in ("meta", "findings", "timeline", "todos")
    )
    view = snap["view"]  # only verified approvals count as approved
    approved_findings = view["findings"]
    approved_timeline = view["timeline"]
    unreadable, bad = snap["unreadable"], snap["bad"]
    if unreadable:
        for line in case_io.unreadable_lines(unreadable, view["result"]):
            print(line, file=sys.stderr)

    def unless(names, value):
        """`value`, or None when a file it is drawn from is unreadable."""
        return None if bad & set(names) else value

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
            "total_findings": unless(["findings.json"], len(findings)),
            "approved_findings": len(approved_findings),
            "total_timeline_events": unless(["timeline.json"], len(timeline)),
            "approved_timeline_events": len(approved_timeline),
            "finding_status": unless(["findings.json"], _status_counts(findings)),
            "timeline_status": unless(["timeline.json"], _status_counts(timeline)),
            "open_todos": unless(
                ["todos.json"], sum(1 for t in todos if t.get("status") == "open")
            ),
        },
        "approved_findings": approved_findings,
        "approved_timeline": approved_timeline,
        "approved_iocs": view["iocs"],
        "iocs": unless(
            ["findings.json", "iocs.json"],
            _extract_all_iocs(approved_findings, view["iocs"], snap["iocs"]),
        ),
        "verification": verification_json(view),
    }
    if withheld(view):
        report["approved_view_withheld"] = True
    if unreadable:
        report["unreadable"] = [{"file": p.name, "why": why} for p, why in unreadable]

    output = json.dumps(report, indent=2, default=str)
    print(output)
    if unreadable:
        if getattr(args, "save", None):
            print(case_io.not_saved_line(p for p, _ in unreadable), file=sys.stderr)
        sys.exit(1)
    _save_output(case_dir, getattr(args, "save", None), output, None)  # JSON: live


def _report_executive_summary(
    case_dir: Path, args, safe: bool = True, snap: dict | None = None
) -> str | None:
    """Executive summary: counts and key statistics."""
    snap = snap or _snapshot(case_dir)
    meta, findings, timeline, todos = (
        snap[k] for k in ("meta", "findings", "timeline", "todos")
    )

    f_counts = _status_counts(findings)
    t_counts = _status_counts(timeline)
    view, bad = snap["view"], snap.get("bad", set())
    iocs = _extract_all_iocs(view["findings"], view["iocs"], snap["iocs"])
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
    F, T, IO, D = "findings.json", "timeline.json", "iocs.json", "todos.json"
    for label, files, items, counts in (
        ("Findings", {F}, findings, f_counts),
        ("Timeline Events", {T}, timeline, t_counts),
    ):
        lines += _shown(bad, files, label, [f"{label}:", f"  Total: {len(items)}"]
                        + [f"  {_d(s, safe)}: {c}" for s, c in sorted(counts.items())])  # fmt: skip
        lines.append("")
    lines += _shown(bad, {F, T}, "Approved (verified)", [
        f"Approved (verified): {len(view['findings'])} findings, "
        f"{len(view['timeline'])} timeline events; not verified: {len(view['not_verified'])}"
    ], view)  # fmt: skip
    lines.append("")
    label = "IOCs (from approved findings)"
    lines += _shown(bad, {F, IO}, label, [f"{label}: {total_iocs}"]
                    + [f"  {_d(t, safe)}: {len(v)}" for t, v in iocs.items()], view)  # fmt: skip
    lines.append("")
    open_todos = sum(1 for t in todos if t.get("status") == "open")
    lines += _shown(bad, {D}, "Open TODOs", [f"Open TODOs: {open_todos}"])

    output = "\n".join(lines)
    return output


def _report_timeline(
    case_dir: Path, args, safe: bool = True, snap: dict | None = None
) -> str | None:
    """Timeline report with optional date filtering."""
    snap = snap or _snapshot(case_dir, todos=False)
    if "timeline.json" in snap.get("bad", set()):
        return f"Timeline: {UNREADABLE}"
    timeline = sorted(
        snap["timeline"],
        key=lambda t: (
            display_instant(t.get("timestamp")),
            text_of(t.get("timestamp")),
        ),
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

    if not timeline:  # an empty-case line: the block follows it, and --save writes it
        return "No timeline events found."

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


def _report_ioc(
    case_dir: Path, args, safe: bool = True, snap: dict | None = None
) -> str | None:
    """IOC report: the case's approved IOC records by type, then the values the
    approved findings name that no IOC record of the case holds."""
    snap = snap or _snapshot(case_dir, todos=False)
    view = snap["view"]
    lines = []
    lines.append("IOC REPORT (Approved IOCs Only)")
    lines.append("=" * 50)
    if snap.get("bad", set()) & {"findings.json", "iocs.json"}:
        lines.append(f"\nIOC records: {UNREADABLE}")
        return "\n".join(lines)
    groups = _extract_all_iocs(view["findings"], view["iocs"], snap["iocs"])
    records = {k: v for k, v in groups.items() if k != TEXT_ONLY}
    scoped = scope_iocs(groups)
    blanked = withheld(view)

    if not records:
        lines.append(f"\n  Approved IOC records: {WITHHELD if blanked else 'none'}")
    for ioc_type, values in scoped.routable.items():
        lines.append(f"\n  {_d(ioc_type, safe)} ({len(values)}):")
        for v in values:
            lines.append(f"    {_d(v, safe)}")

    # Every approved record counts, as the CLI and the Portal count them; the
    # note counts the values on the page, as the non-routable heading does.
    total = sum(len(v) for v in records.values())
    if blanked and not records:
        lines.append(f"\nTotal: {WITHHELD}")
    else:
        listed = sum(len(v) for v in scoped.routable.values())
        split = (
            f" ({listed} listed above, {scoped.non_routable_count} non-routable below)"
        )
        lines.append(
            f"\nTotal: {total} IOC records across {len(records)} types"
            + (split if scoped.non_routable else "")
        )

    if scoped.non_routable:
        # Listed, never dropped: an internal address in a finding usually means
        # something (lateral movement, the compromised host), it just is not a
        # blocklist candidate. Which it is needs context this cannot supply.
        lines.append("")
        lines.append("-" * 50)
        lines.append(
            f"Non-routable addresses ({scoped.non_routable_count}), listed "
            "separately, not blocklist candidates:"
        )
        for ioc_type, entries in scoped.non_routable.items():
            lines.append(f"\n  {_d(ioc_type, safe)}:")
            for value, scope in entries:
                lines.append(f"    {_d(value, safe):<20} {SCOPE_NOTES[scope]}")
    return "\n".join(lines)


def _report_findings(
    case_dir: Path, args, safe: bool = True, snap: dict | None = None
) -> str | None:
    """Report on specific findings by ID."""
    ids_str = getattr(args, "report_findings", "")
    if not ids_str:
        print("No finding IDs specified.", file=sys.stderr)
        sys.exit(1)

    requested_ids = [fid.strip() for fid in ids_str.split(",") if fid.strip()]
    snap = snap or _snapshot(case_dir, todos=False)
    if "findings.json" in snap.get("bad", set()):
        return f"Findings: {UNREADABLE}"
    findings = snap["findings"]

    by_id = {f["id"]: f for f in findings if "id" in f}
    view = snap["view"]
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
        if snap.get("unreadable"):  # another file is unreadable: the block follows
            return ""
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


def _report_status_brief(
    case_dir: Path, args, safe: bool = True, snap: dict | None = None
) -> str | None:
    """Quick status counts."""
    snap = snap or _snapshot(case_dir)
    meta, findings, timeline, todos = (
        snap[k] for k in ("meta", "findings", "timeline", "todos")
    )

    f_counts = _status_counts(findings)
    t_counts = _status_counts(timeline)
    open_todos = sum(1 for t in todos if t.get("status") == "open")
    bad = snap.get("bad", set())

    lines = []
    lines.append(
        f"Case {_d(meta.get('case_id', '?'), safe)}: {_d(meta.get('status', '?'), safe)}"
    )
    f_parts = ", ".join(f"{_d(s, safe)} {c}" for s, c in sorted(f_counts.items()))
    t_parts = ", ".join(f"{_d(s, safe)} {c}" for s, c in sorted(t_counts.items()))
    for label, name, text in (
        ("Findings", "findings.json", f"{len(findings)} ({f_parts})"),
        ("Timeline", "timeline.json", f"{len(timeline)} ({t_parts})"),
        ("Open TODOs", "todos.json", open_todos),
    ):
        lines += _shown(bad, {name}, label, [f"{label}: {text}"])

    output = "\n".join(lines)
    return output
