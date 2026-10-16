"""One text rendering of a finding's provenance, from the fields the chain
resolver stores on it (``provenance_schema``, ``provenance_grade``, and on
each artifact ``provenance_grade``, ``provenance_reason``,
``provenance_root``, ``provenance_chain``, ``provenance_break``) and, for an
import, ``imported_from``. Nothing here computes a grade or a link. Used by
``vhir review``, ``vhir approve`` and both report paths; the portal page has
the same rules in its own script."""

from __future__ import annotations

import json

from vhir_cli.display import one_line

LEGACY = "recorded before 0.6.4"
# A query logged before 0.6.4 records no results to follow: stored BROKEN
# with this break kind, and shown as LEGACY, never as BROKEN
_BEFORE_064 = "recorded-before-0.6.4"


def _s(value) -> str:
    return one_line(str(value))


def root_label(root: dict) -> str:
    """Who registered a root: its stored label, else AI-registered or
    examiner-registered, or a folder with its file count."""
    if root.get("label"):
        return str(root["label"])
    if root.get("kind") == "folder":
        return f"folder ({root.get('file_count', '?')} files)"
    return (
        "AI-registered"
        if root.get("registered_via") == "mcp"
        else "examiner-registered"
    )


def imported_text(imported: dict) -> str:
    return (
        f"chain lives in case {imported.get('case_id') or '?'} (imported from "
        f"{imported.get('examiner') or '?'}, exported {imported.get('exported_at') or '?'})"
    )


def _before_064(art: dict) -> bool:
    brk = art.get("provenance_break")
    return isinstance(brk, dict) and brk.get("kind") == _BEFORE_064


def roots_of(artifact: dict) -> list[dict]:
    """Every root an artifact's chain resolved to: ``provenance_roots``, else
    its one ``provenance_root``."""
    roots = artifact.get("provenance_roots")
    if not isinstance(roots, list) or not roots:
        roots = [artifact.get("provenance_root")]
    return [r for r in roots if isinstance(r, dict) and r.get("path")]


def _artifacts(finding: dict) -> list[dict]:
    return [a for a in finding.get("artifacts") or [] if isinstance(a, dict)]


def grade(finding: dict, art: dict | None = None) -> tuple[str, str]:
    """(label, reason) for a finding, or for one of its artifacts."""
    src = art if art is not None else finding
    imported = finding.get("imported_from")
    if isinstance(imported, dict) and src.get("provenance_grade") == "IMPORTED":
        return "IMPORTED", imported_text(imported)
    if finding.get("provenance_schema") != 2:
        return LEGACY, ""
    if art is not None:
        why = str(art.get("provenance_reason") or "")
        if _before_064(art):
            return LEGACY, why.removeprefix(LEGACY + ": ")
        return str(art.get("provenance_grade") or "?"), why
    arts = _artifacts(finding)
    stored = str(finding.get("provenance_grade") or "?")
    broken = [a for a in arts if a.get("provenance_grade") == "BROKEN"]
    if stored == "BROKEN" and broken and all(_before_064(a) for a in broken):
        stored = LEGACY
    reasons = list(dict.fromkeys(grade(finding, a)[1] for a in arts))
    return stored, "; ".join(r for r in reasons if r)


def grade_label(finding: dict, art: dict | None = None, reason: bool = True) -> str:
    """The grade as stored (LEGACY for a finding recorded before 0.6.4 and
    for a query logged before it; IMPORTED with its origin case), followed by
    its reason when there is one."""
    label, why = grade(finding, art)
    return f"{label}: {why}" if reason and why else label


def _hash(sha) -> str:
    """The start of a SHA-256; a hash still being computed names its job."""
    sha = str(sha or "?")
    if sha.startswith("pending:"):
        return f"pending (job {_s(sha.split(':', 1)[1])})"
    return f"sha256={_s(sha)[:16]}"


def _file(d) -> str:
    d = d if isinstance(d, dict) else {}
    if not d.get("path") and not d.get("sha256"):
        return "(no file)"
    return f"{_s(d.get('path', '?'))} {_hash(d.get('sha256'))}"


def _is_record(link: dict) -> bool:
    """A query link that names a returned record, not a file: it has a
    ``document`` and no ``to`` path."""
    doc, to = link.get("document"), link.get("to")
    return isinstance(doc, dict) and not (isinstance(to, dict) and to.get("path"))


def candidate_line(c: dict) -> str:
    """One of an AMBIGUOUS artifact's candidates, by the fields it has: its
    audit id and the start of its audit line's hash (two candidates can share
    an id), then its tool, path, mounted image and hash when recorded."""
    parts = [_s(c.get("audit_id") or "?")]
    if c.get("entry_sha256"):
        parts.append(f"entry={_s(c['entry_sha256'])[:16]}")
    parts += [f"{k}={_s(c[k])}" for k in ("tool", "path", "image") if c.get(k)]
    if "sha256" in c:
        parts.append(_hash(c["sha256"]) if c["sha256"] else "no hash")
    return " ".join(parts)


def root_line(root) -> str:
    """A root's path, the start of its SHA-256 and who registered it."""
    if not isinstance(root, dict):
        return ""
    return f"{_file(root)} ({_s(root_label(root))})"


def link_line(link: dict) -> str:
    """One step: its method and audit id, then from -> to with their hashes;
    a reference link names its source and version."""
    head = f"[{_s(link.get('method', '?'))}] {_s(link.get('audit_id', ''))}"
    ref = link.get("reference")
    if isinstance(ref, dict):
        head += (
            f" reference: {_s(ref.get('source') or '?')}, "
            f"{_s(ref.get('source_version') or 'version not recorded')}"
        )
    src = link.get("from")
    if isinstance(ref, dict) and not (isinstance(src, dict) and src.get("path")):
        # a reference link starts at its source (a lookup), not at a file
        start = (
            f"{_s(ref.get('source') or '?')} "
            f"({_s(ref.get('source_version') or 'version not recorded')})"
        )
        return f"{head}: {start} -> {_file(link.get('to'))}"
    if _is_record(link):
        doc = link.get("document")
        # a returned record: the query's link names it, not a file; a record
        # with no content hash (recorded before 0.6.4) reads "(no hash)"
        chash = doc.get("content_hash")
        return (
            f"{head}: record {_s(doc.get('_id') or '?')} in "
            f"{_s(doc.get('_index') or '?')} {_hash(chash) if chash else '(no hash)'}"
        )
    if "from" in link:
        return f"{head}: {_file(link.get('from'))} -> {_file(link.get('to'))}"
    return f"{head}: -> {_file(link.get('to'))}" if "to" in link else head


def _grouped_links(links: list[dict]) -> list[dict]:
    """The stored chain regrouped so each distinct ingest chain shows once,
    followed by the records that resolved through it. ``_follow`` stores, per
    returned record, that record's ingest chain and then the record's own
    link, so N records from one ingest repeat the chain N times. Grouping by
    the chain keeps each record under its own ingest even when a query returns
    records from two ingests interleaved; order follows each chain's first
    appearance."""
    groups: list[dict] = []
    by_chain: dict[str, dict] = {}
    pending: list[dict] = []
    for link in links:
        if _is_record(link):
            key = json.dumps(pending, sort_keys=True, default=str)
            grp = by_chain.get(key)
            if grp is None:
                grp = {"chain": list(pending), "records": [], "seen": set()}
                by_chain[key] = grp
                groups.append(grp)
            rkey = json.dumps(link, sort_keys=True, default=str)
            if rkey not in grp["seen"]:  # an identical record link shows once
                grp["seen"].add(rkey)
                grp["records"].append(link)
            pending = []
        else:
            pending.append(link)
    if pending:  # a chain with no record links renders in stored order
        groups.append({"chain": pending, "records": []})
    out: list[dict] = []
    for grp in groups:
        out.extend(grp["chain"])
        out.extend(grp["records"])
    return out


def finding_lines(finding: dict, indent: str = "  ") -> list[str]:
    """The finding's grade, then each artifact's grade, root and links, root
    first. An import lists no chain: it lives in the other case."""
    lines = [f"{indent}Provenance: {_s(grade_label(finding))}"]
    if finding.get("provenance_schema") != 2 or isinstance(
        finding.get("imported_from"), dict
    ):
        return lines
    for n, art in enumerate(_artifacts(finding), 1):
        lines.append(f"{indent}  [{n}] {_s(grade_label(finding, art))}")
        for root in roots_of(art):
            lines.append(f"{indent}      root: {root_line(root)}")
        links = [x for x in art.get("provenance_chain") or [] if isinstance(x, dict)]
        for k, link in enumerate(_grouped_links(links), 1):
            lines.append(f"{indent}      {k}. {link_line(link)}")
        for c in art.get("provenance_candidates") or []:  # what made it AMBIGUOUS
            if isinstance(c, dict):
                lines.append(f"{indent}      candidate: {candidate_line(c)}")
    return lines


def provenance_block(view: dict) -> list[str]:
    """The block both reports end with, after VERIFICATION: each approved,
    verified finding's provenance."""
    lines = ["PROVENANCE", "=" * 50]
    findings = view.get("findings") or []
    for f in findings:
        lines.append(f"[{_s(f.get('id', '?'))}] {_s(f.get('title', ''))}")
        lines += finding_lines(f)
    if not findings:
        lines.append("No approved, verified findings.")
    return lines
