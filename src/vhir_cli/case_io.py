"""Shared case file I/O for CLI commands.

Local-first: flat case directory. Collaboration via export/merge.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

_EXAMINER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")

DEFAULT_CASES_DIR = str(Path.home() / "cases")


class CaseError(Exception):
    """Raised when case directory cannot be resolved or validation fails."""


class NotRegularFile(OSError):
    """A FIFO, device or socket where a case file should be: refused unread.
    An OSError, so every handler of a read error handles it."""


def read_regular(path) -> bytes:
    """A regular file's bytes: opened non-blocking and checked on the open
    descriptor before any read, so a FIFO (or a link to one) never blocks."""
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(f"{path} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "rb") as f:
        return f.read()


def open_regular(path):
    """A regular file opened for reading text line by line, checked as
    `read_regular` checks it, so a FIFO never blocks and a large file is
    never held whole."""
    fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile(f"{path} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, encoding="utf-8")


def _validate_case_id(case_id: str) -> None:
    """Validate case_id to prevent path traversal."""
    if not case_id:
        raise CaseError("Case ID cannot be empty")
    if ".." in case_id or "/" in case_id or "\\" in case_id:
        raise CaseError(f"Invalid case ID (path traversal characters): {case_id}")


def _validate_examiner(examiner: str) -> None:
    """Validate examiner slug: lowercase alphanumeric + hyphens, max 20 chars."""
    if not examiner or not _EXAMINER_RE.fullmatch(examiner):
        raise CaseError(f"Invalid examiner slug: {examiner!r}")


def _atomic_write(path: Path, content: str) -> None:
    """Write file atomically via temp file + rename to prevent data loss on crash."""
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _protected_write(path: Path, content: str) -> None:
    """Write to a chmod-444-protected case data file.

    Unlocks (0o644) before write, locks (0o444) after. Defense-in-depth
    speed bump — combined with deny rules and PreToolUse hook.
    """
    try:
        if path.exists():
            os.chmod(path, 0o644)
    except OSError:
        pass
    _atomic_write(path, content)
    try:
        os.chmod(path, 0o444)
    except OSError:
        pass


def get_case_dir(case_id: str | None = None) -> Path:
    """Resolve the active case directory."""
    if case_id:
        _validate_case_id(case_id)
        cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
        case_dir = cases_dir / case_id
        if not case_dir.exists():
            raise CaseError(f"Case not found: {case_id}")
        return case_dir

    # Check VHIR_CASE_DIR env var
    env_dir = os.environ.get("VHIR_CASE_DIR")
    if env_dir:
        case_dir = Path(env_dir)
        if not case_dir.is_dir():
            raise CaseError(f"Case directory does not exist: {case_dir}")
        return case_dir

    # Check ~/.vhir/active_case pointer (absolute path or legacy bare ID)
    active_file = Path.home() / ".vhir" / "active_case"
    if active_file.exists():
        content = active_file.read_text().strip()
        if os.path.isabs(content):
            case_dir = Path(content)
        else:
            # Legacy: bare case ID — resolve via VHIR_CASES_DIR
            _validate_case_id(content)
            cases_dir = Path(os.environ.get("VHIR_CASES_DIR", DEFAULT_CASES_DIR))
            case_dir = cases_dir / content
        if not case_dir.is_dir():
            raise CaseError(f"Case directory does not exist: {case_dir}")
        return case_dir

    raise CaseError("No active case. Use --case <id> or set VHIR_CASE_DIR.")


def get_examiner(case_dir: Path | None = None) -> str:
    """Get the current examiner identity.

    Resolution: VHIR_EXAMINER > VHIR_ANALYST (deprecated) > CASE.yaml > OS user.
    Validates the result to prevent path traversal via crafted env vars.
    """
    env_exam = os.environ.get("VHIR_EXAMINER", "").strip().lower()
    if env_exam:
        _validate_examiner(env_exam)
        return env_exam
    env_analyst = os.environ.get("VHIR_ANALYST", "").strip().lower()
    if env_analyst:
        _validate_examiner(env_analyst)
        return env_analyst
    if case_dir:
        meta = load_case_meta(case_dir)
        exam = meta.get("examiner", "").strip().lower()
        if exam:
            _validate_examiner(exam)
            return exam
    import getpass

    fallback = getpass.getuser().strip().lower()
    _validate_examiner(fallback)
    return fallback


def load_case_meta(case_dir: Path) -> dict:
    """Load CASE.yaml metadata."""
    meta_file = case_dir / "CASE.yaml"
    if not meta_file.exists():
        return {}
    try:
        with open(meta_file) as f:
            return yaml.safe_load(f) or {}
    except (yaml.YAMLError, OSError):
        return {}


# --- Data I/O (case root) ---


def check_case_file_integrity(case_dir: Path, filename: str) -> None:
    """Abort if a case data file exists with content but fails to parse."""
    path = case_dir / filename
    if not path.exists():
        return
    try:
        raw = path.read_text().strip()
    except OSError as e:
        print(f"ERROR: Cannot read {filename}: {e}", file=sys.stderr)
        sys.exit(1)
    if not raw or raw == "[]":
        return
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        print(
            f"ERROR: {filename} is corrupt and cannot be parsed: {e}",
            file=sys.stderr,
        )
        print("Verify file integrity before proceeding.", file=sys.stderr)
        sys.exit(1)


def load_findings(case_dir: Path) -> list[dict]:
    """Load findings from case root findings.json."""
    findings_file = case_dir / "findings.json"
    if not findings_file.exists():
        return []
    try:
        return json.loads(read_regular(findings_file).decode())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt findings.json ({findings_file}): {e}", file=sys.stderr)
        return []


def save_findings(case_dir: Path, findings: list[dict]) -> None:
    """Save findings to case root."""
    _protected_write(
        case_dir / "findings.json",
        json.dumps(findings, indent=2, default=str),
    )


def load_timeline(case_dir: Path) -> list[dict]:
    """Load timeline events from case root timeline.json."""
    timeline_file = case_dir / "timeline.json"
    if not timeline_file.exists():
        return []
    try:
        return json.loads(read_regular(timeline_file).decode())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt timeline.json ({timeline_file}): {e}", file=sys.stderr)
        return []


def save_timeline(case_dir: Path, timeline: list[dict]) -> None:
    """Save timeline to case root."""
    _protected_write(
        case_dir / "timeline.json",
        json.dumps(timeline, indent=2, default=str),
    )


def load_todos(case_dir: Path) -> list[dict]:
    """Load TODO items from case root todos.json."""
    todos_file = case_dir / "todos.json"
    if not todos_file.exists():
        return []
    try:
        return json.loads(read_regular(todos_file).decode())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt todos.json ({todos_file}): {e}", file=sys.stderr)
        return []


def save_todos(case_dir: Path, todos: list[dict]) -> None:
    """Save TODO items to case root."""
    _atomic_write(
        case_dir / "todos.json",
        json.dumps(todos, indent=2, default=str),
    )


def load_iocs(case_dir: Path) -> list[dict]:
    """Load IOC records from case root iocs.json."""
    iocs_file = case_dir / "iocs.json"
    if not iocs_file.exists():
        return []
    try:
        return json.loads(read_regular(iocs_file).decode())
    except json.JSONDecodeError as e:
        print(f"WARNING: Corrupt iocs.json ({iocs_file}): {e}", file=sys.stderr)
        return []


def save_iocs(case_dir: Path, iocs: list[dict]) -> None:
    """Save IOC records to case root (protected write)."""
    _protected_write(
        case_dir / "iocs.json",
        json.dumps(iocs, indent=2, default=str),
    )


# --- Approval I/O ---


def write_approval_log(
    case_dir: Path,
    item_id: str,
    action: str,
    identity: dict,
    reason: str = "",
    mode: str = "interactive",
    content_hash: str = "",
    stale_at_approval: bool = False,
    coupled_from: str = "",
) -> bool:
    """Write approval/rejection record to approvals.jsonl. Returns True on success."""
    log_file = case_dir / "approvals.jsonl"
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "item_id": item_id,
        "action": action,
        "os_user": identity["os_user"],
        "examiner": identity.get("examiner", identity.get("analyst", "")),
        "examiner_source": identity.get(
            "examiner_source", identity.get("analyst_source", "")
        ),
        "mode": mode,
    }
    if reason:
        entry["reason"] = reason
    if content_hash:
        entry["content_hash"] = content_hash
    if stale_at_approval:
        entry["stale_at_approval"] = True
    if coupled_from:
        entry["coupled_from"] = coupled_from
    try:
        if log_file.exists():
            os.chmod(log_file, 0o644)
    except OSError:
        pass
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        print(f"WARNING: Failed to write approval log: {log_file}", file=sys.stderr)
        return False
    try:
        os.chmod(log_file, 0o444)
    except OSError:
        pass
    return True


def load_approval_log(case_dir: Path) -> list[dict]:
    """Load approval records from approvals.jsonl."""
    log_file = case_dir / "approvals.jsonl"
    if not log_file.exists():
        return []
    entries = []
    corrupt_lines = 0
    with open(log_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                corrupt_lines += 1
                continue
    if corrupt_lines:
        print(
            f"Warning: {corrupt_lines} corrupt line(s) skipped in approvals.jsonl",
            file=sys.stderr,
        )
    return entries


# --- Item lookup ---


def find_draft_item(
    item_id: str, findings: list[dict], timeline: list[dict]
) -> dict | None:
    """Find a DRAFT item by ID in findings or timeline."""
    for f in findings:
        if f["id"] == item_id and f["status"] == "DRAFT":
            return f
    for t in timeline:
        if t["id"] == item_id and t["status"] == "DRAFT":
            return t
    return None


# --- Content hashing ---

HASH_EXCLUDE_KEYS = {
    "status",
    "approved_at",
    "approved_by",
    "rejected_at",
    "rejected_by",
    "rejection_reason",
    "examiner_notes",
    "examiner_modifications",
    "content_hash",
    "verification",
    "modified_at",
    "provenance",
    "provenance_warnings",
    "timeline_event_id",
    "source_evidence",
}


def compute_content_hash(item: dict) -> str:
    """SHA-256 of canonical JSON excluding volatile fields.

    Volatile fields (status, approval metadata, content_hash itself, modified_at)
    are excluded so the hash covers only the substantive content.
    """
    hashable = {k: v for k, v in item.items() if k not in HASH_EXCLUDE_KEYS}
    imported = hashable.get("imported_from")
    if isinstance(imported, dict) and "imported_at" in imported:
        # when it was imported isn't content: a re-import keeps the hash
        hashable["imported_from"] = {
            k: v for k, v in imported.items() if k != "imported_at"
        }
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


# The signed view of an item (what a ledger line's content_snapshot holds).
# View 0 is the 0.6 set (hmac_text), for legacy lines. View 1 signs
# timeline_event_id (the link a timeline cascade follows) and leaves out the
# re-attestation stamp. View 2 also signs the finding's provenance, its
# resolved source evidence and the examiner's edits. An IOC's four derived
# fields, computed from every citing finding, are left out of all of them. A
# change to these sets adds a view; a view is never edited (tests pin them).
REATTEST_KEYS = frozenset({"reattested_at", "reattested_by"})
IOC_DERIVED_KEYS = frozenset(
    {"source_findings", "sightings", "confidence", "mitre_techniques"}
)
VIEW_EXCLUDES = {
    0: frozenset(HASH_EXCLUDE_KEYS),
    1: frozenset(HASH_EXCLUDE_KEYS - {"timeline_event_id"}) | REATTEST_KEYS,
}
VIEW_EXCLUDES[2] = VIEW_EXCLUDES[1] - {
    "source_evidence",
    "provenance",
    "provenance_warnings",
    "examiner_modifications",
}


def signed_text(item: dict, item_type: str, view: int = 2) -> str:
    """The canonical text a ledger line signs for `item` (`item_type`:
    finding, timeline or ioc), in the given view."""
    excluded = VIEW_EXCLUDES[view] | (
        IOC_DERIVED_KEYS if item_type == "ioc" else frozenset()
    )
    return json.dumps(
        {k: v for k, v in item.items() if k not in excluded},
        sort_keys=True,
        default=str,
    )


# --- IOC values, as forensic-mcp's _process_iocs extracts them ---
# A copy of forensic-mcp (case/manager.py: _refang_ioc, _normalize_ioc, the
# IPv4 test in _detect_ioc_type, and _process_iocs' flatten, refang and port
# strip); forensic-mcp doesn't depend on vhir-cli. A parity test runs both.


def _refang_ioc(value: str) -> str:
    v = value.replace("[.]", ".").replace("hxxp", "http")
    return re.sub(r"\[(\W)\]", r"\1", v)


def normalize_ioc(value: str) -> str:
    """An IOC value as forensic-mcp compares them."""
    v = value.strip()
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return v.lower()
    if "." in v and not v.replace(".", "").isdigit():
        return v.lower().rstrip(".")
    if "\\" in v:
        return v.lower()
    return v


def _is_ipv4(value: str) -> bool:
    stripped = re.sub(r"[:/]\d{1,5}$", "", value.strip())
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", stripped):
        return False
    return all(0 <= int(o) <= 255 for o in stripped.split("."))


def ioc_values(iocs_field) -> set[str]:
    """The normalised IOC values a finding's `iocs` field names, as
    forensic-mcp extracts them (its first 100 entries)."""
    raw_iocs = iocs_field or []
    if isinstance(raw_iocs, dict):
        raw_iocs = [
            v
            for vals in raw_iocs.values()
            for v in (vals if isinstance(vals, list) else [vals])
        ]
    if not isinstance(raw_iocs, list):
        return set()
    values = set()
    for raw in raw_iocs[:100]:
        if isinstance(raw, dict) and "value" in raw:
            value = _refang_ioc(str(raw["value"]).strip())
            ipv4 = (
                raw.get("type", "") == "ipv4-addr"
                if raw.get("type")
                else _is_ipv4(value)
            )
        else:
            value = _refang_ioc(str(raw).strip())
            ipv4 = _is_ipv4(value)
        if not value:
            continue
        if ipv4 and re.search(r":\d{1,5}$", value):
            value = re.sub(r":\d{1,5}$", "", value)
        values.add(normalize_ioc(value))
    return values


def case_id_of(case_dir: Path) -> str:
    """The case id every ledger writer and reader uses: CASE.yaml's
    `case_id`, else the directory name."""
    return str(load_case_meta(case_dir).get("case_id") or case_dir.name)


def plan_cascades(
    decided: dict[str, str],
    findings: list[dict],
    timeline: list[dict],
    iocs: list[dict],
    exclude: set[str] | frozenset[str] = frozenset(),
) -> list[dict]:
    """The items a commit decides along with its findings, chosen only through
    each decided finding's signed fields (its `timeline_event_id` and `iocs`).

    `decided`: finding id -> status_after, for findings decided directly in
    this commit (approve, reject or edit; a re-attestation never cascades).
    `findings` hold the post-edit items. `exclude`: ids decided directly or
    skipped by the examiner; they are never cascaded.

    A timeline event cascades when it is the finding's `timeline_event_id`,
    its `auto_created_from` is that finding, it has no examiner
    modifications, and it is DRAFT (approve) or not REJECTED (reject).
    An IOC cascades when it is DRAFT and not manually reviewed, its value is
    among a decided finding's IOCs, and every finding citing it has that
    status after this commit. Unsigned data can only narrow a cascade.

    Returns `{item, type, status_after, coupled_from}` per cascade."""
    out: list[dict] = []
    # entries that aren't records are ignored, never a crash under the lock
    findings = [f for f in findings if isinstance(f, dict)]
    timeline = [t for t in timeline if isinstance(t, dict)]
    by_id = {f.get("id"): f for f in findings}
    events = {t.get("id"): t for t in timeline}
    for fid, after in decided.items():
        f = by_id.get(fid)
        if f is None or after not in ("APPROVED", "REJECTED"):
            continue
        t = events.get(f.get("timeline_event_id"))
        if t is None or t.get("id") in exclude:
            continue
        if t.get("auto_created_from") != fid or t.get("examiner_modifications"):
            continue
        if (after == "APPROVED" and t.get("status") != "DRAFT") or (
            after == "REJECTED" and t.get("status") == "REJECTED"
        ):
            continue
        out.append(
            {"item": t, "type": "timeline", "status_after": after, "coupled_from": fid}
        )
    status_after = {
        f.get("id"): decided.get(f.get("id"), f.get("status", "DRAFT"))
        for f in findings
    }
    cited = {f.get("id"): ioc_values(f.get("iocs")) for f in findings}
    for ioc in iocs:
        if not isinstance(ioc, dict) or ioc.get("id") in exclude:
            continue
        if ioc.get("manually_reviewed") or ioc.get("status") != "DRAFT":
            continue
        value = normalize_ioc(str(ioc.get("value", "")))
        citing = [fid for fid, values in cited.items() if value in values]
        sources = sorted(fid for fid in citing if fid in decided)
        for after in ("APPROVED", "REJECTED"):
            mine = [fid for fid in sources if decided[fid] == after]
            if mine and all(status_after[fid] == after for fid in citing):
                out.append(
                    {
                        "item": ioc,
                        "type": "ioc",
                        "status_after": after,
                        "coupled_from": mine[0],
                    }
                )
                break
    return out


def set_status(
    item: dict,
    decision: str,
    status_after: str,
    examiner: str,
    at: str,
    *,
    reason: str = "",
    fresh_approver: bool = False,
) -> None:
    """Apply a signed decision to its item, with the time and examiner from
    the signed body (never a fresh clock). A re-attestation stamps
    `reattested_*` and keeps `approved_*`, except on an item with no earlier
    approval record (`fresh_approver`)."""
    if decision == "reattest":
        item["reattested_by"], item["reattested_at"] = examiner, at
        if fresh_approver:
            item["approved_by"], item["approved_at"] = examiner, at
    elif status_after == "APPROVED":
        item["status"] = "APPROVED"
        item["approved_by"], item["approved_at"] = examiner, at
    elif status_after == "REJECTED":
        item["status"] = "REJECTED"
        item["rejected_by"], item["rejected_at"] = examiner, at
        if reason:
            item["rejection_reason"] = reason
    item["modified_at"] = at
    item["content_hash"] = compute_content_hash(item)


def hmac_text(item: dict) -> str:
    """The text a 0.6 approval line signed: every field outside the
    content-hash exclusions (view 0 of `signed_text`). Read only to judge
    0.6 lines; no 0.6.4 code signs it."""
    hashable = {k: v for k, v in item.items() if k not in HASH_EXCLUDE_KEYS}
    return json.dumps(hashable, sort_keys=True, default=str)


# --- Integrity verification ---


def verify_approval_integrity(case_dir: Path) -> list[dict]:
    """Cross-reference findings against approvals.

    Returns findings with an added 'verification' field:
    - 'confirmed': status matches an approval record and content hash is valid
    - 'tampered': APPROVED/REJECTED but content hash does not match
    - 'no approval record': APPROVED/REJECTED but no matching record
    - 'draft': still in DRAFT status

    Cross-file check: if the approval record also has a content_hash, both
    findings.json and approvals.jsonl hashes must match the recomputed hash.
    """
    findings = load_findings(case_dir)
    approvals = load_approval_log(case_dir)

    # Build lookup: item_id -> last approval record
    last_approval = {}
    for record in approvals:
        last_approval[record["item_id"]] = record

    results = []
    for f in findings:
        result = dict(f)
        status = f.get("status", "DRAFT")
        fid = f["id"]
        record = last_approval.get(fid)
        if status == "DRAFT":
            result["verification"] = "draft"
        elif record:
            if record["action"] == status:
                recomputed = compute_content_hash(f)
                finding_hash = f.get("content_hash")
                approval_hash = record.get("content_hash")
                # Check findings.json content hash
                if finding_hash and recomputed != finding_hash:  # noqa: SIM114
                    result["verification"] = "tampered"
                # Cross-file check: approval record content hash
                elif approval_hash and recomputed != approval_hash:
                    result["verification"] = "tampered"
                elif finding_hash or approval_hash:
                    result["verification"] = "confirmed"
                else:
                    result["verification"] = "unverified"
            else:
                result["verification"] = "no approval record"
        else:
            result["verification"] = "no approval record"
        results.append(result)
    return results


# --- Audit Index ---


def load_withdrawals(case_dir: Path) -> list[dict]:
    """The candidate findings withdrawn after challenge, oldest first.

    Each is a record_finding audit entry whose result is WITHDRAWN. An entry
    repeated in the trail counts once, by audit id and time together, so two
    withdrawals never collapse into one.
    """
    from vhir_cli.commands.audit_cmd import _load_audit_entries

    def withdrawn(entry) -> bool:
        if not isinstance(entry, dict) or entry.get("tool") != "record_finding":
            return False
        result = entry.get("result_summary")
        return isinstance(result, dict) and result.get("status") == "WITHDRAWN"

    seen: set[tuple] = set()
    withdrawals = []
    # only the withdrawals are kept while the trail is read, never the whole trail
    for entry in _load_audit_entries(case_dir, keep=withdrawn):
        key = (entry.get("audit_id"), entry.get("ts"))
        if key not in seen:
            seen.add(key)
            withdrawals.append(entry)
    return withdrawals


def load_audit_index(case_dir: Path, wanted: set[str] | None = None) -> dict[str, dict]:
    """Scan audit/*.jsonl and build {audit_id: {**entry, "_source_file": filename}}.

    Used by review --detail to resolve evidence chains. Pass `wanted` to keep
    only those audit_ids, so the index stays bounded by what the caller
    resolves rather than by the size of the audit trail.
    """
    audit_dir = case_dir / "audit"
    index: dict[str, dict] = {}
    if not audit_dir.is_dir():
        return index
    for jsonl_file in sorted(audit_dir.glob("*.jsonl")):
        try:
            # a regular file only: a FIFO or a link to a device is refused by
            # name, never waited on or read without end
            with open_regular(jsonl_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        eid = entry.get("audit_id", "")
                        if eid and (wanted is None or eid in wanted):
                            entry["_source_file"] = jsonl_file.name
                            index[eid] = entry
                    except json.JSONDecodeError:
                        continue
        except NotRegularFile as e:
            from vhir_cli.display import one_line  # a file name is the case's data

            print(
                f"  Warning: could not read {one_line(f'{jsonl_file}: {e}')}",
                file=sys.stderr,
            )
        except OSError:
            continue
    return index


# --- Export / Merge ---


# The form forensic-mcp accepts for event timestamps; `since` in another form
# is refused rather than compared.
_ISO_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
)


def _utc(ts: object) -> datetime | None:
    """An ISO timestamp as an aware UTC datetime (naive read as UTC), or None.

    Python 3.10's fromisoformat takes only 3- or 6-digit fractions and
    ±HH:MM offsets, so the fraction is made 6 digits and ±HHMM gets its colon.
    """
    if not isinstance(ts, str):
        return None
    s = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    s = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)
    try:
        dt = datetime.fromisoformat(s)
        return (
            dt.astimezone(timezone.utc)
            if dt.tzinfo
            else dt.replace(tzinfo=timezone.utc)
        )
    except (ValueError, OverflowError):  # out of range at year 1 or 9999
        return None


_ZONED = re.compile(r"(Z|[+-]\d{2}:?\d{2})$")


def display_instant(ts: object) -> str:
    """A timestamp for a table column, to the second. One with an offset (or
    Z) shows its UTC instant ("…Z"); one without shows as written; one that
    doesn't parse shows whole. Never a time cut off its offset, which reads
    as UTC."""
    if not ts:
        return "?"
    text = str(ts)
    value = _utc(text)
    if value is None:
        return text
    if _ZONED.search(text):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return text[:19]


def _at_or_after(ts: object, since: str) -> bool:
    """Compare instants; when either side doesn't parse, compare as text, as before."""
    bound, value = _utc(since), _utc(ts)
    if bound is None or value is None:
        return ts >= since
    return value >= bound


_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _at_or_before(ts: object, end: str) -> bool:
    """Compare instants, with a date-only end including its whole UTC day;
    when either side doesn't parse, compare as text, as before."""
    bound, value = _utc(end), _utc(ts)
    if bound is None or value is None:
        return ts <= end
    if _DATE_ONLY.match(end):
        try:
            return value < bound + timedelta(days=1)
        except OverflowError:  # the end is 9999-12-31
            return True
    return value <= bound


def _changed_at(item: dict) -> object:
    """When this case last changed the item: modified_at, else staged, else
    (an imported copy carries neither) when it came in."""
    imp = item.get("imported_from")
    return (
        item.get("modified_at")
        or item.get("staged")
        or (imp.get("imported_at", "") if isinstance(imp, dict) else "")
    )


_NO_TIME = datetime.min.replace(tzinfo=timezone.utc)


def _rev_key(ts: object) -> datetime:
    """A revision time to compare: a naive one read as UTC; one that isn't a
    string, or doesn't parse, is no time (the oldest)."""
    return _utc(ts) or _NO_TIME


def _revised_at(item: object) -> object:
    """When the item's content last changed: its author's modified_at (else
    staged), found down the imported_from.original chain, or a later edit
    made on the way (examiner_modifications). A copy's own time is a decision
    made there, which never travels, so it isn't a revision."""
    best = ""
    while isinstance(item, dict):
        imp = item.get("imported_from")
        orig = imp.get("original") if isinstance(imp, dict) else None
        if not isinstance(orig, dict):  # the author's own record
            own = next((t for t in (item.get("modified_at"), item.get("staged"))
                        if isinstance(t, str) and t), "")  # fmt: skip
            return max(best, own, key=_rev_key)
        mods = item.get("examiner_modifications")
        for m in mods.values() if isinstance(mods, dict) else ():
            if isinstance(m, dict) and isinstance(m.get("modified_at"), str):
                best = max(best, m["modified_at"], key=_rev_key)
        item = orig
    return best


def export_bundle(case_dir: Path, since: str = "") -> dict:
    """Export findings + timeline as JSON for sharing.

    Raises ValueError if `since` is given and isn't ISO 8601 or a date.
    """
    if since and not _ISO_TIMESTAMP_RE.match(since):
        raise ValueError(
            f"since '{since}' is not valid ISO 8601. "
            "Use format like '2026-01-24T15:00:41Z' or '2026-01-24'."
        )
    meta = load_case_meta(case_dir)
    findings = load_findings(case_dir)
    timeline = load_timeline(case_dir)

    untimed = {}
    if since:
        # an item with no time at all (imported before 0.6.4) can't be judged:
        # left out, and counted so the export says so
        untimed = {k: sum(not _changed_at(i) for i in v)
                   for k, v in (("findings", findings), ("timeline", timeline))}  # fmt: skip
        findings = [f for f in findings if _at_or_after(_changed_at(f), since)]
        timeline = [t for t in timeline if _at_or_after(_changed_at(t), since)]

    from vhir_cli import case_copies

    # the case's copies first (CopyFailed is an OSError), then carried along
    copied = case_copies.write_case_copies(case_id_of(case_dir), case_dir)
    return {
        **({"untimed": untimed} if any(untimed.values()) else {}),
        "case_id": meta.get("case_id", ""),
        "examiner": get_examiner(case_dir),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "timeline": timeline,
        "ledger": case_copies.bundle_block(case_id_of(case_dir), case_dir, copied),
    }


# the deepest a bundle's item may nest (the item is level 1; each list and
# object counts): a relay hop adds 2, and every writer must still store it
_MAX_ITEM_DEPTH = 100


def _too_deep(item: object, limit: int = _MAX_ITEM_DEPTH) -> bool:
    """Whether `item` nests deeper than `limit` levels, counted with an
    explicit stack, never by recursion, so the check can't hit the limit it
    guards."""
    stack = [(item, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        children = node.values() if isinstance(node, dict) else node
        stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
    return False


def bundle_too_deep() -> dict:
    """The refusal for a bundle json can't decode for its depth (RecursionError,
    from about 1000 levels): what each reader of a bundle file returns."""
    return {"status": "error", "message": (
        f"The bundle nests deeper than {_MAX_ITEM_DEPTH} levels; nothing was merged. "
        "Fix the bundle or ask for a new export, then merge again.")}  # fmt: skip


def id_kind(item_id: str) -> str:
    """The kind an item's id names, as approval, review and the portal read
    it: an id starting IOC- is an IOC's, T- a timeline event's, any other a
    finding's."""
    if item_id.startswith("IOC-"):
        return "ioc"
    return "timeline" if item_id.startswith("T-") else "finding"


# every id a Valhuntir writer makes: printable ASCII, no space
_PLAIN_ID = re.compile(r"[!-~]+")

_KIND_FAULTS = {
    "timeline": "has a timeline event's id (it starts with T-)",
    "ioc": "has an IOC's id (it starts with IOC-)",
}


def _unmergeable(items: object, kind: str) -> str:
    """Why the merge can't take a bundle's findings or timeline (`kind`:
    finding or timeline), or "": it takes a list of objects, each id text when
    it's set and naming that kind, none nested deeper than the writers can
    store."""
    if not isinstance(items, list):
        return "isn't a list"
    for n, item in enumerate(items):
        if not isinstance(item, dict):
            return f"item {n} isn't an object"
        item_id = item.get("id")
        if not isinstance(item_id, (str, type(None))):
            return f"item {n} has an id that isn't text"
        if item_id and id_kind(item_id) != kind:  # approval would read another kind
            if kind == "timeline":
                return f"item {n} has an id that doesn't start with T-"
            return f"item {n} {_KIND_FAULTS[id_kind(item_id)]}"
        if item_id and not _PLAIN_ID.fullmatch(item_id):  # a look-alike of another id
            return (
                f"item {n} has an id with a space, a control character or a "
                "character outside ASCII"
            )
        if _too_deep(item):
            return f"item {n} nests deeper than {_MAX_ITEM_DEPTH} levels"
    return ""


def import_bundle(case_dir: Path, bundle: dict | list) -> dict:
    """Merge incoming bundle into local findings + timeline.

    Accepts both wrapper format ({"findings": [...], "timeline": [...]}) and
    bare array format (forensic-mcp export). Uses last-write-wins based on
    modified_at.
    """
    # Bare array → treat as findings-only (forensic-mcp export format)
    if isinstance(bundle, list):
        bundle = {"findings": bundle}
    if not isinstance(bundle, dict):
        return {"status": "error", "message": "Bundle must be a JSON object or array"}
    for key, kind in (("findings", "finding"), ("timeline", "timeline")):
        # refused by name, before the case is touched
        if key in bundle and (why := _unmergeable(bundle[key], kind)):
            return {"status": "error", "message": (
                f"The bundle's {key} {why}; nothing was merged. "
                "Fix the bundle or ask for a new export, then merge again.")}  # fmt: skip
    # Where each item comes from (a bare array names no case or examiner)
    origin = {
        "case_id": str(bundle.get("case_id") or ""),
        "examiner": str(bundle.get("examiner") or ""),
        "exported_at": str(bundle.get("exported_at") or ""),
    }
    # Host identity is this case's own: another case's machine ids and keys
    # never come in with its findings and timeline items.
    bundle = {
        **bundle,
        **{
            k: _without_host_fields(bundle[k])
            for k in ("findings", "timeline")
            if k in bundle
        },
    }

    from vhir_cli import ledger

    findings_result = {"added": 0, "updated": 0, "skipped": 0}
    timeline_result = {"added": 0, "updated": 0, "skipped": 0}
    writes: list = []  # both merged in memory first: a failure writes neither

    # A bundle's chains are never added: they are data, and its keys and
    # heads anchors (decisions don't travel by import; restore carries them).
    # Read first, so a malformed block can't fail the merge after it saved.
    anchors = _bundle_anchors(bundle.get("ledger"))
    # One case-lock span around both merges and their saves, as every writer
    # of the case files: a decision committed meanwhile can't be overwritten.
    with ledger.case_lock(case_id_of(case_dir)):
        # stamped once the lock is held: an import that waited for it stores
        # its items after this time, never before it (export --since reads it)
        origin["imported_at"] = datetime.now(timezone.utc).isoformat()
        # A local file that can't be read as JSON would merge as empty and be
        # written back holding only the bundle's items: refuse before writing either.
        # So is an id held twice, in a local file or the bundle: the merge would
        # compare against one copy and write over the other (an APPROVED one too).
        for key, filename in (
            ("findings", "findings.json"),
            ("timeline", "timeline.json"),
        ):
            local_file = case_dir / filename
            if key not in bundle:
                continue
            if duplicated := _duplicate_ids(bundle[key]):
                return _duplicates_refused(f"The bundle's {key}", duplicated)
            if not local_file.exists():
                continue
            try:
                text = local_file.read_text()
                local = json.loads(text) if text.strip() else []
            except (OSError, ValueError) as e:
                return {
                    "status": "error",
                    "message": (
                        f"{filename} can't be read as JSON ({e}); nothing was merged. "
                        "Fix or restore it, then merge again."
                    ),
                }
            if duplicated := _duplicate_ids(local):
                return _duplicates_refused(filename, duplicated)
        if "findings" in bundle:
            findings_result = _merge_items(
                case_dir, "findings.json", bundle["findings"], "id", origin, writes
            )
        if "timeline" in bundle:
            timeline_result = _merge_items(
                case_dir, "timeline.json", bundle["timeline"], "id", origin, writes
            )
        # every file's text first: one that can't be made writes none
        texts = [(p, json.dumps(v, indent=2, default=str)) for p, v in writes]
        for path, text in texts:
            _protected_write(path, text)

    return {
        "status": "merged",
        "findings": findings_result,
        "timeline": timeline_result,
        "ledger": anchors,
    }


def _duplicate_ids(items: object) -> list:
    """The ids held more than once, keyed as the merge keys them (raw values).
    Non-dict items and an empty or unhashable id are left to the merge."""
    seen: set = set()
    duplicated: dict = {}  # an ordered set: first-seen order, constant-time lookups
    for item in items if isinstance(items, list) else []:
        item_id = item.get("id") if isinstance(item, dict) else None
        try:
            if item_id and item_id in seen:
                duplicated[item_id] = None
            seen.add(item_id)
        except TypeError:  # unhashable
            continue
    return list(duplicated)


def _duplicates_refused(where: str, duplicated: list) -> dict:
    # the ids are case or bundle data: one line, their controls shown as "?",
    # each capped
    from vhir_cli.display import one_line

    shown = [one_line(i) for i in duplicated[:5]]
    named = ", ".join(i if len(i) <= 80 else i[:80] + "…" for i in shown)
    more = f" and {len(duplicated) - 5} more" if len(duplicated) > 5 else ""
    return {
        "status": "error",
        "message": (
            f"{where} holds an id more than once ({named}{more}); nothing was merged. "
            "Keep one item per id, then merge again."
        ),
    }


_ANCHOR_FIELDS = {
    "keys": ("examiner", "fingerprint", "chain_id", "first_seq", "last_seq", "label"),
    "heads": ("chain_id", "seq", "hash"),
}


def _bundle_anchors(block: object) -> dict:
    """A bundle's signing keys and chain heads, as it states them: printed as
    anchors, never added to this case's ledger. Only lists count, and only
    entries with every field the printout reads."""
    out: dict[str, list] = {"keys": [], "heads": []}
    if not isinstance(block, dict):
        return out
    for name, fields in _ANCHOR_FIELDS.items():
        items = block.get(name)
        if isinstance(items, list):
            out[name] = [
                x for x in items if isinstance(x, dict) and all(f in x for f in fields)
            ]
    return out


_HOST_FIELDS = ("host_id", "vhir.host_key", "vhir.unit", "vhir.prev_ids")


def _without_host_fields(items):
    """Incoming items without another case's host identity: `host_id` and
    the `vhir.*` host fields, flat or under `vhir`. Anything not a list of
    dicts is left for the merge to judge."""
    if not isinstance(items, list):
        return items
    out = []
    for item in items:
        if isinstance(item, dict):
            item = {k: v for k, v in item.items() if k not in _HOST_FIELDS}
            if isinstance(item.get("vhir"), dict):
                vhir = {k: v for k, v in item["vhir"].items()
                        if f"vhir.{k}" not in _HOST_FIELDS}  # fmt: skip
                item["vhir"] = vhir
                if not vhir:
                    del item["vhir"]
        out.append(item)
    return out


def _parse_ts(ts: str) -> datetime:
    """Parse ISO timestamp, normalizing Z to +00:00."""
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return datetime.min.replace(tzinfo=timezone.utc)


# What an imported item kept from the case it came from: its who, when, edits
# and grades, under imported_from.original
_ORIGINAL_KEYS = (
    "examiner", "created_by", "staged", "modified_at", "provenance",
    "provenance_detail", "provenance_grade", "provenance_reason",
    "examiner_notes", "examiner_modifications", "imported_from",
)  # fmt: skip
# The other examiner's edits: kept only under imported_from, so an approval
# here never signs them as this case's own
_FOREIGN_EDITS = ("examiner_notes", "examiner_modifications", "provenance_detail")


def _stamp_import(item: dict, cleaned: dict, origin: dict) -> dict:
    """`cleaned`, an incoming item as it will be stored, with where it came
    from and its original who, when, edits and grades under `imported_from`;
    the other examiner's edits are only there. It and its artifacts are
    graded IMPORTED, and its hash is of it as stored."""
    original = {k: item[k] for k in _ORIGINAL_KEYS if k in item}
    for k in _FOREIGN_EDITS:
        cleaned.pop(k, None)
    # Its chain is in the other case: graded IMPORTED here, saying where
    imported = {"provenance_grade": "IMPORTED", "provenance_reason": (
        f"chain lives in case {origin['case_id'] or '?'} (imported from "
        f"{origin['examiner'] or '?'}, exported {origin['exported_at'] or '?'})")}  # fmt: skip
    arts = cleaned.get("artifacts")
    if isinstance(arts, list):
        for key in ("grade", "reason"):
            original[f"artifact_{key}s"] = [
                a.get(f"provenance_{key}") if isinstance(a, dict) else None
                for a in arts
            ]
        cleaned["artifacts"] = [
            {**a, **imported} if isinstance(a, dict) else a for a in arts
        ]
    cleaned["imported_from"] = {**origin, "original": original}
    cleaned.update(imported)
    cleaned["content_hash"] = compute_content_hash(cleaned)  # of it as stored
    return cleaned


def _merge_items(
    case_dir: Path,
    filename: str,
    incoming: list[dict],
    id_field: str,
    origin: dict | None,
    writes: list,
) -> dict:
    """Merge incoming items into a local JSON file using last-write-wins.
    With `origin` (an import), each item added or updated is stamped with it.
    The merged list isn't written: (file, list) is appended to `writes`."""
    local_file = case_dir / filename
    local: list[dict] = []
    if local_file.exists():
        try:
            local = json.loads(local_file.read_text())
        except json.JSONDecodeError:
            pass

    local_by_id = {item[id_field]: item for item in local if id_field in item}
    added = 0
    updated = 0
    skipped = 0
    protected = 0
    own = 0

    # Protected fields that cannot be smuggled via merge
    _MERGE_PROTECTED_FIELDS = {
        "id",
        "status",
        "staged",
        "modified_at",
        "created_by",
        "examiner",
        "provenance",
        # Approval couples an event to its finding by this; only forensic-mcp's
        # auto-timeline sets it, never an import.
        "auto_created_from",
        # A decision belongs to the case that made it: this case has no ledger
        # entry to back an incoming one.
        "approved_at",
        "approved_by",
        "rejected_at",
        "rejected_by",
        "rejection_reason",
        "verification",
        # A read-time annotation (get_findings, export_bundle: whether the
        # source case's approval verifies), never stored content
        "approval_verification",
        # The challenge cites this case's audit trail; the incoming case's
        # skeptic ids don't resolve here.
        "challenged",
    }

    for item in incoming:
        item_id = item.get(id_field, "")
        if not item_id:
            skipped += 1
            continue

        # Strip approval/integrity fields — merged items always enter as DRAFT
        cleaned = {k: v for k, v in item.items() if k not in _MERGE_PROTECTED_FIELDS}
        cleaned["status"] = "DRAFT"
        cleaned[id_field] = item_id  # Restore id after stripping
        if origin is not None:
            cleaned = _stamp_import(item, cleaned, origin)

        if item_id not in local_by_id:
            local.append(cleaned)
            local_by_id[item_id] = cleaned
            added += 1
        else:
            existing = local_by_id[item_id]
            if existing.get("status") in ("APPROVED", "REJECTED"):  # decided here
                protected += 1
                continue
            if existing.get("created_by"):  # recorded here: a copy never replaces it
                own += 1
                continue
            inc_ts, loc_ts = _revised_at(item), _revised_at(existing)
            if _rev_key(inc_ts) > _rev_key(loc_ts):
                idx = next(i for i, x in enumerate(local) if x.get(id_field) == item_id)
                local[idx] = cleaned
                local_by_id[item_id] = cleaned
                updated += 1
            else:
                skipped += 1

    writes.append((local_file, local))
    return {
        "added": added,
        "updated": updated,
        "skipped": skipped,
        "protected": protected,
        "own": own,
    }
