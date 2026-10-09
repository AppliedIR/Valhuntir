"""The checks an approval runs on a finding before it is signed.

ROOT: the evidence the finding resolves to is still what was registered.
ENTRY: each audit entry its chain names is still the line it was resolved
through. DOC: each OpenSearch document it cites is still the one recorded.

A failed check doesn't stop an approval: the examiner types why they approve
anyway (``approval_override_reason``), and the reason is signed with the
result. A finding recorded before chains (no ``provenance_schema: 2``), a
timeline event, and an imported item have nothing here to check
(``not-applicable``). The result is sorted and carries no times, so the same
case gives the same text on every plan.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path

from vhir_cli.provenance_view import roots_of

# A root bigger than this whose stat fields don't vouch for it is hashed in
# the background where the caller can't wait (the portal): until then it is
# "not yet verified", a failed check
INLINE_LIMIT = 1_000_000_000
DOC_TIMEOUT = 5
UNREACHABLE = "couldn't verify: OpenSearch unreachable"
NOT_YET_VERIFIED = "not yet verified (hashing)"
# Each root hashed in full at approval, by real path: its SHA-256 then and
# the stat fields it had, so the next approval needs no read
VERIFIED = "evidence-verified.json"
_STAT_KEYS = ("size", "mtime_ns", "ctime_ns", "st_dev", "st_ino")
_lock = threading.Lock()
_hashing: set[str] = set()


def check_item(
    case_dir, item: dict, kind: str, *, client=None, background=False, note=None
) -> dict:
    """``{result, items}`` (and ``detail`` when nothing applies) for approving
    ``item`` (``kind``: finding, timeline or ioc). ``client``: an OpenSearch
    client for DOC, else the installed one, if any. ``background``: a root
    over the inline limit is hashed in a background thread (and is not yet
    verified meanwhile) rather than now; ``note(path, size)`` is called
    before a root that size is hashed now."""
    case_dir = Path(case_dir)
    imported = item.get("imported_from")
    if isinstance(imported, dict):
        return {
            "result": "not-applicable",
            "detail": (
                f"chain lives in case {imported.get('case_id') or '?'} (imported from "
                f"{imported.get('examiner') or '?'}, exported "
                f"{imported.get('exported_at') or '?'})"
            ),
            "items": [],
        }
    if kind != "finding" or item.get("provenance_schema") != 2:
        return {"result": "not-applicable", "items": []}

    artifacts = [a for a in item.get("artifacts") or [] if isinstance(a, dict)]
    found: list[dict] = []
    roots: dict[tuple[str, str], dict] = {}
    for a in artifacts:
        for root in roots_of(a):
            roots[(str(root["path"]), str(root.get("sha256") or ""))] = root
    for key in sorted(roots):
        found.append(_root(case_dir, roots[key], background, note))

    links = [
        link
        for a in artifacts
        for link in a.get("provenance_chain") or []
        if isinstance(link, dict)
    ]
    entries = sorted(
        {
            (str(x["audit_id"]), str(x.get("entry_sha256") or ""))
            for x in links
            if x.get("audit_id")
        }
    )
    if entries:
        trail = audit_lines(case_dir)
        found += [_entry(trail, audit_id, sha) for audit_id, sha in entries]

    docs = sorted(
        {
            (str(d["_index"]), str(d["_id"]), str(d.get("content_hash") or ""))
            for x in links
            if isinstance(d := x.get("document"), dict)
            and d.get("_index")
            and d.get("_id")
        }
    )
    if docs:
        found += _documents(docs, client)

    found.sort(key=lambda i: (i["check"], i["subject"], i["status"], i["detail"]))
    failed = any(i["status"] == "failed" for i in found)
    return {"result": "failed" if failed else "ok", "items": found}


def failed_items(checks: dict | None) -> list[dict]:
    return [i for i in (checks or {}).get("items", []) if i.get("status") == "failed"]


def failed_sha256(checks: dict | None) -> str:
    """The SHA-256 of a result's failed items, as canonical JSON: what an
    override reason is given for. The portal page computes the same."""
    text = json.dumps(
        failed_items(checks), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def failed_codes(checks: dict | None) -> list[str]:
    """The codes of a result's failed items, in order."""
    return [
        i.get("code", "")
        for i in (checks or {}).get("items", [])
        if i.get("status") == "failed"
    ]


def _ok(check: str, subject: str, detail: str) -> dict:
    return {"check": check, "status": "ok", "subject": subject, "detail": detail}


def _failed(check: str, code: str, subject: str, detail: str) -> dict:
    return {"check": check, "status": "failed", "subject": subject,
            "detail": detail, "code": code}  # fmt: skip


# --- ROOT -------------------------------------------------------------------


def file_sha256(path) -> str:
    """The SHA-256 of a regular file, read in full now (never a cached hash).
    Anything that isn't a regular file is refused unread (ValueError)."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        h = hashlib.sha256()
        with os.fdopen(fd, "rb") as f:
            fd = -1
            while chunk := f.read(1 << 20):
                h.update(chunk)
        return h.hexdigest()
    finally:
        if fd >= 0:
            os.close(fd)


def _registry(case_dir: Path) -> list[dict]:
    try:
        registry = json.loads((case_dir / "evidence.json").read_text())
    except (OSError, ValueError):
        return []
    files = registry.get("files") if isinstance(registry, dict) else registry
    return [e for e in files or [] if isinstance(e, dict)]


def _stat_key(st) -> list[int]:
    return [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_dev, st.st_ino]


def _verified(case_dir: Path) -> dict:
    try:
        seen = json.loads((case_dir / VERIFIED).read_text())
    except (OSError, ValueError):
        return {}
    return seen if isinstance(seen, dict) else {}


def _record(case_dir: Path, real: str, sha: str, key: list[int]) -> None:
    """Keep a full hash with the stat fields the file had while it was read."""
    from vhir_cli.case_io import _atomic_write

    with _lock:
        seen = _verified(case_dir)
        seen[real] = {"sha256": sha, "stat": key}
        try:
            _atomic_write(
                case_dir / VERIFIED, json.dumps(seen, indent=1, sort_keys=True)
            )
        except OSError:
            pass  # hashed again next time


def _hash_now(case_dir: Path, real: str, key: list[int]) -> str:
    """The file's SHA-256, kept with its stat fields when they didn't change
    while it was read; ValueError when they did."""
    now = file_sha256(real)
    if _stat_key(os.stat(real)) != key:
        raise ValueError("it changed while it was read")
    _record(case_dir, real, now, key)
    return now


def _hash_later(case_dir: Path, real: str, key: list[int]) -> None:
    with _lock:
        if real in _hashing:
            return
        _hashing.add(real)

    def run():
        try:
            _hash_now(case_dir, real, key)
        except (OSError, ValueError):
            pass  # checked again at the next approval
        finally:
            with _lock:
                _hashing.discard(real)

    threading.Thread(target=run, name="approval-root-hash", daemon=True).start()


def _root(case_dir: Path, root: dict, background=False, note=None) -> dict:
    """ROOT for one root: still registered with the root's hash, and the file
    unchanged. Its registered stat fields, or those of its last full hash
    here, vouch for it when they're equal; else it is hashed in full, once:
    in the background above the inline limit when ``background``. Only a
    hash that differs is a change."""
    from vhir_cli.commands.evidence import registered_entry_for

    path, sha = str(root["path"]), str(root.get("sha256") or "")
    real = os.path.realpath(path)
    folder = next(
        (
            e
            for e in _registry(case_dir)
            if e.get("kind") == "folder" and e.get("path") == real
        ),
        None,
    )
    if folder is not None:  # a folder root's own path: its manifest's hash
        if folder.get("manifest_sha256") != sha:
            return _failed("ROOT", "ROOT_REREGISTERED", path,
                           "registered again since: its manifest's hash differs")  # fmt: skip
        try:
            now = file_sha256(case_dir / str(folder.get("manifest_path", "")))
        except (OSError, ValueError) as e:
            return _failed("ROOT", "ROOT_CHANGED", path, f"manifest unreadable: {e}")
        if now != sha:
            return _failed("ROOT", "ROOT_CHANGED", path, "its manifest changed")
        return _ok("ROOT", path, "manifest unchanged")

    entry = registered_entry_for(case_dir, path)
    if entry is None:
        return _failed(
            "ROOT", "ROOT_UNREGISTERED", path, "not in the evidence registry"
        )
    if entry.get("sha256") != sha:
        return _failed("ROOT", "ROOT_REREGISTERED", path,
                       "registered with another SHA-256 since")  # fmt: skip
    try:
        st = os.stat(real)
    except OSError:
        return _failed("ROOT", "ROOT_CHANGED", path, "missing")
    current = _stat_key(st)
    if [entry.get(k) for k in _STAT_KEYS] == current:
        return _ok("ROOT", path, "unchanged (stat fields equal)")
    seen = _verified(case_dir).get(real)
    if isinstance(seen, dict) and seen.get("stat") == current:
        now = str(seen.get("sha256"))
    elif background and st.st_size > INLINE_LIMIT:
        _hash_later(case_dir, real, current)
        return _failed("ROOT", "ROOT_UNVERIFIED", path, NOT_YET_VERIFIED)
    else:
        if note is not None and st.st_size > INLINE_LIMIT:
            note(path, st.st_size)
        try:
            now = _hash_now(case_dir, real, current)
        except (OSError, ValueError) as e:
            return _failed("ROOT", "ROOT_UNVERIFIED", path, f"couldn't be read: {e}")
    if now != sha:
        return _failed("ROOT", "ROOT_CHANGED", path, f"its SHA-256 is now {now}")
    return _ok("ROOT", path, "unchanged (hashed again)")


# --- ENTRY ------------------------------------------------------------------


def audit_lines(case_dir) -> dict[str, list[bytes]]:
    """Each audit id in the case's trail with the bytes of every line that
    carries it (as written, without the newline)."""
    by_id: dict[str, list[bytes]] = {}
    for log in sorted((Path(case_dir) / "audit").glob("*.jsonl")):
        try:
            data = log.read_bytes()
        except OSError:
            continue
        for line in data.splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if isinstance(entry, dict) and isinstance(entry.get("audit_id"), str):
                by_id.setdefault(entry["audit_id"], []).append(line)
    return by_id


def entry_sha256(line: bytes) -> str:
    """The SHA-256 of an audit line's bytes, without its newline."""
    return hashlib.sha256(line).hexdigest()


def _entry(trail: dict[str, list[bytes]], audit_id: str, sha: str) -> dict:
    lines = trail.get(audit_id, [])
    if not lines:
        return _failed("ENTRY", "ENTRY_MISSING", audit_id, "no audit line has this id")
    if len(lines) > 1:
        return _failed("ENTRY", "ENTRY_DUPLICATE", audit_id,
                       f"{len(lines)} audit lines have this id")  # fmt: skip
    if entry_sha256(lines[0]) != sha:
        return _failed("ENTRY", "ENTRY_CHANGED", audit_id,
                       "the audit line changed since the chain was resolved")  # fmt: skip
    return _ok("ENTRY", audit_id, "unchanged")


# --- DOC --------------------------------------------------------------------


def _documents(docs: list[tuple[str, str, str]], client) -> list[dict]:
    """DOC for each cited document: fetched now, its content hash computed
    again over its source and compared with the recorded one. With no
    OpenSearch to ask, each one fails as unverified. A document the query
    recorded no content hash for has nothing to compare, and isn't fetched."""
    out = [
        _ok("DOC", f"{i}/{d}", "no content hash was recorded; not compared")
        for i, d, recorded in docs
        if not recorded
    ]
    docs = [doc for doc in docs if doc[2]]
    if not docs:
        return out
    try:
        from sift_common.content_hash import content_hash

        if client is None:
            import importlib.util

            if importlib.util.find_spec("opensearch_mcp") is None:
                raise ImportError("opensearch_mcp")
            from opensearch_mcp.client import get_client

            client = get_client()
    except Exception:  # noqa: BLE001 - nothing here can reach OpenSearch
        return out + [
            _failed("DOC", "DOC_UNREACHABLE", f"{i}/{d}", UNREACHABLE)
            for i, d, _ in docs
        ]
    for index, doc_id, recorded in docs:
        subject = f"{index}/{doc_id}"
        try:
            got = client.get(index=index, id=doc_id, request_timeout=DOC_TIMEOUT)
        except Exception as e:  # noqa: BLE001 - not found, or no answer
            if (
                getattr(e, "status_code", None) == 404
                or type(e).__name__ == "NotFoundError"
            ):
                out.append(
                    _failed("DOC", "DOC_MISSING", subject, "no longer in OpenSearch")
                )
            else:
                out.append(_failed("DOC", "DOC_UNREACHABLE", subject, UNREACHABLE))
            continue
        if (
            not isinstance(got, dict)
            or not got.get("found", True)
            or "_source" not in got
        ):
            out.append(
                _failed("DOC", "DOC_MISSING", subject, "no longer in OpenSearch")
            )
        elif content_hash(got["_source"]) != recorded:
            out.append(_failed("DOC", "DOC_CHANGED", subject, "its content changed"))
        else:
            out.append(_ok("DOC", subject, "unchanged"))
    return out
