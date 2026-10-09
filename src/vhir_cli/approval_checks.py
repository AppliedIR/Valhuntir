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
from pathlib import Path

# A changed root bigger than this isn't re-hashed at approval: it fails
INLINE_LIMIT = 1_000_000_000
DOC_TIMEOUT = 5
UNREACHABLE = "couldn't verify: OpenSearch unreachable"
_STAT_KEYS = ("size", "mtime_ns", "ctime_ns", "st_dev", "st_ino")


def check_item(case_dir, item: dict, kind: str, *, client=None) -> dict:
    """``{result, items}`` (and ``detail`` when nothing applies) for approving
    ``item`` (``kind``: finding, timeline or ioc). ``client``: an OpenSearch
    client for DOC, else the installed one, if any."""
    case_dir = Path(case_dir)
    imported = item.get("imported_from")
    if isinstance(imported, dict):
        return {
            "result": "not-applicable",
            "detail": (
                f"chain lives in case {imported.get('case_id', '?')} (imported from "
                f"{imported.get('examiner', '?')}, exported "
                f"{imported.get('exported_at', '?')})"
            ),
            "items": [],
        }
    if kind != "finding" or item.get("provenance_schema") != 2:
        return {"result": "not-applicable", "items": []}

    artifacts = [a for a in item.get("artifacts") or [] if isinstance(a, dict)]
    found: list[dict] = []
    roots: dict[tuple[str, str], dict] = {}
    for a in artifacts:
        root = a.get("provenance_root")
        if isinstance(root, dict) and root.get("path"):
            roots[(str(root["path"]), str(root.get("sha256") or ""))] = root
    for key in sorted(roots):
        found.append(_root(case_dir, roots[key]))

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


def _root(case_dir: Path, root: dict) -> dict:
    """ROOT for one root: still registered with the root's hash, and the file
    unchanged: by its stat fields when they're recorded and equal, else by
    hashing it again (up to the size limit)."""
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
    recorded = [entry.get(k) for k in _STAT_KEYS]
    current = [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_dev, st.st_ino]
    if None not in recorded and recorded == current:
        return _ok("ROOT", path, "unchanged (stat fields equal)")
    if st.st_size > INLINE_LIMIT:
        return _failed("ROOT", "ROOT_CHANGED", path, "stat changed; not re-hashed")
    try:
        now = file_sha256(real)
    except (OSError, ValueError) as e:
        return _failed("ROOT", "ROOT_CHANGED", path, f"unreadable: {e}")
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
