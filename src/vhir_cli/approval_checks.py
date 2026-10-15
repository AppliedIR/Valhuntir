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

import codecs
import hashlib
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

from vhir_cli.case_io import (
    LINE_CAP,
    CaseError,
    CaseFileNotRegular,
    open_log_unbudgeted,
)
from vhir_cli.display import one_line
from vhir_cli.provenance_view import roots_of

# A root bigger than this whose stat fields don't vouch for it is hashed in
# the background where the caller can't wait (the portal): until then it is
# "not yet verified", a failed check
INLINE_LIMIT = 1_000_000_000
DOC_TIMEOUT = 5
UNREACHABLE = "couldn't verify: OpenSearch unreachable"
NOT_YET_VERIFIED = "not yet verified (hashing)"
HASH_FAILED = "not verified: hashing failed: "
# How long a failed background hash is reported (as long as a portal
# plan's challenge lives, so its commit sees the same result) before the
# next approval asks for the hash again
FAILED_HOLD = 120
# Each root hashed in full at approval, by real path: its SHA-256 then and
# the stat fields it had, so the next approval needs no read
VERIFIED = "evidence-verified.json"
_STAT_KEYS = ("size", "mtime_ns", "ctime_ns", "st_dev", "st_ino")
_lock = threading.Lock()
_hashing: set[str] = set()
_failed_hashes: dict[
    str, tuple[list[int], str, float]
] = {}  # real path -> stat, why, when


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
        trail = audit_lines(case_dir, {audit_id for audit_id, _ in entries})
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
        except (OSError, ValueError) as e:
            with _lock:
                _failed_hashes[real] = (key, str(e), time.monotonic())
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
        with _lock:
            failure = _failed_hashes.get(real)
            stale = failure and (
                failure[0] != current or time.monotonic() - failure[2] > FAILED_HOLD
            )
            if stale:  # the file changed, or long enough: ask for it again
                del _failed_hashes[real]
                failure = None
        if failure:
            return _failed("ROOT", "ROOT_UNVERIFIED", path, HASH_FAILED + failure[1])
        _hash_later(case_dir, real, current)
        return _failed("ROOT", "ROOT_UNVERIFIED", path, NOT_YET_VERIFIED)
    else:
        if note is not None and st.st_size > INLINE_LIMIT:
            note(path, st.st_size)
        try:
            now = _hash_now(case_dir, real, current)
        except (OSError, ValueError) as e:
            return _failed("ROOT", "ROOT_UNVERIFIED", path, HASH_FAILED + str(e))
    if now != sha:
        return _failed("ROOT", "ROOT_CHANGED", path, f"its SHA-256 is now {now}")
    return _ok("ROOT", path, "unchanged (hashed again)")


# --- ENTRY ------------------------------------------------------------------


class AuditUnreadable(CaseError):
    """An audit log, or the audit folder, the approval checks couldn't read:
    one could hold another entry for a chained id. Nothing is signed, and the
    log is left as it is."""

    def __init__(self, unread: list[str]):
        denied = [
            u.rsplit(" (", 1)[0] for u in unread if u.endswith("(Permission denied)")
        ]
        step = f" Check the permissions of {', '.join(map(one_line, denied))}, then approve again." if denied else ""  # fmt: skip
        super().__init__(
            f"The approval checks couldn't read {', '.join(map(one_line, unread))}: an entry there "
            "could change their result. Nothing was signed, and nothing in audit/ was changed: "
            f"audit logs are evidence and stay as they are.{step}"
        )
        self.unread = unread


def audit_lines(case_dir, wanted=None) -> dict[str, list[str]]:
    """Each audit id in the case's trail (only those in `wanted`, when given)
    with the SHA-256 of every line that carries it, as written, without its
    newline. Lines are counted as json.loads counts them, line by line; a line
    longer than LINE_CAP is never held, and is read by `_Skim` instead. A
    folder that can't be listed, or a log that can't be read as a regular
    file, raises AuditUnreadable naming each one; a missing folder is an empty
    trail. A log's size is not capped: memory doesn't grow with it."""
    audit = Path(case_dir) / "audit"
    unread: list[str] = []
    try:
        names = sorted(n for n in os.listdir(audit) if n.endswith(".jsonl"))
    except FileNotFoundError:
        names = []
    except OSError as e:
        names, unread = [], [f"audit/ ({e.strerror or type(e).__name__})"]
    # the longest an id's string can be as written: a character escaped as a
    # surrogate pair (😀) is 12
    cap = 12 * max(map(len, wanted), default=0) if wanted is not None else LINE_CAP
    by_id: dict[str, list[str]] = {}
    for name in names:
        try:
            with open_log_unbudgeted(audit / name) as f:
                for audit_id, sha in _scan(f, cap):
                    if wanted is None or audit_id in wanted:
                        by_id.setdefault(audit_id, []).append(sha)
        except CaseFileNotRegular as e:  # what it is, in words
            unread.append(f"audit/{name} ({e.why})")
        except OSError as e:
            unread.append(f"audit/{name} ({e.strerror or type(e).__name__})")
    if unread:
        raise AuditUnreadable(unread)
    return by_id


_CHUNK = 1 << 20
_SEP = re.compile(rb"\r\n|\r|\n")  # where bytes.splitlines() splits


def _scan(f, cap: int):
    """(audit_id, SHA-256) of each line of `f` that json.loads reads as an
    object whose audit_id is a string, the lines split as bytes.splitlines()
    splits the whole file. A line within LINE_CAP is parsed whole; a longer
    one is fed to `_Skim` as it is read."""
    part = bytearray()
    skim: _Skim | None = None
    carry = b""
    while True:
        chunk = f.read(_CHUNK)
        data = carry + chunk if carry else chunk
        carry = b""
        if chunk and data.endswith(b"\r"):  # it may be the \r of a \r\n
            data, carry = data[:-1], b"\r"
        at = 0
        for m in _SEP.finditer(data):
            skim = _add(part, skim, data[at : m.start()], cap)
            if found := (_line(bytes(part), cap) if skim is None else skim.end()):
                yield found
            part.clear()
            skim, at = None, m.end()
        skim = _add(part, skim, data[at:], cap)
        if not chunk:  # the last line, if the file doesn't end with a newline
            found = None if not part and skim is None else _line(bytes(part), cap) if skim is None else skim.end()  # fmt: skip
            if found:
                yield found
            return


def _add(part: bytearray, skim, piece: bytes, cap: int):
    """`piece` added to the line being read: held while the line is within
    LINE_CAP, else fed to its `_Skim` (made, from what was held, when the line
    passes the cap)."""
    if skim is not None:
        skim.feed(piece)
        return skim
    part += piece
    if len(part) <= LINE_CAP:
        return None
    skim = _Skim(cap)
    for i in range(0, len(part), _CHUNK):
        skim.feed(bytes(part[i : i + _CHUNK]))
    part.clear()
    return skim


def _line(line: bytes, cap: int):
    try:
        entry = json.loads(line)
    except RecursionError:  # nested deeper than this Python parses: skimmed
        skim = _Skim(cap)
        skim.feed(line)
        return skim.end()
    except ValueError:
        return None
    if isinstance(entry, dict) and isinstance(audit_id := entry.get("audit_id"), str):
        return audit_id, entry_sha256(line)
    return None


_STR = re.compile(r'[^"\\]*(?:\\[\s\S][^"\\]*)*')  # a string's text up to its end
_TOP = re.compile(r'[{}\[\]",:]')  # what matters in the top-level object
_DEEP = re.compile(r'[{}\[\]"]')  # what matters below it
_NOT_WS = re.compile(r"[^ \t\n\r]")  # json's whitespace
_KEY_CAP = 48  # "audit_id" with every character escaped as \uXXXX
_NOT_STR = object()  # an audit_id whose value isn't a string
_TOO_LONG = object()  # a string longer than any wanted id can be


class _Skim:
    """A line too long to parse whole, read in pieces: its SHA-256, and its
    top-level audit_id as json.loads would give it. It is decoded as json.loads
    decodes bytes (the encoding found from the first bytes, surrogates passed);
    strings are stepped over, and only top-level keys, and the value of an
    audit_id key, are kept and decoded, each up to its cap. The last audit_id
    decides, as json.loads keeps the last. A line that doesn't decode, isn't an
    object, has a string or bracket left open at its end, or has more than
    whitespace after its object, is not counted, as json.loads skips it; a key
    or an audit_id value that doesn't decode is the same. What isn't checked
    (commas, literals, numbers, which bracket closes which) counts it."""

    def __init__(self, cap: int):
        self.sha = hashlib.sha256()
        self.cap = cap
        self.head = b""
        self.dec = None
        self.state = "before"  # before the object, in it, after it, or dropped
        self.depth = 0
        self.kind: str | None = None  # in a string: "key", "value" or "skip"
        self.raw: list[str] = []
        self.rawlen = 0
        self.esc = False  # a piece ended in a string's backslash
        self.want_key = self.after_colon = self.key_audit = False
        self.found: object = None  # no audit_id yet

    def feed(self, data: bytes) -> None:
        if self.state == "dropped":
            return
        self.sha.update(data)
        if self.dec is None:
            self.head += data
            if len(self.head) < 4:
                return
            data, self.head = self.head, b""
            self.dec = codecs.getincrementaldecoder(json.detect_encoding(data))(
                "surrogatepass"
            )
        try:
            self._text(self.dec.decode(data))
        except UnicodeDecodeError:
            self.state = "dropped"

    def end(self):
        if self.state == "dropped":
            return None
        try:
            if self.dec is None:  # under 4 bytes in all
                self._text(
                    self.head.decode(json.detect_encoding(self.head), "surrogatepass")
                )
            else:
                self._text(self.dec.decode(b"", final=True))
        except UnicodeDecodeError:
            return None
        found = self.found
        if self.state != "after" or not isinstance(found, str):
            return None
        return found, self.sha.hexdigest()

    def _keep(self, text: str) -> None:
        room = (_KEY_CAP if self.kind == "key" else self.cap) + 1 - self.rawlen
        if self.kind != "skip" and room > 0:
            self.raw.append(text[:room])
        self.rawlen += len(text)

    def _closed(self) -> None:
        """A key or audit_id value has ended: decoded, as json.loads would."""
        kind, raw, n = self.kind, "".join(self.raw), self.rawlen
        self.kind, self.raw, self.rawlen = None, [], 0
        if kind == "skip":
            return
        if n > (_KEY_CAP if kind == "key" else self.cap):
            if kind == "key":
                self.key_audit = False
            else:
                self.found = _TOO_LONG
            return
        try:
            text = json.loads(f'"{raw}"')
        except ValueError:  # json.loads would refuse the line
            self.state = "dropped"
            return
        if kind == "key":
            self.key_audit = text == "audit_id"
        else:
            self.found = text

    def _text(self, t: str) -> None:
        i, n = 0, len(t)
        while i < n and self.state != "dropped":
            if self.kind is not None:  # in a string
                if self.esc:
                    self._keep(t[i])
                    self.esc, i = False, i + 1
                    continue
                j = _STR.match(t, i).end()
                self._keep(t[i:j])
                if j == n:
                    return
                if t[j] == "\\":  # the piece ends inside an escape
                    self._keep("\\")
                    self.esc, i = True, j + 1
                    continue
                self._closed()
                i = j + 1
                continue
            if self.state == "before":
                m = _NOT_WS.search(t, i)
                if m is None:
                    return
                if t[m.start()] != "{":
                    self.state = "dropped"
                    return
                self.state, self.depth, self.want_key, i = "in", 1, True, m.end()
                continue
            if self.state == "after":
                if _NOT_WS.search(t, i):
                    self.state = "dropped"
                return
            if self.after_colon and self.key_audit:  # an audit_id's value
                m = _NOT_WS.search(t, i)
                if m is None:
                    return
                self.after_colon = False
                if t[m.start()] == '"':
                    self.kind, i = "value", m.end()
                    continue
                self.found, i = _NOT_STR, m.start()
            m = (_TOP if self.depth == 1 else _DEEP).search(t, i)
            if m is None:
                return
            c, i = t[m.start()], m.end()
            if c == '"':
                self.kind = "key" if self.depth == 1 and self.want_key else "skip"
                self.want_key = self.after_colon = False
            elif c in "{[":
                self.depth += 1
                self.want_key = self.after_colon = False
            elif c in "}]":
                self.depth -= 1
                if self.depth == 0:
                    self.state = "after"
            elif c == ",":
                self.want_key, self.after_colon = True, False
            else:  # ":"
                self.after_colon = True


def entry_sha256(line: bytes) -> str:
    """The SHA-256 of an audit line's bytes, without its newline."""
    return hashlib.sha256(line).hexdigest()


def _entry(trail: dict[str, list[str]], audit_id: str, sha: str) -> dict:
    lines = trail.get(audit_id, [])
    if not lines:
        return _failed("ENTRY", "ENTRY_MISSING", audit_id, "no audit line has this id")
    if len(lines) > 1:
        return _failed("ENTRY", "ENTRY_DUPLICATE", audit_id,
                       f"{len(lines)} audit lines have this id")  # fmt: skip
    if lines[0] != sha:
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
